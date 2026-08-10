package identitybindings

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

type recordedCommand struct {
	binary    string
	arguments []string
}

type recordingRunner struct {
	commands []recordedCommand
	result   CommandResult
	err      error
}

func (runner *recordingRunner) Run(
	_ context.Context,
	binary string,
	arguments []string,
) (CommandResult, error) {
	runner.commands = append(runner.commands, recordedCommand{
		binary:    binary,
		arguments: append([]string(nil), arguments...),
	})
	return runner.result, runner.err
}

func validEntry(t *testing.T) RegistrationEntry {
	t.Helper()
	entry, err := NewRegistrationEntry(
		"spiffe://example.org/ns/prod/sa/agent",
		"spiffe://example.org/spire/agent/k8s/cluster-1/node-1",
		[]Selector{{Type: "k8s", Value: "sa:agent"}, {Type: "k8s", Value: "ns:prod"}},
		time.Hour,
	)
	if err != nil {
		t.Fatalf("NewRegistrationEntry() error = %v", err)
	}
	return entry
}

func TestNewRegistrationEntryValidatesAndSorts(t *testing.T) {
	entry := validEntry(t)
	if got, want := entry.Selectors[0].String(), "k8s:ns:prod"; got != want {
		t.Fatalf("first selector = %q, want %q", got, want)
	}
	if entry.SPIFFEID.String() != "spiffe://example.org/ns/prod/sa/agent" {
		t.Fatalf("unexpected SPIFFE ID %q", entry.SPIFFEID)
	}
}

func TestNewRegistrationEntryRejectsUnsafeInputs(t *testing.T) {
	testCases := []struct {
		name      string
		spiffeID  string
		parentID  string
		selectors []Selector
		ttl       time.Duration
	}{
		{name: "invalid workload ID", spiffeID: "not-spiffe", parentID: "spiffe://example.org/agent", selectors: []Selector{{Type: "unix", Value: "uid:1000"}}, ttl: time.Hour},
		{name: "root workload path", spiffeID: "spiffe://example.org", parentID: "spiffe://example.org/agent", selectors: []Selector{{Type: "unix", Value: "uid:1000"}}, ttl: time.Hour},
		{name: "cross trust domain", spiffeID: "spiffe://example.org/workload", parentID: "spiffe://other.example/agent", selectors: []Selector{{Type: "unix", Value: "uid:1000"}}, ttl: time.Hour},
		{name: "no selectors", spiffeID: "spiffe://example.org/workload", parentID: "spiffe://example.org/agent", selectors: nil, ttl: time.Hour},
		{name: "duplicate selectors", spiffeID: "spiffe://example.org/workload", parentID: "spiffe://example.org/agent", selectors: []Selector{{Type: "unix", Value: "uid:1000"}, {Type: "unix", Value: "uid:1000"}}, ttl: time.Hour},
		{name: "flag injection newline", spiffeID: "spiffe://example.org/workload", parentID: "spiffe://example.org/agent", selectors: []Selector{{Type: "unix", Value: "uid:1000\n-spiffeID evil"}}, ttl: time.Hour},
		{name: "TTL too short", spiffeID: "spiffe://example.org/workload", parentID: "spiffe://example.org/agent", selectors: []Selector{{Type: "unix", Value: "uid:1000"}}, ttl: time.Second},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewRegistrationEntry(
				testCase.spiffeID,
				testCase.parentID,
				testCase.selectors,
				testCase.ttl,
			)
			if err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestSPIRERegistrarUsesExactArgumentVector(t *testing.T) {
	runner := &recordingRunner{result: CommandResult{Stdout: "Entry ID      : entry-123\n"}}
	registrar := SPIRERegistrar{
		BinaryPath: "spire-server",
		SocketPath: "/run/spire/server.sock",
		Runner:     runner,
	}
	result, err := registrar.Register(context.Background(), validEntry(t))
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if result.EntryID != "entry-123" {
		t.Fatalf("EntryID = %q, want entry-123", result.EntryID)
	}
	wantArguments := []string{
		"entry", "create",
		"-socketPath", "/run/spire/server.sock",
		"-parentID", "spiffe://example.org/spire/agent/k8s/cluster-1/node-1",
		"-spiffeID", "spiffe://example.org/ns/prod/sa/agent",
		"-x509SVIDTTL", "3600",
		"-selector", "k8s:ns:prod",
		"-selector", "k8s:sa:agent",
	}
	if len(runner.commands) != 1 || runner.commands[0].binary != "spire-server" {
		t.Fatalf("commands = %#v", runner.commands)
	}
	if !reflect.DeepEqual(runner.commands[0].arguments, wantArguments) {
		t.Fatalf("arguments = %#v, want %#v", runner.commands[0].arguments, wantArguments)
	}
}

func TestSPIRERegistrarFailsClosed(t *testing.T) {
	testCases := []struct {
		name   string
		result CommandResult
		err    error
	}{
		{name: "runner unavailable", err: errors.New("binary missing")},
		{name: "nonzero exit", result: CommandResult{ExitCode: 1, Stderr: "denied"}},
		{name: "missing entry ID", result: CommandResult{Stdout: "created"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			runner := &recordingRunner{result: testCase.result, err: testCase.err}
			registrar := SPIRERegistrar{BinaryPath: "spire-server", SocketPath: "/run/spire.sock", Runner: runner}
			if _, err := registrar.Register(context.Background(), validEntry(t)); err == nil {
				t.Fatal("expected registration failure")
			}
		})
	}
}

type staticSVIDSource struct {
	svid *x509svid.SVID
	err  error
}

func (source staticSVIDSource) GetX509SVID() (*x509svid.SVID, error) {
	return source.svid, source.err
}

func createSVID(t *testing.T, id string, notBefore time.Time, notAfter time.Time) *x509svid.SVID {
	t.Helper()
	spiffeID := spiffeid.RequireFromString(id)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "workload"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		URIs:         []*url.URL{spiffeID.URL()},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	return &x509svid.SVID{ID: spiffeID, Certificates: []*x509.Certificate{certificate}, PrivateKey: privateKey}
}

func TestCurrentIdentityReturnsValidatedSVID(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	svid := createSVID(t, "spiffe://example.org/workload", now.Add(-time.Minute), now.Add(time.Hour))
	identity, err := CurrentIdentity(staticSVIDSource{svid: svid}, now)
	if err != nil {
		t.Fatalf("CurrentIdentity() error = %v", err)
	}
	if identity.ID != svid.ID || !identity.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("unexpected identity %#v", identity)
	}
}

func TestCurrentIdentityRejectsInvalidSourceState(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	valid := createSVID(t, "spiffe://example.org/workload", now.Add(-time.Minute), now.Add(time.Hour))
	mismatch := *valid
	mismatch.ID = spiffeid.RequireFromString("spiffe://example.org/other")
	testCases := []struct {
		name   string
		source X509SVIDSource
	}{
		{name: "nil source", source: nil},
		{name: "source error", source: staticSVIDSource{err: errors.New("unavailable")}},
		{name: "nil SVID", source: staticSVIDSource{}},
		{name: "expired", source: staticSVIDSource{svid: createSVID(t, "spiffe://example.org/workload", now.Add(-time.Hour), now)}},
		{name: "identity mismatch", source: staticSVIDSource{svid: &mismatch}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := CurrentIdentity(testCase.source, now); err == nil {
				t.Fatal("expected identity validation failure")
			}
		})
	}
}
