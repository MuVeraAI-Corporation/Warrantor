// Package identitybindings binds AumOS agent identities to SPIFFE/SPIRE workload identities.
package identitybindings

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	minimumSVIDTTL = time.Minute
	maximumSVIDTTL = 24 * time.Hour
)

var entryIDPattern = regexp.MustCompile(`(?mi)^Entry ID\s*:\s*([a-zA-Z0-9._-]+)\s*$`)

// Selector is a SPIRE workload attestation selector.
type Selector struct {
	Type  string
	Value string
}

// String returns the SPIRE CLI type:value representation.
func (selector Selector) String() string {
	return selector.Type + ":" + selector.Value
}

// RegistrationEntry is a validated workload-to-SPIFFE-ID binding.
type RegistrationEntry struct {
	SPIFFEID  spiffeid.ID
	ParentID  spiffeid.ID
	Selectors []Selector
	X509TTL   time.Duration
}

// RegistrationResult is the durable SPIRE entry identity returned by registration.
type RegistrationResult struct {
	EntryID  string
	SPIFFEID spiffeid.ID
}

// NewRegistrationEntry validates and normalizes an intended SPIRE workload registration.
func NewRegistrationEntry(
	spiffeID string,
	parentID string,
	selectors []Selector,
	x509TTL time.Duration,
) (RegistrationEntry, error) {
	workloadID, err := spiffeid.FromString(spiffeID)
	if err != nil {
		return RegistrationEntry{}, fmt.Errorf("invalid workload SPIFFE ID: %w", err)
	}
	parent, err := spiffeid.FromString(parentID)
	if err != nil {
		return RegistrationEntry{}, fmt.Errorf("invalid parent SPIFFE ID: %w", err)
	}
	if workloadID.Path() == "" || workloadID.Path() == "/" {
		return RegistrationEntry{}, errors.New("workload SPIFFE ID must have a non-root path")
	}
	if workloadID.TrustDomain() != parent.TrustDomain() {
		return RegistrationEntry{}, errors.New("workload and parent SPIFFE IDs must share a trust domain")
	}
	if x509TTL < minimumSVIDTTL || x509TTL > maximumSVIDTTL || x509TTL%time.Second != 0 {
		return RegistrationEntry{}, fmt.Errorf(
			"X509-SVID TTL must be whole seconds between %s and %s",
			minimumSVIDTTL,
			maximumSVIDTTL,
		)
	}
	if len(selectors) == 0 {
		return RegistrationEntry{}, errors.New("at least one workload selector is required")
	}

	normalizedSelectors := append([]Selector(nil), selectors...)
	seen := make(map[string]struct{}, len(normalizedSelectors))
	for _, selector := range normalizedSelectors {
		if selector.Type == "" || selector.Value == "" {
			return RegistrationEntry{}, errors.New("selector type and value must be non-empty")
		}
		if strings.ContainsAny(selector.Type, ":\r\n\x00") || strings.ContainsAny(selector.Value, "\r\n\x00") {
			return RegistrationEntry{}, errors.New("selector contains a forbidden delimiter or control character")
		}
		if _, duplicate := seen[selector.String()]; duplicate {
			return RegistrationEntry{}, fmt.Errorf("duplicate selector %q", selector.String())
		}
		seen[selector.String()] = struct{}{}
	}
	sort.Slice(normalizedSelectors, func(leftIndex int, rightIndex int) bool {
		return normalizedSelectors[leftIndex].String() < normalizedSelectors[rightIndex].String()
	})

	return RegistrationEntry{
		SPIFFEID:  workloadID,
		ParentID:  parent,
		Selectors: normalizedSelectors,
		X509TTL:   x509TTL,
	}, nil
}

// CommandResult captures a subprocess boundary without merging stdout and stderr.
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// CommandRunner executes an argument-vector command without a shell.
type CommandRunner interface {
	Run(ctx context.Context, binary string, arguments []string) (CommandResult, error)
}

type operatingSystemCommandRunner struct{}

func (operatingSystemCommandRunner) Run(
	ctx context.Context,
	binary string,
	arguments []string,
) (CommandResult, error) {
	command := exec.CommandContext(ctx, binary, arguments...)
	stdout, err := command.Output()
	result := CommandResult{Stdout: string(stdout)}
	if err == nil {
		return result, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.Stderr = string(exitError.Stderr)
		result.ExitCode = exitError.ExitCode()
		return result, nil
	}
	return CommandResult{}, err
}

// SPIRERegistrar registers validated entries through the official spire-server CLI.
// The adapter uses an argument vector rather than a shell, so selector values cannot inject flags.
type SPIRERegistrar struct {
	BinaryPath string
	SocketPath string
	Runner     CommandRunner
}

// Register creates one workload entry and returns its SPIRE-generated entry ID.
func (registrar SPIRERegistrar) Register(
	ctx context.Context,
	entry RegistrationEntry,
) (RegistrationResult, error) {
	if registrar.BinaryPath == "" {
		return RegistrationResult{}, errors.New("spire-server binary path is required")
	}
	if registrar.SocketPath == "" {
		return RegistrationResult{}, errors.New("SPIRE Server API socket path is required")
	}
	runner := registrar.Runner
	if runner == nil {
		runner = operatingSystemCommandRunner{}
	}

	arguments := []string{
		"entry",
		"create",
		"-socketPath",
		registrar.SocketPath,
		"-parentID",
		entry.ParentID.String(),
		"-spiffeID",
		entry.SPIFFEID.String(),
		"-x509SVIDTTL",
		strconv.FormatInt(int64(entry.X509TTL/time.Second), 10),
	}
	for _, selector := range entry.Selectors {
		arguments = append(arguments, "-selector", selector.String())
	}

	result, err := runner.Run(ctx, registrar.BinaryPath, arguments)
	if err != nil {
		return RegistrationResult{}, fmt.Errorf("execute spire-server: %w", err)
	}
	if result.ExitCode != 0 {
		return RegistrationResult{}, fmt.Errorf("spire-server entry create failed with exit code %d", result.ExitCode)
	}
	match := entryIDPattern.FindStringSubmatch(result.Stdout)
	if len(match) != 2 {
		return RegistrationResult{}, errors.New("spire-server response did not contain an entry ID")
	}
	return RegistrationResult{EntryID: match[1], SPIFFEID: entry.SPIFFEID}, nil
}

// X509SVIDSource is the narrow Workload API source used by the binding service.
type X509SVIDSource interface {
	GetX509SVID() (*x509svid.SVID, error)
}

// WorkloadIdentity is a currently usable X509-SVID obtained from the SPIFFE Workload API.
type WorkloadIdentity struct {
	ID           spiffeid.ID
	Certificates []*x509.Certificate
	PrivateKey   crypto.Signer
	ExpiresAt    time.Time
}

// WorkloadAPI owns a maintained go-spiffe X509 source.
type WorkloadAPI struct {
	source *workloadapi.X509Source
}

// NewWorkloadAPI connects to the SPIFFE Workload API and blocks until the initial SVID update.
func NewWorkloadAPI(ctx context.Context, address string) (*WorkloadAPI, error) {
	options := []workloadapi.X509SourceOption{}
	if address != "" {
		if err := workloadapi.ValidateAddress(address); err != nil {
			return nil, fmt.Errorf("invalid Workload API address: %w", err)
		}
		options = append(
			options,
			workloadapi.WithClientOptions(workloadapi.WithAddr(address)),
		)
	}
	source, err := workloadapi.NewX509Source(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("connect to SPIFFE Workload API: %w", err)
	}
	return &WorkloadAPI{source: source}, nil
}

// CurrentIdentity obtains and validates the default X509-SVID at the supplied trusted time.
func CurrentIdentity(source X509SVIDSource, now time.Time) (WorkloadIdentity, error) {
	if source == nil {
		return WorkloadIdentity{}, errors.New("X509-SVID source is required")
	}
	svid, err := source.GetX509SVID()
	if err != nil {
		return WorkloadIdentity{}, fmt.Errorf("fetch X509-SVID: %w", err)
	}
	if svid == nil || len(svid.Certificates) == 0 || svid.PrivateKey == nil {
		return WorkloadIdentity{}, errors.New("Workload API returned an incomplete X509-SVID")
	}
	leaf := svid.Certificates[0]
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return WorkloadIdentity{}, errors.New("Workload API returned an X509-SVID outside its validity window")
	}
	certificateID, err := x509svid.IDFromCert(leaf)
	if err != nil {
		return WorkloadIdentity{}, fmt.Errorf("extract SPIFFE ID from X509-SVID: %w", err)
	}
	if certificateID != svid.ID {
		return WorkloadIdentity{}, errors.New("X509-SVID source ID does not match certificate URI SAN")
	}
	return WorkloadIdentity{
		ID:           svid.ID,
		Certificates: append([]*x509.Certificate(nil), svid.Certificates...),
		PrivateKey:   svid.PrivateKey,
		ExpiresAt:    leaf.NotAfter,
	}, nil
}

// CurrentIdentity returns a validated identity from the maintained Workload API source.
func (workloadAPI *WorkloadAPI) CurrentIdentity(now time.Time) (WorkloadIdentity, error) {
	if workloadAPI == nil || workloadAPI.source == nil {
		return WorkloadIdentity{}, errors.New("Workload API is not initialized")
	}
	return CurrentIdentity(workloadAPI.source, now)
}

// Close releases the Workload API watch and transport.
func (workloadAPI *WorkloadAPI) Close() error {
	if workloadAPI == nil || workloadAPI.source == nil {
		return nil
	}
	return workloadAPI.source.Close()
}
