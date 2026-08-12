// Package metrics provides a minimal Prometheus-compatible /metrics endpoint
// for Warrantor Go services. No external dependencies — uses only the standard
// library so every Go binary stays small (critical for edge-sentinel <5MB).
//
// Usage:
//
//	mux := http.NewServeMux()
//	mux.HandleFunc("/metrics", metrics.Handler())
//	mux.HandleFunc("/healthz", metrics.HealthHandler("agent-identity"))
//
//	counter := metrics.NewCounter("warrantor_identity_svids_issued_total", "Total SVIDs issued")
//	counter.Inc()
//
//	hist := metrics.NewHistogram("warrantor_identity_verify_duration_seconds", "SVID verify latency")
//	hist.Observe(0.001)
package metrics

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Registry holds all registered metrics. Thread-safe.
type Registry struct {
	mu      sync.RWMutex
	counter map[string]*Counter
	hist    map[string]*Histogram
	gauge   map[string]*Gauge
}

var defaultRegistry = &Registry{
	counter: make(map[string]*Counter),
	hist:    make(map[string]*Histogram),
	gauge:   make(map[string]*Gauge),
}

// Default returns the process-wide default registry.
func Default() *Registry { return defaultRegistry }

// Counter is a monotonically increasing counter.
type Counter struct {
	name   string
	help   string
	value  atomic.Uint64
	labels map[string]string
}

// NewCounter registers and returns a new counter.
func NewCounter(name, help string) *Counter {
	c := &Counter{name: name, help: help}
	defaultRegistry.mu.Lock()
	defaultRegistry.counter[name] = c
	defaultRegistry.mu.Unlock()
	return c
}

// Inc increments the counter by 1.
func (c *Counter) Inc() { c.value.Add(1) }

// Add adds n to the counter.
func (c *Counter) Add(n uint64) { c.value.Add(n) }

// Value returns the current value.
func (c *Counter) Value() uint64 { return c.value.Load() }

// Histogram tracks a distribution of values (e.g. latency).
type Histogram struct {
	name   string
	help   string
	count  atomic.Uint64
	sum    atomic.Uint64     // sum in microseconds
	bucket [10]atomic.Uint64 // 0.001s, 0.005s, 0.01s, 0.05s, 0.1s, 0.5s, 1s, 5s, 10s, +Inf
}

var histBuckets = [10]float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 1e9}

// NewHistogram registers and returns a new histogram.
func NewHistogram(name, help string) *Histogram {
	h := &Histogram{name: name, help: help}
	defaultRegistry.mu.Lock()
	defaultRegistry.hist[name] = h
	defaultRegistry.mu.Unlock()
	return h
}

// Observe records a value (in seconds).
func (h *Histogram) Observe(seconds float64) {
	usec := uint64(seconds * 1e6)
	h.count.Add(1)
	h.sum.Add(usec)
	for i, bound := range histBuckets {
		if seconds <= bound {
			h.bucket[i].Add(1)
			return
		}
	}
}

// Gauge is a value that can go up or down.
type Gauge struct {
	name  string
	help  string
	value atomic.Int64
}

// NewGauge registers and returns a new gauge.
func NewGauge(name, help string) *Gauge {
	g := &Gauge{name: name, help: help}
	defaultRegistry.mu.Lock()
	defaultRegistry.gauge[name] = g
	defaultRegistry.mu.Unlock()
	return g
}

// Set sets the gauge value.
func (g *Gauge) Set(v int64) { g.value.Store(v) }

// Inc increments by 1.
func (g *Gauge) Inc() { g.value.Add(1) }

// Dec decrements by 1.
func (g *Gauge) Dec() { g.value.Add(-1) }

// Value returns current value.
func (g *Gauge) Value() int64 { return g.value.Load() }

// Handler returns an http.HandlerFunc that renders metrics in Prometheus text format.
func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, Default().Render())
	}
}

// HealthHandler returns an http.HandlerFunc for /healthz with the component name.
func HealthHandler(componentName string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","component":"%s"}`, componentName)
	}
}

// Render renders all metrics in Prometheus text exposition format.
func (r *Registry) Render() string {
	var sb strings.Builder

	r.mu.RLock()
	defer r.mu.RUnlock()

	// Counters
	for _, c := range r.counter {
		fmt.Fprintf(&sb, "# HELP %s %s\n", c.name, c.help)
		fmt.Fprintf(&sb, "# TYPE %s counter\n", c.name)
		fmt.Fprintf(&sb, "%s %d\n", c.name, c.Value())
	}

	// Gauges
	for _, g := range r.gauge {
		fmt.Fprintf(&sb, "# HELP %s %s\n", g.name, g.help)
		fmt.Fprintf(&sb, "# TYPE %s gauge\n", g.name)
		fmt.Fprintf(&sb, "%s %d\n", g.name, g.Value())
	}

	// Histograms
	for _, h := range r.hist {
		fmt.Fprintf(&sb, "# HELP %s %s\n", h.name, h.help)
		fmt.Fprintf(&sb, "# TYPE %s histogram\n", h.name)
		for i, bound := range histBuckets {
			bucketLabel := fmt.Sprintf("%g", bound)
			if bound == 1e9 {
				bucketLabel = "+Inf"
			}
			fmt.Fprintf(&sb, "%s_bucket{le=\"%s\"} %d\n", h.name, bucketLabel, h.bucket[i].Load())
		}
		fmt.Fprintf(&sb, "%s_sum %g\n", h.name, float64(h.sum.Load())/1e6)
		fmt.Fprintf(&sb, "%s_count %d\n", h.name, h.count.Load())
	}

	// Process metrics (Go runtime)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Fprintf(&sb, "# HELP go_goroutines Number of goroutines\n")
	fmt.Fprintf(&sb, "# TYPE go_goroutines gauge\n")
	fmt.Fprintf(&sb, "go_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(&sb, "# HELP go_memstats_alloc_bytes Number of bytes allocated\n")
	fmt.Fprintf(&sb, "# TYPE go_memstats_alloc_bytes gauge\n")
	fmt.Fprintf(&sb, "go_memstats_alloc_bytes %d\n", m.Alloc)

	return sb.String()
}

// Middleware wraps an http.Handler, recording request count and latency.
func Middleware(componentName string, next http.Handler) http.Handler {
	reqCount := NewCounter(
		fmt.Sprintf("aumos_%s_requests_total", strings.ReplaceAll(componentName, "-", "_")),
		"Total HTTP requests",
	)
	reqLatency := NewHistogram(
		fmt.Sprintf("aumos_%s_request_duration_seconds", strings.ReplaceAll(componentName, "-", "_")),
		"HTTP request latency",
	)
	activeReqs := NewGauge(
		fmt.Sprintf("aumos_%s_active_requests", strings.ReplaceAll(componentName, "-", "_")),
		"Active in-flight requests",
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip metrics endpoint itself
		if r.URL.Path == "/metrics" || r.URL.Path == "/healthz" || r.URL.Path == "/versionz" {
			next.ServeHTTP(w, r)
			return
		}
		activeReqs.Inc()
		start := time.Now()
		next.ServeHTTP(w, r)
		elapsed := time.Since(start).Seconds()
		activeReqs.Dec()
		reqCount.Inc()
		reqLatency.Observe(elapsed)
	})
}
