package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCounter(t *testing.T) {
	c := NewCounter("test_counter_total", "test")
	c.Inc()
	c.Inc()
	c.Add(5)
	if c.Value() != 7 {
		t.Errorf("counter = %d, want 7", c.Value())
	}
}

func TestGauge(t *testing.T) {
	g := NewGauge("test_gauge", "test")
	g.Set(42)
	if g.Value() != 42 {
		t.Errorf("gauge = %d, want 42", g.Value())
	}
	g.Inc()
	g.Dec()
	if g.Value() != 42 {
		t.Errorf("gauge after inc/dec = %d, want 42", g.Value())
	}
}

func TestHistogram(t *testing.T) {
	h := NewHistogram("test_hist_seconds", "test")
	h.Observe(0.001)
	h.Observe(0.01)
	h.Observe(0.5)
	h.Observe(5.0)
	if h.count.Load() != 4 {
		t.Errorf("hist count = %d, want 4", h.count.Load())
	}
}

func TestHandlerRendersPrometheusFormat(t *testing.T) {
	c := NewCounter("test_render_total", "test render counter")
	c.Inc()
	g := NewGauge("test_render_gauge", "test render gauge")
	g.Set(99)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "test_render_total") {
		t.Error("body missing counter")
	}
	if !strings.Contains(body, "test_render_gauge 99") {
		t.Error("body missing gauge value")
	}
	if !strings.Contains(body, "# TYPE") {
		t.Error("body missing TYPE line")
	}
	if !strings.Contains(body, "# HELP") {
		t.Error("body missing HELP line")
	}
}

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	HealthHandler("agent-identity").ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "agent-identity") {
		t.Error("body missing component name")
	}
	if !strings.Contains(body, "ok") {
		t.Error("body missing status ok")
	}
}

func TestMiddlewareRecordsMetrics(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := Middleware("test-svc", handler)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	// Check metrics were recorded
	body := Default().Render()
	if !strings.Contains(body, "test_svc_requests_total") {
		t.Error("metrics missing request count")
	}
}

func TestMiddlewareSkipsHealthEndpoints(t *testing.T) {
	calls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	wrapped := Middleware("test-skip", handler)

	// /healthz should not increment metrics
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	body := Default().Render()
	if strings.Contains(body, "test_skip_requests_total 1") {
		t.Error("healthz request should not be counted in metrics")
	}
}

func TestRenderIncludesGoRuntimeMetrics(t *testing.T) {
	body := Default().Render()
	if !strings.Contains(body, "go_goroutines") {
		t.Error("missing go_goroutines")
	}
	if !strings.Contains(body, "go_memstats_alloc_bytes") {
		t.Error("missing go_memstats_alloc_bytes")
	}
}
