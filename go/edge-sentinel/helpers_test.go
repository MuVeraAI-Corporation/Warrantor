package edgesentinel

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// newRequest issues a request against h and returns the recorder. Extracted as a helper so the
// tests read at one line each.
func newRequest(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
