package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// These exercise the HTTP layer's own logic — request validation, status
// mapping, and the metrics exposition — for the cases reachable without any
// network. The resolver's resolution behavior is covered in package favicon.

func TestHandleIconRejectsBadSize(t *testing.T) {
	rr := httptest.NewRecorder()
	newServer().handleIcon(rr, httptest.NewRequest(http.MethodGet, "/icon?domain=example.com&sz=999", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad size: status = %d, want 400", rr.Code)
	}
}

func TestHandleIconRejectsInvalidDomain(t *testing.T) {
	// A domain with no dot fails validation before any network call, so this is
	// hermetic: the resolver returns ErrInvalidDomain and the layer maps it to 400.
	for _, domain := range []string{"localhost", "not-a-domain", "http://x.com", "10.0.0.1"} {
		rr := httptest.NewRecorder()
		newServer().handleIcon(rr, httptest.NewRequest(http.MethodGet, "/icon?domain="+domain+"&sz=32", nil))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("domain %q: status = %d, want 400", domain, rr.Code)
		}
	}
}

func TestHandleHealth(t *testing.T) {
	rr := httptest.NewRecorder()
	newServer().handleHealth(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "ok") {
		t.Fatalf("health = %d %q, want 200 ok", rr.Code, rr.Body.String())
	}
}

func TestHandleMetricsExposition(t *testing.T) {
	s := newServer()
	// Drive one bad-request through so a counter is non-zero.
	s.handleIcon(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/icon?domain=example.com&sz=7", nil))

	rr := httptest.NewRecorder()
	s.handleMetrics(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rr.Body.String()

	for _, want := range []string{
		"sigil_requests_total",
		`sigil_results_total{result="bad_request"} 1`,
		"sigil_resolve_duration_seconds_count",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics output missing %q\n---\n%s", want, body)
		}
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("metrics content-type = %q, want text/plain", ct)
	}
}
