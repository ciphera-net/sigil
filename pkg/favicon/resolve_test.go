package favicon

import (
	"bytes"
	"context"
	"errors"
	"image/png"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync/atomic"
	"testing"
)

// newTestResolver builds a resolver whose fetcher can reach loopback (so an
// httptest server stands in for a real site) and whose origins point at srv.
func newTestResolver(srvURL string) *Resolver {
	r := NewResolver(newTestFetcher(), NewMemoryCache())
	r.origins = func(string) []string { return []string{srvURL} }
	return r
}

func mustDecodePNG(t *testing.T, b []byte) (int, int) {
	t.Helper()
	cfg, err := png.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("result is not a valid PNG: %v", err)
	}
	return cfg.Width, cfg.Height
}

func TestResolveViaLinkRel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><link rel="icon" href="/brand.png"></head></html>`))
		case "/brand.png":
			w.Write(realPNG(t, 64, 64))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	out, err := newTestResolver(srv.URL).Resolve(context.Background(), "example.test", 32)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if w, h := mustDecodePNG(t, out); w != 32 || h != 32 {
		t.Fatalf("resolved icon %dx%d, want 32x32", w, h)
	}
}

func TestResolveWellKnownFallback(t *testing.T) {
	// Homepage declares no icon; the icon exists only at the well-known path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>no icon link</title></head></html>`))
		case "/favicon.ico":
			w.Write(buildICOWithPNG(t, 32, 32, realPNG(t, 32, 32)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	out, err := newTestResolver(srv.URL).Resolve(context.Background(), "example.test", 32)
	if err != nil {
		t.Fatalf("Resolve via well-known: %v", err)
	}
	if w, h := mustDecodePNG(t, out); w != 32 || h != 32 {
		t.Fatalf("resolved %dx%d, want 32x32", w, h)
	}
}

func TestResolveAppleTouchDownscaled(t *testing.T) {
	// Only an apple-touch-icon (180x180) is offered; requesting 64 must downscale.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<head><link rel="apple-touch-icon" href="/at.png"></head>`))
		case "/at.png":
			w.Write(realPNG(t, 180, 180))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	out, err := newTestResolver(srv.URL).Resolve(context.Background(), "example.test", 64)
	if err != nil {
		t.Fatalf("Resolve apple-touch: %v", err)
	}
	if w, h := mustDecodePNG(t, out); w != 64 || h != 64 {
		t.Fatalf("resolved %dx%d, want 64x64", w, h)
	}
}

// TestResolveNegativeAndCached mirrors the id.ciphera.net fixture: no icon
// anywhere. Resolve returns ErrNoIcon, negatively caches it, and a second call
// is served from cache without touching the origin again.
func TestResolveNegativeAndCached(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	res := newTestResolver(srv.URL)
	if _, err := res.Resolve(context.Background(), "example.test", 32); !errors.Is(err, ErrNoIcon) {
		t.Fatalf("first Resolve: want ErrNoIcon, got %v", err)
	}
	afterFirst := atomic.LoadInt32(&hits)
	if afterFirst == 0 {
		t.Fatal("expected the origin to be probed on the first resolve")
	}

	if _, err := res.Resolve(context.Background(), "example.test", 32); !errors.Is(err, ErrNoIcon) {
		t.Fatalf("second Resolve: want ErrNoIcon, got %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != afterFirst {
		t.Fatalf("second resolve hit the origin (%d -> %d); negative cache not used", afterFirst, got)
	}
}

// TestResolveFetchesSVGCandidate: since phase 5 an SVG link is a real
// candidate, so it IS fetched — and when it turns out to be undrawable (this
// fixture has no viewBox and no content), it is rejected per-candidate and
// resolution still succeeds from the PNG. One bad SVG must never sink a
// resolve.
func TestResolveFetchesSVGCandidate(t *testing.T) {
	var svgFetched int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<head>
				<link rel="icon" href="/icon.svg">
				<link rel="icon" href="/icon.png">
			</head>`))
		case "/icon.svg":
			atomic.AddInt32(&svgFetched, 1)
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`))
		case "/icon.png":
			w.Write(realPNG(t, 48, 48))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	out, err := newTestResolver(srv.URL).Resolve(context.Background(), "example.test", 32)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := atomic.LoadInt32(&svgFetched); got != 1 {
		t.Fatalf("the SVG candidate must be fetched exactly once, got %d", got)
	}
	if w, h := mustDecodePNG(t, out); w != 32 || h != 32 {
		t.Fatalf("resolved %dx%d, want 32x32", w, h)
	}
}

// --- unit: link extraction & domain validation -------------------------------

func TestParseIconLinks(t *testing.T) {
	doc := []byte(`<html><head>
		<base href="https://cdn.example.com/assets/">
		<link rel="icon" href="favicon.png">
		<link rel="shortcut icon" href="/legacy.ico">
		<link rel="apple-touch-icon" href="https://other.example.com/at.png">
		<link rel="mask-icon" href="/mask.svg">
		<link rel="icon" href="/vector.svg">
		<link rel="stylesheet" href="/style.css">
	</head></html>`)

	got := parseIconLinks(doc, "https://example.com/page")
	sort.Strings(got)

	want := []string{
		"https://cdn.example.com/assets/favicon.png", // relative, resolved against <base>
		"https://cdn.example.com/legacy.ico",         // root-relative against base host
		"https://cdn.example.com/vector.svg",         // SVG is a first-class candidate since phase 5
		"https://other.example.com/at.png",           // absolute
	}
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("got %d links %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("link %d = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestValidDomain(t *testing.T) {
	ok := []string{"example.com", "id.ciphera.net", "a.co", "xn--80ak6aa92e.com", "sub.domain.example.org"}
	bad := []string{
		"", "localhost", "no-dot", "example.com/path", "http://example.com",
		"example.com:8080", "192.168.1.1", "-lead.com", "trail-.com", "a..b",
		"exa mple.com", "under_score.com",
	}
	for _, d := range ok {
		if !validDomain(d) {
			t.Fatalf("validDomain(%q) = false, want true", d)
		}
	}
	for _, d := range bad {
		if validDomain(d) {
			t.Fatalf("validDomain(%q) = true, want false", d)
		}
	}
}
