package favicon

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"code.dny.dev/ssrf"
)

// --- SSRF range coverage -----------------------------------------------------
//
// These tests assert the denial decision directly against a production-default
// ssrf.New() guard (exactly what NewFetcher() wires into net.Dialer.Control),
// so they are independent of the fetch pipeline AND of the guard library's
// internal representation: if a dependency bump ever stopped denying one of
// these ranges, this test fails rather than shipping the regression to prod.

// deniedTargets enumerates one representative IP:port for every range Sigil must
// refuse to dial (plan §4.2). network is the protocol the stdlib dialer would
// use for that address family.
var deniedTargets = []struct {
	name    string
	network string
	addr    string
}{
	// IPv4 special-purpose ranges.
	{"unspecified 0.0.0.0", "tcp4", "0.0.0.0:80"},
	{"this-network 0.0.0.0/8", "tcp4", "0.1.2.3:80"},
	{"private 10/8", "tcp4", "10.0.0.1:80"},
	{"CGNAT 100.64/10", "tcp4", "100.64.0.1:80"},
	{"loopback 127/8", "tcp4", "127.0.0.1:80"},
	{"loopback resolver 127.0.0.53", "tcp4", "127.0.0.53:80"},
	{"link-local metadata 169.254.169.254", "tcp4", "169.254.169.254:80"},
	{"link-local 169.254/16", "tcp4", "169.254.0.1:80"},
	{"private 172.16/12", "tcp4", "172.16.0.1:80"},
	{"IETF protocol 192.0.0/24", "tcp4", "192.0.0.1:80"},
	{"TEST-NET-1 192.0.2/24", "tcp4", "192.0.2.1:80"},
	{"6to4 relay 192.88.99/24", "tcp4", "192.88.99.1:80"},
	{"private 192.168/16", "tcp4", "192.168.1.1:80"},
	{"benchmarking 198.18/15", "tcp4", "198.18.0.1:80"},
	{"TEST-NET-2 198.51.100/24", "tcp4", "198.51.100.1:80"},
	{"TEST-NET-3 203.0.113/24", "tcp4", "203.0.113.1:80"},
	{"multicast 224/4", "tcp4", "224.0.0.1:80"},
	{"reserved 240/4", "tcp4", "240.0.0.1:80"},
	{"limited broadcast", "tcp4", "255.255.255.255:80"},

	// IPv6 special-purpose ranges (everything outside 2000::/3, plus carve-outs).
	{"IPv6 loopback ::1", "tcp6", "[::1]:80"},
	{"IPv6 unspecified ::", "tcp6", "[::]:80"},
	{"IPv6 ULA fc00::/7", "tcp6", "[fc00::1]:80"},
	{"IPv6 ULA fd00::/8", "tcp6", "[fd00::1]:80"},
	{"IPv6 link-local fe80::/10", "tcp6", "[fe80::1]:80"},
	{"IPv6 documentation 2001:db8::/32", "tcp6", "[2001:db8::1]:80"},
	{"IPv6 6to4 2002::/16", "tcp6", "[2002::1]:80"},
	{"IPv6 documentation 3fff::/20", "tcp6", "[3fff::1]:80"},
	{"IPv6 multicast ff00::/8", "tcp6", "[ff02::1]:80"},
	{"NAT64 64:ff9b::/96 wrapping 127.0.0.1", "tcp6", "[64:ff9b::7f00:1]:80"},

	// The IPv4-mapped IPv6 bypass class — the reason we validate netip.Addr.
	{"IPv4-mapped metadata ::ffff:169.254.169.254", "tcp6", "[::ffff:169.254.169.254]:80"},
	{"IPv4-mapped loopback ::ffff:127.0.0.1", "tcp6", "[::ffff:127.0.0.1]:80"},
}

func TestGuardDeniesPrivateAndSpecialRanges(t *testing.T) {
	guard := ssrf.New() // exactly the production configuration
	for _, tc := range deniedTargets {
		t.Run(tc.name, func(t *testing.T) {
			if err := guard.Safe(tc.network, tc.addr, nil); err == nil {
				t.Fatalf("guard permitted %s (%s) but it must be denied", tc.addr, tc.network)
			}
		})
	}
}

// TestGuardUnmapsIPv4MappedMetadata is the explicit, named proof that the
// ::ffff: form of the metadata endpoint cannot slip past as global unicast —
// the CVE-2026-49857 bypass class. It asserts at the netip.Addr level so it is
// independent of any host:port string parsing.
func TestGuardUnmapsIPv4MappedMetadata(t *testing.T) {
	guard := ssrf.New()
	mapped := netip.MustParseAddr("::ffff:169.254.169.254")
	if !mapped.Is6() {
		t.Fatalf("expected %s to be an IPv6 (4-in-6) address", mapped)
	}
	if err := guard.SafeAddr(mapped); err == nil {
		t.Fatalf("guard permitted IPv4-mapped metadata address %s; unmap check regressed", mapped)
	}
}

// TestGuardAllowsPublicUnicast is the positive control: the guard must NOT deny
// legitimate public destinations on 80/443, or Sigil would resolve nothing.
func TestGuardAllowsPublicUnicast(t *testing.T) {
	guard := ssrf.New()
	allowed := []struct{ network, addr string }{
		{"tcp4", "1.1.1.1:443"},
		{"tcp4", "8.8.8.8:80"},
		{"tcp6", "[2606:4700:4700::1111]:443"},
	}
	for _, tc := range allowed {
		if err := guard.Safe(tc.network, tc.addr, nil); err != nil {
			t.Fatalf("guard denied public destination %s: %v", tc.addr, err)
		}
	}
}

// TestGuardRejectsNonWebPortsAndProtocols asserts the port and network floors:
// only tcp to 80/443 is permitted, so a redirect to an internal service on an
// odd port, or a non-tcp scheme, cannot get through even for a public IP.
func TestGuardRejectsNonWebPortsAndProtocols(t *testing.T) {
	guard := ssrf.New()
	cases := []struct{ network, addr string }{
		{"tcp4", "1.1.1.1:22"},   // SSH port
		{"tcp4", "1.1.1.1:6379"}, // Redis port
		{"udp4", "1.1.1.1:80"},   // non-tcp network
		{"udp6", "[2606:4700:4700::1111]:443"},
	}
	for _, tc := range cases {
		if err := guard.Safe(tc.network, tc.addr, nil); err == nil {
			t.Fatalf("guard permitted %s on %s but it must be denied", tc.addr, tc.network)
		}
	}
}

// --- Fetch pipeline ----------------------------------------------------------
//
// The pipeline tests need a reachable server. httptest binds loopback on a
// random high port, which the production guard denies (correctly). newTestFetcher
// allows loopback and any port ONLY so the test server is reachable; every other
// range — including 169.254.169.254 used in the redirect test below — stays
// denied, so these tests still exercise the real guard for non-loopback targets.
func newTestFetcher() *Fetcher {
	return NewFetcher(
		ssrf.WithAllowedV4Prefixes(netip.MustParsePrefix("127.0.0.0/8")),
		ssrf.WithAllowedV6Prefixes(netip.MustParsePrefix("::1/128")),
		ssrf.WithAnyPort(),
	)
}

// TestProductionFetcherRejectsLoopbackServer proves the DEFAULT configuration
// refuses an httptest loopback server. httptest binds a random HIGH port, and
// the guard checks the port before the IP, so this specifically exercises the
// port floor (only 80/443) wired into the production transport. Asserted on the
// exact error so it cannot pass for the wrong reason.
func TestProductionFetcherRejectsLoopbackServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(pngWithDimensions(t, 32, 32))
	}))
	defer srv.Close()

	_, err := NewFetcher().Fetch(context.Background(), srv.URL)
	if !errors.Is(err, ssrf.ErrProhibitedPort) {
		t.Fatalf("expected ssrf.ErrProhibitedPort for a random-high-port loopback server, got: %v", err)
	}
}

// TestProductionFetcherDeniesLoopbackIP drives the loopback-IP denial through
// the production fetcher at an ALLOWED port (80/443), so the IP check — not the
// port floor — is the deciding factor. No server listens; the dial is refused
// by the guard before connect. This is the case that would catch a
// WithAllowedV4Prefixes(127.0.0.0/8) leak into NewFetcher().
func TestProductionFetcherDeniesLoopbackIP(t *testing.T) {
	f := NewFetcher()
	for _, raw := range []string{"http://127.0.0.1/", "https://127.0.0.1/", "http://[::1]/"} {
		if _, err := f.Fetch(context.Background(), raw); !errors.Is(err, ssrf.ErrProhibitedIP) {
			t.Fatalf("Fetch(%q): expected ssrf.ErrProhibitedIP, got %v", raw, err)
		}
	}
}

func TestFetchRejectsNonHTTPScheme(t *testing.T) {
	f := newTestFetcher()
	for _, raw := range []string{"file:///etc/passwd", "gopher://127.0.0.1:70/", "ftp://example.com/x"} {
		if _, err := f.Fetch(context.Background(), raw); !errors.Is(err, ErrDisallowedScheme) {
			t.Fatalf("Fetch(%q): want ErrDisallowedScheme, got %v", raw, err)
		}
	}
}

// TestFetchRedirectToDeniedIPBlocked points a redirect at the cloud-metadata
// endpoint. The initial hop is loopback (allowed for the test), the redirect
// target is not — proving redirect hops are re-validated at dial time by the
// shared guarded transport.
func TestFetchRedirectToDeniedIPBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	_, err := newTestFetcher().Fetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("fetch followed a redirect to the metadata endpoint; guard bypassed")
	}
	if !errors.Is(err, ssrf.ErrProhibitedIP) {
		t.Fatalf("expected ssrf.ErrProhibitedIP on the redirected dial, got: %v", err)
	}
}

func TestFetchRedirectToDisallowedScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, "file:///etc/passwd", http.StatusFound)
	}))
	defer srv.Close()

	if _, err := newTestFetcher().Fetch(context.Background(), srv.URL); !errors.Is(err, ErrDisallowedScheme) {
		t.Fatalf("want ErrDisallowedScheme on redirect to file://, got %v", err)
	}
}

func TestFetchTooManyRedirects(t *testing.T) {
	// Always redirect back to root: an infinite chain the cap must break.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	defer srv.Close()

	if _, err := newTestFetcher().Fetch(context.Background(), srv.URL); !errors.Is(err, ErrTooManyRedirects) {
		t.Fatalf("want ErrTooManyRedirects, got %v", err)
	}
}

func TestFetchBodyTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png") // lying header, ignored anyway
		// One byte past the cap: the +1-and-compare trick must catch this.
		w.Write(bytes.Repeat([]byte{0xFF}, maxBodyBytes+1))
	}))
	defer srv.Close()

	if _, err := newTestFetcher().Fetch(context.Background(), srv.URL); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("want ErrBodyTooLarge, got %v", err)
	}
}

func TestFetchRejectsHTMLLabelledAsImage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png") // claims PNG; body is HTML
		w.Write([]byte("<!doctype html><html><body>not an image</body></html>"))
	}))
	defer srv.Close()

	if _, err := newTestFetcher().Fetch(context.Background(), srv.URL); !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("want ErrUnsupportedType for HTML sniffed under a PNG header, got %v", err)
	}
}

func TestFetchRejectsSVG(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><script>evil()</script></svg>`))
	}))
	defer srv.Close()

	if _, err := newTestFetcher().Fetch(context.Background(), srv.URL); !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("want ErrUnsupportedType for SVG, got %v", err)
	}
}

// TestFetchRejectsSVGWithPNGMagic covers the disguise: an SVG payload prefixed
// with the PNG signature sniffs as image/png, but must still be rejected — it is
// not a decodable PNG, so the bomb guard's DecodeConfig fails it. This is the
// backstop proving a script-bearing blob can never reach a re-encode.
func TestFetchRejectsSVGWithPNGMagic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body := append([]byte("\x89PNG\r\n\x1a\n"), []byte(`<svg onload="alert(1)"/>`)...)
		w.Write(body)
	}))
	defer srv.Close()

	if _, err := newTestFetcher().Fetch(context.Background(), srv.URL); err == nil {
		t.Fatal("fetch accepted a non-decodable PNG-magic SVG payload")
	}
}

func TestFetchRejectsDecompressionBomb(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A tiny PNG that declares 100000x100000 pixels: header parses, but the
		// dimension bound must reject it before any pixel buffer is allocated.
		w.Write(pngWithDimensions(t, 100000, 100000))
	}))
	defer srv.Close()

	if _, err := newTestFetcher().Fetch(context.Background(), srv.URL); !errors.Is(err, ErrImageTooLarge) {
		t.Fatalf("want ErrImageTooLarge for a pixel bomb, got %v", err)
	}
}

func TestFetchAcceptsValidPNG(t *testing.T) {
	want := pngWithDimensions(t, 32, 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream") // wrong on purpose
		w.Write(want)
	}))
	defer srv.Close()

	res, err := newTestFetcher().Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch of a valid PNG failed: %v", err)
	}
	if res.ContentType != "image/png" {
		t.Fatalf("sniffed type = %q, want image/png (header was octet-stream)", res.ContentType)
	}
	if !bytes.Equal(res.Body, want) {
		t.Fatal("returned body does not match the served PNG")
	}
}

func TestFetchAcceptsICO(t *testing.T) {
	ico := buildICOWithPNG(t, 32, 32, realPNG(t, 32, 32))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(ico)
	}))
	defer srv.Close()

	res, err := newTestFetcher().Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch of a valid ICO failed: %v", err)
	}
	if res.ContentType != "image/x-icon" {
		t.Fatalf("sniffed type = %q, want image/x-icon", res.ContentType)
	}
}

// TestFetchRejectsICOBomb is the fetch-boundary regression for the review's
// PNG-in-ICO bomb: the directory byte says 256, the embedded IHDR says 100000².
// The fail-closed guard (via the real-dimension ICO reader) must reject it.
func TestFetchRejectsICOBomb(t *testing.T) {
	bomb := buildICOWithPNG(t, 0, 0, pngWithDimensions(t, 100000, 100000))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(bomb)
	}))
	defer srv.Close()

	if _, err := newTestFetcher().Fetch(context.Background(), srv.URL); !errors.Is(err, ErrImageTooLarge) {
		t.Fatalf("want ErrImageTooLarge for a PNG-in-ICO bomb, got %v", err)
	}
}

func TestFetchRejectsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := newTestFetcher().Fetch(context.Background(), srv.URL); !errors.Is(err, ErrUpstreamStatus) {
		t.Fatalf("want ErrUpstreamStatus for a 500, got %v", err)
	}
}

// pngWithDimensions builds the smallest byte sequence that image.DecodeConfig
// will accept as a PNG of the given size: the 8-byte signature plus a
// CRC-correct IHDR chunk (truecolor+alpha, so no palette chunk is required).
func pngWithDimensions(t *testing.T, w, h uint32) []byte {
	t.Helper()
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], w)
	binary.BigEndian.PutUint32(ihdr[4:8], h)
	ihdr[8] = 8 // bit depth
	ihdr[9] = 6 // color type: truecolor + alpha (no PLTE needed)
	// ihdr[10..12] compression/filter/interlace = 0

	var buf bytes.Buffer
	buf.Write([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a})
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(ihdr))); err != nil {
		t.Fatal(err)
	}
	crc := crc32.NewIEEE()
	typeAndData := append([]byte("IHDR"), ihdr...)
	buf.Write(typeAndData)
	crc.Write(typeAndData)
	if err := binary.Write(&buf, binary.BigEndian, crc.Sum32()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Guard against an accidental relaxation of the accepted-type set.
func TestAllowedTypesExcludeMarkup(t *testing.T) {
	for _, forbidden := range []string{"text/html", "text/xml", "image/svg+xml", "text/plain", "application/xml"} {
		if _, ok := allowedSniffedTypes[forbidden]; ok {
			t.Fatalf("%q must not be an accepted content type", forbidden)
		}
	}
	if !strings.HasPrefix(userAgent, "Sigil/") {
		t.Fatalf("unexpected user agent %q", userAgent)
	}
}
