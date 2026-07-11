package favicon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"code.dny.dev/ssrf"

	// Register the raster decoders so image.DecodeConfig can read a candidate's
	// header for the decompression-bomb guard below. The ICO codec is registered
	// by image.go with a decoder that reports the embedded image's REAL declared
	// dimensions — besticon's own DecodeConfig reports only the <=256 icon-dir
	// byte, which would let a PNG-in-ICO bomb slip past this guard.
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"

	_ "golang.org/x/image/webp"
)

const (
	// maxRedirects caps redirect depth. A favicon URL has no legitimate reason
	// to bounce more than a couple of times; a long chain is a red flag.
	maxRedirects = 3

	// maxBodyBytes caps an icon response body. A real favicon is well under
	// 100 KB; 1 MiB is generous headroom for large multi-resolution ICO/PNG
	// files while bounding memory per request. Content-Length is never trusted
	// (it is attacker-controlled and absent under chunked transfer).
	maxBodyBytes = 1 << 20

	// maxHTMLBytes caps a homepage read during icon discovery. Only the <head>
	// is needed and it lives near the top, so 512 KiB is ample without buffering
	// a large document.
	maxHTMLBytes = 512 << 10

	// acceptHeader is sent on every request; some servers 403 an empty Accept.
	acceptHeader = "image/png,image/x-icon,image/*;q=0.8,text/html;q=0.7,*/*;q=0.5"

	// maxImageDimension / maxImagePixels bound a decoded image's declared size
	// before any pixels are allocated, defeating decompression bombs: a sub-100
	// KB PNG/GIF can declare billions of pixels and OOM the process
	// (golang/go#5050). 1024x1024 is generous for a favicon.
	maxImageDimension = 1024
	maxImagePixels    = maxImageDimension * maxImageDimension

	// Layered timeouts — any single one is insufficient on its own. The caller's
	// context deadline bounds a stalled body read on top of these.
	dialTimeout           = 3 * time.Second
	tlsHandshakeTimeout   = 5 * time.Second
	responseHeaderTimeout = 5 * time.Second
	requestTimeout        = 8 * time.Second

	// sniffLen is how many leading bytes http.DetectContentType inspects.
	sniffLen = 512

	userAgent = "Sigil/1.0 (+https://github.com/ciphera-net/sigil)"
)

// Fetch-boundary errors. They are sentinels so callers (and the test suite) can
// assert the exact reason a candidate was rejected with errors.Is.
var (
	// ErrDisallowedScheme is returned for an initial URL, or a redirect target,
	// whose scheme is not http or https.
	ErrDisallowedScheme = errors.New("favicon: disallowed URL scheme")
	// ErrMissingHost is returned when a URL has no host component.
	ErrMissingHost = errors.New("favicon: URL has no host")
	// ErrTooManyRedirects is returned when a fetch exceeds maxRedirects hops.
	ErrTooManyRedirects = errors.New("favicon: too many redirects")
	// ErrBodyTooLarge is returned when the response body exceeds maxBodyBytes.
	ErrBodyTooLarge = errors.New("favicon: response body exceeds size cap")
	// ErrEmptyResponse is returned when the response body is empty.
	ErrEmptyResponse = errors.New("favicon: empty response body")
	// ErrUnsupportedType is returned when the sniffed content type is not an
	// accepted raster image type (this is where SVG/HTML/XML are rejected).
	ErrUnsupportedType = errors.New("favicon: unsupported content type")
	// ErrImageTooLarge is returned when a decoded image's declared dimensions
	// exceed the pixel bound.
	ErrImageTooLarge = errors.New("favicon: image dimensions exceed cap")
	// ErrUpstreamStatus is returned when the upstream responds with a non-200
	// status after redirects are resolved.
	ErrUpstreamStatus = errors.New("favicon: non-200 upstream status")
)

// allowedSniffedTypes is the set of content types (as produced by
// http.DetectContentType) we will accept. Anything else — text/html, text/xml,
// image/svg+xml, image/bmp, application/*, ... — is rejected. Note that
// DetectContentType reports ICO as "image/x-icon".
var allowedSniffedTypes = map[string]struct{}{
	"image/png":                {},
	"image/x-icon":             {},
	"image/vnd.microsoft.icon": {},
	"image/gif":                {},
	"image/jpeg":               {},
	"image/webp":               {},
}

// FetchResult is a validated favicon candidate. Body holds the original,
// still-encoded image bytes (decoding and re-encoding happen in the image
// pipeline); ContentType is the type decided by sniffing, not the header.
type FetchResult struct {
	Body        []byte
	ContentType string
}

// Fetcher performs SSRF-guarded HTTP GETs for favicon candidates. A Fetcher is
// safe for concurrent use and should be reused across requests.
type Fetcher struct {
	client *http.Client
}

// NewFetcher builds a Fetcher whose transport will only ever connect to public
// unicast addresses on ports 80/443 (the default policy of code.dny.dev/ssrf).
//
// guardOpts are applied to the underlying dial guard. Production passes NONE —
// the safe defaults are the whole point. The options exist so tests can allow
// loopback (so an httptest server is reachable) without weakening the
// production configuration. Never pass loosening options outside tests.
func NewFetcher(guardOpts ...ssrf.Option) *Fetcher {
	guard := ssrf.New(guardOpts...)

	dialer := &net.Dialer{
		Timeout: dialTimeout,
		// Control runs after DNS resolution and immediately before connect, once
		// per resolved candidate IP, with the literal IP:port about to be dialed.
		// Validating here (rather than pre-resolving the name ourselves) closes
		// the resolve-then-connect TOCTOU gap and re-checks every redirect hop
		// automatically, because the same transport dials each one.
		Control: guard.Safe,
	}

	transport := &http.Transport{
		// Explicitly no proxy. With the default (ProxyFromEnvironment), an
		// HTTP(S)_PROXY in the environment would make the dialer connect to the
		// proxy's IP and tunnel to the real target — the guard would then only
		// see the proxy address, a complete bypass of every IP check below.
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		// One connection per fetch: hosts rarely repeat within a resolution, and
		// this keeps each request's dial (and thus each guard check) independent.
		DisableKeepAlives: true,
	}

	return &Fetcher{
		client: &http.Client{
			Transport:     transport,
			Timeout:       requestTimeout,
			CheckRedirect: checkRedirect,
		},
	}
}

// checkRedirect caps redirect depth and enforces the http/https scheme allowlist
// on each hop (blocking a same-origin-looking URL that 302s to file://,
// gopher://, etc.). The IP-level re-validation is handled by the shared guarded
// transport, not here — which is exactly why the redirect must never be followed
// by a different client.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return ErrTooManyRedirects
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return fmt.Errorf("%w: %q", ErrDisallowedScheme, req.URL.Scheme)
	}
	return nil
}

// do performs a guarded GET and returns the response body read under a hard
// byte cap. It applies the scheme check, the dial-time SSRF guard, redirect
// policy, and the status check (all via the shared client), but layers on NO
// content-type or image validation — callers add that. limit is the byte cap;
// the body is read one byte past it so an oversize response is rejected rather
// than silently truncated.
func (f *Fetcher) do(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("favicon: parse url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: %q", ErrDisallowedScheme, u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("%w: %q", ErrMissingHost, rawURL)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("favicon: build request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", acceptHeader)

	resp, err := f.client.Do(req)
	if err != nil {
		// Includes dial-time guard rejections (ssrf.ErrProhibited*), redirect-cap
		// and scheme errors, and timeouts — all surfaced, never swallowed.
		return nil, err
	}
	defer func() {
		// Drain a bounded amount so the socket can close cleanly, then close.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d", ErrUpstreamStatus, resp.StatusCode)
	}

	// Read one byte past the limit so we can distinguish "exactly at the cap"
	// from "over the cap": io.LimitReader silently truncates otherwise, which
	// would let an oversized body through as a valid-looking short read.
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("favicon: read body: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, ErrBodyTooLarge
	}
	if len(body) == 0 {
		return nil, ErrEmptyResponse
	}
	return body, nil
}

// Fetch retrieves an icon candidate at rawURL and returns the validated bytes.
// rawURL must be an absolute http/https URL. Every property of the response —
// resolved IP, redirect chain, size, content type, and declared image
// dimensions — is treated as hostile and bounded. The returned bytes are the
// original encoding; decoding/re-encoding happen in the image pipeline.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) (*FetchResult, error) {
	body, err := f.do(ctx, rawURL, maxBodyBytes)
	if err != nil {
		return nil, err
	}

	// Content type by sniffing the bytes, never the response header (a hostile
	// server can label an HTML page or an SVG as image/png).
	sniffed := sniffType(body)
	if _, ok := allowedSniffedTypes[sniffed]; !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedType, sniffed)
	}

	// Decompression-bomb guard: bound the declared dimensions before full decode.
	if err := guardImageSize(sniffed, body); err != nil {
		return nil, err
	}

	return &FetchResult{Body: body, ContentType: sniffed}, nil
}

// FetchHTML retrieves an HTML document (a site homepage) for icon discovery. It
// uses the same SSRF-guarded client as Fetch but applies no image allowlist;
// the body is capped tighter (only the <head> is needed) and the sniffed type
// must be text/HTML/XML so a hostile server can't make us buffer a large binary
// under an HTML content-type header.
func (f *Fetcher) FetchHTML(ctx context.Context, rawURL string) ([]byte, error) {
	body, err := f.do(ctx, rawURL, maxHTMLBytes)
	if err != nil {
		return nil, err
	}
	sniffed := sniffType(body)
	if !strings.HasPrefix(sniffed, "text/") && sniffed != "application/xml" {
		return nil, fmt.Errorf("%w: %s (expected html)", ErrUnsupportedType, sniffed)
	}
	return body, nil
}

// sniffType returns the WHATWG-sniffed media type (from the first 512 bytes),
// stripped of any parameters. The response's declared Content-Type header is
// deliberately ignored.
func sniffType(body []byte) string {
	n := len(body)
	if n > sniffLen {
		n = sniffLen
	}
	ct := http.DetectContentType(body[:n])
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(ct)
}

// guardImageSize rejects images whose declared dimensions exceed the pixel
// bound. It reads only headers, so no pixel buffer is ever allocated for a
// hostile declaration.
//
// It fails CLOSED. The body has already passed the sniff allowlist, and every
// accepted type has a bounded reader here. So a header that cannot be read means
// the bytes are malformed or a disguise — an SVG behind a PNG magic prefix,
// arbitrary content behind a 4-byte icon prefix — and is rejected, never
// deferred. (An earlier version treated image.ErrFormat as a safe deferral,
// which silently waved ICO through with no dimension bound at all.)
//
// ICO is handled separately: besticon's DecodeConfig reports only the <=256
// icon-directory byte, not the embedded image's real size, so a PNG-in-ICO bomb
// would read as 256 here and then OOM at decode. icoBestEntryDims (image.go)
// reads the selected entry's REAL declared dimensions instead.
func guardImageSize(sniffed string, body []byte) error {
	if sniffed == "image/x-icon" || sniffed == "image/vnd.microsoft.icon" {
		_, _, err := icoBestEntryDims(body)
		return err
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: undecodable header: %v", ErrUnsupportedType, err)
	}
	return boundDims(cfg.Width, cfg.Height)
}
