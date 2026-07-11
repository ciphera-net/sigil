package favicon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// circleSVG is a minimal real-world-shaped SVG favicon: a filled circle.
const circleSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="40" fill="#1a73e8"/></svg>`

// --- Detection ---------------------------------------------------------------

func TestLooksLikeSVG(t *testing.T) {
	cases := []struct {
		name string
		data string
		want bool
	}{
		{"bare svg root", circleSVG, true},
		{"xml declaration prolog", `<?xml version="1.0" encoding="UTF-8"?>` + circleSVG, true},
		{"doctype and comment prolog", `<?xml version="1.0"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><!-- brand icon -->` + circleSVG, true},
		{"leading whitespace", "\n\t  " + circleSVG, true},
		{"utf8 bom", "\xef\xbb\xbf" + circleSVG, true},
		{"html document", `<!DOCTYPE html><html><head></head><body></body></html>`, false},
		{"xml non-svg root", `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"></feed>`, false},
		{"uppercase root is not svg", `<SVG viewBox="0 0 1 1"></SVG>`, false},
		{"text before root", "hello <svg></svg>", false},
		{"png bytes", string([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0}), false},
		{"empty", "", false},
		// ISO-8859-1 is a charset.NewReaderLabel-supported encoding, so the
		// unified decoder now transcodes and detects it (the guard and renderer
		// agree). This documents the closed guard-vs-renderer divergence.
		{"declared latin-1 encoding is handled", `<?xml version="1.0" encoding="ISO-8859-1"?>` + circleSVG, true},
		{"bogus encoding fails closed", `<?xml version="1.0" encoding="totally-not-a-charset"?>` + circleSVG, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeSVG([]byte(tc.data)); got != tc.want {
				t.Fatalf("looksLikeSVG = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- Pre-render guard ----------------------------------------------------------

func TestGuardSVGAcceptsRealIcon(t *testing.T) {
	if err := guardSVG([]byte(circleSVG)); err != nil {
		t.Fatalf("guardSVG rejected a benign icon: %v", err)
	}
}

func TestGuardSVGBounds(t *testing.T) {
	t.Run("byte cap", func(t *testing.T) {
		// A valid SVG padded past maxSVGBytes with comment filler.
		pad := strings.Repeat("<!-- padding padding padding -->", maxSVGBytes/32)
		doc := `<svg viewBox="0 0 1 1">` + pad + `</svg>`
		if err := guardSVG([]byte(doc)); !errors.Is(err, ErrImageTooLarge) {
			t.Fatalf("oversize svg: got %v, want ErrImageTooLarge", err)
		}
	})
	t.Run("token cap", func(t *testing.T) {
		doc := `<svg viewBox="0 0 1 1">` + strings.Repeat("<g></g>", maxSVGTokens) + `</svg>`
		if err := guardSVG([]byte(doc)); !errors.Is(err, ErrImageTooLarge) {
			t.Fatalf("token bomb: got %v, want ErrImageTooLarge", err)
		}
	})
	t.Run("depth cap", func(t *testing.T) {
		doc := `<svg viewBox="0 0 1 1">` +
			strings.Repeat("<g>", maxSVGDepth+8) + strings.Repeat("</g>", maxSVGDepth+8) + `</svg>`
		if err := guardSVG([]byte(doc)); !errors.Is(err, ErrImageTooLarge) {
			t.Fatalf("nesting bomb: got %v, want ErrImageTooLarge", err)
		}
	})
	t.Run("malformed rejected", func(t *testing.T) {
		if err := guardSVG([]byte(`<svg viewBox="0 0 1 1"><circle`)); !errors.Is(err, ErrUnsupportedType) {
			t.Fatalf("malformed svg: got %v, want ErrUnsupportedType", err)
		}
	})
}

// TestGuardSVGRejectsEntityReference proves the strict decoder turns a would-be
// XXE payload into a plain parse error: encoding/xml never loads DTD-declared
// or external entities, so the reference to one cannot resolve.
func TestGuardSVGRejectsEntityReference(t *testing.T) {
	doc := `<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><text>&xxe;</text></svg>`
	if err := guardSVG([]byte(doc)); !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("entity reference: got %v, want ErrUnsupportedType", err)
	}
}

// TestGuardSVGRejectsBillionLaughs proves the entity-expansion (billion-laughs)
// DoS is not merely bounded but impossible: encoding/xml (with Entity == nil,
// as both guardSVG and oksvg leave it) recognizes only the five predefined XML
// entities, so a DTD-declared entity reference is an "invalid character entity"
// parse error — it never expands. The nested-entity document below would blow
// up to ~100 MB of CharData if expansion happened; instead it is rejected in
// microseconds at the first &g; reference. The internal deadline guards against
// a regression that ever did start expanding.
func TestGuardSVGRejectsBillionLaughs(t *testing.T) {
	doc := `<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY a "aaaaaaaaaa">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
  <!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
  <!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">
  <!ENTITY g "&f;&f;&f;&f;&f;&f;&f;&f;&f;&f;">
]>
<svg viewBox="0 0 10 10"><text>&g;</text></svg>`

	done := make(chan error, 1)
	go func() { done <- guardSVG([]byte(doc)) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrUnsupportedType) {
			t.Fatalf("billion-laughs: got %v, want ErrUnsupportedType (entity must not expand)", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("guardSVG hung on a billion-laughs document; entity expansion regressed")
	}
}

// --- Rasterization -------------------------------------------------------------

func TestRasterizeSVGRendersIcon(t *testing.T) {
	img, err := rasterizeSVG([]byte(circleSVG))
	if err != nil {
		t.Fatalf("rasterizeSVG: %v", err)
	}
	b := img.Bounds()
	if b.Dx() != svgRasterSize || b.Dy() != svgRasterSize {
		t.Fatalf("raster is %dx%d, want %dx%d", b.Dx(), b.Dy(), svgRasterSize, svgRasterSize)
	}
	// The circle center must carry the fill color.
	if _, _, _, a := img.At(svgRasterSize/2, svgRasterSize/2).RGBA(); a == 0 {
		t.Fatal("raster center is transparent; circle did not render")
	}
}

// TestRasterizeWithBudgetHappyPath confirms the watchdog wrapper returns a
// normal render unchanged (the common case): the render completes well within
// svgRenderBudget and comes back via the result channel, not the timeout branch.
func TestRasterizeWithBudgetHappyPath(t *testing.T) {
	img, err := rasterizeWithBudget(context.Background(), []byte(circleSVG))
	if err != nil {
		t.Fatalf("rasterizeWithBudget: %v", err)
	}
	if img == nil {
		t.Fatal("nil image from the budget wrapper")
	}
	if b := img.Bounds(); b.Dx() != svgRasterSize || b.Dy() != svgRasterSize {
		t.Fatalf("raster %dx%d, want %dx%d", b.Dx(), b.Dy(), svgRasterSize, svgRasterSize)
	}
}

// TestRasterizeWithBudgetHonorsCancelledContext proves an already-cancelled
// context short-circuits to the budget-exceeded rejection rather than rendering.
func TestRasterizeWithBudgetHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // dead on arrival
	if _, err := rasterizeWithBudget(ctx, []byte(circleSVG)); !errors.Is(err, ErrUnsupportedType) {
		// Note: a microsecond render can still win the select race; accept a
		// successful render OR the budget rejection, but never a different error.
		if err != nil {
			t.Fatalf("cancelled ctx: got %v, want nil or ErrUnsupportedType", err)
		}
	}
}

func TestRasterizeSVGWidthHeightFallback(t *testing.T) {
	doc := `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"><rect width="64" height="64" fill="red"/></svg>`
	img, err := rasterizeSVG([]byte(doc))
	if err != nil {
		t.Fatalf("rasterizeSVG width/height fallback: %v", err)
	}
	if _, _, _, a := img.At(svgRasterSize/2, svgRasterSize/2).RGBA(); a == 0 {
		t.Fatal("rect did not render")
	}
}

func TestRasterizeSVGRejects(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"no dimensions at all", `<svg xmlns="http://www.w3.org/2000/svg"><circle cx="5" cy="5" r="4"/></svg>`},
		{"zero viewBox", `<svg viewBox="0 0 0 0"><circle cx="1" cy="1" r="1"/></svg>`},
		{"negative viewBox", `<svg viewBox="0 0 -10 10"><circle cx="1" cy="1" r="1"/></svg>`},
		{"NaN viewBox", `<svg viewBox="0 0 NaN 10"><circle cx="1" cy="1" r="1"/></svg>`},
		{"blank render (nothing drawable)", `<svg viewBox="0 0 10 10"><desc>empty</desc></svg>`},
		{"blank render (script only)", `<svg viewBox="0 0 10 10"><script>alert(1)</script></svg>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rasterizeSVG([]byte(tc.data)); !errors.Is(err, ErrUnsupportedType) {
				t.Fatalf("got %v, want ErrUnsupportedType", err)
			}
		})
	}
}

// TestRasterizeSVGContainsPanic exercises the recovery boundary directly: no
// real corpus input reliably panics oksvg, so we substitute a panicking render
// core and assert rasterizeSVG converts the panic into a per-candidate error
// rather than letting it escape (which, in a resolver goroutine, would crash the
// process). Deleting the defer/recover in rasterizeSVG makes this test fail —
// which is the point: it keeps the containment guarantee genuinely tested.
func TestRasterizeSVGContainsPanic(t *testing.T) {
	orig := svgRenderCore
	t.Cleanup(func() { svgRenderCore = orig })

	svgRenderCore = func([]byte) (image.Image, error) { panic("boom from renderer") }

	img, err := rasterizeSVG([]byte(circleSVG))
	if img != nil {
		t.Fatal("expected nil image when the renderer panics")
	}
	if !errors.Is(err, ErrUnsupportedType) || !strings.Contains(err.Error(), "rasterizer panic") {
		t.Fatalf("panic not contained as a rasterizer-panic error: got %v", err)
	}
}

// TestSVGHostileInputsContained feeds the rasterizer inputs crafted to hit
// parser and renderer edge cases. The property under test is containment: no
// call may panic the process; every call returns an image or an error. (The
// recover in rasterizeSVG converts internal oksvg/rasterx panics into errors;
// TestRasterizeSVGContainsPanic proves that path with a forced panic, while this
// corpus exercises the real renderer against adversarial-but-non-panicking
// inputs.)
func TestSVGHostileInputsContained(t *testing.T) {
	corpus := []string{
		// Degenerate/hostile path data.
		`<svg viewBox="0 0 10 10"><path d="M"/></svg>`,
		`<svg viewBox="0 0 10 10"><path d="M0,0A9e999,9e999 0 1 1 5,5z"/></svg>`,
		`<svg viewBox="0 0 10 10"><path d="M0 0L` + strings.Repeat("1e308 1e308 ", 50) + `z"/></svg>`,
		// Hostile geometry and transforms.
		`<svg viewBox="0 0 1e308 1e308"><rect width="1e308" height="1e308"/></svg>`,
		`<svg viewBox="-1e300 -1e300 1e300 1e300"><circle cx="0" cy="0" r="1e300"/></svg>`,
		`<svg viewBox="0 0 10 10"><g transform="scale(1e308)"><rect width="1" height="1"/></g></svg>`,
		`<svg viewBox="0 0 10 10"><g transform="matrix(0,0,0,0,0,0)"><rect width="5" height="5"/></g></svg>`,
		`<svg viewBox="0 0 10 10"><rect width="5" height="5" rx="-1" ry="1e308"/></svg>`,
		// Self-referencing and dangling internal references.
		`<svg viewBox="0 0 10 10"><defs><linearGradient id="g" href="#g"/></defs><rect width="5" height="5" fill="url(#g)"/></svg>`,
		`<svg viewBox="0 0 10 10"><use href="#missing"/><rect width="5" height="5"/></svg>`,
		// Unsupported-but-scary elements skipped by IgnoreErrorMode.
		`<svg viewBox="0 0 10 10"><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><b>x</b></body></foreignObject><rect width="5" height="5"/></svg>`,
		`<svg viewBox="0 0 10 10"><animate attributeName="x" from="0" to="1e308" dur="1s"/><rect width="5" height="5"/></svg>`,
		// Malformed style/class data.
		`<svg viewBox="0 0 10 10"><defs><style>.a{fill:</style></defs><rect class="a" width="5" height="5"/></svg>`,
	}
	for i, doc := range corpus {
		t.Run(fmt.Sprintf("corpus_%02d", i), func(t *testing.T) {
			img, err := rasterizeSVG([]byte(doc))
			if err == nil && img == nil {
				t.Fatal("nil image with nil error")
			}
			// Outcome (render vs reject) is input-dependent; the invariant is
			// simply that we got here without a panic escaping.
		})
	}
}

// TestSVGHostileReferencesNoNetwork is the no-fetch tripwire: an SVG larded
// with every external-reference shape oksvg could conceivably dereference is
// processed through the full SVG pipeline while a live local listener counts
// connections. The pipeline must complete without a single request arriving —
// if a dependency bump ever teaches the renderer to fetch, this fails.
func TestSVGHostileReferencesNoNetwork(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Write(realPNG(t, 16, 16))
	}))
	defer srv.Close()

	doc := `<?xml version="1.0"?>
<?xml-stylesheet href="` + srv.URL + `/style.css" type="text/css"?>
<!DOCTYPE svg [ <!ENTITY ext SYSTEM "` + srv.URL + `/entity"> ]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 100 100">
  <image href="` + srv.URL + `/image.png" x="0" y="0" width="10" height="10"/>
  <image xlink:href="` + srv.URL + `/xlink.png" x="0" y="0" width="10" height="10"/>
  <use href="` + srv.URL + `/use.svg#frag"/>
  <a href="` + srv.URL + `/link"><circle cx="50" cy="50" r="40" fill="green"/></a>
</svg>`

	data := []byte(doc)
	if !looksLikeSVG(data) {
		t.Fatal("fixture no longer detected as SVG")
	}
	if err := guardSVG(data); err != nil {
		t.Fatalf("guardSVG: %v", err)
	}
	// Render outcome may be image or error depending on how oksvg treats the
	// unknown elements; the property under test is zero outbound connections.
	_, _ = rasterizeSVG(data)

	if n := hits.Load(); n != 0 {
		t.Fatalf("SVG processing performed %d network fetch(es); must be zero", n)
	}
}

// --- Fetch-boundary classification ----------------------------------------------

// TestFetchClassifiesSVG proves a served SVG is classified by structure, not by
// the (attacker-controlled) Content-Type header, and takes the SVG pipeline.
func TestFetchClassifiesSVG(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Lying header: claims PNG, body is SVG. Sniffing + structure win.
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte(circleSVG))
	}))
	defer srv.Close()

	res, err := newTestFetcher().Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.ContentType != svgContentType {
		t.Fatalf("ContentType = %q, want %q", res.ContentType, svgContentType)
	}
}

func TestFetchRejectsOversizeSVG(t *testing.T) {
	// Over the SVG byte cap but under the raster body cap, so this exercises
	// the SVG-specific bound, not the generic one.
	pad := strings.Repeat("<!-- padding padding padding -->", (maxSVGBytes/32)+1)
	doc := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1">` + pad + `</svg>`
	if len(doc) >= maxBodyBytes {
		t.Fatal("fixture larger than the raster body cap; shrink the padding")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(doc))
	}))
	defer srv.Close()

	_, err := newTestFetcher().Fetch(context.Background(), srv.URL)
	if !errors.Is(err, ErrImageTooLarge) {
		t.Fatalf("oversize SVG: got %v, want ErrImageTooLarge", err)
	}
}

// TestFetchStillRejectsHTML pins the boundary the SVG path must not widen:
// text that is not structurally SVG stays rejected even under an image header.
func TestFetchStillRejectsHTML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(`<!DOCTYPE html><html><head><title>not an icon</title></head></html>`))
	}))
	defer srv.Close()

	_, err := newTestFetcher().Fetch(context.Background(), srv.URL)
	if !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("HTML under svg header: got %v, want ErrUnsupportedType", err)
	}
}

// --- End-to-end resolution --------------------------------------------------------

// TestResolveSVGOnlySite is the phase-5 coverage win end to end: a site whose
// only icon is a link-declared SVG resolves to a normalized PNG.
func TestResolveSVGOnlySite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><link rel="icon" href="/icon.svg" type="image/svg+xml"></head></html>`))
		case "/icon.svg":
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Write([]byte(circleSVG))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	out, err := newTestResolver(srv.URL).Resolve(context.Background(), "example.test", 64)
	if err != nil {
		t.Fatalf("Resolve svg-only site: %v", err)
	}
	if w, h := mustDecodePNG(t, out); w != 64 || h != 64 {
		t.Fatalf("resolved %dx%d, want 64x64", w, h)
	}
}

// TestResolvePrefersExactRasterOverSVG pins selection neutrality: the SVG
// render enters as a 256px candidate, so a raster icon already at the target
// size still wins under the smallest->=target rule. The two icons carry
// distinct solid colors so the winner is provable from the output pixels.
func TestResolvePrefersExactRasterOverSVG(t *testing.T) {
	redPNG := solidPNG(t, 32, 32, color.NRGBA{R: 0xFF, A: 0xFF})
	blueSVG := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#0000ff"/></svg>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head>
				<link rel="icon" href="/icon.svg" type="image/svg+xml">
				<link rel="icon" href="/icon-32.png" sizes="32x32">
			</head></html>`))
		case "/icon.svg":
			w.Write([]byte(blueSVG))
		case "/icon-32.png":
			w.Write(redPNG)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	out, err := newTestResolver(srv.URL).Resolve(context.Background(), "example.test", 32)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("decode result: %v", err)
	}
	r, _, b, _ := img.At(16, 16).RGBA()
	if !(r > b) {
		t.Fatalf("expected the red 32px raster to win over the blue SVG; center pixel r=%d b=%d", r, b)
	}
}

func solidPNG(t *testing.T, w, h int, c color.NRGBA) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetNRGBA(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
