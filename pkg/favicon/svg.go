package favicon

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"image"
	"io"
	"math"
	"time"

	"github.com/srwiley/oksvg"
	"github.com/srwiley/rasterx"
	"golang.org/x/net/html/charset"
)

// SVG support (phase 5) re-admits a content class v1 rejected outright, so its
// boundaries are explicit:
//
//   - The original SVG bytes are NEVER served, stored, or echoed — they exist
//     only as input to a pure-Go rasterizer whose output is a fixed-size pixel
//     buffer, re-encoded to PNG like every other candidate. The XSS class
//     (script/onload/foreignObject in served markup) dies there: the output
//     contains pixels, not markup.
//   - Parsing uses encoding/xml, which has NO code path that loads external
//     entities, DTDs, or any URL — the XXE / second-order-SSRF class cannot be
//     expressed. The one reader oksvg installs (CharsetReader) is pure byte
//     transcoding. Undeclared entity references fail the strict decoder.
//   - oksvg implements no <image> or external-href handling at all, and imports
//     no network capability; hostile references are inert. A regression test
//     points such references at a live listener and asserts zero connections.
//   - Resource use is bounded BEFORE rendering: input bytes, XML token count,
//     and nesting depth are capped, and the raster target is a fixed
//     svgRasterSize square that the SVG's own declared geometry can never
//     inflate. The rasterizer runs inside the resolver's decode semaphore like
//     any other candidate decode.
//   - oksvg/rasterx can panic on adversarial input; rasterizeSVG converts any
//     panic into a per-candidate error so one hostile SVG cannot take down the
//     process.
const (
	// maxSVGBytes caps SVG input. Real SVG favicons are a few KB of markup, so
	// 64 KiB is ample headroom — but the cap is sized primarily as a DoS bound,
	// not a coverage one: it is what limits the work a SINGLE element (a <path>
	// "d" of hundreds of thousands of coordinates, a <polygon> points list, a
	// long arc/bezier chain) can push through the rasterizer. Measured, a
	// 64 KiB worst-case path/arc bomb rasterizes in tens of ms; a 256 KiB one
	// took hundreds. See maxSVGTokens for the many-small-elements bound.
	maxSVGBytes = 64 << 10

	// maxSVGTokens caps the total XML tokens a document may contain. Beyond
	// bounding oksvg's parse work, this is the bound on the OTHER DoS vector:
	// many full-canvas overdraw elements, each cheap to parse but each doing a
	// full 256x256 scan-conversion pass. Measured, ~1000 full-canvas fills
	// rasterize in ~180 ms; the original 10k allowed ~2 s. Real icon SVGs run
	// well under a few hundred elements, so 2500 is generous headroom.
	maxSVGTokens = 2500

	// maxSVGDepth caps element nesting. Real icons nest a handful of groups
	// deep; deeply nested documents are only ever crafted.
	maxSVGDepth = 64

	// svgRenderBudget is a hard wall-clock ceiling on a single rasterization.
	// oksvg's Draw is not context-aware, so the input caps above are the real
	// bound on render cost — this budget is defense in depth: if a future oksvg
	// change (or an input class we did not measure) ever made a within-caps
	// render pathologically slow, the budget bounds request latency rather than
	// letting one candidate hold a decode slot for the whole resolve deadline.
	// Because the input caps keep the abandoned render short and
	// self-terminating, a tripped budget cannot accumulate orphaned work.
	svgRenderBudget = 4 * time.Second

	// maxSVGPrologTokens bounds how many prolog tokens (XML declaration,
	// DOCTYPE, comments, whitespace) may precede the root element during
	// detection.
	maxSVGPrologTokens = 32

	// svgRasterSize is the fixed square raster target. It is chosen above the
	// largest size the service serves (128) so downscaling stays high-quality,
	// and it — never the SVG's declared dimensions — determines the pixel
	// buffer allocated. A 256x256 RGBA render is 256 KiB.
	svgRasterSize = 256

	// svgContentType is the canonical media type Fetch assigns after positive
	// SVG detection. http.DetectContentType cannot produce it (it has no SVG
	// signature — SVG sniffs as text/xml or text/plain), so its presence in
	// FetchResult.ContentType always means looksLikeSVG vouched for the bytes.
	svgContentType = "image/svg+xml"
)

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// trimBOM strips a leading UTF-8 byte-order mark. encoding/xml does not accept
// a BOM before the XML declaration, but SVG files in the wild carry one; every
// SVG entry point trims it so detection, guarding, and rendering all see the
// same document.
func trimBOM(data []byte) []byte {
	return bytes.TrimPrefix(data, utf8BOM)
}

// newSVGXMLDecoder builds the XML decoder used for BOTH detection (looksLikeSVG)
// and guarding (guardSVG), configured identically to the decoder oksvg's
// ReadIconStream installs — same CharsetReader. Parsing the document the same
// way the renderer will means the guard's well-formedness, token-count, and
// depth decisions describe exactly what the renderer parses, closing any
// guard-vs-renderer divergence (e.g. a non-UTF-8 declared encoding one tolerates
// and the other rejects). charset.NewReaderLabel is pure in-memory transcoding
// via golang.org/x/text charmaps — it performs no I/O, so it adds no fetch
// surface; an unknown/unsupported encoding label surfaces as a decode error,
// which both callers treat as "not a valid SVG" (fail closed).
func newSVGXMLDecoder(data []byte) *xml.Decoder {
	d := xml.NewDecoder(bytes.NewReader(trimBOM(data)))
	d.CharsetReader = charset.NewReaderLabel
	return d
}

// svgSniffCandidate reports whether a sniffed type is one http.DetectContentType
// can assign to SVG bytes. Only these are re-inspected by looksLikeSVG; sniffed
// raster types are never reclassified.
func svgSniffCandidate(sniffed string) bool {
	switch sniffed {
	case "text/xml", "text/plain", "application/xml":
		return true
	}
	return false
}

// looksLikeSVG reports whether the document's root element is <svg>. It
// tokenizes with the strict XML decoder rather than string-matching, so
// prolog content (XML declaration, DOCTYPE, comments) cannot disguise a
// non-SVG document and an SVG cannot be smuggled behind junk bytes. Anything
// the decoder cannot cleanly tokenize — unknown declared encodings included —
// is not SVG for our purposes: fail closed.
func looksLikeSVG(data []byte) bool {
	d := newSVGXMLDecoder(data)
	for i := 0; i < maxSVGPrologTokens; i++ {
		t, err := d.Token()
		if err != nil {
			return false
		}
		switch tok := t.(type) {
		case xml.StartElement:
			return tok.Name.Local == "svg"
		case xml.CharData:
			if len(bytes.TrimSpace(tok)) != 0 {
				return false
			}
		case xml.ProcInst, xml.Directive, xml.Comment:
			// Legitimate prolog content; keep scanning for the root element.
		}
	}
	return false
}

// guardSVG bounds an SVG document before any rendering work: byte size, total
// XML token count, and nesting depth. It also requires the document to be
// well-formed end to end under the strict decoder — which, as a consequence,
// rejects any reference to an entity the parser does not define (encoding/xml
// never loads external or DTD-declared entities, so a would-be XXE payload
// dies here as a plain parse error).
func guardSVG(data []byte) error {
	if len(data) > maxSVGBytes {
		return fmt.Errorf("%w: svg is %d bytes (cap %d)", ErrImageTooLarge, len(data), maxSVGBytes)
	}
	d := newSVGXMLDecoder(data)
	tokens, depth := 0, 0
	for {
		t, err := d.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: malformed svg: %v", ErrUnsupportedType, err)
		}
		tokens++
		if tokens > maxSVGTokens {
			return fmt.Errorf("%w: svg exceeds %d xml tokens", ErrImageTooLarge, maxSVGTokens)
		}
		switch t.(type) {
		case xml.StartElement:
			depth++
			if depth > maxSVGDepth {
				return fmt.Errorf("%w: svg nesting exceeds %d", ErrImageTooLarge, maxSVGDepth)
			}
		case xml.EndElement:
			depth--
		}
	}
}

// rasterizeSVG renders guarded SVG bytes onto a fixed svgRasterSize square,
// preserving aspect ratio, centered. The returned image is a pixel buffer this
// function allocated — nothing derived from the input controls its size.
//
// oksvg runs in its default IgnoreErrorMode: elements it does not implement
// are skipped, not executed (it has no execution or fetch capability to
// invoke), which renders real-world icons that carry decorative extras. The
// blank-render check below catches the degenerate case where nothing drawable
// remained, so a skipped-to-empty document falls through to the caller's next
// candidate instead of producing a transparent square.
//
// oksvg and rasterx are known to panic on some adversarial inputs; the deferred
// recover converts any panic into a per-candidate error, keeping the process
// up. The named returns exist for exactly that path.
//
// The render itself is behind svgRenderCore so the recovery boundary is
// testable: no real corpus input reliably panics oksvg, so a test substitutes a
// panicking core to prove the recover actually catches it (delete the recover
// and that test fails). Production never reassigns svgRenderCore.
func rasterizeSVG(data []byte) (img image.Image, err error) {
	defer func() {
		if r := recover(); r != nil {
			img = nil
			err = fmt.Errorf("%w: svg rasterizer panic: %v", ErrUnsupportedType, r)
		}
	}()
	return svgRenderCore(data)
}

// svgRenderCore is the real oksvg/rasterx render, indirected through a var only
// so rasterizeSVG's panic containment can be exercised (see rasterizeSVG).
var svgRenderCore = renderSVGWithOksvg

func renderSVGWithOksvg(data []byte) (image.Image, error) {
	icon, rerr := oksvg.ReadIconStream(bytes.NewReader(trimBOM(data)))
	if rerr != nil {
		return nil, fmt.Errorf("%w: parse svg: %v", ErrUnsupportedType, rerr)
	}

	// oksvg derives ViewBox from the viewBox attribute, falling back to
	// width/height. Reject anything non-finite or non-positive before it can
	// reach SetTarget's division and poison the transform with Inf/NaN.
	vb := icon.ViewBox
	if !isFinitePositive(vb.W) || !isFinitePositive(vb.H) || !isFinite(vb.X) || !isFinite(vb.Y) {
		return nil, fmt.Errorf("%w: svg viewBox %gx%g", ErrUnsupportedType, vb.W, vb.H)
	}

	scale := math.Min(svgRasterSize/vb.W, svgRasterSize/vb.H)
	w, h := vb.W*scale, vb.H*scale
	x, y := (svgRasterSize-w)/2, (svgRasterSize-h)/2
	icon.SetTarget(x, y, w, h)

	dst := image.NewRGBA(image.Rect(0, 0, svgRasterSize, svgRasterSize))
	scanner := rasterx.NewScannerGV(svgRasterSize, svgRasterSize, dst, dst.Bounds())
	icon.Draw(rasterx.NewDasher(svgRasterSize, svgRasterSize, scanner), 1.0)

	if isBlank(dst) {
		return nil, fmt.Errorf("%w: svg rendered blank", ErrUnsupportedType)
	}
	return dst, nil
}

// rasterizeWithBudget runs rasterizeSVG under svgRenderBudget (further bounded
// by ctx). oksvg cannot be cancelled mid-render, so on a budget/context expiry
// the render goroutine is abandoned — the input caps (maxSVGBytes/maxSVGTokens)
// keep that abandoned run short and self-terminating, so it drains rather than
// piling up. The candidate is dropped and resolution falls through to the next
// one or the caller's monogram fallback. The channel is buffered so the
// abandoned goroutine never blocks on send.
func rasterizeWithBudget(ctx context.Context, data []byte) (image.Image, error) {
	ctx, cancel := context.WithTimeout(ctx, svgRenderBudget)
	defer cancel()

	type result struct {
		img image.Image
		err error
	}
	ch := make(chan result, 1)
	go func() {
		img, err := rasterizeSVG(data)
		ch <- result{img, err}
	}()

	select {
	case r := <-ch:
		return r.img, r.err
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: svg render exceeded %s budget", ErrUnsupportedType, svgRenderBudget)
	}
}

func isFinite(f float64) bool {
	return !math.IsNaN(f) && !math.IsInf(f, 0)
}

func isFinitePositive(f float64) bool {
	return isFinite(f) && f > 0
}

// isBlank reports whether every pixel is fully transparent — the signature of
// an SVG whose drawable content was absent, invalid, or skipped entirely.
func isBlank(img *image.RGBA) bool {
	for i := 3; i < len(img.Pix); i += 4 {
		if img.Pix[i] != 0 {
			return false
		}
	}
	return true
}
