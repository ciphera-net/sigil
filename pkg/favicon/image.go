package favicon

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"image"
	"image/png"

	"golang.org/x/image/draw"

	// besticon's ICO container decoder. We call ico.ParseIco / ico.Decode
	// EXPLICITLY and never through the image registry: besticon's init registers
	// an "ico" format whose DecodeConfig reports only the <=256 directory byte,
	// which would let a PNG-in-ICO bomb past the size guard. Because no code path
	// hands ICO bytes to image.Decode/DecodeConfig, that registration is inert.
	"github.com/mat/besticon/v3/ico"
)

// pngMagic is the 8-byte PNG signature, used to tell a PNG-in-ICO entry from a
// raw DIB entry.
var pngMagic = []byte("\x89PNG\r\n\x1a\n")

// candidate is a fetched, decoded favicon option with its representative pixel
// size (the larger side; favicons are effectively square).
type candidate struct {
	img  image.Image
	side int
}

// boundDims rejects header-declared dimensions outside (0, maxImageDimension] or
// exceeding the pixel budget. It runs before any pixel buffer is allocated.
func boundDims(w, h int) error {
	if w <= 0 || h <= 0 {
		return fmt.Errorf("%w: non-positive %dx%d", ErrImageTooLarge, w, h)
	}
	// Bound each dimension before multiplying so the product cannot overflow.
	if w > maxImageDimension || h > maxImageDimension {
		return fmt.Errorf("%w: %dx%d", ErrImageTooLarge, w, h)
	}
	if w*h > maxImagePixels {
		return fmt.Errorf("%w: %dx%d", ErrImageTooLarge, w, h)
	}
	return nil
}

// icoBestEntryDims parses an ICO, selects the same entry besticon's Decode will
// use (FindBestIcon), and returns that entry's REAL declared dimensions after
// bounding them. besticon's own DecodeConfig reports only the <=256 directory
// byte, so bounding here — against the embedded PNG's IHDR or the raw DIB header
// — is what makes ico.Decode's later allocation safe.
func icoBestEntryDims(data []byte) (int, int, error) {
	dir, err := ico.ParseIco(bytes.NewReader(data))
	if err != nil {
		return 0, 0, fmt.Errorf("%w: parse ico: %v", ErrUnsupportedType, err)
	}
	best := dir.FindBestIcon()
	if best == nil {
		return 0, 0, fmt.Errorf("%w: ico has no entries", ErrUnsupportedType)
	}
	off, size := int64(best.Offset), int64(best.Size)
	if off < 6 || size <= 0 || off > int64(len(data)) || off+size > int64(len(data)) {
		return 0, 0, fmt.Errorf("%w: ico entry out of bounds", ErrUnsupportedType)
	}
	w, h := declaredEntryDimensions(data[off : off+size])
	if w <= 0 || h <= 0 || w > maxImageDimension || h > maxImageDimension {
		return 0, 0, fmt.Errorf("%w: ico entry %dx%d", ErrImageTooLarge, w, h)
	}
	return int(w), int(h), nil
}

// declaredEntryDimensions returns the width and height an ICO entry's payload
// declares — from the embedded PNG's IHDR, or the raw DIB's header — as the
// decoder will interpret them (matching besticon: the DIB height is stored
// doubled, for image + AND-mask, and read unsigned). It works in int64 because
// the fields are uint32 and a hostile value can exceed a 32-bit int. Returns
// (0,0) for an unrecognized or too-short entry.
func declaredEntryDimensions(entry []byte) (int64, int64) {
	if len(entry) >= 24 && bytes.HasPrefix(entry, pngMagic) {
		w := int64(binary.BigEndian.Uint32(entry[16:20]))
		h := int64(binary.BigEndian.Uint32(entry[20:24]))
		return w, h
	}
	if len(entry) >= 12 {
		w := int64(binary.LittleEndian.Uint32(entry[4:8]))
		h := int64(binary.LittleEndian.Uint32(entry[8:12]) / 2)
		return w, h
	}
	return 0, 0
}

// decodeImage decodes validated icon bytes of the given sniffed type. ICO is
// routed through besticon explicitly, and only after its selected entry's real
// dimensions are bounded; other types go through the stdlib/x-image decoders.
// SVG is guarded again (bytes/tokens/depth) and rasterized under a wall-clock
// budget derived from ctx. The decoded result is re-bounded as defense in depth.
func decodeImage(ctx context.Context, sniffed string, data []byte) (image.Image, error) {
	var (
		img image.Image
		err error
	)
	switch sniffed {
	case "image/x-icon", "image/vnd.microsoft.icon":
		if _, _, derr := icoBestEntryDims(data); derr != nil {
			return nil, derr
		}
		img, err = ico.Decode(bytes.NewReader(data))
	case svgContentType:
		if derr := guardSVG(data); derr != nil {
			return nil, derr
		}
		img, err = rasterizeWithBudget(ctx, data)
	default:
		img, _, err = image.Decode(bytes.NewReader(data))
	}
	if err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrUnsupportedType, err)
	}
	b := img.Bounds()
	if err := boundDims(b.Dx(), b.Dy()); err != nil {
		return nil, err
	}
	return img, nil
}

// decodeCandidate decodes icon bytes into a candidate with its representative
// size. ctx bounds the SVG rasterization path; non-SVG decoders ignore it.
func decodeCandidate(ctx context.Context, sniffed string, data []byte) (candidate, error) {
	img, err := decodeImage(ctx, sniffed, data)
	if err != nil {
		return candidate{}, err
	}
	b := img.Bounds()
	side := b.Dx()
	if b.Dy() > side {
		side = b.Dy()
	}
	return candidate{img: img, side: side}, nil
}

// selectBest chooses the candidate that best serves target using besticon's
// rule: the smallest candidate at least as large as target, else the largest
// available. Returns false when there are no candidates.
func selectBest(cands []candidate, target int) (candidate, bool) {
	up, down := -1, -1
	for i, c := range cands {
		if c.side >= target {
			if up == -1 || c.side < cands[up].side {
				up = i
			}
		} else {
			if down == -1 || c.side > cands[down].side {
				down = i
			}
		}
	}
	switch {
	case up != -1:
		return cands[up], true
	case down != -1:
		return cands[down], true
	default:
		return candidate{}, false
	}
}

// renderPNG resizes img to a square target×target and encodes it as PNG. Icons
// are square by convention; CatmullRom gives good downscale quality, and the
// result is cached, so the cost is paid once per (domain, size).
func renderPNG(img image.Image, target int) ([]byte, error) {
	dst := image.NewRGBA(image.Rect(0, 0, target, target))
	draw.CatmullRom.Scale(dst, dst.Bounds(), img, img.Bounds(), draw.Over, nil)
	var buf bytes.Buffer
	if err := (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&buf, dst); err != nil {
		return nil, fmt.Errorf("favicon: encode png: %w", err)
	}
	return buf.Bytes(), nil
}
