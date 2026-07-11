package favicon

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/png"
	"testing"
)

// --- shared test image builders (used across the package's tests) -----------

// realPNG encodes an actual w×h RGBA image as a complete, decodable PNG.
func realPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x), G: uint8(y), B: 0x80, A: 0xFF})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// buildICOWithPNG wraps a PNG payload in a single-entry ICO container. dirW/dirH
// are the ICONDIRENTRY dimension bytes (0 means 256); the payload's own IHDR
// carries the real dimensions, which is the mismatch the bomb guard must catch.
func buildICOWithPNG(t *testing.T, dirW, dirH byte, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	// ICONDIR
	binary.Write(&buf, binary.LittleEndian, uint16(0)) // reserved
	binary.Write(&buf, binary.LittleEndian, uint16(1)) // type: icon
	binary.Write(&buf, binary.LittleEndian, uint16(1)) // count
	// ICONDIRENTRY (16 bytes), payload starts at offset 6 + 16 = 22
	buf.WriteByte(dirW)
	buf.WriteByte(dirH)
	buf.WriteByte(0)                                              // palette count
	buf.WriteByte(0)                                              // reserved
	binary.Write(&buf, binary.LittleEndian, uint16(1))            // color planes
	binary.Write(&buf, binary.LittleEndian, uint16(32))           // bits per pixel
	binary.Write(&buf, binary.LittleEndian, uint32(len(payload))) // size
	binary.Write(&buf, binary.LittleEndian, uint32(22))           // offset
	buf.Write(payload)
	return buf.Bytes()
}

// --- decode / bound ----------------------------------------------------------

func TestDecodeCandidatePNG(t *testing.T) {
	c, err := decodeCandidate(context.Background(), "image/png", realPNG(t, 64, 48))
	if err != nil {
		t.Fatalf("decodeCandidate PNG: %v", err)
	}
	if c.side != 64 {
		t.Fatalf("side = %d, want 64 (max of 64x48)", c.side)
	}
}

func TestDecodeCandidateICO(t *testing.T) {
	ico := buildICOWithPNG(t, 32, 32, realPNG(t, 32, 32))
	c, err := decodeCandidate(context.Background(), "image/x-icon", ico)
	if err != nil {
		t.Fatalf("decodeCandidate ICO: %v", err)
	}
	if c.side != 32 {
		t.Fatalf("side = %d, want 32", c.side)
	}
}

// TestDecodeICOBombRejected is the regression test for the review's PNG-in-ICO
// bomb: the directory byte says 256 but the embedded IHDR declares 100000². It
// must be rejected on declared dimensions before any pixel buffer is allocated.
func TestDecodeICOBombRejected(t *testing.T) {
	bomb := buildICOWithPNG(t, 0 /* =256 */, 0, pngWithDimensions(t, 100000, 100000))

	if _, _, err := icoBestEntryDims(bomb); !errors.Is(err, ErrImageTooLarge) {
		t.Fatalf("icoBestEntryDims: want ErrImageTooLarge, got %v", err)
	}
	if _, err := decodeCandidate(context.Background(), "image/x-icon", bomb); !errors.Is(err, ErrImageTooLarge) {
		t.Fatalf("decodeCandidate: want ErrImageTooLarge, got %v", err)
	}
}

func TestBoundDims(t *testing.T) {
	cases := []struct {
		w, h int
		ok   bool
	}{
		{32, 32, true},
		{1024, 1024, true},
		{1207, 1272, true}, // ciphera.net's real favicon — must be admitted
		{2048, 2048, true}, // exactly at the cap
		{2049, 16, false},  // over the dimension cap
		{16, 2049, false},
		{0, 16, false},
		{-1, 16, false},
		{4096, 4096, false}, // well over
		{100000, 100000, false},
	}
	for _, tc := range cases {
		err := boundDims(tc.w, tc.h)
		if tc.ok && err != nil {
			t.Fatalf("boundDims(%d,%d) = %v, want ok", tc.w, tc.h, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("boundDims(%d,%d) = ok, want rejected", tc.w, tc.h)
		}
	}
}

// --- selection ---------------------------------------------------------------

func TestSelectBest(t *testing.T) {
	mk := func(side int) candidate { return candidate{side: side} }
	cands := []candidate{mk(16), mk(32), mk(64), mk(180)}

	cases := []struct {
		target int
		want   int
	}{
		{16, 16},   // exact
		{24, 32},   // smallest >= target
		{32, 32},   // exact
		{100, 180}, // smallest >= target
		{500, 180}, // none >= target -> largest available
	}
	for _, tc := range cases {
		best, ok := selectBest(cands, tc.target)
		if !ok {
			t.Fatalf("target %d: no candidate selected", tc.target)
		}
		if best.side != tc.want {
			t.Fatalf("target %d: selected side %d, want %d", tc.target, best.side, tc.want)
		}
	}

	if _, ok := selectBest(nil, 32); ok {
		t.Fatal("selectBest(nil) returned a candidate")
	}
}

// --- render ------------------------------------------------------------------

func TestRenderPNGProducesRequestedSize(t *testing.T) {
	src, err := decodeCandidate(context.Background(), "image/png", realPNG(t, 64, 64))
	if err != nil {
		t.Fatal(err)
	}
	out, err := renderPNG(src.img, 32)
	if err != nil {
		t.Fatalf("renderPNG: %v", err)
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("output is not a valid PNG: %v", err)
	}
	if cfg.Width != 32 || cfg.Height != 32 {
		t.Fatalf("rendered %dx%d, want 32x32", cfg.Width, cfg.Height)
	}
}
