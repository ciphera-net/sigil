package favicon

import (
	"strconv"
	"testing"
	"time"
)

func TestCachePositiveRoundTrip(t *testing.T) {
	c := NewMemoryCache()
	c.Put("a|32", Entry{PNG: []byte("png-bytes")})

	e, ok := c.Get("a|32")
	if !ok {
		t.Fatal("expected hit")
	}
	if e.Negative || string(e.PNG) != "png-bytes" {
		t.Fatalf("unexpected entry %+v", e)
	}

	if _, ok := c.Get("missing"); ok {
		t.Fatal("expected miss for absent key")
	}
}

func TestCacheNegative(t *testing.T) {
	c := NewMemoryCache()
	c.Put("b|32", Entry{Negative: true})

	e, ok := c.Get("b|32")
	if !ok {
		t.Fatal("expected hit for negative entry")
	}
	if !e.Negative || e.PNG != nil {
		t.Fatalf("expected negative entry, got %+v", e)
	}
}

func TestCacheExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := NewMemoryCache()
	c.now = func() time.Time { return now }

	c.Put("pos|32", Entry{PNG: []byte("x")})
	c.Put("neg|32", Entry{Negative: true})

	// Just before the negative TTL: both live.
	now = now.Add(DefaultNegativeTTL - time.Minute)
	if _, ok := c.Get("neg|32"); !ok {
		t.Fatal("negative entry expired too early")
	}
	if _, ok := c.Get("pos|32"); !ok {
		t.Fatal("positive entry expired too early")
	}

	// Past the negative TTL but well before the positive TTL: negative gone,
	// positive still live.
	now = now.Add(2 * time.Minute)
	if _, ok := c.Get("neg|32"); ok {
		t.Fatal("negative entry should have expired")
	}
	if _, ok := c.Get("pos|32"); !ok {
		t.Fatal("positive entry expired at the negative TTL")
	}

	// Past the positive TTL: gone.
	now = now.Add(DefaultPositiveTTL)
	if _, ok := c.Get("pos|32"); ok {
		t.Fatal("positive entry should have expired")
	}
}

func TestCacheEvictsByCount(t *testing.T) {
	c := NewMemoryCache()
	c.maxEntries = 3

	for i := 0; i < 5; i++ {
		c.Put(strconv.Itoa(i), Entry{PNG: []byte{byte(i)}})
	}
	if got := len(c.items); got != 3 {
		t.Fatalf("entry count = %d, want 3", got)
	}
	// 0 and 1 are the least-recently-used and should be evicted.
	for _, gone := range []string{"0", "1"} {
		if _, ok := c.Get(gone); ok {
			t.Fatalf("key %s should have been evicted", gone)
		}
	}
	for _, kept := range []string{"2", "3", "4"} {
		if _, ok := c.Get(kept); !ok {
			t.Fatalf("key %s should still be present", kept)
		}
	}
}

func TestCacheEvictsByBytes(t *testing.T) {
	c := NewMemoryCache()
	c.maxBytes = 100

	c.Put("a", Entry{PNG: make([]byte, 60)})
	c.Put("b", Entry{PNG: make([]byte, 60)}) // now 120 > 100 -> evict a
	if _, ok := c.Get("a"); ok {
		t.Fatal("a should have been evicted on byte pressure")
	}
	if _, ok := c.Get("b"); !ok {
		t.Fatal("b should be present")
	}
	if c.curBytes != 60 {
		t.Fatalf("curBytes = %d, want 60", c.curBytes)
	}
}

func TestCacheLRURefreshOnGet(t *testing.T) {
	c := NewMemoryCache()
	c.maxEntries = 2

	c.Put("a", Entry{PNG: []byte("a")})
	c.Put("b", Entry{PNG: []byte("b")})
	// Touch "a" so "b" becomes least-recently-used.
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a missing")
	}
	c.Put("c", Entry{PNG: []byte("c")}) // evicts LRU = b

	if _, ok := c.Get("b"); ok {
		t.Fatal("b should have been evicted as LRU")
	}
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a should have survived (recently used)")
	}
}

func TestCacheReplaceUpdatesBytes(t *testing.T) {
	c := NewMemoryCache()
	c.Put("a", Entry{PNG: make([]byte, 40)})
	c.Put("a", Entry{PNG: make([]byte, 10)}) // replace, not add
	if len(c.items) != 1 {
		t.Fatalf("entry count = %d, want 1 after replace", len(c.items))
	}
	if c.curBytes != 10 {
		t.Fatalf("curBytes = %d, want 10 after replace", c.curBytes)
	}
}
