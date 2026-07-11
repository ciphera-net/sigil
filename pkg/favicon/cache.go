package favicon

import (
	"container/list"
	"sync"
	"time"
)

const (
	// DefaultPositiveTTL keeps a resolved icon for a long time — a site's favicon
	// is effectively immutable, and the CDN in front does most of the work.
	DefaultPositiveTTL = 30 * 24 * time.Hour
	// DefaultNegativeTTL expires "no icon" results sooner, so a site that later
	// adds a favicon recovers within hours rather than a month.
	DefaultNegativeTTL = 6 * time.Hour

	// DefaultMaxEntries / DefaultMaxBytes bound the cache; whichever limit is hit
	// first drives eviction. Negative entries carry no PNG, so the entry count
	// bounds them while bytes bound the positive set.
	DefaultMaxEntries = 4096
	DefaultMaxBytes   = 64 << 20 // 64 MiB of encoded PNGs
)

// Entry is a cached resolution: PNG holds the encoded icon for a positive
// result; Negative marks a domain currently known to have no resolvable icon.
type Entry struct {
	PNG      []byte
	Negative bool
}

// Cache stores resolver results keyed by domain+size. Storing negative results
// is essential: it stops repeated lookups of icon-less domains from hammering
// the fetch path.
type Cache interface {
	Get(key string) (Entry, bool)
	Put(key string, e Entry)
}

type cacheItem struct {
	key     string
	entry   Entry
	size    int
	expires time.Time
}

// MemoryCache is a byte- and count-bounded in-process LRU with separate TTLs for
// positive and negative entries. It is safe for concurrent use.
//
// It is deliberately dependency-free (container/list). An off-the-shelf LRU is
// count-bounded with at most one TTL; the byte bound and the split positive /
// negative TTLs don't map onto that cleanly, so a small purpose-built cache is
// the more robust fit than wrapping one.
type MemoryCache struct {
	mu          sync.Mutex
	ll          *list.List // front = most recently used; values are *cacheItem
	items       map[string]*list.Element
	curBytes    int
	maxBytes    int
	maxEntries  int
	positiveTTL time.Duration
	negativeTTL time.Duration
	now         func() time.Time
}

// NewMemoryCache returns a cache with the default bounds and TTLs.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		ll:          list.New(),
		items:       make(map[string]*list.Element),
		maxBytes:    DefaultMaxBytes,
		maxEntries:  DefaultMaxEntries,
		positiveTTL: DefaultPositiveTTL,
		negativeTTL: DefaultNegativeTTL,
		now:         time.Now,
	}
}

// Get returns the entry for key if present and unexpired, refreshing its
// recency. An expired entry is evicted and reported as a miss.
func (c *MemoryCache) Get(key string) (Entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		return Entry{}, false
	}
	it := el.Value.(*cacheItem)
	if !c.now().Before(it.expires) {
		c.removeElement(el)
		return Entry{}, false
	}
	c.ll.MoveToFront(el)
	return it.entry, true
}

// Put stores e under key with the TTL appropriate to its sign, then evicts from
// the least-recently-used end until both bounds are satisfied.
func (c *MemoryCache) Put(key string, e Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ttl := c.positiveTTL
	if e.Negative {
		ttl = c.negativeTTL
	}
	it := &cacheItem{key: key, entry: e, size: len(e.PNG), expires: c.now().Add(ttl)}

	if el, ok := c.items[key]; ok {
		old := el.Value.(*cacheItem)
		c.curBytes -= old.size
		el.Value = it
		c.curBytes += it.size
		c.ll.MoveToFront(el)
	} else {
		c.items[key] = c.ll.PushFront(it)
		c.curBytes += it.size
	}
	c.evict()
}

func (c *MemoryCache) evict() {
	for len(c.items) > c.maxEntries || c.curBytes > c.maxBytes {
		el := c.ll.Back()
		if el == nil {
			break
		}
		c.removeElement(el)
	}
}

func (c *MemoryCache) removeElement(el *list.Element) {
	it := el.Value.(*cacheItem)
	c.ll.Remove(el)
	delete(c.items, it.key)
	c.curBytes -= it.size
}
