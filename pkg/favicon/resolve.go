package favicon

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/html"
)

// ErrNoIcon is returned when no favicon can be resolved for a domain. The caller
// (the HTTP service) maps it to a 404, and the result is negatively cached.
var ErrNoIcon = errors.New("favicon: no icon found")

// ErrInvalidDomain is returned when the domain is not a bare hostname. The HTTP
// service maps it to a 400.
var ErrInvalidDomain = errors.New("favicon: invalid domain")

// maxCandidates bounds how many icon URLs a single resolve will fetch, so a
// hostile homepage stuffed with thousands of <link> tags cannot fan out into
// thousands of outbound requests.
const maxCandidates = 12

// maxConcurrentCandidates bounds how many candidates decode at once within a
// single resolve. A candidate can be up to 2048x2048 (~16 MB decoded), so this
// caps a resolve's peak decode memory (~6 x 16 MB) regardless of how many
// candidates a hostile page lists.
const maxConcurrentCandidates = 6

// wellKnownPaths are probed unconditionally: these are frequently present with
// no <link> declaring them. (SVG well-known paths are intentionally omitted.)
var wellKnownPaths = []string{
	"/favicon.ico",
	"/apple-touch-icon.png",
	"/apple-touch-icon-precomposed.png",
}

// Resolver turns a domain + size into a normalized PNG favicon, backed by a
// cache. It owns no network capability beyond the guarded Fetcher it is given.
type Resolver struct {
	fetcher *Fetcher
	cache   Cache
	// origins maps a domain to the base origins to try, in order. It is a field
	// only so tests can point resolution at a local server; production always
	// uses defaultOrigins (https then http).
	origins func(domain string) []string
}

// NewResolver wires a Fetcher and a Cache into a Resolver.
func NewResolver(fetcher *Fetcher, cache Cache) *Resolver {
	return &Resolver{fetcher: fetcher, cache: cache, origins: defaultOrigins}
}

func defaultOrigins(domain string) []string {
	return []string{"https://" + domain, "http://" + domain}
}

func cacheKey(domain string, sz int) string {
	return domain + "|" + strconv.Itoa(sz)
}

// Resolve returns a PNG for domain at size sz. It consults the cache first, and
// on a miss runs the discovery pipeline and caches the result — positive or
// negative. It returns ErrNoIcon when nothing resolvable is found.
func (r *Resolver) Resolve(ctx context.Context, domain string, sz int) ([]byte, error) {
	if !validDomain(domain) {
		return nil, ErrInvalidDomain
	}

	key := cacheKey(domain, sz)
	if e, ok := r.cache.Get(key); ok {
		if e.Negative {
			return nil, ErrNoIcon
		}
		return e.PNG, nil
	}

	out, err := r.resolveUncached(ctx, domain, sz)
	if err != nil {
		if errors.Is(err, ErrNoIcon) {
			r.cache.Put(key, Entry{Negative: true})
		}
		return nil, err
	}
	r.cache.Put(key, Entry{PNG: out})
	return out, nil
}

func (r *Resolver) resolveUncached(ctx context.Context, domain string, sz int) ([]byte, error) {
	origins := r.origins(domain)

	seen := make(map[string]bool)
	var candidateURLs []string
	add := func(u string) {
		if u == "" || seen[u] || len(candidateURLs) >= maxCandidates {
			return
		}
		seen[u] = true
		candidateURLs = append(candidateURLs, u)
	}

	// 1. Fetch the homepage <head> and collect declared icon links. Prefer https;
	//    fall back to http. The origin that answered becomes the probe base.
	baseOrigin := ""
	for _, origin := range origins {
		htmlBytes, err := r.fetcher.FetchHTML(ctx, origin+"/")
		if err != nil {
			continue
		}
		baseOrigin = origin
		for _, href := range parseIconLinks(htmlBytes, origin+"/") {
			add(href)
		}
		break
	}

	// 2. Probe well-known paths. If the homepage answered on one scheme, probe
	//    only that origin; otherwise try both.
	probeOrigins := origins
	if baseOrigin != "" {
		probeOrigins = []string{baseOrigin}
	}
	for _, origin := range probeOrigins {
		for _, p := range wellKnownPaths {
			add(origin + p)
		}
	}

	// 3. Fetch and decode candidates concurrently (each independently guarded),
	//    but bound how many decode at once: a large candidate (up to 2048x2048)
	//    is ~16 MB decoded, and a hostile page could list many, so the semaphore
	//    keeps a single resolve's peak decode memory bounded.
	sem := make(chan struct{}, maxConcurrentCandidates)
	var (
		mu    sync.Mutex
		cands []candidate
		wg    sync.WaitGroup
	)
	for _, u := range candidateURLs {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := r.fetcher.Fetch(ctx, u)
			if err != nil {
				return
			}
			c, err := decodeCandidate(res.ContentType, res.Body)
			if err != nil {
				return
			}
			mu.Lock()
			cands = append(cands, c)
			mu.Unlock()
		}(u)
	}
	wg.Wait()

	best, ok := selectBest(cands, sz)
	if !ok {
		return nil, ErrNoIcon
	}
	return renderPNG(best.img, sz)
}

// parseIconLinks extracts absolute, http(s), non-SVG icon URLs declared by
// <link rel="icon|shortcut icon|apple-touch-icon|apple-touch-icon-precomposed">
// in an HTML document, resolving relative hrefs against <base href> if present,
// else against baseURL.
func parseIconLinks(htmlBytes []byte, baseURL string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	doc, err := html.Parse(bytes.NewReader(htmlBytes))
	if err != nil {
		return nil
	}

	resolveBase := base
	var hrefs []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "base":
				if h := nodeAttr(n, "href"); h != "" {
					if u, err := base.Parse(h); err == nil {
						resolveBase = u
					}
				}
			case "link":
				if isIconRel(nodeAttr(n, "rel")) {
					if h := nodeAttr(n, "href"); h != "" {
						if u, err := resolveBase.Parse(h); err == nil && isFetchableIcon(u) {
							hrefs = append(hrefs, u.String())
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return hrefs
}

// isIconRel reports whether a link rel token set names a raster favicon. The rel
// attribute may hold multiple space-separated tokens (e.g. "shortcut icon").
// "mask-icon" is deliberately excluded — it is SVG-only.
func isIconRel(rel string) bool {
	for _, tok := range strings.Fields(strings.ToLower(rel)) {
		switch tok {
		case "icon", "apple-touch-icon", "apple-touch-icon-precomposed":
			return true
		}
	}
	return false
}

// isFetchableIcon accepts only http/https URLs that are not SVG. SVG is rejected
// at discovery (as well as at the fetch boundary) per the v1 no-SVG policy.
func isFetchableIcon(u *url.URL) bool {
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return !strings.HasSuffix(strings.ToLower(u.Path), ".svg")
}

func nodeAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

// validDomain is a conservative bare-hostname check: labels of alphanumerics and
// hyphens separated by dots, no scheme/port/path/IP-literal shapes. The HTTP
// service applies the same rule; this is the library's own belt-and-suspenders
// so a caller can never smuggle a URL or IP literal into an origin string.
func validDomain(domain string) bool {
	if len(domain) < 4 || len(domain) > 253 || !strings.Contains(domain, ".") {
		return false
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	// The TLD is never all-numeric; requiring a non-digit in the last label
	// rejects IPv4 literals like 192.168.1.1 (belt-and-suspenders on the guard).
	last := labels[len(labels)-1]
	if strings.IndexFunc(last, func(r rune) bool { return r < '0' || r > '9' }) < 0 {
		return false
	}
	return true
}
