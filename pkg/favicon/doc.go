// Package favicon resolves and normalizes the favicon for a domain.
//
// It is built to fetch URLs derived from untrusted, caller-supplied domains,
// so the network boundary is treated as hostile: every outbound request goes
// through an SSRF-guarded HTTP client (see fetch.go) that validates the
// resolved IP at dial time, caps redirects, response size, and decoded pixel
// count, and accepts only raster image content — plus SVG, which is never
// served as markup but rasterized to a bounded pixel buffer by a pure-Go,
// entity-free renderer (see svg.go). The resolver, image pipeline, and cache
// build on top of that boundary.
//
// Nothing in this package holds credentials or reaches internal services; its
// only capability is egress to the public internet on ports 80 and 443.
package favicon
