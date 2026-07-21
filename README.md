# Sigil

A small, self-hosted favicon resolver. Given a domain, Sigil fetches that
site's real favicon **server-side**, normalizes it to a PNG at the size you
ask for, and caches the result. It exists to replace third-party favicon
proxies (e.g. `google.com/s2/favicons`) so that resolving an icon never leaks
which domains your users look up to an outside party.

> Apache-2.0. Sigil fetches URLs derived from untrusted domains — an SSRF
> surface by design — so a hardened fetch boundary is its headline feature (see
> the [Security model](#security-model) and [`THREAT-MODEL.md`](./THREAT-MODEL.md)).
> Self-reviewed, not independently audited.

## Security model

Sigil's whole reason to be a separate service is containment: the code that
fetches attacker-influenceable URLs must not run in a process that holds
database credentials or an internal-network position. The running instance is
designed to have **zero internal secrets** and **egress-only** reach — if its
defenses were ever bypassed, the blast radius is a box that can talk to the
public internet and nothing else.

The fetch boundary (`pkg/favicon/fetch.go`) enforces, for every request and
**every redirect hop**:

- **Dial-time IP validation (TOCTOU-safe).** The resolved IP is checked in
  `net.Dialer.Control` — after DNS resolution, immediately before connect, once
  per candidate address — using [`code.dny.dev/ssrf`](https://code.dny.dev/ssrf)
  (an IANA-registry-derived denylist). This closes the resolve-then-connect gap
  and defeats DNS rebinding: a name that rebinds between check and dial is still
  validated at the dial. Validation is on `netip.Addr`, so IPv4-mapped IPv6
  (`::ffff:169.254.169.254`) cannot slip past as global unicast.
- **A default-deny address policy.** Loopback, RFC 1918 private space, CGNAT
  (`100.64.0.0/10`), link-local `169.254.0.0/16` (the cloud metadata endpoint),
  multicast, reserved ranges, IPv6 ULA/link-local, and NAT64 are all rejected.
  Only TCP to ports 80/443 is permitted.
- **Bounded redirects.** At most 3 hops, and every hop must be `http`/`https` —
  a `file://`, `gopher://`, etc. redirect is refused.
- **Bounded responses.** The body is read through a hard byte cap, the
  content type is decided by **sniffing** (never the response header), only
  raster image types are accepted, and the decoded pixel dimensions are
  bounded *before* full decode to defeat decompression bombs.
- **SVG only through a sandboxed rasterizer.** An SVG is XML that can carry
  script (stored-XSS risk) or external entities (XXE / second-order SSRF), so
  SVG bytes are never served or stored: a structurally-detected SVG is bounded
  (bytes, XML tokens, nesting depth) and rendered to a fixed-size pixel buffer
  by a pure-Go renderer ([`oksvg`](https://github.com/srwiley/oksvg) +
  [`rasterx`](https://github.com/srwiley/rasterx)) built on `encoding/xml`,
  which has no code path that loads external entities, DTDs, or URLs — the
  XXE class cannot be expressed, and a no-network regression test keeps it
  that way. Renderer panics are contained per candidate. The output, like
  every icon Sigil serves, is a freshly encoded PNG.

The SSRF test suite (`pkg/favicon/fetch_test.go`) asserts each of these
independently of the guard library, so a dependency bump that regressed a range
would fail our tests rather than silently ship.

## What it is (and is not)

- **Is:** a hardened favicon fetcher + normalizer, usable as a Go library
  (`github.com/ciphera-net/sigil/pkg/favicon`) or as a tiny HTTP service
  (`cmd/server`).
- **Is not:** a public favicon API for the internet, a general URL fetcher, or
  a proxy. The published instance stays internal; publishing the *code* is the
  open-source act.

## Install (library)

    go get github.com/ciphera-net/sigil/pkg/favicon

Requires **Go 1.25+**.

## API (service)

| Route | Response |
|-------|----------|
| `GET /icon?domain=<hostname>&sz=<16\|32\|64\|128>` | `200 image/png` resolved icon · `404` no icon (negatively cached) · `400` bad domain/size · `502` upstream fetch failure (not cached) |
| `GET /healthz` | liveness |
| `GET /metrics` | Prometheus |

`domain` must be a bare hostname (no scheme, port, path, or IP literal).

## Self-host

    docker build -t sigil .
    docker run -p 8085:8085 sigil

The container is a distroless static image holding only the server binary.

## CI

`.woodpecker/` runs, as separate checks: `test` (`gofmt`, `go vet`,
`go test -race`, including the SSRF suite), `govulncheck` (dependency-vuln
scan), and — once the service lands — `build` / `push` / `deploy`.

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](./LICENSE). Contributions require a DCO sign-off; see [CONTRIBUTING.md](./CONTRIBUTING.md).
