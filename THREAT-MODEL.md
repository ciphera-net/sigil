# Sigil — Threat Model

Sigil resolves a domain's favicon by fetching URLs **derived from untrusted,
caller-supplied domains**. The network boundary is therefore hostile by
definition: the whole design treats every byte a remote host returns — and every
address it resolves to — as attacker-controlled. This document enumerates the
trust boundaries and the controls at each.

## Assets to protect

Sigil deliberately holds almost nothing, which is the point.

- **The internal network position of the host it runs on.** The primary asset is
  *not* data Sigil holds (it holds none) but the fact that a compromised fetcher
  could be pointed at internal services. Containment of that reach is the whole
  reason Sigil is a separate, zero-secret service.
- **Process availability.** A single hostile response should not be able to
  exhaust memory, pin a worker, or crash the process.
- **Downstream consumers.** Bytes Sigil returns are rendered as images in other
  applications; they must never be able to carry active content.

Sigil holds **no credentials, no database, no session state**. Its only
capability is egress to the public internet on TCP 80/443.

## Trust boundaries

1. **Inbound request** (`GET /icon?domain=&sz=`). Untrusted. `domain` is validated
   as a bare hostname (no scheme, port, path, or IP literal); `sz` must be one of
   `{16,32,64,128}`. Anything else is a 400 before any work happens.
2. **DNS resolution + TCP dial.** Untrusted. The resolved IP — not the hostname —
   is validated at dial time (see below).
3. **HTTP response** (headers + body, initial and every redirect). Untrusted.
   Size, content type, and declared image dimensions are all bounded, and the
   declared `Content-Type` is never trusted.
4. **Decoded image.** Untrusted until its declared dimensions are bounded; only
   then is it decoded and re-encoded.

## Threats and controls

### T1 — SSRF to internal/link-local/metadata addresses

*Threat:* a domain that resolves (or redirects) to `169.254.169.254`, RFC 1918
space, loopback, CGNAT, IPv6 ULA/link-local, NAT64, or an IPv4-mapped form of
any of these, to reach cloud metadata or internal services.

*Controls:*
- IP validation happens in `net.Dialer.Control` — **after** DNS resolution,
  **before** connect, once per resolved candidate address. This closes the
  resolve-then-connect (TOCTOU / DNS-rebinding) gap: a name that rebinds between
  check and dial is still validated at the dial.
- The denylist is `code.dny.dev/ssrf`, derived from the IANA Special-Purpose
  Address Registries (pinned, vendored, re-reviewed on bump). Only TCP to ports
  80/443 is permitted.
- Validation is on `netip.Addr`, so IPv4-mapped IPv6 (`::ffff:169.254.169.254`)
  is denied — it falls outside the IPv6 global-unicast range rather than slipping
  through as a "public" address.
- **Redirects re-validate automatically**: every hop dials through the same
  guarded transport, so the guard fires again on each redirect target. The
  redirect handler additionally caps depth at 3 and rejects any non-http(s)
  scheme.
- The transport sets `Proxy: nil` explicitly, so an `HTTP(S)_PROXY` in the
  environment cannot route around the dial guard.

*Assurance:* the test suite asserts denial of every range independently of the
guard library, so a dependency bump that regressed a range fails our tests.

### T2 — Decompression / pixel bombs (memory exhaustion)

*Threat:* a small response that declares an enormous decoded size (e.g. a
<100 KB PNG or GIF claiming billions of pixels), causing an OOM at decode.

*Controls:*
- Response bodies are capped at 1 MiB (read one byte past the cap to detect
  oversize rather than silently truncate). `Content-Length` is never trusted.
- Declared image dimensions are bounded (≤1024×1024, ≤1M pixels) via a
  header-only read **before** any pixel buffer is allocated.
- **ICO is a special case.** besticon's `DecodeConfig` reports only the ≤256
  icon-directory byte, not the embedded image's real size, so a PNG-in-ICO whose
  IHDR declares 100000×100000 would pass a naive check and OOM at decode. Sigil
  therefore reads the *selected entry's* real declared dimensions (PNG IHDR or
  raw DIB header) and bounds them before decoding, matching exactly what the
  decoder will allocate.

### T3 — Content-type confusion / active content (stored XSS)

*Threat:* a response labelled `image/png` that is actually HTML, or an SVG
carrying `<script>`/`onload`/external entities, rendered into a browser context.

*Controls:*
- Content type is decided by **sniffing** the bytes (`http.DetectContentType`),
  never by the response header. Only raster types are accepted
  (`png`, `x-icon`, `gif`, `jpeg`, `webp`).
- **SVG is rejected outright** in v1 — at discovery (SVG `<link>`/`.svg` URLs are
  filtered) and at the fetch boundary (SVG sniffs as XML/text, not an accepted
  raster type). This eliminates both the stored-XSS and the XXE/second-order-SSRF
  classes that an SVG parser would introduce.
- The guard is **fail-closed**: an accepted-and-sniffed type whose header cannot
  be read is rejected, not deferred — so a disguised payload (e.g. an SVG behind
  a PNG magic prefix) never reaches a decoder or a re-encode.
- Sigil always **re-encodes** to a fresh PNG; it never returns the original
  bytes, so nothing a remote host authored is served verbatim.

### T4 — Slowloris / resource pinning

*Threat:* a slow or stalling remote host holding a worker open indefinitely.

*Controls:* layered timeouts — 3 s dial, 5 s TLS handshake, 5 s response-header,
8 s whole-request, plus a 15 s resolve deadline on the inbound request. No single
timeout is relied upon alone.

### T5 — Fan-out abuse

*Threat:* a hostile homepage stuffed with thousands of `<link>` tags coercing
Sigil into thousands of outbound requests.

*Controls:* the candidate list is capped (12 URLs/resolve); the homepage read is
capped at 512 KiB; negative results are cached so icon-less domains are not
re-fetched.

## Residual risks (accepted for v1)

- **SVG-only sites** get the monogram fallback instead of their real icon — a
  security-over-polish trade documented in the design; reversible in a later
  phase with a sandboxed, entity-disabled rasterizer.
- **In-process cache** means each instance warms independently; acceptable at
  `count=1` behind a CDN. A shared cache would reintroduce a credentialed
  dependency and is deliberately avoided.
- **`code.dny.dev/ssrf` is pre-1.0.** Pinned and vendored; our range tests are
  version-independent, so a bad bump fails CI rather than shipping silently.

## Deployment control (defense in depth)

Sigil runs as its own Nomad job with **no `vault {}` block** and no internal
secrets — the absence of a Vault role is an auditable isolation control. Even a
full compromise of the process yields only public-internet egress on 80/443:
not the database, not Vault, not the internal service mesh.
