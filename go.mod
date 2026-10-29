module github.com/ciphera-net/sigil

// Build with >= go1.26.10. Sigil performs TLS handshakes and HTTP header
// parsing against attacker-influenced hosts on every request, so stdlib fixes in
// crypto/tls, crypto/x509, net/http and net/textproto are directly reachable.
// Go 1.25 is end-of-life (its last patch, 1.25.14, misses fixes released only
// for 1.26.9 and 1.26.10), so the floor is the 1.26 line. govulncheck confirms
// the reachable set is clear; treat the floor as a security requirement. The
// golang images set GOTOOLCHAIN=local, so an older builder fails here, loudly.
go 1.26.10

require (
	code.dny.dev/ssrf v0.3.0
	github.com/mat/besticon/v3 v3.21.0
	github.com/srwiley/oksvg v0.0.0-20221011165216-be6e8873101c
	github.com/srwiley/rasterx v0.0.0-20220730225603-2ab79fcdd4ef
	golang.org/x/image v0.45.0
	golang.org/x/net v0.62.0
)

require (
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)
