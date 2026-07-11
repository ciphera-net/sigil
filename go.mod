module github.com/ciphera-net/sigil

go 1.25.0

// Build with >= go1.25.12. Sigil performs TLS handshakes and HTTP header
// parsing against attacker-influenced hosts on every request, so a string of
// stdlib fixes are directly reachable — crypto/tls (through go1.25.12),
// crypto/x509 and net/textproto (go1.25.11), net/http and net.Dial/LookupPort
// (go1.25.10, GO-2026-4971). govulncheck confirms 1.25.12 clears the reachable
// set; treat the floor as a security requirement, not a nicety.
toolchain go1.25.12

require (
	code.dny.dev/ssrf v0.3.0
	github.com/mat/besticon/v3 v3.21.0
	golang.org/x/image v0.44.0
	golang.org/x/net v0.57.0
)
