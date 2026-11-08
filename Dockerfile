# --- build stage ---
FROM golang:1.26 AS builder

WORKDIR /src

# Cache dependencies first.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Fully static, stripped, reproducible binary. CGO off keeps it static (Go's
# pure-Go resolver) so it runs on a scratch image with no libc.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/sigil ./cmd/server

# --- final stage: scratch (binary + CA roots only) ---
FROM scratch

# Image metadata. Static on purpose: a per-commit value would give every build a new digest and turn a CI-only
# change into a rollout across every Magic Containers region.
LABEL org.opencontainers.image.title="sigil" \
      org.opencontainers.image.description="Favicon resolver" \
      org.opencontainers.image.source="https://github.com/ciphera-net/sigil" \
      org.opencontainers.image.licenses="Apache-2.0"

# Public CA roots — Sigil does TLS to arbitrary https favicon hosts.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/sigil /sigil

# Run unprivileged. scratch has no /etc/passwd, so use a numeric UID (nobody).
USER 65534:65534

EXPOSE 8085

ENTRYPOINT ["/sigil"]
