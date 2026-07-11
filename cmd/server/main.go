// Command server is the Sigil favicon-resolution HTTP service.
//
// It exposes GET /icon?domain=&sz= (returns a normalized PNG), /healthz, and
// /metrics. It holds no secrets and its only network capability is the
// SSRF-guarded egress of the favicon package.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ciphera-net/sigil/pkg/favicon"
)

// allowedSizes is the service's size contract, mirroring the Pulse consumer.
var allowedSizes = map[string]int{"16": 16, "32": 32, "64": 64, "128": 128}

const (
	defaultAddr    = ":8085"
	resolveTimeout = 15 * time.Second

	// Cache headers mirror the current Pulse proxy so Bunny does the heavy
	// lifting; a resolved icon is effectively immutable.
	positiveCacheControl = "public, max-age=86400, s-maxage=604800, stale-while-revalidate=604800"
	negativeCacheControl = "public, max-age=3600"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	addr := os.Getenv("SIGIL_ADDR")
	if addr == "" {
		addr = defaultAddr
	}

	srv := newServer()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /icon", srv.handleIcon)
	mux.HandleFunc("GET /healthz", srv.handleHealth)
	mux.HandleFunc("GET /metrics", srv.handleMetrics)

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		// The inbound request should return fast; the resolve deadline bounds the
		// outbound work independently.
		WriteTimeout: resolveTimeout + 5*time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("sigil listening", "addr", addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
	}
}

type server struct {
	resolver *favicon.Resolver
	metrics  *metrics
}

func newServer() *server {
	return &server{
		resolver: favicon.NewResolver(favicon.NewFetcher(), favicon.NewMemoryCache()),
		metrics:  &metrics{},
	}
}

func (s *server) handleIcon(w http.ResponseWriter, r *http.Request) {
	s.metrics.requests.Add(1)

	domain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
	szParam := r.URL.Query().Get("sz")
	if szParam == "" {
		szParam = "32"
	}
	sz, okSize := allowedSizes[szParam]
	if !okSize {
		s.metrics.badRequest.Add(1)
		http.Error(w, "invalid size", http.StatusBadRequest)
		return
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), resolveTimeout)
	defer cancel()

	png, err := s.resolver.Resolve(ctx, domain, sz)
	s.metrics.observe(time.Since(start))

	switch {
	case errors.Is(err, favicon.ErrInvalidDomain):
		s.metrics.badRequest.Add(1)
		http.Error(w, "invalid domain", http.StatusBadRequest)
	case errors.Is(err, favicon.ErrNoIcon):
		s.metrics.notFound.Add(1)
		w.Header().Set("Cache-Control", negativeCacheControl)
		w.WriteHeader(http.StatusNotFound)
	case err != nil:
		// Upstream/network failure — surface as 502, do not cache.
		s.metrics.errorsN.Add(1)
		http.Error(w, "resolution failed", http.StatusBadGateway)
	default:
		s.metrics.resolved.Add(1)
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", positiveCacheControl)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(png)
	}
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, "ok\n")
}

func (s *server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.metrics.write(w)
}

// metrics holds Prometheus counters as atomics. It is written in the text
// exposition format directly, keeping the binary dependency-free.
type metrics struct {
	requests   atomic.Int64
	resolved   atomic.Int64
	notFound   atomic.Int64
	badRequest atomic.Int64
	errorsN    atomic.Int64
	durMsSum   atomic.Int64
	durCount   atomic.Int64
}

func (m *metrics) observe(d time.Duration) {
	m.durMsSum.Add(d.Milliseconds())
	m.durCount.Add(1)
}

func (m *metrics) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP sigil_requests_total Total /icon requests received.\n")
	fmt.Fprintf(w, "# TYPE sigil_requests_total counter\n")
	fmt.Fprintf(w, "sigil_requests_total %d\n", m.requests.Load())

	fmt.Fprintf(w, "# HELP sigil_results_total /icon outcomes by result.\n")
	fmt.Fprintf(w, "# TYPE sigil_results_total counter\n")
	fmt.Fprintf(w, "sigil_results_total{result=\"resolved\"} %d\n", m.resolved.Load())
	fmt.Fprintf(w, "sigil_results_total{result=\"not_found\"} %d\n", m.notFound.Load())
	fmt.Fprintf(w, "sigil_results_total{result=\"bad_request\"} %d\n", m.badRequest.Load())
	fmt.Fprintf(w, "sigil_results_total{result=\"error\"} %d\n", m.errorsN.Load())

	fmt.Fprintf(w, "# HELP sigil_resolve_duration_seconds Resolve duration summary.\n")
	fmt.Fprintf(w, "# TYPE sigil_resolve_duration_seconds summary\n")
	fmt.Fprintf(w, "sigil_resolve_duration_seconds_sum %f\n", float64(m.durMsSum.Load())/1000.0)
	fmt.Fprintf(w, "sigil_resolve_duration_seconds_count %d\n", m.durCount.Load())
}
