// Command simple-cache is a caching proxy for package registries (crates.io,
// the Go module proxy, npm and PyPI), one hostname per registry, TLS via
// ACME DNS-01 on Cloudflare.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		// The distroless image has no shell, nc or wget.
		conn, err := net.DialTimeout("tcp", "127.0.0.1:443", 3*time.Second)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		conn.Close()
		return
	}
	httpAddr := flag.String("http-addr", "", "serve plain HTTP on this address instead of TLS on :443 (dev/test: no ACME; public URLs become http://<host>:<port>, port left out if 80)")
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))
	if err := run(*httpAddr); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// publicOrigin maps a host name to our origin as clients see it: https, or
// with -http-addr http on that port. A default port is left out, as browsers
// and package managers would.
func publicOrigin(httpAddr string) (func(host string) string, error) {
	if httpAddr == "" {
		return func(host string) string { return "https://" + host }, nil
	}
	_, port, err := net.SplitHostPort(httpAddr)
	if err != nil {
		return nil, fmt.Errorf("-http-addr: %w", err)
	}
	return func(host string) string {
		if port == "80" {
			return "http://" + host
		}
		return "http://" + net.JoinHostPort(host, port)
	}, nil
}

func run(httpAddr string) error {
	var errs []error
	size := func(k, def string) int64 {
		n, err := parseSize(env(k, def))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", k, err))
		}
		return n
	}
	minFree := size("CACHE_MIN_FREE", "3g")
	idxCap, filesCap := size("CRATES_INDEX_MAX", "256m"), size("CRATES_FILES_MAX", "3g")
	goMetaCap, goFilesCap := size("GOPROXY_META_MAX", "128m"), size("GOPROXY_FILES_MAX", "3g")
	npmMetaCap, npmFilesCap := size("NPM_META_MAX", "512m"), size("NPM_FILES_MAX", "4g")
	pypiIndexCap, pypiFilesCap := size("PYPI_INDEX_MAX", "512m"), size("PYPI_FILES_MAX", "12g")
	maxFills, err := strconv.Atoi(env("MAX_FILLS", "64"))
	if err != nil || maxFills < 1 {
		errs = append(errs, fmt.Errorf("MAX_FILLS: must be a positive integer"))
	}
	names, err := hostEnv()
	if err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	cratesHost, goHost, npmHost, pypiHost := names["CRATES_HOST"], names["GOPROXY_HOST"], names["NPM_HOST"], names["PYPI_HOST"]

	public, err := publicOrigin(httpAddr)
	if err != nil {
		return err
	}

	c := newCache(env("CACHE_DIR", "/cache"), minFree, maxFills)
	crates, err := newCrates(c, public(cratesHost), "https://index.crates.io", "https://static.crates.io", idxCap, filesCap)
	if err != nil {
		return err
	}
	goproxy, err := newGoproxy(c, public(goHost), "https://proxy.golang.org", "https://sum.golang.org", goMetaCap, goFilesCap)
	if err != nil {
		return err
	}
	npm, err := newNpm(c, public(npmHost), "https://registry.npmjs.org", npmMetaCap, npmFilesCap)
	if err != nil {
		return err
	}
	pypi, err := newPypi(c, public(pypiHost), "https://pypi.org", "https://files.pythonhosted.org", pypiIndexCap, pypiFilesCap)
	if err != nil {
		return err
	}
	hosts := router{cratesHost: crates, goHost: goproxy, npmHost: npm, pypiHost: pypi}

	srv := &http.Server{
		Handler:           hosts,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No WriteTimeout: downloads can take hours. Each write gets its own
		// deadline instead (logWriter).
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn),
	}
	if httpAddr != "" {
		srv.Addr = httpAddr
		slog.Info("serving plain HTTP", "addr", httpAddr, "hosts", hosts.names())
		return serve(srv, srv.ListenAndServe)
	}

	token := os.Getenv("CLOUDFLARE_API_TOKEN")
	if token == "" {
		return errors.New("CLOUDFLARE_API_TOKEN is required (or use -http-addr)")
	}
	certmagic.Default.Storage = &certmagic.FileStorage{Path: "/certs"}
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = os.Getenv("ACME_EMAIL")
	// Internal network: Let's Encrypt can't reach us, so DNS-01 only.
	certmagic.DefaultACME.DisableHTTPChallenge = true
	certmagic.DefaultACME.DisableTLSALPNChallenge = true
	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{DNSProvider: &cloudflare.Provider{APIToken: token}},
	}
	tlsCfg := certmagic.NewDefault()
	if err := tlsCfg.ManageAsync(context.Background(), hosts.names()); err != nil {
		return err
	}
	srv.Addr = ":443"
	srv.TLSConfig = tlsCfg.TLSConfig()
	srv.TLSConfig.NextProtos = []string{"h2", "http/1.1"}
	slog.Info("serving HTTPS", "addr", srv.Addr, "hosts", hosts.names())
	return serve(srv, func() error { return srv.ListenAndServeTLS("", "") })
}

// serve runs listen until SIGTERM/SIGINT, then lets requests in flight finish
// for up to shutdownGrace (docker-compose's stop_grace_period is longer).
// Fills cut off then leave temp files that the next start removes.
func serve(srv *http.Server, listen func() error) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- listen() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	stop() // a second signal kills us without waiting out the grace
	slog.Info("shutting down", "grace", shutdownGrace)
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Warn("requests cut off at shutdown", "err", err)
	}
	return nil
}

const shutdownGrace = 100 * time.Second

// hostEnv reads the *_HOST variables, by variable, normalised as the router
// compares them. Two registries on one name would leave one unreachable.
func hostEnv() (map[string]string, error) {
	var errs []error
	names := map[string]string{}
	seen := map[string]string{} // host → variable
	for _, key := range []string{"CRATES_HOST", "GOPROXY_HOST", "NPM_HOST", "PYPI_HOST"} {
		h := strings.TrimSuffix(strings.ToLower(os.Getenv(key)), ".")
		if h == "" {
			errs = append(errs, fmt.Errorf("%s is required", key))
			continue
		}
		if prev, ok := seen[h]; ok {
			errs = append(errs, fmt.Errorf("%s and %s are both %q", prev, key, h))
		}
		seen[h] = key
		names[key] = h
	}
	return names, errors.Join(errs...)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// parseSize reads sizes: 512, 64k, 256m, 3g.
func parseSize(s string) (int64, error) {
	if s == "" {
		return 0, errors.New("empty size")
	}
	mult := int64(1)
	switch strings.ToLower(s[len(s)-1:]) {
	case "k":
		mult = 1 << 10
	case "m":
		mult = 1 << 20
	case "g":
		mult = 1 << 30
	}
	if mult > 1 {
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || n > math.MaxInt64/mult {
		return 0, fmt.Errorf("bad size %q", s)
	}
	return n * mult, nil
}

// router picks the registry by Host (port stripped). Unknown hosts get 404.
type router map[string]http.Handler

func (rt router) names() []string {
	var hs []string
	for h := range rt {
		hs = append(hs, h)
	}
	return hs
}

type logKey struct{}

type logInfo struct {
	udur time.Duration
	// The query may be logged. Off until a registry finds the request is no
	// relay, so a query rejected or relayed before then (npm's web-login
	// poll carries an authId that redeems a token) never reaches the log.
	query bool
}

func (rt router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	li := &logInfo{}
	r = r.WithContext(context.WithValue(r.Context(), logKey{}, li))
	lw := &logWriter{ResponseWriter: w, rc: http.NewResponseController(w)}
	// Clear the deadline the previous request on this connection left behind.
	lw.rc.SetWriteDeadline(time.Time{})
	defer func() {
		rec := recover()
		status := lw.status
		switch {
		case rec != nil:
			status = 0 // aborted mid-response
		case status == 0 && r.Context().Err() != nil:
			status = 499 // client gone before any response
		case status == 0:
			status = http.StatusOK
		}
		uri := r.RequestURI
		if p, _, ok := strings.Cut(uri, "?"); ok && !li.query {
			uri = p + "?REDACTED"
		}
		slog.Info("request", "host", host, "method", r.Method, "uri", uri, "proto", r.Proto,
			"status", status, "bytes", lw.bytes, "cache", lw.Header().Get("X-Cache-Status"),
			"dur", time.Since(start).Round(time.Millisecond), "udur", li.udur.Round(time.Millisecond),
			"remote", r.RemoteAddr, "xff", r.Header.Get("X-Forwarded-For"), "ua", r.UserAgent())
		if rec != nil {
			panic(rec)
		}
	}()
	h := rt[host]
	if h == nil {
		refuse(lw, r, "404 page not found", http.StatusNotFound)
		return
	}
	// Host must match SNI, or we'd answer for a name the connection's
	// certificate doesn't cover. 421 (not 404) makes an HTTP/2 client that
	// reused a connection for another of our names retry on a fresh one. An
	// empty SNI never gets here: certmagic has no certificate to offer it.
	if r.TLS != nil && r.TLS.ServerName != "" && !strings.EqualFold(strings.TrimSuffix(r.TLS.ServerName, "."), host) {
		refuse(lw, r, "misdirected request", http.StatusMisdirectedRequest)
		return
	}
	h.ServeHTTP(lw, r)
}

// logWriter records status/bytes for the access log and gives every write
// its own deadline, so a stalled client can't pin a response forever while a
// slow-but-moving multi-GB download is never cut off.
type logWriter struct {
	http.ResponseWriter
	rc     *http.ResponseController
	status int
	bytes  int64
}

func (w *logWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	// Header-only responses (HEAD, 304) never call Write; bound their flush.
	w.rc.SetWriteDeadline(time.Now().Add(idle))
	w.ResponseWriter.WriteHeader(code)
}

func (w *logWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.rc.SetWriteDeadline(time.Now().Add(idle))
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func (w *logWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
