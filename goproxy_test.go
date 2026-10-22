package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGoCanonical(t *testing.T) {
	for p, want := range map[string]bool{
		"/golang.org/x/text/@v/v0.3.0.info":                                         true,
		"/golang.org/x/text/@v/v0.3.0.mod":                                          true,
		"/github.com/!azure/go-autorest/@v/v14.2.0+incompatible.zip":                true,
		"/github.com/x/y/@v/v0.0.0-20191109021931-daa7c04131f5.info":                true,
		"/github.com/x/y/@v/v1.0.0-!r!c.1.mod":                                      true,
		"/github.com/x/y/@v/v1.0.0-rc.1+incompatible.zip":                           true,
		"/github.com/x/y/@v/main.info":                                              false,
		"/github.com/x/y/@v/v1.2.info":                                              false,
		"/github.com/x/y/@v/v01.2.3.info":                                           false,
		"/github.com/x/y/@v/v1.2.3+meta.info":                                       false,
		"/github.com/x/y/@v/v1.2.3.txt":                                             false,
		"/github.com/x/y/@v/list":                                                   false,
		"/github.com/x/y/@latest":                                                   false,
		"/@v/v1.0.0.zip":                                                            false,
		"/github.com/x/y/@v/v1.2.3.info/extra":                                      false,
		"/github.com/x/y/@v/v1.2.3-.info":                                           false,
		"/github.com/x/y/@v/1.2.3.info":                                             false,
		"/sumdb/sum.golang.org/lookup/github.com/x/y@v1.2.3":                        false,
		"/github.com/x/y/@v/v1.2.3-0.20191109021931-daa7c04131f5+incompatible.info": true,
		"/github.com/x/y/@v/v1.2.4-pre.0.20191109021931-daa7c04131f5.info":          true,
		"/github.com/x/y/@v/v1.0.0-0.zip":                                           true,
		"/github.com/x/y/@v/v1.0.0-0a.1.info":                                       true,
		"/github.com/x/y/@v/v1.0.0--.info":                                          true,
		// Not semver, so revision queries to the go command: never pinned.
		"/github.com/x/y/@v/v1.0.0-01.info":    false,
		"/github.com/x/y/@v/v1.0.0-rc.01.info": false,
		"/github.com/x/y/@v/v2.3.4-007.info":   false,
		"/github.com/x/y/@v/v1.0.0-rc..1.info": false,
		"/github.com/x/y/@v/v1.0.0-.rc.info":   false,
		"/github.com/x/y/@v/v1.0.0-rc..info":   false,
		"/github.com/x/y/@v/v1.0.0-RC.1.info":  false, // unescaped uppercase
		"/github.com/x/y/@v/v1.0.0-!1.info":    false, // `!` escapes letters only
		"/github.com/x/y/@v/v1.0.0-rc!.info":   false,
	} {
		if goCanonical.MatchString(p) != want {
			t.Errorf("%s: canonical=%v, want %v", p, !want, want)
		}
	}
}

func TestGoproxy(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{} // "proxy /path", "sum /path", "gcs /path" → count
	count := func(who string, r *http.Request) {
		mu.Lock()
		hits[who+" "+r.URL.Path]++
		mu.Unlock()
	}
	gcs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count("gcs", r)
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Cache-Control", "private, max-age=0")
		io.WriteString(w, "BIG-ZIP-BYTES")
	}))
	defer gcs.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count("proxy", r)
		w.Header().Set("Cache-Control", "public, max-age=10800")
		switch r.URL.Path {
		case "/golang.org/x/text/@v/v0.3.0.info":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"Version":"v0.3.0"}`)
		case "/golang.org/x/text/@v/v0.3.0.zip":
			w.Header().Set("Content-Type", "application/zip")
			io.WriteString(w, "SMALL-ZIP")
		case "/github.com/!azure/x/@v/v1.0.0-!r!c1.zip":
			http.Redirect(w, r, "https://storage.googleapis.com/proxy-golang-org-prod/abc-module.zip?Expires=1&Signature=sig", http.StatusFound)
		case "/golang.org/x/text/@v/list", "/golang.org/x/text/@v/master.info":
			w.Header().Set("Cache-Control", "public, max-age=60") // as proxy.golang.org
			io.WriteString(w, "v0.3.0\n")
		case "/gone.test/m/@latest":
			http.Error(w, "gone", http.StatusGone)
		default:
			w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, "not found: unknown revision")
		}
	}))
	defer proxy.Close()
	sum := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count("sum", r)
		w.Header().Set("Cache-Control", "public, max-age=10800")
		switch {
		case r.URL.Path == "/latest", strings.HasPrefix(r.URL.Path, "/lookup/"), strings.HasPrefix(r.URL.Path, "/tile/"):
			io.WriteString(w, "sumdb:"+r.URL.Path)
		default:
			http.NotFound(w, r)
		}
	}))
	defer sum.Close()

	c := newCache(t.TempDir(), 0, 64)
	c.free = func() int64 { return 1 << 40 }
	// storage.googleapis.com:443 is the fake GCS; nothing else is reachable.
	for _, tr := range []*http.Transport{c.tr, c.ftr} {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == "storage.googleapis.com:443" {
				addr = gcs.Listener.Addr().String()
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	reg, err := newGoproxy(c, "http://go.test:8080", proxy.URL, sum.URL, 1<<20, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(router{"go.test": reg})
	defer srv.Close()
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	fetch := func(path string) (*http.Response, string) {
		t.Helper()
		resp, b := mustGet(t, cl, "GET", srv.URL+path, "Host", "go.test")
		settle(t, c)
		return resp, string(b)
	}
	stored := func(zone string) int { return len(files(t, filepath.Join(c.root, zone))) }
	// ttlIn is the longest remaining lifetime among zone's entries.
	ttlIn := func(zone string) (longest time.Duration) {
		for _, p := range files(t, filepath.Join(c.root, zone)) {
			f, m, err := openEntry(p)
			if err != nil {
				t.Fatal(err)
			}
			f.Close()
			longest = max(longest, time.Until(m.Expires))
		}
		return longest
	}
	hit := func(who, path string) int {
		mu.Lock()
		defer mu.Unlock()
		return hits[who+" "+path]
	}

	resp, body := fetch("/")
	if resp.StatusCode != 200 || !strings.Contains(body, "export GOPROXY=http://go.test:8080\n") {
		t.Fatalf("health: %d %q", resp.StatusCode, body)
	}

	// Canonical artifacts: files zone, a year, upstream max-age ignored.
	for _, p := range []string{"/golang.org/x/text/@v/v0.3.0.info", "/golang.org/x/text/@v/v0.3.0.zip"} {
		resp, _ = fetch(p)
		expect(t, resp, 200, "MISS")
		resp, _ = fetch(p)
		expect(t, resp, 200, "HIT")
		if resp.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatalf("Cache-Control: %v", resp.Header)
		}
	}
	if n, ttl := stored("goproxy-files"), ttlIn("goproxy-files"); n != 2 || ttl < 300*24*time.Hour {
		t.Fatalf("files zone: %d entries, ttl %v", n, ttl)
	}

	// The 302 to signed GCS is followed inside the fill and the 200 cached
	// under the original key. The path is escaped the way the go command
	// sends it (`!` as %21), which must still count as canonical.
	const big = "/github.com/%21azure/x/@v/v1.0.0-%21r%21c1.zip"
	resp, body = fetch(big)
	expect(t, resp, 200, "MISS")
	if body != "BIG-ZIP-BYTES" || resp.Header.Get("Location") != "" {
		t.Fatalf("big zip: %q %v", body, resp.Header)
	}
	resp, body = fetch(big)
	expect(t, resp, 200, "HIT")
	if body != "BIG-ZIP-BYTES" || hit("gcs", "/proxy-golang-org-prod/abc-module.zip") != 1 {
		t.Fatalf("big zip hit: %q gcs=%d", body, hit("gcs", "/proxy-golang-org-prod/abc-module.zip"))
	}
	if n := stored("goproxy-files"); n != 3 {
		t.Fatalf("files zone after big zip: %d entries", n)
	}

	// 404 on an artifact passes through with its body (go prints it), uncached.
	const missing = "/golang.org/x/text/@v/v9.9.9.info"
	for range 2 {
		resp, body = fetch(missing)
		expect(t, resp, 404, "MISS")
		if body != "not found: unknown revision" {
			t.Fatalf("404 body %q", body)
		}
	}
	if hit("proxy", missing) != 2 {
		t.Fatalf("artifact 404 cached")
	}

	// Mutable metadata: meta zone, upstream's max-age; non-canonical queries too.
	for _, p := range []string{"/golang.org/x/text/@v/list", "/golang.org/x/text/@v/master.info"} {
		resp, _ = fetch(p)
		expect(t, resp, 200, "MISS")
		resp, _ = fetch(p)
		expect(t, resp, 200, "HIT")
	}
	if n, ttl := stored("goproxy-meta"), ttlIn("goproxy-meta"); n != 2 || ttl > time.Minute {
		t.Fatalf("meta zone: %d entries, ttl %v", n, ttl)
	}
	// 404/410 on metadata: cached briefly, body kept.
	for _, p := range []string{"/nope.test/m/@latest", "/gone.test/m/@latest"} {
		resp, _ = fetch(p)
		resp, body = fetch(p)
		if resp.StatusCode/100 != 4 || resp.Header.Get("X-Cache-Status") != "HIT" || body == "" {
			t.Fatalf("%s: %d %v %q", p, resp.StatusCode, resp.Header, body)
		}
	}

	// Checksum DB: /supported answered here; lookup/tile immutable; the rest
	// 5m; all from sum.golang.org's root, never proxy.golang.org.
	resp, _ = fetch("/sumdb/sum.golang.org/supported")
	if resp.StatusCode != 200 || hit("sum", "/supported")+hit("proxy", "/sumdb/sum.golang.org/supported") != 0 {
		t.Fatalf("supported: %d", resp.StatusCode)
	}
	filesBefore, metaBefore := stored("goproxy-files"), stored("goproxy-meta")
	for _, p := range []string{"/lookup/golang.org/x/text@v0.3.0", "/tile/8/0/x001/234.p/5", "/latest"} {
		resp, body = fetch("/sumdb/sum.golang.org" + p)
		expect(t, resp, 200, "MISS")
		if body != "sumdb:"+p {
			t.Fatalf("sumdb %s: %q", p, body)
		}
		resp, _ = fetch("/sumdb/sum.golang.org" + p)
		expect(t, resp, 200, "HIT")
		if gz := resp.Header.Get("Vary") != ""; gz == strings.HasPrefix(p, "/tile/") {
			t.Fatalf("sumdb %s: gzip offered=%v", p, gz)
		}
	}
	if stored("goproxy-files") != filesBefore+2 || stored("goproxy-meta") != metaBefore+1 {
		t.Fatalf("sumdb zones: files %d→%d meta %d→%d", filesBefore, stored("goproxy-files"), metaBefore, stored("goproxy-meta"))
	}
	for range 2 {
		resp, _ = fetch("/sumdb/sum.golang.org/nope")
		expect(t, resp, 404, "MISS")
	}
	mu.Lock()
	for k := range hits {
		if strings.HasPrefix(k, "proxy /sumdb") {
			t.Errorf("sumdb went to the module proxy: %s", k)
		}
	}
	mu.Unlock()

	if _, err := newGoproxy(c, "", proxy.URL, sum.URL, 1<<20, 512<<20); err == nil {
		t.Fatal("files zone below 1g accepted")
	}
}
