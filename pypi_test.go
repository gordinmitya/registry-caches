package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPypi(t *testing.T) {
	const simpleJSON = "application/vnd.pypi.simple.v1+json"
	metadata := []byte("Metadata-Version: 2.1\nName: requests\nVersion: 2.32.3\n" + strings.Repeat("Requires-Dist: x\n", 50))
	wheel := bytes.Repeat([]byte("WHEEL"), 50000)
	var mu sync.Mutex
	hits := map[string]int{}    // upstream "METHOD path" → count
	hdrs := map[string]string{} // upstream path → "Accept|Accept-Encoding"
	release := make(chan struct{})
	var stalled atomic.Bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.Method+" "+r.URL.Path]++
		hdrs[r.URL.Path] = r.Header.Get("Accept") + "|" + r.Header.Get("Accept-Encoding")
		mu.Unlock()
		switch p := r.URL.Path; {
		// pypi.org
		case p == "/simple/requests/" && strings.Contains(r.Header.Get("Accept"), simpleJSON):
			w.Header().Set("Content-Type", simpleJSON)
			w.Header().Set("Vary", "Accept-Encoding, Accept")
			io.WriteString(w, `{"files":[{"filename":"requests-2.32.3-py3-none-any.whl","url":"https://files.pythonhosted.org/packages/f9/9b/requests-2.32.3-py3-none-any.whl","core-metadata":{"sha256":"x"}}],"name":"requests","versions":[`+
				strings.Repeat(`"2.32.3",`, 120)+`"2.32.3"]}`) // over 1 KiB: gzipped
		case p == "/simple/requests/":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<a href="https://files.pythonhosted.org/packages/f9/9b/requests-2.32.3-py3-none-any.whl#sha256=abc" data-dist-info-metadata="sha256=x">requests-2.32.3-py3-none-any.whl</a>`)
		case p == "/simple/Flask_Login/":
			http.Redirect(w, r, "https://pypi.org/simple/flask-login/", http.StatusMovedPermanently)
		case p == "/simple/requests":
			http.Redirect(w, r, "https://pypi.org/simple/requests/", http.StatusMovedPermanently)
		// files.pythonhosted.org
		case p == "/packages/f9/9b/requests-2.32.3-py3-none-any.whl.metadata":
			// Gzipped on request, marked only with Vary: a cache keyed on the
			// URL alone would store whichever encoding came first.
			w.Header().Set("Content-Type", "binary/octet-stream")
			w.Header().Set("Vary", "Accept-Encoding")
			if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				w.Header().Set("Content-Encoding", "gzip")
				gz := gzip.NewWriter(w)
				gz.Write(metadata)
				gz.Close()
				return
			}
			w.Write(metadata)
		case p == "/packages/f9/9b/requests-2.32.3-py3-none-any.whl":
			w.Header().Set("Content-Type", "binary/octet-stream")
			w.Header().Set("Content-Length", "250000")
			if r.Method == http.MethodHead {
				return
			}
			w.Write(wheel[:64<<10])
			w.(http.Flusher).Flush()
			if stalled.CompareAndSwap(false, true) { // only the first download
				<-release
			}
			w.Write(wheel[64<<10:])
		case p == "/packages/source/r/requests/requests-2.32.3.tar.gz":
			http.Redirect(w, r, "https://files.pythonhosted.org/packages/63/70/requests-2.32.3.tar.gz", http.StatusFound)
		default:
			http.Error(w, "404 Not Found", http.StatusNotFound)
		}
	}))
	defer up.Close()
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	c := newCache(t.TempDir(), 0, 64)
	c.free = func() int64 { return 1 << 40 }
	reg, err := newPypi(c, "http://pypi.test:8080", up.URL, up.URL, 1<<20, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(router{"pypi.test": reg})
	defer srv.Close()
	// Like pip: redirects not followed here, gzip decoded only on request.
	cl := &http.Client{
		Transport:     &http.Transport{DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	fetch := func(path string, hdr ...string) (*http.Response, []byte) {
		t.Helper()
		resp, b := mustGet(t, cl, "GET", srv.URL+path, append([]string{"Host", "pypi.test"}, hdr...)...)
		settle(t, c)
		return resp, b
	}
	count := func(p string) int {
		mu.Lock()
		defer mu.Unlock()
		return hits["GET "+p]
	}
	upHdrs := func(p string) string {
		mu.Lock()
		defer mu.Unlock()
		return hdrs[p]
	}

	resp, b := fetch("/")
	if resp.StatusCode != 200 || !strings.Contains(string(b), `url = "http://pypi.test:8080/simple/"`) {
		t.Fatalf("health: %d %s", resp.StatusCode, b)
	}

	// /simple: ours, absolute public origin like every Location we send.
	resp, _ = fetch("/simple")
	if resp.StatusCode != 301 || resp.Header.Get("Location") != "http://pypi.test:8080/simple/" || count("/simple") != 0 {
		t.Fatalf("/simple: %d %v", resp.StatusCode, resp.Header)
	}
	// pypi.org collapses empty segments and ignores queries: each spelling
	// would be another copy of a page (the project list is 45 MB).
	for _, p := range []string{"/simple?x=1", "/simple//", "/simple//requests/", "/simple/requests/?x=1"} {
		if resp, _ = fetch(p); resp.StatusCode != 400 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
	}

	// Index page, JSON form for clients that ask for it (pip >= 22.2, uv);
	// file URLs rewritten.
	const uvAccept = "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.2, text/html;q=0.01"
	resp, b = fetch("/simple/requests/", "Accept", uvAccept)
	expect(t, resp, 200, "MISS")
	want := `"url":"/files/packages/f9/9b/requests-2.32.3-py3-none-any.whl"`
	if !strings.Contains(string(b), want) || strings.Contains(string(b), "pythonhosted") ||
		resp.Header.Get("Content-Type") != simpleJSON || !slices.Equal(resp.Header.Values("Vary"), []string{"Accept", "Accept-Encoding"}) {
		t.Fatalf("simple: %v %s", resp.Header, b)
	}
	if h := upHdrs("/simple/requests/"); h != simpleJSON+"|gzip" {
		t.Fatalf("simple upstream Accept|Accept-Encoding = %q", h)
	}
	resp, b2 := fetch("/simple/requests/", "Accept", "application/vnd.pypi.simple.v1+json, text/html;q=0.1")
	expect(t, resp, 200, "HIT")
	if !bytes.Equal(b, b2) || count("/simple/requests/") != 1 {
		t.Fatalf("simple hit: %d upstream hits", count("/simple/requests/"))
	}
	// PEP 691's latest alias is v1: the same entry.
	resp, b2 = fetch("/simple/requests/", "Accept", "application/vnd.pypi.simple.latest+json")
	expect(t, resp, 200, "HIT")
	if !bytes.Equal(b, b2) || resp.Header.Get("Content-Type") != simpleJSON {
		t.Fatalf("latest+json: %v %s", resp.Header, b2)
	}
	resp, gz := fetch("/simple/requests/", "Accept", simpleJSON, "Accept-Encoding", "gzip")
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("simple not gzipped: %v", resp.Header)
	}
	if zr, err := gzip.NewReader(bytes.NewReader(gz)); err != nil {
		t.Fatal(err)
	} else if plain, _ := io.ReadAll(zr); !bytes.Equal(plain, b) {
		t.Fatal("gzipped simple page differs")
	}
	// HTML for everyone else (pip 22.0 reads nothing but text/html): its own
	// entry, rewritten the same way.
	for _, cs := range []string{"MISS", "HIT"} {
		resp, b = fetch("/simple/requests/", "Accept", "text/html")
		expect(t, resp, 200, cs)
		if !strings.Contains(string(b), `href="/files/packages/f9/9b/requests-2.32.3-py3-none-any.whl#sha256=abc"`) ||
			resp.Header.Get("Content-Type") != "text/html" {
			t.Fatalf("simple HTML: %v %s", resp.Header, b)
		}
	}
	if resp, b2 = fetch("/simple/requests/"); !bytes.Equal(b, b2) || count("/simple/requests/") != 2 {
		t.Fatalf("no Accept: %s, %d upstream hits", b2, count("/simple/requests/"))
	}

	// Upstream 301s (name normalisation, missing slash): forwarded with
	// Location back to us, never cached.
	for path, loc := range map[string]string{
		"/simple/Flask_Login/": "http://pypi.test:8080/simple/flask-login/",
		"/simple/requests":     "http://pypi.test:8080/simple/requests/",
	} {
		for range 2 {
			if resp, _ = fetch(path); resp.StatusCode != 301 || resp.Header.Get("Location") != loc {
				t.Fatalf("%s: %d %v", path, resp.StatusCode, resp.Header)
			}
		}
		if count(path) != 2 {
			t.Fatalf("%s: redirect cached (%d upstream hits)", path, count(path))
		}
	}

	// Unknown project: 404 cached 1m.
	fetch("/simple/nope/")
	resp, _ = fetch("/simple/nope/")
	expect(t, resp, 404, "HIT")

	// The .metadata hash regression: whatever the first client accepts, the
	// stored and served bytes are the identity ones pip hashes.
	const mpath = "/files/packages/f9/9b/requests-2.32.3-py3-none-any.whl.metadata"
	sum := sha256.Sum256(metadata)
	for i, ae := range []string{"gzip, deflate", "identity", "gzip"} {
		resp, b = fetch(mpath, "Accept-Encoding", ae)
		expect(t, resp, 200, map[bool]string{true: "MISS", false: "HIT"}[i == 0])
		if resp.Header.Get("Content-Encoding") != "" || sha256.Sum256(b) != sum {
			t.Fatalf("metadata (%s): encoding %q, hash mismatch %v", ae, resp.Header.Get("Content-Encoding"), sha256.Sum256(b) != sum)
		}
	}
	if h := upHdrs(mpath[len("/files"):]); !strings.HasSuffix(h, "|identity") {
		t.Fatalf("files upstream Accept-Encoding: %q", h)
	}

	// Wheel: the first download streams to its client as it arrives. One
	// overlapping it (here with Range) is relayed whole, uncached; a HEAD
	// meanwhile is relayed as a HEAD.
	const wpath = "/files/packages/f9/9b/requests-2.32.3-py3-none-any.whl"
	first, err := cl.Do(func() *http.Request {
		req, _ := http.NewRequest("GET", srv.URL+wpath, nil)
		req.Host = "pypi.test"
		return req
	}())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()
	expect(t, first, 200, "MISS")
	got := make([]byte, 64<<10)
	if _, err := io.ReadFull(first.Body, got); err != nil {
		t.Fatal(err)
	}
	resp, b = mustGet(t, cl, "GET", srv.URL+wpath, "Host", "pypi.test", "Range", "bytes=5-9")
	expect(t, resp, 200, "BYPASS")
	if !bytes.Equal(b, wheel) {
		t.Fatalf("overlapping wheel: %d bytes", len(b))
	}
	resp, _ = mustGet(t, cl, "HEAD", srv.URL+wpath, "Host", "pypi.test")
	expect(t, resp, 200, "BYPASS")
	if resp.ContentLength != int64(len(wheel)) {
		t.Fatalf("HEAD while filling: %v", resp.Header)
	}
	unblock()
	rest, err := io.ReadAll(first.Body)
	if err != nil || !bytes.Equal(append(got, rest...), wheel) {
		t.Fatalf("wheel body: %d bytes, %v", len(got)+len(rest), err)
	}
	settle(t, c)
	mu.Lock()
	if hits["GET "+wpath[len("/files"):]] != 2 || hits["HEAD "+wpath[len("/files"):]] != 1 {
		t.Fatalf("wheel upstream: %v", hits)
	}
	mu.Unlock()
	// uv reads wheel metadata with Range when there's no .metadata file.
	resp, b = fetch(wpath, "Range", "bytes=5-9")
	expect(t, resp, 206, "HIT")
	if string(b) != "WHEEL" || resp.Header.Get("Accept-Ranges") != "bytes" {
		t.Fatalf("wheel range: %q", b)
	}
	for _, p := range files(t, filepath.Join(c.root, "pypi-files")) {
		f, m, err := openEntry(p)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		if time.Until(m.Expires) < 364*24*time.Hour {
			t.Fatalf("file entry expires in %v", time.Until(m.Expires))
		}
	}

	// Legacy sdist URLs 302 to absolute upstream URLs: pointed back at /files/,
	// uncached.
	const spath = "/files/packages/source/r/requests/requests-2.32.3.tar.gz"
	for range 2 {
		resp, _ = fetch(spath)
		if resp.StatusCode != 302 || resp.Header.Get("Location") != "http://pypi.test:8080/files/packages/63/70/requests-2.32.3.tar.gz" {
			t.Fatalf("source redirect: %d %v", resp.StatusCode, resp.Header)
		}
	}
	// File 404s aren't cached: a just-uploaded file may lag on the CDN.
	fetch("/files/packages/no/pe/x.whl")
	resp, _ = fetch("/files/packages/no/pe/x.whl")
	if resp.StatusCode != 404 || count(spath[len("/files"):]) != 2 || count("/packages/no/pe/x.whl") != 2 {
		t.Fatalf("uncached: 404=%d source=%d", count("/packages/no/pe/x.whl"), count(spath[len("/files"):]))
	}
	if resp, _ = fetch("/packages/f9/9b/requests-2.32.3-py3-none-any.whl"); resp.StatusCode != 404 {
		t.Fatalf("unprefixed path: %d", resp.StatusCode)
	}
}
