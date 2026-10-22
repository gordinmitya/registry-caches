package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// setup returns a cache with a metadata rule under /m/ and a file rule under
// /f/, both pointing at up. Tweak rules before calling front.
func setup(t *testing.T, up string) (*Cache, *registry) {
	t.Helper()
	c := newCache(t.TempDir(), 0, 64)
	c.free = func() int64 { return 1 << 40 }
	mz, err := c.addZone("m", 1<<30, true)
	if err != nil {
		t.Fatal(err)
	}
	fz, err := c.addZone("f", 1<<30, false)
	if err != nil {
		t.Fatal(err)
	}
	return c, &registry{name: "t", public: "http://cache.test", c: c, rules: []*rule{
		{name: "m", match: prefix("/m/"), upstream: up, path: same, zone: mz, ttl: time.Hour, negTTL: time.Minute, compress: []string{"text/"}},
		{name: "f", match: prefix("/f/"), upstream: up, path: same, zone: fz, ttl: time.Hour, negTTL: time.Minute},
	}}
}

// front serves reg over HTTP/1.1, or HTTP/2 (TLS) when h2.
func front(t *testing.T, reg *registry, h2 bool) (string, *http.Client) {
	t.Helper()
	srv := httptest.NewUnstartedServer(router{"127.0.0.1": reg})
	if h2 {
		srv.EnableHTTP2 = true
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	cl := srv.Client()
	cl.Transport.(*http.Transport).DisableCompression = true
	return srv.URL, cl
}

// mustGet sends method url with hdr as name/value pairs ("Host" sets the
// request's Host) and returns the response with its whole body.
func mustGet(t *testing.T, cl *http.Client, method, url string, hdr ...string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	for i := 0; i < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			req.Host = hdr[i+1]
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, b
}

func expect(t *testing.T, resp *http.Response, status int, cache string) {
	t.Helper()
	if resp.StatusCode != status || resp.Header.Get("X-Cache-Status") != cache {
		t.Fatalf("got %d %q, want %d %q", resp.StatusCode, resp.Header.Get("X-Cache-Status"), status, cache)
	}
}

// settle waits for fills to finish: a client can have the last byte of a
// streamed file before the handler has published it.
func settle(t *testing.T, c *Cache) {
	t.Helper()
	for i := 0; ; i++ {
		c.mu.Lock()
		n := len(c.inflight)
		c.mu.Unlock()
		if n == 0 {
			return
		}
		if i > 500 {
			t.Fatal("fills never settled")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func files(t *testing.T, dir string) []string {
	var out []string
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// A miss streams to its client as the bytes arrive, not once the file is in.
func TestStreamingMiss(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789abcdef"), 20000) // 320 KB
	half := 64 << 10
	for _, h2 := range []bool{false, true} {
		t.Run("h2="+strconv.FormatBool(h2), func(t *testing.T) {
			var hits atomic.Int32
			release := make(chan struct{})
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Length", strconv.Itoa(len(data)))
				w.Write(data[:half])
				w.(http.Flusher).Flush()
				<-release
				w.Write(data[half:])
			}))
			defer up.Close()
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			c, reg := setup(t, up.URL)
			url, cl := front(t, reg, h2)

			resp, err := cl.Get(url + "/f/big")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			expect(t, resp, 200, "MISS")
			b := make([]byte, half)
			if _, err := io.ReadFull(resp.Body, b); err != nil {
				t.Fatal(err)
			}
			unblock()
			rest, err := io.ReadAll(resp.Body)
			if err != nil || !bytes.Equal(append(b, rest...), data) {
				t.Fatalf("body: %d bytes, %v", half+len(rest), err)
			}
			settle(t, c)
			resp, b = mustGet(t, cl, "GET", url+"/f/big")
			expect(t, resp, 200, "HIT")
			if !bytes.Equal(b, data) || hits.Load() != 1 {
				t.Fatal("cached body differs or refetched")
			}
		})
	}
}

// A request for a key another one is fetching doesn't wait for it: relayed
// uncached (without the client's credentials), or the expired copy.
func TestOverlap(t *testing.T) {
	data := bytes.Repeat([]byte("o"), 100000)
	var hits atomic.Int32
	var auth atomic.Value
	var block atomic.Bool
	fileGate, metaGate := make(chan struct{}), make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if a := r.Header.Get("Authorization"); a != "" {
			auth.Store(a)
		}
		if strings.HasPrefix(r.URL.Path, "/m/") {
			if block.CompareAndSwap(true, false) {
				<-metaGate
				io.WriteString(w, "new")
				return
			}
			io.WriteString(w, "old")
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Write(data[:1000])
		w.(http.Flusher).Flush()
		if block.CompareAndSwap(true, false) {
			<-fileGate
		}
		w.Write(data[1000:])
	}))
	defer up.Close()
	unblock := sync.OnceFunc(func() { close(fileGate) })
	defer unblock()
	unblockMeta := sync.OnceFunc(func() { close(metaGate) })
	defer unblockMeta()
	c, reg := setup(t, up.URL)
	reg.rules[0].ttl = 50 * time.Millisecond
	url, cl := front(t, reg, false)
	claimed := func() {
		t.Helper()
		for i := 0; ; i++ {
			c.mu.Lock()
			n := len(c.inflight)
			c.mu.Unlock()
			if n == 1 {
				return
			}
			if i > 500 {
				t.Fatal("fill never started")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	block.Store(true)
	first, err := cl.Get(url + "/f/o")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()
	expect(t, first, 200, "MISS")
	resp, b := mustGet(t, cl, "GET", url+"/f/o", "Authorization", "Bearer secret")
	expect(t, resp, 200, "BYPASS")
	if !bytes.Equal(b, data) || resp.Header.Get("Cache-Control") != "private" || auth.Load() != nil {
		t.Fatalf("overlap: %d bytes, %v, upstream Authorization %v", len(b), resp.Header, auth.Load())
	}
	unblock()
	if b, err := io.ReadAll(first.Body); err != nil || len(b) != len(data) {
		t.Fatalf("first: %d bytes, %v", len(b), err)
	}
	settle(t, c)
	resp, _ = mustGet(t, cl, "GET", url+"/f/o")
	expect(t, resp, 200, "HIT")
	if hits.Load() != 2 {
		t.Fatalf("upstream hits %d, want 2", hits.Load())
	}

	// Metadata being refreshed: the expired copy meanwhile.
	mustGet(t, cl, "GET", url+"/m/s")
	time.Sleep(100 * time.Millisecond)
	block.Store(true)
	done := make(chan string)
	go func() {
		resp, b := mustGet(t, cl, "GET", url+"/m/s")
		done <- resp.Header.Get("X-Cache-Status") + " " + string(b)
	}()
	claimed()
	resp, b = mustGet(t, cl, "GET", url+"/m/s")
	expect(t, resp, 200, "STALE")
	if string(b) != "old" || resp.Header.Get("Cache-Control") != "public, max-age=0" {
		t.Fatalf("stale: %q %v", b, resp.Header)
	}
	unblockMeta()
	if got := <-done; got != "EXPIRED new" {
		t.Fatalf("refresh: %q", got)
	}
}

// A request finding the key claimed is relayed, and one with an expired entry
// to fall back on gets it, from its open fd even if eviction unlinks it.
func TestClaimedKeyAndEviction(t *testing.T) {
	var hits atomic.Int32
	var evict atomic.Bool
	var c *Cache
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if evict.Load() {
			c.mu.Lock()
			c.evictLocked(nil, 1<<40)
			c.mu.Unlock()
			http.Error(w, "down", 503)
			return
		}
		io.WriteString(w, "body")
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	reg.rules[1].ttl = 50 * time.Millisecond
	url, cl := front(t, reg, false)
	key := cacheKey("t", "f", up.URL+"/f/k", "", "")

	if !c.claim(key) {
		t.Fatal("claim")
	}
	resp, b := mustGet(t, cl, "GET", url+"/f/k")
	expect(t, resp, 200, "BYPASS")
	if string(b) != "body" || len(files(t, c.root)) != 0 {
		t.Fatalf("claimed: %q, files %v", b, files(t, c.root))
	}
	c.release(key)
	resp, _ = mustGet(t, cl, "GET", url+"/f/k")
	expect(t, resp, 200, "MISS")
	settle(t, c)
	time.Sleep(100 * time.Millisecond)
	c.claim(key)
	resp, b = mustGet(t, cl, "GET", url+"/f/k")
	expect(t, resp, 200, "STALE")
	c.release(key)

	evict.Store(true)
	resp, b = mustGet(t, cl, "GET", url+"/f/k")
	expect(t, resp, 200, "STALE")
	if string(b) != "body" || len(files(t, c.root)) != 0 || hits.Load() != 3 {
		t.Fatalf("evicted under a stale answer: %q, files %v, hits %d", b, files(t, c.root), hits.Load())
	}
}

// An upstream failure after the response is committed must reach clients as
// a broken transfer, never a clean short 200, and must not be cached.
func TestMidBodyFailure(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 100000)
	for _, tc := range []struct {
		name string
		cl   bool // upstream sends Content-Length
		cut  bool // upstream aborts (vs. returns early, leaving body < Content-Length)
	}{{"chunked-abort", false, true}, {"cl-abort", true, true}, {"cl-short", true, false}} {
		for _, h2 := range []bool{false, true} {
			t.Run(tc.name+"/h2="+strconv.FormatBool(h2), func(t *testing.T) {
				var hits atomic.Int32
				die := make(chan struct{})
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					if tc.cl {
						w.Header().Set("Content-Length", strconv.Itoa(len(data)))
					}
					w.Write(data[:len(data)/2])
					w.(http.Flusher).Flush()
					<-die
					if tc.cut {
						panic(http.ErrAbortHandler)
					}
				}))
				defer up.Close()
				kill := sync.OnceFunc(func() { close(die) })
				defer kill()
				c, reg := setup(t, up.URL)
				url, cl := front(t, reg, h2)

				resp, err := cl.Get(url + "/f/x")
				if err != nil {
					t.Fatal(err)
				}
				expect(t, resp, 200, "MISS")
				if _, err := io.ReadFull(resp.Body, make([]byte, 1000)); err != nil {
					t.Fatal(err)
				}
				kill()
				b, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err == nil {
					t.Fatalf("clean EOF after %d bytes; want an aborted transfer", 1000+len(b))
				}
				settle(t, c)
				if f := files(t, reg.rules[1].zone.dir); len(f) != 0 {
					t.Fatalf("left files behind: %v", f)
				}
				if resp, err := cl.Get(url + "/f/x"); err == nil { // fails again, but must go upstream
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				if hits.Load() != 2 {
					t.Fatalf("upstream hits = %d, want 2 (nothing cached)", hits.Load())
				}
			})
		}
	}
}

// A cold HEAD on a file is relayed: no whole download, no entry. On metadata
// it fills like a GET (stale and the rewritten length stay right).
func TestHead(t *testing.T) {
	data := []byte("crate bytes")
	var mu sync.Mutex
	var seen []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/missing") {
			http.Error(w, "nope", 404)
			return
		}
		w.Write(data)
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	reg.rules[0].rewrite = func(b []byte) []byte { return append(b, "+rewritten"...) }
	reg.rules[0].ttl = 50 * time.Millisecond
	url, cl := front(t, reg, false)
	head := func(path string, status int, cs string, length int) {
		t.Helper()
		resp, b := mustGet(t, cl, "HEAD", url+path)
		expect(t, resp, status, cs)
		if len(b) != 0 || resp.ContentLength != int64(length) {
			t.Fatalf("HEAD %s: body %q, length %d, want %d", path, b, resp.ContentLength, length)
		}
		settle(t, c)
	}

	head("/f/a", 200, "BYPASS", len(data))
	if len(files(t, c.root)) != 0 {
		t.Fatal("cold HEAD stored an entry")
	}
	resp, b := mustGet(t, cl, "GET", url+"/f/a")
	expect(t, resp, 200, "MISS")
	if !bytes.Equal(b, data) {
		t.Fatalf("GET after HEAD = %q", b)
	}
	settle(t, c)
	head("/f/a", 200, "HIT", len(data))

	rewritten := len(data) + len("+rewritten")
	head("/m/a", 200, "MISS", rewritten)
	resp, b = mustGet(t, cl, "GET", url+"/m/a")
	expect(t, resp, 200, "HIT")
	if string(b) != string(data)+"+rewritten" {
		t.Fatalf("GET after meta HEAD = %q", b)
	}
	time.Sleep(100 * time.Millisecond)
	head("/m/a", 200, "EXPIRED", rewritten)
	head("/m/missing", 404, "MISS", len("nope\n"))
	head("/m/missing", 404, "HIT", len("nope\n"))

	mu.Lock()
	defer mu.Unlock()
	want := "HEAD /f/a,GET /f/a,GET /m/a,GET /m/a,GET /m/missing"
	if strings.Join(seen, ",") != want {
		t.Fatalf("upstream saw %v, want %s", seen, want)
	}
}

func TestRangeAndConditionalOnCompleteEntry(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			t.Error("Range forwarded upstream")
		}
		io.WriteString(w, "0123456789")
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	url, cl := front(t, reg, true)

	// Range on an in-progress fill is ignored: full 200.
	resp, b := mustGet(t, cl, "GET", url+"/f/r", "Range", "bytes=2-5")
	if resp.StatusCode != 200 || string(b) != "0123456789" {
		t.Fatalf("fill: %d %q", resp.StatusCode, b)
	}
	settle(t, c)
	resp, b = mustGet(t, cl, "GET", url+"/f/r", "Range", "bytes=2-5")
	expect(t, resp, 206, "HIT")
	if string(b) != "2345" {
		t.Fatalf("range body %q", b)
	}
	etag := resp.Header.Get("ETag")
	resp, _ = mustGet(t, cl, "GET", url+"/f/r", "If-None-Match", etag)
	expect(t, resp, 304, "HIT")
}

func TestNegativeCaching(t *testing.T) {
	var hits atomic.Int32
	big := strings.Repeat("x", maxSmall+1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/m/big" {
			http.Error(w, big, 410)
			return
		}
		http.Error(w, "nope", 404)
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	url, cl := front(t, reg, false)

	resp, b := mustGet(t, cl, "GET", url+"/m/missing")
	expect(t, resp, 404, "MISS")
	settle(t, c)
	resp, b2 := mustGet(t, cl, "GET", url+"/m/missing")
	expect(t, resp, 404, "HIT")
	if string(b) != "nope\n" || string(b2) != "nope\n" {
		t.Fatalf("bodies %q %q", b, b2)
	}
	resp, b = mustGet(t, cl, "HEAD", url+"/m/missing")
	expect(t, resp, 404, "HIT")
	if len(b) != 0 || hits.Load() != 1 {
		t.Fatalf("HEAD body %q, hits %d", b, hits.Load())
	}
	// Too big to keep: relayed whole, status kept (GOPROXY lists fall
	// through on 404/410 only), never a 502.
	for range 2 {
		resp, b = mustGet(t, cl, "GET", url+"/m/big")
		expect(t, resp, 410, "MISS")
		if string(b) != big+"\n" {
			t.Fatalf("big 410: %d bytes", len(b))
		}
	}
	if hits.Load() != 3 {
		t.Fatalf("big 410 cached: hits %d", hits.Load())
	}
}

func TestRevalidation(t *testing.T) {
	var conditional, hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/m/nv" {
			io.WriteString(w, "no validators")
			return
		}
		if r.Header.Get("If-None-Match") == `"v1"` {
			conditional.Add(1)
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		io.WriteString(w, "index v1")
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	reg.rules[0].ttl = 100 * time.Millisecond
	url, cl := front(t, reg, false)

	resp, _ := mustGet(t, cl, "GET", url+"/m/i")
	expect(t, resp, 200, "MISS")
	time.Sleep(150 * time.Millisecond)
	resp, b := mustGet(t, cl, "GET", url+"/m/i")
	expect(t, resp, 200, "REVALIDATED")
	if string(b) != "index v1" || conditional.Load() != 1 {
		t.Fatalf("body %q, conditional requests %d", b, conditional.Load())
	}
	settle(t, c)
	resp, _ = mustGet(t, cl, "GET", url+"/m/i")
	expect(t, resp, 200, "HIT")

	// A client asking for a refresh (pip, uv --refresh) gets a fresh entry
	// revalidated; a file is immutable and just served.
	reg.rules[0].ttl = time.Hour
	mustGet(t, cl, "GET", url+"/m/i", "Cache-Control", "no-cache") // stored with the 1h TTL
	entry := files(t, reg.rules[0].zone.dir)
	before, err := os.Stat(entry[0])
	if len(entry) != 1 || err != nil {
		t.Fatalf("entries %v: %v", entry, err)
	}
	for _, hdr := range [][]string{{"Cache-Control", "no-cache"}, {"Cache-Control", "max-age=0"}, {"Cache-Control", `max-age="0"`}, {"Pragma", "no-cache"}} {
		resp, b = mustGet(t, cl, "GET", url+"/m/i", hdr...)
		expect(t, resp, 200, "REVALIDATED")
		if string(b) != "index v1" {
			t.Fatalf("%v: %q", hdr, b)
		}
	}
	// A 304 for a still fresh entry leaves it as it is.
	if after, err := os.Stat(entry[0]); err != nil || !os.SameFile(before, after) {
		t.Fatalf("fresh entry rewritten: %v", err)
	}
	if conditional.Load() != 6 {
		t.Fatalf("refresh: %d conditional requests, want 6", conditional.Load())
	}
	resp, _ = mustGet(t, cl, "GET", url+"/m/i", "Cache-Control", "max-age=60")
	expect(t, resp, 200, "HIT")
	mustGet(t, cl, "GET", url+"/f/i")
	settle(t, c)
	n := hits.Load()
	resp, _ = mustGet(t, cl, "GET", url+"/f/i", "Cache-Control", "no-cache")
	expect(t, resp, 200, "HIT")
	if hits.Load() != n {
		t.Fatal("file refetched on no-cache")
	}
	// Without validators a refresh refetches the body: a MISS, as nothing
	// had expired.
	mustGet(t, cl, "GET", url+"/m/nv")
	resp, _ = mustGet(t, cl, "GET", url+"/m/nv", "Cache-Control", "no-cache")
	expect(t, resp, 200, "MISS")
}

func TestStale(t *testing.T) {
	var mode atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case 0:
			io.WriteString(w, "good")
		case 1:
			w.Header().Set("Retry-After", "7")
			http.Error(w, "down", 503)
		case 2:
			w.Header().Set("Retry-After", "9")
			http.Error(w, "slow down", 429)
		case 3:
			w.Header().Set("Content-Length", "100")
			io.WriteString(w, "partial") // short body: error after headers
		case 4:
			panic(http.ErrAbortHandler) // connection dropped, no response
		}
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	reg.rules[0].ttl = 50 * time.Millisecond
	url, cl := front(t, reg, false)

	resp, _ := mustGet(t, cl, "GET", url+"/m/s")
	expect(t, resp, 200, "MISS")
	time.Sleep(100 * time.Millisecond)
	// No stale copy: the upstream error is passed on, Retry-After included.
	for m, want := range map[int32]int{1: 503, 2: 429} {
		mode.Store(m)
		resp, _ = mustGet(t, cl, "GET", url+"/m/other")
		expect(t, resp, want, "MISS")
		if resp.Header.Get("Retry-After") == "" {
			t.Fatalf("%d: no Retry-After", want)
		}
	}
	for _, m := range []int32{1, 2, 3, 4} {
		mode.Store(m)
		resp, b := mustGet(t, cl, "GET", url+"/m/s")
		expect(t, resp, 200, "STALE")
		if string(b) != "good" || resp.Header.Get("Cache-Control") != "public, max-age=0" {
			t.Fatalf("mode %d: %q %v", m, b, resp.Header)
		}
		settle(t, c)
	}
	// A refresh the client asked for that fails: the fresh copy, but not
	// for the rest of its TTL.
	mode.Store(0)
	reg.rules[0].ttl = time.Hour
	mustGet(t, cl, "GET", url+"/m/fresh")
	mode.Store(1)
	resp, b := mustGet(t, cl, "GET", url+"/m/fresh", "Cache-Control", "no-cache")
	expect(t, resp, 200, "STALE")
	if string(b) != "good" || resp.Header.Get("Cache-Control") != "public, max-age=0" {
		t.Fatalf("failed refresh: %q %v", b, resp.Header)
	}
}

// A transport failure marks the upstream down for a while: requests with a
// stale copy get it without trying upstream; cold ones still try, and a
// response clears the mark.
func TestDownMark(t *testing.T) {
	var hits atomic.Int32
	var drop atomic.Bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if drop.Load() {
			panic(http.ErrAbortHandler)
		}
		io.WriteString(w, "good")
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	reg.rules[0].ttl = 50 * time.Millisecond
	url, cl := front(t, reg, false)

	mustGet(t, cl, "GET", url+"/m/s")
	time.Sleep(100 * time.Millisecond)
	drop.Store(true)
	resp, _ := mustGet(t, cl, "GET", url+"/m/s")
	expect(t, resp, 200, "STALE")
	n := hits.Load() // 3 if the transport retried on a fresh connection
	if n < 2 || !c.isDown(up.URL) {
		t.Fatalf("hits %d, down %v", n, c.isDown(up.URL))
	}
	resp, b := mustGet(t, cl, "GET", url+"/m/s")
	expect(t, resp, 200, "STALE")
	if string(b) != "good" || hits.Load() != n {
		t.Fatalf("tried a down upstream with a stale copy: hits %d → %d", n, hits.Load())
	}
	for _, p := range []string{"/m/cold", "/f/cold"} {
		resp, _ = mustGet(t, cl, "GET", url+p)
		expect(t, resp, 502, "MISS")
	}
	if hits.Load() == n {
		t.Fatal("cold requests never tried upstream")
	}
	drop.Store(false)
	resp, _ = mustGet(t, cl, "GET", url+"/m/cold")
	expect(t, resp, 200, "MISS")
	if c.isDown(up.URL) {
		t.Fatal("still down after a response")
	}
	resp, _ = mustGet(t, cl, "GET", url+"/m/s")
	expect(t, resp, 200, "EXPIRED")
}

func TestEvictionUnderCap(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte("e"), 1000))
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	const entry = hdrSize + 1000
	small, err := c.addZone("small", 3*entry, false)
	if err != nil {
		t.Fatal(err)
	}
	reg.rules = append(reg.rules, &rule{name: "s", match: prefix("/s/"), upstream: up.URL, path: same, zone: small, ttl: time.Hour})
	url, cl := front(t, reg, false)

	for i := range 5 {
		mustGet(t, cl, "GET", url+"/s/"+strconv.Itoa(i))
		settle(t, c)
		c.mu.Lock()
		used := small.used
		c.mu.Unlock()
		if used > small.cap || used != int64(len(files(t, small.dir)))*entry {
			t.Fatalf("after %d: used %d, cap %d, files %d", i, used, small.cap, len(files(t, small.dir)))
		}
	}
	resp, _ := mustGet(t, cl, "GET", url+"/s/4")
	expect(t, resp, 200, "HIT")
	resp, _ = mustGet(t, cl, "GET", url+"/s/0")
	expect(t, resp, 200, "MISS")
}

func TestNoRoomBypasses(t *testing.T) {
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "payload")
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	c.free = func() int64 { return 0 } // disk below the free-space reserve
	c.minFree = 1
	url, cl := front(t, reg, false)

	resp, b := mustGet(t, cl, "GET", url+"/f/x")
	expect(t, resp, 200, "BYPASS")
	if string(b) != "payload" {
		t.Fatalf("body %q", b)
	}
	resp, b = mustGet(t, cl, "GET", url+"/m/x")
	expect(t, resp, 200, "BYPASS")
	if string(b) != "payload" {
		t.Fatalf("body %q", b)
	}
	settle(t, c)
	if f := files(t, c.root); len(f) != 0 {
		t.Fatalf("stored despite no room: %v", f)
	}
}

func TestStartupCleanup(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "kept")
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	url, cl := front(t, reg, false)
	mustGet(t, cl, "GET", url+"/f/a")
	settle(t, c)
	dir := reg.rules[1].zone.dir
	valid := files(t, dir)
	if len(valid) != 1 {
		t.Fatalf("files %v", valid)
	}
	good, _ := os.ReadFile(valid[0])
	junk := filepath.Join(dir, "zz")
	os.MkdirAll(junk, 0o755)
	os.WriteFile(filepath.Join(junk, ".tmp-123"), good, 0o644)              // interrupted fill
	os.WriteFile(filepath.Join(junk, "garbage"), []byte("not json"), 0o644) // unreadable header
	os.WriteFile(filepath.Join(junk, "short"), good[:len(good)-1], 0o644)   // body shorter than meta says

	c2 := newCache(c.root, 0, 64)
	z, err := c2.addZone("f", 1<<30, false)
	if err != nil {
		t.Fatal(err)
	}
	if f := files(t, dir); len(f) != 1 || f[0] != valid[0] {
		t.Fatalf("after cleanup: %v", f)
	}
	if z.used != int64(len(good)) {
		t.Fatalf("used %d, want %d", z.used, len(good))
	}
}

func TestPathValidation(t *testing.T) {
	for _, tc := range []struct {
		path string
		ok   bool
	}{
		{"/f/a..b/c", true},
		{"/f/@scope%2fpkg", true},
		{"/f/a/../b", false},
		{"/f/a/./b", false},
		{"/f/a/%2e%2e/b", false},
		{"/f/a%2f..%2fb", false},
		{"/f/..", false},
		{"//evil.example/x", false},
		{"/f/a//b", false},
		{"/f/a%2f%2fb", false},
		{"/f/a/", true},
		{"/f/%00", false},
		{"/f/%zz", false},
		{"/f/" + strings.Repeat("a", 2100), false},
	} {
		if err := checkPath(tc.path, ""); (err == nil) != tc.ok {
			t.Errorf("checkPath(%q) = %v, want ok=%v", tc.path, err, tc.ok)
		}
	}
	if checkPath("/f/x", strings.Repeat("q", 1100)) == nil {
		t.Error("long query accepted")
	}
	// A raw '#' would end the query upstream but not in our key; a space or
	// non-ASCII byte isn't a query character at all.
	for q, ok := range map[string]bool{
		"text=a%20b&size=20":     true,
		"a=b/c?d:e@f!$'()*+,;=~": true,
		"a=1#frag":               false,
		"a=b c":                  false,
		"a=\x7f":                 false,
		"a=\xc3\xa9":             false,
		"a=%zz":                  false,
	} {
		if err := checkPath("/f/x", q); (err == nil) != ok {
			t.Errorf("checkPath query %q = %v, want ok=%v", q, err, ok)
		}
	}

	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.EscapedPath() != "/f/@scope%2fpkg" {
			t.Errorf("upstream got %q", r.URL.EscapedPath())
		}
	}))
	defer up.Close()
	_, reg := setup(t, up.URL)
	url, cl := front(t, reg, false)
	// Upstreams collapse empty segments and ignore unknown queries: each
	// spelling would be another fill of the same thing. Only a registry that
	// takes queries (npm) accepts one.
	for _, p := range []string{"/f/a/%2e%2e/m/x", "/f/a//b", "/f/x?y=1"} {
		resp, _ := mustGet(t, cl, "GET", url+p)
		if resp.StatusCode != 400 || hits.Load() != 0 {
			t.Fatalf("%s: %d, upstream hits %d", p, resp.StatusCode, hits.Load())
		}
	}
	resp, _ := mustGet(t, cl, "GET", url+"/f/@scope%2fpkg")
	if resp.StatusCode != 200 || hits.Load() != 1 {
		t.Fatalf("escaped slash: %d, upstream hits %d", resp.StatusCode, hits.Load())
	}
	resp, _ = mustGet(t, cl, "POST", url+"/f/x")
	if resp.StatusCode != 405 {
		t.Fatalf("POST: %d", resp.StatusCode)
	}
}

func TestGzipNegotiation(t *testing.T) {
	text := strings.Repeat("serde 1.0.0 index line\n", 200)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, text)
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	url, cl := front(t, reg, true)
	mustGet(t, cl, "GET", url+"/m/g")
	settle(t, c)

	resp, b := mustGet(t, cl, "GET", url+"/m/g", "Accept-Encoding", "br, gzip")
	gzTag := resp.Header.Get("ETag")
	if resp.Header.Get("Content-Encoding") != "gzip" || resp.Header.Get("Vary") != "Accept-Encoding" ||
		resp.ContentLength == int64(len(text)) || !strings.HasPrefix(gzTag, `"`) || !strings.HasSuffix(gzTag, `-gz"`) {
		t.Fatalf("gzip headers: %v (len %d)", resp.Header, resp.ContentLength)
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if plain, _ := io.ReadAll(zr); string(plain) != text {
		t.Fatal("gunzipped body differs")
	}
	plainTag := strings.TrimSuffix(gzTag, `-gz"`) + `"`
	// A 304 carries what the 200 would: validators, Vary, Cache-Control.
	for _, inm := range []string{gzTag, "W/" + gzTag, `"other", W/` + gzTag} {
		resp, _ = mustGet(t, cl, "GET", url+"/m/g", "Accept-Encoding", "gzip", "If-None-Match", inm)
		expect(t, resp, 304, "HIT")
		if resp.Header.Get("ETag") != gzTag || resp.Header.Get("Vary") != "Accept-Encoding" ||
			!strings.HasPrefix(resp.Header.Get("Cache-Control"), "public, max-age=") {
			t.Fatalf("304 for %s: %v", inm, resp.Header)
		}
	}
	// A tag matches its own variant only.
	resp, _ = mustGet(t, cl, "GET", url+"/m/g", "Accept-Encoding", "gzip", "If-None-Match", plainTag)
	if resp.StatusCode != 200 || resp.Header.Get("ETag") != gzTag {
		t.Fatalf("identity tag matched gzip: %d %v", resp.StatusCode, resp.Header)
	}
	resp, _ = mustGet(t, cl, "GET", url+"/m/g", "If-None-Match", plainTag)
	expect(t, resp, 304, "HIT")
	if resp.Header.Get("ETag") != plainTag || resp.Header.Get("Vary") != "Accept-Encoding" || resp.Header.Get("Cache-Control") == "" {
		t.Fatalf("identity 304: %v", resp.Header)
	}
	resp, _ = mustGet(t, cl, "GET", url+"/m/g", "If-None-Match", gzTag)
	if resp.StatusCode != 200 || resp.Header.Get("ETag") != plainTag {
		t.Fatalf("gzip tag matched identity: %d %v", resp.StatusCode, resp.Header)
	}
	resp, b = mustGet(t, cl, "HEAD", url+"/m/g", "Accept-Encoding", "gzip")
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "gzip" || len(b) != 0 {
		t.Fatalf("HEAD gzip: %d %v", resp.StatusCode, resp.Header)
	}

	for _, ae := range []string{"gzip;q=0", "*;q=1, gzip;q=0", "identity", ""} {
		resp, b = mustGet(t, cl, "GET", url+"/m/g", "Accept-Encoding", ae)
		if resp.Header.Get("Content-Encoding") != "" || string(b) != text || resp.Header.Get("Vary") != "Accept-Encoding" ||
			resp.Header.Get("ETag") != plainTag {
			t.Fatalf("AE %q: %v", ae, resp.Header)
		}
	}
	resp, b = mustGet(t, cl, "GET", url+"/m/g", "Accept-Encoding", "gzip", "Range", "bytes=0-4")
	if resp.StatusCode != 206 || resp.Header.Get("Content-Encoding") != "" || string(b) != "serde" {
		t.Fatalf("Range+gzip: %d %v %q", resp.StatusCode, resp.Header, b)
	}
	// Non-compressible rule never gzips.
	mustGet(t, cl, "GET", url+"/f/g")
	settle(t, c)
	resp, _ = mustGet(t, cl, "GET", url+"/f/g", "Accept-Encoding", "gzip")
	if resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("Vary") != "" {
		t.Fatalf("files zone: %v", resp.Header)
	}
}

// A body under 1 KiB is sent identity, with its plain tag, still under Vary.
func TestGzipSmall(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "small")
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	url, cl := front(t, reg, true)
	mustGet(t, cl, "GET", url+"/m/s")
	settle(t, c)
	resp, b := mustGet(t, cl, "GET", url+"/m/s", "Accept-Encoding", "gzip")
	tag := resp.Header.Get("ETag")
	if resp.Header.Get("Content-Encoding") != "" || string(b) != "small" || resp.Header.Get("Vary") != "Accept-Encoding" ||
		strings.HasSuffix(tag, `-gz"`) {
		t.Fatalf("small: %v %q", resp.Header, b)
	}
	resp, _ = mustGet(t, cl, "GET", url+"/m/s", "Accept-Encoding", "gzip", "If-None-Match", tag)
	expect(t, resp, 304, "HIT")
}

// Metadata fills ask upstream for gzip and store the decoded bytes; files
// are always fetched as identity.
func TestGzipUpstream(t *testing.T) {
	text := strings.Repeat("requests 2.32.3 ", 1000)
	var mu sync.Mutex
	ae := map[string]string{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ae[r.URL.Path] = r.Header.Get("Accept-Encoding")
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		if r.Header.Get("Accept-Encoding") == "gzip" {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("ETag", `"gz"`)
			if r.Header.Get("If-None-Match") == `"gz"` {
				w.WriteHeader(304)
				return
			}
			if r.URL.Path == "/m/missing" {
				w.WriteHeader(404)
			}
			zw := gzip.NewWriter(w)
			io.WriteString(zw, text)
			zw.Close()
			return
		}
		io.WriteString(w, text)
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	reg.rules[0].ttl = 50 * time.Millisecond
	reg.rules[0].rewrite = func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("requests"), []byte("REQUESTS")) }
	url, cl := front(t, reg, false)

	want := strings.ReplaceAll(text, "requests", "REQUESTS")
	for _, cs := range []string{"MISS", "HIT"} {
		resp, b := mustGet(t, cl, "GET", url+"/m/p")
		expect(t, resp, 200, cs)
		if string(b) != want || resp.Header.Get("Content-Encoding") != "" || resp.ContentLength != int64(len(want)) {
			t.Fatalf("%s: %d bytes, %v", cs, len(b), resp.Header)
		}
	}
	time.Sleep(100 * time.Millisecond)
	resp, b := mustGet(t, cl, "GET", url+"/m/p")
	expect(t, resp, 200, "REVALIDATED")
	if string(b) != want {
		t.Fatalf("revalidated: %d bytes", len(b))
	}
	resp, b = mustGet(t, cl, "GET", url+"/m/missing")
	expect(t, resp, 404, "MISS")
	if string(b) != text {
		t.Fatalf("negative: %d bytes", len(b))
	}
	resp, b = mustGet(t, cl, "GET", url+"/f/w")
	expect(t, resp, 200, "MISS")
	if string(b) != text {
		t.Fatalf("file: %d bytes", len(b))
	}
	// An overlap relay of metadata asks gzip too.
	if !c.claim(cacheKey("t", "m", up.URL+"/m/o", "", reg.public)) {
		t.Fatal("claim")
	}
	resp, b = mustGet(t, cl, "GET", url+"/m/o")
	expect(t, resp, 200, "BYPASS")
	if string(b) != want || resp.Header.Get("Content-Encoding") != "" || resp.ContentLength != int64(len(want)) {
		t.Fatalf("overlap: %d bytes, %v", len(b), resp.Header)
	}
	mu.Lock()
	defer mu.Unlock()
	if ae["/m/p"] != "gzip" || ae["/m/o"] != "gzip" || ae["/f/w"] != "identity" {
		t.Fatalf("upstream Accept-Encoding: %v", ae)
	}
}

// Clients may keep files forever and metadata for what is left of its TTL;
// relayed answers only privately.
func TestCacheControl(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=3600") // files and 404s ignore it
		if strings.HasSuffix(r.URL.Path, "/missing") {
			http.Error(w, "nope", 404)
			return
		}
		io.WriteString(w, "x")
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	url, cl := front(t, reg, false)
	maxAge := func(resp *http.Response) int {
		t.Helper()
		n, err := strconv.Atoi(strings.TrimPrefix(resp.Header.Get("Cache-Control"), "public, max-age="))
		if err != nil {
			t.Fatalf("Cache-Control %q", resp.Header.Get("Cache-Control"))
		}
		return n
	}
	for _, cs := range []string{"MISS", "HIT"} {
		resp, _ := mustGet(t, cl, "GET", url+"/f/a")
		expect(t, resp, 200, cs)
		if resp.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatalf("file %s: %v", cs, resp.Header)
		}
		settle(t, c)
		resp, _ = mustGet(t, cl, "GET", url+"/m/a")
		expect(t, resp, 200, cs)
		if n := maxAge(resp); n > 3600 || n < 3590 {
			t.Fatalf("meta %s: max-age %d", cs, n)
		}
		resp, _ = mustGet(t, cl, "GET", url+"/m/missing")
		expect(t, resp, 404, cs)
		if n := maxAge(resp); n > 60 || n < 50 {
			t.Fatalf("negative %s: max-age %d", cs, n)
		}
	}
	reg.rules[0].pass = func(*http.Request) bool { return true }
	resp, _ := mustGet(t, cl, "GET", url+"/m/a")
	expect(t, resp, 200, "BYPASS")
	if resp.Header.Get("Cache-Control") != "private" {
		t.Fatalf("relay: %v", resp.Header)
	}
}

func TestFailBeforeFirstByteIs502(t *testing.T) {
	var fail atomic.Bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !fail.Load() {
			io.WriteString(w, "good")
			return
		}
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	reg.rules[1].ttl = 50 * time.Millisecond
	url, cl := front(t, reg, false)
	mustGet(t, cl, "GET", url+"/f/old")
	settle(t, c)
	time.Sleep(100 * time.Millisecond)
	fail.Store(true)
	resp, _ := mustGet(t, cl, "GET", url+"/f/x")
	expect(t, resp, 502, "MISS")
	resp, b := mustGet(t, cl, "GET", url+"/f/old")
	expect(t, resp, 200, "STALE")
	if string(b) != "good" {
		t.Fatalf("stale: %q", b)
	}
}

// Bytes already written by a fill show in statfs; they must not also stay
// reserved, or every concurrent fill counts against the free-space reserve
// twice.
func TestStreamingSettlesReservation(t *testing.T) {
	const size, head = 4 << 20, 3 << 20
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Write(make([]byte, head))
		w.(http.Flusher).Flush()
		<-release
		w.Write(make([]byte, size-head))
	}))
	defer up.Close()
	defer close(release)
	c, reg := setup(t, up.URL)
	url, cl := front(t, reg, false)
	resp, err := cl.Get(url + "/f/big")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadFull(resp.Body, make([]byte, head)); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	unwritten := c.unwritten
	c.mu.Unlock()
	if unwritten > size-head+growStep+hdrSize {
		t.Fatalf("unwritten = %d with %d of %d bytes on disk", unwritten, head, size)
	}
}

// A body that arrived whole but can't be stored (here: meta too big for the
// header area) is still served whole, just not cached, and leaves nothing
// behind.
func TestUnstorableBodyStillServed(t *testing.T) {
	var hits atomic.Int32
	data := bytes.Repeat([]byte("y"), 200000)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("ETag", `"`+strings.Repeat("e", hdrSize)+`"`)
		w.Write(data)
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	url, cl := front(t, reg, false)
	for range 2 {
		resp, b := mustGet(t, cl, "GET", url+"/f/u")
		expect(t, resp, 200, "MISS")
		if !bytes.Equal(b, data) {
			t.Fatalf("got %d bytes, want %d", len(b), len(data))
		}
		settle(t, c)
	}
	c.mu.Lock()
	unwritten, used := c.unwritten, reg.rules[1].zone.used
	c.mu.Unlock()
	if f := files(t, c.root); len(f) != 0 || hits.Load() != 2 || unwritten != 0 || used != 0 {
		t.Fatalf("files %v, upstream hits %d, unwritten %d, used %d", f, hits.Load(), unwritten, used)
	}
}

// A client leaving mid-fill cancels the fetch: no entry, temp file,
// reservation or claim is left.
func TestClientAbortMidFill(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run("h2="+strconv.FormatBool(h2), func(t *testing.T) {
			stop := make(chan struct{})
			upGone := make(chan struct{})
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(upGone)
				w.Header().Set("Content-Length", "1000000")
				w.Write(make([]byte, 100000))
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
				case <-stop:
				}
			}))
			defer up.Close()
			defer close(stop)
			c, reg := setup(t, up.URL)
			url, cl := front(t, reg, h2)
			ctx, cancel := context.WithCancel(context.Background())
			req, _ := http.NewRequestWithContext(ctx, "GET", url+"/f/big", nil)
			resp, err := cl.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(resp.Body, make([]byte, 1000)); err != nil {
				t.Fatal(err)
			}
			cancel()
			resp.Body.Close()
			select {
			case <-upGone: // our fetch was cancelled
			case <-time.After(10 * time.Second):
				t.Fatal("upstream fetch outlived its client")
			}
			settle(t, c)
			c.mu.Lock()
			unwritten, used := c.unwritten, reg.rules[1].zone.used
			c.mu.Unlock()
			if f := files(t, c.root); len(f) != 0 || unwritten != 0 || used != 0 {
				t.Fatalf("left behind: files %v, unwritten %d, used %d", f, unwritten, used)
			}
		})
	}
}

// A metadata fill outlives a client that gave up waiting for it (pip's 15s
// read timeout on a slow page): its retry is a HIT.
func TestMetaFillOutlivesClient(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		io.WriteString(w, "slow page")
	}))
	defer up.Close()
	defer up.CloseClientConnections()
	c, reg := setup(t, up.URL)
	url, cl := front(t, reg, false)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url+"/m/slow", nil)
	if _, err := cl.Do(req); err == nil {
		t.Fatal("request did not time out")
	}
	close(release)
	settle(t, c)
	resp, b := mustGet(t, cl, "GET", url+"/m/slow")
	expect(t, resp, 200, "HIT")
	if string(b) != "slow page" {
		t.Fatalf("body %q", b)
	}
}

// A file the cache can't keep (here: unknown length, over the zone's
// per-object limit) still reaches its client whole, and leaves nothing.
func TestStorageFailureStillServed(t *testing.T) {
	data := bytes.Repeat([]byte("z"), 3<<20)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data[:1000])
		w.(http.Flusher).Flush() // chunked: no Content-Length
		w.Write(data[1000:])
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	small, err := c.addZone("small", 4<<20, false) // 2 MiB per object
	if err != nil {
		t.Fatal(err)
	}
	reg.rules[1].zone = small
	url, cl := front(t, reg, false)
	for range 2 {
		resp, b := mustGet(t, cl, "GET", url+"/f/big")
		expect(t, resp, 200, "MISS")
		if !bytes.Equal(b, data) {
			t.Fatalf("got %d bytes, want %d", len(b), len(data))
		}
		settle(t, c)
	}
	c.mu.Lock()
	unwritten, used := c.unwritten, small.used
	c.mu.Unlock()
	if f := files(t, c.root); len(f) != 0 || unwritten != 0 || used != 0 {
		t.Fatalf("left behind: files %v, unwritten %d, used %d", f, unwritten, used)
	}
}

// MAX_FILLS bounds every upstream request, relays included.
func TestFillLimitBoundsRelays(t *testing.T) {
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "x")
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	reg.rules[0].pass = func(*http.Request) bool { return true }
	url, cl := front(t, reg, false)
	for range cap(c.fillSem) {
		c.fillSem <- struct{}{}
	}
	done := make(chan *http.Response)
	go func() {
		resp, _ := mustGet(t, cl, "GET", url+"/m/x")
		done <- resp
	}()
	time.Sleep(300 * time.Millisecond)
	if hits.Load() != 0 {
		t.Fatal("relay went upstream past the fill limit")
	}
	<-c.fillSem
	expect(t, <-done, 200, "BYPASS")
}

// Nothing reads a body on a cached route: refused, and the connection closed
// rather than drained (a stalled upload would hold it forever).
func TestRequestBodyRejected(t *testing.T) {
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer up.Close()
	_, reg := setup(t, up.URL)
	url, cl := front(t, reg, false)
	for _, body := range []io.Reader{strings.NewReader("x"), io.MultiReader(strings.NewReader("x"))} {
		req, _ := http.NewRequest("GET", url+"/m/x", body)
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 || !resp.Close {
			t.Fatalf("body: %d, close %v", resp.StatusCode, resp.Close)
		}
	}
	// Every early error closes too: a bad path or query, an unknown host, a
	// relay whose upstream can't be reached.
	reg.rules = append(reg.rules, &rule{name: "p", match: prefix("/p/"), upstream: "http://127.0.0.1:1",
		path: same, pass: func(*http.Request) bool { return true }})
	for _, start := range []string{
		"GET /m/x HTTP/1.1\r\nHost: 127.0.0.1\r\n",
		"GET /m//x HTTP/1.1\r\nHost: 127.0.0.1\r\n",
		"GET /m/x?q=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n",
		"GET /m/x HTTP/1.1\r\nHost: elsewhere\r\n",
		"POST /p/x HTTP/1.1\r\nHost: 127.0.0.1\r\n",
	} {
		conn, err := net.Dial("tcp", strings.TrimPrefix(url, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(conn, start+"Content-Length: 10\r\n\r\nx")
		b, err := io.ReadAll(conn) // EOF: the server closed without waiting for the rest
		conn.Close()
		if err != nil || !bytes.HasPrefix(b, []byte("HTTP/1.1 4")) && !bytes.HasPrefix(b, []byte("HTTP/1.1 5")) {
			t.Fatalf("stalled upload, %q: %v %q", start, err, b)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream hits %d", hits.Load())
	}

	// Some HTTP/2 stacks end a bodyless GET with an empty DATA frame, which
	// reads as a body of unknown length.
	url, cl = front(t, reg, true)
	req, _ := http.NewRequest("GET", url+"/m/x", io.MultiReader())
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Close {
		t.Fatalf("HTTP/2 GET, empty body of unknown length: %d, close %v", resp.StatusCode, resp.Close)
	}
}

// Eviction unlinks entries a client may still be reading, which keeps their
// blocks: admission measures free space again rather than counting them freed.
func TestAdmitRemeasures(t *testing.T) {
	c := newCache(t.TempDir(), 0, 64)
	c.free = func() int64 { return 1 << 40 }
	z, err := c.addZone("z", 1<<30, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		m := newMeta("", 200, http.Header{}, make([]byte, 1000), time.Hour)
		if err := c.publish(z, filepath.Join(z.dir, strconv.Itoa(i)), m, make([]byte, 1000)); err != nil {
			t.Fatal(err)
		}
	}
	c.free = func() int64 { return 10000 }
	c.minFree = 10000
	c.mu.Lock()
	ok := c.admitLocked(z, 1000)
	c.mu.Unlock()
	if ok {
		t.Fatal("admitted on space eviction did not free")
	}
}

// A client that leaves before any answer is logged as 499, not 200: a file
// fill ends with it, a metadata fill answers after it left.
func TestAccessLog499(t *testing.T) {
	for _, p := range []string{"/f/slow", "/m/slow"} {
		t.Run(p, func(t *testing.T) {
			logs := &lockedBuffer{}
			defer slog.SetDefault(slog.Default())
			slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
			stop := make(chan struct{})
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-r.Context().Done():
				case <-stop:
					io.WriteString(w, "late")
				}
			}))
			defer up.Close()
			c, reg := setup(t, up.URL)
			srv := httptest.NewServer(router{"127.0.0.1": reg})
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+p, nil)
			if _, err := http.DefaultClient.Do(req); err == nil {
				t.Fatal("request did not time out")
			}
			time.Sleep(50 * time.Millisecond) // for the server to see the client leave
			close(stop)
			srv.Close() // waits for the handler
			logs.mu.Lock()
			out := logs.b.String()
			logs.mu.Unlock()
			if !strings.Contains(out, "status=499") || strings.Contains(out, "upstream fetch failed") || c.isDown(up.URL) {
				t.Fatalf("down %v, log:\n%s", c.isDown(up.URL), out)
			}
		})
	}
}

// relay's own errors don't carry the upstream headers of the answer it
// failed to relay.
func TestRelayErrorHeaders(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/m/stale" && r.Header.Get("If-None-Match") == "" {
			w.Header().Set("ETag", `"v1"`)
			io.WriteString(w, "good")
			return
		}
		w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		w.Header().Set("WWW-Authenticate", "OTP")
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, "short") // then the connection closes
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	reg.rules[0].rewrite = func(b []byte) []byte { return b }
	url, cl := front(t, reg, false)
	resp, _ := mustGet(t, cl, "GET", url+"/m/x")
	expect(t, resp, 502, "MISS")
	if h := resp.Header; h.Get("Last-Modified") != "" || h.Get("WWW-Authenticate") != "" {
		t.Fatalf("502 with upstream headers: %v", h)
	}
	// With an expired copy, a body that breaks before any header went out
	// is a network error like any other: the copy is served.
	reg.rules[0].ttl = 50 * time.Millisecond
	mustGet(t, cl, "GET", url+"/m/stale")
	settle(t, c) // else the claim, not the failed fetch, serves the copy
	time.Sleep(100 * time.Millisecond)
	resp, b := mustGet(t, cl, "GET", url+"/m/stale")
	expect(t, resp, 200, "STALE")
	if string(b) != "good" {
		t.Fatalf("stale: %q", b)
	}
}

// net/http hands an HTTP/2 :method that isn't a token to handlers; building
// the upstream request from it fails, which must be a 400, not a nil request.
func TestPassthroughBadMethod(t *testing.T) {
	_, reg := setup(t, "http://127.0.0.1:1")
	reg.rules[0].pass = func(*http.Request) bool { return true }
	r := httptest.NewRequest("GET", "/m/x", nil)
	r.Method = "BAD METHOD"
	w := httptest.NewRecorder()
	reg.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d", w.Code)
	}
}

// Replacing an expired entry while eviction runs in the same zone must never
// leave the accounting listing a file that isn't there (eviction deleting the
// new file under the old entry's name).
func TestReplaceRacesEviction(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 1000))
	}))
	defer up.Close()
	c, reg := setup(t, up.URL)
	const entry = hdrSize + 1000
	z, err := c.addZone("tiny", 6*entry, true)
	if err != nil {
		t.Fatal(err)
	}
	reg.rules = append(reg.rules, &rule{name: "t", match: prefix("/t/"), upstream: up.URL, path: same, zone: z, ttl: time.Nanosecond})
	url, cl := front(t, reg, false)
	// Under c.mu every accounted entry must exist; a later refill of the key
	// would hide a phantom again, so look while the load runs.
	check := func() (sum int64) {
		c.mu.Lock()
		defer c.mu.Unlock()
		for p, e := range c.entries {
			if e.z != z {
				continue
			}
			if _, err := os.Stat(p); err != nil {
				t.Errorf("accounted entry missing on disk: %v", err)
				return 0
			}
			sum += e.size
		}
		return sum
	}
	stop := make(chan struct{})
	checked := make(chan struct{})
	go func() {
		defer close(checked)
		for {
			select {
			case <-stop:
				return
			default:
				check()
			}
		}
	}()
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Go(func() {
			for i := range 50 {
				mustGet(t, cl, "GET", url+"/t/"+strconv.Itoa((g+i)%8))
			}
		})
	}
	wg.Wait()
	close(stop)
	<-checked
	settle(t, c)
	sum := check()
	c.mu.Lock()
	defer c.mu.Unlock()
	if sum != z.used || c.unwritten != 0 {
		t.Fatalf("entries sum %d, zone used %d, unwritten %d", sum, z.used, c.unwritten)
	}
}

func TestFollowRedirect(t *testing.T) {
	var targetHits atomic.Int32
	var leaked atomic.Value
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		if v := r.Header.Get("Authorization") + r.Header.Get("Cookie") + r.Header.Get("If-None-Match"); v != "" {
			leaked.Store(v)
		}
		switch r.URL.Path {
		case "/again":
			http.Redirect(w, r, "https://example.com/obj", http.StatusFound)
			return
		case "/dead": // GCS failing mid-request
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		io.WriteString(w, "target:"+r.URL.RawQuery)
	}))
	defer target.Close()
	redirects := map[string]string{
		"/f/ok":     "https://example.com/obj?sig=1",
		"/f/ok443":  "https://example.com:443/obj?sig=2",
		"/f/http":   "http://example.com/obj",
		"/f/host":   "https://example.com.evil.test/obj",
		"/f/port":   "https://example.com:8443/obj",
		"/f/user":   "https://u:p@example.com/obj",
		"/f/rel":    "/obj",
		"/f/twice":  "https://example.com/again",
		"/m/ok":     "https://example.com/obj",
		"/f/bypass": "https://example.com/obj?sig=3",
		"/f/stall":  "https://example.com/obj?sig=4",
		"/f/dead":   "https://example.com/dead?sig=secret",
		"/f/badloc": "https://example.com:x/obj?sig=secret",
	}
	stalled := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", redirects[r.URL.Path])
		if r.URL.Path == "/f/stall" { // promises a body, never sends it
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusFound)
			w.(http.Flusher).Flush()
			<-stalled
			return
		}
		w.WriteHeader(http.StatusFound)
	}))
	defer up.Close()
	defer close(stalled)
	c, reg := setup(t, up.URL)
	reg.rules[1].follow = "example.com"
	// example.com:443 is the target (its test certificate covers example.com).
	// Any other dial but the upstream is recorded and refused, so a redirect
	// check that let one through shows up here whatever the network.
	var mu sync.Mutex
	var strays []string
	for _, tr := range []*http.Transport{c.tr, c.ftr} {
		tr.TLSClientConfig = target.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			switch addr {
			case "example.com:443":
				addr = target.Listener.Addr().String()
			case up.Listener.Addr().String():
			default:
				mu.Lock()
				strays = append(strays, addr)
				mu.Unlock()
				return nil, errors.New("test: dial refused")
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
	}
	url, cl := front(t, reg, false)

	for path, query := range map[string]string{"/f/ok": "sig=1", "/f/ok443": "sig=2"} {
		resp, b := mustGet(t, cl, "GET", url+path, "Authorization", "Bearer x", "Cookie", "a=b")
		expect(t, resp, 200, "MISS")
		if string(b) != "target:"+query || resp.Header.Get("Location") != "" {
			t.Fatalf("%s: %q %v", path, b, resp.Header)
		}
		settle(t, c)
		resp, b = mustGet(t, cl, "GET", url+path)
		expect(t, resp, 200, "HIT")
		if string(b) != "target:"+query {
			t.Fatalf("%s hit: %q", path, b)
		}
	}
	if targetHits.Load() != 2 || leaked.Load() != nil {
		t.Fatalf("target hits %d, leaked %v", targetHits.Load(), leaked.Load())
	}

	before := len(files(t, c.root))
	for _, path := range []string{"/f/http", "/f/host", "/f/port", "/f/user", "/f/rel", "/f/twice"} {
		resp, _ := mustGet(t, cl, "GET", url+path)
		if resp.StatusCode != http.StatusBadGateway || resp.Header.Get("Location") != "" {
			t.Fatalf("%s: %d %v", path, resp.StatusCode, resp.Header)
		}
	}
	settle(t, c)
	if targetHits.Load() != 3 || len(files(t, c.root)) != before || len(strays) != 0 { // only /f/twice's first hop
		t.Fatalf("refused redirects: target hits %d, files %d→%d, dialed %v", targetHits.Load(), before, len(files(t, c.root)), strays)
	}

	// A redirect whose body stalls is not waited on: no idle watchdog covers
	// it yet, so draining it would hold a fill slot until maxFill.
	quick := *cl
	quick.Timeout = 5 * time.Second
	resp, b := mustGet(t, &quick, "GET", url+"/f/stall")
	expect(t, resp, 200, "MISS")
	if string(b) != "target:sig=4" {
		t.Fatalf("stall: %q", b)
	}

	// A failed second hop, or a Location that doesn't parse, doesn't put
	// the signed URL in the error (logged).
	for path, want := range map[string]string{"/f/dead": "example.com/dead", "/f/badloc": "refusing upstream redirect"} {
		req, _ := http.NewRequest("GET", up.URL+path, nil)
		if _, err := c.do(req, reg.rules[1]); err == nil || strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: error %v", path, err)
		}
		// The failed hop is the fetch's transport failure: it marks the
		// upstream down, though the redirect before it came through.
		if path == "/f/dead" && !c.isDown(up.URL) {
			t.Fatal("failed redirect hop left the upstream up")
		}
		c.markDown(up.URL, false)
	}

	// Without a follow policy a redirect passes through, uncached.
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, _ = mustGet(t, cl, "GET", url+"/m/ok")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://example.com/obj" {
		t.Fatalf("unfollowed: %d %v", resp.StatusCode, resp.Header)
	}

	// The uncached passthrough (no room) follows too.
	c.free = func() int64 { return 0 }
	c.minFree = 1 << 40 // more than eviction could ever free
	resp, b = mustGet(t, cl, "GET", url+"/f/bypass")
	expect(t, resp, 200, "BYPASS")
	if string(b) != "target:sig=3" {
		t.Fatalf("bypass: %q", b)
	}
}

func TestRedirectRules(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://origin.test/x"+r.URL.Path, http.StatusFound)
	}))
	defer up.Close()
	_, reg := setup(t, up.URL)
	loc := func(l string) string { return strings.Replace(l, "https://origin.test/", "http://cache.test/", 1) }
	reg.rules[0].location, reg.rules[1].location = loc, loc
	reg.rules = append(reg.rules, &rule{name: "r", match: exact("/r"), redirect: "http://cache.test/r/"})
	url, cl := front(t, reg, false)
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, _ := mustGet(t, cl, "GET", url+"/r")
	if resp.StatusCode != 301 || resp.Header.Get("Location") != "http://cache.test/r/" {
		t.Fatalf("local redirect: %d %v", resp.StatusCode, resp.Header)
	}
	resp, _ = mustGet(t, cl, "GET", url+"/m/a")
	expect(t, resp, 302, "MISS")
	if resp.Header.Get("Location") != "http://cache.test/x/m/a" {
		t.Fatalf("filled redirect: %v", resp.Header)
	}
	// The uncached passthrough rewrites too.
	reg.rules[1].pass = func(*http.Request) bool { return true }
	resp, _ = mustGet(t, cl, "GET", url+"/f/a")
	expect(t, resp, 302, "BYPASS")
	if resp.Header.Get("Location") != "http://cache.test/x/f/a" {
		t.Fatalf("bypass redirect: %v", resp.Header)
	}
}

// A body is complete at its Content-Length. An HTTP/2 upstream may send
// END_STREAM later (here: never), by when a client that stopped reading at
// the last byte has left: the fill is stored and a relay ends cleanly, logged
// 200 with its upstream time.
func TestCompleteAtContentLength(t *testing.T) {
	logs := &lockedBuffer{}
	defer slog.SetDefault(slog.Default())
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	stop := make(chan struct{})
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond) // a udur the log shows
		w.Header().Set("Content-Length", "100000")
		w.Write(make([]byte, 100000))
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-stop:
		}
	}))
	up.EnableHTTP2 = true
	up.StartTLS()
	defer up.Close()
	defer close(stop)
	c, reg := setup(t, up.URL)
	c.tr.TLSClientConfig = up.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	c.ftr = c.tr // files over HTTP/2, as they were
	srv := httptest.NewServer(router{"127.0.0.1": reg})
	defer srv.Close()
	get := func(cs string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/f/a", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		expect(t, resp, 200, cs)
		if _, err := io.ReadFull(resp.Body, make([]byte, 100000)); err != nil {
			t.Fatal(err)
		}
		cancel() // gone right after the last byte, as go, npm and curl are
		resp.Body.Close()
	}
	key := cacheKey("t", "f", up.URL+"/f/a", "", "")
	c.claim(key)
	get("BYPASS")
	c.release(key)
	get("MISS")
	settle(t, c)
	resp, b := mustGet(t, http.DefaultClient, "GET", srv.URL+"/f/a")
	expect(t, resp, 200, "HIT")
	if len(b) != 100000 {
		t.Fatalf("stored %d bytes", len(b))
	}
	srv.Close() // waits for the handlers
	logs.mu.Lock()
	out := logs.b.String()
	logs.mu.Unlock()
	if strings.Contains(out, "failed") || strings.Count(out, "status=200") != 3 || strings.Count(out, "udur=0s") != 1 {
		t.Fatalf("log:\n%s", out)
	}
}

// File fetches go upstream over HTTP/1.1, metadata over HTTP/2.
func TestFilesOverHTTP1(t *testing.T) {
	var mu sync.Mutex
	protos := map[string]string{}
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		protos[r.URL.Path] = r.Proto
		mu.Unlock()
		io.WriteString(w, "x")
	}))
	up.EnableHTTP2 = true
	up.StartTLS()
	defer up.Close()
	c, reg := setup(t, up.URL)
	for _, tr := range []*http.Transport{c.tr, c.ftr} {
		tr.TLSClientConfig = up.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	}
	url, cl := front(t, reg, false)
	mustGet(t, cl, "GET", url+"/f/a")
	mustGet(t, cl, "GET", url+"/m/a")
	mu.Lock()
	defer mu.Unlock()
	if protos["/f/a"] != "HTTP/1.1" || protos["/m/a"] != "HTTP/2.0" {
		t.Fatalf("upstream protocols %v", protos)
	}
}

// Answers made here, errors and local pages alike, are kept by no cache.
func TestLocalNoStore(t *testing.T) {
	_, reg := setup(t, "http://127.0.0.1:1") // nothing listens: cold fetches 502
	reg.rules = append([]*rule{
		{name: "health", match: exact("/"), local: "ok\n"},
		{name: "slash", match: exact("/s"), redirect: "http://cache.test/s/"},
	}, reg.rules...)
	url, cl := front(t, reg, false)
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for p, status := range map[string]int{"/": 200, "/s": 301, "/m/a": 502, "/f/a": 502, "/m/a?x=1": 400, "/nope": 404} {
		resp, _ := mustGet(t, cl, "GET", url+p)
		if resp.StatusCode != status || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %d %v", p, resp.StatusCode, resp.Header)
		}
	}
	resp, _ := mustGet(t, cl, "POST", url+"/m/a")
	if resp.StatusCode != 405 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("POST: %d %v", resp.StatusCode, resp.Header)
	}
}

func TestFreshFor(t *testing.T) {
	def := 7 * time.Minute
	for _, tc := range []struct {
		cc, age string
		want    time.Duration
	}{
		{"", "", def},
		{"public", "", def},
		{"public, max-age=60", "", time.Minute},
		{"max-age=600, public", "586", 14 * time.Second},
		{"max-age=300", "900", 0},
		{"max-age=60, s-maxage=\"120\"", "20", 100 * time.Second},
		{"max-age=31536000", "", time.Hour},
		{"no-cache, max-age=600", "", 0},
		{"max-age=bogus", "", def},
	} {
		h := http.Header{}
		if tc.cc != "" {
			h.Set("Cache-Control", tc.cc)
		}
		if tc.age != "" {
			h.Set("Age", tc.age)
		}
		if got := freshFor(h, def); got != tc.want {
			t.Errorf("freshFor(%q, Age %q) = %v, want %v", tc.cc, tc.age, got, tc.want)
		}
	}
}
