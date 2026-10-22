package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// lockedBuffer collects log output written from handler goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func TestNpm(t *testing.T) {
	const install = "application/vnd.npm.install-v1+json"
	logs := &lockedBuffer{}
	defer slog.SetDefault(slog.Default())
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	var mu sync.Mutex
	hits := map[string]int{}      // upstream RequestURI → count
	accept := map[string]string{} // upstream RequestURI → last Accept
	auth := map[string]string{}   // upstream RequestURI → last Authorization
	cookie := ""                  // last Cookie upstream saw
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read first: answering before the body is in would race the relay's
		// 413 for an oversized one.
		reqBody, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		mu.Lock()
		hits[r.RequestURI]++
		accept[r.RequestURI] = r.Header.Get("Accept")
		auth[r.RequestURI] = r.Header.Get("Authorization")
		cookie += r.Header.Get("Cookie")
		mu.Unlock()
		// Cloudflare tags everything with this; it must never be stored or
		// handed to another client.
		w.Header().Set("Set-Cookie", "_cfuvid=abc; Path=/; Domain=npmjs.org")
		w.Header().Set("ETag", `"up"`)
		json := func(ct, body string) {
			w.Header().Set("Content-Type", ct)
			io.WriteString(w, body)
		}
		a := r.Header.Get("Accept")
		switch p := r.URL.Path; {
		case r.Header.Get("Authorization") == "Bearer expired":
			w.Header().Set("WWW-Authenticate", "OTP")
			http.Error(w, "otp required", http.StatusUnauthorized)
		case p == "/express" || p == "/@types/node":
			name := strings.TrimPrefix(p, "/")
			tgz := `"https://registry.npmjs.org/` + name + `/-/x-1.0.0.tgz"`
			switch a {
			case install:
				json(install, `{"name":"`+name+`","versions":{"1.0.0":{"dist":{"tarball":`+tgz+`}}}}`)
			case "application/json":
				json("application/json", `{"name":"`+name+`","time":{"modified":"2026"},"versions":{"1.0.0":{"dist":{"tarball":`+tgz+`}}}}`)
			default:
				http.Error(w, "bad accept "+a, http.StatusNotAcceptable)
			}
		case strings.HasSuffix(p, "-9.0.0.tgz"):
			http.Error(w, `{"error":"Not found"}`, http.StatusNotFound)
		case strings.HasSuffix(p, ".tgz"):
			w.Header().Set("Content-Type", "application/octet-stream")
			io.WriteString(w, "TARBALL "+p)
		case a != "application/json" && strings.Count(p, "/") > 1:
			// Version docs and /-/ have no abbreviated form.
			http.Error(w, "bad accept "+a, http.StatusNotAcceptable)
		case p == "/express/4.0.0", p == "/-/package/express/dist-tags", p == "/-/v1/search":
			json("application/json", `{"tarball":"https://registry.npmjs.org/express/-/express-4.0.0.tgz"}`)
		case p == "/private" && r.Header.Get("Authorization") == "Bearer tok":
			json("application/json", `{"versions":{"1.0.0":{"dist":{"tarball":"https://registry.npmjs.org/private/-/private-1.0.0.tgz"}}}}`)
		case p == "/-/whoami" && r.Header.Get("Authorization") == "Bearer tok":
			json("application/json", `{"username":"me"}`)
		case p == "/-/v1/login" && r.Header.Get("Npm-Auth-Type") == "web":
			json("application/json", `{"doneUrl":"https://registry.npmjs.org/-/v1/done?authId=wait"}`)
		case p == "/-/v1/done" && r.URL.RawQuery == "authId=wait":
			// Login still pending: npm waits Retry-After before polling again.
			w.Header().Set("Retry-After", "5")
			w.Header().Set("Npm-Notice", "finish in the browser")
			w.WriteHeader(http.StatusAccepted)
		case p == "/-/v1/done":
			json("application/json", `{"token":"npm_secret"}`)
		case p == "/-/npm/v1/security/advisories/bulk" && r.Method == "POST":
			zr, err := gzip.NewReader(bytes.NewReader(reqBody))
			if err != nil || r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "bad body", 400)
				return
			}
			b, _ := io.ReadAll(zr)
			json("application/json", `{"got":`+string(b)+`}`)
		default:
			http.Error(w, `{"error":"Not found"}`, http.StatusNotFound)
		}
	}))
	defer up.Close()
	c := newCache(t.TempDir(), 0, 64)
	c.free = func() int64 { return 1 << 40 }
	reg, err := newNpm(c, "http://npm.test:8080", up.URL, 1<<20, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(router{"npm.test": reg})
	defer srv.Close()
	cl := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	fetch := func(method, path string, hdr ...string) (*http.Response, string) {
		t.Helper()
		resp, b := mustGet(t, cl, method, srv.URL+path, append([]string{"Host", "npm.test"}, hdr...)...)
		settle(t, c)
		if resp.Header.Get("Set-Cookie") != "" {
			t.Fatalf("%s: Set-Cookie forwarded", path)
		}
		return resp, string(b)
	}
	count := func(uri string) int {
		mu.Lock()
		defer mu.Unlock()
		return hits[uri]
	}
	upAccept := func(uri string) string {
		mu.Lock()
		defer mu.Unlock()
		return accept[uri]
	}
	// zone checks that name holds n entries, each expiring per its status.
	zone := func(name string, n int, ttl map[int]time.Duration) {
		t.Helper()
		ps := files(t, filepath.Join(c.root, name))
		for _, p := range ps {
			f, m, err := openEntry(p)
			if err != nil {
				t.Fatal(err)
			}
			f.Close()
			if left, want := time.Until(m.Expires), ttl[m.Status]; left > want || left < want-time.Minute {
				t.Fatalf("%s: %d expires in %v, want %v", name, m.Status, left, want)
			}
		}
		if len(ps) != n {
			t.Fatalf("%s: %d entries, want %d", name, len(ps), n)
		}
	}
	const npmAccept = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"

	resp, body := fetch("GET", "/")
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "npm cache ok") || !strings.Contains(body, `registry = "http://npm.test:8080"`) {
		t.Fatalf("health: %d %q", resp.StatusCode, body)
	}

	// Packuments: any client Accept collapses to install-v1 or JSON, each a
	// cache variant; tarball URLs rewritten to our absolute origin.
	for _, c := range []struct{ accept, cache, upstream, has string }{
		{npmAccept, "MISS", install, `"tarball":"http://npm.test:8080/express/-/x-1.0.0.tgz"`},
		{install, "HIT", install, `"versions"`},
		{"application/json", "MISS", "application/json", `"time"`},
		{"", "HIT", "application/json", `"time"`},
		{"*/*", "HIT", "application/json", `"tarball":"http://npm.test:8080/`},
	} {
		resp, body = fetch("GET", "/express", "Accept", c.accept)
		expect(t, resp, 200, c.cache)
		if upAccept("/express") != c.upstream || !strings.Contains(body, c.has) ||
			strings.Contains(body, "registry.npmjs.org") ||
			!slices.Equal(resp.Header.Values("Vary"), []string{"Accept", "Accept-Encoding"}) {
			t.Fatalf("Accept %q: up %q, %v %s", c.accept, upAccept("/express"), resp.Header, body)
		}
	}
	if count("/express") != 2 {
		t.Fatalf("packument fetched %d times", count("/express"))
	}
	// Scoped, every spelling: one entry, fetched upstream as /@types/node.
	for i, p := range []string{"/@types%2fnode", "/@types/node", "/%40types%2Fnode"} {
		resp, body = fetch("GET", p, "Accept", npmAccept)
		expect(t, resp, 200, map[bool]string{true: "MISS", false: "HIT"}[i == 0])
		if upAccept("/@types/node") != install || count("/@types/node") != 1 || !strings.Contains(body, `"http://npm.test:8080/@types/node/-/x-1.0.0.tgz"`) {
			t.Fatalf("%s: up %q hits %d, %s", p, upAccept("/@types/node"), count("/@types/node"), body)
		}
	}
	// A cold HEAD fills like a GET: the rewritten length, then a HIT.
	resp, _ = fetch("HEAD", "/@types/node", "Accept", "application/json")
	expect(t, resp, 200, "MISS")
	length := resp.ContentLength
	resp, body = fetch("GET", "/@types%2Fnode", "Accept", "application/json")
	expect(t, resp, 200, "HIT")
	if int64(len(body)) != length || !strings.Contains(body, `"time"`) {
		t.Fatalf("HEAD length %d, GET %d bytes", length, len(body))
	}

	// Version docs and the shared /-/ endpoints: always JSON upstream (they
	// 406 install-v1), one variant, no Vary: Accept.
	for _, p := range []string{"/express/4.0.0", "/-/package/express/dist-tags", "/-/v1/search?text=express&size=20"} {
		for _, cs := range []string{"MISS", "HIT"} {
			resp, body = fetch("GET", p, "Accept", npmAccept)
			expect(t, resp, 200, cs)
			if upAccept(p) != "application/json" || resp.Header.Get("Vary") == "Accept" ||
				!strings.Contains(body, "http://npm.test:8080/express/-/express-4.0.0.tgz") {
				t.Fatalf("%s: up %q, %v %s", p, upAccept(p), resp.Header, body)
			}
		}
	}

	// 404 cached briefly; metadata lives 5m.
	for _, cs := range []string{"MISS", "HIT"} {
		resp, _ = fetch("GET", "/nope", "Accept", npmAccept)
		expect(t, resp, 404, cs)
	}
	zone("npm-meta", 8, map[int]time.Duration{200: 5 * time.Minute, 404: time.Minute})

	// Tarballs, plain and scoped: immutable, files zone.
	// Both spellings of a scoped one share an entry.
	for _, tc := range []struct{ path, first string }{
		{"/express/-/express-4.0.0.tgz", "MISS"},
		{"/@types/node/-/node-1.0.0.tgz", "MISS"},
		{"/@types%2fnode/-/node-1.0.0.tgz", "HIT"},
	} {
		p := tc.path
		for _, cs := range []string{tc.first, "HIT"} {
			resp, body = fetch("GET", p)
			expect(t, resp, 200, cs)
			if body != "TARBALL "+strings.ReplaceAll(p, "%2f", "/") {
				t.Fatalf("%s: %q", p, body)
			}
		}
	}
	// A missing tarball is kept a minute: it may be published soon.
	for _, cs := range []string{"MISS", "HIT"} {
		resp, _ = fetch("GET", "/express/-/express-9.0.0.tgz")
		expect(t, resp, 404, cs)
	}
	zone("npm-files", 3, map[int]time.Duration{200: 365 * 24 * time.Hour, 404: time.Minute})

	// Nothing of Set-Cookie is on disk.
	for _, p := range files(t, c.root) {
		if b, _ := os.ReadFile(p); bytes.Contains(b, []byte("_cfuvid")) {
			t.Fatalf("%s stores the cookie", p)
		}
	}
	stored := len(files(t, c.root))

	// Token requests: relayed with Authorization every time, rewritten,
	// never stored, and a cached tarball isn't served to them either.
	for range 2 {
		resp, body = fetch("GET", "/private", "Accept", npmAccept, "Authorization", "Bearer tok")
		expect(t, resp, 200, "BYPASS")
		if !strings.Contains(body, `"http://npm.test:8080/private/-/private-1.0.0.tgz"`) || upAccept("/private") != install {
			t.Fatalf("private: %s up %q", body, upAccept("/private"))
		}
	}
	// Kept from shared caches, not from npm's own: an authenticated user's
	// cacache (and --offline) still holds packuments and tarballs.
	if cc := resp.Header.Get("Cache-Control"); cc != "private" {
		t.Fatalf("private packument: Cache-Control %q", cc)
	}
	tarHits := count("/express/-/express-4.0.0.tgz")
	resp, _ = fetch("GET", "/express/-/express-4.0.0.tgz", "Authorization", "Bearer tok")
	expect(t, resp, 200, "BYPASS")
	if cc := resp.Header.Get("Cache-Control"); cc != "private" {
		t.Fatalf("token tarball: Cache-Control %q", cc)
	}
	resp, body = fetch("GET", "/-/whoami", "Authorization", "Bearer tok")
	expect(t, resp, 200, "BYPASS")
	if cc := resp.Header.Get("Cache-Control"); cc != "private, no-store" {
		t.Fatalf("whoami: Cache-Control %q", cc)
	}
	mu.Lock()
	if hits["/private"] != 2 || hits["/express/-/express-4.0.0.tgz"] != tarHits+1 || auth["/-/whoami"] != "Bearer tok" || body != `{"username":"me"}` {
		t.Fatalf("auth relay: hits %v auth %v body %q", hits, auth, body)
	}
	mu.Unlock()
	// Upstream ignores a query it doesn't know, so outside search each ?x=
	// would fill another copy. A relayed one (npm's ?write=true) goes as sent.
	for _, p := range []string{"/express?x=1", "/express/-/express-4.0.0.tgz?x=1", "/express/4.0.0?x=1",
		"/-/package/express/dist-tags?x=1"} {
		if resp, _ = fetch("GET", p); resp.StatusCode != 400 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
	}
	resp, _ = fetch("GET", "/private?write=true", "Accept", npmAccept, "Authorization", "Bearer tok")
	expect(t, resp, 200, "BYPASS")

	// npm audit: gzip JSON POST relayed as sent.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	io.WriteString(zw, `{"express":["4.0.0"]}`)
	zw.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/-/npm/v1/security/advisories/bulk", &gz)
	req.Host = "npm.test"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Cookie", "session=1")
	if resp, err = cl.Do(req); err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	expect(t, resp, 200, "BYPASS")
	mu.Lock()
	if string(b) != `{"got":{"express":["4.0.0"]}}` || resp.Header.Get("Set-Cookie") != "" || cookie != "" {
		t.Fatalf("audit: %q %v, upstream cookie %q", b, resp.Header, cookie)
	}
	mu.Unlock()
	// Oversized bodies: refused up front by length, cut off when chunked
	// (MultiReader hides the length).
	big := make([]byte, maxReqBody+1)
	for _, r := range []io.Reader{bytes.NewReader(big), io.MultiReader(bytes.NewReader(big))} {
		req, _ = http.NewRequest("POST", srv.URL+"/-/npm/v1/security/advisories/bulk", r)
		req.Host = "npm.test"
		if resp, err = cl.Do(req); err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 413 {
			t.Fatalf("big body: %d", resp.StatusCode)
		}
	}

	// The web-login poll hands out a token without Authorization: never
	// cached, however its path is spelled (%2d is '-' to the registry).
	for _, p := range []string{"/-/v1/done?authId=x", "/-/v1/done?authId=x", "/%2d/v1/done?authId=x", "/-%2fv1%2fdone?authId=x"} {
		resp, body = fetch("GET", p)
		expect(t, resp, 200, "BYPASS")
		if body != `{"token":"npm_secret"}` || resp.Header.Get("Cache-Control") != "private, no-store" {
			t.Fatalf("%s: %q %v", p, body, resp.Header)
		}
	}
	// Shapes no rule knows are relayed too, not cached as metadata: a CDN
	// may well normalise them onto the done poll (the stub 404s them). An
	// empty segment is refused outright.
	for _, p := range []string{"/-;/v1/done?authId=x", "/x/y/z"} {
		resp, _ = fetch("GET", p)
		expect(t, resp, 404, "BYPASS")
	}
	if resp, _ = fetch("GET", "/%2F-/v1/done?authId=x"); resp.StatusCode != 400 {
		t.Fatalf("empty segment: %d", resp.StatusCode)
	}
	if count("/-/v1/done?authId=x") != 2 || len(files(t, c.root)) != stored {
		t.Fatalf("relayed requests stored: %d → %d", stored, len(files(t, c.root)))
	}
	// Web login: the registry refuses it (401) without npm-auth-type: web;
	// its doneUrl points back at us.
	resp, body = fetch("POST", "/-/v1/login", "Npm-Auth-Type", "web")
	expect(t, resp, 200, "BYPASS")
	if body != `{"doneUrl":"http://npm.test:8080/-/v1/done?authId=wait"}` {
		t.Fatalf("login: %q", body)
	}
	// Pending login: without Retry-After npm re-polls with no delay.
	resp, _ = fetch("GET", "/-/v1/done?authId=wait")
	if resp.StatusCode != 202 || resp.Header.Get("Retry-After") != "5" || resp.Header.Get("Npm-Notice") == "" {
		t.Fatalf("pending login: %d %v", resp.StatusCode, resp.Header)
	}
	// Writes elsewhere are relayed too, never answered from the cache.
	resp, _ = fetch("PUT", "/express")
	expect(t, resp, 200, "BYPASS")
	// As the client spelled them: only cache keys are canonicalised.
	if resp, _ = fetch("PUT", "/@types%2fnode"); count("/@types%2fnode") != 1 {
		t.Fatalf("scoped write: %d, upstream hits %v", resp.StatusCode, hits)
	}
	// WWW-Authenticate: OTP is how npm learns a token needs a 2FA code.
	resp, _ = fetch("PUT", "/express", "Authorization", "Bearer expired")
	if resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") != "OTP" {
		t.Fatalf("otp: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, _ = fetch("POST", "/"); resp.StatusCode != 405 {
		t.Fatalf("POST /: %d", resp.StatusCode)
	}

	// Nor a rejected one's: the query is dropped before validation.
	if resp, _ = fetch("GET", "/-/v1/done?authId=x%zz"); resp.StatusCode != 400 {
		t.Fatalf("malformed poll: %d", resp.StatusCode)
	}

	// The access log keeps queries of cached requests but never a relayed
	// or rejected one's: the done poll's authId redeems a token. Close waits
	// for the handlers, so every access line is written.
	srv.Close()
	logs.mu.Lock()
	out := logs.b.String()
	logs.mu.Unlock()
	if strings.Contains(out, "authId") || !strings.Contains(out, "/-/v1/done?REDACTED") || !strings.Contains(out, "/-/v1/search?text=express") {
		t.Fatalf("access log:\n%s", out)
	}
}
