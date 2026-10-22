package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestCrates(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{} // upstream path → Range header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get("Range")
		mu.Unlock()
		switch r.URL.Path {
		case "/config.json":
			w.Header().Set("Content-Type", "application/octet-stream")
			io.WriteString(w, `{"dl":"https://static.crates.io/crates","api":"https://crates.io"}`)
		case "/se/rd/serde":
			io.WriteString(w, `{"name":"serde","vers":"1.0.0"}`+"\n")
		case "/crates/serde/1.0.0/download":
			io.WriteString(w, "CRATE-TARBALL")
		default:
			http.NotFound(w, r)
		}
	}))
	defer up.Close()
	c := newCache(t.TempDir(), 0, 64)
	c.free = func() int64 { return 1 << 40 }
	reg, err := newCrates(c, "http://crates.test:8080", up.URL, up.URL, 1<<20, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(router{"crates.test": reg})
	defer srv.Close()
	fetch := func(host, path string, hdr ...string) (*http.Response, string) {
		t.Helper()
		resp, b := mustGet(t, http.DefaultClient, "GET", srv.URL+path, append([]string{"Host", host}, hdr...)...)
		return resp, string(b)
	}

	resp, body := fetch("crates.test:8080", "/index/config.json")
	if resp.StatusCode != 200 || body != `{"dl":"http://crates.test:8080/crates","api":"https://crates.io"}` {
		t.Fatalf("config.json: %d %s", resp.StatusCode, body)
	}
	resp, body = fetch("Crates.Test", "/index/se/rd/serde")
	if resp.StatusCode != 200 || !strings.Contains(body, `"serde"`) {
		t.Fatalf("index: %d %s", resp.StatusCode, body)
	}
	resp, body = fetch("crates.test", "/crates/serde/1.0.0/download", "Range", "bytes=0-4")
	if resp.StatusCode != 200 || body != "CRATE-TARBALL" {
		t.Fatalf("crate: %d %s", resp.StatusCode, body)
	}
	settle(t, c)
	resp, body = fetch("crates.test", "/crates/serde/1.0.0/download", "Range", "bytes=0-4")
	if resp.StatusCode != 206 || body != "CRATE" || resp.Header.Get("X-Cache-Status") != "HIT" {
		t.Fatalf("crate range hit: %d %s %v", resp.StatusCode, body, resp.Header)
	}
	resp, _ = fetch("crates.test", "/index/no/pe/nope")
	resp, _ = fetch("crates.test", "/index/no/pe/nope")
	if resp.StatusCode != 404 || resp.Header.Get("X-Cache-Status") != "HIT" {
		t.Fatalf("index 404: %d %v", resp.StatusCode, resp.Header)
	}
	mu.Lock()
	for _, p := range []string{"/config.json", "/se/rd/serde", "/crates/serde/1.0.0/download", "/no/pe/nope"} {
		r, ok := seen[p]
		if !ok || r != "" {
			t.Errorf("upstream %s: seen=%v range=%q", p, ok, r)
		}
	}
	mu.Unlock()

	resp, body = fetch("crates.test", "/")
	if resp.StatusCode != 200 || !strings.Contains(body, `"sparse+http://crates.test:8080/index/"`) {
		t.Fatalf("health: %d %s", resp.StatusCode, body)
	}
	if resp, _ = fetch("crates.test", "/elsewhere"); resp.StatusCode != 404 {
		t.Fatalf("unknown path: %d", resp.StatusCode)
	}
	if resp, _ = fetch("other.test", "/"); resp.StatusCode != 404 {
		t.Fatalf("unknown host: %d", resp.StatusCode)
	}

	// Over TLS, Host must match SNI.
	tsrv := httptest.NewTLSServer(router{"crates.test": reg, "other.test": reg})
	defer tsrv.Close()
	cl := tsrv.Client()
	for sni, want := range map[string]int{"crates.test": 200, "other.test": 421} {
		cl.Transport.(*http.Transport).TLSClientConfig.ServerName = sni
		cl.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
		if resp, _ := mustGet(t, cl, "GET", tsrv.URL+"/", "Host", "crates.test"); resp.StatusCode != want {
			t.Fatalf("SNI %s: %d, want %d", sni, resp.StatusCode, want)
		}
		cl.CloseIdleConnections()
	}
}
