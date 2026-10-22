package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Every *_HOST is required, and two registries on one host name (after the router's normalisation) would
// leave one unreachable: refused, naming the variables.
func TestHostEnvDuplicates(t *testing.T) {
	for _, k := range []string{"CRATES_HOST", "GOPROXY_HOST", "NPM_HOST", "PYPI_HOST"} {
		t.Setenv(k, "")
	}
	if _, err := hostEnv(); err == nil || !strings.Contains(err.Error(), "PYPI_HOST is required") {
		t.Fatalf("unset: %v", err)
	}
	t.Setenv("CRATES_HOST", "crates.example.com")
	t.Setenv("GOPROXY_HOST", "goproxy.example.com")
	t.Setenv("PYPI_HOST", "pypi.example.com")
	for _, v := range []string{"crates.example.com", "Crates.Example.Com", "crates.example.com."} {
		t.Setenv("NPM_HOST", v)
		_, err := hostEnv()
		if err == nil || !strings.Contains(err.Error(), "CRATES_HOST") || !strings.Contains(err.Error(), "NPM_HOST") {
			t.Fatalf("NPM_HOST=%s: %v", v, err)
		}
	}
	t.Setenv("NPM_HOST", "Registry.Example.")
	names, err := hostEnv()
	if err != nil || names["NPM_HOST"] != "registry.example" {
		t.Fatalf("%v %v", names, err)
	}
}

// Public URLs (rewritten bodies, redirect Locations) leave a default port out.
func TestPublicOrigin(t *testing.T) {
	for addr, want := range map[string]string{
		"": "https://npm.test", ":80": "http://npm.test", "127.0.0.1:80": "http://npm.test",
		":8080": "http://npm.test:8080",
	} {
		public, err := publicOrigin(addr)
		if err != nil || public("npm.test") != want {
			t.Fatalf("%q: %v", addr, err)
		}
	}
	if _, err := publicOrigin("8080"); err == nil {
		t.Fatal("no port accepted")
	}
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error { d.deadline = t; return nil }

// A header-only response (HEAD, 304) never calls Write, yet its final flush
// must still be bounded: WriteHeader alone installs the idle deadline.
func TestLogWriterHeaderOnlyDeadline(t *testing.T) {
	d := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	lw := &logWriter{ResponseWriter: d, rc: http.NewResponseController(d)}
	before := time.Now()
	lw.WriteHeader(http.StatusNotModified)
	if d.deadline.Before(before.Add(idle)) || d.deadline.After(time.Now().Add(idle)) {
		t.Fatalf("deadline %v, want ~now+%v", d.deadline, idle)
	}
}
