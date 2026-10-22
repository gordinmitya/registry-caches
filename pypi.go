package main

import (
	"bytes"
	"net/http"
	"strings"
	"time"
)

// simpleAccept picks the simple-page form: PEP 691 JSON for clients that ask
// for it (pip >= 22.2, uv), else HTML, which pip < 22.2 (Ubuntu 22.04's
// 22.0.2) needs. Any client Accept collapses to one of the two, which is both
// what goes upstream and the cache variant. PEP 691's "latest" alias is v1,
// the only JSON version there is.
func simpleAccept(r *http.Request) string {
	if a := r.Header.Get("Accept"); strings.Contains(a, "application/vnd.pypi.simple.v1+json") ||
		strings.Contains(a, "application/vnd.pypi.simple.latest+json") {
		return "application/vnd.pypi.simple.v1+json"
	}
	return "text/html"
}

// newPypi serves the PyPI simple API from indexUp (pypi.org) and, under
// /files/, the wheels, sdists and PEP 658 .metadata it links to from filesUp
// (files.pythonhosted.org).
func newPypi(c *Cache, public, indexUp, filesUp string, indexCap, filesCap int64) (*registry, error) {
	index, err := c.addZone("pypi-index", indexCap, true)
	if err != nil {
		return nil, err
	}
	files, err := c.addZone("pypi-files", filesCap, false)
	if err != nil {
		return nil, err
	}
	const year, indexTTL, negTTL = 365 * 24 * time.Hour, 10 * time.Minute, time.Minute
	// Both upstreams redirect to absolute URLs on themselves; send the
	// follow-up back here, or the client goes around the cache.
	rebase := func(from, to string) func(string) string {
		return func(loc string) string {
			if rest, ok := strings.CutPrefix(loc, from); ok {
				return to + rest
			}
			return loc
		}
	}
	return &registry{name: "pypi", public: public, c: c, rules: []*rule{
		{name: "health", match: exact("/"), local: "pypi cache ok\n\nUse it (pyproject.toml):\n" +
			"  [[tool.uv.index]]\n  url = \"" + public + "/simple/\"\n  default = true\n"},
		// For people typing the index URL; pip and uv always ask for
		// /simple/<name>/.
		{name: "simple-slash", match: exact("/simple"), redirect: public + "/simple/"},
		// Two forms per page at most (see simpleAccept), with Vary: Accept.
		// pypi.org 301s non-normalised names (/simple/Flask_Login/) and a
		// missing trailing slash to absolute https://pypi.org/ URLs; those pass
		// through uncached with Location pointed back here.
		// File URLs, JSON fields or HTML hrefs alike, become root-relative
		// /files/...: clients resolve them against the page URL, which is
		// always ours.
		// ponytail: buffered whole, up to maxBuffer (128 MiB); the biggest
		// page, the /simple/ project list, is ~45 MB.
		{name: "simple", match: prefix("/simple/"), upstream: indexUp, path: same,
			zone: index, ttl: indexTTL, negTTL: negTTL, variant: simpleAccept,
			compress: []string{"text/", "application/json", "application/vnd.pypi.simple.v1+json"},
			rewrite: func(b []byte) []byte {
				return bytes.ReplaceAll(b, []byte("https://files.pythonhosted.org/"), []byte("/files/"))
			},
			location: rebase("https://pypi.org/", public+"/")},
		// Paths carry the file's hash, so immutable; streamed to the client
		// while filling (pip gives up after 15s of silence). Never gzipped to
		// clients either: pip hashes the raw body. Upstream gzips .metadata
		// when asked; files are always fetched as identity. Fills never send
		// Range upstream: Fastly served numpy 2.5.4's wheel with a different
		// ETag per byte range.
		// 404 not cached. Legacy /packages/source/<x>/<name>/<sdist>
		// paths 302 to the hashed path, passed through uncached.
		{name: "files", match: prefix("/files/"), upstream: filesUp, path: strip("/files"),
			zone: files, ttl: year,
			location: rebase("https://files.pythonhosted.org/", public+"/files/")},
	}}, nil
}
