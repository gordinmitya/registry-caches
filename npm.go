package main

import (
	"bytes"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Matched against the decoded path: a scoped name may
// arrive as /@scope/pkg, /@scope%2fpkg or /%40scope%2Fpkg.
var (
	// Tarballs: /<pkg>/-/<file>.tgz, /@scope/<pkg>/-/<file>.tgz. `/-/` never
	// occurs in a package name, so it cleanly tells tarballs from metadata.
	npmTarball = regexp.MustCompile(`^/(?:@[^/]+/)?[^/]+/-/.+\.tgz$`)
	// Packuments: /<pkg>, /@scope/<pkg>.
	npmPackument = regexp.MustCompile(`^/(?:@[^/]+/)?[^/]+$`)
	// The /-/ API endpoints worth sharing: dist-tags and search.
	npmDistTags = regexp.MustCompile(`^/-/package/(?:@[^/]+/)?[^/]+/dist-tags$`)
	npmSearch   = regexp.MustCompile(`^/-/v1/search$`)
	// Version documents: /<pkg>/<version or tag>, /@scope/<pkg>/<...>. Names
	// are URL-safe (what encodeURIComponent leaves alone; legacy ones may
	// have uppercase); a version may carry +build.
	npmVersionDoc = regexp.MustCompile(`^/(?:@[A-Za-z0-9._~!*'()-]+/)?[A-Za-z0-9._~!*'()-]+/[A-Za-z0-9._~!*'()+-]+$`)
)

// npmPath spells every cached path one way, so all spellings of a scoped
// name share one entry and go upstream as /@scope/pkg.
func npmPath(p string) string {
	d, err := url.PathUnescape(p)
	if err != nil {
		return p // unreachable: checkPath unescaped it already
	}
	return (&url.URL{Path: d}).EscapedPath()
}

// Packuments come in two forms. Installers ask for the abbreviated one
// (install-v1); `npm view` and minimumReleaseAge gates need the full one for
// its `time` field. Any client Accept collapses to one of the two, which is
// both what goes upstream and the cache variant.
func packumentAccept(r *http.Request) string {
	if strings.Contains(r.Header.Get("Accept"), "install-v1") {
		return "application/vnd.npm.install-v1+json"
	}
	return "application/json"
}

// Token-authenticated requests (private packages, /-/whoami) are per-user,
// and writes (npm audit's POST) aren't cacheable: never store or share them.
// ponytail: the relay forwards Authorization, Content-Type, Content-Encoding
// and Npm-Auth-Type only, so publishing with a 2FA one-time password (npm-otp
// header) fails. This is an install cache; relay npm-otp if publishing here
// is ever wanted.
func npmPass(r *http.Request) bool {
	return r.Header.Get("Authorization") != "" || (r.Method != http.MethodGet && r.Method != http.MethodHead)
}

// newNpm serves the npm registry from up (registry.npmjs.org).
func newNpm(c *Cache, public, up string, metaCap, filesCap int64) (*registry, error) {
	meta, err := c.addZone("npm-meta", metaCap, true)
	if err != nil {
		return nil, err
	}
	files, err := c.addZone("npm-files", filesCap, false)
	if err != nil {
		return nil, err
	}
	const year, metaTTL, negTTL = 365 * 24 * time.Hour, 5 * time.Minute, time.Minute
	// Metadata carries absolute tarball URLs; point them at us, or `registry=`
	// would only cover metadata and tarballs would go straight to npmjs.
	// Absolute, not relative: bun rejects relative tarball URLs (InvalidURL).
	// Tarball bytes are untouched, so their sha512 integrity still verifies.
	// ponytail: buffered whole, up to maxBuffer (128 MiB); the biggest
	// packument today (renovate, full form) is ~73 MB.
	rewrite := func(b []byte) []byte {
		return bytes.ReplaceAll(b, []byte("https://registry.npmjs.org/"), []byte(public+"/"))
	}
	text := []string{"text/", "application/json", "application/vnd.npm.install-v1+json"}
	always := func(*http.Request) bool { return true }
	return &registry{name: "npm", public: public, c: c, rules: []*rule{
		{name: "health", match: exact("/"), local: "npm cache ok\n\nUse it (bunfig.toml):\n" +
			"  [install]\n  registry = \"" + public + "\"\n"},
		// Integrity-pinned by sha512 in metadata, so immutable. Streamed to
		// the client while filling. 404s kept a minute, like metadata's. With
		// a token: relayed uncached, never shared.
		{name: "tarball", match: decoded(npmTarball), upstream: up, path: npmPath,
			zone: files, ttl: year, negTTL: negTTL, pass: npmPass},
		{name: "packument", match: decoded(npmPackument), upstream: up, path: npmPath,
			zone: meta, ttl: metaTTL, negTTL: negTTL, compress: text, rewrite: rewrite,
			variant: packumentAccept, pass: npmPass},
		// Version documents (/<pkg>/<ver>, which corepack fetches to bootstrap
		// pnpm/yarn), dist-tags and search have no abbreviated form and answer
		// install-v1 with 406, so they always get JSON. Matched decoded and
		// positively: /-/ (and /%2d/, which the registry's CDN normalises to
		// /-/) is otherwise per-user or one-shot, and any shape we don't know
		// falls to api below rather than being cached. Only search takes a
		// query, part of its key.
		{name: "search", match: decoded(npmSearch), upstream: up, path: npmPath,
			zone: meta, ttl: metaTTL, negTTL: negTTL, compress: text, rewrite: rewrite,
			accept: "application/json", pass: npmPass, query: true},
		{name: "meta", match: func(p string) bool {
			d, err := url.PathUnescape(p)
			return err == nil && (npmDistTags.MatchString(d) ||
				!strings.HasPrefix(d, "/-/") && npmVersionDoc.MatchString(d))
		}, upstream: up, path: npmPath,
			zone: meta, ttl: metaTTL, negTTL: negTTL, compress: text, rewrite: rewrite,
			accept: "application/json", pass: npmPass},
		// Everything else: ping, whoami, audit, the web-login poll
		// /-/v1/done (which hands out a token without Authorization), and
		// paths of no known shape. Relayed, never stored. The rewrite points
		// login's doneUrl back at us.
		{name: "api", match: prefix("/"), upstream: up, path: same, rewrite: rewrite,
			accept: "application/json", pass: always},
	}}, nil
}
