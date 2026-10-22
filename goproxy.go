package main

import (
	"errors"
	"regexp"
	"time"
)

// Per-version artifacts /<module>/@v/<version>.{info,mod,zip} are immutable
// under the GOPROXY protocol, but only for canonical versions:
// vX.Y.Z[-pre][+incompatible], no leading zeros, `!` being Go's escape for an
// uppercase letter. `go get foo@main` asks for /@v/main.info, which resolves
// to wherever the branch points now, so that stays short-lived metadata. So
// does anything semver rejects, e.g. v1.0.0-rc.01 (leading zero) or
// v1.0.0-rc..1: the go command sends those as revision queries too, and a
// branch named like that must not be pinned for a year. Prerelease
// identifiers are numeric without leading zeros, or alphanumeric with at
// least one non-digit; in escaped form a letter is [a-z] or `!`[a-z].
var goCanonical = func() *regexp.Regexp {
	const num = `(0|[1-9][0-9]*)`
	const ident = `(0|[1-9][0-9]*|[0-9]*([a-z-]|![a-z])([0-9a-z-]|![a-z])*)`
	return regexp.MustCompile(`^/.+/@v/v` + num + `\.` + num + `\.` + num +
		`(-` + ident + `(\.` + ident + `)*)?(\+incompatible)?\.(info|mod|zip)$`)
}()

// newGoproxy serves the Go module proxy protocol from proxyUp
// (proxy.golang.org) and mirrors the checksum DB from sumUp (sum.golang.org).
// The go command appends paths to GOPROXY and responses carry no absolute
// URLs, so nothing is rewritten.
func newGoproxy(c *Cache, public, proxyUp, sumUp string, metaCap, filesCap int64) (*registry, error) {
	// ponytail: a zip over the per-object limit (cap/2) is fetched again on
	// every request, never stored. The go command caps module zips at 500 MiB,
	// so a files zone of 1g or more stores them all.
	if filesCap < 1<<30 {
		return nil, errors.New("go files zone must be at least 1g: module zips go up to 500 MiB")
	}
	meta, err := c.addZone("goproxy-meta", metaCap, true)
	if err != nil {
		return nil, err
	}
	files, err := c.addZone("goproxy-files", filesCap, false)
	if err != nil {
		return nil, err
	}
	const year, metaTTL, negTTL = 365 * 24 * time.Hour, 5 * time.Minute, time.Minute
	text := []string{"text/", "application/json"}
	const sumdb = "/sumdb/sum.golang.org"
	return &registry{name: "goproxy", public: public, c: c, rules: []*rule{
		{name: "health", match: exact("/"), local: "go cache ok\n\nUse it:\n  export GOPROXY=" + public + "\n"},
		// Checksum DB, at <GOPROXY>/sumdb/sum.golang.org/<path>. The go command
		// asks the proxy first, so mirroring it keeps verification on and all
		// egress here. proxy.golang.org doesn't serve it: strip the prefix and
		// go to sum.golang.org's root.
		// A 200 on /supported tells the go command we mirror this sumdb.
		// sum.golang.org has no such endpoint (it'd 404 and go would fall back
		// to contacting sum.golang.org directly), so answer it ourselves.
		{name: "sumdb-supported", match: exact(sumdb + "/supported"), local: ""},
		// Records and tiles of an append-only transparency log never change.
		// sum.golang.org sends max-age=10800 and no validators; ignoring that
		// (as the engine always does) avoids a full refetch every 3h.
		{name: "sumdb-lookup", match: prefix(sumdb + "/lookup/"), upstream: sumUp, path: strip(sumdb),
			zone: files, ttl: year, compress: text},
		// Tiles are raw hashes labelled text/plain: gzip only makes them bigger.
		{name: "sumdb-tile", match: prefix(sumdb + "/tile/"), upstream: sumUp, path: strip(sumdb),
			zone: files, ttl: year},
		// /latest, the signed tree head, moves as the log grows: short TTL so a
		// freshly published module isn't checked against an old head.
		{name: "sumdb", match: prefix(sumdb + "/"), upstream: sumUp, path: strip(sumdb),
			zone: meta, ttl: metaTTL, compress: text},
		// proxy.golang.org sends max-age=10800 on these; the engine ignores it,
		// so the 1y holds. Large zips come back as a 302 to a signed
		// storage.googleapis.com URL, followed and cached as this key's 200.
		// 404/410 pass through uncached: the go command prints the
		// body as the error, and a version may appear any moment.
		// Matched decoded: the go command sends `!` as %21 (url.PathEscape),
		// so a prerelease like -!r!c1 arrives as -%21r%21c1. Key and upstream
		// path stay escaped.
		{name: "version", match: decoded(goCanonical), upstream: proxyUp, path: same,
			zone: files, ttl: year, compress: text, follow: "storage.googleapis.com"},
		// /@v/list, /@latest, non-canonical queries (/@v/main.info).
		{name: "meta", match: prefix("/"), upstream: proxyUp, path: same,
			zone: meta, ttl: metaTTL, negTTL: negTTL, compress: text},
	}}, nil
}
