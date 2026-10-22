package main

import (
	"bytes"
	"time"
)

// newCrates serves the crates.io sparse registry: /index/ → index.crates.io,
// /crates/ → static.crates.io. indexUp/staticUp are the upstream origins.
func newCrates(c *Cache, public, indexUp, staticUp string, indexCap, filesCap int64) (*registry, error) {
	index, err := c.addZone("crates-index", indexCap, true)
	if err != nil {
		return nil, err
	}
	files, err := c.addZone("crates-files", filesCap, false)
	if err != nil {
		return nil, err
	}
	// Index files come as application/octet-stream; compress those too.
	// .crate files are already gzip.
	indexTypes := []string{"text/", "application/json", "application/octet-stream"}
	// index.crates.io sends max-age=600; 404s carry no Cache-Control. Cargo probes many names that
	// don't exist (-/_ variants, typos), hence the short negative TTL.
	const indexTTL, negTTL = 10 * time.Minute, time.Minute
	return &registry{name: "crates", public: public, c: c, rules: []*rule{
		{name: "health", match: exact("/"), local: "crates cache ok\n\nUse it (.cargo/config.toml):\n" +
			"  [source.crates-io]\n  replace-with = \"mirror\"\n" +
			"  [registries.mirror]\n  index = \"sparse+" + public + "/index/\"\n"},
		// config.json's dl field tells cargo where to download .crate files
		// (cargo appends /{crate}/{version}/download). Point it back at us.
		{name: "config", match: exact("/index/config.json"), upstream: indexUp, path: strip("/index"),
			zone: index, ttl: indexTTL, negTTL: negTTL, compress: indexTypes,
			rewrite: func(b []byte) []byte {
				return bytes.ReplaceAll(b, []byte("https://static.crates.io/crates"), []byte(public+"/crates"))
			}},
		// /index/se/rd/serde, /index/1/a, /index/3/d/def → upstream root.
		{name: "index", match: prefix("/index/"), upstream: indexUp, path: strip("/index"),
			zone: index, ttl: indexTTL, negTTL: negTTL, compress: indexTypes},
		// /crates/<crate>/<version>/download, served 200 directly (no redirect).
		// Immutable. Fills never send Range upstream, which matters here:
		// static.crates.io answers a Range past EOF with a bogus Content-Range.
		// 404 not cached: a just-published version may lag on the CDN.
		{name: "crates", match: prefix("/crates/"), upstream: staticUp, path: same,
			zone: files, ttl: 365 * 24 * time.Hour},
	}}, nil
}
