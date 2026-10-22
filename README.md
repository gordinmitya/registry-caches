# simple-cache

Caching proxy for crates.io, Go modules, npm and PyPI: one static Go binary,
one hostname per registry, TLS from Let's Encrypt via DNS-01 on Cloudflare.
Meant for an internal network; no client auth.

## Run

```sh
cat > .env <<'EOF'
CLOUDFLARE_API_TOKEN=...   # Zone.DNS:Edit
ACME_EMAIL=admin@example.com
CRATES_HOST=crates.example.com
GOPROXY_HOST=goproxy.example.com
NPM_HOST=npm.example.com
PYPI_HOST=pypi.example.com
EOF
docker compose up -d --build
```

The access log has one line per request with
`cache=HIT|MISS|EXPIRED|REVALIDATED|STALE|BYPASS`; clients get it as
`X-Cache-Status`. Without ACME: `simple-cache -http-addr :8080` serves plain
HTTP.

## Clients

cargo, `.cargo/config.toml`:

```toml
[source.crates-io]
replace-with = "mirror"

[registries.mirror]
index = "sparse+https://crates.example.com/index/"
```

Go: `GOPROXY=https://goproxy.example.com`. Keep `GOSUMDB` default; the
checksum database is proxied too. Set `GOPRIVATE` for private modules, or
their paths leak to proxy.golang.org.

npm: `registry=https://npm.example.com/` in `.npmrc`; bun: `registry` under
`[install]` in `bunfig.toml`. Don't configure a token for this host: requests
with `Authorization` bypass the cache. bun ignores the registry for
registry.npmjs.org URLs already in `bun.lock`; rewrite or delete the lock.

PyPI: `PIP_INDEX_URL` / `UV_DEFAULT_INDEX=https://pypi.example.com/simple/`.

## Environment

| Variable | Default | |
|---|---|---|
| `CLOUDFLARE_API_TOKEN` | required for TLS | |
| `ACME_EMAIL` | | |
| `CRATES_HOST`, `GOPROXY_HOST`, `NPM_HOST`, `PYPI_HOST` | required | |
| `CRATES_INDEX_MAX` / `CRATES_FILES_MAX` | `256m` / `3g` | zone caps |
| `GOPROXY_META_MAX` / `GOPROXY_FILES_MAX` | `128m` / `3g` | files at least `1g` |
| `NPM_META_MAX` / `NPM_FILES_MAX` | `512m` / `4g` | |
| `PYPI_INDEX_MAX` / `PYPI_FILES_MAX` | `512m` / `12g` | |
| `CACHE_MIN_FREE` | `3g` | free disk kept; oldest entries go first |
| `MAX_FILLS` | `64` | concurrent upstream requests; more wait 10s, then 503 |
| `CACHE_DIR` | `/cache` | |
| `HTTPS_PROXY`, `NO_PROXY` | | egress proxy (Basic auth only) |
| `SSL_CERT_FILE` | | CA bundle for a TLS-intercepting proxy |

An object may take at most half its zone; bigger ones are proxied uncached.

## How it caches

- Files (crates, module zips, tarballs, wheels) are immutable: kept a year,
  streamed to the client while being stored, published only when complete.
- Metadata (index files, packuments, simple pages) is fetched whole, lives
  5–10 minutes, then is revalidated with the origin's validators. 404s are
  cached for a minute.
- A request for a key that is already being fetched gets the stale copy if
  there is one, otherwise it is relayed uncached. There is no coalescing.
- Upstream 429/5xx or network errors serve the stale copy. After a network
  error the upstream is skipped for 30s for requests that have a stale copy.
- `Cache-Control: no-cache` from a client revalidates metadata; files always
  come from the cache.
- Responses carry `Cache-Control` (files immutable, metadata its remaining
  TTL), strong ETags, and gzip for text when the client accepts it.
- URLs in metadata are rewritten to point here; file bytes are never touched,
  so client hash checks hold. PyPI pages are served as JSON or as HTML (pip
  < 22.2), by `Accept`.
- Query strings and empty path segments get a 400 (except npm search).
- SIGTERM gives requests in flight 100s to finish.

## Purging an entry

Each entry file starts with a JSON header holding its upstream `url`:

```sh
docker compose stop cache
docker run --rm -v simple-cache_cache:/cache busybox \
  sh -c 'grep -rlF "files.pythonhosted.org/packages/.../bad.whl" /cache | xargs -r rm -v'
docker compose start cache
```
