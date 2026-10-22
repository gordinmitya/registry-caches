package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Entry file: a fixed header area holding the JSON meta (NUL-padded), body
// from hdrSize on. Fills write the body into a temp file at hdrSize+, the meta
// last, and rename, so a visible entry is always complete. A 304 rewrites the
// whole (small) entry the same way.
const (
	hdrSize = 4096
	// Metadata bodies are buffered whole (rewrite, stale-on-body-error).
	// renovate's full packument is 69 MiB; PyPI's /simple/ 45 MB.
	maxBuffer  = 128 << 20
	maxSmall   = 64 << 10 // negative entries
	maxReqBody = 32 << 20 // request bodies relayed by rule.pass (npm audit sends a few MB)
	idle       = 60 * time.Second
	// Below pip's 15s read timeout: a client waiting for a slot gets a 503
	// with Retry-After rather than timing out on us.
	semWait = 10 * time.Second
	// ponytail: caps a metadata fill, which no client leaving ends, so an
	// upstream dripping a byte a minute can't pin a fill slot for good.
	// File fills and relays go at their client's pace and end with it: an
	// upstream dripping to a patient client holds its slot as long.
	maxFill  = 2 * time.Hour
	growStep = 1 << 20 // disk reservation step for bodies of unknown length
	// After a transport failure an upstream is not tried for this long by
	// requests that have a stale copy to serve instead.
	downFor = 30 * time.Second
)

var (
	errCorrupt = errors.New("corrupt cache entry")
	errNoRoom  = errors.New("no room in cache")
	errTooBig  = errors.New("object exceeds size limit")
	errDown    = errors.New("upstream down after a recent connection failure")
)

// zone is one size-capped directory of entries. meta zones hold small mutable
// metadata: fetched whole before answering, revalidated when expired. The
// others hold immutable artifacts, streamed to the client while they fill.
type zone struct {
	dir  string
	cap  int64
	meta bool
	used int64 // bytes on disk incl. in-flight reservations; guarded by Cache.mu
}

// ponytail: one file may take half the zone; a bigger file would flush
// everything else for one hit. Raise if a registry needs it.
func (z *zone) maxFile() int64 { return z.cap / 2 }

// rule maps one family of client paths to an upstream. Later registries add
// what they need here; the engine only reads fields.
type rule struct {
	name     string
	match    func(p string) bool
	local    string // fixed text/plain answer, no upstream (health/usage)
	redirect string // fixed 301 target, no upstream
	upstream string // scheme://host, fixed: clients never choose where we connect
	path     func(p string) string
	zone     *zone
	ttl      time.Duration       // 200
	negTTL   time.Duration       // 404/410; 0 = not cached
	rewrite  func([]byte) []byte // applied to metadata bodies before storing
	compress []string            // Content-Type prefixes we may gzip
	follow   string              // host whose redirects we fetch ourselves (see do)
	// location rewrites the Location of redirects passed to clients, so an
	// absolute upstream URL brings the follow-up back to us.
	location func(string) string
	accept   string // upstream Accept
	// variant picks the upstream Accept per request, overriding accept. It is
	// part of the cache key and clients get Vary: Accept, so it must map any
	// client Accept onto a few canonical values or the cache fragments.
	variant func(r *http.Request) string
	// pass sends a request through passthrough instead of the cache: any
	// method, Authorization and body forwarded, nothing stored or shared.
	pass func(r *http.Request) bool
	// query: the path takes a query string (npm search). Elsewhere one is
	// refused unless passed: upstream ignores what it doesn't know, so
	// ?x=1, ?x=2... would each fill and store a copy of the same page.
	query bool
}

func exact(s string) func(string) bool { return func(p string) bool { return p == s } }
func prefix(s string) func(string) bool {
	return func(p string) bool { return strings.HasPrefix(p, s) }
}

// decoded matches re against the unescaped path.
func decoded(re *regexp.Regexp) func(string) bool {
	return func(p string) bool {
		d, err := url.PathUnescape(p)
		return err == nil && re.MatchString(d)
	}
}

func strip(s string) func(string) string {
	return func(p string) string { return strings.TrimPrefix(p, s) }
}
func same(p string) string { return p }

type registry struct {
	name   string
	public string // our own origin, e.g. https://crates.example.com; never taken from Host
	c      *Cache
	rules  []*rule
}

func (reg *registry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.EscapedPath()
	if err := checkPath(p, r.URL.RawQuery); err != nil {
		refuse(w, r, err.Error(), http.StatusBadRequest)
		return
	}
	var rt *rule
	for _, x := range reg.rules {
		if x.match(p) {
			rt = x
			break
		}
	}
	if rt != nil && rt.variant != nil {
		w.Header().Set("Vary", "Accept")
	}
	if rt != nil && rt.pass != nil && rt.pass(r) {
		reg.c.passthrough(w, r, rt, true)
		return
	}
	if r.URL.RawQuery != "" && (rt == nil || !rt.query) {
		refuse(w, r, "query not supported", http.StatusBadRequest)
		return
	}
	// Nothing below reads a body. An HTTP/2 request of unknown length may
	// have none: some stacks end a bodyless GET with an empty DATA frame.
	if r.ContentLength > 0 || r.ContentLength < 0 && r.ProtoMajor == 1 {
		refuse(w, r, "request body not allowed", http.StatusBadRequest)
		return
	}
	if rt == nil {
		refuse(w, r, "404 page not found", http.StatusNotFound)
		return
	}
	if li, ok := r.Context().Value(logKey{}).(*logInfo); ok {
		li.query = true // not relayed: a cache key, no credential
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		refuse(w, r, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Answers made here are cheap to make again and may change with our
	// config: no cache keeps them, like the errors refuse sends.
	if rt.upstream == "" || rt.redirect != "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	if rt.redirect != "" {
		http.Redirect(w, r, rt.redirect, http.StatusMovedPermanently)
		return
	}
	if rt.upstream == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, rt.local)
		return
	}
	reg.c.handle(w, r, reg, rt)
}

// refuse answers with an error, leaving the request body unread. net/http
// would drain it after us, forever if the client stalls, so HTTP/1 closes the
// connection instead. HTTP/2 resets an unread stream by itself, and
// Connection: close there would shut down the client's other streams. An
// error is no answer to keep: no-store.
func refuse(w http.ResponseWriter, r *http.Request, msg string, status int) {
	w.Header().Set("Cache-Control", "no-store")
	if r.ProtoMajor == 1 && r.ContentLength != 0 {
		w.Header().Set("Connection", "close")
		http.NewResponseController(w).SetReadDeadline(time.Now())
	}
	http.Error(w, msg, status)
}

// target is where r goes upstream under rt: fixed origin, escaped path (keeps
// npm's @scope%2fpkg unless the rule canonicalises it), and the canonical
// Accept.
func (rt *rule) target(r *http.Request) (up, accept string) {
	up = rt.upstream + rt.path(r.URL.EscapedPath())
	if q := r.URL.RawQuery; q != "" {
		up += "?" + q
	}
	accept = rt.accept
	if rt.variant != nil {
		accept = rt.variant(r)
	}
	return up, accept
}

// queryChars are RFC 3986 query bytes: pchar / "/" / "?", '%' escapes being
// checked by unescaping.
const queryChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@/?%"

// checkPath rejects what could make the upstream path differ from the one we
// key on. Validated on the decoded form so %2e%2e and a%2f..%2fb count, but
// ".." inside a name (a..b) is fine. No path.Clean: rewriting would alias keys.
func checkPath(p, q string) error {
	if len(p) > 2048 || len(q) > 1024 {
		return errors.New("request URI too long")
	}
	if !strings.HasPrefix(p, "/") {
		return errors.New("bad path")
	}
	dec, err := url.PathUnescape(p)
	if err != nil {
		return errors.New("malformed escape in path")
	}
	// No registry path has an empty segment, and upstreams collapse them
	// (pypi.org serves /simple//x/ as /simple/x/): each spelling would be
	// another fill of the same page.
	if strings.Contains(dec, "//") {
		return errors.New("empty segment in path")
	}
	// The query goes upstream as sent, so RFC 3986 query bytes only: a raw
	// '#' would cut it short there (the rest a fragment, never sent) while
	// staying in our key, and a space would split the request line.
	if strings.IndexFunc(q, func(r rune) bool { return !strings.ContainsRune(queryChars, r) }) >= 0 {
		return errors.New("bad character in query")
	}
	qdec, err := url.QueryUnescape(q)
	if err != nil {
		return errors.New("malformed escape in query")
	}
	if strings.ContainsRune(dec, 0) || strings.ContainsRune(qdec, 0) {
		return errors.New("NUL in request")
	}
	for seg := range strings.SplitSeq(dec, "/") {
		if seg == "." || seg == ".." {
			return errors.New("dot segment in path")
		}
	}
	return nil
}

// cacheKey hashes length-prefixed fields so no two field lists collide.
func cacheKey(fields ...string) string {
	h := sha256.New()
	for _, f := range fields {
		binary.Write(h, binary.BigEndian, uint32(len(f)))
		io.WriteString(h, f)
	}
	return hex.EncodeToString(h.Sum(nil))
}

type meta struct {
	V            int       `json:"v"`
	Status       int       `json:"status"`
	URL          string    `json:"url,omitempty"` // fetched from; for finding an entry to purge
	ContentType  string    `json:"ct,omitempty"`
	ETag         string    `json:"etag,omitempty"` // origin's; only sent back upstream
	LastModified string    `json:"lm,omitempty"`
	Hash         string    `json:"hash"` // of the stored body; our ETag to clients
	Expires      time.Time `json:"exp"`
	Size         int64     `json:"size"`
}

func encodeMeta(m *meta) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if len(b) >= hdrSize {
		return nil, errTooBig
	}
	out := make([]byte, hdrSize)
	copy(out, b)
	return out, nil
}

func openEntry(path string) (*os.File, *meta, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	var hdr [hdrSize]byte
	m := new(meta)
	_, err = io.ReadFull(f, hdr[:])
	if err == nil {
		end := bytes.IndexByte(hdr[:], 0)
		if end < 0 {
			end = 0
		}
		err = json.Unmarshal(hdr[:end], m)
	}
	var fi os.FileInfo
	if err == nil {
		fi, err = f.Stat()
	}
	if err != nil || m.V != 1 || m.Status == 0 || fi.Size() != hdrSize+m.Size {
		f.Close()
		return nil, nil, errCorrupt
	}
	return f, m, nil
}

// section is an entry's body.
func section(f *os.File, m *meta) io.ReadSeeker { return io.NewSectionReader(f, hdrSize, m.Size) }

type entryInfo struct {
	z     *zone
	size  int64
	atime time.Time // last use, at 1h granularity; mirrored to mtime for restarts
}

type Cache struct {
	root    string
	minFree int64
	// Requests go straight to the transport: http.Client would parse the
	// Location of every redirect and, when that fails, put the whole header
	// (a signed URL, say) into its error, and wrap every error in a *url.Error
	// that repeats the request URL with its query. We follow redirects
	// ourselves (see do) or hand them to the client as they are.
	tr *http.Transport
	// ftr fetches file-zone entries over HTTP/1.1, a connection each. On one
	// HTTP/2 connection Fastly (files.pythonhosted.org) advertises 100
	// streams but sends response headers for only ~12 big files at a time;
	// the rest wait until earlier ones finish, which on a slow uplink is past
	// ResponseHeaderTimeout: 8 of 20 overlapping cold wheel requests got a
	// 502 after 60s, while 20 over HTTP/1.1 all had headers within 3s. Go's
	// transport opens no second connection below the advertised limit.
	// Metadata stays on tr (HTTP/2), whose pings find a dead connection
	// before a stale copy is served.
	ftr *http.Transport
	// fillSem bounds every upstream request, fills and relays alike.
	fillSem chan struct{}
	bufSem  chan struct{}
	free    func() int64 // bytes available on the cache filesystem

	mu sync.Mutex
	// inflight holds the keys being fetched to fill an entry. Requests for
	// one don't wait for it (see handle).
	inflight  map[string]struct{}
	down      map[string]time.Time  // upstream origin → not tried before
	entries   map[string]*entryInfo // by file path
	unwritten int64                 // reserved but not yet on disk, so statfs can't see it
}

func newCache(root string, minFree int64, maxFills int) *Cache {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	c := &Cache{
		root:    root,
		minFree: minFree,
		fillSem: make(chan struct{}, maxFills),
		// Worst case 16 x 128 MiB of buffered metadata in memory; packuments
		// and simple pages are mostly KBs.
		bufSem:   make(chan struct{}, 16),
		inflight: map[string]struct{}{},
		down:     map[string]time.Time{},
		entries:  map[string]*entryInfo{},
	}
	transport := func() *http.Transport {
		return &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           d.DialContext,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			// Pings find a dead pooled HTTP/2 connection (an egress
			// blackhole) in seconds; otherwise every request multiplexed
			// onto it waits out ResponseHeaderTimeout, longer than cargo's
			// 30s, before it can get a stale copy.
			HTTP2:               &http.HTTP2Config{SendPingTimeout: 10 * time.Second, PingTimeout: 5 * time.Second},
			MaxIdleConnsPerHost: 16,
			// Below CDN idle timeouts, so we rarely reuse a connection the
			// far side already closed.
			IdleConnTimeout: 30 * time.Second,
			// We pin Accept-Encoding ourselves; the transport must not add
			// gzip and silently decode it.
			DisableCompression: true,
		}
	}
	c.tr, c.ftr = transport(), transport()
	c.ftr.Protocols = new(http.Protocols)
	c.ftr.Protocols.SetHTTP1(true)
	c.free = func() int64 {
		var st syscall.Statfs_t
		if err := syscall.Statfs(root, &st); err != nil {
			return 0 // unknown → treat the disk as full rather than risk ENOSPC
		}
		return int64(st.Bavail) * st.Bsize
	}
	return c
}

// addZone creates/loads a zone, dropping temp files and unreadable entries
// left by a crash, and accounts what remains.
func (c *Cache) addZone(name string, cap int64, meta bool) (*zone, error) {
	z := &zone{dir: filepath.Join(c.root, name), cap: cap, meta: meta}
	if err := os.MkdirAll(z.dir, 0o755); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// ponytail: reads every entry header at startup; seconds for ~10^5 entries.
	err := filepath.WalkDir(z.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasPrefix(d.Name(), ".tmp-") {
			return os.Remove(p)
		}
		f, m, err := openEntry(p)
		if err != nil {
			slog.Warn("dropping unreadable cache entry", "path", p)
			return os.Remove(p)
		}
		f.Close()
		fi, err := d.Info() // mtime: last use (see touch)
		if err != nil {
			return err
		}
		size := hdrSize + m.Size // checked against the file by openEntry
		c.entries[p] = &entryInfo{z: z, size: size, atime: fi.ModTime()}
		z.used += size
		return nil
	})
	if z.used > z.cap {
		c.evictLocked(z, z.used-z.cap*9/10)
	}
	return z, err
}

// admitLocked makes room for n more bytes in z, evicting down to a low-water
// mark so we don't evict on every fill. False means no room can be made.
func (c *Cache) admitLocked(z *zone, n int64) bool {
	if z.used+n > z.cap {
		c.evictLocked(z, z.used+n-z.cap*9/10)
	}
	// All zones share one filesystem; the reserve keeps it from filling up
	// whatever the caps add up to.
	free := c.free() - c.unwritten
	if free-n < c.minFree {
		c.evictLocked(nil, c.minFree+n-free+c.minFree/10)
		// Measured again, not free += evicted: an unlinked entry a client
		// is still reading keeps its blocks until the fd closes.
		free = c.free() - c.unwritten
	}
	if z.used+n > z.cap || free-n < c.minFree {
		return false
	}
	z.used += n
	c.unwritten += n
	return true
}

// evictLocked deletes least recently used entries (of z, or of all zones when
// z is nil) until need bytes are freed.
// ponytail: O(n log n) over all entries per eviction batch; fine for ~10^5.
func (c *Cache) evictLocked(z *zone, need int64) (freed int64) {
	var victims []string
	for p, e := range c.entries {
		if z == nil || e.z == z {
			victims = append(victims, p)
		}
	}
	slices.SortFunc(victims, func(a, b string) int { return c.entries[a].atime.Compare(c.entries[b].atime) })
	for _, p := range victims {
		if freed >= need {
			break
		}
		e := c.entries[p]
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Error("evict", "path", p, "err", err)
			continue
		}
		e.z.used -= e.size
		freed += e.size
		delete(c.entries, p)
	}
	return freed
}

func (c *Cache) touch(path string) {
	now := time.Now()
	c.mu.Lock()
	e := c.entries[path]
	bump := e != nil && now.Sub(e.atime) > time.Hour
	if bump {
		e.atime = now
	}
	c.mu.Unlock()
	if bump {
		os.Chtimes(path, now, now)
	}
}

// claim marks key as being fetched. False means another request already is.
func (c *Cache) claim(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.inflight[key]; ok {
		return false
	}
	c.inflight[key] = struct{}{}
	return true
}

func (c *Cache) release(key string) {
	c.mu.Lock()
	delete(c.inflight, key)
	c.mu.Unlock()
}

func (c *Cache) isDown(origin string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Before(c.down[origin])
}

func (c *Cache) markDown(origin string, down bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if down {
		c.down[origin] = time.Now().Add(downFor)
	} else {
		delete(c.down, origin)
	}
}

// reservation is one fill's claim on disk space, grown as the body arrives.
type reservation struct {
	c                 *Cache
	z                 *zone
	admitted, settled int64 // settled = bytes known to be on disk
}

func (r *reservation) grow(written, total int64) bool {
	c := r.c
	c.mu.Lock()
	defer c.mu.Unlock()
	c.unwritten -= written - r.settled
	r.settled = written
	if total <= r.admitted {
		return true
	}
	if !c.admitLocked(r.z, total-r.admitted) {
		return false
	}
	r.admitted = total
	return true
}

// commit renames tmp onto path and accounts it in one step under c.mu. Done
// apart, eviction could pick the old entry still listed for path and delete
// the new file we just renamed there. On error nothing changed; cancel still
// applies.
func (r *reservation) commit(tmp, path string, size int64) error {
	c := r.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	c.unwritten -= r.admitted - r.settled
	r.z.used += size - r.admitted
	if old := c.entries[path]; old != nil {
		old.z.used -= old.size
	}
	c.entries[path] = &entryInfo{z: r.z, size: size, atime: time.Now()}
	return nil
}

func (r *reservation) cancel() {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	r.c.unwritten -= r.admitted - r.settled
	r.z.used -= r.admitted
}

// begin reserves total bytes and creates the temp file that will become path.
func (c *Cache) begin(z *zone, path string, total int64) (*os.File, *reservation, error) {
	res := &reservation{c: c, z: z}
	if !res.grow(0, total) {
		return nil, nil, errNoRoom
	}
	err := os.MkdirAll(filepath.Dir(path), 0o755)
	var tmp *os.File
	if err == nil {
		tmp, err = os.CreateTemp(filepath.Dir(path), ".tmp-*")
	}
	if err != nil {
		res.cancel()
		return nil, nil, err
	}
	return tmp, res, nil
}

// publish atomically stores a fully buffered entry.
func (c *Cache) publish(z *zone, path string, m *meta, body []byte) error {
	hdr, err := encodeMeta(m)
	if err != nil {
		return err
	}
	tmp, res, err := c.begin(z, path, hdrSize+int64(len(body)))
	if err != nil {
		return err
	}
	_, err = tmp.Write(hdr)
	if err == nil {
		_, err = tmp.Write(body)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = res.commit(tmp.Name(), path, hdrSize+int64(len(body)))
	}
	if err != nil {
		os.Remove(tmp.Name())
		res.cancel()
	}
	return err
}

func newMeta(up string, status int, h http.Header, body []byte, ttl time.Duration) *meta {
	sum := sha256.Sum256(body)
	return &meta{V: 1, Status: status, URL: up, ContentType: h.Get("Content-Type"),
		ETag: h.Get("ETag"), LastModified: h.Get("Last-Modified"),
		Hash: hex.EncodeToString(sum[:16]), Expires: time.Now().Add(ttl), Size: int64(len(body))}
}

// handle answers a cacheable request from a fresh entry, or fetches it on
// this request's goroutine. A request that finds its key already being
// fetched doesn't wait for that: it gets the expired entry if there is one,
// else is relayed uncached. Load is low; this trades some egress on
// overlapping cold requests for having no shared state between requests.
func (c *Cache) handle(w http.ResponseWriter, r *http.Request, reg *registry, rt *rule) {
	origin := ""
	if rt.rewrite != nil {
		origin = reg.public // rewritten bodies embed it
	}
	up, accept := rt.target(r)
	// Keyed on what goes upstream, so the spellings a rule's path
	// canonicalises (npm's @scope%2fname) share one entry.
	key := cacheKey(reg.name, rt.name, up, accept, origin)
	path := filepath.Join(rt.zone.dir, key[:2], key)
	// An expired entry stays open for the whole request: it is the stale
	// fallback and the 304 body, and eviction can unlink it but not take it
	// from under us.
	f, m, _ := openEntry(path)
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	// Files are immutable: asking to refresh one gets the entry.
	refresh := rt.zone.meta && wantsRefresh(r)
	fresh := func() bool { return f != nil && !refresh && time.Now().Before(m.Expires) }
	if fresh() {
		c.touch(path)
		serveEntry(w, r, rt, section(f, m), m, "HIT")
		return
	}
	// A cold HEAD on a file is relayed: it never downloads a whole file for
	// its headers, nor creates an entry.
	if r.Method == http.MethodHead && !rt.zone.meta {
		c.passthrough(w, r, rt, false)
		return
	}
	if !c.claim(key) {
		if f != nil {
			cs := "STALE"
			if time.Now().Before(m.Expires) {
				cs = "HIT" // fresh, the client asked for a refresh
			}
			serveEntry(w, r, rt, section(f, m), m, cs)
			return
		}
		c.passthrough(w, r, rt, false)
		return
	}
	// Runs after publishing, so a newcomer sees the claim or the entry.
	defer c.release(key)
	// Another request may have published between our look and our claim.
	if nf, nm, err := openEntry(path); err == nil {
		if f != nil {
			f.Close()
		}
		f, m = nf, nm
		if fresh() {
			c.touch(path)
			serveEntry(w, r, rt, section(f, m), m, "HIT")
			return
		}
	}
	c.fill(w, r, rt, up, accept, path, f, m)
}

// wantsRefresh: the client asks for an end-to-end revalidation (uv
// --refresh, pip on every index page; npm --prefer-online sends neither
// header, so npm's refresh ends at our TTL). For metadata that
// is a cheap conditional request upstream.
func wantsRefresh(r *http.Request) bool {
	cc := r.Header.Values("Cache-Control")
	if len(cc) == 0 {
		return strings.Contains(strings.ToLower(r.Header.Get("Pragma")), "no-cache")
	}
	for _, v := range cc {
		for d := range strings.SplitSeq(v, ",") {
			// max-age="0": a directive argument may be quoted (RFC 9111 5.2).
			name, arg, _ := strings.Cut(strings.ToLower(strings.TrimSpace(d)), "=")
			if name == "no-cache" || name == "max-age" && strings.Trim(arg, `"`) == "0" {
				return true
			}
		}
	}
	return false
}

// fill fetches up for a missing or expired entry (f, m: the expired one, if
// any, else nil), answers the client and stores what may be stored.
func (c *Cache) fill(w http.ResponseWriter, r *http.Request, rt *rule, up, accept, path string, f *os.File, m *meta) {
	// A client's refresh of a fresh entry that gets a new body is a MISS:
	// nothing had expired.
	cs := "MISS"
	if f != nil && !time.Now().Before(m.Expires) {
		cs = "EXPIRED"
	}
	// fail is only used before anything reached the client, so stale is
	// still an option.
	fail := func(status int, msg string, err error) {
		if r.Context().Err() != nil {
			return // client gone, logged as 499
		}
		slog.Warn("upstream fetch failed", "url", up, "err", err)
		if f != nil {
			serveEntry(w, r, rt, section(f, m), m, "STALE")
			return
		}
		w.Header().Set("X-Cache-Status", cs)
		if status == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", "5")
		}
		refuse(w, r, msg, status)
	}
	// After a connection failure a client with a copy gets it at once, not
	// after upstream fails again. A cold request tries anyway: a 502 is all
	// it would get otherwise, and one blip must not fail 30s of installs.
	if f != nil && c.isDown(rt.upstream) {
		fail(http.StatusBadGateway, "", errDown)
		return
	}

	// A metadata body reaches the client only once whole, so a client with a
	// short read timeout (pip: 15s) may give up on a slow page: its fill
	// finishes anyway, and the retry is a HIT. A file streams at its
	// client's pace, which may take hours, and its client leaving cancels it.
	var ctx context.Context
	var cancel context.CancelFunc
	if rt.zone.meta {
		ctx, cancel = context.WithTimeout(context.WithoutCancel(r.Context()), maxFill)
	} else {
		ctx, cancel = context.WithCancel(r.Context())
	}
	defer cancel()
	if !acquire(ctx, c.fillSem) {
		fail(http.StatusServiceUnavailable, "too many upstream fetches", errors.New("fill limit"))
		return
	}
	defer func() { <-c.fillSem }()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, up, nil)
	if err != nil {
		fail(http.StatusBadRequest, "bad request", err) // unreachable while checkPath holds
		return
	}
	upstreamHeaders(req, accept)
	if rt.zone.meta {
		// Buffered whole anyway, so decoded here: stored bytes stay
		// canonical, and big pages cost 4-6x less egress.
		req.Header.Set("Accept-Encoding", "gzip")
	}
	revalidate := f != nil && rt.zone.meta && m.Status == http.StatusOK && (m.ETag != "" || m.LastModified != "")
	if revalidate {
		if m.ETag != "" {
			req.Header.Set("If-None-Match", m.ETag)
		}
		if m.LastModified != "" {
			req.Header.Set("If-Modified-Since", m.LastModified)
		}
	}
	resp, err := c.do(req, rt)
	if err != nil {
		fail(http.StatusBadGateway, "upstream error", err)
		return
	}
	defer resp.Body.Close()
	body, stop := watch(resp.Body, cancel)
	defer stop()
	if rt.zone.meta {
		body = ungzip(resp, body)
	}

	switch st := resp.StatusCode; {
	case !identity(resp.Header.Get("Content-Encoding")):
		// Anything else would be stored as the canonical bytes and break
		// hash checks (pip) or rewrites.
		fail(http.StatusBadGateway, "upstream sent an encoded body", errors.New(resp.Header.Get("Content-Encoding")))
	case st == 429 || st == 500 || st == 502 || st == 503 || st == 504:
		// 429 too: a rate limit on our shared egress IP is no answer to keep
		// from a client that has a copy.
		if f != nil {
			fail(st, "", fmt.Errorf("upstream status %d", st))
			return
		}
		c.relay(w, r, rt, resp, body, cs, fail)
	case st == http.StatusNotModified:
		if !revalidate {
			fail(http.StatusBadGateway, "unexpected 304 from upstream", nil)
			return
		}
		if time.Now().Before(m.Expires) {
			// A client's refresh of a fresh entry (pip asks one for every
			// index page): its expiry still holds, nothing to rewrite.
			serveEntry(w, r, rt, section(f, m), m, "REVALIDATED")
			return
		}
		// Our old body, republished with a new expiry.
		if !acquire(ctx, c.bufSem) {
			fail(http.StatusServiceUnavailable, "too many upstream fetches", errors.New("buffer limit"))
			return
		}
		defer func() { <-c.bufSem }()
		b := make([]byte, m.Size)
		if _, err := io.ReadFull(section(f, m), b); err != nil {
			fail(http.StatusBadGateway, "cache read error", err)
			return
		}
		nm := *m
		nm.URL, nm.Expires = up, time.Now().Add(rt.ttl)
		if v := resp.Header.Get("ETag"); v != "" {
			nm.ETag = v
		}
		if v := resp.Header.Get("Last-Modified"); v != "" {
			nm.LastModified = v
		}
		if err := c.publish(rt.zone, path, &nm, b); err != nil {
			slog.Warn("revalidation not stored", "path", path, "err", err)
		}
		serveEntry(w, r, rt, bytes.NewReader(b), &nm, "REVALIDATED")
	case st == http.StatusOK && rt.zone.meta, (st == http.StatusNotFound || st == http.StatusGone) && rt.negTTL > 0:
		limit, ttl := int64(maxSmall), rt.negTTL
		if st == http.StatusOK {
			limit, ttl = maxBuffer, rt.ttl
			if !acquire(ctx, c.bufSem) {
				fail(http.StatusServiceUnavailable, "too many upstream fetches", errors.New("buffer limit"))
				return
			}
			defer func() { <-c.bufSem }()
		}
		b, err := readMax(body, limit)
		if errors.Is(err, errTooBig) && st != http.StatusOK {
			// Too big to keep, but the status stands: the go command's
			// GOPROXY list falls through to the next proxy on 404/410 only.
			c.relay(w, r, rt, resp, io.MultiReader(bytes.NewReader(b), body), cs, fail)
			return
		}
		if err != nil {
			fail(http.StatusBadGateway, "upstream error", err)
			return
		}
		if st == http.StatusOK && rt.rewrite != nil {
			b = rt.rewrite(b)
		}
		nm := newMeta(up, st, resp.Header, b, ttl)
		if err := c.publish(rt.zone, path, nm, b); err != nil {
			slog.Warn("not cached", "url", up, "err", err)
			cs = "BYPASS"
		}
		serveEntry(w, r, rt, bytes.NewReader(b), nm, cs)
	case st == http.StatusOK:
		c.streamFile(w, r, rt, up, path, cs, resp, body, fail)
	default:
		// Redirects and other statuses pass through uncached.
		c.relay(w, r, rt, resp, body, cs, fail)
	}
}

// streamFile sends a file's body to the client as it arrives while writing it
// to a temp file, published once complete and length-checked. An upstream
// failure never ends as a clean short 200: the transfer is aborted and
// nothing is stored. Storing is best effort: when it fails (no room, a write
// error, a body of unknown length over maxFile) the client still gets every
// byte. Range is ignored (200), and our hash ETag isn't known yet.
func (c *Cache) streamFile(w http.ResponseWriter, r *http.Request, rt *rule, up, path, cs string,
	resp *http.Response, body io.Reader, fail func(int, string, error)) {
	z := rt.zone
	size := resp.ContentLength
	if size > z.maxFile() {
		c.relay(w, r, rt, resp, body, "BYPASS", fail)
		return
	}
	total := hdrSize + size
	if size < 0 {
		total = hdrSize + growStep
	}
	tmp, res, err := c.begin(z, path, total)
	if err != nil {
		slog.Warn("not cached", "path", path, "err", err)
		c.relay(w, r, rt, resp, body, "BYPASS", fail)
		return
	}
	storing := true // cleared once the temp file is committed or dropped
	drop := func(err error) {
		if !storing {
			return
		}
		storing = false
		if err != nil {
			slog.Warn("not cached", "path", path, "err", err)
		}
		tmp.Close()
		os.Remove(tmp.Name())
		res.cancel()
	}
	defer drop(nil)
	var n int64
	save := func(p []byte) error {
		end := hdrSize + n + int64(len(p))
		want := res.admitted
		if end > want {
			want = end + growStep
		}
		switch {
		case n+int64(len(p)) > z.maxFile():
			return errTooBig
		// Settle every step, not only when growing: written bytes already
		// show in statfs, and leaving them in c.unwritten as well would
		// take them off the free-space reserve twice.
		case want > res.admitted || end-res.settled > growStep:
			if !res.grow(hdrSize+n, want) {
				return errNoRoom
			}
		}
		_, err := tmp.Write(p)
		return err
	}

	m := newMeta(up, http.StatusOK, resp.Header, nil, rt.ttl)
	// Headers wait for the first body byte: a fetch that dies before it
	// still gets stale or a clean 502 instead of an aborted 200.
	started := false
	start := func() {
		entryHeaders(w.Header(), rt, m, cs)
		if size >= 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		}
		w.WriteHeader(http.StatusOK)
		started = true
	}
	rc := http.NewResponseController(w)
	sum := sha256.New()
	buf := make([]byte, 64<<10)
	if _, err := tmp.Seek(hdrSize, io.SeekStart); err != nil {
		drop(err)
	}
	for {
		k, rerr := body.Read(buf)
		if k > 0 {
			if storing {
				if err := save(buf[:k]); err != nil {
					drop(err)
				}
			}
			sum.Write(buf[:k])
			n += int64(k)
			if !started {
				start()
			}
			if _, err := w.Write(buf[:k]); err != nil {
				return // client gone
			}
			// Bytes go out as they arrive: a client waiting on a multi-GB file
			// never sits silent past its idle timeout.
			rc.Flush()
		}
		// All of a declared length is the whole body. Over HTTP/2 the EOF
		// (END_STREAM) may come later, by when a client that stops reading
		// at Content-Length has left and cancelled us: no waiting for it.
		if rerr == io.EOF || size >= 0 && n == size {
			break
		}
		if rerr != nil {
			err = rerr
			break
		}
	}
	if err == nil && size >= 0 && n != size {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		if !started {
			fail(http.StatusBadGateway, "upstream error", err)
			return
		}
		slog.Warn("fill failed", "path", path, "bytes", n, "err", err)
		panic(http.ErrAbortHandler)
	}
	if !started {
		start() // empty body
	}
	if !storing {
		return
	}
	// The client has every byte; storing them is best effort from here.
	m.Hash, m.Size = hex.EncodeToString(sum.Sum(nil)[:16]), n
	hdr, err := encodeMeta(m)
	if err == nil {
		_, err = tmp.WriteAt(hdr, 0)
	}
	if err == nil {
		err = tmp.Close()
	}
	if err == nil {
		err = res.commit(tmp.Name(), path, hdrSize+n)
	}
	if err != nil {
		drop(err)
		return
	}
	storing = false // committed: nothing to drop
}

// entryHeaders sets what every answer shaped like an entry carries, from
// disk, from memory or still streaming in, and reports whether its body may
// be gzipped.
func entryHeaders(h http.Header, rt *rule, m *meta, cs string) (compressible bool) {
	h.Set("X-Cache-Status", cs)
	if m.ContentType != "" {
		h.Set("Content-Type", m.ContentType)
	} else {
		h["Content-Type"] = nil // don't let net/http sniff one
	}
	if lm, err := http.ParseTime(m.LastModified); err == nil {
		h.Set("Last-Modified", lm.UTC().Format(http.TimeFormat))
	}
	h.Set("Cache-Control", cacheControl(rt, m, cs == "STALE"))
	compressible = m.Status == http.StatusOK && slices.ContainsFunc(rt.compress, func(p string) bool {
		return strings.HasPrefix(strings.ToLower(m.ContentType), p)
	})
	if compressible {
		h.Add("Vary", "Accept-Encoding") // next to a rule's Vary: Accept
	}
	return compressible
}

// cacheControl: files are immutable. Metadata may be kept for what is left of
// our own TTL, so a client can't hold an almost expired (or stale: 0) copy a
// whole extra TTL. Without it npm guesses from Last-Modified and can keep an
// old packument for weeks.
func cacheControl(rt *rule, m *meta, stale bool) string {
	if !rt.zone.meta && m.Status == http.StatusOK {
		return "public, max-age=31536000, immutable"
	}
	if stale {
		// Expired, or fresh but a refresh the client asked for failed.
		return "public, max-age=0"
	}
	return "public, max-age=" + strconv.Itoa(int(max(0, time.Until(m.Expires).Seconds())))
}

// serveEntry sends a complete entry, from disk or memory. 200s go through
// ServeContent (Range, conditionals) or gzip; negative entries are sent as
// stored.
func serveEntry(w http.ResponseWriter, r *http.Request, rt *rule, body io.ReadSeeker, m *meta, cs string) {
	if r.Context().Err() != nil {
		return // client gone (a metadata fill outlives it), logged as 499
	}
	h := w.Header()
	compressible := entryHeaders(h, rt, m, cs)
	if m.Status != http.StatusOK {
		h.Set("Content-Length", strconv.FormatInt(m.Size, 10))
		w.WriteHeader(m.Status)
		if r.Method != http.MethodHead {
			io.Copy(w, body)
		}
		return
	}
	lm, _ := http.ParseTime(m.LastModified)
	tag := `"` + m.Hash + `"`
	// Under 1 KiB gzip's framing outweighs what it saves: identity, though
	// still with Vary, as a bigger body at this URL would be gzipped.
	if !compressible || m.Size < 1024 || r.Header.Get("Range") != "" || !acceptsGzip(r.Header.Get("Accept-Encoding")) {
		h.Set("ETag", tag)
		http.ServeContent(w, r, "", lm, body)
		return
	}
	// The gzip variant gets a strong tag of its own: uv revalidates only
	// with strong tags, and our PEP 691 pages have no Last-Modified. Its
	// bytes may change with the compressor, but strong adds nothing over
	// weak but Range, which a gzip body is never offered (Range requests get
	// identity).
	gzTag := `"` + m.Hash + `-gz"`
	h.Set("ETag", gzTag)
	if notModified(r, lm, gzTag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Encoding", "gzip")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	gz := gzip.NewWriter(w)
	if _, err := io.Copy(gz, body); err != nil {
		// Chunked: returning would end a cut-short gzip stream cleanly.
		panic(http.ErrAbortHandler)
	}
	gz.Close()
}

// notModified matches If-None-Match against tag, weak form included, or else
// If-Modified-Since. Only the tag of the variant being sent: a 304 must not
// pin its tag on bytes of the other one.
func notModified(r *http.Request, lm time.Time, tag string) bool {
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		for t := range strings.SplitSeq(inm, ",") {
			t = strings.TrimPrefix(strings.TrimSpace(t), "W/")
			if t == "*" || t == tag {
				return true
			}
		}
		return false
	}
	ims, err := http.ParseTime(r.Header.Get("If-Modified-Since"))
	return err == nil && !lm.IsZero() && !lm.Truncate(time.Second).After(ims)
}

// acceptsGzip honours q-values: "gzip;q=0" refuses gzip even next to "*".
func acceptsGzip(ae string) bool {
	gz, star := -1.0, -1.0
	for part := range strings.SplitSeq(ae, ",") {
		name, params, _ := strings.Cut(part, ";")
		q := 1.0
		for p := range strings.SplitSeq(params, ";") {
			k, v, _ := strings.Cut(p, "=")
			if strings.EqualFold(strings.TrimSpace(k), "q") {
				var err error
				if q, err = strconv.ParseFloat(strings.TrimSpace(v), 64); err != nil {
					q = 0
				}
			}
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "gzip", "x-gzip":
			gz = q
		case "*":
			star = q
		}
	}
	if gz >= 0 {
		return gz > 0
	}
	return star > 0
}

// passthrough fetches r upstream uncached, on the client's context, and
// relays the answer: rule.pass requests, a cold HEAD on a file, and requests
// for a key another request is already fetching. Only rule.pass requests
// (forward) carry Authorization and a body upstream (npm tokens, audit
// POSTs); a cached-path request never does. No retries: a POST need not be
// idempotent.
func (c *Cache) passthrough(w http.ResponseWriter, r *http.Request, rt *rule, forward bool) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	up, accept := rt.target(r)
	if forward {
		// As the client spelled it: rt.path makes one spelling of a cache
		// key, and npm's writes (PUT /@scope%2fpkg) take the encoded name.
		up = rt.upstream + r.URL.RequestURI()
	}
	// A relayed query may be a credential (npm's web-login poll carries an
	// authId that redeems a token): it stays out of every log line.
	logURL, _, _ := strings.Cut(up, "?")
	var body io.Reader
	if forward && r.ContentLength != 0 {
		if r.ContentLength > maxReqBody {
			refuse(w, r, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		body = idleBody{http.MaxBytesReader(w, r.Body, maxReqBody), http.NewResponseController(w)}
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, up, body)
	if err != nil {
		// e.g. an HTTP/2 :method that isn't a token, which net/http lets in.
		refuse(w, r, "bad request", http.StatusBadRequest)
		return
	}
	upstreamHeaders(req, accept)
	// Metadata as a fill gets it: relay buffers a rewritten page whole
	// anyway, and an overlap shouldn't cost 4-6x the fill's egress.
	meta := rt.zone != nil && rt.zone.meta
	if meta {
		req.Header.Set("Accept-Encoding", "gzip")
	}
	if forward {
		req.ContentLength = r.ContentLength // -1 (chunked) stays chunked
		// npm audit gzips its JSON body; it goes upstream as sent. The registry
		// refuses web login (POST /-/v1/login) without Npm-Auth-Type: web.
		copyHeaders(req.Header, r.Header, "Authorization", "Content-Type", "Content-Encoding", "Npm-Auth-Type")
	}
	if !acquire(ctx, c.fillSem) {
		if r.Context().Err() == nil {
			busy(w, r)
		}
		return
	}
	defer func() { <-c.fillSem }()
	resp, err := c.do(req, rt)
	if err != nil {
		if tooBig := new(http.MaxBytesError); errors.As(err, &tooBig) {
			refuse(w, r, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		if r.Context().Err() != nil {
			return // client gone, logged as 499
		}
		slog.Warn("passthrough failed", "url", logURL, "err", err)
		refuse(w, r, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	rbody, stop := watch(resp.Body, cancel)
	defer stop()
	if meta {
		rbody = ungzip(resp, rbody)
	}
	if !identity(resp.Header.Get("Content-Encoding")) {
		refuse(w, r, "upstream sent an encoded body", http.StatusBadGateway)
		return
	}
	c.relay(w, r, rt, resp, rbody, "BYPASS", func(status int, msg string, err error) {
		slog.Warn("relay failed", "url", logURL, "err", err)
		refuse(w, r, msg, status)
	})
}

// relay answers with an upstream response that isn't stored. A rule's
// rewrite still applies, so authenticated packuments keep tarballs routed
// through the cache. A failed copy aborts the transfer, never ends it as a
// clean short answer; one before any header went out goes to fail, so a fill
// can still serve its stale copy.
func (c *Cache) relay(w http.ResponseWriter, r *http.Request, rt *rule, resp *http.Response, body io.Reader, cs string,
	fail func(int, string, error)) {
	if r.Context().Err() != nil {
		return // client gone (a metadata fill outlives it), logged as 499
	}
	h := w.Header()
	h.Set("X-Cache-Status", cs)
	// A body to rewrite is read whole before any upstream header is set, so
	// an error here doesn't look like upstream's answer. Same memory bound
	// as buffered fills.
	var b []byte
	if rt.rewrite != nil && r.Method != http.MethodHead {
		if !acquire(r.Context(), c.bufSem) {
			if r.Context().Err() == nil {
				busy(w, r)
			}
			return
		}
		defer func() { <-c.bufSem }()
		var err error
		if b, err = readMax(body, maxBuffer); err != nil {
			fail(http.StatusBadGateway, "upstream error", err)
			return
		}
		b = rt.rewrite(b)
	}
	// A whitelist, so Set-Cookie (npm's Cloudflare _cfuvid) never reaches a
	// client. WWW-Authenticate: OTP is how npm learns a token needs 2FA.
	// Retry-After paces npm's web-login poll (202 until the browser step is
	// done; without it npm re-polls in a tight loop) and clients behind an
	// upstream 429/503. npm prints Npm-Notice.
	copyHeaders(h, resp.Header, "Content-Type", "Last-Modified", "Location", "WWW-Authenticate",
		"Retry-After", "Npm-Notice")
	relocate(h, rt)
	// Possibly per-user (a token's private packument): no shared cache may
	// keep it, whatever upstream's Cache-Control said. The client's own may:
	// npm keeps an authenticated user's tarballs in ~/.npm/_cacache, and
	// --offline needs them there. A rule we never store (npm's api: tokens,
	// whoami, audit) answers one-off, so not even the client keeps that.
	cc := "private"
	if rt.zone == nil {
		cc += ", no-store"
	}
	h.Set("Cache-Control", cc)
	if rt.rewrite == nil {
		copyHeaders(h, resp.Header, "Content-Length", "ETag")
	}
	switch {
	case r.Method == http.MethodHead:
		// Without a body, and the length of a rewritten one isn't known.
		w.WriteHeader(resp.StatusCode)
		return
	case rt.rewrite == nil:
		w.WriteHeader(resp.StatusCode)
		// Done at the declared length, as streamFile is, not at an EOF that
		// may come after the client has left.
		if resp.ContentLength >= 0 {
			body = io.LimitReader(body, resp.ContentLength)
		}
		if n, err := io.Copy(w, body); err != nil || resp.ContentLength >= 0 && n != resp.ContentLength {
			panic(http.ErrAbortHandler)
		}
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(resp.StatusCode)
	w.Write(b)
}

func relocate(h http.Header, rt *rule) {
	if loc := h.Get("Location"); loc != "" && rt.location != nil {
		h.Set("Location", rt.location(loc))
	}
}

// busy answers a local limit being full.
func busy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Retry-After", "5")
	refuse(w, r, "too many upstream fetches", http.StatusServiceUnavailable)
}

// idleBody gives a relayed request body the idle bound upstream bodies get:
// the server has no ReadTimeout and ResponseHeaderTimeout starts only once the
// body is sent, so a client that stops mid-upload would hold the handler and
// an upstream connection forever.
type idleBody struct {
	r  io.Reader
	rc *http.ResponseController
}

func (b idleBody) Read(p []byte) (int, error) {
	b.rc.SetReadDeadline(time.Now().Add(idle))
	n, err := b.r.Read(p)
	if err == io.EOF {
		// At EOF the server starts the background read that notices a client
		// hanging up; left set, the deadline would fire there while upstream
		// is still answering and cancel the request. Kept on other errors: the
		// server drains an unread body after the handler, which must not hang.
		b.rc.SetReadDeadline(time.Time{})
	}
	return n, err
}

// do sends req. If the rule follows redirects, one hop to an allowed host is
// fetched here instead of reaching the client: proxy.golang.org answers big
// zips with a 302 to a signed GCS URL, and passing that on would send the
// client around the cache (and out an egress it may not have). The target's
// response stands in for the original, so it is cached under the original
// key; the redirect itself is never stored (its signature expires in ~24h).
// The time to its response headers goes to the access log (udur).
func (c *Cache) do(req *http.Request, rt *rule) (*http.Response, error) {
	if li, ok := req.Context().Value(logKey{}).(*logInfo); ok {
		defer func(t0 time.Time) { li.udur = time.Since(t0) }(time.Now())
	}
	tr := c.tr
	if rt.zone != nil && !rt.zone.meta {
		tr = c.ftr
	}
	resp, err := tr.RoundTrip(req)
	switch {
	case err == nil:
		c.markDown(rt.upstream, false)
	// Only our own transport failure marks it: not a status, not the client
	// hanging up, not a relayed upload the client broke off.
	case req.Context().Err() == nil && req.Body == nil:
		c.markDown(rt.upstream, true)
	}
	if err != nil || rt.follow == "" || !isRedirect(resp.StatusCode) {
		return resp, err
	}
	// Not drained for connection reuse: no idle watchdog runs yet, and a body
	// that stalls would hold the fill slot.
	resp.Body.Close()
	// Location is upstream-controlled: absolute https to an exact allowed host
	// on the default port, no userinfo, so a confused or hostile upstream
	// can't aim our fetch at the internal network. The query (the signature)
	// stays out of errors and logs.
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Scheme != "https" || loc.User != nil ||
		loc.Hostname() != rt.follow || (loc.Port() != "" && loc.Port() != "443") {
		to := ""
		if err == nil {
			to = loc.Scheme + "://" + loc.Host
		}
		return nil, fmt.Errorf("refusing upstream redirect %d to %q", resp.StatusCode, to)
	}
	slog.Info("following upstream redirect", "from", req.URL.String(), "to", loc.Host+loc.EscapedPath())
	next, err := http.NewRequestWithContext(req.Context(), req.Method, loc.String(), nil)
	if err != nil {
		// Its message would quote the signed URL.
		return nil, fmt.Errorf("following redirect to %s%s: bad URL", loc.Host, loc.EscapedPath())
	}
	upstreamHeaders(next, "") // fresh: nothing (validators included) carries over to another host
	resp, err = tr.RoundTrip(next)
	if err != nil {
		// The hop is part of this fetch: its failure marks the upstream as
		// the first hop's would, the redirect having cleared the mark.
		if next.Context().Err() == nil {
			c.markDown(rt.upstream, true)
		}
		return nil, fmt.Errorf("following redirect to %s%s: %w", loc.Host, loc.EscapedPath(), err)
	}
	if isRedirect(resp.StatusCode) {
		resp.Body.Close()
		return nil, fmt.Errorf("upstream redirected twice (%d from %s)", resp.StatusCode, loc.Host)
	}
	return resp, err
}

func isRedirect(st int) bool {
	switch st {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

// Upstream requests are built from scratch: nothing from the client (cookies,
// Authorization, Range, Accept-Encoding) is forwarded; Accept only as the
// rule canonicalised it. Identity bytes, unless metadata asks for gzip and
// decodes it itself.
func upstreamHeaders(req *http.Request, accept string) {
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "simple-cache (internal package mirror)")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
}

// ungzip decodes resp's body if upstream gzipped it, as asked.
func ungzip(resp *http.Response, body io.Reader) io.Reader {
	if !strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		return body
	}
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1 // of the gzip stream, not of what we read
	return &gunzip{r: body}
}

// gunzip decodes a body we asked gzip for. Lazily: an empty body (a 304's,
// say) is no gzip stream and reads as empty.
type gunzip struct {
	r  io.Reader
	zr *gzip.Reader
}

func (g *gunzip) Read(p []byte) (int, error) {
	if g.zr == nil {
		zr, err := gzip.NewReader(g.r)
		if err != nil {
			return 0, err
		}
		g.zr = zr
	}
	return g.zr.Read(p)
}

func copyHeaders(dst, src http.Header, keys ...string) {
	for _, k := range keys {
		if v := src.Get(k); v != "" {
			dst.Set(k, v)
		}
	}
}

func identity(enc string) bool { return enc == "" || strings.EqualFold(enc, "identity") }

// acquire takes a slot, waiting up to semWait unless ctx ends first.
func acquire(ctx context.Context, sem chan struct{}) bool {
	t := time.NewTimer(semWait)
	defer t.Stop()
	select {
	case sem <- struct{}{}:
		return true
	case <-t.C:
		return false
	case <-ctx.Done():
		return false
	}
}

func readMax(r io.Reader, n int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, n+1))
	if err == nil && int64(len(b)) > n {
		err = errTooBig
	}
	return b, err
}

// watch cancels the fetch when the upstream body goes silent for idle: the
// transport's timeouts stop at the response headers.
func watch(body io.Reader, cancel context.CancelFunc) (io.Reader, func() bool) {
	t := time.AfterFunc(idle, cancel)
	return &idleReader{body, t}, t.Stop
}

type idleReader struct {
	r io.Reader
	t *time.Timer
}

func (ir *idleReader) Read(p []byte) (int, error) {
	n, err := ir.r.Read(p)
	ir.t.Reset(idle)
	return n, err
}
