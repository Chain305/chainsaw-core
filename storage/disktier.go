package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DiskTier is a local-disk cache of blob bytes in front of a remote blob
// store (docs/REPORTS.md#backend-perf-load-test-2026-10-29 J.2 C). On the
// measured deployment every cache hit was an S3 GET (p50 584 ms) and the
// store throttled at three concurrent installs; a tier hit is a local read.
//
// Files are named sha256(blobKey) + "-" + content sha256, so a copy is only
// ever served for the blob key it was stored under (blob keys are
// org-scoped: no content is shared across tenants) and only while the
// metadata row still names the same bytes. Writes land in tmp/ and are
// renamed into place only after the bytes hashed to the expected digest;
// reads verify the digest again while streaming and drop a file that fails.
//
// It is a cache: losing it costs S3 reads, never correctness. Eviction is
// least-recently-used, bounded by maxBytes and by a free-space floor on the
// filesystem.
type DiskTier struct {
	dir      string
	maxBytes int64
	minFree  float64

	mu      sync.Mutex
	entries map[string]*tierEntry          // file name -> entry
	byKey   map[string]map[string]struct{} // sha256(blobKey) -> file names
	total   int64
	// warnedFull is set once the free-space floor has been logged.
	warnedFull bool

	hits, misses, fills atomic.Int64
}

type tierEntry struct {
	keyHash string
	size    int64
	used    int64 // unix nanos
}

// errTierDigest is a tier file whose bytes no longer hash to its name.
var errTierDigest = errors.New("disk tier: content digest mismatch")

// DefaultDiskTierMinFree is the share of the filesystem the tier leaves free.
const DefaultDiskTierMinFree = 0.20

// NewDiskTier opens (creating) a tier rooted at dir, holding at most
// maxBytes. Files left by a previous process are indexed; partial writes in
// tmp/ are discarded.
func NewDiskTier(dir string, maxBytes int64) (*DiskTier, error) {
	if dir == "" || maxBytes <= 0 {
		return nil, errors.New("disk tier: a directory and a positive size are required")
	}
	tmp := filepath.Join(dir, "tmp")
	if err := os.RemoveAll(tmp); err != nil {
		return nil, fmt.Errorf("disk tier: clear tmp: %w", err)
	}
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return nil, fmt.Errorf("disk tier: %w", err)
	}
	t := &DiskTier{
		dir:      dir,
		maxBytes: maxBytes,
		minFree:  DefaultDiskTierMinFree,
		entries:  map[string]*tierEntry{},
		byKey:    map[string]map[string]struct{}{},
	}
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("disk tier: %w", err)
	}
	for _, de := range des {
		keyHash, _, ok := strings.Cut(de.Name(), "-")
		if de.IsDir() || !ok {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		t.index(de.Name(), keyHash, info.Size(), info.ModTime().UnixNano())
	}
	t.mu.Lock()
	t.evictLocked()
	t.mu.Unlock()
	return t, nil
}

// SetMinFree sets the share of the filesystem the tier leaves free (0..1).
// Below it the tier keeps nothing: a full disk is worse than S3 reads.
func (t *DiskTier) SetMinFree(f float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.minFree = min(max(f, 0), 1)
}

// Stats reports hits, misses and fills since start.
func (t *DiskTier) Stats() (hits, misses, fills int64) {
	return t.hits.Load(), t.misses.Load(), t.fills.Load()
}

func tierNames(blobKey, sha string) (keyHash, name string) {
	sum := sha256.Sum256([]byte(blobKey))
	keyHash = hex.EncodeToString(sum[:])
	return keyHash, keyHash + "-" + strings.ToLower(sha)
}

// open returns a reader over the tier copy of blobKey with digest sha, or
// false on a miss. The reader fails with errTierDigest, and removes the
// file, if the bytes do not hash to sha.
func (t *DiskTier) open(blobKey, sha string) (io.ReadCloser, bool) {
	keyHash, name := tierNames(blobKey, sha)
	f, err := os.Open(filepath.Join(t.dir, name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.forget(name)
		}
		t.misses.Add(1)
		return nil, false
	}
	t.mu.Lock()
	if e, ok := t.entries[name]; ok {
		e.used = time.Now().UnixNano()
	} else if info, err := f.Stat(); err == nil {
		t.mu.Unlock()
		t.index(name, keyHash, info.Size(), time.Now().UnixNano())
		t.mu.Lock()
	}
	t.mu.Unlock()
	t.hits.Add(1)
	return &verifyingReader{f: f, h: sha256.New(), want: strings.ToLower(sha), bad: func() { t.remove(name) }}, true
}

// openAt returns the tier copy positioned at offset, unverified (see
// CachedContent.OpenAt), or false on a miss.
func (t *DiskTier) openAt(blobKey, sha string, offset int64) (io.ReadCloser, bool) {
	_, name := tierNames(blobKey, sha)
	rc, err := openFileAt(filepath.Join(t.dir, name), offset)
	if err != nil {
		t.misses.Add(1)
		return nil, false
	}
	t.mu.Lock()
	if e, ok := t.entries[name]; ok {
		e.used = time.Now().UnixNano()
	}
	t.mu.Unlock()
	t.hits.Add(1)
	return rc, true
}

// fill wraps a blob-store reader so that, once it has been read to EOF and
// the bytes hashed to sha, they are kept in the tier. A partial read, a
// mismatch or a local write failure keeps nothing; the caller's read is
// unaffected either way.
func (t *DiskTier) fill(blobKey, sha string, src io.ReadCloser) io.ReadCloser {
	w := t.newWriter()
	if w == nil {
		return src
	}
	return &fillingReader{src: src, w: w, h: sha256.New(), commit: func(got string) {
		if strings.EqualFold(got, sha) {
			w.commit(blobKey, sha)
			return
		}
		w.abort()
	}}
}

// drop removes every tier copy of blobKey.
func (t *DiskTier) drop(blobKey string) {
	sum := sha256.Sum256([]byte(blobKey))
	keyHash := hex.EncodeToString(sum[:])
	t.mu.Lock()
	names := make([]string, 0, len(t.byKey[keyHash]))
	for n := range t.byKey[keyHash] {
		names = append(names, n)
	}
	t.mu.Unlock()
	for _, n := range names {
		t.remove(n)
	}
}

func (t *DiskTier) index(name, keyHash string, size, used int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if old, ok := t.entries[name]; ok {
		t.total -= old.size
	}
	t.entries[name] = &tierEntry{keyHash: keyHash, size: size, used: used}
	t.total += size
	if t.byKey[keyHash] == nil {
		t.byKey[keyHash] = map[string]struct{}{}
	}
	t.byKey[keyHash][name] = struct{}{}
}

func (t *DiskTier) forget(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.forgetLocked(name)
}

func (t *DiskTier) forgetLocked(name string) {
	e, ok := t.entries[name]
	if !ok {
		return
	}
	t.total -= e.size
	delete(t.entries, name)
	delete(t.byKey[e.keyHash], name)
	if len(t.byKey[e.keyHash]) == 0 {
		delete(t.byKey, e.keyHash)
	}
}

func (t *DiskTier) remove(name string) {
	t.forget(name)
	_ = os.Remove(filepath.Join(t.dir, name))
}

// evictLocked removes least-recently-used files until the tier is within
// maxBytes and the filesystem keeps minFree of its space free.
func (t *DiskTier) evictLocked() {
	free, known := diskFree(t.dir)
	if t.total <= t.maxBytes && (!known || free >= t.minFree) {
		return
	}
	names := make([]string, 0, len(t.entries))
	for n := range t.entries {
		names = append(names, n)
	}
	if known && free < t.minFree && !t.warnedFull {
		// Every file the tier holds is about to go: say so once, or a
		// full disk silently turns every cache hit back into an S3 read.
		t.warnedFull = true
		slog.Warn("disk tier: filesystem below its free-space floor; evicting, and keeping nothing until space frees",
			"dir", t.dir, "free", free, "min_free", t.minFree)
	}
	sort.Slice(names, func(i, j int) bool { return t.entries[names[i]].used < t.entries[names[j]].used })
	for _, n := range names {
		if t.total <= t.maxBytes*9/10 {
			if free, known := diskFree(t.dir); !known || free >= t.minFree {
				return
			}
		}
		t.forgetLocked(n)
		_ = os.Remove(filepath.Join(t.dir, n))
	}
}

// diskFree reads the free share of a filesystem; tests replace it.
var diskFree = diskFreeFraction

// tierWriter spools bytes into tmp/. Write never fails: a local disk error
// must not fail the blob-store write it shadows, so it just stops keeping
// bytes and the commit becomes an abort.
type tierWriter struct {
	t      *DiskTier
	f      *os.File
	failed bool
	done   bool
}

func (t *DiskTier) newWriter() *tierWriter {
	f, err := os.CreateTemp(filepath.Join(t.dir, "tmp"), "fill-*")
	if err != nil {
		return nil
	}
	return &tierWriter{t: t, f: f}
}

func (w *tierWriter) Write(p []byte) (int, error) {
	if w == nil || w.failed || w.done {
		return len(p), nil
	}
	if _, err := w.f.Write(p); err != nil {
		w.failed = true
	}
	return len(p), nil
}

// commit moves the spooled bytes into place as the copy of blobKey/sha.
// The caller has already checked they hash to sha.
func (w *tierWriter) commit(blobKey, sha string) {
	if w == nil || w.done {
		return
	}
	w.done = true
	if w.failed {
		w.discard()
		return
	}
	info, statErr := w.f.Stat()
	if err := w.f.Close(); err != nil || statErr != nil {
		_ = os.Remove(w.f.Name())
		return
	}
	keyHash, name := tierNames(blobKey, sha)
	if err := os.Rename(w.f.Name(), filepath.Join(w.t.dir, name)); err != nil {
		_ = os.Remove(w.f.Name())
		return
	}
	w.t.index(name, keyHash, info.Size(), time.Now().UnixNano())
	w.t.fills.Add(1)
	w.t.mu.Lock()
	w.t.evictLocked()
	w.t.mu.Unlock()
}

func (w *tierWriter) abort() {
	if w == nil || w.done {
		return
	}
	w.done = true
	w.discard()
}

func (w *tierWriter) discard() {
	_ = w.f.Close()
	_ = os.Remove(w.f.Name())
}

// fillingReader tees a blob-store read into a tierWriter and settles it at
// EOF (commit on a matching digest) or Close (abort if EOF never came).
type fillingReader struct {
	src    io.ReadCloser
	w      *tierWriter
	h      hash.Hash
	commit func(got string)
	ended  bool
}

func (r *fillingReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	if n > 0 {
		r.h.Write(p[:n])
		_, _ = r.w.Write(p[:n])
	}
	if errors.Is(err, io.EOF) && !r.ended {
		r.ended = true
		r.commit(hex.EncodeToString(r.h.Sum(nil)))
	}
	return n, err
}

func (r *fillingReader) Close() error {
	if !r.ended {
		r.ended = true
		r.w.abort()
	}
	return r.src.Close()
}

// verifyingReader streams a tier file and checks its digest at EOF.
type verifyingReader struct {
	f    *os.File
	h    hash.Hash
	want string
	bad  func()
	done bool
}

func (r *verifyingReader) Read(p []byte) (int, error) {
	n, err := r.f.Read(p)
	if n > 0 {
		r.h.Write(p[:n])
	}
	if errors.Is(err, io.EOF) && !r.done {
		r.done = true
		if hex.EncodeToString(r.h.Sum(nil)) != r.want {
			r.bad()
			return n, errTierDigest
		}
	}
	return n, err
}

func (r *verifyingReader) Close() error { return r.f.Close() }

// DefaultDiskTierMaxMB is the tier's size when CHAINSAW_DISK_TIER_MAX_MB is
// unset.
const DefaultDiskTierMaxMB = 10240

// SharedDiskTier is the process-wide tier configured by
// CHAINSAW_DISK_TIER_DIR (unset: none) and CHAINSAW_DISK_TIER_MAX_MB. Every
// repository shares it, so the byte cap is one budget for the process.
var SharedDiskTier = sync.OnceValue(func() *DiskTier {
	dir := strings.TrimSpace(os.Getenv("CHAINSAW_DISK_TIER_DIR"))
	if dir == "" {
		return nil
	}
	mb := int64(DefaultDiskTierMaxMB)
	if v := strings.TrimSpace(os.Getenv("CHAINSAW_DISK_TIER_MAX_MB")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			mb = n
		}
	}
	t, err := NewDiskTier(dir, mb<<20)
	if err != nil {
		slog.Warn("disk tier disabled", "dir", dir, "error", err)
		return nil
	}
	if v := strings.TrimSpace(os.Getenv("CHAINSAW_DISK_TIER_MIN_FREE_PCT")); v != "" {
		if pct, err := strconv.ParseFloat(v, 64); err == nil && pct >= 0 && pct <= 100 {
			t.SetMinFree(pct / 100)
		}
	}
	slog.Info("disk tier enabled", "dir", dir, "max_mb", mb, "indexed_bytes", t.total)
	return t
})
