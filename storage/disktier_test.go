package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/chain305/chainsaw-core/blobstore"
)

// openCountingStore counts blob-store reads; on S3 each is a GET. failWrite
// makes WriteForOrg read part of its input and then fail, like an S3 upload
// throttled mid-stream.
type openCountingStore struct {
	blobstore.BlobStore
	opens     atomic.Int32
	failWrite bool
}

func (s *openCountingStore) Open(key string) (io.ReadCloser, error) {
	s.opens.Add(1)
	return s.BlobStore.Open(key)
}

func (s *openCountingStore) WriteForOrg(orgID, repo, logicalPath string, src io.Reader) (*blobstore.Blob, error) {
	if s.failWrite {
		_, _ = io.CopyN(io.Discard, src, 3)
		return nil, errors.New("SlowDown: throttled")
	}
	return s.BlobStore.WriteForOrg(orgID, repo, logicalPath, src)
}

// plentyFree makes the free-space floor hold whatever the test machine's
// disk looks like.
func plentyFree(t *testing.T) {
	t.Helper()
	saved := diskFree
	diskFree = func(string) (float64, bool) { return 0.9, true }
	t.Cleanup(func() { diskFree = saved })
}

func newTierStorage(t *testing.T, maxBytes int64) (*LocalStorage, *openCountingStore, *DiskTier) {
	t.Helper()
	plentyFree(t)
	fs, err := blobstore.NewFileBlobStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := &openCountingStore{BlobStore: fs}
	tier, err := NewDiskTier(t.TempDir(), maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	s := NewLocalStorage("npmjs", store)
	s.SetDiskTier(tier)
	return s, store, tier
}

func readAll(t *testing.T, c *CachedContent) ([]byte, error) {
	t.Helper()
	rc, err := c.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func tierFiles(t *testing.T, tier *DiskTier) []string {
	t.Helper()
	des, err := os.ReadDir(tier.dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, de := range des {
		if !de.IsDir() {
			out = append(out, de.Name())
		}
	}
	return out
}

// Put writes through to the tier, so a cache hit reads local disk and the
// blob store is not asked at all.
func TestDiskTierPutWritesThroughAndHitsSkipTheStore(t *testing.T) {
	s, store, _ := newTierStorage(t, 1<<20)
	ctx := context.Background()
	body := []byte("package bytes v1")
	if _, err := s.Put(ctx, "a/-/a-1.tgz", bytes.NewReader(body), ContentMetadata{}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		c, err := s.Get(ctx, "a/-/a-1.tgz")
		if err != nil {
			t.Fatal(err)
		}
		if got, err := readAll(t, c); err != nil || !bytes.Equal(got, body) {
			t.Fatalf("hit %d: %q %v", i, got, err)
		}
	}
	if n := store.opens.Load(); n != 0 {
		t.Fatalf("blob store read %d times for tier hits, want 0", n)
	}
}

// A blob stored before the tier existed is copied in on its first full
// read; a read that stops early keeps nothing.
func TestDiskTierFillsOnFullReadOnly(t *testing.T) {
	s, store, tier := newTierStorage(t, 1<<20)
	ctx := context.Background()
	s.SetDiskTier(nil)
	body := []byte(strings.Repeat("x", 4096))
	if _, err := s.Put(ctx, "a/-/a-1.tgz", bytes.NewReader(body), ContentMetadata{}); err != nil {
		t.Fatal(err)
	}
	s.SetDiskTier(tier)
	s.metaCache.Invalidate(mustBlobPath(t, s, "a/-/a-1.tgz")) // content() captures the tier

	c, _ := s.Get(ctx, "a/-/a-1.tgz")
	rc, err := c.Open()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadFull(rc, make([]byte, 10))
	_ = rc.Close()
	if files := tierFiles(t, tier); len(files) != 0 {
		t.Fatalf("a partial read filled the tier: %v", files)
	}
	if got, err := readAll(t, c); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("full read: %v", err)
	}
	opens := store.opens.Load()
	if got, err := readAll(t, c); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("tier read: %v", err)
	}
	if store.opens.Load() != opens {
		t.Fatal("the read after a full fill went to the blob store")
	}
}

// A tier file whose bytes changed fails the read and is removed; the next
// read goes back to the blob store.
func TestDiskTierRejectsCorruptedCopy(t *testing.T) {
	s, store, tier := newTierStorage(t, 1<<20)
	ctx := context.Background()
	body := []byte("the real bytes")
	if _, err := s.Put(ctx, "a/-/a-1.tgz", bytes.NewReader(body), ContentMetadata{}); err != nil {
		t.Fatal(err)
	}
	files := tierFiles(t, tier)
	if len(files) != 1 {
		t.Fatalf("tier files = %v, want 1", files)
	}
	if err := os.WriteFile(filepath.Join(tier.dir, files[0]), []byte("tampered bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := s.Get(ctx, "a/-/a-1.tgz")
	if _, err := readAll(t, c); !errors.Is(err, errTierDigest) {
		t.Fatalf("corrupted tier read = %v, want errTierDigest", err)
	}
	if left := tierFiles(t, tier); len(left) != 0 {
		t.Fatalf("corrupted file kept: %v", left)
	}
	if got, err := readAll(t, c); err != nil || !bytes.Equal(got, body) || store.opens.Load() == 0 {
		t.Fatalf("after rejecting the copy: %q %v opens=%d", got, err, store.opens.Load())
	}
}

// Remove (quarantine purge) erases the tier copy too, and the same bytes
// under another blob key are a separate file: nothing is shared by content.
func TestDiskTierRemoveAndKeyIsolation(t *testing.T) {
	s, _, tier := newTierStorage(t, 1<<20)
	ctx := context.Background()
	body := []byte("same bytes")
	for _, p := range []string{"a/-/a-1.tgz", "b/-/b-1.tgz"} {
		if _, err := s.Put(ctx, p, bytes.NewReader(body), ContentMetadata{}); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(tierFiles(t, tier)); n != 2 {
		t.Fatalf("two keys with the same bytes made %d tier files, want 2", n)
	}
	if err := s.Remove(ctx, "a/-/a-1.tgz"); err != nil {
		t.Fatal(err)
	}
	if n := len(tierFiles(t, tier)); n != 1 {
		t.Fatalf("after Remove: %d tier files, want 1", n)
	}
	if _, err := s.Get(ctx, "a/-/a-1.tgz"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed artifact still found: %v", err)
	}
}

// The tier stays within its byte cap, dropping the least recently used.
func TestDiskTierEvictsToItsCap(t *testing.T) {
	s, _, tier := newTierStorage(t, 3000)
	ctx := context.Background()
	for i, p := range []string{"a", "b", "c", "d", "e"} {
		body := bytes.Repeat([]byte{byte('a' + i)}, 1000)
		if _, err := s.Put(ctx, p+"/-/x.tgz", bytes.NewReader(body), ContentMetadata{}); err != nil {
			t.Fatal(err)
		}
	}
	tier.mu.Lock()
	total := tier.total
	tier.mu.Unlock()
	if total > 3000 {
		t.Fatalf("tier holds %d bytes over its 3000-byte cap", total)
	}
	var size int64
	for _, f := range tierFiles(t, tier) {
		info, _ := os.Stat(filepath.Join(tier.dir, f))
		size += info.Size()
	}
	if size != total {
		t.Fatalf("index says %d bytes, disk holds %d", total, size)
	}
}

// A restarted process indexes the files it finds and discards partial ones.
func TestDiskTierReindexesOnRestart(t *testing.T) {
	s, _, tier := newTierStorage(t, 1<<20)
	if _, err := s.Put(context.Background(), "a/-/a-1.tgz", bytes.NewReader([]byte("kept")), ContentMetadata{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tier.dir, "tmp", "fill-partial"), []byte("half"), 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := NewDiskTier(tier.dir, 1<<20) // plentyFree still applies
	if err != nil {
		t.Fatal(err)
	}
	if again.total != 4 || len(again.entries) != 1 {
		t.Fatalf("reindexed %d entries / %d bytes, want 1 / 4", len(again.entries), again.total)
	}
	if des, _ := os.ReadDir(filepath.Join(tier.dir, "tmp")); len(des) != 0 {
		t.Fatal("a partial write survived the restart")
	}
}

// A proxy fill whose blob store write fails is served from the tier with
// the exact upstream bytes and no metadata row; a strict Put still fails.
func TestPutOrSpoolServesFromTierWhenStoreWriteFails(t *testing.T) {
	s, store, _ := newTierStorage(t, 1<<20)
	store.failWrite = true
	ctx := context.Background()
	body := []byte("upstream tarball bytes")

	if _, err := s.Put(ctx, "a/-/a-1.tgz", bytes.NewReader(body), ContentMetadata{}); err == nil {
		t.Fatal("strict Put succeeded on a failed blob store write")
	}
	c, stored, err := s.PutOrSpool(ctx, "a/-/a-1.tgz", bytes.NewReader(body), ContentMetadata{PackageName: "a"})
	if err != nil || stored {
		t.Fatalf("PutOrSpool: stored=%v err=%v, want false nil", stored, err)
	}
	if got, err := readAll(t, c); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("spooled content = %q %v, want the upstream bytes", got, err)
	}
	if c.Metadata.Size != int64(len(body)) || c.Metadata.PackageName != "a" {
		t.Fatalf("spooled metadata = %+v", c.Metadata)
	}
	if _, err := s.Get(ctx, "a/-/a-1.tgz"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a spooled fill wrote a metadata row: %v", err)
	}
}

func mustBlobPath(t *testing.T, s *LocalStorage, logicalPath string) string {
	t.Helper()
	p, err := s.blobStore.BlobPathForOrg(OrgFromContext(context.Background()), s.repo, logicalPath)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Under the free-space floor the tier keeps nothing, whatever its cap.
func TestDiskTierRespectsFreeSpaceFloor(t *testing.T) {
	s, _, tier := newTierStorage(t, 1<<30)
	diskFree = func(string) (float64, bool) { return 0.05, true }
	if _, err := s.Put(context.Background(), "a/-/a-1.tgz", bytes.NewReader([]byte("bytes")), ContentMetadata{}); err != nil {
		t.Fatal(err)
	}
	if files := tierFiles(t, tier); len(files) != 0 {
		t.Fatalf("tier kept %v with 5%% of the disk free", files)
	}
}

// rangeCountingStore records which read the content asked the store for.
type rangeCountingStore struct {
	*openCountingStore
	ranged atomic.Int32
}

func (s *rangeCountingStore) OpenRange(key string, offset int64) (io.ReadCloser, error) {
	s.ranged.Add(1)
	return s.BlobStore.(blobstore.RangeOpener).OpenRange(key, offset)
}

// OpenAt starts the read at the offset: a tier copy is seeked without
// asking the store, a store that supports ranges is asked for one, and an
// in-memory or spooled body is sliced (J.2 D).
func TestOpenAtStartsAtTheOffset(t *testing.T) {
	s, store, tier := newTierStorage(t, 1<<20)
	ctx := context.Background()
	body := []byte("0123456789abcdef")
	if _, err := s.Put(ctx, "a/-/a-1.tgz", bytes.NewReader(body), ContentMetadata{}); err != nil {
		t.Fatal(err)
	}
	read := func(c *CachedContent, off int64) string {
		t.Helper()
		rc, err := c.OpenAt(off)
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		b, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read at %d: %v", off, err)
		}
		return string(b)
	}
	c, _ := s.Get(ctx, "a/-/a-1.tgz")
	if got := read(c, 10); got != "abcdef" || store.opens.Load() != 0 {
		t.Fatalf("tier hit at 10 = %q with %d store opens, want abcdef and 0", got, store.opens.Load())
	}
	// The tier copy is seeked, not read from the start: a changed prefix is
	// not seen by a ranged read (only a full read can check the digest).
	files := tierFiles(t, tier)
	path := filepath.Join(tier.dir, files[0])
	raw, _ := os.ReadFile(path)
	raw[0] = 'X'
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := read(c, 10); got != "abcdef" {
		t.Fatalf("seeked tier read at 10 = %q, want abcdef", got)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	rs := &rangeCountingStore{openCountingStore: store}
	s2 := NewLocalStorage("npmjs", rs)
	if _, err := s2.Put(ctx, "b/-/b-1.tgz", bytes.NewReader(body), ContentMetadata{}); err != nil {
		t.Fatal(err)
	}
	c2, _ := s2.Get(ctx, "b/-/b-1.tgz")
	opens := store.opens.Load()
	if got := read(c2, 4); got != "456789abcdef" || rs.ranged.Load() != 1 || store.opens.Load() != opens {
		t.Fatalf("store read at 4 = %q, ranged=%d, whole opens +%d; want one ranged read", got, rs.ranged.Load(), store.opens.Load()-opens)
	}

	if got := read(NewInMemoryContent(ContentMetadata{}, body), 14); got != "ef" {
		t.Fatalf("in-memory at 14 = %q", got)
	}
	store.failWrite = true
	spooled, _, err := s.PutOrSpool(ctx, "c/-/c-1.tgz", bytes.NewReader(body), ContentMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	if got := read(spooled, 15); got != "f" {
		t.Fatalf("spool at 15 = %q", got)
	}
}

// A request's blob-store traffic is counted for its log line: a Put and a
// store read count, a disk-tier hit does not (J.2 A1).
func TestBlobOpsCountsStoreTrafficOnly(t *testing.T) {
	s, _, tier := newTierStorage(t, 1<<20)
	ctx, ops := WithBlobOps(context.Background())
	if _, err := s.Put(ctx, "a/-/a-1.tgz", bytes.NewReader([]byte("bytes")), ContentMetadata{}); err != nil {
		t.Fatal(err)
	}
	c, _ := s.Get(ctx, "a/-/a-1.tgz")
	if _, err := readAll(t, c); err != nil {
		t.Fatal(err)
	}
	if ops.String() != "0/1" {
		t.Fatalf("Put + tier hit = %s, want 0/1", ops.String())
	}
	s.SetDiskTier(nil)
	c, _ = s.Get(ctx, "a/-/a-1.tgz")
	if _, err := readAll(t, c); err != nil {
		t.Fatal(err)
	}
	if ops.String() != "1/1" {
		t.Fatalf("after a store read = %s, want 1/1", ops.String())
	}
	_ = tier
}
