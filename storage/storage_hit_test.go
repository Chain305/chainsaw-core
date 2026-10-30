package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"testing"

	"github.com/chain305/chainsaw-core/blobstore"
)

// statCountingStore counts Stat calls; on S3 each one is a HEAD.
type statCountingStore struct {
	blobstore.BlobStore
	stats atomic.Int32
}

func (s *statCountingStore) Stat(key string) (os.FileInfo, error) {
	s.stats.Add(1)
	return s.BlobStore.Stat(key)
}

func newHitStorage(t *testing.T) (*LocalStorage, *statCountingStore, string) {
	t.Helper()
	dir := t.TempDir()
	fs, err := blobstore.NewFileBlobStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	cs := &statCountingStore{BlobStore: fs}
	return NewLocalStorage("npmjs", cs), cs, dir
}

// A cache hit used to HEAD the blob before reading its metadata row. On the
// Contabo S3 backend that was 256 ms p50 per hit and the first call to be
// throttled. The metadata row decides existence now.
func TestGetDoesNotStatTheBlob(t *testing.T) {
	ls, cs, _ := newHitStorage(t)
	ctx := WithOrg(context.Background(), "org-a")
	if _, err := ls.Put(ctx, "pkg/-/pkg-1.0.0.tgz", bytes.NewReader([]byte("x")), ContentMetadata{}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := ls.Get(ctx, "pkg/-/pkg-1.0.0.tgz"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ls.UpdateMetadata(ctx, "pkg/-/pkg-1.0.0.tgz", ContentMetadata{}); err != nil {
		t.Fatal(err)
	}
	if n := cs.stats.Load(); n != 0 {
		t.Fatalf("cache hits made %d blob Stat calls, want 0", n)
	}
	if _, err := ls.Get(ctx, "pkg/-/missing-1.0.0.tgz"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing path: %v, want ErrNotFound", err)
	}
}

// If the row outlives its blob (removed out of band, or by another replica
// whose cache this one does not share), the first failed Open drops the row
// so the next request refetches instead of failing forever.
func TestOpenOnMissingBlobDropsTheRow(t *testing.T) {
	ls, _, dir := newHitStorage(t)
	ctx := WithOrg(context.Background(), "org-a")
	content, err := ls.Put(ctx, "pkg/-/pkg-1.0.0.tgz", bytes.NewReader([]byte("x")), ContentMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(content.path); err != nil {
		t.Fatalf("remove blob under %s: %v", dir, err)
	}
	got, err := ls.Get(ctx, "pkg/-/pkg-1.0.0.tgz")
	if err != nil {
		t.Fatalf("row still present, Get should succeed: %v", err)
	}
	if rc, err := got.Open(); err == nil {
		_, _ = io.Copy(io.Discard, rc)
		rc.Close()
		t.Fatal("Open of a removed blob succeeded")
	}
	if _, err := ls.Get(ctx, "pkg/-/pkg-1.0.0.tgz"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after a failed Open: %v, want ErrNotFound so the next request refetches", err)
	}
}
