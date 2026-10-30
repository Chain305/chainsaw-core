package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/chain305/chainsaw-core/blobstore"
	"github.com/chain305/chainsaw-core/storage"
)

// hostRewriter stands in for the npm/PyPI transformers: it rewrites a
// placeholder to the request's base URL.
type hostRewriter struct{ calls atomic.Int32 }

func (*hostRewriter) ShouldTransform(string, *http.Response) bool { return true }
func (h *hostRewriter) Transform(ctx context.Context, _ string, body []byte) ([]byte, error) {
	h.calls.Add(1)
	return bytes.ReplaceAll(body, []byte("BASE"), []byte(BaseURLFromContext(ctx))), nil
}

// countingStorage counts writes to, and blob reads through, the facet's store.
type countingStorage struct {
	*storage.LocalStorage
	puts atomic.Int32
}

func (c *countingStorage) Put(ctx context.Context, p string, r io.Reader, m storage.ContentMetadata) (*storage.CachedContent, error) {
	c.puts.Add(1)
	return c.LocalStorage.Put(ctx, p, r, m)
}

type openCountingBlobs struct {
	blobstore.BlobStore
	opens atomic.Int32
}

func (o *openCountingBlobs) Open(key string) (io.ReadCloser, error) {
	o.opens.Add(1)
	return o.BlobStore.Open(key)
}

// A warm packument hit used to re-read the stored body from the blob store,
// re-transform it, and write it back whenever the requester's host differed
// from the last one. It must now write nothing, and a repeated hit from the
// same context must not touch the blob store at all.
func TestCachedRewriteIsMemoisedAndNeverWrittenBack(t *testing.T) {
	fs, err := blobstore.NewFileBlobStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	blobs := &openCountingBlobs{BlobStore: fs}
	cs := &countingStorage{LocalStorage: storage.NewLocalStorage("r", blobs)}
	rw := &hostRewriter{}
	f := NewFacet(FacetConfig{RepoName: "r", Format: "npm", Storage: cs, Rewrite: rw, Logger: discardLogger()}).(*facet)

	if _, err := cs.LocalStorage.Put(context.Background(), "pkg", strings.NewReader(`{"tarball":"BASE/pkg.tgz"}`),
		storage.ContentMetadata{ContentType: "application/json"}); err != nil {
		t.Fatal(err)
	}
	stored, err := cs.Get(context.Background(), "pkg")
	if err != nil {
		t.Fatal(err)
	}

	serve := func(base string) string {
		ctx := WithBaseURL(context.Background(), base)
		resp, err := f.respondFromCache(ctx, "pkg", stored, false)
		if err != nil {
			t.Fatal(err)
		}
		rc, err := resp.Content.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		b, _ := io.ReadAll(rc)
		return string(b)
	}

	a1 := serve("https://a.example")
	b1 := serve("https://b.example")
	if !strings.Contains(a1, "https://a.example/pkg.tgz") || !strings.Contains(b1, "https://b.example/pkg.tgz") {
		t.Fatalf("each host must get its own rewrite: a=%q b=%q", a1, b1)
	}
	opensAfterFirst := blobs.opens.Load()
	callsAfterFirst := rw.calls.Load()
	if a2 := serve("https://a.example"); a2 != a1 {
		t.Fatalf("memoised rewrite differs: %q vs %q", a2, a1)
	}
	if got := cs.puts.Load(); got != 0 {
		t.Fatalf("cache hits wrote to the blob store %d times, want 0", got)
	}
	if blobs.opens.Load() != opensAfterFirst || rw.calls.Load() != callsAfterFirst {
		t.Fatalf("a repeated hit re-read (%d->%d opens) or re-transformed (%d->%d), want neither",
			opensAfterFirst, blobs.opens.Load(), callsAfterFirst, rw.calls.Load())
	}
}

func TestByteLRUEvictsByBytes(t *testing.T) {
	c := newByteLRU(10)
	c.put(rewriteMemoEntry{key: "a", data: make([]byte, 6)})
	c.put(rewriteMemoEntry{key: "b", data: make([]byte, 6)})
	if _, ok := c.get("a"); ok {
		t.Fatal("oldest entry should be evicted once the byte cap is exceeded")
	}
	if _, ok := c.get("b"); !ok {
		t.Fatal("newest entry should remain")
	}
	c.put(rewriteMemoEntry{key: "huge", data: make([]byte, 11)})
	if _, ok := c.get("huge"); ok {
		t.Fatal("an entry larger than the cap must not be stored")
	}
	if off := newByteLRU(0); func() bool { off.put(rewriteMemoEntry{key: "x"}); _, ok := off.get("x"); return ok }() {
		t.Fatal("a zero cap disables the memo")
	}
}
