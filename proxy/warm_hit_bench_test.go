package proxy

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/blobstore"
	"github.com/chain305/chainsaw-core/storage"
)

// slowBlobs adds a fixed delay to every blob-store round trip, standing in
// for the remote object store (Contabo measured 256-668 ms p50 per op; 2 ms
// here keeps the benchmark fast while preserving the ratio).
type slowBlobs struct {
	blobstore.BlobStore
	delay time.Duration
}

func (s slowBlobs) Stat(k string) (os.FileInfo, error) {
	time.Sleep(s.delay)
	return s.BlobStore.Stat(k)
}

func (s slowBlobs) Open(k string) (io.ReadCloser, error) {
	time.Sleep(s.delay)
	return s.BlobStore.Open(k)
}

func (s slowBlobs) WriteForOrg(org, repo, p string, r io.Reader) (*blobstore.Blob, error) {
	time.Sleep(s.delay)
	return s.BlobStore.WriteForOrg(org, repo, p, r)
}

// BenchmarkWarmPackumentHit is one warm packument cache hit as the facet
// serves it: storage lookup, transform for the request, open and read the
// body to serve. Run against the pre-change code for the comparison in
// REPORTS.md §K.
func BenchmarkWarmPackumentHit(b *testing.B) {
	fs, err := blobstore.NewFileBlobStore(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	ls := storage.NewLocalStorage("r", slowBlobs{BlobStore: fs, delay: 2 * time.Millisecond})
	f := NewFacet(FacetConfig{RepoName: "r", Format: "npm", Storage: ls, Rewrite: &hostRewriter{}, Logger: discardLogger()}).(*facet)
	body := `{"versions":{` + strings.Repeat(`"1.0.0":{"dist":{"tarball":"BASE/x.tgz"}},`, 200) + `"9.9.9":{}}}`
	if _, err := ls.Put(context.Background(), "pkg", strings.NewReader(body), storage.ContentMetadata{ContentType: "application/json"}); err != nil {
		b.Fatal(err)
	}
	ctx := WithBaseURL(context.Background(), "https://chain305.com/chainproxy/repository/@acme/npmjs")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		content, err := ls.Get(ctx, "pkg")
		if err != nil {
			b.Fatal(err)
		}
		resp, err := f.respondFromCache(ctx, "pkg", content, false)
		if err != nil {
			b.Fatal(err)
		}
		rc, err := resp.Content.Open()
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, rc)
		rc.Close()
	}
}
