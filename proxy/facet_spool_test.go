package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/chain305/chainsaw-core/blobstore"
	"github.com/chain305/chainsaw-core/storage"
)

// failingWrites is a blob store whose writes are throttled mid-stream.
type failingWrites struct{ blobstore.BlobStore }

func (failingWrites) WriteForOrg(_, _, _ string, src io.Reader) (*blobstore.Blob, error) {
	_, _ = io.CopyN(io.Discard, src, 2)
	return nil, errors.New("SlowDown: throttled")
}

// J.2 C: a proxy fill whose blob store write fails is served from the local
// disk tier instead of failing the install, and is not recorded as cached.
// Without a tier it still fails, as before.
func TestFillIsServedFromDiskTierWhenStoreWriteFails(t *testing.T) {
	const body = "upstream tarball"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL + "/")
	fs, err := blobstore.NewFileBlobStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	newFacet := func(tier *storage.DiskTier) (Facet, *storage.LocalStorage) {
		ls := storage.NewLocalStorage("r", failingWrites{fs})
		ls.SetDiskTier(tier)
		return NewFacet(FacetConfig{RepoName: "r", Format: "npm", Storage: ls, Resolver: tgzResolver{},
			Remote: RemoteDefinition{BaseURL: base, Client: srv.Client()}, Logger: discardLogger()}), ls
	}
	ctx := context.Background()
	req := &Request{LogicalPath: "pkg/-/pkg-1.0.0.tgz", Method: http.MethodGet, Header: http.Header{}}

	if f, _ := newFacet(nil); true {
		if _, err := f.Get(ctx, req); err == nil {
			t.Fatal("without a disk tier a failed store write must still fail the fill")
		}
	}

	tier, err := storage.NewDiskTier(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	f, ls := newFacet(tier)
	resp, err := f.Get(ctx, req)
	if err != nil {
		t.Fatalf("fill with a disk tier: %v", err)
	}
	if got := readAll(t, resp.Content); got != body {
		t.Fatalf("served %q, want the upstream bytes", got)
	}
	if _, err := ls.Get(ctx, req.LogicalPath); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("a spooled fill was recorded as cached: %v", err)
	}
}
