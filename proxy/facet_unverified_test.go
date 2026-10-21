package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/blobstore"
	"github.com/chain305/chainsaw-core/formats/common"
	"github.com/chain305/chainsaw-core/storage"
)

// tgzResolver describes only .tgz paths as artifacts.
type tgzResolver struct{}

func (tgzResolver) Describe(p string) (common.PackageCoordinate, bool) {
	if !strings.HasSuffix(p, ".tgz") {
		return common.PackageCoordinate{}, false
	}
	return common.PackageCoordinate{Name: "pkg", Version: "1.0.0", Format: "npm"}, true
}

func (tgzResolver) Format() string { return "npm" }

// An artifact the facet fetches is stored unverified, and a cache hit on
// it is not reported as one (FromCache false) until the caller clears the
// mark after verifying it. Before, the first fetch's bytes were a plain
// cache hit for every request that arrived while it was being verified.
// A path the resolver does not describe as an artifact is not marked.
func TestFetchedArtifactIsUnverifiedUntilCommitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("bytes"))
	}))
	t.Cleanup(srv.Close)
	base, err := url.Parse(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	bs, err := blobstore.NewFileBlobStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ls := storage.NewLocalStorage("r", bs)
	f := NewFacet(FacetConfig{RepoName: "r", Format: "npm", Storage: ls, Resolver: tgzResolver{},
		Remote: RemoteDefinition{BaseURL: base, Client: srv.Client()}, Logger: discardLogger()})
	ctx := context.Background()
	get := func(path string) *Response {
		t.Helper()
		resp, err := f.Get(ctx, &Request{LogicalPath: path, Method: http.MethodGet, Header: http.Header{}})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	const artifact = "pkg/-/pkg-1.0.0.tgz"
	if resp := get(artifact); resp.FromCache || !resp.Content.Metadata.Unverified {
		t.Fatalf("fetched artifact: FromCache=%v Unverified=%v, want false/true", resp.FromCache, resp.Content.Metadata.Unverified)
	}
	hit := get(artifact)
	if hit.FromCache {
		t.Fatal("unverified artifact answered as a cache hit")
	}
	meta := hit.Content.Metadata
	meta.Unverified = false
	if _, err := ls.UpdateMetadata(ctx, artifact, meta); err != nil {
		t.Fatal(err)
	}
	if !get(artifact).FromCache {
		t.Fatal("committed artifact not answered as a cache hit")
	}

	const document = "pkg"
	get(document)
	if !get(document).FromCache {
		t.Fatal("a non-artifact path was marked unverified")
	}
}
