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

type stubInternalChecker struct {
	internal bool
	err      error
}

func (s stubInternalChecker) IsInternalVersion(_, _, _, _ string) bool {
	return s.internal && s.err == nil
}

func (s stubInternalChecker) IsInternalVersionErr(_, _, _, _ string) (bool, error) {
	return s.internal, s.err
}

func newInternalFacet(t *testing.T, checker InternalPackageChecker) (*facet, *storage.LocalStorage) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "public namesake bytes")
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
		Remote: RemoteDefinition{BaseURL: base, Client: srv.Client()}, Logger: discardLogger(),
		InternalChecker: checker})
	return f.(*facet), ls
}

// The internal-package override decides whether upstream bytes may be stored
// for a name/version. Both of its failure modes used to fall through to the
// normal store path, which fetched, stored and served the PUBLIC package for
// a private name: dependency confusion on a DB or storage error.
func TestInternalOverrideFailsClosed(t *testing.T) {
	const artifact = "acme-internal/-/acme-internal-1.0.0.tgz"
	get := func(f *facet) error {
		_, err := f.Get(context.Background(), &Request{LogicalPath: artifact, Method: http.MethodGet})
		return err
	}

	t.Run("lookup error", func(t *testing.T) {
		f, ls := newInternalFacet(t, stubInternalChecker{err: errors.New("db down")})
		if err := get(f); err == nil {
			t.Fatal("internal lookup error must fail the fetch, not fall through to upstream")
		}
		if _, err := ls.Get(context.Background(), artifact); err == nil {
			t.Fatal("upstream bytes were stored for a name whose internal status is unknown")
		}
	})

	t.Run("internal but stored copy unreadable", func(t *testing.T) {
		f, ls := newInternalFacet(t, stubInternalChecker{internal: true})
		if err := get(f); err == nil {
			t.Fatal("a published internal version with no readable copy must fail, not serve the public namesake")
		}
		if _, err := ls.Get(context.Background(), artifact); err == nil {
			t.Fatal("public bytes were stored over an internal version")
		}
	})

	t.Run("not internal", func(t *testing.T) {
		f, _ := newInternalFacet(t, stubInternalChecker{})
		if err := get(f); err != nil {
			t.Fatalf("a public package must still be fetched: %v", err)
		}
	})
}
