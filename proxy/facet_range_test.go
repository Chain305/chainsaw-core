package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/blobstore"
	"github.com/chain305/chainsaw-core/storage"
)

const rangeTestBody = "0123456789abcdefghij"

// newRangeFacet wires a facet over real local storage against an upstream
// that honours Range the way registries and CDNs do: 206 with the slice.
func newRangeFacet(t *testing.T, handler http.HandlerFunc) (*facet, *storage.LocalStorage) {
	t.Helper()
	srv := httptest.NewServer(handler)
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
	return f.(*facet), ls
}

func readAll(t *testing.T, c *storage.CachedContent) string {
	t.Helper()
	rc, err := c.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A client Range must never reach upstream. The facet stores whole objects;
// a forwarded Range made upstream answer 206, handleUpstreamStatus let it
// through (206 < 400), and storeUpstream cached the slice AS the artifact,
// for every later request and for the enforcement scan.
//
// Verified by deletion: removing header.Del("Range") in Get fails this with
// upstream Range "bytes=0-3" and a 4-byte cached artifact.
func TestClientRangeIsNotForwardedUpstream(t *testing.T) {
	var sawRange []string
	f, ls := newRangeFacet(t, func(w http.ResponseWriter, r *http.Request) {
		rng := r.Header.Get("Range")
		sawRange = append(sawRange, rng)
		if rng == "bytes=0-3" {
			w.Header().Set("Content-Range", "bytes 0-3/"+strconv.Itoa(len(rangeTestBody)))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = io.WriteString(w, rangeTestBody[:4])
			return
		}
		_, _ = io.WriteString(w, rangeTestBody)
	})

	const artifact = "pkg/-/pkg-1.0.0.tgz"
	resp, err := f.Get(context.Background(), &Request{
		LogicalPath: artifact,
		Method:      http.MethodGet,
		Header:      http.Header{"Range": {"bytes=0-3"}, "If-Range": {`"etag"`}},
	})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(sawRange) != 1 || sawRange[0] != "" {
		t.Fatalf("upstream saw Range %q, want one fetch with no Range", sawRange)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 for the whole object", resp.StatusCode)
	}
	cached, err := ls.Get(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, cached); got != rangeTestBody {
		t.Fatalf("cached artifact = %q, want the whole object %q", got, rangeTestBody)
	}
}

// An upstream that answers 206 to a whole-object fetch is refused, not
// cached: the second line of defence behind stripping Range.
//
// Verified by deletion: removing the StatusPartialContent branch in
// handleUpstreamStatus fails this with a cached 4-byte artifact.
func TestUpstreamPartialContentIsNotCached(t *testing.T) {
	f, ls := newRangeFacet(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Range", "bytes 0-3/"+strconv.Itoa(len(rangeTestBody)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, rangeTestBody[:4])
	})

	const artifact = "pkg/-/pkg-1.0.0.tgz"
	resp, err := f.Get(context.Background(), &Request{LogicalPath: artifact, Method: http.MethodGet, Header: http.Header{}})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway || resp.Content != nil {
		t.Fatalf("status = %d content=%v, want 502 with no content", resp.StatusCode, resp.Content != nil)
	}
	if _, err := ls.Get(context.Background(), artifact); err == nil {
		t.Fatal("a 206 from upstream was cached as the artifact")
	} else if !strings.Contains(err.Error(), "not found") && err != storage.ErrNotFound {
		t.Fatalf("unexpected storage error: %v", err)
	}
}
