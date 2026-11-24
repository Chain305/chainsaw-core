package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/chain305/chainsaw-core/blobstore"
	"github.com/chain305/chainsaw-core/storage"
)

// TestSecurityGuard_RemoteURLIsLiteral — pentest #9/#23/#29: the decision
// judges the logical path as written, so the fetch may only go to that exact
// path under the (post-mapper) base. A dot segment that ResolveReference
// would remove must fail the fetch instead of silently fetching a different
// coordinate.
func TestSecurityGuard_RemoteURLIsLiteral(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		_, _ = w.Write([]byte("bytes"))
	}))
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL + "/npm/")
	fs, err := blobstore.NewFileBlobStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// The mapper moves some paths to another base, as pip's and composer's do.
	mapper := func(lp string, b *url.URL) *RemoteURLMapping {
		if rest, ok := strings.CutPrefix(lp, "mapped/"); ok {
			nb, _ := url.Parse(srv.URL + "/other/base")
			return &RemoteURLMapping{Base: nb, LogicalPath: rest}
		}
		return nil
	}
	f := NewFacet(FacetConfig{RepoName: "r", Format: "npm", Storage: storage.NewLocalStorage("r", fs), Resolver: tgzResolver{},
		Remote: RemoteDefinition{BaseURL: base, Client: srv.Client()}, Logger: discardLogger(), Mapper: mapper})
	get := func(lp string) error {
		_, err := f.Get(context.Background(), &Request{LogicalPath: lp, Method: http.MethodGet, Header: http.Header{}})
		return err
	}
	take := func() []string { mu.Lock(); defer mu.Unlock(); s := seen; seen = nil; return s }

	for _, lp := range []string{
		"minimist/../minimist/-/minimist-1.2.5.tgz",
		"evil/../../escape/-/x-1.0.0.tgz",
		"a/./b/-/b-1.0.0.tgz",
		"mapped/x/../y/-/y-1.0.0.tgz",
	} {
		if err := get(lp); err == nil {
			t.Errorf("%q: fetch succeeded, want refusal", lp)
		}
		if s := take(); len(s) != 0 {
			t.Errorf("%q reached upstream as %v", lp, s)
		}
	}

	// Positive controls: literal paths, including through the mapper and a
	// base without a trailing slash (its last segment is dropped by RFC 3986).
	for lp, want := range map[string]string{
		"minimist/-/minimist-1.2.5.tgz": "/npm/minimist/-/minimist-1.2.5.tgz",
		"@types/node":                   "/npm/@types/node",
		"mapped/y/-/y-1.0.0.tgz":        "/other/y/-/y-1.0.0.tgz",
	} {
		if err := get(lp); err != nil {
			t.Errorf("%q: %v", lp, err)
		}
		if s := take(); len(s) != 1 || s[0] != want {
			t.Errorf("%q: upstream saw %v, want %s", lp, s, want)
		}
	}
}

// FuzzLiteralRemoteURL: LiteralRemoteURL either refuses or returns a URL whose
// path is exactly the base directory plus the logical path — and it refuses
// only a path that has a dot segment or would replace the base path (an
// over-refusal is an outage).
func FuzzLiteralRemoteURL(f *testing.F) {
	for _, s := range []string{"a/b", "a/../b", "./a", "a//b", "%2e%2e/a", "a/..", "..", "x:y/z", "/a", "//a"} {
		f.Add("/base/dir/", s)
		f.Add("/base/file", s)
		f.Add("", s)
	}
	hasDot := func(p string) bool {
		for _, s := range strings.Split(p, "/") {
			if s == "." || s == ".." {
				return true
			}
		}
		return false
	}
	f.Fuzz(func(t *testing.T, basePath, lp string) {
		base := &url.URL{Scheme: "https", Host: "h", Path: basePath}
		got, err := LiteralRemoteURL(base, lp, "")
		ref := strings.TrimPrefix(lp, "/")
		if err != nil {
			if !hasDot(ref) && !hasDot(basePath) && !strings.HasPrefix(ref, "/") && !strings.HasPrefix(basePath, "//") {
				t.Fatalf("base %q lp %q refused with no dot segment", basePath, lp)
			}
			return
		}
		u, perr := url.Parse(got)
		if perr != nil {
			t.Fatalf("unparseable %q: %v", got, perr)
		}
		if ref == "" {
			return
		}
		dir := basePath[:strings.LastIndex(basePath, "/")+1]
		want := dir + ref
		if !strings.HasPrefix(want, "/") {
			want = "/" + want
		}
		if u.Path != want {
			t.Fatalf("base %q lp %q: path %q, want %q", basePath, lp, u.Path, want)
		}
	})
}
