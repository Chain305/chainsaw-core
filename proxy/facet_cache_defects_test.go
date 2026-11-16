package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/blobstore"
	"github.com/chain305/chainsaw-core/storage"
)

func newFileStorage(t *testing.T) *storage.LocalStorage {
	t.Helper()
	bs, err := blobstore.NewFileBlobStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return storage.NewLocalStorage("r", bs)
}

// --- 1. uploaded content belongs to us, not to the upstream ------------

// A hosted repository still has the format's default upstream. An uploaded
// maven-metadata.xml or pushed docker tag used to be "mutable": it expired
// after the metadata TTL, was revalidated against the public upstream and
// replaced by (or negative-cached as) the public namesake.
func TestUploadedEntryIsNeverExpiredOrReplacedByUpstream(t *testing.T) {
	for _, tc := range []struct{ format, path string }{
		{"maven", "com/acme/lib/maven-metadata.xml"},
		{"docker", "v2/acme/app/manifests/latest"},
		{"npm", "acme-lib"},
	} {
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			_, _ = io.WriteString(w, "public namesake")
		}))
		base, _ := url.Parse(srv.URL + "/")
		ls := newFileStorage(t)
		ctx := context.Background()
		if _, err := ls.Put(ctx, tc.path, strings.NewReader("internal doc"), storage.ContentMetadata{
			Uploaded: true,
			CachedAt: time.Now().Add(-365 * 24 * time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		f := NewFacet(FacetConfig{RepoName: "r", Format: tc.format, Storage: ls,
			Remote:      RemoteDefinition{BaseURL: base, Client: srv.Client()},
			MetadataTTL: 600 * time.Second, Logger: discardLogger()})

		resp, err := f.Get(ctx, &Request{LogicalPath: tc.path, Method: http.MethodGet, Header: http.Header{}})
		srv.Close()
		if err != nil {
			t.Fatalf("%s: %v", tc.format, err)
		}
		if hits.Load() != 0 {
			t.Errorf("%s %s: a year-old UPLOADED entry was revalidated against the upstream", tc.format, tc.path)
		}
		if got := readResp(t, resp); got != "internal doc" {
			t.Errorf("%s: served %q, want the uploaded document", tc.format, got)
		}
		if w := resp.Headers.Get("Warning"); w != "" {
			t.Errorf("%s: uploaded entry served with Warning %q", tc.format, w)
		}
	}
}

// An uploaded pip page recorded without a Content-Encoding must not take the
// encoding-repair miss either: that miss is an upstream refetch.
func TestUploadedEntryIsNeverEncodingRepaired(t *testing.T) {
	meta := storage.ContentMetadata{LogicalPath: "simple/acme/", ContentType: "text/html", Uploaded: true}
	if needsEncodingRepair(meta) {
		t.Fatal("an uploaded simple page was routed to the upstream for encoding repair")
	}
}

// Whatever path leads to storeUpstream (a race with an upload, a future
// caller), an upstream body must never be written over an uploaded entry.
func TestStoreUpstreamNeverOverwritesUploadedEntry(t *testing.T) {
	store := &freshStorage{present: true, meta: storage.ContentMetadata{Uploaded: true, ContentType: "application/xml"}}
	base, _ := url.Parse("https://repo1.maven.org/maven2/")
	f := &facet{format: "maven", storage: store, logger: discardLogger(),
		remote: RemoteDefinition{BaseURL: base, Client: http.DefaultClient}}
	upstream := &http.Response{StatusCode: http.StatusOK, Header: http.Header{},
		Body: io.NopCloser(strings.NewReader("public namesake"))}

	resp, err := f.storeUpstream(context.Background(), f.remote, "com/acme/lib/maven-metadata.xml", upstream)
	if err != nil {
		t.Fatal(err)
	}
	if store.puts != 0 {
		t.Fatal("upstream bytes were written over an uploaded entry")
	}
	if resp == nil || !resp.Content.Metadata.Uploaded {
		t.Fatalf("response is not the uploaded entry: %+v", resp)
	}
}

// --- 2. metadata documents that used to be cached forever -------------

func TestMutableDocumentsForRemainingFormats(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"
	mutable := []struct{ format, path string }{
		{"go", "github.com/pkg/errors/@v/list"},
		{"go", "github.com/!azure/azure-sdk-for-go/@latest"},
		{"cargo", "1/a"},
		{"cargo", "2/io"},
		{"cargo", "3/s/syn"},
		{"cargo", "se/rd/serde"},
		{"cargo", "to/ki/tokio-util"},
		{"pub", "api/packages/http"},
		{"pub", "api/packages/http/advisories"},
		{"swift", "apple/swift-nio"},
		{"swift", "apple/swift-nio.json"},
		{"swift", "apple/swift-nio/2.65.0"},
		{"cocoapods", "all_pods_versions_a_b_c.txt"},
		{"cocoapods", "Specs/a/b/c/Auntie/all_pods_versions_a_b_c.txt"},
		{"cocoapods", "CocoaPods-version.yml"},
		{"cocoapods", "deprecated_podspecs.txt"},
		{"huggingface", "api/models/bert-base-uncased"},
		{"huggingface", "api/models/google/gemma-2b/revision/main"},
		{"huggingface", "api/datasets/squad"},
		{"huggingface", "google/gemma-2b/resolve/main/config.json"},
		{"huggingface", "bert-base-uncased/resolve/v1.0/config.json"},
		{"huggingface", "datasets/squad/resolve/main/README.md"},
		{"huggingface", "datasets/org/set/raw/refs%2Fpr%2F1/data.csv"},
		{"rubygems", "specs.4.8.gz"},
		{"rubygems", "latest_specs.4.8.gz"},
		{"rubygems", "prerelease_specs.4.8.gz"},
		{"rubygems", "versions"},
		{"rubygems", "names"},
		{"rubygems", "info/rails"},
	}
	for _, tc := range mutable {
		if !isMutableDocument(tc.format, tc.path) {
			t.Errorf("isMutableDocument(%q, %q) = false, want true", tc.format, tc.path)
		}
	}

	immutable := []struct{ format, path string }{
		{"go", "github.com/pkg/errors/@v/v0.9.1.zip"},
		{"go", "github.com/pkg/errors/@v/v0.9.1.mod"},
		{"go", "github.com/pkg/errors/@v/v0.9.1.info"},
		{"cargo", "config.json"},
		{"cargo", "api/v1/crates/serde/1.0.0/download"},
		{"cargo", "crates/serde/serde-1.0.0.crate"},
		{"cargo", "se/rd/tokio"}, // not a shard of its own name
		{"pub", "api/packages/http/versions/1.2.0"},
		{"pub", "pub/http/1.2.0/archive/aHR0cHM6Ly9leGFtcGxlLmNvbS9h"},
		{"swift", "apple/swift-nio/2.65.0.zip"},
		{"swift", "apple/swift-nio/2.65.0.zip.sig"},
		{"swift", "apple/swift-nio/2.65.0/metadata.json"},
		{"swift", "apple/swift-nio/2.65.0/Package.swift"},
		{"cocoapods", "Specs/a/b/c/Auntie/1.0.0/Auntie.podspec.json"},
		{"huggingface", "google/gemma-2b/resolve/" + commit + "/model.safetensors"},
		// Weights at a branch stay cached: revalidating a multi-GB file
		// every TTL could re-download it.
		{"huggingface", "google/gemma-2b/resolve/main/model.safetensors"},
		{"huggingface", "TheBloke/x-GGUF/resolve/main/x.Q4_K_M.gguf"},
		{"huggingface", "datasets/squad/resolve/" + commit + "/README.md"},
		{"rubygems", "gems/rails-7.1.0.gem"},
		{"rubygems", "quick/Marshal.4.8/rails-7.1.0.gemspec.rz"},
	}
	for _, tc := range immutable {
		if isMutableDocument(tc.format, tc.path) {
			t.Errorf("isMutableDocument(%q, %q) = true, want false", tc.format, tc.path)
		}
	}
}

// --- 3. an oversized transformed body is refused, never spliced -------

type upperTransformer struct{}

func (upperTransformer) ShouldTransform(string, *http.Response) bool { return true }
func (upperTransformer) Transform(_ context.Context, _ string, b []byte) ([]byte, error) {
	return bytes.ToUpper(b), nil
}

// readBodyWithEncoding consumed ~50 MiB, then the facet stored the REST of
// resp.Body: a body missing its first 50 MiB, cached as the packument.
func TestOversizedTransformBodyIsRefusedNotTruncated(t *testing.T) {
	// Streamed, so the test does not hold a 256 MiB body of its own.
	chunk := bytes.Repeat([]byte("a"), 1<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for i := 0; i <= maxTransformBodySize/len(chunk); i++ {
			_, _ = w.Write(chunk)
		}
	}))
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL + "/")
	store := &freshStorage{}
	f := NewFacet(FacetConfig{RepoName: "r", Format: "npm", Storage: store, Rewrite: upperTransformer{},
		Remote: RemoteDefinition{BaseURL: base, Client: srv.Client()}, Logger: discardLogger()})

	resp, err := f.Get(context.Background(), &Request{LogicalPath: "huge", Method: http.MethodGet, Header: http.Header{}})
	if err == nil {
		t.Fatalf("an oversized transformed body was served (status %d); want an error", resp.StatusCode)
	}
	if store.puts != 0 {
		t.Fatal("an oversized body was cached")
	}
}

// --- 4. the first client's Accept must not decide the cached variant --

func TestUpstreamAcceptIsNormalisedForSharedDocuments(t *testing.T) {
	for _, tc := range []struct {
		format, path, clientAccept string
		want                       []string
		notWant                    string
	}{
		{"docker", "v2/library/nginx/manifests/latest", "application/vnd.docker.distribution.manifest.v2+json",
			[]string{
				"application/vnd.oci.image.index.v1+json",
				"application/vnd.oci.image.manifest.v1+json",
				"application/vnd.docker.distribution.manifest.list.v2+json",
				"application/vnd.docker.distribution.manifest.v2+json",
				"application/vnd.docker.distribution.manifest.v1+prettyjws",
			}, ""},
		{"npm", "undici", "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*",
			[]string{"application/json"}, "install-v1"},
	} {
		var got string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Get("Accept")
			_, _ = io.WriteString(w, "{}")
		}))
		base, _ := url.Parse(srv.URL + "/")
		f := NewFacet(FacetConfig{RepoName: "r", Format: tc.format, Storage: &freshStorage{},
			Remote: RemoteDefinition{BaseURL: base, Client: srv.Client()}, Logger: discardLogger()})
		_, err := f.Get(context.Background(), &Request{LogicalPath: tc.path, Method: http.MethodGet,
			Header: http.Header{"Accept": {tc.clientAccept}}})
		srv.Close()
		if err != nil {
			t.Fatalf("%s: %v", tc.format, err)
		}
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: upstream Accept %q lacks %q", tc.format, got, w)
			}
		}
		if tc.notWant != "" && strings.Contains(got, tc.notWant) {
			t.Errorf("%s: upstream Accept %q still carries the client's %q", tc.format, got, tc.notWant)
		}
	}
}

// --- 5. docker tags/list pagination -----------------------------------

func TestDockerTagsListPagesAreNotPageOne(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("last") == "b" {
			_, _ = io.WriteString(w, `{"name":"library/nginx","tags":["c"]}`)
			return
		}
		w.Header().Set("Link", `</v2/library/nginx/tags/list?last=b&n=2>; rel="next"`)
		_, _ = io.WriteString(w, `{"name":"library/nginx","tags":["a","b"]}`)
	}))
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL + "/")
	ls := newFileStorage(t)
	f := NewFacet(FacetConfig{RepoName: "r", Format: "docker", Storage: ls,
		Remote: RemoteDefinition{BaseURL: base, Client: srv.Client()}, Logger: discardLogger()})
	ctx := context.Background()
	get := func(q string) *Response {
		t.Helper()
		resp, err := f.Get(ctx, &Request{LogicalPath: "v2/library/nginx/tags/list", RawQuery: q,
			Method: http.MethodGet, Header: http.Header{}})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	first := get("n=2")
	if body := readResp(t, first); !strings.Contains(body, `"a","b"`) {
		t.Fatalf("page 1 = %s", body)
	}
	if link := first.Headers.Get("Link"); link != `<?last=b&n=2>; rel="next"` {
		t.Errorf("page 1 Link = %q; want it pointed back at this proxy path", link)
	}
	second := get("last=b&n=2&evil=1")
	if body := readResp(t, second); !strings.Contains(body, `"c"`) {
		t.Fatalf("page 2 served %s; the query was dropped and page 1 returned", body)
	}
	if queries[len(queries)-1] != "last=b&n=2" {
		t.Errorf("upstream query = %q, want only last and n forwarded", queries[len(queries)-1])
	}
	// Page 2 must not have replaced the cached unpaginated list.
	if _, err := ls.Get(ctx, "v2/library/nginx/tags/list"); err == nil {
		t.Error("a paginated tags/list page was stored under the unpaginated path")
	}
	plain := get("")
	if body := readResp(t, plain); !strings.Contains(body, `"a","b"`) {
		t.Fatalf("unpaginated list = %s", body)
	}
	if link := plain.Headers.Get("Link"); link != `<?last=b&n=2>; rel="next"` {
		t.Errorf("cached list Link = %q", link)
	}
}

// --- 6. integrity headers survive the cache ---------------------------

func TestIntegrityHeadersSurviveTheCache(t *testing.T) {
	h := http.Header{}
	for _, k := range []string{"Docker-Content-Digest", "X-Checksum-Sha1", "X-Checksum-Md5", "X-Checksum-Sha256"} {
		h.Set(k, "v-"+k)
	}
	out := headersFromMetadata(storage.ContentMetadata{ExtraHeaders: captureExtraHeaders(h)})
	for k := range h {
		if out.Get(k) != "v-"+k {
			t.Errorf("%s lost across the cache", k)
		}
	}
}

func readResp(t *testing.T, resp *Response) string {
	t.Helper()
	if resp == nil || resp.Content == nil {
		t.Fatalf("no content in response %+v", resp)
	}
	return readAll(t, resp.Content)
}
