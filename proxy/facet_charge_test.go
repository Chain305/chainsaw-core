package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/chain305/chainsaw-core/blobstore"
	"github.com/chain305/chainsaw-core/storage"
)

// Every upstream fetch made for a client is reported to the charger, so it
// counts against the process-wide upstream budget; a cache hit is not
// (J.4 I13-1).
func TestFacetChargesUpstreamFetches(t *testing.T) {
	var mu sync.Mutex
	var hosts []string
	SetUpstreamCharger(func(h string) { mu.Lock(); hosts = append(hosts, h); mu.Unlock() })
	t.Cleanup(func() { SetUpstreamCharger(nil) })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("doc")) }))
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL + "/")
	fs, err := blobstore.NewFileBlobStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := NewFacet(FacetConfig{RepoName: "r", Format: "npm", Storage: storage.NewLocalStorage("r", fs), Resolver: tgzResolver{},
		Remote: RemoteDefinition{BaseURL: base, Client: srv.Client()}, Logger: discardLogger()})
	for i := 0; i < 2; i++ { // the second is answered from cache
		if _, err := f.Get(context.Background(), &Request{LogicalPath: "pkg", Method: http.MethodGet, Header: http.Header{}}); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hosts) != 1 || hosts[0] != base.Hostname() {
		t.Fatalf("charged %v, want one charge for %s", hosts, base.Hostname())
	}
}
