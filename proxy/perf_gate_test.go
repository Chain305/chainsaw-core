package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/blobstore"
	"github.com/chain305/chainsaw-core/storage"
)

// slowCountingStore is an object store with injected latency on every call
// that reaches it, counting each kind: the shape that made the measured warm
// install 4-5x slower than going direct (docs/REPORTS.md
// #backend-perf-load-test-2026-10-29 §B, J.6 I17 step 8).
type slowCountingStore struct {
	blobstore.BlobStore
	delay             time.Duration
	gets, heads, puts atomic.Int64
}

func (s *slowCountingStore) Open(key string) (io.ReadCloser, error) {
	s.gets.Add(1)
	time.Sleep(s.delay)
	return s.BlobStore.Open(key)
}

func (s *slowCountingStore) Stat(key string) (os.FileInfo, error) {
	s.heads.Add(1)
	time.Sleep(s.delay)
	return s.BlobStore.Stat(key)
}

func (s *slowCountingStore) WriteForOrg(org, repo, p string, src io.Reader) (*blobstore.Blob, error) {
	s.puts.Add(1)
	time.Sleep(s.delay)
	return s.BlobStore.WriteForOrg(org, repo, p, src)
}

// TestPerfGateWarmHits is the serving-path regression gate (make
// perf-gate): object-store calls per warm hit and warm-hit latency, with
// 20 ms injected on every store call. Before J.2 a warm tarball hit cost a
// HEAD and a GET; with the disk tier it costs nothing on the store.
func TestPerfGateWarmHits(t *testing.T) {
	const hits = 50
	upstreamHits := atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, _ = w.Write([]byte("tarball bytes for the perf gate"))
	}))
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL + "/")

	for _, withTier := range []bool{false, true} {
		fs, err := blobstore.NewFileBlobStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		store := &slowCountingStore{BlobStore: fs, delay: 20 * time.Millisecond}
		ls := storage.NewLocalStorage("r", store)
		if withTier {
			tier, err := storage.NewDiskTier(t.TempDir(), 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			tier.SetMinFree(0) // the gate measures the tier, not this machine's disk
			ls.SetDiskTier(tier)
		}
		f := NewFacet(FacetConfig{RepoName: "r", Format: "npm", Storage: ls, Resolver: tgzResolver{},
			Remote: RemoteDefinition{BaseURL: base, Client: srv.Client()}, Logger: discardLogger()})
		ctx := context.Background()
		const artifact = "pkg/-/pkg-1.0.0.tgz"
		get := func() (*Response, time.Duration) {
			t.Helper()
			start := time.Now()
			resp, err := f.Get(ctx, &Request{LogicalPath: artifact, Method: http.MethodGet, Header: http.Header{}})
			if err != nil {
				t.Fatal(err)
			}
			rc, err := resp.Content.Open()
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, rc)
			rc.Close()
			return resp, time.Since(start)
		}
		resp, _ := get() // the cold fill
		meta := resp.Content.Metadata
		meta.Unverified = false
		if _, err := ls.UpdateMetadata(ctx, artifact, meta); err != nil {
			t.Fatal(err)
		}
		g0, h0, p0 := store.gets.Load(), store.heads.Load(), store.puts.Load()
		upstream0 := upstreamHits.Load()
		var lat []time.Duration
		for i := 0; i < hits; i++ {
			resp, d := get()
			if !resp.FromCache {
				t.Fatal("a warm request was not answered from cache")
			}
			lat = append(lat, d)
		}
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		p95 := lat[hits*95/100]
		gets := float64(store.gets.Load()-g0) / hits
		heads := store.heads.Load() - h0
		puts := store.puts.Load() - p0
		t.Logf("tier=%v: %.2f GETs, %d HEADs, %d PUTs per %d warm hits; p95 %v", withTier, gets, heads, puts, hits, p95)

		if heads != 0 || puts != 0 {
			t.Errorf("tier=%v: warm hits made %d HEADs and %d PUTs on the object store, want 0", withTier, heads, puts)
		}
		if upstreamHits.Load() != upstream0 {
			t.Errorf("tier=%v: warm hits went upstream", withTier)
		}
		wantGets := 1.0
		budget := 60 * time.Millisecond // one 20 ms GET plus slack
		if withTier {
			wantGets, budget = 0, 15*time.Millisecond
		}
		if gets > wantGets {
			t.Errorf("tier=%v: %.2f object-store GETs per warm hit, want <= %.0f", withTier, gets, wantGets)
		}
		if p95 > budget {
			t.Errorf("tier=%v: warm-hit p95 %v, budget %v", withTier, p95, budget)
		}
	}
}
