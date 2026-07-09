package proxy

import (
	"context"
	"io"
	"net/http"
	"testing"

	"time"

	"github.com/chain305/chainsaw-core/cache"
	"github.com/chain305/chainsaw-core/formats/common"
	"github.com/chain305/chainsaw-core/storage"
)

// benchResolver is a tiny in-package CoordinateResolver so the bench
// avoids importing internal/formats/npm (which would create an import
// cycle: npm imports internal/proxy for its transformer).
type benchResolver struct{}

func (benchResolver) Describe(p string) (common.PackageCoordinate, bool) {
	return common.PackageCoordinate{Name: "lodash", Version: "4.17.21", Format: "npm"}, true
}

func (benchResolver) Format() string { return "npm" }

// benchStorage is a no-op StorageFacet that always returns the same
// pre-populated CachedContent. The benchmark targets the cache-hit fast
// path through facet.Get → tryCacheHit, so we strip out the blob open()
// path which is dominated by the OS file system, not our code.
type benchStorage struct {
	content *storage.CachedContent
}

func (b *benchStorage) Get(context.Context, string) (*storage.CachedContent, error) {
	return b.content, nil
}

func (b *benchStorage) Put(context.Context, string, io.Reader, storage.ContentMetadata) (*storage.CachedContent, error) {
	return b.content, nil
}

func (b *benchStorage) UpdateMetadata(context.Context, string, storage.ContentMetadata) (*storage.CachedContent, error) {
	return b.content, nil
}

func (b *benchStorage) Remove(context.Context, string) error { return nil }

func (b *benchStorage) FindPathsByCoordinate(context.Context, string, string) ([]string, error) {
	return nil, nil
}

// BenchmarkCacheHit measures the proxy facet's cache-hit fast path:
// negative-cache check → storage.Get → coordinate-resolver describe →
// metadata→headers wiring → Response. Excludes the singleflight branch
// and upstream HTTP altogether — that's the slow path.
//
// p99 target: <15ms
func BenchmarkCacheHit(b *testing.B) {
	cached := &storage.CachedContent{
		Metadata: storage.ContentMetadata{
			LogicalPath:    "lodash/-/lodash-4.17.21.tgz",
			ContentType:    "application/octet-stream",
			ETag:           `"deadbeef"`,
			Size:           143000,
			PackageName:    "lodash",
			PackageVersion: "4.17.21",
		},
	}
	store := &benchStorage{content: cached}

	f := NewFacet(FacetConfig{
		RepoName:           "npm-proxy",
		Format:             "npm",
		Storage:            store,
		Resolver:           benchResolver{},
		Negative:           cache.NewNegativeCache(5 * time.Minute),
		AllowMissingRemote: true,
	})

	req := &Request{
		Method:      http.MethodGet,
		LogicalPath: "/lodash/-/lodash-4.17.21.tgz",
		Header:      http.Header{},
	}
	ctx := context.Background()

	// Sanity: ensure we are actually hitting the cache path.
	if resp, err := f.Get(ctx, req); err != nil || resp == nil || !resp.FromCache {
		b.Fatalf("setup: expected cache hit, err=%v resp=%+v", err, resp)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = f.Get(ctx, req)
	}

	// Compile-time check that benchResolver implements the interface.
	var _ common.CoordinateResolver = benchResolver{}
}
