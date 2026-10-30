package intelligence

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func resetEtagCache(t *testing.T, mb string) {
	t.Helper()
	t.Setenv("CHAINSAW_REGISTRY_ETAG_CACHE_MB", mb)
	etagCache.Lock()
	etagCache.m, etagCache.bytes, etagCache.limit = map[string]etagEntry{}, 0, -1
	etagCache.Unlock()
	t.Cleanup(func() {
		etagCache.Lock()
		etagCache.m, etagCache.bytes, etagCache.limit = map[string]etagEntry{}, 0, -1
		etagCache.Unlock()
	})
}

// A document refetched unchanged costs a 304 and decodes to the same value;
// a changed one is downloaded; a 404 forgets the kept copy; headers come
// back on a 304 as they were on the 200.
func TestRegistryFetchConditionalGET(t *testing.T) {
	resetEtagCache(t, "64")
	var full, notModified atomic.Int32
	version := atomic.Value{}
	version.Store("1")
	gone := atomic.Bool{}
	mux := http.NewServeMux()
	mux.HandleFunc("/doc", func(w http.ResponseWriter, r *http.Request) {
		if gone.Load() {
			http.NotFound(w, r)
			return
		}
		v := version.Load().(string)
		etag := `"v` + v + `"`
		if r.Header.Get("If-None-Match") == etag {
			notModified.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		full.Add(1)
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", "Tue, 0"+v+" Jan 2026 00:00:00 GMT")
		_, _ = w.Write([]byte(`{"version":"` + v + `"}` + "\n"))
	})
	p, srv := newStubProvider(t, mux)
	fetch := func() (string, string) {
		t.Helper()
		var out struct{ Version string }
		var h http.Header
		warn, err := p.fetchJSON(withHeaderCapture(context.Background(), &h), srv.URL+"/doc", "application/json", &out)
		if warn != nil || err != nil {
			t.Fatalf("fetch: %+v %v", warn, err)
		}
		return out.Version, h.Get("Last-Modified")
	}

	if v, _ := fetch(); v != "1" {
		t.Fatalf("first fetch %q", v)
	}
	v, lm := fetch()
	if v != "1" || full.Load() != 1 || notModified.Load() != 1 || !strings.Contains(lm, "01 Jan") {
		t.Fatalf("unchanged refetch: v=%q full=%d 304=%d lm=%q; want 1, 1 download, 1 not-modified, headers kept", v, full.Load(), notModified.Load(), lm)
	}
	version.Store("2")
	if v, _ := fetch(); v != "2" || full.Load() != 2 {
		t.Fatalf("changed document: v=%q full=%d, want 2 and a second download", v, full.Load())
	}
	gone.Store(true)
	var out struct{ Version string }
	if warn, _ := p.fetchJSON(context.Background(), srv.URL+"/doc", "application/json", &out); warn == nil || warn.Code != WarnRegistryNotFound {
		t.Fatalf("404 not reported: %+v", warn)
	}
	if _, ok := etagCacheGet(etagCacheKey(srv.URL+"/doc", "application/json")); ok {
		t.Fatal("a 404 left the kept copy in place")
	}
}

// Off at 0, and a document over a quarter of the cache is never kept.
func TestRegistryETagCacheBounds(t *testing.T) {
	var full atomic.Int32
	big := `{"pad":"` + strings.Repeat("x", 300<<10) + `"}`
	mux := http.NewServeMux()
	mux.HandleFunc("/doc", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"a"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		full.Add(1)
		w.Header().Set("ETag", `"a"`)
		_, _ = w.Write([]byte(big))
	})
	p, srv := newStubProvider(t, mux)
	var out map[string]any
	for _, mb := range []string{"0", "1"} { // off; then 1 MiB, so 256 KiB per document
		resetEtagCache(t, mb)
		full.Store(0)
		for i := 0; i < 2; i++ {
			if warn, err := p.fetchJSON(context.Background(), srv.URL+"/doc", "application/json", &out); warn != nil || err != nil {
				t.Fatalf("fetch: %+v %v", warn, err)
			}
		}
		if full.Load() != 2 {
			t.Fatalf("cache %s MB: %d downloads of a 300 KiB document, want 2 (not kept)", mb, full.Load())
		}
	}
	resetEtagCache(t, "4") // 1 MiB per document: now kept
	full.Store(0)
	for i := 0; i < 2; i++ {
		_, _ = p.fetchJSON(context.Background(), srv.URL+"/doc", "application/json", &out)
	}
	if full.Load() != 1 {
		t.Fatalf("4 MB cache: %d downloads, want 1", full.Load())
	}
}

// The buffer that keeps a body while it streams stops holding bytes past its
// cap, so a 15 MB packument is not copied into memory a second time.
func TestCappedBuffer(t *testing.T) {
	c := &cappedBuffer{max: 4}
	if n, _ := c.Write([]byte("abc")); n != 3 || string(c.buf) != "abc" || c.over {
		t.Fatalf("under the cap: %q over=%v", c.buf, c.over)
	}
	if n, _ := c.Write([]byte("de")); n != 2 || c.buf != nil || !c.over {
		t.Fatalf("past the cap: %q over=%v, want nil and over", c.buf, c.over)
	}
	if c.Write([]byte("f")); c.buf != nil {
		t.Fatal("kept bytes after overflowing")
	}
}
