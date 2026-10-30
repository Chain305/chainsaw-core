package intelligence

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// A second scan of a canonical Go version reuses its .info; a 404 and a
// non-canonical query are refetched every time.
func TestRunGoReusesInfoAcrossScans(t *testing.T) {
	var infoGets atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v9.9.9.info"):
			infoGets.Add(1)
			http.NotFound(w, r)
		case strings.HasSuffix(r.URL.Path, "/vmaster.info"), strings.HasSuffix(r.URL.Path, "/v1.3.0.info"):
			infoGets.Add(1)
			_, _ = w.Write([]byte(`{"Version":"v1.2.0","Time":"2026-01-01T00:00:00Z"}`))
		case strings.HasSuffix(r.URL.Path, ".info"):
			infoGets.Add(1)
			_, _ = w.Write([]byte(`{"Version":"v1.2.0","Time":"2026-01-01T00:00:00Z","Origin":{"URL":"https://github.com/example/m"}}`))
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = w.Write([]byte(`{"Version":"v1.2.0","Time":"2026-01-01T00:00:00Z"}`))
		case strings.HasSuffix(r.URL.Path, ".mod"):
			_, _ = w.Write([]byte("module example.com/m\n"))
		default:
			http.NotFound(w, r)
		}
	})
	p, _ := newStubProvider(t, mux)
	scan := func(ver string) PartialReport {
		t.Helper()
		pr, err := p.runGo(context.Background(), "example.com/m", ver)
		if err != nil {
			t.Fatal(err)
		}
		return pr
	}

	first := scan("v1.2.0")
	second := scan("v1.2.0")
	if n := infoGets.Load(); n != 1 {
		t.Fatalf(".info fetched %d times over two scans, want 1", n)
	}
	if second.Release == nil || second.Release.PublishedAt == nil || !second.Release.PublishedAt.Equal(*first.Release.PublishedAt) {
		t.Fatalf("reused scan lost the publish time: %+v", second.Release)
	}
	if second.URLs == nil || second.URLs.SourceRepoURL != first.URLs.SourceRepoURL || first.URLs.SourceRepoURL == "" {
		t.Fatalf("reused scan lost the origin: first %+v second %+v", first.URLs, second.URLs)
	}

	infoGets.Store(0)
	scan("v9.9.9")
	scan("v9.9.9")
	if n := infoGets.Load(); n != 2 {
		t.Fatalf("a 404 .info was fetched %d times over two scans, want 2 (never cached)", n)
	}
	infoGets.Store(0)
	scan("master")
	scan("master")
	if n := infoGets.Load(); n != 2 {
		t.Fatalf("a branch query's .info was fetched %d times over two scans, want 2 (never cached)", n)
	}
	// An answer naming a different version than asked is not this version's
	// immutable record.
	infoGets.Store(0)
	scan("v1.3.0")
	scan("v1.3.0")
	if n := infoGets.Load(); n != 2 {
		t.Fatalf("a mismatched .info was fetched %d times over two scans, want 2 (never cached)", n)
	}
}
