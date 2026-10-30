package intelligence

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// When the requested version is the latest, its go.mod (dependencies) and
// the latest go.mod (retractions, deprecation) are one file, fetched once
// per scan (J.4 I13-2). It used to be fetched twice.
func TestRunGoFetchesALatestGoModOnce(t *testing.T) {
	var modGets atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"), strings.HasSuffix(r.URL.Path, ".info"):
			_, _ = w.Write([]byte(`{"Version":"v1.2.0","Time":"2026-01-01T00:00:00Z"}`))
		case strings.HasSuffix(r.URL.Path, ".mod"):
			modGets.Add(1)
			_, _ = w.Write([]byte("module example.com/m\n\nrequire golang.org/x/text v0.3.0\n\nretract v1.1.0\n"))
		default:
			http.NotFound(w, r)
		}
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.runGo(context.Background(), "example.com/m", "v1.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if n := modGets.Load(); n != 1 {
		t.Fatalf("go.mod fetched %d times for a version that is the latest, want 1", n)
	}
	if pr.Dependencies == nil || len(pr.Dependencies.Direct) != 1 {
		t.Fatalf("dependencies not read from the shared fetch: %+v", pr.Dependencies)
	}
}
