package provenance

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	resolverCommitSHA = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	resolverTagSHA    = "1111111111111111111111111111111111111111111111111111111111111111"
)

func TestGitHubAPIRefResolver_AlreadyHexDigest_NoAPICall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected API call to %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	r := NewGitHubAPIRefResolver(srv.Client(), "", nil)
	r.BaseURL = srv.URL

	got, err := r.Resolve(context.Background(), "actions", "checkout", resolverCommitSHA)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != resolverCommitSHA {
		t.Fatalf("digest: got %q want %q", got, resolverCommitSHA)
	}

	// Also accept "sha256:" prefix.
	got2, err := r.Resolve(context.Background(), "actions", "checkout", "sha256:"+resolverCommitSHA)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got2 != resolverCommitSHA {
		t.Fatalf("digest with prefix: got %q want %q", got2, resolverCommitSHA)
	}
}

func TestGitHubAPIRefResolver_LightweightTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/actions/checkout/git/ref/tags/v4":
			fmt.Fprintf(w, `{"object":{"type":"commit","sha":%q}}`, resolverCommitSHA)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	r := NewGitHubAPIRefResolver(srv.Client(), "tok", nil)
	r.BaseURL = srv.URL

	got, err := r.Resolve(context.Background(), "actions", "checkout", "v4")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != resolverCommitSHA {
		t.Fatalf("digest: got %q want %q", got, resolverCommitSHA)
	}
}

func TestGitHubAPIRefResolver_AnnotatedTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/actions/checkout/git/ref/tags/v4.0.0":
			fmt.Fprintf(w, `{"object":{"type":"tag","sha":%q}}`, resolverTagSHA)
		case "/repos/actions/checkout/git/tags/" + resolverTagSHA:
			fmt.Fprintf(w, `{"object":{"type":"commit","sha":%q}}`, resolverCommitSHA)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	r := NewGitHubAPIRefResolver(srv.Client(), "", nil)
	r.BaseURL = srv.URL

	got, err := r.Resolve(context.Background(), "actions", "checkout", "v4.0.0")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != resolverCommitSHA {
		t.Fatalf("digest: got %q want %q", got, resolverCommitSHA)
	}
}

func TestGitHubAPIRefResolver_Branch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/actions/checkout/git/ref/tags/main":
			http.NotFound(w, r) // not a tag
		case "/repos/actions/checkout/git/ref/heads/main":
			fmt.Fprintf(w, `{"object":{"type":"commit","sha":%q}}`, resolverCommitSHA)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	r := NewGitHubAPIRefResolver(srv.Client(), "", nil)
	r.BaseURL = srv.URL

	got, err := r.Resolve(context.Background(), "actions", "checkout", "main")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != resolverCommitSHA {
		t.Fatalf("digest: got %q want %q", got, resolverCommitSHA)
	}
}

func TestGitHubAPIRefResolver_CommitFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/repos/actions/checkout/git/ref/"):
			http.NotFound(w, r)
		case r.URL.Path == "/repos/actions/checkout/commits/abc123":
			fmt.Fprintf(w, `{"sha":%q}`, resolverCommitSHA)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	r := NewGitHubAPIRefResolver(srv.Client(), "", nil)
	r.BaseURL = srv.URL

	got, err := r.Resolve(context.Background(), "actions", "checkout", "abc123")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != resolverCommitSHA {
		t.Fatalf("digest: got %q want %q", got, resolverCommitSHA)
	}
}

func TestGitHubAPIRefResolver_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	r := NewGitHubAPIRefResolver(srv.Client(), "", nil)
	r.BaseURL = srv.URL

	_, err := r.Resolve(context.Background(), "actions", "checkout", "nonexistent")
	if !errors.Is(err, ErrUnresolvableRef) {
		t.Fatalf("want ErrUnresolvableRef, got %v", err)
	}
}

func TestGitHubAPIRefResolver_CacheHit(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		switch r.URL.Path {
		case "/repos/actions/checkout/git/ref/tags/v4":
			fmt.Fprintf(w, `{"object":{"type":"commit","sha":%q}}`, resolverCommitSHA)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cache := &InMemoryDigestCache{}
	r := NewGitHubAPIRefResolver(srv.Client(), "", cache)
	r.BaseURL = srv.URL

	// First call hits the API.
	if _, err := r.Resolve(context.Background(), "actions", "checkout", "v4"); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	first := atomic.LoadInt32(&calls)
	if first == 0 {
		t.Fatalf("expected at least one API call on first resolve")
	}

	// Now resolve the commit SHA directly — it's already a hex digest, so
	// no API call. But more importantly: simulate a second tag-resolve that
	// already has the commit cached. We test the cache directly.
	if v, ok := cache.Get(resolverCommitSHA); !ok || v != resolverCommitSHA {
		t.Fatalf("expected cache to hold %q -> %q, got (%q,%v)", resolverCommitSHA, resolverCommitSHA, v, ok)
	}

	// Resolve the same hex digest again — should not call the API.
	got, err := r.Resolve(context.Background(), "actions", "checkout", resolverCommitSHA)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if got != resolverCommitSHA {
		t.Fatalf("digest: got %q want %q", got, resolverCommitSHA)
	}
	if got2 := atomic.LoadInt32(&calls); got2 != first {
		t.Fatalf("expected no extra API calls on hex-digest pass-through, got %d calls (was %d)", got2, first)
	}
}

func TestGitHubAPIRefResolver_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hang until ctx times out.
		<-r.Context().Done()
	}))
	defer srv.Close()

	r := NewGitHubAPIRefResolver(srv.Client(), "", nil)
	r.BaseURL = srv.URL

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	_, err := r.Resolve(ctx, "actions", "checkout", "v4")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestInMemoryDigestCache_Roundtrip(t *testing.T) {
	c := &InMemoryDigestCache{}
	if _, ok := c.Get("nope"); ok {
		t.Fatalf("expected miss")
	}
	c.Set("k", "v")
	v, ok := c.Get("k")
	if !ok || v != "v" {
		t.Fatalf("got (%q,%v) want (\"v\",true)", v, ok)
	}
}
