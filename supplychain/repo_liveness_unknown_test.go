package supplychain

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// An attempted probe that ends unknown carries why, so the caller can say
// the check failed instead of looking like a package with no repo.
func TestClassifyUnknownCarriesItsReason(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		status int
		header map[string]string
		want   string
	}{
		// GitHub's budget answer: 403 with X-RateLimit-Remaining: 0.
		{"github budget exhausted", http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0"}, UnknownRateLimited},
		{"secondary rate limit 429", http.StatusTooManyRequests, nil, UnknownRateLimited},
		{"403 that is not a rate limit", http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "4211"}, UnknownHTTP},
		{"server error", http.StatusBadGateway, nil, UnknownHTTP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tc.header {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
			}))
			defer srv.Close()
			c := NewRepoLivenessChecker(&http.Client{Timeout: 5 * time.Second}, nil, WithAPIBaseOverride("github", srv.URL))
			got := c.Classify(context.Background(), "https://github.com/chalk/chalk", nil)
			if got.Status != RepoLinkStatusUnknown || got.UnknownReason != tc.want {
				t.Errorf("got status %q reason %q, want unknown / %q", got.Status, got.UnknownReason, tc.want)
			}
		})
	}

	t.Run("transport failure", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		base := srv.URL
		srv.Close() // nothing listens: a dial error
		c := NewRepoLivenessChecker(&http.Client{Timeout: 2 * time.Second}, nil, WithAPIBaseOverride("github", base))
		got := c.Classify(context.Background(), "https://github.com/chalk/chalk", nil)
		if got.Status != RepoLinkStatusUnknown || got.UnknownReason != UnknownTransport {
			t.Errorf("got status %q reason %q, want unknown / transport", got.Status, got.UnknownReason)
		}
	})

	t.Run("unrecognised host was never probed", func(t *testing.T) {
		c := NewRepoLivenessChecker(&http.Client{Timeout: time.Second}, nil)
		got := c.Classify(context.Background(), "https://git.example.org/team/repo", nil)
		if got.Status != RepoLinkStatusUnknown || got.UnknownReason != "" {
			t.Errorf("got status %q reason %q, want unknown with no reason", got.Status, got.UnknownReason)
		}
	})

	t.Run("a known answer has no reason", func(t *testing.T) {
		srv := newGitHubStub(t, nil)
		c := NewRepoLivenessChecker(&http.Client{Timeout: 5 * time.Second}, nil, WithAPIBaseOverride("github", srv.URL))
		if got := c.Classify(context.Background(), "https://github.com/chalk/chalk", nil); got.UnknownReason != "" {
			t.Errorf("ok result carries reason %q", got.UnknownReason)
		}
	})
}

// A renamed GitHub repo answers 301 to /repositories/<id>. The production
// checker (built with a nil client, as Bootstrap does) must follow it, at a
// cost of two requests, and classify the target.
func TestClassifyFollowsAGitHubRename(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/repos/old-owner/old-name":
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("first hop lost the token")
			}
			w.Header().Set("Location", srv.URL+"/repositories/123456")
			w.WriteHeader(http.StatusMovedPermanently)
		case "/repositories/123456":
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("redirect hop lost the token, so a rename spends the anonymous budget")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"archived": true, "pushed_at": "2021-01-01T00:00:00Z"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := NewRepoLivenessChecker(nil, nil, WithAPIBaseOverride("github", srv.URL))
	c.githubToken = "tok"
	got := c.Classify(context.Background(), "https://github.com/old-owner/old-name", nil)
	if got.Status != RepoLinkStatusArchived {
		t.Fatalf("renamed repo classified %q (reason %q), want archived", got.Status, got.UnknownReason)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("rename cost %d requests, want 2", n)
	}
}
