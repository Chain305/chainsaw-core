package supplychain

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// newGitHubStub returns an httptest.Server that emulates the subset of
// the GitHub repos API that Classify touches. handler controls the
// response for each repo path (e.g. "/repos/owner/repo"). Passing
// nil routes every request to a 200 with a non-archived body.
func newGitHubStub(t *testing.T, handler func(r *http.Request) (int, string)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"archived": false}`))
			return
		}
		code, body := handler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestClassify_GitHub_OK ensures a normal 200+not-archived repo is
// classified as "ok". This is the hot path — every healthy GitHub
// package contributes +10 to the trust-score.
func TestClassify_GitHub_OK(t *testing.T) {
	t.Parallel()
	srv := newGitHubStub(t, func(r *http.Request) (int, string) {
		if r.URL.Path != "/repos/lodash/lodash" {
			return http.StatusNotFound, `{}`
		}
		return http.StatusOK, `{"archived": false, "name": "lodash"}`
	})
	c := NewRepoLivenessChecker(&http.Client{Timeout: 5 * time.Second}, nil, WithAPIBaseOverride("github", srv.URL))
	got := c.Classify(context.Background(), "https://github.com/lodash/lodash.git", nil)
	if got.Status != RepoLinkStatusOK {
		t.Errorf("status: got %q, want %q", got.Status, RepoLinkStatusOK)
	}
	if got.CheckedAt.IsZero() {
		t.Error("CheckedAt must be set on every result")
	}
}

// TestClassify_GitHub_Archived — the `archived: true` branch must
// produce "archived" so the trust-score picks up a -10 penalty.
func TestClassify_GitHub_Archived(t *testing.T) {
	t.Parallel()
	srv := newGitHubStub(t, func(r *http.Request) (int, string) {
		return http.StatusOK, `{"archived": true, "name": "sunset"}`
	})
	c := NewRepoLivenessChecker(nil, nil, WithAPIBaseOverride("github", srv.URL))
	got := c.Classify(context.Background(), "https://github.com/someone/sunset", nil)
	if got.Status != RepoLinkStatusArchived {
		t.Errorf("status: got %q, want %q", got.Status, RepoLinkStatusArchived)
	}
}

// TestClassify_GitHub_Missing — a 404 from the API (repo deleted,
// never existed, or renamed) must produce "missing".
func TestClassify_GitHub_Missing(t *testing.T) {
	t.Parallel()
	srv := newGitHubStub(t, func(r *http.Request) (int, string) {
		return http.StatusNotFound, `{"message":"Not Found"}`
	})
	c := NewRepoLivenessChecker(nil, nil, WithAPIBaseOverride("github", srv.URL))
	got := c.Classify(context.Background(), "https://github.com/ghost/deleted", nil)
	if got.Status != RepoLinkStatusMissing {
		t.Errorf("status: got %q, want %q", got.Status, RepoLinkStatusMissing)
	}
}

// TestClassify_GitHub_OwnershipMismatch requires TWO independent
// conditions: (a) the repo owner is in the corporate shortlist, and
// (b) at least one publisher ID uses a well-known public-email
// provider. This asymmetry is deliberate — conservative firing.
func TestClassify_GitHub_OwnershipMismatch(t *testing.T) {
	t.Parallel()
	srv := newGitHubStub(t, func(r *http.Request) (int, string) {
		return http.StatusOK, `{"archived": false}`
	})
	c := NewRepoLivenessChecker(nil, nil, WithAPIBaseOverride("github", srv.URL))
	got := c.Classify(context.Background(), "https://github.com/google/angular", []string{"impersonator@gmail.com"})
	if got.Status != RepoLinkStatusOwnershipMismatch {
		t.Errorf("status: got %q, want %q", got.Status, RepoLinkStatusOwnershipMismatch)
	}
}

// TestClassify_GitHub_NoMismatchWhenOwnerNotCorporate guards against
// a common false-positive: a hobby repo published by a gmail user
// must NOT fire ownership_mismatch. Otherwise we'd penalise half of
// open source.
func TestClassify_GitHub_NoMismatchWhenOwnerNotCorporate(t *testing.T) {
	t.Parallel()
	srv := newGitHubStub(t, func(r *http.Request) (int, string) {
		return http.StatusOK, `{"archived": false}`
	})
	c := NewRepoLivenessChecker(nil, nil, WithAPIBaseOverride("github", srv.URL))
	got := c.Classify(context.Background(), "https://github.com/alice/cool-tool", []string{"alice@gmail.com"})
	if got.Status != RepoLinkStatusOK {
		t.Errorf("status: got %q, want %q (publisher uses gmail but owner is not corporate)", got.Status, RepoLinkStatusOK)
	}
}

// TestClassify_GitHub_NoMismatchWhenPublisherEmpty — the
// conservative policy says "never fire ownership_mismatch without
// publisher evidence." An empty publisherIDs slice must degrade to
// "ok" even for a corporate owner.
func TestClassify_GitHub_NoMismatchWhenPublisherEmpty(t *testing.T) {
	t.Parallel()
	srv := newGitHubStub(t, func(r *http.Request) (int, string) {
		return http.StatusOK, `{"archived": false}`
	})
	c := NewRepoLivenessChecker(nil, nil, WithAPIBaseOverride("github", srv.URL))
	got := c.Classify(context.Background(), "https://github.com/google/angular", nil)
	if got.Status != RepoLinkStatusOK {
		t.Errorf("status with nil publishers: got %q, want %q", got.Status, RepoLinkStatusOK)
	}
	got = c.Classify(context.Background(), "https://github.com/google/angular", []string{})
	if got.Status != RepoLinkStatusOK {
		t.Errorf("status with empty publishers: got %q, want %q", got.Status, RepoLinkStatusOK)
	}
}

// TestClassify_Unknown_UnrecognisedHost — a self-hosted Gitea or
// corporate GitHub Enterprise URL must degrade to "unknown" rather
// than trying to hit an unsupported API surface.
func TestClassify_Unknown_UnrecognisedHost(t *testing.T) {
	t.Parallel()
	c := NewRepoLivenessChecker(nil, nil)
	for _, raw := range []string{
		"https://internal.example.com/team/tool",
		"https://git.kernel.org/linus/linux",
		"",
		"not-a-url",
	} {
		got := c.Classify(context.Background(), raw, nil)
		if got.Status != RepoLinkStatusUnknown {
			t.Errorf("input %q: got %q, want %q", raw, got.Status, RepoLinkStatusUnknown)
		}
	}
}

// TestClassify_GitLab_Archived mirrors the github archived case for
// the gitlab backend — verify the gitlab.com/api/v4/projects endpoint
// is contacted.
func TestClassify_GitLab_Archived(t *testing.T) {
	t.Parallel()
	var calledPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"archived": true, "name":"dead-project"}`))
	}))
	t.Cleanup(srv.Close)
	c := NewRepoLivenessChecker(nil, nil, WithAPIBaseOverride("gitlab", srv.URL))
	got := c.Classify(context.Background(), "https://gitlab.com/acme/dead-project", nil)
	if got.Status != RepoLinkStatusArchived {
		t.Errorf("status: got %q, want %q", got.Status, RepoLinkStatusArchived)
	}
	// Must be URL-encoded "acme/dead-project".
	if !strings.Contains(calledPath, "/api/v4/projects/") {
		t.Errorf("unexpected path %q", calledPath)
	}
	encoded, _ := url.QueryUnescape(strings.TrimPrefix(calledPath, "/api/v4/projects/"))
	if encoded != "acme/dead-project" {
		t.Errorf("project path: got %q, want %q", encoded, "acme/dead-project")
	}
}

// TestClassify_Bitbucket_OKWithoutArchivedFlag — bitbucket's public
// 2.0 API doesn't expose an "archived" flag, so a 200 always
// classifies as ok (the checker falls through to ownership_match
// evaluation, which here returns false).
func TestClassify_Bitbucket_OKWithoutArchivedFlag(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"app"}`))
	}))
	t.Cleanup(srv.Close)
	c := NewRepoLivenessChecker(nil, nil, WithAPIBaseOverride("bitbucket", srv.URL))
	got := c.Classify(context.Background(), "https://bitbucket.org/team/app", nil)
	if got.Status != RepoLinkStatusOK {
		t.Errorf("status: got %q, want %q", got.Status, RepoLinkStatusOK)
	}
}

// TestClassify_Bitbucket_Missing — 404 returns missing.
func TestClassify_Bitbucket_Missing(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := NewRepoLivenessChecker(nil, nil, WithAPIBaseOverride("bitbucket", srv.URL))
	got := c.Classify(context.Background(), "https://bitbucket.org/team/deleted", nil)
	if got.Status != RepoLinkStatusMissing {
		t.Errorf("status: got %q, want %q", got.Status, RepoLinkStatusMissing)
	}
}

// TestParseRepoURL exercises the SSH form, git+ prefix, and .git
// suffix commonly seen in npm `repository.url`. Regression here
// would silently bypass the enricher.
func TestParseRepoURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in        string
		wantHost  string
		wantOwner string
		wantRepo  string
		wantKind  string
	}{
		{"https://github.com/lodash/lodash.git", "github.com", "lodash", "lodash", "github"},
		{"git+https://github.com/a/b.git", "github.com", "a", "b", "github"},
		{"git@github.com:a/b.git", "github.com", "a", "b", "github"},
		{"https://gitlab.com/grp/proj", "gitlab.com", "grp", "proj", "gitlab"},
		{"https://bitbucket.org/team/repo", "bitbucket.org", "team", "repo", "bitbucket"},
		{"", "", "", "", ""},
		{"https://github.com/justowner", "", "", "", ""},
		{"https://internal.example.com/a/b", "", "", "", ""},
	}
	for _, c := range cases {
		h, o, r, k := parseRepoURL(c.in)
		if h != c.wantHost || o != c.wantOwner || r != c.wantRepo || k != c.wantKind {
			t.Errorf("parseRepoURL(%q) = (%q,%q,%q,%q), want (%q,%q,%q,%q)",
				c.in, h, o, r, k, c.wantHost, c.wantOwner, c.wantRepo, c.wantKind)
		}
	}
}

// TestOwnershipMismatchConservative documents the full truth-table of
// the ownership-match fire rule. Any future relaxation of the
// conservative stance should update this test first.
func TestOwnershipMismatchConservative(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		owner      string
		publishers []string
		want       bool
	}{
		{"corporate + gmail publisher", "google", []string{"imposter@gmail.com"}, true},
		{"corporate + outlook publisher", "microsoft", []string{"x@outlook.com"}, true},
		{"corporate + corporate email", "google", []string{"dev@google.com"}, false},
		{"corporate + no publishers", "google", nil, false},
		{"non-corporate + gmail publisher", "alice", []string{"x@gmail.com"}, false},
		{"non-corporate + corporate email", "alice", []string{"x@acme.com"}, false},
		{"corporate + bare domain match", "google", []string{"gmail.com"}, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ownershipMismatch(tc.owner, tc.publishers); got != tc.want {
				t.Errorf("ownershipMismatch(%q, %v) = %v, want %v",
					tc.owner, tc.publishers, got, tc.want)
			}
		})
	}
}

// TestNilCheckerClassifyDoesNotPanic — callers receive a nil
// checker when the feature is disabled; Classify must degrade
// gracefully to "unknown".
func TestNilCheckerClassifyDoesNotPanic(t *testing.T) {
	t.Parallel()
	var c *RepoLivenessChecker
	got := c.Classify(context.Background(), "https://github.com/x/y", nil)
	if got.Status != RepoLinkStatusUnknown {
		t.Errorf("nil checker: got %q, want %q", got.Status, RepoLinkStatusUnknown)
	}
}

// TestClassify_GitHub_SurfacesArchivedAndPushedAt locks in the
// secondary fields the maintenance enricher depends on: archived must
// arrive as &true (not a bare bool) and pushed_at must parse as an
// RFC3339 timestamp pointer. Together they let the risk engine fire
// repo-archived / abandoned-repo without a second HTTP round-trip.
func TestClassify_GitHub_SurfacesArchivedAndPushedAt(t *testing.T) {
	t.Parallel()
	srv := newGitHubStub(t, func(r *http.Request) (int, string) {
		return http.StatusOK, `{"archived": true, "pushed_at": "2025-01-15T10:00:00Z"}`
	})
	c := NewRepoLivenessChecker(nil, nil, WithAPIBaseOverride("github", srv.URL))
	got := c.Classify(context.Background(), "https://github.com/someone/sunset", nil)
	if got.Status != RepoLinkStatusArchived {
		t.Errorf("status: got %q, want %q", got.Status, RepoLinkStatusArchived)
	}
	if got.Archived == nil || *got.Archived != true {
		t.Errorf("Archived: got %v, want &true", got.Archived)
	}
	if got.LastCommitAt == nil {
		t.Fatal("LastCommitAt: got nil, want parsed time")
	}
	want, _ := time.Parse(time.RFC3339, "2025-01-15T10:00:00Z")
	if !got.LastCommitAt.Equal(want) {
		t.Errorf("LastCommitAt: got %v, want %v", got.LastCommitAt, want)
	}
}

// TestClassify_GitHub_MissingPushedAtStaysNil — when the upstream
// response omits pushed_at the result MUST keep LastCommitAt = nil
// rather than collapsing to time.Time{}. The risk engine reads nil as
// "unknown" and a zero-time would silently fire the abandoned-repo
// signal on every healthy repo.
func TestClassify_GitHub_MissingPushedAtStaysNil(t *testing.T) {
	t.Parallel()
	srv := newGitHubStub(t, func(r *http.Request) (int, string) {
		return http.StatusOK, `{"archived": false}`
	})
	c := NewRepoLivenessChecker(nil, nil, WithAPIBaseOverride("github", srv.URL))
	got := c.Classify(context.Background(), "https://github.com/lodash/lodash", nil)
	if got.Status != RepoLinkStatusOK {
		t.Errorf("status: got %q, want %q", got.Status, RepoLinkStatusOK)
	}
	if got.LastCommitAt != nil {
		t.Errorf("LastCommitAt: got %v, want nil", got.LastCommitAt)
	}
	if got.Archived == nil || *got.Archived != false {
		t.Errorf("Archived: got %v, want &false", got.Archived)
	}
}
