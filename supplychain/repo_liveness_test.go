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
		// C-9: GitLab nests groups. Before, every one of these probed the
		// group grp/sub as if it were a project.
		{"https://gitlab.com/grp/sub/proj", "gitlab.com", "grp/sub", "proj", "gitlab"},
		{"git+https://gitlab.com/grp/sub/deeper/proj.git", "gitlab.com", "grp/sub/deeper", "proj", "gitlab"},
		{"https://gitlab.com/grp/sub/proj/-/tree/main", "gitlab.com", "grp/sub", "proj", "gitlab"},
		// Pre-"/-/" route URLs must still end at the project, or the
		// nested parse would invent project "main" in namespace grp/proj/tree.
		{"https://gitlab.com/grp/proj/tree/master", "gitlab.com", "grp", "proj", "gitlab"},
		{"https://gitlab.com/grp/proj/blob/master/README.md", "gitlab.com", "grp", "proj", "gitlab"},
		// GitHub has no nesting: deep paths still resolve to owner/repo.
		{"https://github.com/owner/repo/tree/main/packages/x", "github.com", "owner", "repo", "github"},
		{"https://github.com/owner/repo/a/b/c", "github.com", "owner", "repo", "github"},
		// A group page is not a project; probing grp/- would 404 into missing.
		{"https://gitlab.com/grp/-/issues", "", "", "", ""},
		{"", "", "", "", ""},
		{"https://github.com/justowner", "", "", "", ""},
		{"https://internal.example.com/a/b", "", "", "", ""},
		// Non-https forms as registries store them (corpus-v1 rev5 rows).
		{"git://github.com/juliangruber/brace-expansion", "github.com", "juliangruber", "brace-expansion", "github"},
		{"ssh://git@github.com/AzureAD/passport-azure-ad", "github.com", "AzureAD", "passport-azure-ad", "github"},
		{"git+ssh://git@github.com/a/b.git", "github.com", "a", "b", "github"},
		{"git+https://github.com/a/b.git#v1.2.0", "github.com", "a", "b", "github"},
		// Maven <scm>: org.grails:grails-core writes the scp form behind
		// "scm:", others "scm:git:".
		{"scm:git@github.com:grails/grails-core.git", "github.com", "grails", "grails-core", "github"},
		{"scm:git:git@github.com:a/b.git", "github.com", "a", "b", "github"},
		{"scm:git:https://github.com/a/b.git", "github.com", "a", "b", "github"},
		{"scm:git:git://github.com/a/b.git", "github.com", "a", "b", "github"},
		// A scheme with the scp colon, and an explicit ssh port.
		{"git+ssh://git@github.com:a/b.git", "github.com", "a", "b", "github"},
		{"ssh://git@github.com:22/a/b.git", "github.com", "a", "b", "github"},
		// npm host shorthands.
		{"github:a/b", "github.com", "a", "b", "github"},
		{"bitbucket:team/repo", "bitbucket.org", "team", "repo", "bitbucket"},
		{"gitlab:grp/sub/proj", "gitlab.com", "grp/sub", "proj", "gitlab"},
		// Userinfo with a password must not be mistaken for the scp colon.
		{"https://user:token@github.com/a/b.git", "github.com", "a", "b", "github"},
		// Pages sites are not repositories; no guess is made.
		{"http://davetron5000.github.com/moocow", "", "", "", ""},
		{"http://pixaranimationstudios.github.io/ruby-jss/", "", "", "", ""},
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

// The GitHub probe carries CHAINSAW_GITHUB_TOKEN; GitLab and Bitbucket never
// receive it. Anonymous, the refresh path exhausts GitHub's 60/hour per-IP
// budget and 62% of GitHub-hosted reports lost their repo-link status to 403s
// (2026-09-27).
func TestClassify_GitHubSendsTheTokenOthersDoNot(t *testing.T) {
	t.Setenv("CHAINSAW_GITHUB_TOKEN", "ghp_test_token")
	got := map[string]string{}
	stub := func(name string) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got[name] = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"archived": false}`))
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	gh, gl, bb := stub("github"), stub("gitlab"), stub("bitbucket")
	c := NewRepoLivenessChecker(&http.Client{Timeout: 5 * time.Second}, nil,
		WithAPIBaseOverride("github", gh.URL),
		WithAPIBaseOverride("gitlab", gl.URL),
		WithAPIBaseOverride("bitbucket", bb.URL))
	for _, u := range []string{
		"https://github.com/lodash/lodash",
		"https://gitlab.com/group/project",
		"https://bitbucket.org/team/repo",
	} {
		c.Classify(context.Background(), u, nil)
	}
	if got["github"] != "Bearer ghp_test_token" {
		t.Errorf("GitHub Authorization = %q, want the bearer token", got["github"])
	}
	for _, name := range []string{"gitlab", "bitbucket"} {
		if v, ok := got[name]; !ok {
			t.Errorf("%s stub was never called", name)
		} else if v != "" {
			t.Errorf("%s received Authorization %q; the GitHub token must not leave GitHub", name, v)
		}
	}
}

// TestRepoLivenessCheckerDecodesRepoStats: stars come off the liveness
// response itself (T-4), so registry metadata need not fetch /repos too.
func TestRepoLivenessCheckerDecodesRepoStats(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/o/r":
			_, _ = w.Write([]byte(`{"archived":false,"stargazers_count":1234,"forks_count":56,"open_issues_count":7,"subscribers_count":89}`))
		case "/repos/o/watchers":
			_, _ = w.Write([]byte(`{"archived":true,"stargazers_count":3,"watchers_count":11}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	c := NewRepoLivenessChecker(srv.Client(), nil, WithAPIBaseOverride("github", srv.URL))

	if got := c.Classify(context.Background(), "https://github.com/o/r", nil).Stats; got != (RepoStats{Stars: 1234, Forks: 56, OpenIssues: 7, Subscribers: 89}) {
		t.Errorf("ok repo stats = %+v", got)
	}
	archived := c.Classify(context.Background(), "https://github.com/o/watchers", nil)
	if archived.Status != RepoLinkStatusArchived || archived.Stats != (RepoStats{Stars: 3, Subscribers: 11}) {
		t.Errorf("archived repo = %+v; want archived with stars 3 and watchers standing in for subscribers", archived)
	}
	// A failed fetch observes nothing: unknown, and no counts to write
	// over the stored ones.
	failed := c.Classify(context.Background(), "https://github.com/o/broken", nil)
	if failed.Status != RepoLinkStatusUnknown || failed.Stats != (RepoStats{}) {
		t.Errorf("failed fetch = %+v; want unknown with zero stats", failed)
	}
}

// TestClassify_GitLab_SubgroupProbesTheProject (C-9): the probe must name
// grp/sub/proj, not the group grp/sub. Before the fix this classified as
// missing — the API 404s a group path on /projects.
func TestClassify_GitLab_SubgroupProbesTheProject(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/api/v4/projects/"))
		if p != "gitlab-org/sub/proj" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"archived":false}`))
	}))
	t.Cleanup(srv.Close)
	c := NewRepoLivenessChecker(srv.Client(), nil, WithAPIBaseOverride("gitlab", srv.URL))

	if got := c.Classify(context.Background(), "https://gitlab.com/gitlab-org/sub/proj", nil); got.Status != RepoLinkStatusOK {
		t.Errorf("subgroup project: status %q, want ok from gitlab-org/sub/proj", got.Status)
	}
	// The newly reachable tightening: a corporate top-level group with a
	// public-email publisher now reaches the ownership check instead of
	// stopping at a false missing.
	got := c.Classify(context.Background(), "https://gitlab.com/gitlab-org/sub/proj", []string{"someone@gmail.com"})
	if got.Status != RepoLinkStatusOwnershipMismatch {
		t.Errorf("subgroup of a corporate group, gmail publisher: status %q, want ownership_mismatch", got.Status)
	}
	if st, ok := OwnershipStatus("https://gitlab.com/gitlab-org/sub/proj", []string{"someone@gmail.com"}); !ok || st != RepoLinkStatusOwnershipMismatch {
		t.Errorf("OwnershipStatus on a subgroup = (%q, %v); the owner is the top-level group", st, ok)
	}
}

// TestClassify_DNSFailureIsUnknown (C-8): every probe dials a fixed SaaS
// API host, so a name that does not resolve is our network, not the repo.
// Before the fix all three returned missing — a false sc.repo_missing.
func TestClassify_DNSFailureIsUnknown(t *testing.T) {
	t.Parallel()
	const dead = "http://chainsaw-c8-test.invalid" // RFC 2606: never resolves
	for _, tc := range []struct{ forge, repoURL string }{
		{"github", "https://github.com/o/r"},
		{"gitlab", "https://gitlab.com/g/p"},
		{"bitbucket", "https://bitbucket.org/w/r"},
	} {
		c := NewRepoLivenessChecker(nil, nil, WithAPIBaseOverride(tc.forge, dead))
		if got := c.Classify(context.Background(), tc.repoURL, nil); got.Status != RepoLinkStatusUnknown {
			t.Errorf("%s: DNS failure on the API host classified %q, want unknown", tc.forge, got.Status)
		}
	}
	// The other side of the rule: a self-hosted forge is never dialled, so
	// its DNS can never be read as the repository's absence.
	c := NewRepoLivenessChecker(nil, nil, WithAPIBaseOverride("gitlab", dead))
	if got := c.Classify(context.Background(), "https://gitlab.example-selfhosted.invalid/g/p", nil); got.Status != RepoLinkStatusUnknown {
		t.Errorf("self-hosted forge: status %q, want unknown without a probe", got.Status)
	}
}

// T-4 fetch 3 prerequisite: the probe must decode created_at off the body it
// already downloads.
//
// premium's suspicious_repo_stars is an AND of three dimensions — stars, repo
// AGE, days since last push — and it gets all three from a THIRD GET of
// /repos/{owner}/{repo} per scan. The first two are already supplied from this
// body (Stats.Stars, LastCommitAt); repo age was the only one missing, which
// is why the fetch could not simply be dropped.
//
// Reading it here costs zero requests. The loop is still open by two fields
// elsewhere — see the CreatedAt doc comment — so this is a prerequisite, not
// the saving.
func TestGitHubProbeDecodesRepoCreatedAt(t *testing.T) {
	created := "2019-03-04T05:06:07Z"
	body := map[string]any{
		"stargazers_count": float64(42),
		"pushed_at":        "2026-09-01T00:00:00Z",
		"created_at":       created,
	}

	st := githubRepoStats(body)

	if st.CreatedAt == nil {
		t.Fatal("created_at was not decoded; suspicious_repo_stars has no source for repo age " +
			"other than its own third GET of /repos")
	}
	want, err := time.Parse(time.RFC3339, created)
	if err != nil {
		t.Fatal(err)
	}
	if !st.CreatedAt.Equal(want) {
		t.Errorf("CreatedAt = %v, want %v", st.CreatedAt, want)
	}
	// The counts must keep working — this is an addition, not a rewrite.
	if st.Stars != 42 {
		t.Errorf("Stars = %d, want 42", st.Stars)
	}
}

// Three-state contract: absent and unparseable both stay nil. A zero time
// would read as a repo created in year 1, which is "maximally old" to a
// freshness threshold — the opposite of unknown, and it would silently
// suppress the signal rather than leave it quiet.
func TestGitHubProbeLeavesRepoCreatedAtNilWhenUnusable(t *testing.T) {
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"absent", map[string]any{"stargazers_count": float64(1)}},
		{"unparseable", map[string]any{"created_at": "not-a-timestamp"}},
		{"wrong type", map[string]any{"created_at": float64(12345)}},
	} {
		if got := githubRepoStats(tc.body).CreatedAt; got != nil {
			t.Errorf("%s: CreatedAt = %v, want nil — a zero or guessed time reads as an "+
				"ancient repo and inverts the freshness test", tc.name, got)
		}
	}
}
