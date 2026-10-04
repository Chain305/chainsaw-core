package supplychain

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/httpclient"
)

// Repo liveness classifications. Values mirror the CHECK constraint on
// package_metadata.repo_link_status added in the foundation migration.
const (
	RepoLinkStatusOK                = "ok"
	RepoLinkStatusArchived          = "archived"
	RepoLinkStatusMissing           = "missing"
	RepoLinkStatusOwnershipMismatch = "ownership_mismatch"
	RepoLinkStatusUnknown           = "unknown"
)

// DefaultRepoLivenessInterval is how often the intelligence repolink
// provider re-probes a repository it has already classified. A scan whose
// stored intelligence_reports row carries a classification younger than
// this (SupplyChain.RepoLinkLastChecked) re-uses it instead of calling the
// forge API; older, missing or unknown results are probed. Overridden by
// BootstrapConfig.RepoLivenessCheckInterval.
const DefaultRepoLivenessInterval = 7 * 24 * time.Hour

// RepoLivenessResult carries the output of a single classification.
//
// LastCommitAt and Archived are three-state: nil means "the upstream
// classifier did not surface this fact" (e.g. Bitbucket has no
// `archived` flag, or the response omitted `pushed_at`). Callers MUST
// treat nil as "unknown" — never collapse it to false / zero-time.
type RepoLivenessResult struct {
	Status    string
	CheckedAt time.Time
	// UnknownReason says why a probe that WAS attempted ended as unknown:
	// UnknownRateLimited, UnknownTransport or UnknownHTTP. It is "" when
	// Status is known, and also when the URL was never probed (an
	// unrecognised host), because there was no check to fail. Callers
	// surface it so a failed check is not mistaken for "no repo".
	UnknownReason string

	LastCommitAt *time.Time
	Archived     *bool

	// Stats are the repo's activity counts, decoded from the same GitHub
	// response the classification reads, so stars cost no request of
	// their own. Set only from a 2xx GitHub response; zero otherwise,
	// and zero means "not observed" to every consumer
	// (intelligence.mergeMaintenance, the store's carry-forward).
	Stats RepoStats
}

// Why an attempted probe ended as unknown (RepoLivenessResult.UnknownReason).
const (
	// UnknownRateLimited: the forge refused for budget — a 429, or a 403
	// carrying X-RateLimit-Remaining: 0 / RateLimit-Remaining: 0.
	UnknownRateLimited = "rate_limited"
	// UnknownTransport: no HTTP answer (dial, TLS, timeout, cancellation)
	// or a 2xx body that did not decode.
	UnknownTransport = "transport"
	// UnknownHTTP: any other non-2xx, non-404 answer — a 5xx, a 401/403
	// that is not a rate limit, or an unfollowed 3xx.
	UnknownHTTP = "http_status"
)

// RepoStats are display-only repository activity counts.
type RepoStats struct {
	Stars, Forks, OpenIssues, Subscribers int

	// CreatedAt is the repository's creation timestamp, nil when the
	// response omitted it or it did not parse — the same three-state
	// contract LastCommitAt carries, because "unknown" and "epoch" mean
	// opposite things to a freshness threshold.
	//
	// Decoded here for T-4 fetch 3. premium's suspicious_repo_stars needs
	// THREE dimensions with AND semantics — stars, repo AGE and days since
	// last push — and it currently gets them from a third GET of
	// /repos/{owner}/{repo} per scan. This probe already downloads that
	// exact body, so reading one more field from it costs nothing and is
	// the same move T-4 made for the counts below.
	//
	// NOT yet reachable by that provider: MaintenanceSection has no
	// repo-creation field and carryRepoStats cannot carry one, so the loop
	// is open by two fields in core/intelligence/report.go and
	// core/intelligence/store.go. Do NOT substitute
	// Maintenance.FirstPublishedAt for it — that is the package's earliest
	// RELEASE, not the repo's creation, and the two diverge whenever a
	// project migrated repositories or published before opening the source.
	CreatedAt *time.Time
}

// RepoLivenessChecker classifies repository URLs as ok / archived /
// missing / ownership_mismatch / unknown. It uses a bounded outbound
// HTTP client. GitLab and Bitbucket are called anonymously; GitHub carries
// CHAINSAW_GITHUB_TOKEN when it is set (see githubToken).
type RepoLivenessChecker struct {
	client *http.Client
	logger *slog.Logger
	// githubToken is CHAINSAW_GITHUB_TOKEN, read at construction. The GitHub
	// probe ran anonymously until 2026-09-27, on an IP whose 60/hour
	// anonymous budget the refresh path exhausts: 5,516 of ~14,000 refresher
	// calls to api.github.com a day came back 403, and 6,574 of 10,588
	// GitHub-hosted reports refreshed in two days carried no repo-link status
	// at all — the archived / missing signals silently off for 62% of them.
	githubToken string
	// apiBaseOverride, when non-nil, rewrites outbound API hostnames
	// (github.com / gitlab.com / bitbucket.org) to a test URL. Tests
	// use httptest.Server and inject a fixed base; production always
	// leaves this nil so the real upstream is hit.
	apiBaseOverride map[string]string
	// recheckInterval is how long a stored classification stands before
	// the intelligence repolink provider probes the repo again. Set by
	// Bootstrap from RepoLivenessCheckInterval; zero means the default.
	recheckInterval time.Duration
}

// RecheckInterval is how long a stored classification stands before the
// repo is probed again. Zero when the checker was built outside Bootstrap;
// callers then use DefaultRepoLivenessInterval.
func (c *RepoLivenessChecker) RecheckInterval() time.Duration {
	if c == nil {
		return 0
	}
	return c.recheckInterval
}

// RepoLivenessOption customises a checker. Currently the only hook is
// test-only API rewrite; production callers pass no options.
type RepoLivenessOption func(*RepoLivenessChecker)

// WithAPIBaseOverride redirects outbound requests for the given provider
// ("github", "gitlab", "bitbucket") to baseURL. Intended for tests
// backed by httptest.Server — NOT for production rewrite of upstream
// APIs.
func WithAPIBaseOverride(provider, baseURL string) RepoLivenessOption {
	return func(c *RepoLivenessChecker) {
		if c.apiBaseOverride == nil {
			c.apiBaseOverride = map[string]string{}
		}
		c.apiBaseOverride[provider] = strings.TrimRight(baseURL, "/")
	}
}

// NewRepoLivenessChecker constructs a liveness checker. httpClient may be
// nil, in which case a short-timeout client is created. The logger is
// used only for debug-level trace; failures never propagate to the
// caller.
func NewRepoLivenessChecker(httpClient *http.Client, logger *slog.Logger, opts ...RepoLivenessOption) *RepoLivenessChecker {
	if httpClient == nil {
		httpClient = httpclient.New(httpclient.WithTimeout(10 * time.Second))
	}
	if logger == nil {
		logger = slog.Default()
	}
	c := &RepoLivenessChecker{
		client:      httpClient,
		logger:      logger,
		githubToken: strings.TrimSpace(os.Getenv("CHAINSAW_GITHUB_TOKEN")),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// wellKnownPublicEmailDomains is the conservative shortlist of
// personal-email providers that, when combined with a clearly corporate
// repo owner (e.g. "google", "microsoft"), constitute HIGH-confidence
// evidence that the publisher is not authorised to publish on behalf of
// the owning org. Anything outside this list falls back to
// RepoLinkStatusOK — false positives on ownership_mismatch are costly
// (trust-score -20) so we bias toward non-fires.
var wellKnownPublicEmailDomains = map[string]struct{}{
	"gmail.com":      {},
	"googlemail.com": {},
	"yahoo.com":      {},
	"yahoo.co.uk":    {},
	"hotmail.com":    {},
	"outlook.com":    {},
	"live.com":       {},
	"msn.com":        {},
	"icloud.com":     {},
	"me.com":         {},
	"mac.com":        {},
	"aol.com":        {},
	"protonmail.com": {},
	"proton.me":      {},
	"pm.me":          {},
	"mail.com":       {},
	"yandex.com":     {},
	"qq.com":         {},
	"163.com":        {},
	"126.com":        {},
	"foxmail.com":    {},
	"gmx.com":        {},
	"gmx.net":        {},
	"zoho.com":       {},
	"fastmail.com":   {},
}

// corporateRepoOwners lists repo owners that are known corporate
// namespaces. When combined with a publisher using a public-email
// provider, we fire ownership_mismatch. This is intentionally a narrow
// shortlist — growing it is safe, shrinking it loses coverage.
var corporateRepoOwners = map[string]struct{}{
	"google":           {},
	"googleapis":       {},
	"microsoft":        {},
	"azure":            {},
	"apple":            {},
	"facebook":         {},
	"meta":             {},
	"amazon":           {},
	"aws":              {},
	"awslabs":          {},
	"netflix":          {},
	"uber":             {},
	"airbnb":           {},
	"twitter":          {},
	"x":                {},
	"linkedin":         {},
	"github":           {},
	"gitlab-org":       {},
	"bitbucket":        {},
	"atlassian":        {},
	"stripe":           {},
	"shopify":          {},
	"ibm":              {},
	"redhat":           {},
	"oracle":           {},
	"sap":              {},
	"salesforce":       {},
	"cloudflare":       {},
	"digitalocean":     {},
	"docker":           {},
	"dockerlibrary":    {},
	"kubernetes":       {},
	"cncf":             {},
	"mozilla":          {},
	"mozilla-services": {},
	"intel":            {},
	"nvidia":           {},
	"amd":              {},
	"openai":           {},
	"anthropics":       {},
	"hashicorp":        {},
	"elastic":          {},
	"elasticsearch":    {},
	"grafana":          {},
	"prometheus":       {},
	"kubernetes-sigs":  {},
	"tensorflow":       {},
	"pytorch":          {},
	"huggingface":      {},
}

// Classify probes repoURL and returns a liveness status. publisherIDs
// is an optional list of normalized publisher identifiers (typically
// email addresses or domain names) drawn from package metadata. When
// empty, ownership_mismatch is never fired — the check is strictly
// opt-in per the conservative policy on trust-score penalties.
//
// The method never returns an error: every non-classifiable path
// degrades to RepoLinkStatusUnknown so callers can persist a result
// without branching on failure.
//
// missing means the forge ANSWERED that the repository does not exist
// (404). A transport failure — DNS included — is unknown: every probe
// goes to a fixed SaaS API host (api.github.com, gitlab.com,
// api.bitbucket.org), so failing to resolve one is our network, never
// the repository (C-8). A repository's own domain is never dialled —
// self-hosted forges are not probed at all — so there is no host whose
// DNS failure could mean the repository is gone. If that changes, the
// distinction belongs there, not in a blanket DNS-error rule.
func (c *RepoLivenessChecker) Classify(ctx context.Context, repoURL string, publisherIDs []string) RepoLivenessResult {
	now := time.Now().UTC()
	result := RepoLivenessResult{Status: RepoLinkStatusUnknown, CheckedAt: now}
	if c == nil {
		return result
	}
	trimmed := strings.TrimSpace(repoURL)
	if trimmed == "" {
		return result
	}

	host, owner, repo, kind := parseRepoURL(trimmed)
	if host == "" || kind == "" {
		// Non-recognised host (self-hosted Gitea, corporate GitHub
		// Enterprise, etc.). We don't try to classify those — the
		// surface area of one-off APIs isn't worth the maintenance
		// burden and the conservative policy says "unknown on
		// uncertainty".
		return result
	}

	switch kind {
	case "github":
		return c.classifyGitHub(ctx, owner, repo, publisherIDs, now)
	case "gitlab":
		return c.classifyGitLab(ctx, host, owner, repo, publisherIDs, now)
	case "bitbucket":
		return c.classifyBitbucket(ctx, owner, repo, publisherIDs, now)
	}
	return result
}

// classifyGitHub calls the public GitHub API (no auth). 404 means
// missing, `archived: true` means archived, otherwise ok unless the
// ownership-match branch fires.
func (c *RepoLivenessChecker) classifyGitHub(ctx context.Context, owner, repo string, publisherIDs []string, now time.Time) RepoLivenessResult {
	base := c.baseURL("github", "https://api.github.com")
	apiURL := fmt.Sprintf("%s/repos/%s/%s", base, url.PathEscape(owner), url.PathEscape(repo))
	body, status, limited, err := c.fetchJSON(ctx, apiURL, c.githubToken)
	if err != nil {
		return unknownAfter(now, limited, err)
	}
	if status == http.StatusNotFound {
		return RepoLivenessResult{Status: RepoLinkStatusMissing, CheckedAt: now}
	}
	if status < 200 || status >= 300 {
		// 401/403 on a public repo means unusual — don't penalise.
		return unknownAfter(now, limited, nil)
	}
	archived, archivedOK := body["archived"].(bool)
	// pushed_at is GitHub's last-commit timestamp on the default branch.
	// It's an RFC3339 string; on parse failure we leave the pointer nil
	// rather than collapsing to a zero time, preserving the three-state
	// "unknown vs known" contract the risk engine depends on.
	lastCommit := parseRFC3339Pointer(body["pushed_at"])
	var archivedPtr *bool
	if archivedOK {
		a := archived
		archivedPtr = &a
	}
	res := RepoLivenessResult{Status: RepoLinkStatusOK, CheckedAt: now, LastCommitAt: lastCommit, Archived: archivedPtr, Stats: githubRepoStats(body)}
	if archived {
		res.Status = RepoLinkStatusArchived
	} else if ownershipMismatch(owner, publisherIDs) {
		res.Status = RepoLinkStatusOwnershipMismatch
	}
	return res
}

// githubRepoStats reads the activity counts off a /repos/{o}/{r} body.
// subscribers_count is absent on some responses; watchers_count stands in,
// as the registry-metadata stars fetch this replaced did.
func githubRepoStats(body map[string]any) RepoStats {
	n := func(k string) int {
		f, _ := body[k].(float64)
		return int(f)
	}
	st := RepoStats{Stars: n("stargazers_count"), Forks: n("forks_count"), OpenIssues: n("open_issues_count"), Subscribers: n("subscribers_count")}
	if st.Subscribers == 0 {
		st.Subscribers = n("watchers_count")
	}
	// Same parser as pushed_at, so a malformed stamp stays nil rather than
	// collapsing to the zero time and reading as a 2,000-year-old repo.
	st.CreatedAt = parseRFC3339Pointer(body["created_at"])
	return st
}

// classifyGitLab calls the GitLab project API (no auth) with the
// URL-encoded "owner/repo" path. host may be gitlab.com or a self-
// hosted gitlab-* instance; we only attempt classification for the
// public gitlab.com surface and degrade to unknown elsewhere.
func (c *RepoLivenessChecker) classifyGitLab(ctx context.Context, host, owner, repo string, publisherIDs []string, now time.Time) RepoLivenessResult {
	if host != "gitlab.com" {
		return RepoLivenessResult{Status: RepoLinkStatusUnknown, CheckedAt: now}
	}
	projectPath := url.PathEscape(owner + "/" + repo)
	base := c.baseURL("gitlab", "https://gitlab.com")
	apiURL := fmt.Sprintf("%s/api/v4/projects/%s", base, projectPath)
	body, status, limited, err := c.fetchJSON(ctx, apiURL, "")
	if err != nil {
		return unknownAfter(now, limited, err)
	}
	if status == http.StatusNotFound {
		return RepoLivenessResult{Status: RepoLinkStatusMissing, CheckedAt: now}
	}
	if status < 200 || status >= 300 {
		return unknownAfter(now, limited, nil)
	}
	archived, archivedOK := body["archived"].(bool)
	// GitLab exposes `last_activity_at` (RFC3339), which tracks the
	// most recent activity on the project — close enough to a "last
	// commit" signal for the abandonment heuristic. Same nil-on-error
	// contract as the GitHub branch.
	lastCommit := parseRFC3339Pointer(body["last_activity_at"])
	var archivedPtr *bool
	if archivedOK {
		a := archived
		archivedPtr = &a
	}
	if archived {
		return RepoLivenessResult{Status: RepoLinkStatusArchived, CheckedAt: now, LastCommitAt: lastCommit, Archived: archivedPtr}
	}
	if ownershipMismatch(owner, publisherIDs) {
		return RepoLivenessResult{Status: RepoLinkStatusOwnershipMismatch, CheckedAt: now, LastCommitAt: lastCommit, Archived: archivedPtr}
	}
	return RepoLivenessResult{Status: RepoLinkStatusOK, CheckedAt: now, LastCommitAt: lastCommit, Archived: archivedPtr}
}

// classifyBitbucket does not expose an `archived` flag via the public
// 2.0 API, so we only distinguish missing vs ok. Ownership match still
// fires when publisher evidence is strong.
func (c *RepoLivenessChecker) classifyBitbucket(ctx context.Context, owner, repo string, publisherIDs []string, now time.Time) RepoLivenessResult {
	base := c.baseURL("bitbucket", "https://api.bitbucket.org")
	apiURL := fmt.Sprintf("%s/2.0/repositories/%s/%s",
		base, url.PathEscape(owner), url.PathEscape(repo))
	_, status, limited, err := c.fetchJSON(ctx, apiURL, "")
	if err != nil {
		return unknownAfter(now, limited, err)
	}
	if status == http.StatusNotFound {
		return RepoLivenessResult{Status: RepoLinkStatusMissing, CheckedAt: now}
	}
	if status < 200 || status >= 300 {
		return unknownAfter(now, limited, nil)
	}
	if ownershipMismatch(owner, publisherIDs) {
		return RepoLivenessResult{Status: RepoLinkStatusOwnershipMismatch, CheckedAt: now}
	}
	return RepoLivenessResult{Status: RepoLinkStatusOK, CheckedAt: now}
}

// unknownAfter is the unknown result of an attempted probe, with the reason.
func unknownAfter(now time.Time, limited bool, err error) RepoLivenessResult {
	reason := UnknownHTTP
	switch {
	case limited:
		reason = UnknownRateLimited
	case err != nil:
		reason = UnknownTransport
	}
	return RepoLivenessResult{Status: RepoLinkStatusUnknown, CheckedAt: now, UnknownReason: reason}
}

// baseURL returns the production base URL for a provider unless a test
// override has been installed via WithAPIBaseOverride.
func (c *RepoLivenessChecker) baseURL(provider, production string) string {
	if c == nil || c.apiBaseOverride == nil {
		return production
	}
	if override, ok := c.apiBaseOverride[provider]; ok && override != "" {
		return override
	}
	return production
}

// fetchJSON performs a GET and parses the body as JSON. It returns the
// decoded body, the HTTP status, and any transport error. Non-2xx
// statuses are NOT returned as errors — callers branch on status.
// fetchJSON GETs u. bearer, when non-empty, is sent as the Authorization
// header; only the GitHub probe passes one.
func (c *RepoLivenessChecker) fetchJSON(ctx context.Context, u, bearer string) (map[string]any, int, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "chainsaw-repo-liveness/1.0")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, false, err
	}
	defer resp.Body.Close()
	limited := resp.StatusCode == http.StatusTooManyRequests ||
		(resp.StatusCode == http.StatusForbidden &&
			(resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("RateLimit-Remaining") == "0"))
	var body map[string]any
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return nil, resp.StatusCode, limited, err
		}
	}
	return body, resp.StatusCode, limited, nil
}

// parseRFC3339Pointer extracts an RFC3339-formatted timestamp from a
// decoded-JSON value (typed `any`) and returns it as a *time.Time. A
// missing field, non-string value, empty string, or parse error all
// degrade to nil — preserving the three-state contract on
// RepoLivenessResult.LastCommitAt (nil = unknown vs &t = known).
func parseRFC3339Pointer(v any) *time.Time {
	s, ok := v.(string)
	if !ok || s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

// parseRepoURL extracts (host, owner, repo, kind) from a common
// repository URL shape. Kind is one of "github", "gitlab",
// "bitbucket", or "" for unrecognised hosts.
func parseRepoURL(raw string) (host, owner, repo, kind string) {
	// Strip common prefixes (git+, ssh:, git:) and ".git" suffix.
	s := strings.TrimSpace(raw)
	// Maven <scm> URLs carry an "scm:<provider>:" prefix
	// ("scm:git:git@github.com:o/r.git", "scm:git@github.com:o/r.git" as
	// org.grails:grails-core writes it). Only the URL after it is the repo.
	if rest, ok := strings.CutPrefix(s, "scm:"); ok {
		s = rest
		for _, prov := range []string{"git:", "svn:", "hg:"} {
			s = strings.TrimPrefix(s, prov)
		}
	}
	// npm's host shorthands ("github:o/r", "gitlab:g/p", "bitbucket:o/r").
	for prefix, host := range map[string]string{"github:": "github.com", "gitlab:": "gitlab.com", "bitbucket:": "bitbucket.org"} {
		if rest, ok := strings.CutPrefix(s, prefix); ok && !strings.HasPrefix(rest, "//") {
			s = "https://" + host + "/" + rest
		}
	}
	s = strings.TrimPrefix(s, "git+")
	s = strings.TrimPrefix(s, "git://")
	// "ssh://git@github.com:o/r.git" mixes a scheme with the scp-style
	// colon, which url.Parse reads as a port and rejects. A colon after the
	// host that is not followed by a port number is a path separator.
	if i := strings.Index(s, "://"); i >= 0 {
		rest := s[i+3:]
		authority := rest
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			authority = rest[:slash]
		}
		hostStart := strings.LastIndexByte(authority, '@') + 1 // past any userinfo
		if colon := strings.IndexByte(authority[hostStart:], ':'); colon >= 0 {
			cut := hostStart + colon
			if after := rest[cut+1:]; after != "" && (after[0] < '0' || after[0] > '9') {
				s = s[:i+3] + rest[:cut] + "/" + after
			}
		}
	}
	// Rewrite "git@github.com:owner/repo" to the equivalent HTTPS URL
	// so url.Parse has something it can understand. The SSH form is
	// common in npm `repository.url` fields.
	if strings.HasPrefix(s, "git@") {
		at := strings.IndexByte(s, '@')
		colon := strings.IndexByte(s, ':')
		if colon > at {
			s = "https://" + s[at+1:colon] + "/" + s[colon+1:]
		}
	}
	// Default to https if no scheme.
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", "", "", ""
	}
	h := strings.ToLower(u.Hostname()) // drops userinfo and an ssh port
	path := strings.Trim(u.Path, "/")
	path = strings.TrimSuffix(path, ".git")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return "", "", "", ""
	}
	o := parts[0]
	r := parts[1]
	if o == "" || r == "" {
		return "", "", "", ""
	}
	if h == "gitlab.com" || strings.HasSuffix(h, ".gitlab.com") {
		// GitLab nests groups; parts[0]/parts[1] would probe a group as
		// if it were a project (C-9).
		o, r, ok := GitLabProjectPath(path)
		if !ok {
			return "", "", "", ""
		}
		return h, o, r, "gitlab"
	}
	switch {
	case h == "github.com" || strings.HasSuffix(h, ".github.com"):
		return h, o, r, "github"
	case h == "gitlab.com" || strings.HasSuffix(h, ".gitlab.com"):
		return h, o, r, "gitlab"
	case h == "bitbucket.org" || strings.HasSuffix(h, ".bitbucket.org"):
		return h, o, r, "bitbucket"
	}
	return "", "", "", ""
}

// RepoProbeTarget is where Classify would send repoURL: the forge host,
// owner (for GitLab, the full namespace) and repo it parses to. Kind is
// "" when Classify would not probe at all. Exported for read-only tooling
// that must parse exactly as production does (scripts/c9-flipcount).
func RepoProbeTarget(repoURL string) (host, owner, repo, kind string) {
	return parseRepoURL(strings.TrimSpace(repoURL))
}

// gitLabProjectRoutes are path segments GitLab reserves for project
// sub-pages (PROJECT_WILDCARD_ROUTES in GitLab's lib/gitlab/path_regex.rb),
// so no group or project can carry one of these names. They end a project
// path in pre-"/-/" URLs such as gitlab.com/group/project/tree/main.
var gitLabProjectRoutes = map[string]struct{}{
	"-": {}, "badges": {}, "blame": {}, "blob": {}, "builds": {}, "commits": {},
	"create": {}, "create_dir": {}, "edit": {}, "files": {}, "find_file": {},
	"new": {}, "preview": {}, "raw": {}, "refs": {}, "tree": {}, "update": {},
	"update_dir": {},
}

// GitLabProjectPath splits a gitlab.com URL path into its namespace and
// project. GitLab nests groups (group/subgroup/project): the project is the
// last segment before any route, and the namespace is everything before it.
// The ONE GitLab path rule: the liveness probe and the registry-metadata
// stars fetch (intelligence.parseForgeRepo) both call it, so they cannot
// name different projects for the same URL.
func GitLabProjectPath(path string) (namespace, project string, ok bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, seg := range parts {
		// From index 1: route names are illegal for groups as well as
		// projects, so gitlab.com/group/-/issues is a group page and must
		// not parse as project "issues" in namespace "group/-".
		if _, route := gitLabProjectRoutes[seg]; route && i >= 1 {
			parts = parts[:i]
			break
		}
	}
	if len(parts) < 2 {
		return "", "", false
	}
	project = strings.TrimSuffix(parts[len(parts)-1], ".git")
	namespace = strings.Join(parts[:len(parts)-1], "/")
	if parts[0] == "" || project == "" {
		return "", "", false
	}
	return namespace, project, true
}

// ownershipMismatch is intentionally conservative. It fires only when:
//   - the repo owner appears in the corporate-owner shortlist, AND
//   - at least one publisher identifier uses a well-known public-email
//     provider (gmail.com, outlook.com, etc.).
//
// Every other combination returns false — an empty publisher list, a
// corporate owner matching a verified corporate email domain, or a
// self-hosted owner name all yield `false`. The asymmetry is
// deliberate: a -20 trust-score delta needs HIGH-confidence evidence,
// and the cost of a false positive outweighs the cost of missing a
// subtle takeover.
// OwnershipStatus re-derives the ok / ownership_mismatch half of a
// classification for repoURL against the CURRENT publisher set, with no
// network: the owner comes from the URL and ownershipMismatch is local.
// Callers that reuse a stored Classify result must call this rather than
// trust a stored ok — a publisher change inside the reuse window is the
// takeover sc.repo_ownership_mismatch exists to catch. ok is false when the
// URL does not parse to a classifiable owner; the caller must then probe.
//
// It does not know whether the repo is archived: Classify ranks archived
// above ownership, so only re-derive a stored ok or ownership_mismatch.
func OwnershipStatus(repoURL string, publisherIDs []string) (status string, ok bool) {
	host, owner, _, kind := parseRepoURL(strings.TrimSpace(repoURL))
	if host == "" || kind == "" || owner == "" {
		return "", false
	}
	if ownershipMismatch(owner, publisherIDs) {
		return RepoLinkStatusOwnershipMismatch, true
	}
	return RepoLinkStatusOK, true
}

func ownershipMismatch(repoOwner string, publisherIDs []string) bool {
	if len(publisherIDs) == 0 {
		return false
	}
	owner := strings.ToLower(strings.TrimSpace(repoOwner))
	// A GitLab subgroup project is owned by its top-level group; the
	// corporate list names top-level owners.
	if i := strings.IndexByte(owner, '/'); i >= 0 {
		owner = owner[:i]
	}
	if _, ok := corporateRepoOwners[owner]; !ok {
		return false
	}
	for _, id := range publisherIDs {
		id = strings.ToLower(strings.TrimSpace(id))
		if id == "" {
			continue
		}
		domain := id
		if at := strings.IndexByte(id, '@'); at >= 0 {
			domain = id[at+1:]
		}
		if _, ok := wellKnownPublicEmailDomains[domain]; ok {
			return true
		}
	}
	return false
}
