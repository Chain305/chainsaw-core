package supplychain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
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

// DefaultRepoLivenessInterval is how often the liveness enricher will
// re-probe a repository that was previously classified. Values older
// than this in package_metadata.repo_link_last_checked_at trigger a
// refresh; rows within the window are skipped to bound outbound HTTP
// load.
const DefaultRepoLivenessInterval = 7 * 24 * time.Hour

// RepoLivenessResult carries the output of a single classification.
//
// LastCommitAt and Archived are three-state: nil means "the upstream
// classifier did not surface this fact" (e.g. Bitbucket has no
// `archived` flag, or the response omitted `pushed_at`). Callers MUST
// treat nil as "unknown" — never collapse it to false / zero-time.
type RepoLivenessResult struct {
	Status       string
	CheckedAt    time.Time
	LastCommitAt *time.Time
	Archived     *bool
}

// RepoLivenessChecker classifies repository URLs as ok / archived /
// missing / ownership_mismatch / unknown. It uses a bounded outbound
// HTTP client and intentionally never authenticates — private repos
// correctly fall back to `unknown`.
type RepoLivenessChecker struct {
	client *http.Client
	logger *slog.Logger
	// apiBaseOverride, when non-nil, rewrites outbound API hostnames
	// (github.com / gitlab.com / bitbucket.org) to a test URL. Tests
	// use httptest.Server and inject a fixed base; production always
	// leaves this nil so the real upstream is hit.
	apiBaseOverride map[string]string
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
	c := &RepoLivenessChecker{client: httpClient, logger: logger}
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
	body, status, err := c.fetchJSON(ctx, apiURL)
	if err != nil {
		if isDNSError(err) {
			return RepoLivenessResult{Status: RepoLinkStatusMissing, CheckedAt: now}
		}
		return RepoLivenessResult{Status: RepoLinkStatusUnknown, CheckedAt: now}
	}
	if status == http.StatusNotFound {
		return RepoLivenessResult{Status: RepoLinkStatusMissing, CheckedAt: now}
	}
	if status < 200 || status >= 300 {
		// 401/403 on a public repo means unusual — don't penalise.
		return RepoLivenessResult{Status: RepoLinkStatusUnknown, CheckedAt: now}
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
	if archived {
		return RepoLivenessResult{Status: RepoLinkStatusArchived, CheckedAt: now, LastCommitAt: lastCommit, Archived: archivedPtr}
	}
	if ownershipMismatch(owner, publisherIDs) {
		return RepoLivenessResult{Status: RepoLinkStatusOwnershipMismatch, CheckedAt: now, LastCommitAt: lastCommit, Archived: archivedPtr}
	}
	return RepoLivenessResult{Status: RepoLinkStatusOK, CheckedAt: now, LastCommitAt: lastCommit, Archived: archivedPtr}
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
	body, status, err := c.fetchJSON(ctx, apiURL)
	if err != nil {
		if isDNSError(err) {
			return RepoLivenessResult{Status: RepoLinkStatusMissing, CheckedAt: now}
		}
		return RepoLivenessResult{Status: RepoLinkStatusUnknown, CheckedAt: now}
	}
	if status == http.StatusNotFound {
		return RepoLivenessResult{Status: RepoLinkStatusMissing, CheckedAt: now}
	}
	if status < 200 || status >= 300 {
		return RepoLivenessResult{Status: RepoLinkStatusUnknown, CheckedAt: now}
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
	_, status, err := c.fetchJSON(ctx, apiURL)
	if err != nil {
		if isDNSError(err) {
			return RepoLivenessResult{Status: RepoLinkStatusMissing, CheckedAt: now}
		}
		return RepoLivenessResult{Status: RepoLinkStatusUnknown, CheckedAt: now}
	}
	if status == http.StatusNotFound {
		return RepoLivenessResult{Status: RepoLinkStatusMissing, CheckedAt: now}
	}
	if status < 200 || status >= 300 {
		return RepoLivenessResult{Status: RepoLinkStatusUnknown, CheckedAt: now}
	}
	if ownershipMismatch(owner, publisherIDs) {
		return RepoLivenessResult{Status: RepoLinkStatusOwnershipMismatch, CheckedAt: now}
	}
	return RepoLivenessResult{Status: RepoLinkStatusOK, CheckedAt: now}
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
func (c *RepoLivenessChecker) fetchJSON(ctx context.Context, u string) (map[string]any, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "chainsaw-repo-liveness/1.0")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	var body map[string]any
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return nil, resp.StatusCode, err
		}
	}
	return body, resp.StatusCode, nil
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

// isDNSError distinguishes "host does not resolve" from a transient
// network error so Classify can treat the former as `missing` (the
// repository URL points at a dead host) and the latter as `unknown`
// (we'll try again later).
func isDNSError(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "no such host") || strings.Contains(s, "NXDOMAIN")
}

// parseRepoURL extracts (host, owner, repo, kind) from a common
// repository URL shape. Kind is one of "github", "gitlab",
// "bitbucket", or "" for unrecognised hosts.
func parseRepoURL(raw string) (host, owner, repo, kind string) {
	// Strip common prefixes (git+, ssh:, git:) and ".git" suffix.
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "git+")
	s = strings.TrimPrefix(s, "git://")
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
	h := strings.ToLower(u.Host)
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
func ownershipMismatch(repoOwner string, publisherIDs []string) bool {
	if len(publisherIDs) == 0 {
		return false
	}
	owner := strings.ToLower(strings.TrimSpace(repoOwner))
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
