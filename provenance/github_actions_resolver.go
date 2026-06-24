package provenance

// GitHub Actions ref resolver.
//
// Wave 5 shipped the AttestationFetcher (github_actions_fetcher.go) which
// requires the ref to ALREADY be a hex sha256 digest. That's not how
// callers reference Actions in the wild — they use tags ("v4"), branches
// ("main"), or short commit SHAs. This file adds the resolution layer
// that sits in front of the fetcher and turns a (owner, name, ref) triple
// into the digest the attestations API expects.
//
// Design choices:
//
//   - RefResolver is a narrow interface so production (GitHubAPIRefResolver)
//     and tests (fakes) plug in interchangeably. The verifier only needs
//     Resolve(ctx, owner, name, ref) -> digest.
//
//   - Digest semantics: we use the COMMIT SHA itself as the artifact
//     digest. The spec explicitly allows this ("some attestation schemes
//     key on commit SHA, not tarball SHA"), and for GitHub Actions the
//     attestations API accepts a commit SHA as the subject. The
//     alternative — hashing the release tarball — fetches MB-sized
//     zipballs on every miss, which is wasteful and slow. Commit SHA is
//     deterministic, free to compute, and round-trips through the
//     existing fetcher (which already accepts a 64-char hex string).
//
//   - DigestCache is a tiny optional interface so callers can plug in
//     anything from sync.Map to Redis. The default InMemoryDigestCache is
//     sync.Map-backed, process-lifetime, no eviction (sized for a typical
//     scan: a few thousand resolved refs per run).
//
//   - Resolution algorithm in priority order:
//       1. ref already a 64-char lowercase hex string -> return as-is.
//       2. GET /repos/.../git/ref/tags/{ref} -> follow tag.object.sha;
//          if it's an annotated tag (object.type == "tag"), follow
//          /repos/.../git/tags/{tag_sha} once more for the commit.
//       3. GET /repos/.../git/ref/heads/{ref} -> branch -> commit sha.
//       4. GET /repos/.../commits/{ref} -> commit sha (handles short
//          prefixes and bare commit refs).
//     Anything else returns ErrUnresolvableRef.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/chain305/chainsaw-core/httpclient"
)

// ErrUnresolvableRef is the sentinel returned when a ref cannot be mapped
// to an artifact digest — e.g., the tag doesn't exist, the repo is
// private, or the API is unreachable. Callers should treat this as a
// terminal "we don't know" rather than a verification failure.
var ErrUnresolvableRef = errors.New("ref could not be resolved to an artifact digest")

// RefResolver maps (owner, name, ref) where ref may be a tag, branch, or
// commit SHA into the artifact digest the GitHub attestations API
// expects. Implementations must return ErrUnresolvableRef (wrapped is
// fine) when the ref can't be mapped.
type RefResolver interface {
	Resolve(ctx context.Context, owner, name, ref string) (artifactDigest string, err error)
}

// DigestCache is a small interface so callers can plug in their own cache.
// Implementations must be safe for concurrent use.
type DigestCache interface {
	Get(commitSHA string) (digest string, ok bool)
	Set(commitSHA, digest string)
}

// InMemoryDigestCache is a sync.Map-backed DigestCache with no eviction.
// Sized for a typical scan run (a few thousand entries); restart drops
// the cache.
type InMemoryDigestCache struct {
	m sync.Map
}

// Get returns the cached digest for a commit SHA, if present.
func (c *InMemoryDigestCache) Get(commitSHA string) (string, bool) {
	v, ok := c.m.Load(commitSHA)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// Set stores a digest for a commit SHA.
func (c *InMemoryDigestCache) Set(commitSHA, digest string) {
	c.m.Store(commitSHA, digest)
}

// GitHubAPIRefResolver implements RefResolver via the GitHub REST API.
// See the file-level doc for the resolution algorithm and digest choice.
type GitHubAPIRefResolver struct {
	HTTPClient *http.Client
	Token      string
	// BaseURL allows tests to point at httptest.Server. Defaults to
	// https://api.github.com when empty.
	BaseURL string
	// Cache is optional. If nil, the resolver hits the API every call.
	Cache DigestCache
}

// NewGitHubAPIRefResolver constructs a GitHubAPIRefResolver with sane
// defaults. httpClient may be nil (a chainsaw-tuned client is created;
// the previous nil-fallback used http.DefaultClient with no timeout and
// MaxIdleConnsPerHost=2, which the audit flagged for repeat resolves).
// token may be empty (anonymous, rate-limited). cache may be nil.
func NewGitHubAPIRefResolver(httpClient *http.Client, token string, cache DigestCache) *GitHubAPIRefResolver {
	if httpClient == nil {
		httpClient = httpclient.New()
	}
	return &GitHubAPIRefResolver{HTTPClient: httpClient, Token: token, Cache: cache}
}

// Resolve implements RefResolver.
func (r *GitHubAPIRefResolver) Resolve(ctx context.Context, owner, name, ref string) (string, error) {
	if r == nil {
		return "", fmt.Errorf("%w: nil resolver", ErrUnresolvableRef)
	}
	ref = strings.TrimPrefix(ref, "sha256:")
	if isHexSHA256(ref) {
		// Already an artifact digest; pass through.
		return strings.ToLower(ref), nil
	}

	// 1. Tag lookup.
	if commit, err := r.resolveTag(ctx, owner, name, ref); err == nil {
		return r.commitToDigest(commit), nil
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "", err
	}

	// 2. Branch lookup.
	if commit, err := r.resolveBranch(ctx, owner, name, ref); err == nil {
		return r.commitToDigest(commit), nil
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "", err
	}

	// 3. Commit lookup (handles short prefixes and bare commit refs).
	if commit, err := r.resolveCommit(ctx, owner, name, ref); err == nil {
		return r.commitToDigest(commit), nil
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "", err
	}

	return "", fmt.Errorf("%w: %s/%s@%s", ErrUnresolvableRef, owner, name, ref)
}

// commitToDigest applies our digest convention (commit SHA == digest)
// with caching. Cache key is the commit SHA so different refs pointing at
// the same commit share a cache slot.
func (r *GitHubAPIRefResolver) commitToDigest(commitSHA string) string {
	commitSHA = strings.ToLower(commitSHA)
	if r.Cache != nil {
		if v, ok := r.Cache.Get(commitSHA); ok {
			return v
		}
		r.Cache.Set(commitSHA, commitSHA)
	}
	return commitSHA
}

// gitRefResponse mirrors GET /repos/{o}/{n}/git/ref/{ref}.
type gitRefResponse struct {
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
	} `json:"object"`
}

// gitTagResponse mirrors GET /repos/{o}/{n}/git/tags/{tag_sha} (used for
// annotated tags, where the ref's object points at a tag object instead
// of a commit).
type gitTagResponse struct {
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
	} `json:"object"`
}

// commitResponse mirrors GET /repos/{o}/{n}/commits/{ref}.
type commitResponse struct {
	SHA string `json:"sha"`
}

func (r *GitHubAPIRefResolver) resolveTag(ctx context.Context, owner, name, tag string) (string, error) {
	var ref gitRefResponse
	url := fmt.Sprintf("%s/repos/%s/%s/git/ref/tags/%s", r.baseURL(), owner, name, tag)
	if err := r.getJSON(ctx, url, &ref); err != nil {
		return "", err
	}
	if ref.Object.SHA == "" {
		return "", fmt.Errorf("%w: empty tag object", ErrUnresolvableRef)
	}
	if ref.Object.Type == "commit" {
		return ref.Object.SHA, nil
	}
	if ref.Object.Type == "tag" {
		// Annotated tag — follow one level of indirection.
		var tagObj gitTagResponse
		tagURL := fmt.Sprintf("%s/repos/%s/%s/git/tags/%s", r.baseURL(), owner, name, ref.Object.SHA)
		if err := r.getJSON(ctx, tagURL, &tagObj); err != nil {
			return "", err
		}
		if tagObj.Object.SHA == "" || tagObj.Object.Type != "commit" {
			return "", fmt.Errorf("%w: annotated tag did not resolve to commit", ErrUnresolvableRef)
		}
		return tagObj.Object.SHA, nil
	}
	return "", fmt.Errorf("%w: unknown tag object type %q", ErrUnresolvableRef, ref.Object.Type)
}

func (r *GitHubAPIRefResolver) resolveBranch(ctx context.Context, owner, name, branch string) (string, error) {
	var ref gitRefResponse
	url := fmt.Sprintf("%s/repos/%s/%s/git/ref/heads/%s", r.baseURL(), owner, name, branch)
	if err := r.getJSON(ctx, url, &ref); err != nil {
		return "", err
	}
	if ref.Object.SHA == "" || ref.Object.Type != "commit" {
		return "", fmt.Errorf("%w: branch did not resolve to commit", ErrUnresolvableRef)
	}
	return ref.Object.SHA, nil
}

func (r *GitHubAPIRefResolver) resolveCommit(ctx context.Context, owner, name, ref string) (string, error) {
	var c commitResponse
	url := fmt.Sprintf("%s/repos/%s/%s/commits/%s", r.baseURL(), owner, name, ref)
	if err := r.getJSON(ctx, url, &c); err != nil {
		return "", err
	}
	if c.SHA == "" {
		return "", fmt.Errorf("%w: empty commit sha", ErrUnresolvableRef)
	}
	return c.SHA, nil
}

func (r *GitHubAPIRefResolver) baseURL() string {
	if r.BaseURL != "" {
		return strings.TrimRight(r.BaseURL, "/")
	}
	return "https://api.github.com"
}

// getJSON performs a GET against the GitHub REST API and decodes the
// response into out. 404 is wrapped as ErrUnresolvableRef. Context errors
// are propagated unwrapped so callers can detect cancellation.
func (r *GitHubAPIRefResolver) getJSON(ctx context.Context, url string, out interface{}) error {
	client := r.HTTPClient
	if client == nil {
		client = httpclient.New()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if r.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.Token)
	}
	resp, err := client.Do(req)
	if err != nil {
		// Surface ctx errors directly so callers can errors.Is them.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: %v", ErrUnresolvableRef, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: 404", ErrUnresolvableRef)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d", ErrUnresolvableRef, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return fmt.Errorf("%w: read body: %v", ErrUnresolvableRef, err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: decode: %v", ErrUnresolvableRef, err)
	}
	return nil
}

// isHexSHA256 reports whether s is exactly 64 lowercase hex chars.
func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// Compile-time checks.
var (
	_ RefResolver = (*GitHubAPIRefResolver)(nil)
	_ DigestCache = (*InMemoryDigestCache)(nil)
)
