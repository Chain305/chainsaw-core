package provenance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/chain305/chainsaw-core/httpclient"
)

// GitHubAPIFetcher is a production AttestationFetcher backed by the
// GitHub REST API. It calls
//
//	GET /repos/{owner}/{name}/attestations/sha256:{subject_digest}
//
// and returns the first published Sigstore bundle for that subject.
//
// Limitation: this v1 implementation assumes ref is already the
// hex-encoded SHA-256 of the artifact (or "sha256:<hex>"). Tag-to-commit
// resolution and tarball-hashing are a follow-up — for Wave 5, callers
// pre-resolve the ref to a commit/artifact digest and pass it directly.
// This keeps the fetcher minimal and fully testable while leaving room
// for a Resolver layer to slot in later.
type GitHubAPIFetcher struct {
	HTTP    *http.Client
	Token   string // optional; empty falls through to anonymous (rate-limited)
	BaseURL string // optional override; defaults to https://api.github.com
}

// NewGitHubAPIFetcher constructs a GitHubAPIFetcher. httpClient may be nil
// (defaults to a chainsaw-tuned client). token may be empty (anonymous
// calls allowed but rate-limited).
func NewGitHubAPIFetcher(httpClient *http.Client, token string) *GitHubAPIFetcher {
	if httpClient == nil {
		httpClient = httpclient.New()
	}
	return &GitHubAPIFetcher{HTTP: httpClient, Token: token}
}

// githubAttestationsResponse mirrors the documented response shape of
// GET /repos/{owner}/{repo}/attestations/{subject_digest}. Only the
// fields we need are modeled.
type githubAttestationsResponse struct {
	Attestations []struct {
		Bundle json.RawMessage `json:"bundle"`
	} `json:"attestations"`
}

// Fetch implements AttestationFetcher. ref is treated as the subject
// digest (with or without "sha256:" prefix). Returns ErrNoAttestation on
// HTTP 404 so the verifier maps it to StatusUnavailable.
func (f *GitHubAPIFetcher) Fetch(ctx context.Context, owner, name, ref string) ([]byte, string, error) {
	digest := strings.TrimPrefix(ref, "sha256:")
	if len(digest) != 64 {
		return nil, "", fmt.Errorf("github attestations: ref must be hex sha256 (64 chars); tag/commit resolution not yet implemented")
	}

	base := f.BaseURL
	if base == "" {
		base = "https://api.github.com"
	}
	url := fmt.Sprintf("%s/repos/%s/%s/attestations/sha256:%s", strings.TrimRight(base, "/"), owner, name, digest)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if f.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.Token)
	}

	resp, err := f.HTTP.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil, "", ErrNoAttestation
	case http.StatusOK:
		// continue
	default:
		return nil, "", fmt.Errorf("github attestations: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MiB cap
	if err != nil {
		return nil, "", fmt.Errorf("github attestations: read body: %w", err)
	}

	var parsed githubAttestationsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, "", fmt.Errorf("github attestations: parse response: %w", err)
	}
	if len(parsed.Attestations) == 0 || len(parsed.Attestations[0].Bundle) == 0 {
		return nil, "", ErrNoAttestation
	}
	return []byte(parsed.Attestations[0].Bundle), digest, nil
}

// Compile-time check.
var _ AttestationFetcher = (*GitHubAPIFetcher)(nil)
