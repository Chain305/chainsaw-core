package provenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

// sigstoreVerifier is the minimal surface of sigstoreverify.Verifier that
// the OCI path uses. Tests can substitute a mock by overriding
// defaultSigstoreVerifier below — this lets A2's end-to-end test exercise
// the fetch-manifest-then-blob-then-verify chain without building a real
// Sigstore bundle in-process (which would require network I/O against the
// live TUF trust root).
type sigstoreVerifier interface {
	Verify(bundleJSON []byte, artifactSHA256 []byte) (*sigstoreverify.Identity, error)
}

// defaultSigstoreVerifier resolves the process-wide Verifier. Tests override
// this to inject a mock; production callers get sigstoreverify.Default which
// caches the live Sigstore trust root.
var defaultSigstoreVerifier = func(ctx context.Context) (sigstoreVerifier, error) {
	return sigstoreverify.Default(ctx)
}

// ociChecker looks for Sigstore attestations attached to an OCI image via
// the Referrers API (spec >= v1.1) and falls back to the legacy cosign
// `{digest}.sig` tag scheme for registries that don't implement it.
//
// Package name is expected as "registry/repository" or just "repository"
// (Docker Hub). Version is a tag or digest. If a tag is supplied we first
// resolve it via HEAD /v2/.../manifests/{tag}.
type ociChecker struct {
	client    *http.Client
	transport *OCITransport
	logger    *slog.Logger
	// scheme is overridable for tests against httptest servers that only
	// speak HTTP. Defaults to "https".
	scheme string
}

func newOCIChecker(client *http.Client, logger *slog.Logger) *ociChecker {
	return &ociChecker{
		client:    client,
		transport: NewOCITransport(client),
		logger:    logger,
		scheme:    "https",
	}
}

func (c *ociChecker) registryURL(registry, path string) string {
	s := c.scheme
	if s == "" {
		s = "https"
	}
	return fmt.Sprintf("%s://%s%s", s, registry, path)
}

func (c *ociChecker) Ecosystem() string { return "docker" }

const sigstoreArtifactType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// sigstoreLegacyArtifactType is the pre-v0.3 media type still emitted by
// some tooling (notably older cosign releases and registries that haven't
// rotated to the current Sigstore bundle spec). Accepted as a candidate
// referrer so we don't silently miss attestations on legacy publishers.
const sigstoreLegacyArtifactType = "application/vnd.dev.sigstore.bundle+json;version=0.1"

// isSigstoreArtifactType reports whether a referrer entry's artifactType
// is one we recognize as a Sigstore bundle. Matching is tolerant of
// whitespace around the parameter separator; the registry is free to
// normalize the parameter order so we only compare the leading media type
// and explicit version parameter.
func isSigstoreArtifactType(t string) bool {
	t = strings.TrimSpace(t)
	if t == sigstoreArtifactType {
		return true
	}
	// Match "application/vnd.dev.sigstore.bundle+json;version=0.1" with
	// any whitespace around the ';'.
	base, params, ok := strings.Cut(t, ";")
	if !ok {
		return false
	}
	if strings.TrimSpace(base) != "application/vnd.dev.sigstore.bundle+json" {
		return false
	}
	for _, p := range strings.Split(params, ";") {
		if strings.TrimSpace(p) == "version=0.1" {
			return true
		}
	}
	return false
}

func (c *ociChecker) Check(ctx context.Context, packageName, version string) Result {
	registry, repo := splitOCIName(packageName)
	digest, err := c.resolveDigest(ctx, registry, repo, version)
	if err != nil {
		return Result{Status: StatusFailed, Ecosystem: "docker", Error: fmt.Sprintf("resolve digest: %v", err)}
	}

	// Fetch referrers filtered by Sigstore bundle artifact type.
	referrersURL := c.registryURL(registry, fmt.Sprintf("/v2/%s/referrers/%s?artifactType=%s",
		repo, digest, sigstoreArtifactType))
	body, status, err := fetchOCIBytes(ctx, c.transport, referrersURL, 5<<20, "")
	if err != nil {
		if status == http.StatusNotFound {
			// No Referrers API — for GHCR and similar, fall back to the
			// GitHub attestations API if we can recognize the registry.
			if registry == "ghcr.io" {
				return c.checkGitHubAttestation(ctx, repo, digest)
			}
			return Result{Status: StatusMissing, Ecosystem: "docker"}
		}
		return Result{Status: StatusFailed, Ecosystem: "docker", Error: err.Error()}
	}

	// Response is an OCI image index with a `manifests` array. Each entry
	// that matches artifactType is a candidate attestation.
	var idx struct {
		Manifests []struct {
			Digest       string `json:"digest"`
			ArtifactType string `json:"artifactType"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(body, &idx); err != nil {
		return Result{Status: StatusFailed, Ecosystem: "docker", Error: fmt.Sprintf("parse referrers: %v", err)}
	}

	// Collect candidate Sigstore bundles. Registries MAY honor the
	// ?artifactType filter or return the full referrer set and leave the
	// client to filter; we do the filter defensively either way.
	var candidates []string
	for _, m := range idx.Manifests {
		if isSigstoreArtifactType(m.ArtifactType) {
			candidates = append(candidates, m.Digest)
		}
	}
	if len(candidates) == 0 {
		// GHCR sometimes returns an empty referrers index instead of 404.
		// Fall back to the GitHub attestations API when that's where the
		// bundle actually lives.
		if registry == "ghcr.io" {
			return c.checkGitHubAttestation(ctx, repo, digest)
		}
		return Result{Status: StatusMissing, Ecosystem: "docker"}
	}

	digestBytes, err := decodeHexDigest(digest)
	if err != nil {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "docker",
			AttestationType: "sigstore",
			Error:           err.Error(),
		}
	}

	// Walk every Sigstore candidate: the first one that verifies wins. If
	// none verify but at least one was located, surface the last verifier
	// error as StatusUnverified — the bundle was *found*, it just failed
	// the crypto check, which is a meaningfully different operator signal
	// from "registry refused us" (StatusFailed) or "no attestation exists"
	// (StatusMissing).
	var (
		verifier      sigstoreVerifier
		verifierErr   error
		fetchErr      error
		lastVerifyErr error
	)
	for _, refDigest := range candidates {
		bundleJSON, ferr := c.fetchOCIBundle(ctx, registry, repo, refDigest)
		if ferr != nil {
			// Network/transport error reaching the bundle — caller needs
			// to know "we couldn't fetch it," which is StatusFailed.
			fetchErr = ferr
			continue
		}
		if verifier == nil && verifierErr == nil {
			verifier, verifierErr = defaultSigstoreVerifier(ctx)
		}
		if verifierErr != nil {
			// Can't initialize the Sigstore trust root (e.g. offline, TUF
			// endpoint down). The bundle itself was located; we just
			// can't attest to it cryptographically.
			return Result{
				Status:          StatusUnverified,
				Ecosystem:       "docker",
				AttestationType: "sigstore",
				Error:           fmt.Sprintf("sigstore init: %v", verifierErr),
			}
		}
		id, verr := verifier.Verify(bundleJSON, digestBytes)
		if verr == nil {
			return Result{
				Status:          StatusVerified,
				Ecosystem:       "docker",
				AttestationType: "sigstore",
				SourceRepo:      id.SourceRepo,
				BuilderID:       id.BuilderID,
			}
		}
		if c.logger != nil {
			c.logger.Debug("docker sigstore verification failed",
				"registry", registry, "repo", repo, "digest", digest,
				"referrer", refDigest, "error", verr.Error())
		}
		lastVerifyErr = verr
	}

	// Every candidate either failed to fetch or failed to verify. Prefer
	// the "found but didn't verify" signal when we have it: StatusUnverified
	// is the contract for "bundle present, crypto check did not pass."
	if lastVerifyErr != nil {
		return Result{
			Status:          StatusUnverified,
			Ecosystem:       "docker",
			AttestationType: "sigstore",
			Error:           lastVerifyErr.Error(),
		}
	}
	// No bundle ever successfully fetched — report the transport failure.
	return Result{
		Status:          StatusFailed,
		Ecosystem:       "docker",
		AttestationType: "sigstore",
		Error:           fmt.Sprintf("fetch bundle: %v", fetchErr),
	}
}

// fetchOCIBundle resolves a referrer manifest to its actual Sigstore bundle
// bytes. The referrer itself is a small manifest that points to the bundle
// as its first (and typically only) layer.
func (c *ociChecker) fetchOCIBundle(ctx context.Context, registry, repo, manifestDigest string) ([]byte, error) {
	manifestURL := c.registryURL(registry, fmt.Sprintf("/v2/%s/manifests/%s", repo, manifestDigest))
	body, _, err := fetchOCIBytes(ctx, c.transport, manifestURL, 1<<20,
		"application/vnd.oci.image.manifest.v1+json")
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	var man struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(body, &man); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if len(man.Layers) == 0 {
		return nil, fmt.Errorf("referrer manifest has no layers")
	}
	blobURL := c.registryURL(registry, fmt.Sprintf("/v2/%s/blobs/%s", repo, man.Layers[0].Digest))
	bundle, _, err := fetchOCIBytes(ctx, c.transport, blobURL, 10<<20, "")
	if err != nil {
		return nil, fmt.Errorf("blob: %w", err)
	}
	return bundle, nil
}

// checkGitHubAttestation calls the GitHub attestations endpoint for a
// given image digest. Requires the repo path to map to a GitHub
// owner/repo — for ghcr.io this is the image name itself.
func (c *ociChecker) checkGitHubAttestation(ctx context.Context, repo, digest string) Result {
	// repo on ghcr.io is "owner/image"; the attestations API is keyed by
	// owner/repo where repo == the GitHub repo, which often matches the
	// image name but not always. Best-effort.
	owner, image := splitOCIRepo(repo)
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/attestations/%s",
		owner, image, digest)

	body, status, err := fetchBytes(ctx, c.client, apiURL, 5<<20)
	if err != nil {
		if isNotFound(status) {
			return Result{Status: StatusMissing, Ecosystem: "docker"}
		}
		return Result{Status: StatusFailed, Ecosystem: "docker", Error: err.Error()}
	}
	var wrap struct {
		Attestations []struct {
			Bundle json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil || len(wrap.Attestations) == 0 {
		return Result{Status: StatusMissing, Ecosystem: "docker"}
	}

	digestBytes, err := decodeHexDigest(digest)
	if err != nil {
		return Result{
			Status:          StatusUnverified,
			Ecosystem:       "docker",
			AttestationType: "sigstore",
			Error:           err.Error(),
		}
	}
	verifier, err := sigstoreverify.Default(ctx)
	if err != nil {
		return Result{
			Status:          StatusUnverified,
			Ecosystem:       "docker",
			AttestationType: "sigstore",
			Error:           fmt.Sprintf("sigstore init: %v", err),
		}
	}
	id, err := verifier.Verify([]byte(wrap.Attestations[0].Bundle), digestBytes)
	if err != nil {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "docker",
			AttestationType: "sigstore",
			Error:           err.Error(),
		}
	}
	return Result{
		Status:          StatusVerified,
		Ecosystem:       "docker",
		AttestationType: "sigstore",
		SourceRepo:      id.SourceRepo,
		BuilderID:       id.BuilderID,
	}
}

// resolveDigest returns a `sha256:…` digest for a tag or digest input. If
// version already starts with "sha256:" it's returned as-is.
func (c *ociChecker) resolveDigest(ctx context.Context, registry, repo, version string) (string, error) {
	if strings.HasPrefix(version, "sha256:") {
		return version, nil
	}
	manifestURL := c.registryURL(registry, fmt.Sprintf("/v2/%s/manifests/%s", repo, version))
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, manifestURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")
	resp, err := c.transport.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Swallow the body — we only care about the header.
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("HEAD manifest: HTTP %d", resp.StatusCode)
	}
	if digest := resp.Header.Get("Docker-Content-Digest"); digest != "" {
		return digest, nil
	}
	// C2: some registries (and proxy CDNs) don't set the header on HEAD.
	// Fall back to GET and hash the canonical manifest bytes.
	return c.resolveDigestByGet(ctx, manifestURL)
}

// resolveDigestByGet GETs the manifest and hashes its canonical bytes to
// derive a sha256 digest. Per the OCI distribution spec the digest is
// computed over the exact manifest bytes returned, so this is equivalent
// to whatever the registry would have put in Docker-Content-Digest.
func (c *ociChecker) resolveDigestByGet(ctx context.Context, manifestURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")
	resp, err := c.transport.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET manifest: HTTP %d", resp.StatusCode)
	}
	if digest := resp.Header.Get("Docker-Content-Digest"); digest != "" {
		return digest, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// splitOCIName splits "registry/owner/repo" or "owner/repo" (Docker Hub)
// into (registry, repoPath).
func splitOCIName(name string) (registry, repo string) {
	if !strings.Contains(name, "/") {
		return "registry-1.docker.io", "library/" + name
	}
	first := name[:strings.Index(name, "/")]
	// A registry component must contain a dot or colon (RFC says hostname).
	if strings.ContainsAny(first, ".:") {
		return first, name[len(first)+1:]
	}
	// Docker Hub with owner: "owner/repo".
	return "registry-1.docker.io", name
}

// splitOCIRepo splits "owner/image" into (owner, image). For longer paths
// like "owner/namespace/image" the first segment is the owner and the
// remainder becomes the image name.
func splitOCIRepo(repo string) (owner, image string) {
	if idx := strings.Index(repo, "/"); idx > 0 {
		return repo[:idx], repo[idx+1:]
	}
	return "", repo
}

func decodeHexDigest(digest string) ([]byte, error) {
	const prefix = "sha256:"
	if !strings.HasPrefix(digest, prefix) {
		return nil, fmt.Errorf("unsupported digest algorithm %q", digest)
	}
	return hex.DecodeString(digest[len(prefix):])
}

// fetchOCIBytes is fetchBytes routed through the OCI bearer-token
// transport. Use for anything behind /v2/ on a registry; use fetchBytes
// directly for GitHub API and other non-OCI endpoints.
//
// The returned HTTP status code distinguishes the two provenance error
// shapes that look similar at first glance: 404 means the artifact is
// genuinely absent (caller should return StatusMissing); any other
// non-2xx — including a final 401 after the transport's token exchange
// — means the registry refused us and the caller should return
// StatusFailed rather than silently StatusMissing.
func fetchOCIBytes(ctx context.Context, t *OCITransport, url string, limit int64, accept string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := t.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}
