package provenance

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

// npmChecker queries the npm registry for Sigstore SLSA provenance
// attestations and crypto-verifies the bundle against the live Sigstore
// trust root, falling back to a last-known-good cache when Rekor/Fulcio
// is unreachable.
type npmChecker struct {
	client   *http.Client
	logger   *slog.Logger
	cacheFor func() *sigstoreverify.BundleCache
}

func newNPMChecker(client *http.Client, logger *slog.Logger, cacheFor func() *sigstoreverify.BundleCache) *npmChecker {
	if cacheFor == nil {
		cacheFor = func() *sigstoreverify.BundleCache { return nil }
	}
	return &npmChecker{client: client, logger: logger, cacheFor: cacheFor}
}

func (c *npmChecker) Ecosystem() string { return "npm" }

func (c *npmChecker) Check(ctx context.Context, packageName, version string) Result {
	encodedPkg := url.PathEscape(packageName)
	encodedVer := url.PathEscape(version)
	reqURL := fmt.Sprintf("https://registry.npmjs.org/-/npm/v1/attestations/%s@%s", encodedPkg, encodedVer)

	body, err := fetchJSON(ctx, c.client, reqURL)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return Result{Status: StatusMissing, Ecosystem: "npm"}
		}
		return Result{Status: StatusFailed, Ecosystem: "npm", Error: err.Error()}
	}

	attestations, ok := body["attestations"].([]any)
	if !ok || len(attestations) == 0 {
		return Result{Status: StatusMissing, Ecosystem: "npm"}
	}

	// Pick the SLSA provenance attestation (skip publish-attest and other
	// predicateTypes). npm stamps multiple attestations per release; the
	// SLSA one is what carries builder identity + source claims.
	bundleJSON, predicateType, found := pickSLSAAttestation(attestations)
	result := Result{
		Status:          StatusUnverified,
		Ecosystem:       "npm",
		AttestationType: "sigstore",
	}
	if !found {
		// Attestations exist but none are SLSA provenance (publish-attest
		// only). Surface presence; downstream policy can still match on
		// AttestationType when it cares about presence-only signals.
		return result
	}

	// Resolve the tarball SHA-256 needed to crypto-verify the bundle. npm
	// dist.integrity is base64-encoded sha512 by default; fetching the
	// tarball is the only way to get a verifier-compatible sha256. The
	// BundleCache means we only pay this cost once per (bundle, artifact).
	tarballSHA, err := c.tarballSHA256(ctx, packageName, version)
	if err != nil {
		// Bundle present but we can't get the artifact digest to verify
		// against. Surface identity from the bundle (informational) and
		// leave Status=StatusUnverified.
		noteUnverifiedBundle(&result, bundleJSON, fmt.Sprintf("resolve tarball sha256: %v", err))
		return result
	}

	vr, err := runSigstoreVerify(ctx, c.cacheFor(), bundleJSON, tarballSHA)
	if err != nil {
		// Verification attempted and failed. Distinguish "bundle malformed
		// or signed by an untrusted identity" (StatusFailed) from "we
		// couldn't reach Rekor at all" — but at the Result level both
		// surface as failure with Error populated.
		failed := Result{
			Status:          StatusFailed,
			Ecosystem:       "npm",
			AttestationType: "sigstore",
			Error:           err.Error(),
		}
		noteUnverifiedBundle(&failed, bundleJSON, "")
		// Promote Status back to Failed since noteUnverifiedBundle never
		// touches it but we want the failure to be visible.
		failed.Status = StatusFailed
		_ = predicateType // reserved for future per-predicate handling
		return failed
	}

	result.Status = StatusVerified
	applySigstoreToResult(&result, vr, bundleJSON)
	return result
}

// pickSLSAAttestation returns the first attestation entry that has an
// SLSA provenance predicate. The bundle is returned as raw JSON.
func pickSLSAAttestation(attestations []any) ([]byte, string, bool) {
	for _, att := range attestations {
		attMap, ok := att.(map[string]any)
		if !ok {
			continue
		}
		predicateType, _ := attMap["predicateType"].(string)
		if !strings.Contains(predicateType, "slsa") && !strings.Contains(predicateType, "provenance") {
			continue
		}
		bundle, ok := attMap["bundle"].(map[string]any)
		if !ok {
			continue
		}
		raw, err := json.Marshal(bundle)
		if err != nil {
			continue
		}
		return raw, predicateType, true
	}
	return nil, "", false
}

// tarballSHA256 fetches the npm tarball for (pkg, version) and computes
// its SHA-256 digest. Used as the artifact digest input to Sigstore
// bundle verification.
func (c *npmChecker) tarballSHA256(ctx context.Context, packageName, version string) ([]byte, error) {
	encodedPkg := url.PathEscape(packageName)
	encodedVer := url.PathEscape(version)
	metaURL := fmt.Sprintf("https://registry.npmjs.org/%s/%s", encodedPkg, encodedVer)
	meta, err := fetchJSON(ctx, c.client, metaURL)
	if err != nil {
		return nil, fmt.Errorf("fetch metadata: %w", err)
	}
	dist, ok := meta["dist"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("metadata missing dist")
	}
	tarballURL, _ := dist["tarball"].(string)
	if tarballURL == "" {
		return nil, fmt.Errorf("metadata missing dist.tarball")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tarballURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch tarball: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tarball fetch HTTP %d", resp.StatusCode)
	}
	h := sha256.New()
	// Cap at 200 MiB to keep memory bounded; npm packages above that are
	// vanishingly rare. If we ever hit one we'd surface as an error.
	if _, err := io.Copy(h, io.LimitReader(resp.Body, 200<<20)); err != nil {
		return nil, fmt.Errorf("read tarball: %w", err)
	}
	return h.Sum(nil), nil
}
