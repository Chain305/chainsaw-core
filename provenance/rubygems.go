package provenance

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

// rubygemsChecker queries the RubyGems attestations API (gem push
// --attestation, shipped 2024; auto-attestation in 2025) and verifies the
// resulting Sigstore bundle. When no Sigstore attestation is present, it
// falls back to the legacy `gem cert` X.509 detached signature flow
// implemented in x509rubygems.go (mirrors the maven sigstore →
// pgp-detached fallback in maven.go).
//
// Future: validate the gem-cert chain against rubygems.org's known
// signing keys when that registry exists; today the cert is gem-bundled
// and self-issued, so verification is "internal consistency only."
type rubygemsChecker struct {
	client *http.Client
	logger *slog.Logger
}

func newRubyGemsChecker(client *http.Client, logger *slog.Logger) *rubygemsChecker {
	return &rubygemsChecker{client: client, logger: logger}
}

func (c *rubygemsChecker) Ecosystem() string { return "rubygems" }

func (c *rubygemsChecker) Check(ctx context.Context, packageName, version string) Result {
	encodedPkg := url.PathEscape(packageName)
	encodedVer := url.PathEscape(version)
	metaURL := fmt.Sprintf("https://rubygems.org/api/v2/gems/%s/versions/%s.json", encodedPkg, encodedVer)

	body, err := fetchJSON(ctx, c.client, metaURL)
	if err != nil {
		if status := statusFromErr(err); status == http.StatusNotFound {
			return Result{Status: StatusMissing, Ecosystem: "rubygems"}
		}
		return Result{Status: StatusFailed, Ecosystem: "rubygems", Error: err.Error()}
	}

	bundleURL, bundleBytes, gemSHA256 := extractRubyGemsAttestation(body)
	if bundleURL == "" && bundleBytes == nil {
		// No Sigstore attestation — fall back to legacy gem-cert.
		return c.tryGemCert(ctx, encodedPkg, encodedVer)
	}

	if bundleBytes == nil {
		fetched, status, err := fetchBytes(ctx, c.client, bundleURL, 1<<20)
		if err != nil {
			if isNotFound(status) {
				return Result{Status: StatusMissing, Ecosystem: "rubygems"}
			}
			return Result{
				Status:          StatusFailed,
				Ecosystem:       "rubygems",
				AttestationType: "sigstore",
				Error:           fmt.Sprintf("fetch bundle: %v", err),
			}
		}
		bundleBytes = fetched
	}

	// Prefer the SHA from the API response; fall back to streaming the gem.
	var digest [32]byte
	if gemSHA256 != "" {
		raw, err := hex.DecodeString(gemSHA256)
		if err == nil && len(raw) == 32 {
			copy(digest[:], raw)
		}
	}
	if digest == ([32]byte{}) {
		gemURL := fmt.Sprintf("https://rubygems.org/gems/%s-%s.gem", encodedPkg, encodedVer)
		digest, err = fetchSHA256(ctx, c.client, gemURL)
		if err != nil {
			return Result{
				Status:          StatusFailed,
				Ecosystem:       "rubygems",
				AttestationType: "sigstore",
				Error:           fmt.Sprintf("fetch gem for digest: %v", err),
			}
		}
	}

	verifier, err := sigstoreverify.Default(ctx)
	if err != nil {
		return Result{
			Status:          StatusUnverified,
			Ecosystem:       "rubygems",
			AttestationType: "sigstore",
			Error:           fmt.Sprintf("sigstore init: %v", err),
		}
	}
	id, err := verifier.Verify(bundleBytes, digest[:])
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("rubygems sigstore verification failed",
				"package", packageName, "version", version, "error", err.Error())
		}
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "rubygems",
			AttestationType: "sigstore",
			Error:           err.Error(),
		}
	}
	return Result{
		Status:          StatusVerified,
		Ecosystem:       "rubygems",
		AttestationType: "sigstore",
		SourceRepo:      id.SourceRepo,
		BuilderID:       id.BuilderID,
	}
}

// tryGemCert downloads the .gem artifact and runs the legacy
// `gem cert` X.509 verification (see x509rubygems.go). Returns
// StatusMissing if the gem itself isn't on the registry, otherwise
// passes through the VerifyGemSignature verdict.
func (c *rubygemsChecker) tryGemCert(ctx context.Context, encodedPkg, encodedVer string) Result {
	gemURL := fmt.Sprintf("https://rubygems.org/gems/%s-%s.gem", encodedPkg, encodedVer)
	gemBytes, status, err := fetchBytes(ctx, c.client, gemURL, 256<<20)
	if err != nil {
		if isNotFound(status) {
			return Result{Status: StatusMissing, Ecosystem: "rubygems"}
		}
		return Result{Status: StatusFailed, Ecosystem: "rubygems", Error: fmt.Sprintf("fetch gem: %v", err)}
	}
	res, err := VerifyGemSignature(ctx, gemBytes)
	if err != nil {
		return Result{Status: StatusFailed, Ecosystem: "rubygems", Error: err.Error()}
	}
	if res.Status == StatusUnavailable {
		// No gem-cert signature either — surface as "missing" so the
		// caller treats this as "ecosystem supports it, this artifact
		// just doesn't have one" rather than "ecosystem unsupported".
		return Result{
			Status:    StatusMissing,
			Ecosystem: "rubygems",
			Warnings:  res.Warnings,
		}
	}
	return *res
}

// extractRubyGemsAttestation plucks the first attestation pointer and the
// gem's SHA-256 from the /gems/<name>/versions/<ver>.json response. The
// pointer is either a URL (bundleURL) or inline base64-decoded bytes
// (bundleBytes) — callers check which one is populated. Returns empty
// values when no attestation is present.
func extractRubyGemsAttestation(body map[string]any) (bundleURL string, bundleBytes []byte, gemSHA256 string) {
	if s, ok := body["sha"].(string); ok {
		gemSHA256 = s
	}
	atts, ok := body["attestations"].([]any)
	if !ok || len(atts) == 0 {
		// Some API variants use "attestation_url" as a single field.
		if u, ok := body["attestation_url"].(string); ok {
			bundleURL = u
		}
		return
	}
	for _, a := range atts {
		am, ok := a.(map[string]any)
		if !ok {
			continue
		}
		if u, ok := am["url"].(string); ok && u != "" {
			bundleURL = u
			return
		}
		// Some responses embed the bundle inline as base64.
		if inline, ok := am["bundle"].(string); ok && inline != "" {
			raw, err := base64.StdEncoding.DecodeString(inline)
			if err == nil && len(raw) > 0 {
				bundleBytes = raw
				return
			}
		}
	}
	return
}

// statusFromErr is a tiny helper that sniffs the stringified HTTP error
// for a status code. fetchJSON currently returns only "404 not found" or
// "HTTP <n>"; keep this tolerant.
func statusFromErr(err error) int {
	if err == nil {
		return 0
	}
	var n int
	s := err.Error()
	if _, scanErr := fmt.Sscanf(s, "HTTP %d", &n); scanErr == nil {
		return n
	}
	if s == "404 not found" || s == "404 Not Found" {
		return http.StatusNotFound
	}
	return 0
}
