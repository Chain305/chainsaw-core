package provenance

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

// huggingfaceChecker looks for an OpenSSF model-signing v1 sidecar
// (`model.sig`) at the given revision. If absent it falls back to commit
// GPG verification via the commits API.
//
// packageName is the repo path ("owner/model-name"); version is a ref or
// commit SHA (HuggingFace calls this a "revision").
type huggingfaceChecker struct {
	client  *http.Client
	logger  *slog.Logger
	baseURL string // overridable for tests; defaults to huggingface.co
}

func newHuggingFaceChecker(client *http.Client, logger *slog.Logger) *huggingfaceChecker {
	return &huggingfaceChecker{client: client, logger: logger, baseURL: "https://huggingface.co"}
}

func (c *huggingfaceChecker) Ecosystem() string { return "huggingface" }

func (c *huggingfaceChecker) Check(ctx context.Context, packageName, version string) Result {
	if version == "" {
		version = "main"
	}
	base := c.baseURL
	if base == "" {
		base = "https://huggingface.co"
	}
	sigURL := fmt.Sprintf("%s/%s/resolve/%s/model.sig", base, packageName, version)

	sigBytes, status, err := fetchBytes(ctx, c.client, sigURL, 2<<20)
	if err != nil {
		if isNotFound(status) {
			// No model.sig → try commit signature as a weaker signal.
			return c.tryCommitSig(ctx, packageName, version)
		}
		return Result{Status: StatusFailed, Ecosystem: "huggingface", Error: err.Error()}
	}

	// model-signing v1 bundles cover an in-toto manifest that lists every
	// file in the repo with its hash — the bundle does NOT cover the .sig
	// file itself. Without fetching the manifest (a larger change), we
	// can't run full cryptographic verification here. Report presence and
	// signer identity extracted from the Fulcio cert so the UI can still
	// attribute the signature, but mark the result StatusUnverified.
	id, err := sigstoreverify.InspectBundleIdentity(sigBytes)
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("huggingface bundle inspection failed",
				"package", packageName, "version", version, "url", sigURL, "error", err.Error())
		}
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "huggingface",
			AttestationType: "sigstore",
			Error:           fmt.Sprintf("inspect bundle: %v", err),
		}
	}
	return Result{
		Status:          StatusUnverified,
		Ecosystem:       "huggingface",
		AttestationType: "sigstore",
		SourceRepo:      id.SourceRepo,
		BuilderID:       id.BuilderID,
		Error:           "model-signing manifest verification not implemented",
	}
}

// tryCommitSig falls back to HuggingFace's commit GPG verification flag.
func (c *huggingfaceChecker) tryCommitSig(ctx context.Context, repo, rev string) Result {
	base := c.baseURL
	if base == "" {
		base = "https://huggingface.co"
	}
	apiURL := fmt.Sprintf("%s/api/models/%s/commits/%s", base, repo, rev)
	body, status, err := fetchBytes(ctx, c.client, apiURL, 1<<20)
	if err != nil {
		if isNotFound(status) {
			return Result{Status: StatusMissing, Ecosystem: "huggingface"}
		}
		return Result{Status: StatusFailed, Ecosystem: "huggingface", Error: err.Error()}
	}
	if !hasGpgVerifiedFlag(body) {
		return Result{Status: StatusMissing, Ecosystem: "huggingface"}
	}
	return Result{
		Status:          StatusUnverified,
		Ecosystem:       "huggingface",
		AttestationType: "pgp-commit",
		SourceRepo:      base + "/" + repo,
	}
}

// hasGpgVerifiedFlag is a substring check — HuggingFace emits both
// `"gpg_verified":true` and `"verified": true` across API shapes.
// Substring match is good enough without committing to a JSON schema
// we don't control.
func hasGpgVerifiedFlag(body []byte) bool {
	s := string(body)
	for _, needle := range []string{
		`"gpg_verified":true`,
		`"gpg_verified": true`,
		`"verified":true`,
		`"verified": true`,
	} {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
