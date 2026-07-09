package provenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

// Caps for the model-signing file-level integrity walk. A signed manifest
// can list an unbounded number of subjects; re-fetching every one would let
// a large repo turn a single provenance check into hundreds of megabytes of
// egress. On exceeding either cap we still return StatusVerified (the
// manifest signature is proven) but mark the file-level check partial via a
// warning, mirroring the plan's "verify the signature but mark file-level
// check partial" contract.
const (
	hfMaxManifestFiles     = 128
	hfMaxManifestBytes     = 256 << 20 // 256 MiB total across re-fetched files
	hfMaxManifestFileBytes = 2 << 30   // 2 GiB per file (weights are large)
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
	// maxFileBytes is the per-file re-fetch cap. Overridable for tests so a
	// truncation case can be exercised without serving a 2 GiB body; 0 means
	// use the package default hfMaxManifestFileBytes.
	maxFileBytes int64
	// verify is the crypto-verify seam. Production resolves the process-wide
	// sigstoreverify.Default; tests inject a stub so Check() can be driven to
	// StatusVerified / tamper-StatusFailed deterministically without the live
	// Sigstore trust root. nil means use the default.
	verify func(ctx context.Context, bundleJSON, artifactSHA256 []byte) (*sigstoreverify.Identity, error)
}

func newHuggingFaceChecker(client *http.Client, logger *slog.Logger) *huggingfaceChecker {
	return &huggingfaceChecker{client: client, logger: logger, baseURL: "https://huggingface.co"}
}

// fileCap returns the effective per-file re-fetch cap.
func (c *huggingfaceChecker) fileCap() int64 {
	if c.maxFileBytes > 0 {
		return c.maxFileBytes
	}
	return hfMaxManifestFileBytes
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

	// OpenSSF model-signing v1: the .sig is a Sigstore bundle whose DSSE
	// envelope payload IS an in-toto statement. That statement's subjects
	// list every file in the repo with its sha256. The statement is inline
	// in the bundle — there is NO separate manifest file to fetch.
	subjects, err := sigstoreverify.BundleSubjects(sigBytes)
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

	// Pick any subject digest as the artifact digest for cryptographic
	// verification. Verify() checks the DSSE signature against the trust
	// root AND that this digest is one of the statement's subjects — so a
	// single subject digest both authenticates the whole manifest and
	// proves the digest belongs to it. We then independently walk every
	// subject against the live repo bytes.
	var anchor []byte
	for _, s := range subjects {
		if len(s.SHA256) == 32 {
			anchor = s.SHA256
			break
		}
	}
	if anchor == nil {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "huggingface",
			AttestationType: "sigstore",
			Error:           "model-signing manifest has no sha256 subjects",
		}
	}

	verify := c.verify
	if verify == nil {
		verifier, err := sigstoreverify.Default(ctx)
		if err != nil {
			// Couldn't init the trust root — the bundle exists but we can't
			// prove it. Attribute the signer informationally (best-effort) and
			// degrade to StatusUnverified, matching the maven sigstore path.
			res := Result{
				Status:          StatusUnverified,
				Ecosystem:       "huggingface",
				AttestationType: "sigstore",
				Error:           fmt.Sprintf("sigstore init: %v", err),
			}
			if id, iErr := sigstoreverify.InspectBundleIdentity(sigBytes); iErr == nil {
				res.SourceRepo = id.SourceRepo
				res.BuilderID = id.BuilderID
			}
			return res
		}
		verify = func(ctx context.Context, bundleJSON, artifactSHA256 []byte) (*sigstoreverify.Identity, error) {
			return verifier.Verify(bundleJSON, artifactSHA256)
		}
	}

	id, err := verify(ctx, sigBytes, anchor)
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("huggingface sigstore verification failed",
				"package", packageName, "version", version, "url", sigURL, "error", err.Error())
		}
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "huggingface",
			AttestationType: "sigstore",
			Error:           err.Error(),
		}
	}

	// Manifest signature is cryptographically proven. Now confirm the live
	// repo files still match the signed digests. Any mismatch is a strong
	// tamper signal → StatusFailed.
	mismatch, partial := c.verifyManifestFiles(ctx, base, packageName, version, subjects)
	if mismatch != "" {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "huggingface",
			AttestationType: "sigstore",
			SourceRepo:      id.SourceRepo,
			BuilderID:       id.BuilderID,
			Error:           mismatch,
		}
	}
	res := Result{
		Status:          StatusVerified,
		Ecosystem:       "huggingface",
		AttestationType: "sigstore",
		SourceRepo:      id.SourceRepo,
		BuilderID:       id.BuilderID,
	}
	if partial != "" {
		res.Warnings = append(res.Warnings, partial)
	}
	return res
}

// verifyManifestFiles re-fetches each signed subject from the repo and
// confirms its sha256 matches the manifest.
//
//   - mismatch is non-empty when a fetched file's bytes do NOT match the
//     signed digest (tamper under a valid signature) → caller returns
//     StatusFailed. A subject that 404s in the live repo is treated as a
//     mismatch (the signed file is gone).
//   - partial is a non-empty warning when the walk stopped early on a cap
//     (too many files, or total bytes exceeded) — the caller keeps
//     StatusVerified but records that the file-level check is incomplete.
//
// Files are fetched newest-cap-first; a transient network error on a file
// (not a 404) short-circuits to a partial warning rather than a false
// tamper verdict, since we can't distinguish "changed" from "unreachable".
func (c *huggingfaceChecker) verifyManifestFiles(ctx context.Context, base, repo, rev string, subjects []sigstoreverify.Subject) (mismatch, partial string) {
	var (
		checked int
		total   int64
	)
	for _, s := range subjects {
		if len(s.SHA256) != 32 || s.Name == "" {
			continue // no digest / unnamed subject — nothing to re-check
		}
		if checked >= hfMaxManifestFiles {
			return "", fmt.Sprintf("file-level check partial: capped at %d files", hfMaxManifestFiles)
		}
		if total >= hfMaxManifestBytes {
			return "", fmt.Sprintf("file-level check partial: capped at %d bytes", hfMaxManifestBytes)
		}
		fileURL := fmt.Sprintf("%s/%s/resolve/%s/%s", base, repo, rev, s.Name)
		fileBytes, status, truncated, err := fetchBytesDetectTruncation(ctx, c.client, fileURL, c.fileCap())
		if err != nil {
			if isNotFound(status) {
				return fmt.Sprintf("signed file %q missing from repo", s.Name), ""
			}
			// Transient/unreachable — don't claim tamper we can't prove.
			return "", fmt.Sprintf("file-level check partial: %q unreachable: %v", s.Name, err)
		}
		if truncated {
			// The file is larger than our per-file cap (weight shards routinely
			// exceed it). Hashing the truncated prefix would manufacture a
			// false "tampered" verdict on a legitimate signed model. Downgrade
			// to a partial file-level check instead — a size cap must never
			// masquerade as a tamper signal.
			return "", fmt.Sprintf("file-level check partial: %q exceeds %d-byte per-file cap; hash not verified", s.Name, c.fileCap())
		}
		sum := sha256.Sum256(fileBytes)
		if !bytes.Equal(sum[:], s.SHA256) {
			return fmt.Sprintf("signed file %q sha256 mismatch (tampered)", s.Name), ""
		}
		checked++
		total += int64(len(fileBytes))
	}
	return "", ""
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
