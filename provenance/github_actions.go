package provenance

// GitHub Actions provenance verifier.
//
// GitHub Actions ship attestations through the GitHub-native artifact
// attestations API (GA Sep 2024). The wire format is a Sigstore bundle
// (DSSE-wrapped, in-toto v1 statement) bound to a release artifact's
// SHA-256 digest. The verifier checks whether a given Action ref has a
// published attestation and whether the bundle validates against the live
// Sigstore trust root.
//
// Design notes:
//
//   - The existing top-level provenance Checker dispatches by (ecosystem,
//     packageName, version). GitHub Actions don't fit cleanly: an Action
//     reference is owner/name@ref, where ref is typically a tag or commit
//     SHA — not a version. Rather than overload one of those parameters
//     into the EcosystemChecker.Check signature, this verifier exposes its
//     own Verify(ctx, owner, name, ref) entry point and reuses the package
//     Result/Status types so callers slot the output into the same
//     downstream pipeline. Wiring into the dispatch table is a separate
//     concern (callers can construct it directly or wrap it).
//
//   - AttestationFetcher abstracts the GitHub REST call. Production wraps
//     it; tests stub it. Resolution from ref to the artifact's subject
//     digest is the fetcher's responsibility — see github_actions_fetcher.go
//     for the limitations of the v1 implementation.
//
//   - SigstoreBundleValidator is the narrow surface this verifier needs
//     from the existing sigstoreverify package. The default adapter
//     (DefaultSigstoreValidator) calls sigstoreverify.Default and
//     v.Verify, so we do NOT reimplement Sigstore validation here.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

// SigstoreIdentity carries the verified-signer info we surface upstream.
// Aliased to sigstoreverify.Identity so callers don't have to import the
// inner package and we don't redefine an equivalent struct.
type SigstoreIdentity = sigstoreverify.Identity

// ErrNoAttestation is the sentinel returned by an AttestationFetcher when
// the GitHub API reports no attestation exists for the requested ref
// (HTTP 404). The verifier translates this into StatusUnavailable.
var ErrNoAttestation = errors.New("github actions: no attestation published for ref")

// AttestationFetcher abstracts the "given owner/name@ref, give me the raw
// attestation bundle plus the artifact's subject digest" call. Production
// wraps the GitHub REST API; tests stub it.
//
// subjectDigest is the hex-encoded SHA-256 of the artifact the bundle
// attests to (no algorithm prefix). The verifier passes it to the
// SigstoreBundleValidator as the expected digest.
type AttestationFetcher interface {
	Fetch(ctx context.Context, owner, name, ref string) (bundleBytes []byte, subjectDigest string, err error)
}

// SigstoreBundleValidator is the narrow surface this verifier needs from
// sigstoreverify. The real implementation wraps sigstoreverify.Default +
// Verifier.Verify; tests pass a fake.
//
// expectedDigest is the hex-encoded SHA-256 of the artifact the bundle
// must bind to.
type SigstoreBundleValidator interface {
	VerifyBundle(ctx context.Context, bundleBytes []byte, expectedDigest string) (signer SigstoreIdentity, err error)
}

// GitHubActionsVerifier checks GitHub-native artifact attestations for a
// given Action ref (owner/name@ref). Resolution from ref to artifact
// digest is delegated to the AttestationFetcher so this verifier stays
// testable without hitting the live GitHub API.
//
// Resolver, when non-nil, runs first: it maps a tag/branch/commit ref
// into the artifact digest the Fetcher expects. When nil, the verifier
// falls through to the historical Wave 5 behavior (the ref is passed to
// the Fetcher as-is, which only accepts pre-resolved hex digests).
type GitHubActionsVerifier struct {
	Resolver       RefResolver
	Fetcher        AttestationFetcher
	SigstoreVerify SigstoreBundleValidator
}

// Verify resolves the Action ref via Fetcher, validates the bundle via
// SigstoreVerify, and returns a provenance Result.
//
// Status semantics:
//
//	StatusVerified    - bundle present and cryptographic digest match
//	StatusUnavailable - no attestation published for this ref (ErrNoAttestation)
//	StatusFailed      - bundle present but signature or digest mismatch,
//	                    or the GitHub API call itself failed
//
// The brief's "invalid" state maps to StatusFailed in this package's enum
// (the existing provenance package uses StatusFailed for "verification
// attempted and failed").
func (v *GitHubActionsVerifier) Verify(ctx context.Context, owner, name, ref string) (Result, error) {
	if v == nil || v.Fetcher == nil || v.SigstoreVerify == nil {
		return Result{Status: StatusFailed, Ecosystem: "github_actions", Error: "verifier not configured"},
			errors.New("github actions verifier: missing fetcher or sigstore validator")
	}

	// Resolve the ref to an artifact digest if a resolver is configured.
	// Backward compat: nil resolver means callers pre-resolved (or pass a
	// hex digest directly), matching Wave 5 behavior.
	fetchRef := ref
	if v.Resolver != nil {
		digest, err := v.Resolver.Resolve(ctx, owner, name, ref)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return Result{Status: StatusFailed, Ecosystem: "github_actions", Error: err.Error()}, err
			}
			if errors.Is(err, ErrUnresolvableRef) {
				return Result{
					Status:    StatusUnavailable,
					Ecosystem: "github_actions",
					Error:     err.Error(),
				}, nil
			}
			return Result{
				Status:    StatusFailed,
				Ecosystem: "github_actions",
				Error:     fmt.Sprintf("resolve ref: %v", err),
			}, nil
		}
		fetchRef = digest
	}

	bundle, digest, err := v.Fetcher.Fetch(ctx, owner, name, fetchRef)
	if err != nil {
		if errors.Is(err, ErrNoAttestation) {
			return Result{
				Status:    StatusUnavailable,
				Ecosystem: "github_actions",
			}, nil
		}
		// Propagate context cancellation as-is so callers can react to it.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Result{Status: StatusFailed, Ecosystem: "github_actions", Error: err.Error()}, err
		}
		return Result{
			Status:    StatusFailed,
			Ecosystem: "github_actions",
			Error:     fmt.Sprintf("fetch attestation: %v", err),
		}, nil
	}

	id, err := v.SigstoreVerify.VerifyBundle(ctx, bundle, digest)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Result{Status: StatusFailed, Ecosystem: "github_actions", Error: err.Error()}, err
		}
		res := Result{
			Status:            StatusFailed,
			Ecosystem:         "github_actions",
			AttestationType:   "sigstore",
			AttestationBundle: bundle,
			BundleFormat:      "sigstore-bundle",
			Error:             err.Error(),
		}
		if digest != "" {
			res.SubjectDigest = "sha256:" + digest
		}
		return res, nil
	}

	res := Result{
		Status:            StatusVerified,
		Ecosystem:         "github_actions",
		AttestationType:   "sigstore",
		AttestationBundle: bundle,
		BundleFormat:      "sigstore-bundle",
		SourceRepo:        id.SourceRepo,
		BuilderID:         id.BuilderID,
	}
	if digest != "" {
		res.SubjectDigest = "sha256:" + digest
	}
	return res, nil
}

// DefaultSigstoreValidator is the production SigstoreBundleValidator. It
// resolves the process-wide cached sigstoreverify.Verifier and runs the
// full Sigstore verify pipeline (signature, transparency log, certificate
// chain, artifact-digest binding). The expectedDigest must be the
// hex-encoded SHA-256 of the artifact (64 hex chars).
type DefaultSigstoreValidator struct{}

// VerifyBundle implements SigstoreBundleValidator by delegating to the
// existing sigstoreverify package. We do NOT reimplement Sigstore
// validation here.
func (DefaultSigstoreValidator) VerifyBundle(ctx context.Context, bundleBytes []byte, expectedDigest string) (SigstoreIdentity, error) {
	expectedDigest = strings.TrimPrefix(expectedDigest, "sha256:")
	if len(expectedDigest) != 64 {
		return SigstoreIdentity{}, fmt.Errorf("expected sha256 digest (64 hex chars), got %d", len(expectedDigest))
	}
	rawDigest, err := hex.DecodeString(expectedDigest)
	if err != nil {
		return SigstoreIdentity{}, fmt.Errorf("decode expected digest: %w", err)
	}
	v, err := sigstoreverify.Default(ctx)
	if err != nil {
		return SigstoreIdentity{}, fmt.Errorf("sigstore trust root: %w", err)
	}
	id, err := v.Verify(bundleBytes, rawDigest)
	if err != nil {
		return SigstoreIdentity{}, err
	}
	if id == nil {
		return SigstoreIdentity{}, nil
	}
	return *id, nil
}
