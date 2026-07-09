package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

// VerifyResult captures the outcome of a signed-SBOM verification.
//
// Identity is non-empty on success; SBOMDigest is the sha256 the
// attestation bound to (matching what's inside the in-toto subject); the
// Statement is the parsed in-toto envelope so callers can re-extract the
// embedded BOM without re-decoding the bundle.
type VerifyResult struct {
	Identity   sigstoreverify.Identity
	SBOMDigest [32]byte
	Statement  *InTotoStatement
	CacheStale bool
}

// VerifySignedSBOM verifies a Sigstore-signed SBOM bundle against the
// SBOM document it claims to attest to.
//
//   - bundleJSON: the Sigstore bundle JSON produced by `cosign sign-blob`
//     or equivalent.
//   - bom: the CycloneDX BOM the bundle is supposed to bind to.
//   - cache: optional Sigstore bundle cache. When non-nil, fresh hits
//     short-circuit Rekor/Fulcio; stale hits fall back when live
//     verification fails. Pass nil to force live verification.
//
// Returns an error when:
//   - The bundle's signature does not validate against the live Sigstore
//     trust root.
//   - The in-toto subject digest does not match sha256(canonical(bom)).
//   - The predicateType is not CycloneDX.
//
// Identity is extracted on success. Callers (the `chainsaw sbom verify`
// CLI, dashboard, audit log) typically display Identity.SourceRepo and
// Identity.BuilderID to confirm the SBOM was produced by the expected
// builder for the expected source repository.
func VerifySignedSBOM(ctx context.Context, bundleJSON []byte, bom *CycloneDXBOM, cache *sigstoreverify.BundleCache) (*VerifyResult, error) {
	if len(bundleJSON) == 0 {
		return nil, errors.New("sbom: empty bundle")
	}
	digest, err := SBOMSubjectDigest(bom)
	if err != nil {
		return nil, err
	}

	v, err := sigstoreverify.Default(ctx)
	if err != nil {
		return nil, fmt.Errorf("sbom: sigstore trust root: %w", err)
	}
	vr, err := v.VerifyWithCache(cache, bundleJSON, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sbom: sigstore verify: %w", err)
	}

	// Re-parse the bundle's DSSE payload so we can confirm the embedded
	// in-toto Statement's predicateType actually says CycloneDX. A
	// signature-valid bundle whose predicate is something else (SLSA
	// provenance, custom predicate) would otherwise pass through and
	// confuse callers expecting an SBOM payload.
	stmt, err := extractInTotoFromBundle(bundleJSON)
	if err != nil {
		return nil, fmt.Errorf("sbom: extract statement: %w", err)
	}
	if stmt.PredicateType != CycloneDXPredicateType {
		return nil, fmt.Errorf("sbom: predicateType = %q, want %q", stmt.PredicateType, CycloneDXPredicateType)
	}

	// Defence-in-depth: confirm the subject digest in the statement
	// matches what we computed from the BOM. Sigstore already binds the
	// signature to the artifact digest, but the in-toto layer carries
	// its own copy and a mismatch would mean a malformed bundle.
	if !bundleSubjectMatches(stmt, digest) {
		return nil, errors.New("sbom: in-toto subject digest mismatch with computed BOM digest")
	}

	return &VerifyResult{
		Identity:   vr.Identity,
		SBOMDigest: digest,
		Statement:  stmt,
		CacheStale: vr.CacheStale,
	}, nil
}

// dsseEnvelopeShape is the minimum subset of a Sigstore bundle JSON we
// need to lift the in-toto Statement back out of the signed payload. The
// full sigstore-go bundle type does the same parsing internally; we
// duplicate the small piece here to avoid a hard dependency from
// internal/sbom on sigstore-go's bundle package.
type dsseEnvelopeShape struct {
	DSSE struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
	} `json:"dsseEnvelope"`
}

// extractInTotoFromBundle decodes the DSSE payload of a Sigstore bundle
// to its embedded in-toto Statement.
func extractInTotoFromBundle(bundleJSON []byte) (*InTotoStatement, error) {
	var env dsseEnvelopeShape
	if err := json.Unmarshal(bundleJSON, &env); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}
	if env.DSSE.Payload == "" {
		return nil, errors.New("bundle has no dsseEnvelope.payload")
	}
	raw, err := base64DecodeStrict(env.DSSE.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode dsse payload: %w", err)
	}
	var stmt InTotoStatement
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return nil, fmt.Errorf("parse in-toto statement: %w", err)
	}
	return &stmt, nil
}

func bundleSubjectMatches(stmt *InTotoStatement, want [32]byte) bool {
	if stmt == nil || len(stmt.Subject) == 0 {
		return false
	}
	got, ok := stmt.Subject[0].Digest["sha256"]
	if !ok || got == "" {
		return false
	}
	wantHex := encodeHex(want[:])
	return bytes.EqualFold([]byte(got), []byte(wantHex))
}
