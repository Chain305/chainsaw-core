package sbom

import (
	"context"
	"fmt"
	"time"

	"github.com/chain305/chainsaw-core/attestation"
)

// PersistVerifiedSBOM writes a verified signed-SBOM bundle to the
// attestations table with attestation_type="sbom". Used by the dashboard
// upload path and the `chainsaw sbom verify` workflow when an operator
// wants the verified bundle preserved in the canonical store.
//
// Per the attestations-table design (Phase 3), the (ecosystem, package,
// version, attestation_type) tuple is unique — uploading a fresher SBOM
// for the same coordinate replaces the prior row. The full Sigstore
// bundle is preserved in the bundle column so the dashboard / verify
// CLI can re-verify offline without re-fetching.
//
// If store is nil, this is a no-op (matches the "tests run without DB"
// pattern used elsewhere in the codebase).
func PersistVerifiedSBOM(ctx context.Context, store *attestation.Store, ecosystem, pkg, version string, bundleJSON []byte, vr *VerifyResult) error {
	if store == nil {
		return nil
	}
	if ecosystem == "" || pkg == "" || version == "" {
		return fmt.Errorf("sbom persist: missing identity (eco=%q pkg=%q ver=%q)", ecosystem, pkg, version)
	}
	if vr == nil {
		return fmt.Errorf("sbom persist: nil VerifyResult")
	}
	att := &attestation.Attestation{
		Ecosystem:       ecosystem,
		Package:         pkg,
		Version:         version,
		AttestationType: "sbom",
		SubjectDigest:   "sha256:" + encodeHex(vr.SBOMDigest[:]),
		BundleFormat:    "sigstore-bundle",
		// SLSA level lives on the provenance attestation, not the SBOM
		// one. Leave at 0 — readers distinguish provenance vs sbom rows
		// by attestation_type and don't expect SLSALevel on the latter.
		BuilderID:  vr.Identity.BuilderID,
		SourceRepo: vr.Identity.SourceRepo,
		Bundle:     bundleJSON,
		VerifiedAt: time.Now().UTC(),
		CacheStale: vr.CacheStale,
	}
	return store.Upsert(ctx, att)
}
