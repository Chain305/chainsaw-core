package pgstore

import "fmt"

// One-shot, idempotent clear of attestation IDENTITY on package_metadata
// rows whose provenance was never verified.
//
// WHAT THE POISON IS. package_metadata.attestation_builder_id,
// attestation_issuer, attestation_source_repo and
// attestation_transparency_log are the columns core/policy's
// RequireBuilderID / RequireBuilderIssuer / RequireSourceRepo /
// RequireTransparencyLog conditions match on — substring tests and a
// bare-presence test. Until the change this migration ships with, every
// producer wrote them from material nothing had validated:
//
//   - core/provenance.noteUnverifiedBundle extracts BuilderID and SourceRepo
//     via sigstoreverify.InspectBundleIdentity, which does no chain
//     validation, and TransparencyLogURL straight out of the envelope's
//     TLogEntries[0] with no Rekor lookup — on a path whose own contract
//     says full verification could not run. core/provenance/npm.go's
//     StatusFailed branch calls it with a bundle its own comment describes
//     as possibly "signed by an untrusted identity".
//   - core/provenance/x509rubygems.go returns StatusVerified with a
//     BuilderID read from the Subject CN of a cert bundled INSIDE the .gem
//     it attests, validated against no external root.
//   - core/provenance/swift.go carries SourceRepo from unauthenticated
//     SE-0292 registry JSON.
//   - core/intelligence/provider_registrymetadata.go — the widest source by
//     row count — writes the publisher's own `repository.url` into
//     SourceRepo, with an empty provenance status, for the stated reason
//     that "the new UI picks it up". A display concern populating a
//     policy-gated column.
//
// WHY A MIGRATION AND NOT JUST THE WRITE GATE. metadata.ProjectSLSAFields
// was non-empty-wins on these columns: a clause was appended only when the
// incoming value was non-empty, so no later scan could ever retract an
// earlier write. Gating the producers alone would therefore leave every
// already-poisoned row poisoned PERMANENTLY. This is the exact failure of
// commit d4f2bda5, which fixed unverified bundles writing SLSALevel and
// shipped three files with no migration — that poison is still resident in
// production. ProjectSLSAFields now writes SQL NULL for these four columns
// when the report is authoritative about provenance, which is what stops
// this backfill being re-poisoned on the next scan.
//
// WHY IT IS SAFE TO RUN UNATTENDED AT BOOT, unlike its neighbour
// PurgeUnevaluableCoordinates (which is opt-in because it DELETEs). This is
// an idempotent UPDATE converging on a known-good value, in the shape of
// backfillDefaultPlanAssignment and BackfillStaleRepositoryGuides:
//
//   - It touches only the four identity columns. provenance_status,
//     slsa_level and attestation_cache_stale are untouched, so no row's
//     verification verdict, SLSA level or staleness changes.
//   - It cannot clear a genuinely verified identity. ProjectSLSAFields
//     writes provenance_status and the identity columns from one
//     SLSAReport in one UPDATE, so a verified identity always sits beside
//     provenance_status = 'verified'. The reverse — identity with a NULL or
//     non-verified status — is precisely the poison.
//   - Nothing is lost that a rescan cannot reproduce: package_metadata is a
//     projection, and internal/attestation's `attestations` table remains
//     the canonical record of full bundles.
//   - The dashboard is unaffected. attestation-card.tsx and the
//     intelligence version page render the intelligence Report's
//     ProvenanceSection, not these columns, and they show the status badge
//     beside the identity.
//
// IS DISTINCT FROM, not <>. provenance_status is nullable TEXT with no
// default (migrate_packages.go:12) and rows are born with it NULL — the
// registry-metadata shape writes a source repo and no status at all. Plain
// `provenance_status <> 'verified'` evaluates to NULL for those rows and
// the WHERE clause drops exactly the population this exists to clean.
// lower(coalesce(...)) additionally matches the case-folded comparison
// core/policy.provenanceVerified and policy_simulate.go use on read.
//
// Convention note: pgstore has no numbered migration runner (see the TODO
// at the top of migrate.go) and no rollback step anywhere; this is
// forward-only like everything else here.

// clearUnverifiedAttestationIdentity NULLs the four policy-gated
// attestation identity columns on every package_metadata row whose
// provenance_status is not 'verified'. Returns the number of rows changed.
//
// Idempotent by construction: the WHERE clause requires at least one of the
// four columns to be non-NULL, so a second run matches nothing and reports
// 0. TestClearUnverifiedAttestationIdentity asserts that second-run zero —
// a migration that keeps reporting work on every boot is one that is not
// converging.
func (s *Store) clearUnverifiedAttestationIdentity() (int64, error) {
	res, err := s.db.Exec(`
		UPDATE package_metadata
		SET attestation_builder_id       = NULL,
		    attestation_issuer           = NULL,
		    attestation_source_repo      = NULL,
		    attestation_transparency_log = NULL
		WHERE lower(coalesce(provenance_status, '')) IS DISTINCT FROM 'verified'
		  AND (attestation_builder_id       IS NOT NULL
		    OR attestation_issuer           IS NOT NULL
		    OR attestation_source_repo      IS NOT NULL
		    OR attestation_transparency_log IS NOT NULL)`)
	if err != nil {
		return 0, fmt.Errorf("clear unverified attestation identity: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		// Driver does not report affected rows. The UPDATE itself
		// succeeded, which is what the caller needs; the count is
		// telemetry.
		return 0, nil
	}
	return n, nil
}

// CountUnverifiedAttestationIdentity is the read-only census an operator can
// run to size the change before (or after) a boot applies it. It counts the
// rows clearUnverifiedAttestationIdentity would touch, using the identical
// predicate so the two cannot drift — a second run should report 0.
func (s *Store) CountUnverifiedAttestationIdentity() (int64, error) {
	var n int64
	err := s.db.QueryRow(`
		SELECT count(*) FROM package_metadata
		WHERE lower(coalesce(provenance_status, '')) IS DISTINCT FROM 'verified'
		  AND (attestation_builder_id       IS NOT NULL
		    OR attestation_issuer           IS NOT NULL
		    OR attestation_source_repo      IS NOT NULL
		    OR attestation_transparency_log IS NOT NULL)`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count unverified attestation identity: %w", err)
	}
	return n, nil
}
