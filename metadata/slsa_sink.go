package metadata

import (
	"context"
	"log/slog"
	"strings"
)

// SLSAReport is the minimal projection of an intelligence Report that the
// SLSA-substrate denormaliser cares about. Defining it here (rather than
// importing internal/intelligence) keeps the dependency arrow pointing
// from server → intelligence and server → metadata, never the diamond.
//
// Server bootstrap adapts intelligence.Report → SLSAReport before calling
// the sink — see cmd/chainsaw-proxy/init_server.go.
//
// Repository is intentionally absent: SLSA / Sigstore attestation claims
// are facts about a (ecosystem, package, version) coordinate, not about
// a tenant's specific upstream proxy. The sink projects across every
// matching package_metadata row regardless of repository.
type SLSAReport struct {
	Ecosystem string
	Package   string
	Version   string

	ProvenanceStatus           string
	SLSALevel                  int
	AttestationBuilderID       string
	AttestationIssuer          string
	AttestationSourceRepo      string
	AttestationTransparencyLog string
	AttestationCacheStale      bool
}

// ProvenanceVerified reports whether the report's provenance status means
// the attestation was cryptographically verified. The wire value is
// core/provenance.StatusVerified ("verified"); this package does not import
// core/provenance (the sink is deliberately dependency-light — see the type
// doc above), so the literal is duplicated and pinned by
// TestSLSAReportVerifiedLiteralMatchesProvenance.
func (r SLSAReport) ProvenanceVerified() bool {
	return strings.EqualFold(strings.TrimSpace(r.ProvenanceStatus), "verified")
}

// ProvenanceAuthoritative reports whether the producer actually ran a
// provenance check and is stating the outcome. An empty status means the
// report simply has nothing to say about provenance (an ecosystem with no
// checker, or a registry-metadata provider that filled in a source repo for
// display) — such a report must NOT be allowed to clear a previously
// verified identity, so the projection keeps its non-empty-wins behaviour
// for it.
func (r SLSAReport) ProvenanceAuthoritative() bool {
	return strings.TrimSpace(r.ProvenanceStatus) != ""
}

// WithoutUnverifiedIdentity returns the report with every attestation
// IDENTITY field zeroed unless provenance was actually verified.
//
// BuilderID, Issuer, SourceRepo and TransparencyLog are policy-gated
// (RequireBuilderID / RequireBuilderIssuer / RequireSourceRepo /
// RequireTransparencyLog in core/policy) but are produced best-effort from
// material nothing validated: noteUnverifiedBundle extracts them from
// bundles the verifier declined to verify, x509 gem certs are bundled
// inside the artifact they attest, the Swift SE-0292 registry repo URL is
// unauthenticated JSON, and provider_registrymetadata writes a publisher's
// own `repository.url` into the source-repo column "so the new UI picks it
// up". None of that is admissible as an enforcement signal.
//
// This is the WRITE half of the same rule core/policy applies on read. Both
// halves exist on purpose: the evaluator gate protects rows already in the
// table, this one stops new poison arriving, and the one-shot backfill in
// core/pgstore clears what is already resident.
//
// The descriptive fields are untouched — SLSALevel is gated at its own
// producer (d4f2bda5), and SubjectDigest / SourceCommit never reach this
// projection at all.
func (r SLSAReport) WithoutUnverifiedIdentity() SLSAReport {
	if r.ProvenanceVerified() {
		return r
	}
	r.AttestationBuilderID = ""
	r.AttestationIssuer = ""
	r.AttestationSourceRepo = ""
	r.AttestationTransparencyLog = ""
	return r
}

// HasAnyAttestationFields returns true when at least one of the
// SLSA-substrate fields carries a non-zero value. The denormaliser uses
// this to skip writes for reports whose provenance section was empty
// (e.g. ecosystems without a checker, or unverified attestations) so it
// doesn't churn package_metadata rows on no-op updates.
func (r SLSAReport) HasAnyAttestationFields() bool {
	if r.ProvenanceStatus != "" {
		return true
	}
	if r.SLSALevel > 0 {
		return true
	}
	if r.AttestationBuilderID != "" || r.AttestationIssuer != "" {
		return true
	}
	if r.AttestationSourceRepo != "" || r.AttestationTransparencyLog != "" {
		return true
	}
	return r.AttestationCacheStale
}

// SLSAReportSink projects a verified SLSAReport onto the package_metadata
// row by writing its denormalised SLSA-substrate columns (provenance_status,
// slsa_level, attestation_builder_id, attestation_source_repo,
// attestation_transparency_log, attestation_cache_stale).
//
// The sink is best-effort: write failures are logged at Debug and never
// returned to the caller. The canonical record of attestation history is
// the dedicated `attestations` table; package_metadata only carries the
// hot-path projection.
type SLSAReportSink struct {
	store  *Store
	logger *slog.Logger
}

// NewSLSAReportSink wires a sink that hydrates package_metadata from
// SLSAReport. A nil store makes the sink a no-op (safe in tests).
func NewSLSAReportSink(store *Store, logger *slog.Logger) *SLSAReportSink {
	if logger == nil {
		logger = slog.Default()
	}
	return &SLSAReportSink{store: store, logger: logger}
}

// Project writes the SLSAReport's denormalised fields. The orgID is the
// tenant authoring the underlying intelligence Report. Suitable for use
// as the callback passed to intelligence.DefaultService.SetReportSink
// after adaption (see internal/server/slsa_sink.go).
func (s *SLSAReportSink) Project(ctx context.Context, orgID string, r SLSAReport) {
	if s == nil || s.store == nil {
		return
	}
	if r.Package == "" || r.Version == "" {
		return
	}
	// Strip unverified attestation identity BEFORE the has-anything check,
	// so a report whose ONLY content was unverified identity (the
	// provider_registrymetadata shape: a publisher's repository.url and no
	// provenance status at all) short-circuits here instead of writing a
	// policy-gated column.
	r = r.WithoutUnverifiedIdentity()
	if !r.HasAnyAttestationFields() {
		return
	}
	if err := s.store.ProjectSLSAFields(ctx, r); err != nil {
		s.logger.Debug("slsa report sink: persist failed",
			"org", orgID,
			"package", r.Package,
			"version", r.Version,
			"error", err,
		)
	}
}
