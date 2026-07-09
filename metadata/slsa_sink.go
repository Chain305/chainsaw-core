package metadata

import (
	"context"
	"log/slog"
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
