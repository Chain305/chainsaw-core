package intelligence

// provenanceProvider wraps *provenance.Checker. Emits the Provenance
// section plus a SupplyChain/URL source-repo hint when the underlying
// verification surfaces one.
//
// Ecosystems with a registered checker (provenance.SupportsProvenance)
// are "supported" here. Formats where the checker is registered but
// returns StatusUnavailable internally (cargo / composer / cocoapods
// today — no standardised attestation channel) still count as supported;
// recording the StatusUnavailable outcome is the point.

import (
	"context"
	"errors"
	"time"

	"github.com/chain305/chainsaw-core/httpclient"
	"github.com/chain305/chainsaw-core/provenance"
)

type provenanceProvider struct {
	checker *provenance.Checker
}

func newProvenanceProvider(checker *provenance.Checker) *provenanceProvider {
	return &provenanceProvider{checker: checker}
}

func (p *provenanceProvider) Name() string { return "provenance" }

func (p *provenanceProvider) Signal() SignalMask { return SignalProvenance }

func (p *provenanceProvider) Tier() int { return 1 }

// NeedsArtifact is false — provenance probes are metadata / registry
// lookups (npm attestations endpoint, sumdb, sigstore bundle, ...).
func (p *provenanceProvider) NeedsArtifact() bool { return false }

// Supports mirrors provenance.SupportsProvenance so policies don't emit
// an "ecosystem_unsupported" warning for formats the checker cannot
// cover. Nil checker disables the provider entirely.
func (p *provenanceProvider) Supports(ecosystem string) bool {
	if p.checker == nil {
		return false
	}
	return provenance.SupportsProvenance(ecosystem)
}

// Run calls CheckWithSource so the upstream-URL hint (gradle→maven
// override, swift registry overrides, apt/dnf repo selection) threads
// through. Maps provenance.Result → ProvenanceSection + the optional
// SupplyChain.SourceRepo URL.
// provenanceReuseFor is how long a verified attestation result is reused
// instead of verified again. An attestation published with a version is a
// fact about that version: re-verifying it on every rescan re-fetched the
// attestation, the bundle and the transparency-log entry (~2 requests per
// maven/gradle coordinate alone; docs/REPORTS.md
// #backend-perf-load-test-2026-10-29 J.4 I13-2). The bound re-checks it now
// and then, which is what notices a revoked signing identity.
const provenanceReuseFor = 30 * 24 * time.Hour

func (p *provenanceProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if p.checker == nil {
		return PartialReport{}, nil
	}
	// Only a VERIFIED result is reused. Unavailable, absent and failed
	// results are re-checked every time: a transient failure must be able
	// to recover, and an attestation can still appear.
	//
	// A tier-1 provider is run with prior == nil (the scanner keeps the
	// merged report away from phase 1); the stored row travels on the
	// request instead.
	stored := prior
	if stored == nil {
		stored = req.StoredRow()
	}
	if stored != nil && stored.Provenance.Verified && !stored.Provenance.CacheStale &&
		!stored.Observation.CollectedAt.IsZero() && time.Since(stored.Observation.CollectedAt) < provenanceReuseFor {
		kept := stored.Provenance
		kept.Warnings = append([]string(nil), stored.Provenance.Warnings...)
		partial := PartialReport{Provenance: &kept}
		if kept.SourceRepo != "" {
			partial.URLs = &URLSection{SourceRepoURL: kept.SourceRepo}
		}
		return partial, nil
	}
	// T-1: attestation probes are their own cost class and the largest
	// refresher egress with no sub-caller before this — ~2 requests per
	// maven/gradle coordinate, since trySigstore and tryPGP are both tried.
	// Tagged here rather than inside the ~15 per-ecosystem checkers: one
	// call site covers all of them, and the sidecar shapes stay separable
	// by the host x outcome pair the counter already carries.
	result := p.checker.CheckWithSource(
		httpclient.RefineEgressCaller(ctx, httpclient.EgressCallerRefreshProvenance),
		req.Key.Ecosystem, req.Key.Package, req.Key.Version, req.UpstreamURL)

	// Context deadlines / cancellations surface as a warning plus the
	// unavailable status so the Report still records "we tried".
	if err := ctx.Err(); err != nil {
		return PartialReport{
			Provenance: &ProvenanceSection{
				Kind:      result.AttestationType,
				Status:    string(provenance.StatusUnavailable),
				Available: false,
				Verified:  false,
			},
			Warnings: []Warning{{
				Provider: p.Name(),
				Code:     provenanceWarnCodeForCtxErr(err),
				Message:  err.Error(),
			}},
		}, nil
	}

	partial := PartialReport{}
	partial.Provenance = &ProvenanceSection{
		Kind:            result.AttestationType,
		Status:          string(result.Status),
		Verified:        result.Status == provenance.StatusVerified,
		Available:       result.Status != provenance.StatusUnavailable,
		BuilderID:       result.BuilderID,
		SignerID:        result.SignerID,
		SubjectDigest:   result.SubjectDigest,
		BundleFormat:    result.BundleFormat,
		SourceCommit:    result.SourceCommit,
		TransparencyLog: result.TransparencyLogURL,
		SLSALevel:       result.SLSALevel,
		CacheStale:      result.CacheStale,
		Warnings:        append([]string(nil), result.Warnings...),
	}

	if result.SourceRepo != "" {
		partial.Provenance.SourceRepo = result.SourceRepo
		partial.URLs = &URLSection{SourceRepoURL: result.SourceRepo}
	}

	// A StatusFailed result carries a human-readable reason — surface it
	// as a warning so operators debugging a failed attestation see the
	// detail without loading the Scanner's log stream.
	if result.Status == provenance.StatusFailed && result.Error != "" {
		partial.Warnings = append(partial.Warnings, Warning{
			Provider: p.Name(),
			Code:     WarnParseFailed,
			Message:  result.Error,
		})
	}

	return partial, nil
}

func provenanceWarnCodeForCtxErr(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return WarnTimeout
	}
	return WarnBreakerOpen
}

var _ Provider = (*provenanceProvider)(nil)
