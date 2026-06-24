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
func (p *provenanceProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if p.checker == nil {
		return PartialReport{}, nil
	}
	result := p.checker.CheckWithSource(ctx, req.Key.Ecosystem, req.Key.Package, req.Key.Version, req.UpstreamURL)

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
