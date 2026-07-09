package intelligence

// repolinkProvider is a Tier-3 enricher that probes the upstream source-
// repository URL surfaced by Tier-1 registrymetadata and projects the
// classifier's verdict onto SupplyChain.RepoLinkStatus,
// SupplyChain.RepoLastCommitAt, and SupplyChain.RepoArchived.
//
// It runs in Tier-3 (parallel against the Tier-1/2 merge) so its
// output is visible to any Tier-4 consumer (today: maintenanceProvider,
// which projects the secondary fields onto MaintenanceSection).
//
// Source map:
//   - prior.URLs.SourceRepoURL → primary input (HomepageURL fallback)
//   - prior.People.PublisherIDs → ownership-mismatch hint for Classify
//
// Three-state contract preserved end-to-end: when Classify returns
// RepoLinkStatusUnknown the provider emits no SupplyChain patch at all,
// so a richer prior value (e.g. a previously cached probe result) is
// not overwritten with zeros.

import (
	"context"
	"fmt"
	"time"

	"github.com/chain305/chainsaw-core/supplychain"
)

// repoLivenessClassifier is the narrow seam over
// *supplychain.RepoLivenessChecker so tests can inject a fake without
// hitting the network. The production implementation is the concrete
// checker pointer; nil is a permitted value (probe is skipped).
//
// The interface lives in core (here, with the repolinkProvider that
// consumes it) so the free build compiles without the premium maintenance
// provider. The premium maintenanceProvider (internal/intelligence/premium)
// only consumes repolinkProvider's merged SupplyChain.RepoLink* output, so
// it no longer needs this seam after the open-core split.
type repoLivenessClassifier interface {
	Classify(ctx context.Context, repoURL string, publisherIDs []string) supplychain.RepoLivenessResult
}

type repolinkProvider struct {
	checker repoLivenessClassifier
}

func newRepolinkProvider(checker repoLivenessClassifier) *repolinkProvider {
	return &repolinkProvider{checker: checker}
}

func (p *repolinkProvider) Name() string { return "repolink" }

func (p *repolinkProvider) Signal() SignalMask { return SignalMaintenance }

func (p *repolinkProvider) Tier() int { return 3 }

func (p *repolinkProvider) NeedsArtifact() bool { return false }

func (p *repolinkProvider) Supports(ecosystem string) bool { return true }

// Run probes the repo-liveness classifier exactly once per scan,
// gated on a non-empty SourceRepoURL (or HomepageURL fallback). A nil
// checker (the production fallback when liveness is disabled) makes
// Run a no-op. The Classify call never returns an error per its
// contract — every non-classifiable path degrades to
// RepoLinkStatusUnknown — so the warning surface is reserved for
// future expansion.
func (p *repolinkProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if prior == nil || p.checker == nil {
		return PartialReport{}, nil
	}
	repoURL := prior.URLs.SourceRepoURL
	if repoURL == "" {
		repoURL = prior.URLs.HomepageURL
	}
	if repoURL == "" {
		return PartialReport{}, nil
	}

	result := p.checker.Classify(ctx, repoURL, prior.People.PublisherIDs)

	// Only emit a SupplyChain patch when the probe produced something
	// more useful than the default "unknown" + nil secondary fields.
	// This keeps no-op probes (e.g. self-hosted forge that returned
	// nothing) from overwriting a richer prior value via the merge
	// helper.
	if result.Status != "" && result.Status != supplychain.RepoLinkStatusUnknown {
		sc := SupplyChainSection{RepoLinkStatus: result.Status}
		if result.LastCommitAt != nil {
			t := *result.LastCommitAt
			sc.RepoLastCommitAt = &t
		}
		if result.Archived != nil {
			a := *result.Archived
			sc.RepoArchived = &a
		}
		return PartialReport{SupplyChain: &sc}, nil
	}

	if result.Status == supplychain.RepoLinkStatusUnknown && result.CheckedAt.IsZero() {
		// Defensive: only fires if a future Classify variant signals
		// a probe-level error via a zero CheckedAt. The current
		// implementation never hits this path, but the warning code
		// is reserved.
		return PartialReport{Warnings: []Warning{{
			Provider: p.Name(),
			Code:     "repolink_probe_error",
			Message:  fmt.Sprintf("repo-liveness probe failed for %s", repoURL),
			At:       time.Now().UTC(),
		}}}, nil
	}

	return PartialReport{}, nil
}

var _ Provider = (*repolinkProvider)(nil)
