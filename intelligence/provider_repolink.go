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

	"github.com/chain305/chainsaw-core/httpclient"
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
	// recheck is how long a stored probe result stands before the repo is
	// probed again (supplychain.BootstrapConfig.RepoLivenessCheckInterval,
	// default 7 days). Zero probes on every scan.
	recheck time.Duration
}

func newRepolinkProvider(checker repoLivenessClassifier, recheck time.Duration) *repolinkProvider {
	return &repolinkProvider{checker: checker, recheck: recheck}
}

func (p *repolinkProvider) Name() string { return "repolink" }

func (p *repolinkProvider) Signal() SignalMask { return SignalMaintenance }

func (p *repolinkProvider) Tier() int { return 3 }

func (p *repolinkProvider) NeedsArtifact() bool { return false }

func (p *repolinkProvider) Supports(ecosystem string) bool { return true }

// Run probes the repo-liveness classifier at most once per scan, gated on
// a non-empty SourceRepoURL (or HomepageURL fallback), and not at all
// while the stored row's probe result is inside the recheck window — see
// storedProbe. A nil
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

	if carried, ok := p.storedProbe(prior.priorRow, repoURL, prior.People.PublisherIDs); ok {
		return PartialReport{SupplyChain: carried}, nil
	}

	// T-1: repository metadata is the largest single upstream line at 1.55
	// req/coordinate, and it is T-3's and T-4's shared subject — so it is
	// counted apart from the package documents fetched in the same scan.
	result := p.checker.Classify(
		httpclient.RefineEgressCaller(ctx, httpclient.EgressCallerRefreshRepo),
		repoURL, prior.People.PublisherIDs)

	// Only emit a SupplyChain patch when the probe produced something
	// more useful than the default "unknown" + nil secondary fields.
	// This keeps no-op probes (e.g. self-hosted forge that returned
	// nothing) from overwriting a richer prior value via the merge
	// helper.
	if result.Status != "" && result.Status != supplychain.RepoLinkStatusUnknown {
		// Stamp the probe time: it is what storedProbe reads on the next
		// scan. Nothing wrote this field before the recheck window existed.
		checked := result.CheckedAt
		if checked.IsZero() {
			checked = time.Now().UTC()
		}
		sc := SupplyChainSection{RepoLinkStatus: result.Status, RepoLinkLastChecked: &checked}
		if result.LastCommitAt != nil {
			t := *result.LastCommitAt
			sc.RepoLastCommitAt = &t
		}
		if result.Archived != nil {
			a := *result.Archived
			sc.RepoArchived = &a
		}
		out := PartialReport{SupplyChain: &sc}
		// Stars come off the same response; registry metadata no longer
		// fetches GitHub for them. Zero counts are silence to the merge,
		// so only a populated set is emitted.
		if st := result.Stats; st != (supplychain.RepoStats{}) {
			out.Maintenance = &MaintenanceSection{
				Stars: st.Stars, Forks: st.Forks, OpenIssues: st.OpenIssues, Subscribers: st.Subscribers,
				// The repo's creation date rides along so
				// suspicious_repo_stars stops making its own third GET of
				// the same endpoint (T-4 fetch 3).
				RepoCreatedAt: st.CreatedAt,
			}
		}
		return out, nil
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

// storedProbe returns the stored row's probe result when it is still inside
// the recheck window for the same repo URL, so Run can skip the network
// call.
//
// It re-EMITS the stored facts rather than emitting nothing and leaving
// them to applyStickySupplyChain, for two reasons:
//   - Sticky revives RepoLinkStatus but not RepoLinkLastChecked. Emitting
//     nothing would persist the status without its timestamp, and the next
//     scan would probe again — every other scan instead of one per window.
//   - Sticky runs after the whole fan-out, so Tier-4 projections (the
//     premium maintenance provider maps RepoLastCommitAt / RepoArchived
//     onto MaintenanceSection, which feeds maint.abandoned_repo) would not
//     see the facts in this scan. The verdict would lose a fact the stored
//     report still carries: P8-71.
//
// The ORIGINAL check time is carried, never "now", or the window would
// slide forward on every skipped scan and the repo would never be probed
// again.
//
// The ok / ownership_mismatch distinction is NOT carried: it is re-derived
// from the current publisher set on every scan (see OwnershipStatus).
//
// Everything short of a clean match probes: no stored row, no stored time,
// an unknown or missing status, a time in the future, a repo URL that
// differs from the one the stored result was taken for, or one that does
// not parse to an owner.
func (p *repolinkProvider) storedProbe(row *Report, repoURL string, publisherIDs []string) (*SupplyChainSection, bool) {
	if p.recheck <= 0 || row == nil {
		return nil, false
	}
	ps := row.SupplyChain
	switch ps.RepoLinkStatus {
	case "", supplychain.RepoLinkStatusUnknown, supplychain.RepoLinkStatusMissing:
		// missing is never cached: classifyGitHub also returns it for a
		// DNS error resolving api.github.com — our network, not the repo —
		// and the stored result cannot tell that from a genuine 404. A
		// transient failure must not become a seven-day sc.repo_missing.
		return nil, false
	}
	if ps.RepoLinkLastChecked == nil {
		return nil, false
	}
	storedURL := row.URLs.SourceRepoURL
	if storedURL == "" {
		storedURL = row.URLs.HomepageURL
	}
	if storedURL != repoURL {
		return nil, false
	}
	age := time.Since(*ps.RepoLinkLastChecked)
	if age < 0 || age >= p.recheck {
		return nil, false
	}
	status := ps.RepoLinkStatus
	if status == supplychain.RepoLinkStatusOK || status == supplychain.RepoLinkStatusOwnershipMismatch {
		// Never cache the ownership half: it depends on the publisher set,
		// which can change inside the window (a takeover), and it is free
		// to recompute. archived ranks above ownership in Classify, so a
		// stored archived stands.
		var ok bool
		if status, ok = supplychain.OwnershipStatus(repoURL, publisherIDs); !ok {
			return nil, false
		}
	}
	checked := *ps.RepoLinkLastChecked
	sc := &SupplyChainSection{RepoLinkStatus: status, RepoLinkLastChecked: &checked}
	if ps.RepoLastCommitAt != nil {
		t := *ps.RepoLastCommitAt
		sc.RepoLastCommitAt = &t
	}
	if ps.RepoArchived != nil {
		a := *ps.RepoArchived
		sc.RepoArchived = &a
	}
	return sc, true
}

var _ Provider = (*repolinkProvider)(nil)
