package intelligence

// personalize.go — the read seam of the federated intelligence model.
//
// THE MODEL. `intelligence_reports` has no org_id and never will: a report
// about a coordinate is a fact about that coordinate, shared by every org
// and by the anonymous public surface. One scan serves everyone, which is
// the point — it is why the cache is worth having.
//
// What broke that model was not the sharing. It was that two values on the
// shared row were derived from whichever tenant happened to scan first:
//
//   - SupplyChain.TrustScore / Risk, computed under that org's private
//     weight overrides, and
//   - Vulnerabilities, read from that org's org-scoped
//     vulnerability_metadata and then PRESERVED across merges
//     (mergeReportPayload), so one tenant could pin — or suppress —
//     another tenant's CVE view. That is defect L-02.
//
// The fix is not to add an org_id. It is to stop writing org-derived values
// to the shared row at all (see the FEDERATION notes in scanner.go,
// provider_cve.go and provider_installscripts.go) and to apply the reader's
// own weights and own CVE rows HERE, on the way out.
//
// Every caller reaches a Report through Service.Scan or Service.Get, and
// both funnel through personalize, so no call site can forget it. That is
// deliberate: an opt-in flag is how the public endpoint would eventually be
// served some org's private data.

import (
	"context"

	"github.com/chain305/chainsaw-core/risk"
)

// personalize returns the READER's view of a federated report: their own
// weight overrides applied and their own private CVE rows overlaid.
//
// It never mutates its argument. The fan-out hands the same *Report to
// every singleflight waiter, and those waiters belong to different orgs —
// mutating in place would let one org's overlay leak into another's result
// and corrupt the cached row at the same time.
func (s *DefaultService) personalize(ctx context.Context, req Request, shared *Report) *Report {
	// A nil report has nothing to personalize; an empty OrgID is the
	// anonymous/public reader.
	//
	// The OrgID check is a SECURITY guard, not an optimisation.
	// metadata.Store.ForOrg("") routes through tenancy.NormalizeOrgID,
	// which maps "" to the literal org "org-default" — a REAL org with
	// real rows. Without this line the public package-intelligence
	// surface would be served org-default's private Trivy findings.
	if shared == nil || req.OrgID == "" {
		return shared
	}

	weights := OrgWeightsResolver(req.OrgID)
	signalWeights := OrgSignalWeightsResolver(req.OrgID)
	overlay := s.orgVulnOverlay(req)

	// Hot path. The overwhelming majority of reads are an org with no
	// tuning and no private CVE row for this exact coordinate: nothing to
	// apply, so hand back the shared pointer untouched and skip both the
	// copy and the re-evaluation. TestPersonalizeShortCircuits pins that
	// this returns the SAME pointer, which is what proves the hot path is
	// actually free rather than merely cheap.
	if len(weights) == 0 && len(signalWeights) == 0 && overlay == nil {
		return shared
	}

	// Shallow copy, then deep-copy only what we are about to write. The
	// Report is large and almost entirely read-only from here; the
	// vulnerability section is the only subtree the overlay touches.
	rep := *shared
	rep.Vulnerabilities = cloneVulnSection(shared.Vulnerabilities)
	if overlay != nil {
		mergeVulns(&rep.Vulnerabilities, *overlay)
	}

	// Re-score under this reader's weights.
	//
	// The tree-derived fields are carried over rather than recomputed:
	// the transitive walk is a BFS over every descendant's cached row,
	// which is the one part of evaluation that is NOT re-derivable from
	// this Report alone. ProjectToRiskInput folds
	// Resolution.TransitiveSeverity back into the Input so the transitive
	// signals still fire, and risk.EvaluateTree runs with bare Options
	// (no weights), which is exactly why its output is org-independent
	// and safe to persist and reuse.
	// Carry over the tree FACTS, not the tree SCORE.
	//
	// TransitiveBlame (which descendants are to blame) and
	// TransitiveSeverity (how many, at what severity) are outputs of a BFS
	// over every descendant's cached row, run with bare risk.Options. They
	// are org-independent and not re-derivable here, so they are preserved
	// verbatim.
	//
	// RolledUp is deliberately NOT preserved. It is a SCORE, and carrying
	// it would overwrite the very thing this function exists to compute —
	// an earlier revision did exactly that and both orgs read the same
	// federated number. The transitive contribution is not lost: the
	// severity counts above are folded back into the Input by
	// ProjectToRiskInput, so the transitive signals fire again under the
	// reader's own weights.
	//
	// Accepted trade: the tree pass's descendant-deficit DECAY is not
	// reproduced by this re-score, so a tuned org's rolled-up number can
	// differ slightly from the federated one beyond the weight change
	// itself. It only affects orgs that actively tune — an org with no
	// overrides short-circuits above and keeps the stored evaluation
	// bit-for-bit.
	hadTree := shared.Risk != nil
	var (
		blame    []risk.Key
		severity risk.TransitiveSeverity
	)
	if hadTree {
		blame = shared.Risk.Resolution.TransitiveBlame
		severity = shared.Risk.Resolution.TransitiveSeverity
	}

	ComputeTrustScoreForOrg(&rep, req.OrgID)

	if hadTree && rep.Risk != nil {
		rep.Risk.Resolution.TransitiveBlame = blame
		rep.Risk.Resolution.TransitiveSeverity = severity
	}

	// Same restoration the write path performs after the transitive
	// overlay: re-apply the known-fix/upgrade display fields, judged
	// against the post-transitive evaluation.
	ReapplyKnownFixAfterTransitive(&rep, req.OrgID)

	return &rep
}

// orgVulnOverlay reads the requesting org's private vulnerability_metadata
// row for this coordinate, or nil when there is none.
//
// It reuses cveProvider's own query rather than reimplementing it, so the
// read path and the (docker-only) write path cannot drift apart. The
// provider's write-path ecosystem gate is deliberately bypassed: the gate
// governs what may be PERSISTED on the shared row, not what the owning org
// is allowed to see about its own packages.
func (s *DefaultService) orgVulnOverlay(req Request) *VulnSection {
	for _, p := range s.providers {
		cp, ok := p.(*cveProvider)
		if !ok {
			continue
		}
		partial, err := cp.lookup(req)
		if err != nil {
			// A store error here must not fail the read. The federated
			// row still stands on its own (OSV is its vulnerability
			// source); the overlay is additive, so its absence can only
			// under-report the reader's private findings, never
			// manufacture a clean verdict.
			return nil
		}
		return partial.Vulns
	}
	return nil
}

// cloneVulnSection deep-copies the slices personalize may merge into, so a
// reader's overlay can never write through into the shared cached Report.
func cloneVulnSection(v VulnSection) VulnSection {
	out := v
	out.CVEs = append([]string(nil), v.CVEs...)
	out.CVEDetails = append([]CVEDetail(nil), v.CVEDetails...)
	out.ClearedCVEs = append([]string(nil), v.ClearedCVEs...)
	out.KEVEntries = append([]KEVEntry(nil), v.KEVEntries...)
	return out
}
