package intelligence

// refresher_advisory_gate.go — the advisory gate on the primary walk.
//
// THE PROBLEM. A newly published advisory reaches a stored report only when
// that coordinate is next rescanned, and nothing in the refresh path is keyed
// on the advisory corpus changing. The walk's skip gate (refreshRow)
// short-circuits on `reportFresh && probeAnswered`, so a coordinate whose
// report is younger than MaxStaleness is skipped on every tick no matter what
// the bundle now says about it. The OSV refresher hot-swaps a fresh bundle
// every 6h (osv/refresher.go, runOnce -> cfg.Swap) and no read path reacts to
// the swap at all.
//
// WHY A GATE AND NOT A REVERSE INDEX. The obvious shape — diff two bundle
// generations, prefix-scan intelligence_reports for the affected coordinates,
// and write the new advisory onto each stored report — cannot be built without
// a SECOND vulnerability merge path, and that path can disagree with the
// scanner's:
//
//   - Store.Upsert replaces the VulnSection WHOLESALE. mergeReportPayload
//     preserves the prior section only when the incoming one is EMPTY, so a
//     writer has to reconstruct the entire section, not the OSV delta.
//   - The stored section is the flattened merge of osv AND the org-scoped
//     Trivy-backed cveProvider, and which provider contributed a given CVE is
//     unrecoverable from it (MergeScan flattens). So OSV's contribution can
//     neither be subtracted nor re-derived in isolation; writing an OSV-only
//     section would RETRACT every Trivy finding on the row — a fail-open on
//     the one section whose job is to fail closed.
//   - intelligence_reports has no org_id (personalize.go) and must keep none,
//     so a sweep over that table cannot build the metadata.PackageMetadataRow
//     that DiffReports and DiffSupplyChain stamp their events from. A reverse
//     index over it would update rows and alert NOBODY, which is strictly
//     worse than the latency it set out to fix.
//
// So the gate writes no report. It decides, from data the walk has ALREADY
// loaded, that this coordinate's cached answer predates something the corpus
// now knows — and then declines to skip, letting the walk's own Scan produce
// the row through the one merge path that exists. The write is a real scan, so
// it cannot disagree with a later real scan, and the walk's existing
// OnRefreshedReport call fires with the real (prior, next) pair for free.
//
// ZERO UPSTREAM FOR THE DECISION, ONE SCAN FOR THE WRITE. The decision costs a
// map lookup and a version compare against the in-memory index: the row, the
// prior report and the index are all already in hand at the skip site, so the
// read side adds no I/O and no upstream request whatsoever. The write costs
// the scan the coordinate was going to get anyway, roughly 2.6 days later.
// This is not "zero upstream" — it is zero ADDITIONAL upstream, brought
// forward. The forced scan is a full scheduled-shaped refresh, artifact bytes
// included; refreshRow's artifact call site records why trimming it to the
// metadata half would be a fail-open on a row that was otherwise fine.
//
// CONVERGENCE — WHY THE LoadedAt COMPARISON IS LOAD-BEARING. Firing on "the
// corpus asserts a CVE the stored report lacks" alone is NOT convergent: if
// another provider's ClearedCVEs vetoes that id during the merge, the forced
// rescan leaves the stored section unchanged, the gate re-opens on the next
// tick, and it does so forever. That is precisely the shape of the v0.22.14
// defect — ~27 Scans per real refresh because the two ends of a gate measured
// staleness on different things. Requiring the stored report to PREDATE the
// live bundle bounds it: once the row is rescanned under this bundle
// generation its CollectedAt is after LoadedAt, and the gate is shut for that
// coordinate until the next swap. At most one forced scan per coordinate per
// bundle generation, veto or no veto.
//
// ONE-DIRECTIONAL, DELIBERATELY. Only advisories in LookupEx's `hits` bucket
// that the stored report does not already carry open the gate. A CVE the
// report carries and the corpus does not is NOT a trigger: the stored section
// is a cross-provider merge, so a Trivy-only finding is indistinguishable from
// a retracted OSV one from here, and firing on it would rescan every
// Trivy-covered row on every tick. Retraction is already handled where it
// belongs — provider_osv's ClearedCVEs veto, on the next scan the row takes
// for any reason.
//
// cleared AND undecidable ARE NOT CONSULTED, and that is the entire reason the
// gate calls LookupEx instead of re-deriving the match: the three-way split
// and the reasoning behind it (osv/bundle.go, LookupEx's doc comment) stay in
// exactly one place, so there is no second matcher to drift. The gate reads
// `hits` and discards the other two buckets, so a bound this ecosystem's
// grammar could not parse is neither a trigger nor a clearance here — and the
// section that eventually lands is the provider's own output, never the
// gate's. The lookup also never normalises an ecosystem or a package name:
// canonicalKey does that inside LookupEx, which is what keeps PyPI's PEP 503
// fold in one place (the Phase 11 defect) rather than two.

import (
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/intelligence/osv"
	"github.com/chain305/chainsaw-core/metadata"
)

// DefaultAdvisoryGateMaxRows bounds the coordinates one tick will force a
// rescan for. Every other phase of the tick has a row budget and this one
// needs the same: a bundle swap that lands a popular advisory — one keyed to a
// package thousands of stored rows depend on — would otherwise turn a single
// 6-hourly swap into a scan of all of them at once.
//
// 200 matches the stale-report sweep's budget for the same reason it chose it:
// this work competes with the primary walk for the same upstream budget. At
// the measured ~9.22 upstream requests per refreshed coordinate that is ~1,850
// requests in the worst tick, against the refresher's measured ~3,400/hour.
// The budget is per-tick and not a total — an advisory affecting more rows
// than the budget drains over successive ticks, and the convergence bound
// above guarantees the drain terminates instead of re-queueing itself.
const DefaultAdvisoryGateMaxRows = 200

// advisoryRefreshStaleness is the MaxStaleness stamped on a gate-forced Scan.
// It has to defeat Scan's own cache-first read, which serves the cached row
// whenever `age < maxStale` — and the row is fresh by definition here, since
// that freshness is why the walk was about to skip it. One nanosecond is the
// existing idiom for this in refreshAsync; the comment there says "force a
// fetch" and this is the same requirement.
const advisoryRefreshStaleness = 1 * time.Nanosecond

// RefreshReasonAdvisory is stamped on Observation.RefreshReason for every
// Report the gate forces, so a row can be attributed to a new advisory rather
// than to the scheduled walk ("scheduled"), the matcher-epoch sweep or the
// stale-report sweep. Distinct on purpose and for the reason the sibling
// constants give: after an advisory lands, the operator's first question is
// "did this reach the coordinate", and the answer has to be legible from the
// row itself.
const RefreshReasonAdvisory = "advisory_gate"

// AdvisoryCorpus returns the live OSV advisory index, or nil when no bundle is
// loaded (dormant provider, trimmed build, airgapped first boot). The returned
// pointer is the same immutable index the provider's Run path reads, so a
// caller holding it across a hot swap sees a consistent older generation
// rather than a torn one.
//
// Exported off the Service because the Service is what owns the provider list
// and the refresher already holds a Service — which means the gate needs no
// new wiring in internal/server or cmd/ and therefore cannot ship inert. The
// dead-function hazard this tree keeps hitting (SafeUpgradeVersion,
// backfillRepositoryGuides) is a new exported entry point waiting to be wired;
// TestAdvisoryGateIsCalledFromRefreshRow and
// TestDefaultServiceExposesAdvisoryCorpus pin that this one is not.
func (s *DefaultService) AdvisoryCorpus() *osv.Index {
	if s == nil {
		return nil
	}
	for _, prov := range s.providers {
		if op, ok := prov.(*osvProvider); ok {
			return op.index()
		}
	}
	return nil
}

// index reads the live index pointer under the same RLock Run uses.
func (p *osvProvider) index() *osv.Index {
	if p == nil {
		return nil
	}
	p.idxMu.RLock()
	defer p.idxMu.RUnlock()
	return p.idx
}

// advisoryCorpusProvider is the optional capability the gate looks for on the
// configured Service. Declared as an anonymous-shaped named interface rather
// than asserting inline so the guard test can assert *DefaultService satisfies
// exactly this.
type advisoryCorpusProvider interface {
	AdvisoryCorpus() *osv.Index
}

// advisoryCorpus resolves the live index from the configured Service, or nil.
// Nil leaves the gate dormant — a Service that cannot answer is a reason to
// behave exactly as the walk did before this file existed, never a reason to
// force work.
func (r *Refresher) advisoryCorpus() *osv.Index {
	if r == nil || r.cfg.AdvisoryGateDisabled {
		return nil
	}
	src, ok := r.cfg.Service.(advisoryCorpusProvider)
	if !ok {
		return nil
	}
	return src.AdvisoryCorpus()
}

// advisoryGateOpen reports whether the live advisory corpus asserts a CVE for
// this coordinate that the stored report does not carry, and the stored report
// predates the corpus. True means "do not skip this row" — see this file's
// header for why that is the whole intervention.
//
// Consumes one unit of the per-tick budget when it returns true, and ONLY
// then: a closed gate must not spend budget, or one popular advisory would
// starve every other coordinate for the rest of the tick.
func (r *Refresher) advisoryGateOpen(row metadata.PackageMetadataRow, ecosystem string, prior *Report) bool {
	// prior == nil means no stored report, which is a reason to scan that the
	// walk's own staleness gate already reaches. The gate only ever speaks
	// about rows that were about to be SKIPPED.
	if prior == nil {
		return false
	}
	idx := r.advisoryCorpus()
	if idx == nil {
		return false
	}
	loadedAt := idx.LoadedAt()
	if loadedAt.IsZero() {
		return false
	}
	// The convergence bound. A report collected under this bundle generation
	// has already had OSV's answer merged into it, so a hit it still lacks is
	// a veto and rescanning cannot change it.
	if !prior.Observation.CollectedAt.Before(loadedAt) {
		return false
	}

	hits, _, _ := idx.LookupEx(ecosystem, row.Package, row.Version)
	if len(hits) == 0 {
		return false
	}
	known := make(map[string]struct{}, len(prior.Vulnerabilities.CVEs))
	for _, cve := range prior.Vulnerabilities.CVEs {
		// Folded exactly as DiffReports folds it, so the two sides of this
		// comparison cannot disagree about "CVE-2024-1" vs " cve-2024-1 ".
		if id := strings.ToUpper(strings.TrimSpace(cve)); id != "" {
			known[id] = struct{}{}
		}
	}
	for _, a := range hits {
		id := strings.ToUpper(strings.TrimSpace(a.PreferredCVE()))
		if id == "" {
			continue
		}
		if _, seen := known[id]; seen {
			continue
		}
		budget := r.cfg.AdvisoryGateMaxRows
		if budget <= 0 {
			budget = DefaultAdvisoryGateMaxRows
		}
		if r.advisoryForced.Load() >= int64(budget) {
			// Budget exhausted. Say so rather than silently skipping: a tick
			// that is leaving advisory-bearing rows behind is the one state an
			// operator has to be able to see, and the row is picked up on the
			// next tick because the gate's predicate is unchanged by not
			// acting on it.
			r.cfg.Logger.Warn("advisory gate budget exhausted",
				"budget", budget, "ecosystem", ecosystem,
				"package", row.Package, "version", row.Version, "advisory", id)
			return false
		}
		r.advisoryForced.Add(1)
		// Logged with the advisory's own `modified` stamp, which is what makes
		// the advisory -> alert latency computable from logs: this line's
		// timestamp minus `advisory_modified` is the end-to-end figure, and no
		// new metric or schema field is needed to read it. The stamp is a
		// verbatim upstream string (osv.Advisory.Modified) and may be empty on
		// a record that did not carry one.
		r.cfg.Logger.Info("advisory gate forcing refresh",
			"ecosystem", ecosystem, "package", row.Package, "version", row.Version,
			"advisory", id, "advisory_modified", a.Modified,
			"report_collected_at", prior.Observation.CollectedAt,
			"bundle_loaded_at", loadedAt)
		return true
	}
	return false
}
