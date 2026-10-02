package intelligence

// refresher_alert_fanout.go — the C-7 fix on the primary walk.
//
// THE DEFECT. `intelligence_reports` holds exactly ONE row per coordinate and
// has no `org_id`. Every alerting path derives its "prior" from that one shared
// row, so whichever caller refreshes it first consumes the only prior/next diff
// window that will ever exist for that change. Every later org's row reads a
// report that already contains the new fact, `reportIsFresh` says skip (or the
// advisory gate's convergence bound shuts), and those tenants are never told.
// Silence is indistinguishable from "no vulnerability".
//
// Measured before this file existed: two orgs, one coordinate, a new CVE —
// `rows_scanned=1 rows_skipped=1`, exactly one org alerted.
//
// THE FIX IS DISPATCH-TIME FAN-OUT. The audience comes from the table that
// knows who holds the coordinate (`package_metadata`, keyed
// `(org_id, repository, package, version)`) at the moment a diff is found,
// rather than from whichever single row happened to trigger the refresh.
//
// FOUR THINGS THIS DELIBERATELY DOES NOT DO.
//
//  1. It does not touch the advisory gate's convergence bound. That bound is
//     what makes the gate fire at most once per coordinate per bundle
//     generation, and loosening it to "let every org's row through" would
//     reintroduce the unbounded rescan loop the bound exists to prevent — N
//     orgs' rows each forcing a scan of the same coordinate, every tick,
//     forever. The gate still fires once; the ALERT is what fans out.
//
//  2. It does not hand a peer org the walker's personalized report. `Scan`
//     returns the REQUESTING org's view (personalize.go: that org's weight
//     overrides and its private vulnerability_metadata overlay), so passing
//     `nextReport` to another tenant would alert org B about a CVE that exists
//     only in org A's private rows — a cross-tenant disclosure of exactly the
//     class L-02 was about. The fan-out re-reads the SHARED row instead
//     (Store.Get ignores its orgID argument by design, store.go:145) and
//     refuses to fan out if that read fails. A missed peer alert is recoverable
//     on the next refresh; a leaked private CVE is not.
//
//  3. It does not substitute the walker's repository. Each peer is alerted with
//     ITS OWN (OrgID, Repository) — `Repository` becomes RepoName on the event,
//     RepoID on the finding and Repository on the webhook, so a copy of the
//     walker's row with the OrgID swapped would misattribute every finding.
//     Exactly four fields reach an alert and all four come from the peer's own
//     row; see metadata.PackageHolder.
//
//  4. It adds NO dedup, because both dispatchers already key theirs per org:
//     `OrgID|Package|Version|CVE|Trigger` (internal/server/intelligence_vuln_alerts.go,
//     alreadyAlerted) and `OrgID|Package|Version|recallPolicyIDFor(ev)`
//     (recall_alerts.go). At Concurrency > 1 two orgs' rows DO both fan out and
//     each org therefore sees its event twice — once from its own row, once
//     from the peer's — and those two layers collapse it to one delivery. A
//     dedup keyed without the org would instead suppress the second ORG, which
//     is the defect again; TestVulnAlertDedupIsPerOrg in internal/server pins
//     that direction.

import (
	"context"

	"github.com/chain305/chainsaw-core/metadata"
)

// DefaultAlertFanOutMaxOrgs caps the peer orgs one diff will notify.
//
// Every peer costs a finding upsert plus a webhook fan-out, synchronously,
// inside one row's processing — so an uncapped fan-out on a coordinate shared
// by thousands of tenants would stall the tick that found the diff. 100 is
// comfortably above the whole production estate (~40 orgs) while bounding the
// pathological case, and the truncation is logged rather than silent, because a
// tenant who was not told must not be invisible.
const DefaultAlertFanOutMaxOrgs = 100

// fanOutAlertToPeers notifies every OTHER org holding this coordinate.
//
// Called only from the walk's post-Scan alerter hook, and only when the
// walker's own diff was non-empty: that gate is what keeps this to one query
// per diff-producing refresh rather than one per examined row. A tick that
// finds nothing issues no queries at all.
// SUPERSEDED BY shared_change_fanout.go, and kept as the walk's thin adapter
// onto it. The holder loop, the shared re-read, the private-overlay guard, the
// ecosystem check and the truncation log all moved to SharedChangeFanout so
// monitorsweep could call the same code — the two surfaces were stealing each
// other's diff windows while each fanned out correctly within itself (C-7
// across surfaces; see that file's header).
//
// The note at the bottom of this file about the compile-time seam still
// governs, and now covers two seams rather than one.
func (r *Refresher) fanOutAlertToPeers(
	ctx context.Context,
	row metadata.PackageMetadataRow,
	ecosystem string,
	prior, next *Report,
) {
	if r == nil || prior == nil || next == nil {
		return
	}
	r.sharedChangeFanout().Notify(ctx, ecosystem, row.Package, row.Version, prior,
		SharedChangeOrigin{OrgID: row.OrgID})
}

// SetDeclaredAudience wires the DECLARED half of the cross-surface fan-out.
//
// A setter rather than config fields filled at construction, for the same
// reason SetVulnAlerter is one: internal/server creates the recall dispatcher
// while building the refresher, so the dispatcher does not exist yet when
// RefresherConfig is assembled. The config fields remain for callers that can
// supply them up front (the tests do).
//
// Compile-time seam: a rename breaks the call in internal/server.
func (r *Refresher) SetDeclaredAudience(
	declared DeclaredTargetSource,
	supply SupplyChainDispatcher,
	orgAllowed func(orgID string) bool,
) {
	if r == nil {
		return
	}
	r.cfg.DeclaredTargets = declared
	r.cfg.SupplyChainDispatcher = supply
	r.declaredOrgAllowed = orgAllowed
}

// sharedChangeFanout assembles the dispatch from the refresher's own config.
//
// Holders is r.cfg.Metadata, which carries PackageMetadataHolders as a
// compile-time member of MetadataSource. Declared and Supply are the two
// fields this fix added to RefresherConfig; both are nil in tests that do not
// wire them, and a nil half is skipped rather than fatal.
func (r *Refresher) sharedChangeFanout() SharedChangeFanout {
	return SharedChangeFanout{
		Alerter:            r.alerter,
		Supply:             r.cfg.SupplyChainDispatcher,
		Holders:            r.cfg.Metadata,
		Declared:           r.cfg.DeclaredTargets,
		Shared:             r.cfg.Store,
		Resolver:           r.cfg.EcosystemResolver,
		DeclaredOrgAllowed: r.declaredOrgAllowed,
		Logger:             r.cfg.Logger,
	}
}

// NOTE ON THE SEAM. PackageMetadataHolders is a method on MetadataSource — a
// COMPILE-TIME requirement — rather than an optional interface resolved by a
// runtime type assertion. The assertion form is what this tree keeps getting
// bitten by: it fails silently, so a rename or a signature change leaves the
// fan-out dormant in production while every test that injects its own fake goes
// on passing. MetadataSource has exactly two implementations (*metadata.Store
// and the refresher tests' fake), so the cost of the safer form is one method on
// one fake and the compiler is the guard.
