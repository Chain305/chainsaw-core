package intelligence

// shared_change_fanout.go — ONE dispatch for "this coordinate's shared report
// changed from prior to shared", notifying every audience.
//
// WHY ONE. Two fixes shipped before this file, and each fanned out within a
// single surface: the walk notified every package_metadata holder (C-7, walk),
// the declared-inventory sweep notified every declaring target (C-7, declared).
// The shared row does not know which surface refreshed it, so the two fixes
// stole from each other:
//
//	the WALK refreshes a coordinate org B DECLARES -> B is not in the walk's
//	audience, and B's own sweep then reads the already-updated row as its prior,
//	so prior == next and B hears nothing;
//
//	MONITORSWEEP refreshes a coordinate org A PROXIES -> A is not in the sweep's
//	audience, nothing on that path runs DiffReports at all, and A's walk row
//	then reads the row as fresh and skips it.
//
// Both were reproduced before this file existed; the tests are
// internal/monitorsweep/cross_surface_db_test.go. Keeping two fan-outs and
// adding the missing audience to each would mean two definitions of "who holds
// this coordinate" drifting apart, and a third surface would have to remember
// to touch both. This is the one place that answers the question.
//
// THE PRIVATE-OVERLAY RULE STILL HOLDS, and it is the reason Notify re-reads
// the row itself rather than accepting a `next` from its caller. Both callers
// have a PERSONALIZED report in hand — Scan returns the requesting org's view,
// with that org's weight overrides and its private vulnerability_metadata
// overlay (personalize.go) — so handing it to a peer would alert them about a
// CVE that exists only in the caller's private rows. Store.Get ignores its
// orgID argument and returns the federated row by design (store.go). A peer
// only ever sees that.
//
// FAIL CLOSED ON THE LEAK, NOT ON THE ALERT. If the shared row cannot be read,
// the fan-out is skipped and logged: the caller's own alert has already gone
// out, and a missed peer alert is recoverable on a later change while a leaked
// private overlay is not. The peers DO miss this particular change, because the
// shared row is now current and no later refresh reopens the window.
//
// DEDUP IS DELIBERATELY NOT HERE. Both production dispatchers key theirs per
// org — `OrgID|Package|Version|CVE|Trigger` for the CVE path and
// `OrgID|Package|Version|policy` for recall — so an org reached through both
// surfaces, or twice through one, collapses to a single delivery. A dedup keyed
// without the org would instead suppress the second ORG, which is C-7 again.
// What this file owes the dedup is not dispatching an org twice for sport:
// TestOrgThatBothProxiesAndDeclaresIsAlertedOnce counts dispatch attempts, not
// deliveries, precisely so a double dispatch cannot hide behind the dedup.

import (
	"context"
	"log/slog"
	"strings"

	"github.com/chain305/chainsaw-core/metadata"
)

// DeclaredTarget is one monitored target that declares a coordinate: the
// declared-inventory half of the audience.
//
// A VALUE TYPE IN core, not internal/monitoredtargets.Target, because core
// cannot import internal. It carries exactly the four fields an alert needs —
// the org and repo label that attribute the event, the trigger set that decides
// whether this target wanted it, and the id that identifies the origin so the
// caller is not notified as its own peer.
type DeclaredTarget struct {
	TargetID  int64
	OrgID     string
	RepoLabel string
	Triggers  []string
}

// DeclaredTargetSource answers "which monitored targets declare this
// coordinate". Implemented by *monitoredtargets.Store.
type DeclaredTargetSource interface {
	DeclaringTargets(ctx context.Context, ecosystem, pkg, version string, excludeTargetID int64, limit int) ([]DeclaredTarget, bool, error)
}

// PackageHolderSource answers "which orgs hold this coordinate" from
// package_metadata: the proxy half of the audience. Implemented by
// *metadata.Store, and already a member of MetadataSource.
type PackageHolderSource interface {
	PackageMetadataHolders(ctx context.Context, packageName, version string, limit int) ([]metadata.PackageHolder, error)
}

// SupplyChainDispatcher dispatches an already-diffed batch of one coordinate's
// transitions. Implemented by internal/server's recall dispatcher.
type SupplyChainDispatcher interface {
	SupplyChainAlerts(ctx context.Context, events []SupplyChainAlertEvent)
}

// SharedReportReader reads the federated row. Implemented by *Store, whose Get
// ignores its orgID argument.
type SharedReportReader interface {
	Get(ctx context.Context, orgID string, key Key) (*Report, error)
}

// DefaultDeclaredFanOutMaxTargets caps the declared half. Mirrors
// monitoredtargets.MaxDeclaringTargets; duplicated as a number rather than
// imported because core cannot see that package.
const DefaultDeclaredFanOutMaxTargets = 200

// SharedChangeFanout holds the seams the dispatch needs. Every field is
// optional and a nil one SKIPS that half rather than failing: the walk has no
// declared source wired in a test fixture, monitorsweep has no holder source in
// one, and neither should stop working because the other half is absent.
//
// EVERY SEAM IS COMPILE-TIME. None of them is resolved by a runtime type
// assertion, which is the form this tree keeps getting bitten by: an assertion
// fails silently, so a rename or a signature change leaves the fan-out dormant
// in production while every test injecting its own fake goes on passing. The
// fields are assigned in internal/server, so a rename breaks the build there.
type SharedChangeFanout struct {
	// Alerter receives the proxy half, per holder org, as the same
	// (row, ecosystem, prior, shared) callback the walk uses.
	Alerter VulnAlerter
	// Supply receives the declared half, as an already-diffed batch per target.
	Supply SupplyChainDispatcher

	Holders  PackageHolderSource
	Declared DeclaredTargetSource
	Shared   SharedReportReader

	// Resolver maps a package_metadata repository to an ecosystem. REQUIRED
	// for the proxy half: package_metadata stores a proxy repository, not an
	// ecosystem, so a holder whose repository resolves elsewhere is a
	// different coordinate that happens to share a name and version — npm
	// `lodash@4.17.21` and a maven artifact called `lodash` are not the same
	// package. With no resolver the proxy half is skipped rather than guessed.
	Resolver EcosystemResolver

	// DeclaredOrgAllowed gates the DECLARED half per org. Declared inventory
	// is behind a per-org feature flag, and a target in an org with it off
	// must not be alerted — including when the WALK is the caller, which is
	// the path that never saw that flag before this fix. Nil allows every
	// org, which is correct for a caller with no flag provider wired.
	//
	// It gates only the declared half: there is no equivalent flag on the
	// proxy surface, and inventing one here would silently disable alerts
	// that ship on by default.
	DeclaredOrgAllowed func(orgID string) bool

	Logger *slog.Logger

	MaxOrgs    int
	MaxTargets int
}

// SharedChangeOrigin identifies the caller's own row or target, which the
// caller has already alerted and which must not be notified again as its own
// peer. The walk fills OrgID; monitorsweep fills TargetID. Each leaves the
// other zero, which excludes nothing — exactly right, because a walk refresh
// owes every declaring target an alert and a sweep refresh owes every holder
// one.
type SharedChangeOrigin struct {
	OrgID    string
	TargetID int64
}

func (f SharedChangeFanout) logger() *slog.Logger {
	if f.Logger != nil {
		return f.Logger
	}
	return slog.Default()
}

// Notify is THE dispatch. prior is the report as it stood BEFORE the caller's
// refresh; the "next" side is always re-read from the store, never supplied.
//
// It is called only when the caller's own diff was non-empty, which is what
// keeps this to a bounded number of queries per diff-producing refresh rather
// than per examined row: a tick that finds nothing issues none of them.
func (f SharedChangeFanout) Notify(
	ctx context.Context,
	ecosystem, pkg, version string,
	prior *Report,
	origin SharedChangeOrigin,
) {
	if prior == nil {
		return
	}
	if f.Shared == nil {
		// LOUD, not silent. Shared is not optional the way the audience
		// sources are: without it there is no federated row to diff against,
		// so the whole fan-out is off. A caller that wired an AUDIENCE but no
		// reader has half-configured this and would otherwise see a silent
		// no-op — the exact failure mode the compile-time seams elsewhere in
		// this file exist to avoid, reintroduced through a nil field.
		if f.Declared != nil || f.Holders != nil {
			f.logger().Warn("alert fan-out DISABLED: an audience source is wired but "+
				"SharedReportReader is nil, so no peer will ever be notified",
				"ecosystem", ecosystem, "package", pkg, "version", version,
				"has_declared", f.Declared != nil, "has_holders", f.Holders != nil)
		}
		return
	}
	shared, err := f.Shared.Get(ctx, origin.OrgID, Key{
		Ecosystem: ecosystem, Package: pkg, Version: version,
	})
	if err != nil || shared == nil {
		f.logger().Warn("alert fan-out skipped: shared report unreadable",
			"ecosystem", ecosystem, "package", pkg, "version", version, "error", err)
		return
	}

	// Gate on the pair the PEERS receive, (prior, shared) — never on the
	// caller's personalized next. Letting one org's weight overrides decide
	// whether every other org hears about a change to the shared row is how an
	// override that keeps the caller's verdict flat would silence a
	// verdict_degraded every peer should get. Both diffs are pure functions,
	// so this is not a second notion of "alert-worthy".
	//
	// The row carries the ORIGIN's identity only so DiffSupplyChain has
	// something to stamp; nothing from it reaches a peer's event.
	gateRow := metadata.PackageMetadataRow{
		OrgID:           origin.OrgID,
		PackageMetadata: metadata.PackageMetadata{Package: pkg, Version: version},
	}
	if len(DiffReports(gateRow, ecosystem, prior, shared)) == 0 &&
		len(DiffSupplyChain(gateRow, ecosystem, prior, shared)) == 0 {
		return
	}

	f.notifyHolders(ctx, ecosystem, pkg, version, prior, shared, origin)
	f.notifyDeclaringTargets(ctx, ecosystem, pkg, version, prior, shared, origin)
}

// notifyHolders is the PROXY half: every org whose package_metadata carries
// this coordinate, through the same callback the walk uses, so both the CVE
// dispatcher and the recall dispatcher see it.
func (f SharedChangeFanout) notifyHolders(
	ctx context.Context,
	ecosystem, pkg, version string,
	prior, shared *Report,
	origin SharedChangeOrigin,
) {
	if f.Alerter == nil || f.Holders == nil || f.Resolver == nil {
		return
	}
	cap := f.MaxOrgs
	if cap <= 0 {
		cap = DefaultAlertFanOutMaxOrgs
	}
	peers, err := f.Holders.PackageMetadataHolders(ctx, pkg, version, cap)
	if err != nil {
		f.logger().Warn("alert fan-out holder lookup failed",
			"ecosystem", ecosystem, "package", pkg, "version", version, "error", err)
		return
	}
	if len(peers) >= cap {
		// Named explicitly: with a cap below the holder count the ORDER decides
		// whose alert is dropped, and a tenant who was not told must not be
		// invisible in the logs.
		f.logger().Warn("alert fan-out truncated; some holders were not notified",
			"cap", cap, "ecosystem", ecosystem, "package", pkg, "version", version)
	}
	for _, peer := range peers {
		if ctx.Err() != nil {
			return
		}
		if origin.OrgID != "" && peer.OrgID == origin.OrgID {
			// Already alerted by the caller.
			continue
		}
		if strings.TrimSpace(f.Resolver(peer.Repository)) != ecosystem {
			continue
		}
		// Each peer is alerted with ITS OWN org and repository — never a copy
		// of the caller's row with the OrgID swapped. Repository becomes
		// RepoName on the event, RepoID on the finding and Repository on the
		// webhook, so substituting the caller's would misattribute every one.
		f.Alerter.OnRefreshedReport(ctx, metadata.PackageMetadataRow{
			OrgID: peer.OrgID,
			PackageMetadata: metadata.PackageMetadata{
				Repository: peer.Repository,
				Package:    peer.Package,
				Version:    peer.Version,
			},
		}, ecosystem, prior, shared)
	}
}

// notifyDeclaringTargets is the DECLARED half: every monitored target that
// declares this coordinate, each through ITS OWN trigger set.
//
// The diff is recomputed per target rather than re-stamped, because
// DiffSupplyChain writes the target's org and repo label into every event and
// those are what attribute the alert. It is a pure function over two reports
// already in hand, so this costs no I/O.
func (f SharedChangeFanout) notifyDeclaringTargets(
	ctx context.Context,
	ecosystem, pkg, version string,
	prior, shared *Report,
	origin SharedChangeOrigin,
) {
	if f.Supply == nil || f.Declared == nil {
		return
	}
	cap := f.MaxTargets
	if cap <= 0 {
		cap = DefaultDeclaredFanOutMaxTargets
	}
	targets, truncated, err := f.Declared.DeclaringTargets(ctx, ecosystem, pkg, version, origin.TargetID, cap)
	if err != nil {
		f.logger().Warn("alert fan-out declaring-target lookup failed",
			"ecosystem", ecosystem, "package", pkg, "version", version, "error", err)
		return
	}
	if truncated {
		f.logger().Warn("declared fan-out truncated at the cap; targets beyond it "+
			"were NOT alerted",
			"cap", cap, "ecosystem", ecosystem, "package", pkg, "version", version)
	}
	for _, target := range targets {
		if ctx.Err() != nil {
			return
		}
		if f.DeclaredOrgAllowed != nil && !f.DeclaredOrgAllowed(target.OrgID) {
			continue
		}
		row := metadata.PackageMetadataRow{
			OrgID: target.OrgID,
			PackageMetadata: metadata.PackageMetadata{
				// The customer's own repo LABEL, not a repository we fetched
				// from. It is display data they typed and is untrusted on every
				// sink; it reaches the event's RepoName, which is why it is
				// carried at all.
				Repository: target.RepoLabel,
				Package:    pkg,
				Version:    version,
			},
		}
		wanted := DeclaredTriggerSet(target.Triggers)
		var batch []SupplyChainAlertEvent
		for _, ev := range DiffSupplyChain(row, ecosystem, prior, shared) {
			if wanted[string(ev.Trigger)] {
				batch = append(batch, ev)
			}
		}
		if len(batch) == 0 {
			continue
		}
		// One batch per target, which also satisfies SupplyChainAlerts'
		// one-coordinate-per-batch contract: the verdict floor is computed per
		// batch and this batch is one coordinate's transitions.
		f.Supply.SupplyChainAlerts(ctx, batch)
	}
}

// DeclaredTriggerSet turns a target's configured triggers into a lookup.
//
// NO FALLBACK FOR AN EMPTY SET, deliberately, and this is the opposite of what
// monitorsweep's own triggerSet does. The product default (every trigger except
// cve) belongs to internal/monitoredtargets, which owns the schema DEFAULT,
// validates on write, and applies the default inside DeclaringTargets — so a
// row reaching here with no triggers has already been through that. Inventing
// a second default in core would give the two places a chance to disagree
// about what a customer subscribed to, and core cannot see the authoritative
// list.
//
// An empty set therefore matches nothing and the target is skipped. That is
// the safe direction for a source core cannot validate: the alternative is
// alerting a customer for triggers they never chose.
func DeclaredTriggerSet(triggers []string) map[string]bool {
	out := make(map[string]bool, len(triggers))
	for _, t := range triggers {
		if t = strings.TrimSpace(t); t != "" {
			out[t] = true
		}
	}
	return out
}
