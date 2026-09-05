package intelligence

// Sticky-on-silence supply-chain facts — ONE definition, TWO call sites.
//
// # What "sticky on silence" means
//
// A Tier-3 enricher (metadiff, repo-link probe, malware/typosquat index)
// records an OBSERVED event. A later Tier-1-only refresh does not re-run
// that enricher, so its section of the incoming Report is empty. Empty is
// not "the observation was withdrawn" — it is "nobody looked this time".
// So an empty incoming field takes the prior row's value.
//
// The converse is NOT sticky. An incoming field that is explicitly set —
// including *bool(false) — IS an observation and wins, so a package that
// genuinely returns to clean returns to clean. See
// TestPublisherChangedClearsOnExplicitFalse; P8-35 was filed against the
// opposite behaviour and the code was right.
//
// # Why this lives in its own function (P8-71)
//
// It used to be an inline block inside mergeReportPayload, which runs
// inside Store.Upsert — i.e. AFTER risk.EvaluatePackage has already run on
// the in-flight report in ComputeTrustScoreForOrg. The consequence was that
// the stored `report` column and the stored `risk_evaluation` column were
// snapshots of two DIFFERENT sets of facts: a sticky fact was revived for
// DISPLAY and discarded for ENFORCEMENT. The dashboard said
// publisher-changed; the verdict, which is what actually gates, did not.
//
// Measured on prod at epoch 12, the drift was strictly one-directional —
// 28 rows with publisherChanged=true and no publisher signal in the
// evaluation, 180 with versionAnomaly=true and no qual.version_anomaly, 83
// across repoLinkStatus and 12 across typosquatStatus — 298 distinct rows —
// and ZERO rows the other way.
// Zero the other way is the proof of mechanism: a fired signal implies the
// incoming scan genuinely observed the fact, so only the revival direction
// can drift.
//
// The fix is to apply this carry-forward to the RISK INPUT, before the
// evaluation, rather than to the report afterwards. runFanout calls it
// immediately before ComputeTrustScoreForOrg; mergeReportPayload still
// calls it on the way to the row (see "Applied twice, deliberately"
// below). Both columns are then derived from the same facts.
//
// # Adding a field
//
// Add it HERE and nowhere else. That is the whole point of the function:
// a sticky field added to a block inside the store would be invisible to
// the evaluator again, which is the exact defect P8-71 recorded. A guard
// test (TestStickySupplyChainIsTheOnlyCarryForward) fails if
// mergeReportPayload grows a SupplyChain carry-forward of its own.
//
// # Applied twice, deliberately
//
// Both call sites keep calling it, and that is safe because every rule
// below is guarded on the DESTINATION being empty: once applied, a second
// application with the same prior is a no-op. See
// TestApplyStickySupplyChainIsIdempotent.
//
// Keeping the store-side call matters because Store.Upsert is the last
// gate every writer reaches — the refreshers, the scan worker, and any
// Report built by hand — while the pre-evaluation call only covers the
// Scan fan-out. Removing it would silently drop stickiness for every other
// writer. The store-side call also re-reads the prior row under
// SELECT … FOR UPDATE, so it is the one that is correct under concurrency;
// the pre-evaluation read is an unlocked snapshot.

// applyStickySupplyChain copies the sticky-on-silence SupplyChain facts
// from prior into next. Both nil-safe; a nil prior (fresh coordinate) is a
// no-op.
//
// It never mutates prior, and never copies a slice by reference.
func applyStickySupplyChain(next *Report, prior *Report) {
	if next == nil || prior == nil {
		return
	}
	sc := &next.SupplyChain
	ps := &prior.SupplyChain

	// Tier-1 index verdicts. Empty means the index was not consulted on
	// this pass, not that the package was cleared.
	if sc.MalwareStatus == "" && ps.MalwareStatus != "" {
		sc.MalwareStatus = ps.MalwareStatus
	}
	if sc.TyposquatStatus == "" && ps.TyposquatStatus != "" {
		sc.TyposquatStatus = ps.TyposquatStatus
	}

	// Tier-3 repo-link probe.
	if sc.RepoLinkStatus == "" && ps.RepoLinkStatus != "" {
		sc.RepoLinkStatus = ps.RepoLinkStatus
	}
	if sc.RepoLastCommitAt == nil && ps.RepoLastCommitAt != nil {
		sc.RepoLastCommitAt = ps.RepoLastCommitAt
	}

	// PublisherChanged: *bool, sticky ON SILENCE ONLY.
	//
	// Preserve when incoming is nil — a Tier-1-only refresh that never ran
	// the metadiff provider has observed nothing, and silence is not a
	// withdrawal. An explicit incoming *false IS an observation and DOES
	// clear the flag: provider_metadiff.go computes
	// `changed := len(added) > 0 || len(removed) > 0` and always assigns
	// it, so a later scan that finds the publisher set unchanged returns
	// the package to clean. Never "once true, always true" — that would
	// leave a package flagged forever after one legitimate maintainer
	// handover, with no path back.
	//
	// AND IT TRAVELS WITH ITS EVIDENCE, for the same reason VersionAnomaly
	// does below. Carrying the bool alone is what put `publisherChanged:
	// true` with an empty added AND removed list on 30 of the 66 flagged
	// production rows — `requests 2.31.0` among them, capped at WARN 40 on
	// a maintainer change nobody can name. provider_metadiff computes
	// `changed := len(added) > 0 || len(removed) > 0`, so it can never
	// emit true with empty lists; every such row was minted here.
	if sc.PublisherChanged == nil && ps.PublisherChanged != nil {
		v := *ps.PublisherChanged
		hasEvidence := len(ps.PublisherAdded) > 0 || len(ps.PublisherRemoved) > 0
		// A TRUE is only revived together with the names that justify it.
		// A FALSE carries freely: it is an observation of absence and has
		// no evidence to lose. Reviving a bare true is what produced the
		// evidence-less rows, and it would ALSO break the P8-71 invariant
		// that the stored report and the stored verdict describe the same
		// fact — the row would claim a publisher change the evaluation
		// could not see.
		if !v || hasEvidence {
			sc.PublisherChanged = &v
			if len(sc.PublisherAdded) == 0 && len(ps.PublisherAdded) > 0 {
				sc.PublisherAdded = append([]string(nil), ps.PublisherAdded...)
			}
			if len(sc.PublisherRemoved) == 0 && len(ps.PublisherRemoved) > 0 {
				sc.PublisherRemoved = append([]string(nil), ps.PublisherRemoved...)
			}
		}
	}

	// VersionAnomaly travels WITH ITS FLAGS, as one fact.
	//
	// The bool is what the UI renders; `VersionAnomalyFlags` is what the
	// risk engine reads (qual.version_anomaly fires on
	// `len(in.VersionAnomalyFlags) > 0`, never on the bool). Carrying the
	// bool alone is what produced the largest slice of the P8-71
	// population: 161 of the 180 drifted prod rows say versionAnomaly=true
	// with an EMPTY flag list, because the bool was revived here and its
	// evidence was not. A fact whose evidence has been dropped cannot bind
	// a verdict, so the two move together or not at all.
	//
	// Gated on the BOOL being silent, not on the flags being empty: an
	// explicit incoming bool — true or false — is an observation, and
	// reviving stale flags underneath an explicit `false` would fire the
	// signal on a package the latest scan just cleared.
	// Symmetric with PublisherChanged above: a TRUE is only revived
	// together with the flags that justify it. Carrying it alone left the
	// stored row claiming an anomaly its own verdict never saw — the
	// signal fires on `len(flags) > 0`, so a flagless true is inert for
	// enforcement and misleading on screen. Measured 2026-09-05: 117 of
	// the 1,157 rows carrying versionAnomaly=true had an empty flag list.
	// A FALSE still carries freely; an observation of absence has no
	// evidence to lose.
	if sc.VersionAnomaly == nil && ps.VersionAnomaly != nil {
		v := *ps.VersionAnomaly
		if !v || len(ps.VersionAnomalyFlags) > 0 {
			sc.VersionAnomaly = &v
			if len(sc.VersionAnomalyFlags) == 0 && len(ps.VersionAnomalyFlags) > 0 {
				sc.VersionAnomalyFlags = append([]string(nil), ps.VersionAnomalyFlags...)
			}
		}
	}

	// Note: SuspiciousRepoStars, MaintainerAccountAgeDays,
	// FirstTimeCollaborator, and NonExistentAuthor live on
	// ArtifactScanSection (not SupplyChainSection — the audit groups them
	// by *signal source* rather than struct location). They are preserved
	// by the whole-Scan-section guard in mergeReportPayload when the
	// incoming Scan is empty, and naturally overwritten when a fresh
	// Tier-2 scan runs and writes the section. That guard is a
	// whole-section swap rather than a field-level carry-forward, so it is
	// not part of this function; if it is ever narrowed to per-field
	// rules, those fields belong here.
}
