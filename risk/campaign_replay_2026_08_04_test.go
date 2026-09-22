package risk

import (
	"sort"
	"testing"
	"time"
)

// Replay of the 2026-08-04 keyv/cacheable campaign against the real
// evaluator, for docs/designs/cacheable-campaign-signal-replay.md.
//
// The question this answers: between keyv@6.0.0 going live (09:35:00Z)
// and MAL-2026-11524 existing (11:19:14Z), would the NON-advisory
// signals have moved the verdict off `allow`?
//
// The malicious tarball no longer exists anywhere (npm 404, deps.dev
// 404, no blobstore copy, no attestation), so the artifact-derived
// fields cannot be measured. They are set here from the FACTS THE
// ADVISORY DOCUMENTS, which makes every case below an upper bound on
// what the engine could have seen, never a measurement. See the
// evidence-tier labels in the design doc.
//
// The non-artifact fields are real surviving data:
//   - publish timestamps: registry.npmjs.org `time` map (survives unpublish)
//   - maintainer set, license, repo: packument + the clean 5.6.0 report
//     stored in prod (intelligence_reports, collected 2026-09-21)
//   - provenance verified: MAL-2026-11524 states the poisoned releases
//     "reached npm with a valid, signed provenance attestation"
func campaignBaseInput() Input {
	published := time.Date(2026, 8, 4, 9, 35, 0, 763000000, time.UTC)
	dl := 71_000_000
	return Input{
		Ecosystem: "npm",
		Package:   "keyv",
		Version:   "6.0.0",

		// --- surviving registry facts ---
		LicenseSPDX:          "MIT",
		LicenseTags:          Classify("MIT"),
		MaintainerCount:      2,
		HasSourceRepo:        true,
		RepoLinkStatus:       "ok",
		PublishedAt:          &published,
		LatestReleaseAt:      &published,
		VersionCount:         86,
		VersionDataAvailable: true,
		WeeklyDownloads:      &dl,

		// --- advisory feed as of 09:35Z: nothing. That is the premise. ---
		VulnDataAvailable: true,
		IsKnownMalicious:  false,

		// --- provenance: the attack rode the real release workflow ---
		HasProvenance:    true,
		ProvenanceStatus: "verified",
		SLSALevel:        2,
		ChecksumVerified: true,
	}
}

// withDocumentedPayload applies the artifact-derived facts that
// MAL-2026-11524 documents: a `preinstall` hook, a loader that fetches a
// Bun runtime over the network and execs it, an RC4-style string decoder,
// a 728 KB obfuscated bundle, and a credential sweep over env vars.
func withDocumentedPayload(in Input, strongDetectors bool) Input {
	in.HasInstallScript = true
	in.NetworkAccess = true
	in.EnvVarAccess = true
	in.CapShell = true
	in.CapNetwork = true
	in.CapEnvAccess = true
	in.CapFilesystemWrite = true
	in.IsMinifiedCode = true
	in.MinifiedFiles = []string{"Math_Symbol.js"}

	// The two high-weight install-script detectors. Production has never
	// fired either one (0 of 14,948 stored reports), so the honest
	// default is OFF; strongDetectors=true is the counterfactual.
	in.InstallScriptFetchesRemote = strongDetectors
	in.InstallScriptEvalEncoded = strongDetectors
	return in
}

func campaignFiredIDs(ev *Evaluation) []string {
	seen := map[string]bool{}
	for _, cs := range ev.DirectScore.Categories {
		for _, f := range cs.FiredSignals {
			seen[f.ID] = true
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func TestCacheableCampaignReplay(t *testing.T) {
	opts := Options{Now: func() time.Time {
		return time.Date(2026, 8, 4, 9, 35, 30, 0, time.UTC)
	}}

	cases := []struct {
		name string
		in   Input
		want Verdict
	}{
		{
			// What the engine sees with metadata only — no tarball
			// fetched, or fetched and scanned by nothing.
			name: "A_metadata_only",
			in:   campaignBaseInput(),
			want: VerdictAllow,
		},
		{
			// Tarball fetched and scanned, but only the detectors that
			// production has been observed to fire.
			name: "B_bytes_weak_detectors",
			in:   withDocumentedPayload(campaignBaseInput(), false),
			want: VerdictAllow,
		},
		{
			// Tarball fetched and the two -25/MaxImpact-40 install-script
			// detectors work as designed.
			//
			// WAS ALLOW UNTIL S-7 (docs/plan_signal_repair.md). The campaign
			// ships verified provenance, so it banks sc.provenance_verified
			// (+15) and sc.slsa_level_bonus — and the two compound rules it
			// trips used to DELETE the MaxImpact ceiling outright, so the
			// most corroborated row in this table scored best. It is now
			// warn at 40, pinned by sc.install_script_eval_encoded.
			//
			// This row is the whole point of the replay: a signed trojan,
			// with the byte detectors working, scored allow pre-advisory.
			// It no longer does. It is still not a quarantine — the reward
			// signals are real and the behavioural layer has no negative
			// counterpart to them yet, which is S-2 and S-3.
			name: "C_bytes_strong_detectors",
			in:   withDocumentedPayload(campaignBaseInput(), true),
			want: VerdictWarn,
		},
		{
			// Control: the input the engine actually built on 2026-09-13,
			// 40 days later. Everything zeroed by unavailableInput except
			// the malware facts. Reproduces the stored prod row.
			name: "D_post_advisory_tombstone",
			in: Input{
				Ecosystem: "npm", Package: "keyv", Version: "6.0.0",
				SignalsUnavailable: true,
				UnavailableReason:  "version not found in registry",
				IsKnownMalicious:   true,
				MalwareID:          "MAL-2026-11524",
				MalwareSummary:     "Malicious code in keyv (npm)",
			},
			want: VerdictQuarantine,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := EvaluatePackage(tc.in, opts)
			t.Logf("verdict=%s overall=%d ceiling=%q fired=%v",
				ev.Verdict, ev.DirectScore.Overall,
				ev.DirectScore.CeilingSignal, campaignFiredIDs(ev))
			if ev.Verdict != tc.want {
				t.Errorf("verdict = %s, want %s (overall=%d)",
					ev.Verdict, tc.want, ev.DirectScore.Overall)
			}
		})
	}
}

// TestCacheableCampaignVelocityCannotFire pins the arithmetic reason the
// publish-velocity signal is inert on this campaign: the threshold is
// >20 publishes in 24h and the campaign published 10 packages in 44
// minutes. This is independent of whether the counter had any data.
func TestCacheableCampaignVelocityCannotFire(t *testing.T) {
	const campaignPublishes = 10 // the full family, 09:31:01Z–10:14:41Z
	const threshold = 20         // publishVelocityAnomalyThreshold

	if campaignPublishes > threshold {
		t.Fatalf("campaign size %d exceeds threshold %d — the premise of "+
			"the report's §3 velocity finding no longer holds",
			campaignPublishes, threshold)
	}

	in := campaignBaseInput()
	in.PublishVelocityAnomaly = campaignPublishes > threshold
	ev := EvaluatePackage(in, Options{Now: func() time.Time {
		return time.Date(2026, 8, 4, 9, 35, 30, 0, time.UTC)
	}})
	for _, id := range campaignFiredIDs(ev) {
		if id == SignalSCPublishVelocity {
			t.Fatal("sc.publish_velocity_anomaly fired on a 10-package campaign")
		}
	}
}

// TestCompoundDoesNotSuppressMaxImpactCeiling is the monotonicity gate
// that replaced TestCompoundSuppressesMaxImpactCeiling (S-7).
//
// The old test pinned the inversion as a fact: applyMaxImpactCeiling
// returned early when ANY compound fired, so the per-signal ceilings were
// skipped exactly when the engine held the MOST corroborating evidence,
// and the same package scored HIGHER with two compound rules tripped than
// without them. Its own doc comment said to delete it when the scores
// converge. They have.
//
// What replaces it is the property, not the number: adding evidence of
// malice must never improve the score. Stated as `with <= without`, so it
// fails on any future change that re-opens a path where more signals
// produce a better result — which a fixed expected value would not.
func TestCompoundDoesNotSuppressMaxImpactCeiling(t *testing.T) {
	opts := Options{Now: func() time.Time {
		return time.Date(2026, 8, 4, 9, 35, 30, 0, time.UTC)
	}}

	withCompound := withDocumentedPayload(campaignBaseInput(), true)

	// Same package, minus the network axis. That drops both compound
	// rules (each requires NetworkAccess) while leaving the -25
	// install-script primitives and their MaxImpact-40 ceilings intact.
	noCompound := withCompound
	noCompound.NetworkAccess = false
	noCompound.CapNetwork = false

	evWith := EvaluatePackage(withCompound, opts)
	evWithout := EvaluatePackage(noCompound, opts)

	t.Logf("compound fired:      overall=%3d verdict=%-10s ceiling=%q",
		evWith.DirectScore.Overall, evWith.Verdict, evWith.DirectScore.CeilingSignal)
	t.Logf("compound suppressed: overall=%3d verdict=%-10s ceiling=%q",
		evWithout.DirectScore.Overall, evWithout.Verdict, evWithout.DirectScore.CeilingSignal)

	if evWith.DirectScore.Overall > evWithout.DirectScore.Overall {
		t.Errorf("INVERSION: with-compound scored %d, better than without-compound %d. "+
			"Adding evidence of malice must never improve the score.",
			evWith.DirectScore.Overall, evWithout.DirectScore.Overall)
	}
	// The ceiling must BIND on both sides now. An empty CeilingSignal on
	// the compound side is the exact shape of the old bypass returning.
	if evWith.DirectScore.CeilingSignal == "" {
		t.Errorf("no ceiling bound with a compound fired — the bypass is back")
	}
	if evWithout.DirectScore.CeilingSignal == "" {
		t.Errorf("no ceiling bound with no compound fired")
	}
	if evWith.Verdict == VerdictAllow {
		t.Errorf("verdict = allow on a row carrying two install-script primitives "+
			"and two compound rules (overall=%d)", evWith.DirectScore.Overall)
	}
}
