package cli

// Tests for pr-scan's policy decision point (policy.SurfacePR).
//
// The property under test throughout is TIGHTEN-ONLY: with no operator
// bundle the report is byte-identical to the pre-policy output, a rule
// can raise a verdict, and no rule can clear one.

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// prScanPolicyTestEnv isolates a test from the developer's real config
// home and from any CHAINSAW_POLICY_BUNDLE they have exported, then
// points the loader at bundleDir (pass "" for the no-bundle case).
//
// Isolating the config home matters even in the no-bundle case:
// guardPolicyBundleSources falls back to <config home>/policy, so
// without this a machine that happens to have a bundle installed would
// silently change what these tests are measuring.
func prScanPolicyTestEnv(t *testing.T, bundleDir string) {
	t.Helper()
	prScanPolicyResetForTest()
	t.Cleanup(prScanPolicyResetForTest)
	t.Setenv(guardPolicyBundleEnv, bundleDir)
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())
}

func strPtr(s string) *string { return &s }

// ---------------------------------------------------------------------------
// 1. Default off
// ---------------------------------------------------------------------------

// TestPRScanPolicy_DefaultOffIsByteIdentical is the regression that
// protects every existing user. Wiring a decision point into a merge
// gate is only acceptable if the gate does not move for anyone who did
// not ask for it: with no operator bundle, and with the built-in bundle
// carrying no rule that can fire at SurfacePR (its only rule keys on
// input.signalsUnavailable, which pr-scan never sets because it does not
// read artifact bytes), the report JSON must be exactly what the
// pre-policy code emitted.
//
// The expectation is a literal, not a re-derivation from the same
// helpers, because a re-derivation would pass even if both sides drifted
// together.
func TestPRScanPolicy_DefaultOffIsByteIdentical(t *testing.T) {
	prScanPolicyTestEnv(t, "")

	entries := []prScanEntry{
		// New dependency whose name is one edit from "lodash":
		// both offline heuristics that can fire, do.
		evaluatePREntry(rawEntry{Ecosystem: "npm", Name: "lodahs", Version: "1.0.0"}),
		// Upgrade of an exact well-known name: nothing fires, and
		// the nil signals slice must still marshal as null (that is
		// the shipped v1 wire shape, not a bug to tidy up here).
		evaluatePREntry(rawEntry{Ecosystem: "npm", Name: "express", Version: "4.19.0", PreviousVersion: strPtr("4.18.0")}),
	}

	got, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal entries: %v", err)
	}

	const want = `[` +
		`{"ecosystem":"npm","name":"lodahs","version":"1.0.0","previous_version":null,` +
		`"signals":[` +
		`{"id":"sc.typosquat_low","severity":"warn","reason":"name distance to \"lodash\" = 1 (possible typosquat)"},` +
		`{"id":"sc.new_dep","severity":"warn","reason":"new dependency lodahs@1.0.0 introduced in this PR"}` +
		`],"verdict":"warn"},` +
		`{"ecosystem":"npm","name":"express","version":"4.19.0","previous_version":"4.18.0",` +
		`"signals":null,"verdict":"allow"}` +
		`]`

	if string(got) != want {
		t.Fatalf("default-off output is not byte-identical to the pre-policy report.\n got: %s\nwant: %s", got, want)
	}
}

// ---------------------------------------------------------------------------
// 2. Tighten-only
// ---------------------------------------------------------------------------

// TestPRScanPolicy_MonitorRuleCannotClearAWarn pins the boundary in the
// direction operators will actually push on. The loudest pr-scan
// complaint is sc.new_dep firing on every added dependency, and the
// obvious "fix" is a rule that says allow. Policy folds with
// dsl.Stricter, so it cannot: an allow rule changes nothing, and a
// monitor rule adds a row without demoting the existing warn or
// removing any heuristic signal.
func TestPRScanPolicy_MonitorRuleCannotClearAWarn(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "loosen.rego"), `package chainsaw.policy

decision contains {
	"action":  "allow",
	"rule_id": "org/new-deps-are-fine",
	"message": "we do not care about new dependencies",
} if {
	input.surface == "pr"
}

decision contains {
	"action":  "monitor",
	"rule_id": "org/note-it",
	"message": "noted",
} if {
	input.surface == "pr"
}
`)
	prScanPolicyTestEnv(t, dir)

	got := evaluatePREntry(rawEntry{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})

	if got.Verdict != "warn" {
		t.Fatalf("policy must not clear a heuristic warn; verdict = %q, want \"warn\"", got.Verdict)
	}
	if !hasPRSignal(got.Signals, "sc.new_dep") {
		t.Fatalf("the heuristic signal must survive a policy pass, got %+v", got.Signals)
	}
	if hasPRSignal(got.Signals, "policy:org/new-deps-are-fine") {
		t.Fatalf("an allow rule carries no enforcement weight and must emit no row, got %+v", got.Signals)
	}
	if !hasPRSignal(got.Signals, "policy:org/note-it") {
		t.Fatalf("a monitor rule must be visible in the report, got %+v", got.Signals)
	}
	for _, s := range got.Signals {
		if s.ID == "policy:org/note-it" && s.Severity != "warn" {
			t.Fatalf("monitor must project to severity warn, got %q", s.Severity)
		}
	}
}

// ---------------------------------------------------------------------------
// 3. Exit 20 becomes reachable
// ---------------------------------------------------------------------------

// TestPRScanPolicy_BlockRuleMakesExit20Reachable is the deliverable.
//
// Both halves matter. Without a rule the same PR exits 10, which is
// exactly the state that made the shipped Action's default
// `pr-scan-fail-on: block` a no-op: it gates on exit 20 and no offline
// heuristic could ever produce one. With a rule that raises the
// typosquat signal — and ONLY that signal, leaving sc.new_dep at warn —
// the same PR exits 20.
func TestPRScanPolicy_BlockRuleMakesExit20Reachable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping git-backed test in short mode")
	}

	const base = `{"name":"app","version":"1.0.0","dependencies":{"express":"4.18.0"}}`
	const head = `{"name":"app","version":"1.0.0","dependencies":{"express":"4.18.0","lodahs":"1.0.0"}}`
	dir, baseSHA, headSHA := initPRScanRepo(t, "package.json", base, head)

	t.Run("no rule: exit 10, block unreachable", func(t *testing.T) {
		prScanPolicyTestEnv(t, "")
		report, exitCode, err := buildPRScanReport(baseSHA, headSHA, dir)
		if err != nil {
			t.Fatalf("buildPRScanReport: %v", err)
		}
		if exitCode != prScanExitWarning {
			t.Fatalf("baseline exit code = %d, want %d — the baseline must stay exactly as permissive as it was", exitCode, prScanExitWarning)
		}
		if report.Summary.Blocking != 0 {
			t.Fatalf("no offline heuristic emits severity block; Summary.Blocking = %d", report.Summary.Blocking)
		}
	})

	t.Run("operator rule: exit 20", func(t *testing.T) {
		bundle := t.TempDir()
		mustWrite(t, filepath.Join(bundle, "pr.rego"), `package chainsaw.policy

decision contains {
	"action":  "block",
	"rule_id": "org/no-typosquats-in-prs",
	"message": "name is one edit from a well-known package",
} if {
	input.surface == "pr"
	input.isSuspectedTyposquat == true
}
`)
		prScanPolicyTestEnv(t, bundle)

		report, exitCode, err := buildPRScanReport(baseSHA, headSHA, dir)
		if err != nil {
			t.Fatalf("buildPRScanReport: %v", err)
		}
		if exitCode != prScanExitBlocking {
			t.Fatalf("exit code = %d, want %d — a block rule must make exit 20 reachable without --strict", exitCode, prScanExitBlocking)
		}
		if report.Summary.Blocking != 1 {
			t.Fatalf("Summary.Blocking = %d, want 1", report.Summary.Blocking)
		}

		var blocked *prScanEntry
		for i := range report.Added {
			if report.Added[i].Name == "lodahs" {
				blocked = &report.Added[i]
			}
			if report.Added[i].Name == "express" {
				t.Fatalf("express is an exact well-known name and must not be reported as added")
			}
		}
		if blocked == nil {
			t.Fatal("the typosquatted dependency is missing from the report")
		}
		if blocked.Verdict != "block" {
			t.Fatalf("verdict = %q, want \"block\"", blocked.Verdict)
		}
		if !hasPRSignal(blocked.Signals, "policy:org/no-typosquats-in-prs") {
			t.Fatalf("the policy row must name the rule that fired so a reviewer can trace it, got %+v", blocked.Signals)
		}
		// The point of a rule instead of --strict: the noisy signal
		// stays a warn.
		for _, s := range blocked.Signals {
			if s.ID == "sc.new_dep" && s.Severity != "warn" {
				t.Fatalf("sc.new_dep must stay warn — raising one signal must not raise them all; got %q", s.Severity)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 4. Fail posture
// ---------------------------------------------------------------------------

// TestPRScanPolicy_BrokenBundleFailsOpenAndIsCounted: a rule file that
// will not compile is one operator's mistake. On this surface it would
// otherwise wedge every PR in the org, so it must cost them their rules
// and nothing else — and it must be COUNTED, because a silent
// degradation nobody can see is a degradation nobody fixes.
func TestPRScanPolicy_BrokenBundleFailsOpenAndIsCounted(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "broken.rego"), "package chainsaw.policy\n\nthis is not rego {{{\n")
	prScanPolicyTestEnv(t, dir)

	before := GuardPolicyLoadFailureCount()
	got := evaluatePREntry(rawEntry{Ecosystem: "npm", Name: "lodahs", Version: "1.0.0"})

	if got.Verdict == "block" {
		t.Fatalf("a broken bundle must never block a PR, got %+v", got)
	}
	if got.Verdict != "warn" {
		t.Fatalf("the offline heuristics must be unaffected by a broken bundle; verdict = %q, want \"warn\"", got.Verdict)
	}
	for _, s := range got.Signals {
		if strings.HasPrefix(s.ID, prScanPolicySignalPrefix) {
			t.Fatalf("a bundle that did not compile must emit no policy rows, got %+v", s)
		}
	}
	if GuardPolicyLoadFailureCount() == before {
		t.Fatal("a bundle compile failure must be counted, not silent")
	}
}

// TestPRScanPolicy_MissingConfiguredBundleIsCounted: an operator who
// points CHAINSAW_POLICY_BUNDLE at a path that is not there believes
// their PRs are gated and they are not. On a merge gate that is the
// worst failure mode available, so it is counted too.
func TestPRScanPolicy_MissingConfiguredBundleIsCounted(t *testing.T) {
	prScanPolicyTestEnv(t, filepath.Join(t.TempDir(), "does-not-exist"))

	before := GuardPolicyLoadFailureCount()
	evaluatePREntry(rawEntry{Ecosystem: "npm", Name: "some-pkg", Version: "1.0.0"})
	if GuardPolicyLoadFailureCount() == before {
		t.Fatal("a configured-but-absent bundle must be counted")
	}
}

// ---------------------------------------------------------------------------
// 5. The populated-field contract
// ---------------------------------------------------------------------------

// prScanPopulatedInputFields is the EXACT set of policy.Input fields
// pr-scan can honestly populate at SurfacePR, named by their Rego key.
//
// This list is the load-bearing part of the "same Rego, every surface"
// claim. policy.Input carries ~70 fields; pr-scan reads a git diff, so
// it can fill five. A rule an operator wrote against the proxy keyed on
// input.cvss, input.isKnownMalicious, or input.hasInstallScript is
// UNDEFINED here and silently never fires — a merge gate that looks
// configured and enforces nothing.
//
// Changing this list is a product decision about what pr-scan claims to
// know, so it must be made deliberately in this file and not fall out of
// an edit to prScanPolicyInput.
var prScanPopulatedInputFields = []string{
	"ecosystem",
	"isSuspectedTyposquat",
	"package",
	"surface",
	"version",
}

// TestPRScanPolicyInput_PopulatedFieldContract walks policy.Input by
// reflection with the most-populated entry pr-scan can produce and pins
// which fields are non-zero.
func TestPRScanPolicyInput_PopulatedFieldContract(t *testing.T) {
	// The maximal case: every offline heuristic that exists has fired.
	e := rawEntry{Ecosystem: "npm", Name: "lodahs", Version: "1.0.0"}
	in := prScanPolicyInput(e, prOfflineSignals(e))

	if !in.IsSuspectedTyposquat {
		t.Fatal("the typosquat heuristic fired but did not reach policy input — a rule keyed on input.isSuspectedTyposquat would silently never fire at SurfacePR")
	}
	// Rego authors write `input.ecosystem == "npm"`; the manifest
	// parsers are the only thing deciding the case of the string that
	// gets there, so normalize it the way every other surface does.
	upper := rawEntry{Ecosystem: "NPM", Name: "lodahs", Version: "1.0.0"}
	if got := prScanPolicyInput(upper, nil).RepositoryFormat; got != "npm" {
		t.Fatalf("ecosystem must be lower-cased for Rego authors, got %q", got)
	}

	var got []string
	v := reflect.ValueOf(in)
	rt := v.Type()
	for i := 0; i < rt.NumField(); i++ {
		if v.Field(i).IsZero() {
			continue
		}
		got = append(got, regoKey(rt.Field(i)))
	}
	sort.Strings(got)

	if !reflect.DeepEqual(got, prScanPopulatedInputFields) {
		t.Fatalf("SurfacePR populated-field set changed.\n got: %v\nwant: %v\n\n"+
			"If you added a field, update prScanPopulatedInputFields deliberately and check that pr-scan can honestly know it from a git diff. "+
			"If a field DISAPPEARED, every operator rule keyed on it just became a silent no-op at PR time.", got, prScanPopulatedInputFields)
	}
}

// TestPRScanPolicyInput_ProxyOnlyFieldsAreAbsent states the negative
// half of the same contract in the vocabulary operators actually use,
// so the failure message names the trap rather than a diff of two lists.
func TestPRScanPolicyInput_ProxyOnlyFieldsAreAbsent(t *testing.T) {
	e := rawEntry{Ecosystem: "npm", Name: "lodahs", Version: "1.0.0"}
	in := prScanPolicyInput(e, prOfflineSignals(e))

	doc, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(doc, &fields); err != nil {
		t.Fatalf("unmarshal input: %v", err)
	}

	// Fields a rule author is most likely to reach for after writing
	// rules against the proxy. pr-scan reads a git diff: it never
	// fetches the artifact, never consults an advisory feed, and never
	// sees a caller identity, so none of these can be known here.
	for _, key := range []string{
		"cvss", "epss", "cves", "isVulnerable",
		"isKnownMalicious", "hasInstallScript", "trustScore",
		"licenseSpdx", "hasProvenance", "signalsUnavailable",
		"clientId", "repository",
	} {
		if _, ok := fields[key]; ok {
			t.Fatalf("input.%s is present at SurfacePR — pr-scan cannot honestly know it from a git diff; either it is being faked or the contract changed", key)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func hasPRSignal(signals []prScanSignal, id string) bool {
	for _, s := range signals {
		if s.ID == id {
			return true
		}
	}
	return false
}

// regoKey returns the JSON/Rego key for a policy.Input field — the name
// a rule author writes after `input.`.
func regoKey(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" {
		return f.Name
	}
	if name := strings.Split(tag, ",")[0]; name != "" && name != "-" {
		return name
	}
	return f.Name
}
