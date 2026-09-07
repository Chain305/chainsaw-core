package policy

import (
	"sync"
	"testing"
	"time"
)

// F5 — a publish-age gate whose keying date is absent must become
// VISIBLE (metric + audit reason) without becoming a BLOCK.
//
// The fail-open here is a stated decision, not an oversight: the
// evaluator is specified to fail open so a slow registry never converts
// into a spurious block, and the condition language is a pure
// conjunction, so "match on an absent date" would silently strengthen
// every unrelated rule that happens to carry cooldownDays. These tests
// pin BOTH halves — the new signal, and the unchanged verdict — so a
// later reader who mistakes the fail-open for the bug gets a red suite
// rather than a shipped regression.

// recordingPublishDateMetric captures the package-level recorder's
// calls. Installs and restores around fn; not parallel-safe by
// construction (the recorder is package state), so these tests must not
// call t.Parallel.
type recordingPublishDateMetric struct {
	mu      sync.Mutex
	samples [][2]string
}

func (r *recordingPublishDateMetric) all() [][2]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][2]string, len(r.samples))
	copy(out, r.samples)
	return out
}

func withPublishDateMetric(fn func(*recordingPublishDateMetric)) {
	rec := &recordingPublishDateMetric{}
	SetPublishDateUnavailableRecorder(func(condition, ecosystem string) {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.samples = append(rec.samples, [2]string{condition, ecosystem})
	})
	defer SetPublishDateUnavailableRecorder(nil)
	fn(rec)
}

func npmRequest() EvaluationContext {
	return EvaluationContext{
		OrgID: "org-1", Repository: "npmjs", RepositoryFormat: "npm",
		PackageName: "axios", PackageVersion: "1.7.2",
	}
}

// TestCooldownWithNoVersionDateIsVisibleAndStillAllows is the core F5
// assertion, and it is deliberately three assertions in one test
// because separating them is how the fail-open gets "fixed" by
// accident: the signal fires, the audit row says the rule RAN, and the
// verdict is still allow.
func TestCooldownWithNoVersionDateIsVisibleAndStillAllows(t *testing.T) {
	ctx := npmRequest()
	ctx.VersionReleaseDate = nil // the whole point

	pol := Policy{
		ID: "pol-cooldown", Status: StatusEnabled, Mode: ModeBlock,
		Conditions: Conditions{CooldownDays: intPtr(7)},
	}

	withPublishDateMetric(func(rec *recordingPublishDateMetric) {
		auditor, res := evalWithAuditor([]Policy{pol}, ctx)

		// (1) The verdict has NOT moved. Do not "fix" this.
		if res.Action != ModeAllow {
			t.Fatalf("verdict = %s, want %s. The absent-date branch is a STATED "+
				"fail-open (see SkipReasonPublishDateUnavailable): matching on an "+
				"absent date turns every undated package into a block and, because "+
				"conditions are a pure conjunction, silently strengthens every "+
				"unrelated rule carrying cooldownDays.", res.Action, ModeAllow)
		}

		// (2) The metric fired, labelled by condition and ecosystem.
		got := rec.all()
		if len(got) != 1 {
			t.Fatalf("publish-date metric samples = %v, want exactly 1", got)
		}
		if got[0] != [2]string{string(ConditionCooldown), "npm"} {
			t.Errorf("metric sample = %v, want [Cooldown npm]", got[0])
		}

		// (3) The audit row exists, names the condition, and says the
		// rule RAN — a sink keying on RuleEvaluated must not report it
		// as `policy.rule.skipped`.
		events := auditor.byReason(SkipReasonPublishDateUnavailable)
		if len(events) != 1 {
			t.Fatalf("audit events = %d, want 1 (%+v)", len(events), events)
		}
		ev := events[0]
		if !ev.RuleEvaluated {
			t.Error("RuleEvaluated=false — the rule DID run; a sink will file this " +
				"under policy.rule.skipped and assert a discard that never happened")
		}
		if ev.Condition != string(ConditionCooldown) {
			t.Errorf("condition = %q, want %q", ev.Condition, ConditionCooldown)
		}
		if ev.Ecosystem != "npm" || ev.PolicyID != "pol-cooldown" || ev.OrgID != "org-1" {
			t.Errorf("event mis-attributed: %+v", ev)
		}
	})
}

// TestCooldownWithVersionDateEmitsNothing — no noise on the path that
// can actually decide. A signal that fires when the date IS present
// tells an operator nothing.
func TestCooldownWithVersionDateEmitsNothing(t *testing.T) {
	old := time.Now().Add(-90 * 24 * time.Hour)
	ctx := npmRequest()
	ctx.VersionReleaseDate = &old

	withPublishDateMetric(func(rec *recordingPublishDateMetric) {
		auditor, res := evalWithAuditor([]Policy{{
			ID: "p", Status: StatusEnabled, Mode: ModeBlock,
			Conditions: Conditions{CooldownDays: intPtr(7)},
		}}, ctx)
		if res.Action != ModeAllow {
			t.Fatalf("a 90-day-old version must not match cooldownDays:7, got %s", res.Action)
		}
		if n := len(rec.all()); n != 0 {
			t.Errorf("%d metric samples on a dated package — the signal must mean "+
				"'could not tell', not 'did not match'", n)
		}
		if n := len(auditor.byReason(SkipReasonPublishDateUnavailable)); n != 0 {
			t.Errorf("%d audit events on a dated package", n)
		}
	})
}

// TestDarkPublishDateIsRecordOnly — wiring the auditor must move no
// verdict, for any mode and either polarity of a second condition.
func TestDarkPublishDateIsRecordOnly(t *testing.T) {
	conds := []Conditions{
		{CooldownDays: intPtr(7)},
		{PackageAge: intPtr(30)},
		{CooldownDays: intPtr(7), PackageAge: intPtr(30)},
		{CooldownDays: intPtr(7), IsKnownMalicious: boolPtr(true)},
		{PackageAge: intPtr(30), IsVulnerable: boolPtr(false)},
	}
	for _, mode := range []Mode{ModeBlock, ModeAllow, ModeMonitor, ModeQuarantine} {
		for i, c := range conds {
			for _, malicious := range []bool{false, true} {
				ctx := npmRequest()
				ctx.IsKnownMalicious = malicious
				p := Policy{ID: "p", Status: StatusEnabled, Mode: mode, Conditions: c}

				bare := verdict(t, []Policy{p}, ctx)
				_, withAudit := evalWithAuditor([]Policy{p}, ctx)
				if bare != withAudit.Action {
					t.Fatalf("VERDICT MOVED (%s cond#%d malicious=%v): %s without auditor, "+
						"%s with. The publish-date marker must be record-only.",
						mode, i, malicious, bare, withAudit.Action)
				}
			}
		}
	}
}

// TestAPTCooldownEmitsExactlyOneSkipRecord — the double-report guard.
//
// ConditionCooldown is SupportNone for APT, so detectUnsupported
// already discards the whole policy and emits `policy.rule.skipped`
// (RuleEvaluated=false). If the publish-date emitter also fired, the
// operator would read one rule as both discarded and evaluated — the
// exact conflation the two audit actions exist to remove.
func TestAPTCooldownEmitsExactlyOneSkipRecord(t *testing.T) {
	ctx := aptRequest()
	ctx.VersionReleaseDate = nil

	withPublishDateMetric(func(rec *recordingPublishDateMetric) {
		auditor, _ := evalWithAuditor([]Policy{{
			ID: "pol-apt", Status: StatusEnabled, Mode: ModeBlock,
			Conditions: Conditions{CooldownDays: intPtr(7)},
		}}, ctx)

		unsupported := auditor.byReason(SkipReasonUnsupportedEcosystem)
		darkDate := auditor.byReason(SkipReasonPublishDateUnavailable)

		if len(unsupported) != 1 {
			t.Fatalf("unsupported_ecosystem events = %d, want 1 (%+v)", len(unsupported), unsupported)
		}
		if len(darkDate) != 0 {
			t.Errorf("publish_date_unavailable events = %d, want 0 — APT cooldown is "+
				"already reported as a hard skip; two records for one rule tells the "+
				"operator it both did and did not run", len(darkDate))
		}
		if n := len(rec.all()); n != 0 {
			t.Errorf("%d metric samples for an APT cooldown policy that was discarded "+
				"before it ever consulted a date", n)
		}
	})
}

// TestDarkPublishDateOnlyFiresForTargetedPolicies — a rule scoped to
// another coordinate says nothing about this request, and one row per
// policy per request would bury the rows that mean something.
func TestDarkPublishDateOnlyFiresForTargetedPolicies(t *testing.T) {
	ctx := npmRequest() // axios @ npmjs

	cases := []struct {
		name string
		pol  Policy
		want int
	}{
		{"targets this package", Policy{
			ID: "p", Status: StatusEnabled, Mode: ModeBlock,
			Identifier: Identifier{TargetPackageName: "axios"},
			Conditions: Conditions{CooldownDays: intPtr(7)},
		}, 1},
		{"targets another package", Policy{
			ID: "p", Status: StatusEnabled, Mode: ModeBlock,
			Identifier: Identifier{TargetPackageName: "lodash"},
			Conditions: Conditions{CooldownDays: intPtr(7)},
		}, 0},
		{"scoped to another client", Policy{
			ID: "p", Status: StatusEnabled, Mode: ModeBlock,
			Scope:      Scope{TargetClient: []string{"ci-runner"}},
			Conditions: Conditions{CooldownDays: intPtr(7)},
		}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auditor, _ := evalWithAuditor([]Policy{tc.pol}, ctx)
			if n := len(auditor.byReason(SkipReasonPublishDateUnavailable)); n != tc.want {
				t.Errorf("events = %d, want %d", n, tc.want)
			}
		})
	}
}

// TestPublishDateSignalIsOrderIndependent — the emitter is hoisted out
// of matchesConditions precisely because that function short-circuits.
// A policy carrying BOTH dark columns must report both, regardless of
// which one a short-circuiting matcher would have reached first.
func TestPublishDateSignalIsOrderIndependent(t *testing.T) {
	ctx := npmRequest()
	ctx.PackageReleaseDate = nil
	ctx.VersionReleaseDate = nil

	withPublishDateMetric(func(rec *recordingPublishDateMetric) {
		auditor, _ := evalWithAuditor([]Policy{{
			ID: "p", Status: StatusEnabled, Mode: ModeBlock,
			// isVulnerable:true is a guaranteed non-match on this ctx and
			// sits BEFORE both date branches in matchesConditions, so an
			// emitter living inside that function would report nothing at
			// all here.
			Conditions: Conditions{
				IsVulnerable: boolPtr(true),
				PackageAge:   intPtr(30),
				CooldownDays: intPtr(7),
			},
		}}, ctx)

		var conds []string
		for _, ev := range auditor.byReason(SkipReasonPublishDateUnavailable) {
			conds = append(conds, ev.Condition)
		}
		if len(conds) != 2 || conds[0] != string(ConditionPackageAge) || conds[1] != string(ConditionCooldown) {
			t.Errorf("conditions = %v, want [PackageAge Cooldown] — both dark columns, "+
				"in a fixed order that does not depend on Conditions' field order", conds)
		}
		if n := len(rec.all()); n != 2 {
			t.Errorf("metric samples = %d, want 2", n)
		}
	})
}

// --- N1: packageAge and cooldownDays must key on DIFFERENT dates ------

// TestPackageAgeAndCooldownKeyOnDifferentDates is the adversarial case
// the evaluator's own doc comment describes and production did not
// deliver: an account-takeover publishes a NEW version of an OLD
// package. cooldownDays must fire; packageAge must not.
//
// Before the N1 fix every proxy path wrote the VERSION's date into both
// PackageReleaseDate and VersionReleaseDate, so the two conditions were
// the same control under two names and this test's second half failed.
func TestPackageAgeAndCooldownKeyOnDifferentDates(t *testing.T) {
	created := time.Now().Add(-3650 * 24 * time.Hour) // decade-old package
	published := time.Now().Add(-2 * time.Hour)       // brand-new version

	ctx := npmRequest()
	ctx.PackageReleaseDate = &created
	ctx.VersionReleaseDate = &published

	cooldown := Policy{
		ID: "pol-cooldown", Status: StatusEnabled, Mode: ModeBlock,
		Conditions: Conditions{CooldownDays: intPtr(7)},
	}
	packageAge := Policy{
		ID: "pol-package-age", Status: StatusEnabled, Mode: ModeBlock,
		Conditions: Conditions{PackageAge: intPtr(30)},
	}

	if got := verdict(t, []Policy{cooldown}, ctx); got != ModeBlock {
		t.Errorf("cooldownDays:7 on a 2-hour-old VERSION = %s, want %s — this is the "+
			"Axios/Chalk account-takeover shape and it is the whole reason cooldown "+
			"keys on VersionReleaseDate", got, ModeBlock)
	}
	if got := verdict(t, []Policy{packageAge}, ctx); got != ModeAllow {
		t.Errorf("packageAge:30 on a decade-old PACKAGE = %s, want %s. If this blocks, "+
			"PackageReleaseDate is being aliased to the version's date and the two "+
			"conditions are one control under two names (N1)", got, ModeAllow)
	}

	// And the mirror: a genuinely new package trips packageAge.
	fresh := time.Now().Add(-24 * time.Hour)
	newPkg := npmRequest()
	newPkg.PackageReleaseDate = &fresh
	newPkg.VersionReleaseDate = &fresh
	if got := verdict(t, []Policy{packageAge}, newPkg); got != ModeBlock {
		t.Errorf("packageAge:30 on a 1-day-old package = %s, want %s", got, ModeBlock)
	}
}

// --- matchesPackageName: PEP 503 folding, pip only --------------------

// TestBlockRuleFoldsPEP503SeparatorsOnPyPIOnly. The proxy canonicalises
// pip coordinates, so a rule authored `foo_bar` must still match the
// `foo-bar` that reaches the evaluator — otherwise it is a silent no-op
// block rule. It must NOT fold on npm/maven/go, where `foo_bar` and
// `foo-bar` are different packages owned by different people.
func TestBlockRuleFoldsPEP503SeparatorsOnPyPIOnly(t *testing.T) {
	cases := []struct {
		format  string
		pkg     string
		pattern string
		want    bool
		why     string
	}{
		{"pip", "foo-bar", "foo_bar", true, "PEP 503: pip install foo_bar and foo-bar fetch identical bytes"},
		{"pypi", "foo-bar", "foo_bar", true, "the pypi format alias must fold identically to pip"},
		{"pip", "foo-bar", "Foo.Bar", true, "PEP 503 collapses . and _ to - and lowercases"},
		{"pip", "foo--bar", "foo_bar", true, "PEP 503 collapses RUNS of separators"},
		{"pip", "foobar", "foo_bar", false, "folding separators must not delete them"},
		{"npm", "foo-bar", "foo_bar", false, "npm foo_bar and foo-bar are different packages"},
		{"maven", "com.acme:foo-bar", "com.acme:foo_bar", false, "maven artifactIds keep separators"},
		{"go", "example.com/foo-bar", "example.com/foo_bar", false, "go module paths keep separators"},
		{"", "foo-bar", "foo_bar", false, "an unresolved format means no fold — fail-safe, and the state simulate is in"},
		{"npm", "foo-bar", "FOO-BAR", true, "case-insensitivity is unchanged on every ecosystem"},
	}
	for _, tc := range cases {
		ctx := EvaluationContext{
			OrgID: "org-1", Repository: "r", RepositoryFormat: tc.format,
			PackageName: tc.pkg, PackageVersion: "1.0.0",
		}
		pol := Policy{
			ID: "p", Status: StatusEnabled, Mode: ModeBlock,
			Identifier: Identifier{TargetPackageName: tc.pattern},
		}
		gotMode := verdict(t, []Policy{pol}, ctx)
		got := gotMode == ModeBlock
		if got != tc.want {
			t.Errorf("format=%q pkg=%q pattern=%q: matched=%v, want %v — %s",
				tc.format, tc.pkg, tc.pattern, got, tc.want, tc.why)
		}
	}
}

// TestMatchesPackageNameLeavesRepoLegAlone — the fold is on the NAME
// leg only. Repository names are chainsaw's own, not PEP 503
// identifiers, and folding them would make a pip-scoped rule match a
// repository the operator never named.
func TestMatchesPackageNameLeavesRepoLegAlone(t *testing.T) {
	ctx := EvaluationContext{
		OrgID: "org-1", Repository: "pypi-proxy", RepositoryFormat: "pip",
		PackageName: "requests", PackageVersion: "2.32.3",
	}
	pol := Policy{
		ID: "p", Status: StatusEnabled, Mode: ModeBlock,
		Identifier: Identifier{TargetPackageRepo: "pypi_proxy", TargetPackageName: "requests"},
	}
	if got := verdict(t, []Policy{pol}, ctx); got != ModeAllow {
		t.Errorf("repo leg folded separators (got %s) — matchesPattern must stay "+
			"untouched on the repository leg", got)
	}
}

// TestMatchesPackageNameWildcardStillMatches — the "*" short-circuit
// must survive the ecosystem gate on every format.
func TestMatchesPackageNameWildcardStillMatches(t *testing.T) {
	for _, format := range []string{"pip", "npm", ""} {
		if !matchesPackageName(format, "anything_at_all", "*") {
			t.Errorf("format=%q: wildcard stopped matching", format)
		}
	}
}
