package policy

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
)

// findingFor returns the single finding for field, or fails.
func findingFor(t *testing.T, findings []RangeAuditFinding, field string) RangeAuditFinding {
	t.Helper()
	var hits []RangeAuditFinding
	for _, f := range findings {
		if f.Field == field {
			hits = append(hits, f)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("want exactly 1 finding for %s, got %d (all: %+v)", field, len(hits), findings)
	}
	return hits[0]
}

// TestAuditPolicyRanges_NeverFiresIsDistinctFromMatchAll is the residual's
// whole point: `cvssMin: 999` and `cvssMin: 0` are both wrong, in opposite
// directions, and an operator reading a report that lumps them together
// learns nothing. 999 blocks NOTHING; 0 blocks EVERYTHING.
func TestAuditPolicyRanges_NeverFiresIsDistinctFromMatchAll(t *testing.T) {
	t.Parallel()

	findings := AuditPolicyRanges("qa-org", []Policy{
		{
			ID: "test-999", Name: "block criticals", Mode: ModeBlock, Status: StatusEnabled,
			Conditions: Conditions{CVSSMin: floatPtr(999)},
		},
		{
			ID: "test-zero", Name: "block vulnerable", Mode: ModeBlock, Status: StatusEnabled,
			Conditions: Conditions{CVSSMin: floatPtr(0)},
		},
	})
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(findings), findings)
	}

	never := findings[0]
	if never.PolicyID != "test-999" || never.OrgID != "qa-org" {
		t.Errorf("identity: got id=%q org=%q, want test-999/qa-org", never.PolicyID, never.OrgID)
	}
	if never.PolicyName != "block criticals" || never.Mode != string(ModeBlock) || never.Status != string(StatusEnabled) {
		t.Errorf("row context missing: %+v", never)
	}
	if never.Field != "conditions.cvssMin" || never.Value != 999 {
		t.Errorf("field/value: got %s=%v", never.Field, never.Value)
	}
	if never.ValidRange != "0 to 10" {
		t.Errorf("validRange: got %q, want %q", never.ValidRange, "0 to 10")
	}
	if never.Severity != RangeAuditSeverityError {
		t.Errorf("999 is outside the bound Create enforces, so it is an error, got %q", never.Severity)
	}
	if never.Effect != RangeEffectNeverFires {
		t.Fatalf("effect: got %q, want %q", never.Effect, RangeEffectNeverFires)
	}
	if !strings.Contains(never.Consequence, "blocks nothing") {
		t.Errorf("consequence must say the block policy blocks nothing, got: %s", never.Consequence)
	}

	all := findings[1]
	if all.Effect != RangeEffectMatchesEverything {
		t.Fatalf("cvssMin 0 effect: got %q, want %q", all.Effect, RangeEffectMatchesEverything)
	}
	if all.Severity != RangeAuditSeverityWarning {
		t.Errorf("0 is INSIDE [0,10] so Create accepts it; it is a warning, got %q", all.Severity)
	}
	if !strings.Contains(all.Consequence, "no CVE") {
		t.Errorf("consequence must name the no-CVE package, got: %s", all.Consequence)
	}
	if !strings.Contains(all.Consequence, "blocks every request that reaches it") {
		t.Errorf("consequence must say the block policy blocks everything, got: %s", all.Consequence)
	}
	if all.Consequence == never.Consequence {
		t.Fatal("the two consequences must not read alike — that is the defect")
	}
}

// TestAuditPolicyRanges_CleanStoreReportsNothing — an in-range row is not
// reported. A report that flags healthy policies is one an operator learns
// to ignore.
func TestAuditPolicyRanges_CleanStoreReportsNothing(t *testing.T) {
	t.Parallel()

	findings := AuditPolicyRanges("qa-org", []Policy{
		{
			ID: "ok-1", Name: "block criticals", Mode: ModeBlock, Status: StatusEnabled,
			Conditions: Conditions{CVSSMin: floatPtr(9), CVSSMax: floatPtr(10), EPSSMin: floatPtr(0.5)},
		},
		{
			ID: "ok-2", Name: "slsa baseline", Mode: ModeMonitor, Status: StatusEnabled,
			Conditions: Conditions{RequireSLSALevel: intPtr(3), PackageAge: intPtr(30), CooldownDays: intPtr(7)},
		},
		{
			ID: "ok-3", Name: "trust floor", Mode: ModeBlock, Status: StatusEnabled,
			Conditions: Conditions{TrustScoreMin: intPtr(40), TrustScoreMax: intPtr(100)},
		},
	})
	if len(findings) != 0 {
		t.Fatalf("clean policies must produce no findings, got: %+v", findings)
	}
	if AuditPolicyRanges("qa-org", nil) != nil {
		t.Error("an empty store must audit to nil, not a phantom finding")
	}
}

// TestAuditPolicyRanges_EveryBoundedFieldIsClassified walks each numeric
// condition on both sides of its domain. The classification is derived from
// the evaluator's own compare (core/policy/evaluator.go matchesConditions),
// not from the field name.
func TestAuditPolicyRanges_EveryBoundedFieldIsClassified(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		c        Conditions
		field    string
		effect   string
		severity string
	}{
		{"cvssMin above the CVSS ceiling", Conditions{CVSSMin: floatPtr(999)}, "conditions.cvssMin", RangeEffectNeverFires, RangeAuditSeverityError},
		{"cvssMin below the floor", Conditions{CVSSMin: floatPtr(-1)}, "conditions.cvssMin", RangeEffectMatchesEverything, RangeAuditSeverityError},
		{"cvssMax below the floor", Conditions{CVSSMax: floatPtr(-1)}, "conditions.cvssMax", RangeEffectNeverFires, RangeAuditSeverityError},
		{"cvssMax at the ceiling", Conditions{CVSSMax: floatPtr(10)}, "conditions.cvssMax", RangeEffectMatchesEverything, RangeAuditSeverityWarning},
		{"epssMin above 1", Conditions{EPSSMin: floatPtr(2)}, "conditions.epssMin", RangeEffectNeverFires, RangeAuditSeverityError},
		{"epssMin at 0", Conditions{EPSSMin: floatPtr(0)}, "conditions.epssMin", RangeEffectMatchesEverything, RangeAuditSeverityWarning},
		{"epssMax below 0", Conditions{EPSSMax: floatPtr(-0.5)}, "conditions.epssMax", RangeEffectNeverFires, RangeAuditSeverityError},
		{"trustScoreMin above 100", Conditions{TrustScoreMin: intPtr(200)}, "conditions.trustScoreMin", RangeEffectNeverFires, RangeAuditSeverityError},
		{"trustScoreMin at 0", Conditions{TrustScoreMin: intPtr(0)}, "conditions.trustScoreMin", RangeEffectMatchesEverything, RangeAuditSeverityWarning},
		{"requireSlsaLevel above 4", Conditions{RequireSLSALevel: intPtr(99)}, "conditions.requireSlsaLevel", RangeEffectNeverFires, RangeAuditSeverityError},
		{"requireSlsaLevel 0", Conditions{RequireSLSALevel: intPtr(0)}, "conditions.requireSlsaLevel", RangeEffectMatchesEverything, RangeAuditSeverityError},
		{"packageAge negative", Conditions{PackageAge: intPtr(-1)}, "conditions.packageAge", RangeEffectNeverFires, RangeAuditSeverityError},
		{"cooldownDays negative", Conditions{CooldownDays: intPtr(-3)}, "conditions.cooldownDays", RangeEffectNeverFires, RangeAuditSeverityError},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings := AuditPolicyRanges("", []Policy{{
				ID: "p", Name: tc.name, Mode: ModeBlock, Status: StatusEnabled, Conditions: tc.c,
			}})
			f := findingFor(t, findings, tc.field)
			if f.Effect != tc.effect {
				t.Errorf("effect: got %q, want %q (consequence: %s)", f.Effect, tc.effect, f.Consequence)
			}
			if f.Severity != tc.severity {
				t.Errorf("severity: got %q, want %q", f.Severity, tc.severity)
			}
			if f.Comparison == "" {
				t.Error("every finding must carry the evaluator comparison it was derived from")
			}
		})
	}
}

// TestAuditPolicyRanges_ContradictoryPairNeverFires — min > max is legal on
// each half and impossible together.
func TestAuditPolicyRanges_ContradictoryPairNeverFires(t *testing.T) {
	t.Parallel()

	findings := AuditPolicyRanges("", []Policy{{
		ID: "pair", Name: "impossible window", Mode: ModeQuarantine, Status: StatusEnabled,
		Conditions: Conditions{CVSSMin: floatPtr(9), CVSSMax: floatPtr(1)},
	}})
	f := findingFor(t, findings, "conditions.cvssMin")
	if f.Effect != RangeEffectNeverFires {
		t.Fatalf("effect: got %q, want never_fires", f.Effect)
	}
	if f.ValidRange != "0 to 1" {
		t.Errorf("the range must be narrowed by the sibling bound, got %q", f.ValidRange)
	}
	if !strings.Contains(f.Consequence, "quarantines nothing") {
		t.Errorf("consequence must speak the policy's own mode, got: %s", f.Consequence)
	}
}

// TestAuditPolicyRanges_MatchAllWithOtherConditionsIsInert — a match-all
// threshold on a policy that ALSO gates on something else does not make the
// policy block everything; it makes that one condition inert. Saying
// "blocks everything" there would be a false alarm.
func TestAuditPolicyRanges_MatchAllWithOtherConditionsIsInert(t *testing.T) {
	t.Parallel()

	findings := AuditPolicyRanges("", []Policy{{
		ID: "narrowed", Name: "malware + cvss floor", Mode: ModeBlock, Status: StatusEnabled,
		Conditions: Conditions{CVSSMin: floatPtr(0), IsKnownMalicious: boolPtr(true)},
	}})
	f := findingFor(t, findings, "conditions.cvssMin")
	if f.Effect != RangeEffectMatchesEverything {
		t.Fatalf("effect: got %q", f.Effect)
	}
	if strings.Contains(f.Consequence, "blocks every request") {
		t.Errorf("must NOT claim the policy blocks everything — isKnownMalicious still narrows it: %s", f.Consequence)
	}
	if !strings.Contains(f.Consequence, "narrows nothing") {
		t.Errorf("consequence must say the condition is inert, got: %s", f.Consequence)
	}

	// An identifier is a narrowing too.
	scoped := AuditPolicyRanges("", []Policy{{
		ID: "scoped", Name: "one package", Mode: ModeBlock, Status: StatusEnabled,
		Identifier: Identifier{TargetPackageName: "lodash"},
		Conditions: Conditions{CVSSMin: floatPtr(0)},
	}})
	if s := findingFor(t, scoped, "conditions.cvssMin"); !strings.Contains(s.Consequence, "narrows nothing") {
		t.Errorf("an identifier narrows the policy, got: %s", s.Consequence)
	}
}

// TestAuditPolicyRanges_BothHalvesMatchAllStillBlocksEverything — cvssMin: 0
// paired with cvssMax: 10 is two inert conditions, not two narrowings. The
// naive "does any other field exist?" answer says each is narrowed by the
// other and reports the policy as harmless; it is a match-all block.
func TestAuditPolicyRanges_BothHalvesMatchAllStillBlocksEverything(t *testing.T) {
	t.Parallel()

	findings := AuditPolicyRanges("", []Policy{{
		ID: "wide", Name: "the whole range", Mode: ModeBlock, Status: StatusEnabled,
		Conditions: Conditions{CVSSMin: floatPtr(0), CVSSMax: floatPtr(10)},
	}})
	if len(findings) != 2 {
		t.Fatalf("want a finding per half, got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if !strings.Contains(f.Consequence, "blocks every request that reaches it") {
			t.Errorf("%s: both halves are inert, so the policy matches everything: %s", f.Field, f.Consequence)
		}
	}
}

// TestAuditPolicyRanges_TrustScoreMatchAllIsQualified — a package with no
// trust score matches NEITHER trust bound (evaluator.go: `ctx.TrustScore ==
// nil` fails both), so trustScoreMin: 0 does not match literally every
// package the way cvssMin: 0 does.
func TestAuditPolicyRanges_TrustScoreMatchAllIsQualified(t *testing.T) {
	t.Parallel()

	f := findingFor(t, AuditPolicyRanges("", []Policy{{
		ID: "trust", Name: "trust floor", Mode: ModeBlock, Status: StatusEnabled,
		Conditions: Conditions{TrustScoreMin: intPtr(0)},
	}}), "conditions.trustScoreMin")
	if !strings.Contains(f.Consequence, "trust score") {
		t.Errorf("consequence must qualify the population, got: %s", f.Consequence)
	}
	if strings.Contains(f.Consequence, "blocks every request that reaches it.") {
		t.Errorf("unqualified match-all claim is wrong for a signal a package can lack: %s", f.Consequence)
	}
}

// TestAuditPolicyRanges_DisabledRowSaysItDoesNotEvaluate — the evaluator
// only honours StatusEnabled, so a disabled bad row is a latent problem,
// not a live one, and the report must not read like an outage.
func TestAuditPolicyRanges_DisabledRowSaysItDoesNotEvaluate(t *testing.T) {
	t.Parallel()

	f := findingFor(t, AuditPolicyRanges("", []Policy{{
		ID: "off", Name: "parked", Mode: ModeBlock, Status: StatusDisabled,
		Conditions: Conditions{CVSSMin: floatPtr(999)},
	}}), "conditions.cvssMin")
	if !strings.Contains(f.Consequence, "disabled") {
		t.Errorf("consequence must say the row is disabled, got: %s", f.Consequence)
	}
}

// TestAuditPolicyRanges_ExceptionConditionsAreNeverEvaluated — the evaluator
// short-circuits a KindException row on the identifier alone
// (evaluator.go matchesPolicy) and never reads its conditions, so an
// out-of-range value there changes no verdict. Reporting it as a blocking
// change would send an operator to edit a row that does nothing.
func TestAuditPolicyRanges_ExceptionConditionsAreNeverEvaluated(t *testing.T) {
	t.Parallel()

	f := findingFor(t, AuditPolicyRanges("", []Policy{{
		ID: "exc", Name: "Exception: lodash@4.17.21", Mode: ModeAllow, Status: StatusEnabled,
		Kind:       KindException,
		Identifier: Identifier{TargetPackageName: "lodash", TargetPackageVersion: "4.17.21"},
		Conditions: Conditions{CVSSMin: floatPtr(999)},
	}}), "conditions.cvssMin")
	if !strings.Contains(f.Consequence, "never reads") {
		t.Errorf("consequence must say the exception path never reads conditions, got: %s", f.Consequence)
	}
	if strings.Contains(f.Consequence, "allow policy") {
		t.Errorf("must not describe a mode effect the evaluator never applies: %s", f.Consequence)
	}
}

// TestAuditPolicyRanges_CoversEveryStoreRangeError is the parity guard: any
// value Store.Create now REFUSES must be findable by the audit on a row
// that predates the bound. If the two drift, an operator can hold a row the
// API would reject and the audit stays silent about it.
func TestAuditPolicyRanges_CoversEveryStoreRangeError(t *testing.T) {
	t.Parallel()

	conds := []Conditions{
		{CVSSMin: floatPtr(999)},
		{CVSSMin: floatPtr(-1)},
		{CVSSMax: floatPtr(10.1)},
		{EPSSMin: floatPtr(2)},
		{EPSSMax: floatPtr(-1)},
		{CVSSMin: floatPtr(9), CVSSMax: floatPtr(1)},
		{EPSSMin: floatPtr(0.9), EPSSMax: floatPtr(0.1)},
		{TrustScoreMin: intPtr(-5)},
		{TrustScoreMax: intPtr(101)},
		{TrustScoreMin: intPtr(80), TrustScoreMax: intPtr(10)},
		{RequireSLSALevel: intPtr(0)},
		{RequireSLSALevel: intPtr(5)},
		{PackageAge: intPtr(-1)},
		{CooldownDays: intPtr(-1)},
	}
	for _, c := range conds {
		violations := conditionRangeViolations(c)
		if len(violations) == 0 {
			t.Fatalf("fixture is wrong — the store accepts %+v", c)
		}
		findings := AuditPolicyRanges("", []Policy{{
			ID: "p", Name: "legacy", Mode: ModeBlock, Status: StatusEnabled, Conditions: c,
		}})
		for _, v := range violations {
			found := false
			for _, f := range findings {
				if f.Field == v.Field && f.Severity == RangeAuditSeverityError {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Store.Create refuses %s but the audit does not report it as an error: %+v", v.Field, findings)
			}
		}
	}
}

// TestStoreAuditRanges_FindsRowsWrittenBeforeTheBound seeds the exact shape
// the residual is about — a row written straight to SQL, as every pre-A1 row
// was — and proves the store-level entry point surfaces it.
func TestStoreAuditRanges_FindsRowsWrittenBeforeTheBound(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	base, err := NewStore(db)
	if err != nil {
		t.Fatalf("new policy store: %v", err)
	}
	orgID := "test-audit-" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	t.Cleanup(func() { _, _ = db.DB().Exec(`DELETE FROM policies WHERE org_id=?`, orgID) })
	store := base.ForOrg(orgID)

	clean, err := store.Create(Policy{
		Name: "clean row", Precedence: 500, Mode: ModeBlock, Status: StatusEnabled,
		Conditions: Conditions{CVSSMin: floatPtr(7)},
	})
	if err != nil {
		t.Fatalf("create clean: %v", err)
	}
	findings, err := store.AuditRanges()
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("a clean org must audit clean, got: %+v", findings)
	}

	// A different threshold from the clean row above: identical
	// mode+identifier+conditions+scope is a duplicate by parameter hash.
	legacy, err := store.Create(Policy{
		Name: "legacy row", Precedence: 501, Mode: ModeBlock, Status: StatusEnabled,
		Conditions: Conditions{CVSSMin: floatPtr(8)},
	})
	if err != nil {
		t.Fatalf("create legacy: %v", err)
	}
	if _, err := db.DB().Exec(`UPDATE policies SET conditions=? WHERE id=?`, `{"cvssMin":999}`, legacy.ID); err != nil {
		t.Fatalf("seed legacy out-of-range row: %v", err)
	}

	findings, err = store.AuditRanges()
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want exactly the legacy row, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.PolicyID != legacy.ID || f.PolicyID == clean.ID {
		t.Errorf("wrong row: %+v", f)
	}
	if f.OrgID != orgID {
		t.Errorf("org: got %q, want %q", f.OrgID, orgID)
	}
	if f.Effect != RangeEffectNeverFires || !strings.Contains(f.Consequence, "blocks nothing") {
		t.Errorf("consequence: %+v", f)
	}

	// The audit is read-only: the row it reported is untouched.
	after, err := store.Get(legacy.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if after.Conditions.CVSSMin == nil || *after.Conditions.CVSSMin != 999 {
		t.Fatalf("the audit must not repair anything, conditions are now %+v", after.Conditions)
	}
}

// TestStoreAuditRanges_NilStore keeps the nil guard honest — every other
// Store method answers with an error rather than panicking.
func TestStoreAuditRanges_NilStore(t *testing.T) {
	t.Parallel()
	var s *Store
	if _, err := s.AuditRanges(); err == nil {
		t.Fatal("a nil store must return an error, not nil findings")
	} else if !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("unexpected error: %v", err)
	}
}

// A min>max pair is unsatisfiable because of its sibling, not because the
// signal cannot reach the threshold. The consequence used to read "no
// package's trust score can reach 80 — the highest possible is 100",
// which is visibly false and points at the wrong half of the rule.
func TestAuditPolicyRanges_PairConsequenceNamesTheSibling(t *testing.T) {
	lo, hi := 80, 20
	p := Policy{
		ID: "pol-pair", Name: "contradictory", Kind: KindEnforcement,
		Mode: ModeBlock, Status: StatusEnabled,
		Conditions: Conditions{TrustScoreMin: &lo, TrustScoreMax: &hi},
	}
	found := AuditPolicyRanges("org", []Policy{p})
	if len(found) != 1 {
		t.Fatalf("want exactly one pair finding, got %d: %+v", len(found), found)
	}
	c := found[0].Consequence
	if strings.Contains(c, "the highest possible is") {
		t.Errorf("consequence blames the signal ceiling instead of the paired maximum:\n%s", c)
	}
	if !strings.Contains(c, "80") || !strings.Contains(c, "20") {
		t.Errorf("consequence does not name both halves of the contradiction:\n%s", c)
	}
}
