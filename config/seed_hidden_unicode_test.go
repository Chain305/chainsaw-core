package config

// seed_hidden_unicode_test.go — guards on the seeded hidden-Unicode rules.
//
// The hidden-Unicode control works end to end on the proxy: extracted text
// files are scanned, hits land on the report, the flags reach the
// EvaluationContext and the evaluator sees them. But the only seeded rule
// that BLOCKED on them narrowed to hiddenUnicodeKinds: ["bidi_override"],
// so a U+200B zero-width payload — the commonest GlassWorm shape — was
// detected, scored and then permitted by default policy.
//
// The fix is a second rule in MONITOR mode with no kinds filter, not a
// widened block rule: core/hiddenunicode's threshold is one rune, so
// blocking every kind would hard-block emoji ZWJ sequences and i18n
// fixtures across every ecosystem in a single deploy.
//
// These tests run the real seeded policies through the real evaluator, so
// they fail if either half of that is undone.

import (
	"os"
	"testing"

	"github.com/chain305/chainsaw-core/policy"
	"gopkg.in/yaml.v3"
)

// loadSeededPolicies parses the `policies:` block out of one of the two
// seed config files. Deliberately a minimal schema rather than a full
// config.Load: this asserts on what the file SAYS, and a loader default
// filling something in would hide exactly the drift being guarded.
func loadSeededPolicies(t *testing.T, path string) []policy.Policy {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Policies []policy.Policy `yaml:"policies"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(doc.Policies) == 0 {
		t.Fatalf("%s has no policies — this guard would pass vacuously", path)
	}
	return doc.Policies
}

// hiddenUnicodeContext is a coordinate whose ONLY interesting property is
// the hidden-Unicode hit: no CVE, no release dates, no publisher change, so
// none of the other seeded rules can fire and change the verdict underneath
// the assertion.
func hiddenUnicodeContext(name string, kinds ...string) policy.EvaluationContext {
	return policy.EvaluationContext{
		Repository:         "npmjs",
		RepositoryFormat:   "npm",
		PackageName:        name,
		PackageVersion:     "1.0.0",
		HasHiddenUnicode:   true,
		HiddenUnicodeKinds: kinds,
	}
}

func evaluateSeeded(t *testing.T, path string, ctx policy.EvaluationContext) policy.EvaluationResult {
	t.Helper()
	// NewStore(nil) returns a nil *Store and an error; the evaluator only
	// needs the store for exception lookups, which EvaluateWithPolicies
	// does not perform. Same construction the in-package evaluator tests
	// use.
	store, _ := policy.NewStore(nil)
	eval := policy.NewEvaluator(store)
	return eval.EvaluateWithPolicies(ctx, loadSeededPolicies(t, path), 0)
}

// The defect: a zero-width payload was detected and permitted. It must now
// match a rule — and that rule must NOT block, because the one-rune
// threshold makes a block rule here a mass false-positive.
func TestSeededPolicyFlagsZeroWidthHiddenUnicode(t *testing.T) {
	requireMonorepoTree(t, "configs")
	for _, path := range seedConfigPaths {
		res := evaluateSeeded(t, path, hiddenUnicodeContext("zw-payload", "zero_width"))
		if res.Action == policy.ModeAllow {
			t.Errorf("%s: a zero-width hidden-Unicode payload matched no seeded rule "+
				"— detected, scored and silently permitted", path)
		}
		if res.Action == policy.ModeBlock || res.Action == policy.ModeQuarantine {
			t.Errorf("%s: the zero-width rule refuses (%s). The scan threshold is one "+
				"rune, so this hard-blocks emoji ZWJ sequences and i18n fixtures "+
				"across every ecosystem — it must stay in monitor mode",
				path, res.Action)
		}
		if res.Action != policy.ModeMonitor {
			t.Errorf("%s: zero-width payload resolved to %q, want monitor", path, res.Action)
		}
	}
}

// Control, and the proof the narrow block rule was not disturbed: a
// bidi-override payload must still be refused. Without this, deleting the
// block rule entirely would pass the test above.
func TestSeededPolicyStillBlocksBidiOverride(t *testing.T) {
	requireMonorepoTree(t, "configs")
	for _, path := range seedConfigPaths {
		res := evaluateSeeded(t, path, hiddenUnicodeContext("bidi-payload", "bidi_override"))
		if res.Action != policy.ModeBlock {
			t.Errorf("%s: a bidi-override payload resolved to %q, want block — the "+
				"Trojan Source rule (CVE-2021-42574) has been weakened", path, res.Action)
		}
	}
}

// A package with no hidden Unicode at all must be untouched by either rule.
// Without this, a rule that matched everything would pass both tests above.
func TestSeededHiddenUnicodePoliciesDoNotFireOnCleanPackages(t *testing.T) {
	requireMonorepoTree(t, "configs")
	for _, path := range seedConfigPaths {
		ctx := hiddenUnicodeContext("clean-pkg")
		ctx.HasHiddenUnicode = false
		ctx.HiddenUnicodeKinds = nil
		res := evaluateSeeded(t, path, ctx)
		if res.Action != policy.ModeAllow {
			t.Errorf("%s: a package with no hidden Unicode resolved to %q, want allow",
				path, res.Action)
		}
	}
}

// The two seed files are byte-for-byte twins in their policies block, and
// only one of them is baked into the container image. A fix applied to one
// reaches half the installs.
func TestBothSeedFilesCarryTheSameHiddenUnicodeRules(t *testing.T) {
	requireMonorepoTree(t, "configs")
	shape := func(path string) map[string]string {
		out := map[string]string{}
		for _, p := range loadSeededPolicies(t, path) {
			if p.Conditions.HasHiddenUnicode == nil {
				continue
			}
			out[p.Name] = string(p.Mode) + "/" + string(p.Status) + "/" +
				joinKinds(p.Conditions.HiddenUnicodeKinds)
		}
		return out
	}
	a, b := shape(seedConfigPaths[0]), shape(seedConfigPaths[1])
	if len(a) < 2 {
		t.Fatalf("%s carries %d hidden-Unicode rules, want at least 2 (narrow block + broad monitor)",
			seedConfigPaths[0], len(a))
	}
	for name, want := range a {
		if got, ok := b[name]; !ok || got != want {
			t.Errorf("%q differs between the seed files: %s has %q, %s has %q",
				name, seedConfigPaths[0], want, seedConfigPaths[1], got)
		}
	}
	for name := range b {
		if _, ok := a[name]; !ok {
			t.Errorf("%q exists only in %s", name, seedConfigPaths[1])
		}
	}
}

func joinKinds(kinds []string) string {
	if len(kinds) == 0 {
		return "(any)"
	}
	out := ""
	for i, k := range kinds {
		if i > 0 {
			out += ","
		}
		out += k
	}
	return out
}
