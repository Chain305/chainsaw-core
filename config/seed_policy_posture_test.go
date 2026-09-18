package config

// seed_policy_posture_test.go — the free-tier default-posture guard.
//
// configs/seed.yaml is baked into the shipped container as
// dockerized/config.yaml and seeded into EVERY new org, free tier
// included (internal/server/policies_seed.go). Whatever mode a rule
// carries here is the mode a hobbyist meets on their first install.
//
// Three of these rules used to ship as `block` and refused ordinary,
// legitimate installs: cooldownDays (a 10-day embargo on every fresh
// version of every package), publisherChanged (every maintainer
// handoff), and isVulnerable (every advisory, at any CVSS, with no
// severity floor). A trial user hit the cooldown rule on a four-day-old
// Playwright alpha and asked how to uninstall Chainsaw.
//
// This guard is deliberately an EXHAUSTIVE table rather than a spot
// check on the three rules that were demoted. A spot check would pass
// while someone seeded a fourth broad block rule next to them, which is
// exactly how the posture drifted the first time. Adding a rule to the
// seed now requires adding it here, which is the point: the mode a new
// org inherits is a product decision, not a YAML default.

import (
	"testing"

	"github.com/chain305/chainsaw-core/policy"
)

// seededPolicyPosture is the mode every policy in the seed config must
// carry. Editing a value here is editing what every new org enforces on
// day one — do it deliberately, and read the comment beside the rule in
// configs/seed.yaml first.
var seededPolicyPosture = map[string]policy.Mode{
	// BLOCK — high precision. A match is strong evidence of an attack and
	// costs approximately no legitimate install.
	"Block packages released within 1 day":         policy.ModeBlock,
	"Block install scripts that fetch remote URLs": policy.ModeBlock,
	"Block bidi-override hidden Unicode payloads":  policy.ModeBlock,

	// MONITOR — real signals that also fire on ordinary legitimate
	// activity. Flagged for review and promoted deliberately per org via
	// the monitor-to-enforce nudge, never enforced by default.
	//
	// These three still read "Block ..." ON PURPOSE. Renaming them to match
	// the mode crashlooped production on 2026-09-18: seeding dedups by NAME
	// and allocates the precedence from the YAML, so on an org holding the
	// old row the renamed rule is INSERTed at a precedence already taken and
	// violates idx_policies_org_precedence_unique. The mode column is the
	// source of truth; the name is an identity key.
	"Block vulnerable packages":                               policy.ModeMonitor,
	"Block publisher-changed versions":                        policy.ModeMonitor,
	"Block brand-new versions (account-takeover / zero-hour)": policy.ModeMonitor,
	"Flag hidden Unicode payloads (any kind)":                 policy.ModeMonitor,
}

func TestSeedConfigPolicyPosture(t *testing.T) {
	t.Parallel()
	requireMonorepoTree(t, "configs")

	for _, path := range seedConfigPaths {
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("load %s: %v", path, err)
		}
		if len(cfg.Policies) == 0 {
			t.Fatalf("%s seeded no policies — the posture guard would pass "+
				"vacuously; this is a DID-NOT-RUN, not a pass", path)
		}

		seen := make(map[string]bool, len(cfg.Policies))
		for _, p := range cfg.Policies {
			seen[p.Name] = true
			want, known := seededPolicyPosture[p.Name]
			if !known {
				t.Errorf("%s: policy %q is not in seededPolicyPosture.\n"+
					"Every seeded rule is inherited by every new org including the free "+
					"tier, so its mode is a deliberate product decision. Add it to the "+
					"table in this file with the mode you intend.", path, p.Name)
				continue
			}
			if p.Mode != want {
				t.Errorf("%s: policy %q has mode %q, want %q.\n"+
					"See the comment beside this rule in configs/seed.yaml before "+
					"changing the expectation.", path, p.Name, p.Mode, want)
			}
		}
		for name := range seededPolicyPosture {
			if !seen[name] {
				t.Errorf("%s: expected seeded policy %q is missing — it was renamed or "+
					"deleted. Seeding dedups by NAME, so a rename also orphans the rule "+
					"in every existing org.", path, name)
			}
		}
	}
}

// TestSeedConfigBlockingModeDefaultsOn pins the other half of the
// posture. Demoting three rules to monitor is only meaningful while the
// remaining block rules still block: blocking_mode: false would turn
// every block policy into a flagged audit entry deployment-wide, which
// is a different (and much larger) decision than this one.
func TestSeedConfigBlockingModeDefaultsOn(t *testing.T) {
	t.Parallel()
	requireMonorepoTree(t, "configs")
	for _, path := range seedConfigPaths {
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("load %s: %v", path, err)
		}
		if !cfg.BlockingEnabled() {
			t.Errorf("%s: blocking_mode is off. The seed demotes the noisy rules "+
				"individually and deliberately; it does not disable enforcement "+
				"deployment-wide.", path)
		}
	}
}
