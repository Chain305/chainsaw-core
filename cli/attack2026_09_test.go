package cli

// Attack 2026-09: ForceMemo force-push campaign (2026-03-08..14). Hijacked
// GitHub accounts rebased each repo's latest commit with an obfuscated
// Python tail in setup.py / main.py / app.py and force-pushed the default
// branch (sample: watercrawl/watercrawl-py commit 16f7797f). Victims were
// projects users "install straight from a git URL". No PyPI release.
//
// Chainsaw never fetches or scans a git dependency (not assessed), so the
// payload itself is never seen. What does stop it is the non-registry-source
// policy (v0.22.100): input.nonRegistrySourceUnpinned is true for a git
// install without a full commit SHA, and a block rule on it refuses
// `pip install pkg @ git+https://github.com/o/r` — the branch HEAD a
// force-push rewrites. A consumer pinned to a full SHA keeps the commit it
// reviewed (a force-push creates a new SHA), and that pinned twin is allowed.
// Off by default: the rule must be in the org's Rego bundle. Someone who
// git-clones and runs the repo is outside every surface.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/typosquat"
)

const atk09Rego = `package chainsaw.policy

decision contains {
	"action":  "block",
	"rule_id": "org/non-registry-unpinned",
	"message": sprintf("%s is not pinned to a commit or a content hash", [split(input.nonRegistryOrigin, "/")[0]]),
} if {
	input.nonRegistrySource == true
	input.nonRegistrySourceUnpinned == true
}
`

func TestAttack2026_09_ForceMemoUnpinnedGit(t *testing.T) {
	g := &localGuard{detectors: map[string]*typosquat.Detector{}, malware: malware.NewIndex(nil)}
	unpinned := parsePipSpec("watercrawl-py @ git+https://github.com/watercrawl/watercrawl-py")
	pinned := parsePipSpec("watercrawl-py @ git+https://github.com/watercrawl/watercrawl-py@9d4c1f0e2b3a49586c7d8e9f0a1b2c3d4e5f6a7b")

	// Default (no bundle): not assessed, never refused.
	guardPolicyTestEnv(t, t.TempDir())
	if v := g.evaluateNonRegistry(context.Background(), unpinned); v.Block {
		t.Fatalf("default config refuses an unpinned git install (%+v): update the attack-09 knob", v)
	}

	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "non_registry.rego"), atk09Rego)
	guardPolicyTestEnv(t, dir)
	if v := g.evaluateNonRegistry(context.Background(), unpinned); !v.Block || !strings.Contains(v.Reason, "org/non-registry-unpinned") {
		t.Fatalf("unpinned git install must be refused by the recipe, got %+v", v)
	}
	if v := g.evaluateNonRegistry(context.Background(), pinned); v.Block {
		t.Fatalf("SHA-pinned twin must be allowed, got %+v", v)
	}
}
