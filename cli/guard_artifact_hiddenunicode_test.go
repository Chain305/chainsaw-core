package cli

// Guard-side hidden-unicode tiering tests, plus CLI↔server parity on the
// calibration fixtures the benign-context suppressor was built from
// (typescript@5.4.5's Korean diagnosticMessages catalog and lib.es2015 JSDoc).
// The incident these guard against: 2026-07 false-positive blocks on
// typescript / zod / @types/node from the pre-suppression `any hit → BLOCK`.

import (
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/hiddenunicode"
	"github.com/chain305/chainsaw-core/intelligence"
)

// tsCatalogJSON mirrors typescript@5.4.5's ko/diagnosticMessages.generated.json
// shape: a U+200B word-break aid inside a JSON string VALUE of a localized,
// generated message catalog.
const tsCatalogJSON = `{"Add_missing_typeof_90099":"누락된 'typeof'​ 추가"}`

// tsLibDTS mirrors lib.es2015.core.d.ts: a U+200D zero-width joiner inside a
// JSDoc math expression (`10‍−‍16`). Comments never execute.
const tsLibDTS = "/**\n * Converts 10‍−16 to a number.\n */\nexport declare function f(): number;\n"

func tsShapedFiles() map[string]string {
	return map[string]string{
		"package/package.json":                             `{"name":"typescript-shaped","version":"5.4.5"}`,
		"package/lib/ko/diagnosticMessages.generated.json": tsCatalogJSON,
		"package/lib/lib.es2015.core.d.ts":                 tsLibDTS,
	}
}

// TestAnalyzeArtifact_HiddenUnicodeBenignTypescriptShape is the incident
// regression: the exact benign shapes that blocked typescript must produce
// NO verdict at all — not even a warn — after suppression.
func TestAnalyzeArtifact_HiddenUnicodeBenignTypescriptShape(t *testing.T) {
	v := analyzeArtifact("npm", makeTGZ(t, tsShapedFiles()))
	if v.Block || v.Severity != "" {
		t.Fatalf("typescript-shaped benign unicode must be fully suppressed, got %+v", v)
	}
}

// TestGuardServerHiddenUnicodeParity pins the CLI guard to the server-side
// provider's suppression decisions on the shared calibration fixtures: when
// the server suppressor clears a file map, the guard must be silent; when
// hits survive server-side, the guard must produce a verdict.
func TestGuardServerHiddenUnicodeParity(t *testing.T) {
	benign := map[string][]byte{
		"package/lib/ko/diagnosticMessages.generated.json": []byte(tsCatalogJSON),
		"package/lib/lib.es2015.core.d.ts":                 []byte(tsLibDTS),
	}
	res := hiddenunicode.Scan(benign)
	if res.Hits == 0 {
		t.Fatal("fixture must produce raw hits pre-suppression, or the parity test is vacuous")
	}
	intelligence.SuppressBenignHiddenUnicode(&res, benign)
	if res.Hits != 0 {
		t.Fatalf("server suppressor must clear the calibration fixtures, %d hits survive: %+v", res.Hits, res.PerFile)
	}
	// Guard agrees: same content, no verdict (asserted in the test above);
	// now the inverse — a surviving payload must fire on BOTH surfaces.
	payload := map[string][]byte{
		"package/index.js": []byte("var k = \"" + strings.Repeat("​", 8) + "\";\n"),
	}
	pres := hiddenunicode.Scan(payload)
	intelligence.SuppressBenignHiddenUnicode(&pres, payload)
	if pres.Hits == 0 {
		t.Fatal("payload run must survive server suppression")
	}
	v := analyzeArtifact("npm", makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"evil","version":"1.0.0"}`,
		"package/index.js":     "var k = \"" + strings.Repeat("​", 8) + "\";\n",
	}))
	if !v.Block {
		t.Fatalf("guard must block what survives server suppression, got %+v", v)
	}
}

// TestAnalyzeArtifact_HiddenUnicodeZeroWidthRunInCodeBlocks: a contiguous
// zero-width run longer than the benign word-break ceiling in executable
// source is the GlassWorm byte-encoding shape — hard BLOCK.
func TestAnalyzeArtifact_HiddenUnicodeZeroWidthRunInCodeBlocks(t *testing.T) {
	v := analyzeArtifact("npm", makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"evil","version":"1.0.0"}`,
		"package/index.js":     "var k = \"" + strings.Repeat("​", 8) + "\";\n",
	}))
	if !v.Block || v.Severity != "behavioral-high" {
		t.Fatalf("expected BLOCK for zero-width payload run in code, got %+v", v)
	}
	if !strings.Contains(v.Reason, "zero-width payload") {
		t.Errorf("reason = %q, want zero-width payload detail", v.Reason)
	}
}

// TestAnalyzeArtifact_HiddenUnicodeLoneZeroWidthInDataWarns: the zod /
// @types/node incident class — a stray zero-width in a data file survives
// suppression but must WARN, not break the install.
func TestAnalyzeArtifact_HiddenUnicodeLoneZeroWidthInDataWarns(t *testing.T) {
	v := analyzeArtifact("npm", makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"zod-shaped","version":"3.25.76"}`,
		"package/README.md":    "usage notes ​ here\n",
	}))
	if v.Block {
		t.Fatalf("lone zero-width in a data file must not block, got %+v", v)
	}
	if v.Severity != "behavioral-medium" || !strings.Contains(v.Reason, "zero-width") {
		t.Fatalf("expected behavioral-medium zero-width warn, got %+v", v)
	}
}

// TestAnalyzeArtifact_HiddenUnicodeLoneZeroWidthInCodeWarns: a single
// surviving zero-width in code (no run, below density) is suspicious but not
// certain — warn-tier per the verdict doctrine.
func TestAnalyzeArtifact_HiddenUnicodeLoneZeroWidthInCodeWarns(t *testing.T) {
	v := analyzeArtifact("npm", makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"odd","version":"1.0.0"}`,
		"package/index.js":     "var he​llo = 1;\n",
	}))
	if v.Block {
		t.Fatalf("lone zero-width in code must warn, not block, got %+v", v)
	}
	if v.Severity != "behavioral-medium" {
		t.Fatalf("expected behavioral-medium warn, got %+v", v)
	}
}

// TestAnalyzeArtifact_HiddenUnicodeTagCharBlocksAnywhere: tag characters
// (U+E0000–E007F) have no benign use — BLOCK even in a data file.
func TestAnalyzeArtifact_HiddenUnicodeTagCharBlocksAnywhere(t *testing.T) {
	v := analyzeArtifact("npm", makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"tagged","version":"1.0.0"}`,
		"package/README.md":    "notes \U000E0041\U000E0042 end\n",
	}))
	if !v.Block || !strings.Contains(v.Reason, "tag characters") {
		t.Fatalf("expected BLOCK for tag characters in data file, got %+v", v)
	}
}

// TestAnalyzeArtifact_HiddenUnicodeBidiInI18nSuppressed: bidi marks in a
// translation catalog are legitimate mixed-direction text — fully clean.
func TestAnalyzeArtifact_HiddenUnicodeBidiInI18nSuppressed(t *testing.T) {
	v := analyzeArtifact("npm", makeTGZ(t, map[string]string{
		"package/package.json":    `{"name":"i18n","version":"1.0.0"}`,
		"package/locales/ar.json": "{\"greeting\":\"‫مرحبا‬\"}",
	}))
	if v.Block || v.Severity != "" {
		t.Fatalf("bidi marks in an i18n catalog must be suppressed, got %+v", v)
	}
}

// TestAnalyzeArtifact_HiddenUnicodeBidiInDataFileWarns: a bidi override in a
// NON-i18n data file survives suppression and warns — visible to a reviewer
// without breaking the install.
func TestAnalyzeArtifact_HiddenUnicodeBidiInDataFileWarns(t *testing.T) {
	v := analyzeArtifact("npm", makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"docs","version":"1.0.0"}`,
		"package/README.md":    "see ‮reversed‬ text\n",
	}))
	if v.Block {
		t.Fatalf("bidi in a plain data file must warn, not block, got %+v", v)
	}
	if v.Severity != "behavioral-medium" || !strings.Contains(v.Reason, "bidi override") {
		t.Fatalf("expected behavioral-medium bidi warn, got %+v", v)
	}
}

// shikiGrammarMJS mirrors @shikijs/langs/dist/*.mjs: a syntax-highlighter
// grammar whose identifier `match` regex lists ZWNJ (U+200C) and ZWJ (U+200D)
// as literal members of a `[...]` character class — the CSS/Unicode
// identifier-continue charset. 28 zero-widths (well past the density ceiling),
// all inert regex match-set data. The real-world FP: this is a top-of-ecosystem
// transitive dep (Astro / Expressive Code pull it) and the pre-fix density
// backstop hard-BLOCKed `npm ci` on it.
func shikiGrammarMJS() string {
	// 14 ZWNJ/ZWJ pairs = 28 zero-widths, all inside one bracketed class,
	// interleaved with Unicode letter ranges exactly as shiki emits them.
	class := "[A-Z_a-z" + strings.Repeat("À-Ö‌‍", 14) + "]"
	return "export default [{\"scopeName\":\"source.less\",\"match\":\"--|-?(?:" + class + ")\"}];\n"
}

// TestAnalyzeArtifact_HiddenUnicodeGrammarCharClassSuppressed is the launch
// regression: a highlighter grammar's dense ZWNJ/ZWJ-in-a-character-class must
// be fully suppressed — no BLOCK, no warn — because those runes are literal
// regex data, never an executable identifier.
func TestAnalyzeArtifact_HiddenUnicodeGrammarCharClassSuppressed(t *testing.T) {
	v := analyzeArtifact("npm", makeTGZ(t, map[string]string{
		"package/package.json":  `{"name":"@shikijs/langs","version":"3.23.0"}`,
		"package/dist/less.mjs": shikiGrammarMJS(),
	}))
	if v.Block || v.Severity != "" {
		t.Fatalf("grammar ZWNJ/ZWJ inside a regex char class must be fully suppressed, got %+v", v)
	}
}

// TestAnalyzeArtifact_HiddenUnicodeDenseIdentifierZWOutsideClassBlocks pins the
// anti-bypass boundary: the SAME code points (ZWNJ/ZWJ) at the SAME density,
// but NOT inside a `[...]` class, are not the benign grammar shape — the
// density backstop must still fire. Proves the suppression keys on the
// bracketed-class context, not on the code point alone.
func TestAnalyzeArtifact_HiddenUnicodeDenseIdentifierZWOutsideClassBlocks(t *testing.T) {
	// 28 ZWNJ/ZWJ smuggled into a string value, no surrounding character class.
	payload := "export const k = \"" + strings.Repeat("‌‍", 14) + "\";\n"
	v := analyzeArtifact("npm", makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"evil","version":"1.0.0"}`,
		"package/index.mjs":    payload,
	}))
	if !v.Block {
		t.Fatalf("dense ZWNJ/ZWJ outside a char class must still block, got %+v", v)
	}
}

// TestAnalyzeArtifact_HiddenUnicodeThresholdKnob: the pre-existing
// CHAINSAW_HIDDEN_UNICODE_THRESHOLD knob (ignored by the guard before this
// change) gates the verdict on the post-suppression hit count.
func TestAnalyzeArtifact_HiddenUnicodeThresholdKnob(t *testing.T) {
	t.Setenv("CHAINSAW_HIDDEN_UNICODE_THRESHOLD", "5")
	v := analyzeArtifact("npm", makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"quiet","version":"1.0.0"}`,
		"package/README.md":    "usage notes ​ here\n",
	}))
	if v.Block || v.Severity != "" {
		t.Fatalf("1 surviving hit under threshold 5 must produce no verdict, got %+v", v)
	}
}
