package intelligence

import (
	"context"
	"strings"
	"testing"
)

func TestHiddenUnicodeProvider_DetectsZeroWidth(t *testing.T) {
	p := newHiddenUnicodeProvider()
	if !p.Supports("npm") {
		t.Fatalf("npm should be supported")
	}
	if !p.NeedsArtifact() {
		t.Fatalf("provider should report NeedsArtifact=true")
	}

	// U+200B = zero-width space. Embed in a .js file under an npm
	// tarball's conventional "package/" prefix.
	evil := "const x = \"a\u200Bb\";\n"
	payload := buildTGZ(t, map[string]string{
		"package/index.js":     evil,
		"package/package.json": `{"name":"x","version":"1.0.0"}`,
	})

	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil {
		t.Fatalf("expected Scan to be populated")
	}
	if partial.Scan.HiddenUnicodeHits == 0 {
		t.Fatalf("expected at least one hit, got 0")
	}
	if !partial.Scan.Performed {
		t.Fatalf("Performed should be true")
	}
	foundZW := false
	for _, kind := range partial.Scan.HiddenUnicodeKinds {
		if kind == "zero_width" {
			foundZW = true
			break
		}
	}
	if !foundZW {
		t.Fatalf("expected zero_width in Kinds, got %v", partial.Scan.HiddenUnicodeKinds)
	}
}

func TestHiddenUnicodeProvider_CleanArtifactReportsNoHits(t *testing.T) {
	p := newHiddenUnicodeProvider()
	payload := buildTGZ(t, map[string]string{
		"package/index.js":     "const x = 'hello';\n",
		"package/package.json": `{"name":"clean","version":"1.0.0"}`,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "clean", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil {
		t.Fatalf("expected Scan populated even when clean")
	}
	if partial.Scan.HiddenUnicodeHits != 0 {
		t.Fatalf("expected 0 hits, got %d", partial.Scan.HiddenUnicodeHits)
	}
}

func TestHiddenUnicodeProvider_NilArtifactShortCircuits(t *testing.T) {
	p := newHiddenUnicodeProvider()
	partial, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan != nil {
		t.Fatalf("expected empty PartialReport on nil artifact, got %+v", partial.Scan)
	}
}

// TestHiddenUnicodeProvider_I18nBidiSuppressed: a JSON locale catalog
// containing only bidi-override marks (FSI U+2068, PDI U+2069 — the
// directional-isolate pair used to wrap mixed-direction substitutions in
// i18n messages) should produce zero surviving hits and a single
// suppression warning. This is the false-positive class we explicitly
// want to silence.
//
// Note: U+200E LRM and U+200F RLM fall into hiddenunicode.KindZeroWidth
// per the scanner's classification (0x200B–0x200F range), so they are
// always-suspicious and would NOT be suppressed. We use FSI/PDI instead,
// which are unambiguously KindBidiOverride.
func TestHiddenUnicodeProvider_I18nBidiSuppressed(t *testing.T) {
	p := newHiddenUnicodeProvider()
	// U+2068 FSI + U+2069 PDI — bidi_override range.
	lrmJSON := "{\"greeting\": \"hello⁨world⁩\"}\n"
	payload := buildTGZ(t, map[string]string{
		"package/locales/messages.json": lrmJSON,
		"package/package.json":          `{"name":"x","version":"1.0.0"}`,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil {
		t.Fatalf("expected Scan populated")
	}
	if partial.Scan.HiddenUnicodeHits != 0 {
		t.Fatalf("expected 0 surviving hits after i18n suppression, got %d (kinds=%v)", partial.Scan.HiddenUnicodeHits, partial.Scan.HiddenUnicodeKinds)
	}
	if len(partial.Scan.HiddenUnicodeKinds) != 0 {
		t.Fatalf("expected empty Kinds, got %v", partial.Scan.HiddenUnicodeKinds)
	}
	if len(partial.Warnings) != 1 || partial.Warnings[0].Code != WarnHiddenUnicodeI18nSuppressed {
		t.Fatalf("expected one i18n suppression warning, got %+v", partial.Warnings)
	}
}

// TestHiddenUnicodeProvider_I18nZeroWidthNotSuppressed: even inside an i18n
// file, a zero-width injection char is the steganography attack vector
// and MUST surface. This is the security regression guard.
func TestHiddenUnicodeProvider_I18nZeroWidthNotSuppressed(t *testing.T) {
	p := newHiddenUnicodeProvider()
	// U+200B = zero-width space. Stuffed into a JSON locale.
	zwJSON := "{\"greeting\": \"hel​lo\"}\n"
	payload := buildTGZ(t, map[string]string{
		"package/locales/messages.json": zwJSON,
		"package/package.json":          `{"name":"x","version":"1.0.0"}`,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || partial.Scan.HiddenUnicodeHits == 0 {
		t.Fatalf("expected zero_width hit to survive in i18n file, got %+v", partial.Scan)
	}
	foundZW := false
	for _, k := range partial.Scan.HiddenUnicodeKinds {
		if k == "zero_width" {
			foundZW = true
		}
	}
	if !foundZW {
		t.Fatalf("expected zero_width preserved in Kinds, got %v", partial.Scan.HiddenUnicodeKinds)
	}
	for _, w := range partial.Warnings {
		if w.Code == WarnHiddenUnicodeI18nSuppressed {
			t.Fatalf("did not expect suppression warning when zero-width survived, got %+v", partial.Warnings)
		}
	}
}

// TestHiddenUnicodeProvider_NonI18nBidiSurvives: bidi marks in plain source
// code are NOT i18n-context, so suppression must NOT apply (trojan-source
// attack territory).
func TestHiddenUnicodeProvider_NonI18nBidiSurvives(t *testing.T) {
	p := newHiddenUnicodeProvider()
	// U+202E RLO (right-to-left override) — bidi_override — in src/main.js.
	lrmJS := "const x = 'a‮b';\n"
	payload := buildTGZ(t, map[string]string{
		"package/src/main.js":  lrmJS,
		"package/package.json": `{"name":"x","version":"1.0.0"}`,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || partial.Scan.HiddenUnicodeHits != 1 {
		t.Fatalf("expected 1 surviving hit (non-i18n path), got %+v", partial.Scan)
	}
	for _, w := range partial.Warnings {
		if w.Code == WarnHiddenUnicodeI18nSuppressed {
			t.Fatalf("did not expect suppression warning for src/main.js, got %+v", partial.Warnings)
		}
	}
}

// TestHiddenUnicodeProvider_NonI18nZeroWidth: baseline — zero-width in
// regular source still fires.
func TestHiddenUnicodeProvider_NonI18nZeroWidth(t *testing.T) {
	p := newHiddenUnicodeProvider()
	zwJS := "const x = 'a​b';\n"
	payload := buildTGZ(t, map[string]string{
		"package/src/main.js":  zwJS,
		"package/package.json": `{"name":"x","version":"1.0.0"}`,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || partial.Scan.HiddenUnicodeHits != 1 {
		t.Fatalf("expected 1 zero_width hit in src/main.js, got %+v", partial.Scan)
	}
}

// TestHiddenUnicodeProvider_LocalesJSONBidiSuppressed: bidi marks in a
// .json file under /locales/ should be suppressed (covers the locale-
// catalog case for ecosystems whose translation extension is not in the
// scanner allowlist).
func TestHiddenUnicodeProvider_LocalesJSONBidiSuppressed(t *testing.T) {
	p := newHiddenUnicodeProvider()
	// U+202E RLO override inside an Arabic-style locale entry.
	rloJSON := "{\"ar\": \"‮test\"}\n"
	payload := buildTGZ(t, map[string]string{
		"package/locales/ar.json": rloJSON,
		"package/package.json":    `{"name":"x","version":"1.0.0"}`,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || partial.Scan.HiddenUnicodeHits != 0 {
		t.Fatalf("expected 0 surviving hits in locales/ar.json, got %+v", partial.Scan)
	}
	foundWarn := false
	for _, w := range partial.Warnings {
		if w.Code == WarnHiddenUnicodeI18nSuppressed {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Fatalf("expected suppression warning, got %+v", partial.Warnings)
	}
}

// ---------------------------------------------------------------------------
// R2 false-positive regression guards (flywheel detection-lead eval).
//
// The detection-lead eval surfaced typescript@5.4.5 firing hidden-unicode on
// two legitimate zero-width uses:
//   - ko/diagnosticMessages.generated.json: U+200B word-break aids in the
//     Korean message-catalog STRING VALUES.
//   - lib.es2015.core.d.ts: U+200D (ZWJ) in a JSDoc math expression (10‍−‍16).
// Both are benign; neither should fire. The genuine GlassWorm vector — a
// zero-width smuggled BETWEEN ASCII letters of a token, in code or in a
// catalog VALUE — must still fire. These tests lock both halves.
// ---------------------------------------------------------------------------

// TestHiddenUnicodeProvider_CatalogWordBreakSuppressed: a localized/generated
// message catalog whose string VALUE carries a zero-width word-break adjacent
// to a quote / CJK / whitespace (NOT inside an ASCII word) is suppressed.
// Mirrors typescript's ko/diagnosticMessages.generated.json.
func TestHiddenUnicodeProvider_CatalogWordBreakSuppressed(t *testing.T) {
	p := newHiddenUnicodeProvider()
	// U+200B before a quote and before Korean text — the exact benign shape.
	catalog := "{\n  \"MSG_1\": \"출력에서 ​​'__extends'\",\n  \"MSG_2\": \"색상 ​서식\"\n}\n"
	payload := buildTGZ(t, map[string]string{
		"package/lib/ko/diagnosticMessages.generated.json": catalog,
		"package/package.json":                             `{"name":"x","version":"1.0.0"}`,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || partial.Scan.HiddenUnicodeHits != 0 {
		t.Fatalf("expected 0 surviving hits in generated catalog, got %+v", partial.Scan)
	}
	foundWarn := false
	for _, w := range partial.Warnings {
		if w.Code == WarnHiddenUnicodeI18nSuppressed {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Fatalf("expected suppression warning, got %+v", partial.Warnings)
	}
}

// TestHiddenUnicodeProvider_CommentZWJSuppressed: a zero-width-joiner inside a
// block comment (math notation) is suppressed — comments never execute.
// Mirrors typescript's lib.es2015.core.d.ts.
func TestHiddenUnicodeProvider_CommentZWJSuppressed(t *testing.T) {
	p := newHiddenUnicodeProvider()
	// U+200D between '0' and U+2212 (minus) inside a /* */ comment.
	src := "/**\n * EPSILON is 10‍−‍16 approximately.\n */\nexport const x = 1;\n"
	payload := buildTGZ(t, map[string]string{
		"package/lib/lib.es2015.core.d.ts": src,
		"package/package.json":             `{"name":"x","version":"1.0.0"}`,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || partial.Scan.HiddenUnicodeHits != 0 {
		t.Fatalf("expected 0 surviving hits for comment ZWJ, got %+v", partial.Scan)
	}
}

// TestHiddenUnicodeProvider_CatalogAsciiWordStegoSurvives: the SECURITY guard.
// A zero-width smuggled BETWEEN ASCII letters of a token, even inside a
// generated-catalog string value, is the steganography vector and MUST fire.
// This proves the FP fix did not blanket-whitelist catalog files.
func TestHiddenUnicodeProvider_CatalogAsciiWordStegoSurvives(t *testing.T) {
	p := newHiddenUnicodeProvider()
	// U+200B inside the ASCII word "extends" — `ext<ZW>ends`. Same catalog
	// file shape as the benign test, but the position is an attack.
	catalog := "{\n  \"MSG_1\": \"ext​ends payload\"\n}\n"
	payload := buildTGZ(t, map[string]string{
		"package/lib/ko/diagnosticMessages.generated.json": catalog,
		"package/package.json":                             `{"name":"x","version":"1.0.0"}`,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || partial.Scan.HiddenUnicodeHits != 1 {
		t.Fatalf("expected 1 surviving zero_width hit (stego in ASCII word), got %+v", partial.Scan)
	}
}

// TestHiddenUnicodeProvider_CommentAsciiWordStegoSurvives: a zero-width
// between ASCII letters is an attack even inside a comment (a payload can be
// decoded out of a comment by a loader). MUST fire.
func TestHiddenUnicodeProvider_CommentAsciiWordStegoSurvives(t *testing.T) {
	p := newHiddenUnicodeProvider()
	// U+200B inside "secret" within a // comment.
	src := "// token is sec​ret here\nexport const x = 1;\n"
	payload := buildTGZ(t, map[string]string{
		"package/src/main.ts":  src,
		"package/package.json": `{"name":"x","version":"1.0.0"}`,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || partial.Scan.HiddenUnicodeHits != 1 {
		t.Fatalf("expected 1 surviving zero_width hit (stego in comment), got %+v", partial.Scan)
	}
}

// TestHiddenUnicodeProvider_CommentZeroWidthRunSurvives: the bypass guard. A
// RUN of adjacent zero-widths (ZWSP/ZWNJ/ZWJ) is the byte-encoding shape of a
// steganographic payload — and the run's neighbours are themselves zero-widths
// (non-alphanumeric), so the ASCII-word guard does NOT catch it. Inside a
// comment it would have been blanket-suppressed by Rule 3; the adjacency gate
// MUST keep it. This is the GlassWorm-class case the per-hit context gate
// missed.
func TestHiddenUnicodeProvider_CommentZeroWidthRunSurvives(t *testing.T) {
	p := newHiddenUnicodeProvider()
	// Four adjacent zero-widths encoding a payload, dressed as a comment.
	src := "// note ​‌‍​ end\nexport const x = 1;\n"
	payload := buildTGZ(t, map[string]string{
		"package/src/main.ts":  src,
		"package/package.json": `{"name":"x","version":"1.0.0"}`,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || partial.Scan.HiddenUnicodeHits == 0 {
		t.Fatalf("zero-width RUN in a comment must NOT be suppressed (payload-encoding shape), got %+v", partial.Scan)
	}
}

// TestHiddenUnicodeProvider_CatalogZeroWidthRunSurvives: same run bypass inside
// a generated-catalog string VALUE (attacker controls the file path + content).
// Rule 2 would have suppressed it; the adjacency gate MUST keep the run.
func TestHiddenUnicodeProvider_CatalogZeroWidthRunSurvives(t *testing.T) {
	p := newHiddenUnicodeProvider()
	catalog := "{\n  \"MSG_1\": \"hi ​‌‍​ there\"\n}\n"
	payload := buildTGZ(t, map[string]string{
		"package/lib/ko/diagnosticMessages.generated.json": catalog,
		"package/package.json":                             `{"name":"x","version":"1.0.0"}`,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || partial.Scan.HiddenUnicodeHits == 0 {
		t.Fatalf("zero-width RUN in a catalog value must NOT be suppressed, got %+v", partial.Scan)
	}
}

// TestHiddenUnicodeProvider_DensityBackstopSurvives: a payload encoded as many
// NON-adjacent zero-widths (each flanked by a space, so it dodges both the
// ASCII-word guard and the adjacency gate) is re-armed by the per-file density
// backstop once the count clears hiddenUnicodeZeroWidthDensityCeiling.
func TestHiddenUnicodeProvider_DensityBackstopSurvives(t *testing.T) {
	p := newHiddenUnicodeProvider()
	// 14 zero-widths (> ceiling 12), each isolated inside a comment.
	src := "// " + strings.Repeat("​ ", 14) + "\nexport const x = 1;\n"
	payload := buildTGZ(t, map[string]string{
		"package/src/main.ts":  src,
		"package/package.json": `{"name":"x","version":"1.0.0"}`,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || partial.Scan.HiddenUnicodeHits == 0 {
		t.Fatalf("high-density zero-widths must NOT be suppressed (density backstop), got %+v", partial.Scan)
	}
}

// TestHiddenUnicodeProvider_CatalogKeyNotSuppressed: a zero-width in a catalog
// KEY (not a value) is not a word-break aid — keys are identifiers. It must
// survive even though the file is a catalog. Guards the key/value split.
func TestHiddenUnicodeProvider_CatalogKeyNotSuppressed(t *testing.T) {
	p := newHiddenUnicodeProvider()
	// U+200B adjacent to a quote inside the KEY position (before ':').
	catalog := "{\n  \"MS​G\": \"hello world\"\n}\n"
	payload := buildTGZ(t, map[string]string{
		"package/lib/ko/diagnosticMessages.generated.json": catalog,
		"package/package.json":                             `{"name":"x","version":"1.0.0"}`,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	// "MS<ZW>G" — ZW is between ASCII 'S' and 'G', so the ascii-word guard
	// alone makes it survive (defense in depth: even if it weren't, it's a
	// key not a value).
	if partial.Scan == nil || partial.Scan.HiddenUnicodeHits != 1 {
		t.Fatalf("expected zero_width in catalog KEY to survive, got %+v", partial.Scan)
	}
}

// TestHiddenUnicodeProvider_NonCatalogJSONValueNotSuppressed: a zero-width
// word-break in a plain (non-locale) JSON value is NOT suppressed — the
// catalog gate requires a locale/generated-catalog file shape, so an
// arbitrary config.json can't be used as a suppression bypass.
func TestHiddenUnicodeProvider_NonCatalogJSONValueNotSuppressed(t *testing.T) {
	p := newHiddenUnicodeProvider()
	// U+200B adjacent to a quote in a plain config value (not a catalog path).
	cfg := "{\n  \"url\": \"​http://x\"\n}\n"
	payload := buildTGZ(t, map[string]string{
		"package/config.json":  cfg,
		"package/package.json": `{"name":"x","version":"1.0.0"}`,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || partial.Scan.HiddenUnicodeHits != 1 {
		t.Fatalf("expected zero_width in non-catalog JSON value to survive, got %+v", partial.Scan)
	}
}

func TestHiddenUnicodeProvider_UnsupportedEcosystem(t *testing.T) {
	p := newHiddenUnicodeProvider()
	if p.Supports("docker") {
		t.Fatalf("docker should not be supported (binary-only)")
	}
	if p.Supports("apt") {
		t.Fatalf("apt should not be supported (binary-only)")
	}
	if !p.Supports("pip") {
		t.Fatalf("pip should be supported (text files)")
	}
	if !p.Supports("huggingface") {
		t.Fatalf("huggingface should be supported (text model cards)")
	}
}
