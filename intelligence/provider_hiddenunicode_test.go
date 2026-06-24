package intelligence

import (
	"context"
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
