package typosquat

import (
	"strings"
	"unicode"
)

// confusables maps a visually-suspicious rune to its canonical ASCII
// equivalent. It is a curated subset of the Unicode TR39 confusables
// data (https://www.unicode.org/Public/security/latest/confusables.txt)
// — the full table has ~6500 entries; this map keeps only categories
// that are realistic supply-chain attack vectors against ASCII package
// names: Cyrillic ↔ Latin, Greek ↔ Latin, fullwidth Latin, common
// digit ambiguities, and a handful of math/turkish lookalikes.
//
// All values are lowercase ASCII. Mappings are unidirectional
// (suspicious → canonical) so Normalize is idempotent: applying it
// twice produces the same result as applying it once. The handful of
// ASCII digit ambiguities (l/1, o/0, s/5) pick a single canonical
// direction (digit → letter) so a normalized form is unambiguous.
//
// This complements the bidirectional ExpandHomoglyphs variant generator
// in normalize.go: that path expands a query into many candidate forms
// and probes each against the popular index, while the Normalize path
// here is the inverse — it collapses the query AND every popular name
// onto a single canonical key for O(1) lookup. Both paths fire under
// Method "homoglyph" but the Normalize path catches Unicode collisions
// that ExpandHomoglyphs's variant cap (50) drops on long names.
var confusables = map[rune]rune{
	// ────────────────────────────────────────────────────────────
	// Cyrillic → Latin (lowercase). U+04xx block.
	// These render visually identical to ASCII letters in most
	// fonts and are the most common Unicode typosquat vector
	// (CVE-style attacks: еxpress, gооgle-auth-library, etc.).
	'а': 'a', // U+0430
	'в': 'b', // U+0432 (resembles Latin B/v)
	'с': 'c', // U+0441
	'е': 'e', // U+0435
	'һ': 'h', // U+04BB (Cyrillic shha — Latin h lookalike)
	'і': 'i', // U+0456 (Ukrainian/Belarusian i)
	'ј': 'j', // U+0458
	'к': 'k', // U+043A
	'м': 'm', // U+043C
	'н': 'h', // U+043D — Cyrillic en visually maps to Latin H
	'о': 'o', // U+043E
	'р': 'p', // U+0440
	'ѕ': 's', // U+0455
	'т': 't', // U+0442
	'у': 'y', // U+0443 — Cyrillic u looks like Latin y
	'х': 'x', // U+0445
	'ѵ': 'v', // U+0475
	'ԁ': 'd', // U+0501
	'ԍ': 'g', // U+050D
	'ԝ': 'w', // U+051D
	'ӏ': 'l', // U+04CF Cyrillic palochka (lowercase) → l
	'ʏ': 'y', // U+028F (latin small capital y)

	// Cyrillic uppercase forms — fold to lowercase ASCII so the
	// mapping is consistent with the lowercase Normalize pass.
	'А': 'a', // U+0410
	'В': 'b', // U+0412
	'С': 'c', // U+0421
	'Е': 'e', // U+0415
	'Н': 'h', // U+041D
	'К': 'k', // U+041A
	'М': 'm', // U+041C
	'О': 'o', // U+041E
	'Р': 'p', // U+0420
	'Т': 'T', // see fold below; placeholder, reset next line
	'Х': 'x', // U+0425
	'У': 'y', // U+0423
	'І': 'i', // U+0406

	// ────────────────────────────────────────────────────────────
	// Greek → Latin. U+03xx block.
	'α': 'a', // U+03B1 alpha
	'β': 'b', // U+03B2 beta
	'γ': 'y', // U+03B3 gamma
	'ε': 'e', // U+03B5 epsilon
	'ζ': 'z', // U+03B6 zeta
	'η': 'n', // U+03B7 eta
	'ι': 'i', // U+03B9 iota
	'κ': 'k', // U+03BA kappa
	'μ': 'u', // U+03BC mu
	'ν': 'v', // U+03BD nu (visually 'v')
	'ο': 'o', // U+03BF omicron
	'π': 'n', // U+03C0 — borderline; keep as 'n' style (rare)
	'ρ': 'p', // U+03C1 rho
	'τ': 't', // U+03C4 tau
	'υ': 'y', // U+03C5 upsilon
	'χ': 'x', // U+03C7 chi
	'Α': 'a', 'Β': 'b', 'Ε': 'e', 'Ζ': 'z', 'Η': 'h',
	'Ι': 'i', 'Κ': 'k', 'Μ': 'm', 'Ν': 'n', 'Ο': 'o',
	'Ρ': 'p', 'Τ': 't', 'Υ': 'y', 'Χ': 'x',

	// ────────────────────────────────────────────────────────────
	// Digit ambiguity — pick a single canonical direction
	// (digit → letter) so Normalize is deterministic. An attacker
	// who registers `expr3ss` (digit-3 instead of 'e') normalizes
	// to `express` and collides with the popular name. Same for
	// `g00gle` (zero) → `google`, `1odash` (one) → `lodash`.
	'0': 'o',
	'1': 'l',
	'3': 'e',
	'5': 's',
	// Note: '4' → 'a' is too noisy (real packages use 4 as a
	// version marker, e.g. `log4j`, `ipv4-utils`); intentionally
	// omitted. Same for '8' → 'b'.

	// ────────────────────────────────────────────────────────────
	// Turkish / Latin extended dotless letters and palochka.
	'ı': 'i', // U+0131 dotless i
	'Ӏ': 'l', // U+04C0 (uppercase palochka) → l

	// ────────────────────────────────────────────────────────────
	// Fullwidth Latin letters U+FF21–U+FF5A → ASCII a-z.
	// Common in copy-pasted CJK contexts where attackers embed
	// fullwidth glyphs that render close to ASCII. Built
	// programmatically in init() rather than listed by hand.
}

func init() {
	// Reset the placeholder we set above for visual consistency:
	// Cyrillic Т (U+0422) folds to Latin lowercase 't'.
	confusables['Т'] = 't'

	// Fullwidth Latin: U+FF21..U+FF3A (A–Z) → 'a'..'z',
	//                  U+FF41..U+FF5A (a–z) → 'a'..'z'.
	for r := rune(0xFF21); r <= 0xFF3A; r++ {
		confusables[r] = rune('a' + (r - 0xFF21))
	}
	for r := rune(0xFF41); r <= 0xFF5A; r++ {
		confusables[r] = rune('a' + (r - 0xFF41))
	}
	// Fullwidth digits U+FF10..U+FF19 → ASCII; route through the
	// digit-ambiguity table so `１` (fullwidth 1) → 'l' just like
	// ASCII '1' → 'l'.
	for r := rune(0xFF10); r <= 0xFF19; r++ {
		ascii := rune('0' + (r - 0xFF10))
		if mapped, ok := confusables[ascii]; ok {
			confusables[r] = mapped
		} else {
			confusables[r] = ascii
		}
	}
}

// Normalize folds visually-confusable runes to their canonical ASCII
// equivalent and lowercases the result. The returned form is what the
// homoglyph collision check compares against. It is deliberately a
// pure rune-by-rune fold (no PEP 503-style delimiter collapse) so it
// composes cleanly with the per-ecosystem Normalizer in normalize.go:
// callers should run their ecosystem normalizer first, then feed the
// result through Normalize.
//
// Idempotence: every value in the confusables map is plain ASCII that
// is NOT itself a key, so Normalize(Normalize(x)) == Normalize(x).
func Normalize(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if mapped, ok := confusables[r]; ok {
			b.WriteRune(mapped)
			continue
		}
		// Lowercase any remaining ASCII letters; non-confusable
		// non-ASCII letters pass through unchanged so we never
		// silently collapse runes we haven't vetted.
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// IsHomoglyphCollision reports whether `input` and `candidate` share a
// normalized form while differing in their raw bytes. A true return
// means the two names are visually confusable but not byte-identical
// — i.e. the input is a homoglyph attack against the candidate (or
// vice versa).
func IsHomoglyphCollision(input, candidate string) bool {
	if input == candidate {
		return false
	}
	return Normalize(input) == Normalize(candidate)
}
