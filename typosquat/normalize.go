package typosquat

import (
	"strings"
	"unicode"
)

// Normalizer defines how a package name is canonicalized for comparison.
type Normalizer func(name string) string

// NormalizeNPM lowercases the full package name. Scope is part of npm
// identity, not a strippable prefix: @scope/foo and unscoped foo are
// different packages on the registry, owned by different parties.
// Stripping @scope/ collapsed @attacker/react onto "react", which then
// exact-matched the popular index and got CLEARED as "not a
// typosquat" — turning a scope-shadow attack into a silent pass.
// Combosquat still catches @attacker/react vs popular react via the
// substring path. Symmetric to the Maven/Composer/HuggingFace fix.
func NormalizeNPM(name string) string {
	return strings.ToLower(name)
}

// NormalizePyPI applies PEP 503 normalization: lowercase and replace
// any run of [-_.] with a single hyphen.
func NormalizePyPI(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	b.Grow(len(name))
	prevSep := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('-')
				prevSep = true
			}
			continue
		}
		prevSep = false
		b.WriteRune(r)
	}
	return b.String()
}

// NormalizeMaven lowercases the full Maven/Gradle coordinate. Like
// NormalizeGo, the ecosystem's identity is the full groupId:artifactId
// path — groupId is part of the coordinate, not a routing prefix to
// strip. Stripping it collapsed every "*:library" artifact to
// "library" in the popular index, which made the combosquat substring
// check (Step 3 in detector.Check) fire on completely unrelated
// coordinates whose artifactIds happened to share a substring — e.g.
// "com.android.databinding:baseLibrary" was flagged as a typosquat of
// "org.opendaylight.ovsdb:library" because "baselibrary" contains
// "library". Different groupId = different package, even when
// artifactIds rhyme. Keep the whole string.
func NormalizeMaven(name string) string {
	return strings.ToLower(name)
}

// NormalizeCargo lowercases and normalizes hyphens/underscores.
func NormalizeCargo(name string) string {
	name = strings.ToLower(name)
	return strings.ReplaceAll(name, "_", "-")
}

// NormalizeGo lowercases the full module path. Unlike most ecosystems, Go
// module identity is the entire import path (e.g. "github.com/spf13/cobra"),
// not the last segment — two modules with the same final segment but
// different owners are unrelated, and dropping the prefix would collapse
// "github.com/attacker/cobra" into "github.com/spf13/cobra" for typosquat
// comparison purposes, producing false "exact popular match" hits.
func NormalizeGo(name string) string {
	return strings.ToLower(name)
}

// NormalizeCocoapods lowercases the pod name. Cocoapods spec names are
// case-preserving in the repo but case-insensitive for `pod install`
// resolution, so the detector treats "AFNetworking" and "afnetworking"
// as the same coordinate.
func NormalizeCocoapods(name string) string {
	return strings.ToLower(name)
}

// NormalizeDocker lowercases the full image reference. registry/org/name
// is the canonical identity — myorg/alpine and library/alpine (Docker
// Hub official) are different images. Stripping arbitrary org prefixes
// would collapse unrelated org images into a shared key and make every
// "alpine-anything" combosquat-flag against popular "alpine".
//
// Exception: the literal leading "library/" prefix on Docker Hub is the
// pseudo-namespace for official images — Hub's CLI and registry resolve
// "library/alpine" and "alpine" to the same image. Users overwhelmingly
// type the bare form, and the popular index is seeded with bare names,
// so we collapse "library/alpine" → "alpine" one-way only. The reverse
// is intentionally NOT done (bare "alpine" stays "alpine") — keeping
// the collapse asymmetric matches the asymmetry of Hub itself: every
// official image has a "library/" alias, but no other org does.
//
// Strip is leading-only: a "library/" segment that appears mid-path
// (e.g. "gcr.io/library/alpine") is part of a different registry's
// own namespace and is NOT touched.
func NormalizeDocker(name string) string {
	name = strings.ToLower(name)
	if strings.HasPrefix(name, "library/") {
		name = name[len("library/"):]
	}
	return name
}

// NormalizeComposer lowercases the full vendor/package coordinate.
// Packagist requires a vendor namespace — vendor/package is the only
// canonical form. Two packages with the same artifact name under
// different vendors are entirely different packages. Stripping the
// vendor collapsed all "*/laravel" onto "laravel" and triggered
// combosquat false positives. Symmetric to the Maven fix.
func NormalizeComposer(name string) string {
	return strings.ToLower(name)
}

// NormalizeRubyGems lowercases and collapses underscore/hyphen. RubyGems
// names commonly use `_` and `-` interchangeably in the wild — `my_gem`
// and `my-gem` are routinely treated as the same package by humans, and
// gem authors often publish or recommend both spellings. For typosquat
// detection we want them to share a key so that `my-gem` registered by
// an attacker collides with popular `my_gem` (and vice versa) instead
// of slipping through as a non-match. Mirrors NormalizeCargo, which has
// the same convention on crates.io.
func NormalizeRubyGems(name string) string {
	name = strings.ToLower(name)
	return strings.ReplaceAll(name, "_", "-")
}

// NormalizeNuGet lowercases and strips delimiters. Symmetric with the
// detector pipeline: detector.LoadEcosystem applies NormalizerForFormat
// to every popular package before BK-tree insertion, so popular names
// in the index pass through this same delimiter strip — query and index
// agree on the canonical form.
func NormalizeNuGet(name string) string {
	return stripDelimiters(strings.ToLower(name))
}

// NormalizeHuggingFace lowercases the full org/model coordinate. Hub
// requires an org or user namespace — org/model is the canonical form.
// Different orgs publishing the same model name (e.g. fine-tunes that
// share a base name) are different artifacts. Stripping the org
// collapsed them and produced combosquat false positives the same way
// Maven did. Symmetric fix.
func NormalizeHuggingFace(name string) string {
	return strings.ToLower(name)
}

// NormalizeGeneric strips delimiters and lowercases.
func NormalizeGeneric(name string) string {
	return stripDelimiters(strings.ToLower(name))
}

// stripDelimiters removes hyphens, underscores, and dots.
func stripDelimiters(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '-' || r == '_' || r == '.' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ReorderTokens splits name on `-`, `_`, `.`, sorts the resulting tokens
// lexicographically, and returns a hyphen-joined canonical form plus the
// token count. A token count of 1 means the name had no delimiter and
// reordering is meaningless — callers should treat a pure-reorder match as
// invalid when the count is 1 (prevents `lodash` from colliding with every
// single-token name that happens to sort to the same letters).
//
// Reorder normalization intentionally sits below ecosystem-specific
// Normalizer (see NormalizerForFormat): callers should first normalize via
// the per-ecosystem function — which handles @scope stripping, vendor/
// prefix removal, case folding — and then feed the result into
// ReorderTokens. That way the token set matches what operators see when
// they type the package name without @scope or groupId clutter.
func ReorderTokens(name string) (canonical string, tokenCount int) {
	if name == "" {
		return "", 0
	}
	// Split on any of '-', '_', '.'.
	tokens := splitOnDelimiters(name)
	if len(tokens) == 0 {
		return "", 0
	}
	// Sort in-place; tokens are already lowercased if upstream normalizer
	// ran, but we defensively lower here for direct callers.
	sorted := make([]string, len(tokens))
	for i, t := range tokens {
		sorted[i] = strings.ToLower(t)
	}
	sortStrings(sorted)
	return strings.Join(sorted, "-"), len(sorted)
}

// splitOnDelimiters breaks s at every '-', '_', or '.' and drops empty
// tokens (so "my--name" → ["my","name"], not ["my","","name"]).
func splitOnDelimiters(s string) []string {
	out := make([]string, 0, 4)
	start := 0
	for i, r := range s {
		if r == '-' || r == '_' || r == '.' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// sortStrings is a small insertion sort to avoid dragging in the sort
// package for the tiny slices ReorderTokens produces (typical len ≤ 4).
func sortStrings(xs []string) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j-1] > xs[j]; j-- {
			xs[j-1], xs[j] = xs[j], xs[j-1]
		}
	}
}

// NormalizerForFormat returns the appropriate normalizer for a package format.
func NormalizerForFormat(format string) Normalizer {
	switch strings.ToLower(format) {
	case "npm", "yarn", "bun":
		return NormalizeNPM
	case "pip", "pypi":
		return NormalizePyPI
	case "maven", "gradle":
		return NormalizeMaven
	case "cargo":
		return NormalizeCargo
	case "go", "gomod":
		return NormalizeGo
	case "docker":
		return NormalizeDocker
	case "composer":
		return NormalizeComposer
	case "rubygems":
		return NormalizeRubyGems
	case "nuget":
		return NormalizeNuGet
	case "huggingface":
		return NormalizeHuggingFace
	case "cocoapods":
		return NormalizeCocoapods
	case "pub":
		// pub.dev names are flat snake_case with no scopes; generic
		// lowercase normalization is the correct identity.
		return NormalizeGeneric
	// github_actions ecosystem
	case "github_actions":
		return NormalizeGitHubActions
	// github_actions ecosystem
	default:
		return NormalizeGeneric
	}
}

// homoglyphMap contains visual confusable replacements.
//
// Two classes of confusables are present:
//
//  1. ASCII⇄ASCII bidirectional pairs (l↔1, o↔0, etc.). These cover the
//     classic typo/glyph-confusion attacks where an attacker registers
//     "rust1ang" against popular "rustlang", or "g00gle" against
//     "google". Both directions are useful because the popular index
//     and the query are both ASCII, so either form might be the
//     attacker's choice and either form might be the legitimate name.
//
//  2. Non-ASCII → ASCII unidirectional Cyrillic and Greek mappings.
//     These exist to catch the IDN/Unicode look-alike attack where an
//     attacker registers a name with a Cyrillic 'а' (U+0430) or Greek
//     'α' (U+03B1) that renders identical to ASCII 'a' but is a
//     different codepoint, e.g. "reаct" with Cyrillic а against
//     popular "react". The detection direction matters: a query
//     containing Cyrillic/Greek expands to ASCII variants and matches
//     the popular index (which is ASCII). The reverse direction —
//     expanding ASCII queries into 32 Cyrillic/Greek variants per
//     letter — would burn through the maxHomoglyphVariants=50 cap on
//     pointless permutations of the legitimate name (the popular
//     index never contains Cyrillic forms, so no popular name could
//     be hit by ASCII→Cyrillic expansion). One-way mapping keeps the
//     variant budget focused on real attack patterns.
//
// Encoding-vs-display note: this map operates on Unicode codepoints,
// not on visually rendered glyphs. Two runes that render identically
// in a given font are still distinct keys here; we add them
// individually as their attack relevance is established.
var homoglyphMap = map[rune][]rune{
	'l': {'1', 'i'},
	'1': {'l', 'i'},
	'i': {'l', '1'},
	'o': {'0'},
	'0': {'o'},
	'q': {'g'},
	'g': {'q'},
	's': {'5'},
	'5': {'s'},
	'z': {'2'},
	'2': {'z'},
	'b': {'6'},
	'6': {'b'},
	// Cyrillic look-alikes → ASCII (unidirectional).
	'а': {'a'}, // U+0430 CYRILLIC SMALL LETTER A
	'е': {'e'}, // U+0435 CYRILLIC SMALL LETTER IE
	'о': {'o'}, // U+043E CYRILLIC SMALL LETTER O
	'р': {'p'}, // U+0440 CYRILLIC SMALL LETTER ER
	'с': {'c'}, // U+0441 CYRILLIC SMALL LETTER ES
	'у': {'y'}, // U+0443 CYRILLIC SMALL LETTER U
	'х': {'x'}, // U+0445 CYRILLIC SMALL LETTER HA
	// Greek look-alikes → ASCII (unidirectional).
	'α': {'a'}, // U+03B1 GREEK SMALL LETTER ALPHA
	'ε': {'e'}, // U+03B5 GREEK SMALL LETTER EPSILON
	'ο': {'o'}, // U+03BF GREEK SMALL LETTER OMICRON
	'ρ': {'p'}, // U+03C1 GREEK SMALL LETTER RHO
	'υ': {'y'}, // U+03C5 GREEK SMALL LETTER UPSILON
}

// multiHomoglyphMap contains multi-character confusable patterns.
var multiHomoglyphMap = map[string]string{
	"rn": "m",
	"m":  "rn",
	"cl": "d",
	"d":  "cl",
	"vv": "w",
	"w":  "vv",
}

// maxHomoglyphVariants caps the number of variants generated to prevent DoS.
const maxHomoglyphVariants = 50

// ExpandHomoglyphs generates variations of a name with single-character
// homoglyph substitutions. Returns only unique results, capped at
// maxHomoglyphVariants to prevent combinatorial explosion.
func ExpandHomoglyphs(name string) []string {
	runes := []rune(name)
	var results []string
	seen := map[string]bool{name: true}

	// Single-character substitutions.
	for i, r := range runes {
		if len(results) >= maxHomoglyphVariants {
			break
		}
		lr := unicode.ToLower(r)
		replacements, ok := homoglyphMap[lr]
		if !ok {
			continue
		}
		for _, rep := range replacements {
			if len(results) >= maxHomoglyphVariants {
				break
			}
			variant := make([]rune, len(runes))
			copy(variant, runes)
			variant[i] = rep
			s := string(variant)
			if !seen[s] {
				seen[s] = true
				results = append(results, s)
			}
		}
	}

	// Multi-character substitutions.
	for pattern, replacement := range multiHomoglyphMap {
		if len(results) >= maxHomoglyphVariants {
			break
		}
		idx := strings.Index(name, pattern)
		for idx >= 0 {
			if len(results) >= maxHomoglyphVariants {
				break
			}
			variant := name[:idx] + replacement + name[idx+len(pattern):]
			if !seen[variant] {
				seen[variant] = true
				results = append(results, variant)
			}
			next := strings.Index(name[idx+1:], pattern)
			if next < 0 {
				break
			}
			idx = idx + 1 + next
		}
	}

	return results
}
