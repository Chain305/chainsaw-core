package codesmell

import (
	"bytes"
	"strings"
)

// IsLikelyTestOrVendor reports whether path looks like test code, vendored
// dependencies, or build/dist output that should typically be excluded from
// noise-prone code-smell scanners (eval / network / shell / fs / env /
// entropy / urls).
//
// The classification is path-based and case-insensitive. It is INTENTIONALLY
// conservative: when in doubt the function returns false (include the file).
// Better a false positive than a missed payload. Two scanners must NOT use
// this filter: MinifiedCode (minified bundles in dist/ are a legitimate
// target) and NativeBinaryPresent (a native binary in vendor/ is exactly
// what we want to see).
//
// The check matches path SEGMENTS (`/segment/`) rather than substrings so
// that legitimate paths like `src/test_utils/foo.js` are not excluded by
// accident — only files actually living under a test-shaped directory are
// filtered.
func IsLikelyTestOrVendor(p string) bool {
	if p == "" {
		return false
	}
	// Normalise: lower-case, slash-separated, leading+trailing slash so the
	// segment checks match at boundaries without special-casing the start
	// or end of the path.
	norm := "/" + strings.ToLower(strings.ReplaceAll(p, "\\", "/")) + "/"

	// Test/spec dirs.
	for _, seg := range testOrVendorSegments {
		if strings.Contains(norm, seg) {
			return true
		}
	}

	// Test file suffix patterns. These are checked against the basename
	// only, but operating on the normalised string is fine because the
	// suffixes contain a dot which cannot appear in a directory boundary.
	low := strings.ToLower(p)
	for _, suf := range testFileSuffixes {
		if strings.HasSuffix(low, suf) {
			return true
		}
	}
	return false
}

// exampleOrDocSegments — path segments that mark "intentional packaging
// artifacts" rather than vendored or built code. Used by the shrinkwrap
// provider's path-based suppression. STRICT SUBSET of testOrVendorSegments:
// callers that need vendored deps (node_modules/, vendor/) and build
// output (dist/, build/) to ALSO match should call IsLikelyTestOrVendor.
//
// Lockfiles inside vendored deps (node_modules/foo/package-lock.json)
// are deliberately NOT covered here — bundled deps with their own pinned
// graphs are exactly the review-bypass pattern the shrinkwrap signal
// targets.
var exampleOrDocSegments = []string{
	"/test/", "/tests/", "/__tests__/", "/spec/", "/specs/",
	"/testdata/", "/fixtures/",
	"/examples/", "/example/", "/docs/", "/doc/",
	"/templates/", "/template/", "/samples/",
}

// IsLikelyExampleOrDoc reports whether path lives under a directory
// that conventionally holds intentional packaging artifacts (tests,
// fixtures, examples, documentation, templates, samples). UNLIKE
// IsLikelyTestOrVendor, this does NOT match vendored deps or build
// output — callers that want a lockfile inside node_modules/ to count
// as a real signal should use this helper instead.
func IsLikelyExampleOrDoc(p string) bool {
	if p == "" {
		return false
	}
	norm := "/" + strings.ToLower(strings.ReplaceAll(p, "\\", "/")) + "/"
	for _, seg := range exampleOrDocSegments {
		if strings.Contains(norm, seg) {
			return true
		}
	}
	return false
}

// testOrVendorSegments are matched as `/segment/` substrings on a
// lower-cased, slash-normalised path. Order is unimportant.
var testOrVendorSegments = []string{
	// Test / spec dirs.
	"/test/", "/tests/", "/__tests__/", "/spec/", "/specs/",
	"/testdata/", "/fixtures/",
	// Vendored deps.
	"/node_modules/", "/vendor/", "/site-packages/",
	"/.gradle/", "/.cargo/", "/.m2/", "/__pycache__/",
	// Build / dist.
	"/dist/", "/build/", "/.next/", "/.nuxt/",
	"/target/release/", "/target/debug/", "/out/",
	// Examples / docs / templates / samples.
	"/examples/", "/example/", "/docs/", "/doc/",
	"/templates/", "/template/", "/samples/",
}

// testFileSuffixes match per-file naming conventions for unit tests across
// Go and the JS/TS ecosystem. Lower-cased.
var testFileSuffixes = []string{
	"_test.go",
	".test.js", ".test.jsx", ".test.ts", ".test.tsx",
	".spec.js", ".spec.jsx", ".spec.ts", ".spec.tsx",
}

// i18nPathSegments are matched as `/segment/` substrings on a lower-cased,
// slash-normalised path. Order is unimportant. These are the conventional
// directories for translation catalogs, locale resources, and message
// bundles across ecosystems.
var i18nPathSegments = []string{
	"/locales/", "/locale/", "/i18n/", "/lang/",
	"/translations/", "/messages/",
}

// i18nFileSuffixes match per-file naming conventions for translation
// catalogs (gettext .po/.pot/.mo, Mozilla Fluent .ftl) regardless of where
// they live. Lower-cased.
var i18nFileSuffixes = []string{
	".po", ".pot", ".mo", ".ftl",
	"/messages.json", "/strings.xml", "/localizable.strings",
}

// IsLikelyI18nFile reports whether path looks like a translation catalog,
// locale resource, or message bundle — files that legitimately contain
// bidi-override marks (LRM/RLM/LRE/RLE/PDF/LRI/RLI/FSI/PDI) for mixed-
// direction text. The hiddenunicode provider uses this to suppress
// false-positive bidi hits in i18n content while keeping zero-width and
// tag-character hits (which are NEVER legitimate, even in i18n files).
//
// The classification is path-based and case-insensitive. Conservative by
// design: when in doubt return false so callers fall back to flagging.
//
// Match rules:
//   - any path segment under known i18n dirs (/locales/, /i18n/, etc.)
//   - any path with a translation-catalog extension (.po, .pot, .mo, .ftl)
//   - specific filename conventions (messages.json, strings.xml,
//     Localizable.strings)
//   - .json / .yaml / .yml living under an i18n segment
func IsLikelyI18nFile(p string) bool {
	if p == "" {
		return false
	}
	norm := "/" + strings.ToLower(strings.ReplaceAll(p, "\\", "/")) + "/"

	for _, seg := range i18nPathSegments {
		if strings.Contains(norm, seg) {
			return true
		}
	}

	low := strings.ToLower(p)
	for _, suf := range i18nFileSuffixes {
		if strings.HasSuffix(low, suf) {
			return true
		}
	}
	return false
}

// generatedHeadMarkers are byte sequences that, when present in the first
// few hundred bytes of a file, identify it as machine-generated. The markers
// are case-sensitive — every common convention preserves the case shown.
var generatedHeadMarkers = [][]byte{
	[]byte("// @generated"),
	[]byte("/* AUTO-GENERATED"),
	[]byte("# Generated by"),
	[]byte("<!-- Generated by"),
}

// generatedHeadProbe is the maximum number of bytes from the start of the
// file scanned for a generated-marker. 500 covers shebangs, license
// boilerplate, and a couple of comment lines — enough to find the marker
// when present without paying a scan over the full file.
const generatedHeadProbe = 500

// LooksGenerated reports whether body opens with a marker indicating the
// file was emitted by a code generator. Only the first generatedHeadProbe
// bytes are inspected.
func LooksGenerated(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	head := body
	if len(head) > generatedHeadProbe {
		head = head[:generatedHeadProbe]
	}
	for _, m := range generatedHeadMarkers {
		if bytes.Contains(head, m) {
			return true
		}
	}
	return false
}

// FilterTestVendorGenerated returns a new map with paths matching
// IsLikelyTestOrVendor or LooksGenerated removed. The returned map shares
// the same []byte slices as the input; callers must not mutate them.
//
// Apply this to the 7 noisy signal scanners (eval, network, shell, fs, env,
// entropy, urls) at the call site. Do NOT apply it to MinifiedCode or
// NativeBinary — both signals legitimately fire on bundled or vendored
// artefacts.
func FilterTestVendorGenerated(in map[string][]byte) map[string][]byte {
	if len(in) == 0 {
		return in
	}
	out := make(map[string][]byte, len(in))
	for p, b := range in {
		if IsLikelyTestOrVendor(p) {
			continue
		}
		if LooksGenerated(b) {
			continue
		}
		out[p] = b
	}
	return out
}
