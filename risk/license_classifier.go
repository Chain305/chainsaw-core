package risk

// license_classifier.go is a pure function that maps an SPDX expression
// to the five Socket-gap "License*" taxonomy tags. Single source of
// truth, shared across every ecosystem that surfaces a license field.
//
// The mapping is ordered: a single expression can emit multiple tags
// (e.g. "GPL-2.0-only OR MIT" emits LicenseCopyleft AND
// LicenseAmbiguousClassifier — the copyleft half is real AND the
// compound form still asks the operator to choose).
//
// Wave 1 ships this as a shared helper rather than per-ecosystem so
// there's no risk of Python/Rust/npm disagreeing on what counts as
// "copyleft". The go-spdx/v2 parser does the heavy lifting for
// compound expressions, WITH-exceptions, and validity checks.

import (
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"
)

// LicenseTag is one of the five Wave-1 license classifications. The
// string values double as risk-signal IDs so the risk engine can emit
// them without a second mapping.
type LicenseTag string

const (
	// LicenseTagCopyleft — GPL, AGPL, LGPL, EUPL, CDDL, MPL, OSL, SSPL.
	LicenseTagCopyleft LicenseTag = "license.copyleft"
	// LicenseTagNonPermissive — copyleft OR source-available (BUSL,
	// SSPL, Commons Clause, ELv2, RSALv2, Confluent Community).
	LicenseTagNonPermissive LicenseTag = "license.non_permissive"
	// LicenseTagExceptionPresent — any `WITH <exception>` clause.
	LicenseTagExceptionPresent LicenseTag = "license.exception_present"
	// LicenseTagAmbiguous — compound expressions with >1 distinct family
	// or NOASSERTION mixed with SPDX.
	LicenseTagAmbiguous LicenseTag = "license.ambiguous_classifier"
	// LicenseTagUnidentified — NOASSERTION, empty, or unknown non-SPDX.
	LicenseTagUnidentified LicenseTag = "license.unidentified"
)

// weakCopyleftPrefixes and strongCopyleftPrefixes partition the copyleft
// family by HOW FAR the reciprocity obligation reaches. Both halves emit
// LicenseTagCopyleft — the tag's meaning is unchanged and is the contract
// core/policy reads — but the split lets the risk registry price them
// differently. See LicenseStrength for what the bands mean and why.
//
// The version-bearing prefixes carry a trailing hyphen so "GPL-" cannot
// swallow "LGPL-"/"AGPL-"; the bare family tokens ("gpl", "lgpl", …) exist
// for the versionless names NormalizeLicenseExpression produces from free
// text — "GNU Lesser General Public License" pins no version, and it does
// not need to, because the weak/strong band is version-invariant across
// every published version of each family.
//
// Order matters within matchesPrefix only in that the bare "gpl" token must
// not match "lgpl-3.0" — it does not, because matchesPrefix is HasPrefix,
// and "lgpl-3.0" does not start with "gpl".
var weakCopyleftPrefixes = []string{
	"lgpl-", "lgpl",
	"cddl-", "cddl",
	"mpl-", "mpl",
	"epl-", "epl",
	"ms-rl",
	"cecill-c",
}

var strongCopyleftPrefixes = []string{
	"agpl-", "agpl",
	"gpl-", "gpl",
	"eupl-", "eupl",
	"osl-", "osl",
	"sspl-", "sspl",
	"sleepycat",
}

// copyleftPrefixes is compared against each SPDX identifier extracted
// from the expression (case-insensitive, after lowercasing). Exact
// GPL-2.0-only matches via the "gpl" prefix; "MPL-2.0" via "mpl".
//
// It is the UNION of the two bands above, so LicenseTagCopyleft fires on
// exactly the set it fired on before the bands were introduced.
var copyleftPrefixes = append(append([]string{}, weakCopyleftPrefixes...), strongCopyleftPrefixes...)

// sourceAvailablePrefixes covers licenses that look like FOSS but
// forbid competing commercial use. None of these have SPDX IDs in some
// cases (BUSL, ELv2 are SPDX; Commons Clause is a rider) — we match
// both the SPDX id and common fulltext markers.
var sourceAvailablePrefixes = []string{
	"busl-",
	"sspl-",
	"elastic-",
	"rsal-",
	"confluent",
	"commons-clause",
	"server-side-public-license",
}

// LicenseStrength ranks how far a non-permissive licence's obligations
// reach INTO THE CONSUMER'S OWN CODE. It is the axis the flat -20/-20
// copyleft pricing was missing: before this existed, MPL-2.0 and AGPL-3.0
// and BUSL-1.1 were all the same number, and MPL-2.0 was in fact the most
// expensive of the three (it paid -20 twice, once as copyleft and once as
// the non-permissive superset, while BUSL paid -20 once).
//
// The bands, and the reason each sits where it does:
//
//	WeakCopyleft — MPL, EPL, CDDL, LGPL, EUPL's file-scoped cousins, MS-RL,
//	  CeCILL-C. Reciprocity is scoped to the dependency's OWN files (MPL /
//	  EPL / CDDL) or to linkage (LGPL). A consumer that takes the library
//	  unmodified and links it inherits no obligation over its own source.
//	  This is the overwhelmingly common shape of a copyleft dependency and
//	  is why the flat rate was the largest remaining licence over-call.
//
//	SourceAvailable — BUSL, ELv2, RSAL, Confluent Community, Commons
//	  Clause. Not OSI-free at all: the grant forbids offering a competing
//	  service. It imposes nothing on the consumer's source, but it can
//	  forbid the consumer's BUSINESS outright, which no copyleft licence
//	  does. Prices above weak copyleft.
//
//	StrongCopyleft — GPL, AGPL, OSL, SSPL, Sleepycat. Distributing a
//	  derived work obliges the whole work under the same terms; AGPL and
//	  SSPL extend that to network use, which is what makes them the sharp
//	  case for a SaaS consumer. Prices above both.
//
// A caveat that is deliberately NOT modelled: LGPL is weak copyleft only
// under dynamic linking. Go and Rust link statically, which pulls LGPL
// toward the strong band for those two ecosystems. The engine has no
// linkage facts at all — it sees a registry metadata string — so inventing
// a per-ecosystem override here would be a guess dressed as a measurement.
// LGPL sits in the weak band for every ecosystem and this is the record of
// why.
type LicenseStrength int

const (
	// LicenseStrengthPermissive — no non-permissive identifier present.
	LicenseStrengthPermissive LicenseStrength = iota
	// LicenseStrengthWeakCopyleft — file- or linkage-scoped reciprocity.
	LicenseStrengthWeakCopyleft
	// LicenseStrengthSourceAvailable — not OSI-free; forbids competing use.
	LicenseStrengthSourceAvailable
	// LicenseStrengthStrongCopyleft — whole-work reciprocity.
	LicenseStrengthStrongCopyleft
)

// LicenseStrengthOf returns the HIGHEST band any identifier in the
// expression reaches. A compound like "MPL-2.0 AND GPL-3.0" is strong:
// the tightest obligation in the expression is the one that binds.
//
// It runs the same name normalisation Classify does, so it answers the
// same way for "GNU General Public License" as for "GPL-3.0-only", and it
// is safe to call on a raw registry string.
func LicenseStrengthOf(expression string) LicenseStrength {
	raw := strings.TrimSpace(expression)
	if raw == "" {
		return LicenseStrengthPermissive
	}
	raw = normalizeIfUnparsed(raw)

	ids, err := spdxexp.ExtractLicenses(raw)
	if err != nil || len(ids) == 0 {
		// Same tokenisation the fallback classifier uses, so a
		// non-SPDX rider ("Apache-2.0 AND Commons-Clause") is still
		// ranked rather than silently reported permissive.
		ids = splitLicenseTokens(raw)
	}
	best := LicenseStrengthPermissive
	for _, id := range ids {
		low := strings.ToLower(strings.Trim(strings.TrimSpace(id), "() "))
		s := LicenseStrengthPermissive
		switch {
		case matchesPrefix(low, strongCopyleftPrefixes):
			s = LicenseStrengthStrongCopyleft
		case matchesPrefix(low, sourceAvailablePrefixes) || strings.Contains(low, "commons"):
			s = LicenseStrengthSourceAvailable
		case matchesPrefix(low, weakCopyleftPrefixes):
			s = LicenseStrengthWeakCopyleft
		}
		if s > best {
			best = s
		}
	}
	return best
}

// splitLicenseTokens splits a compound expression on the SPDX connectives
// and returns the trimmed operands. Shared by fallbackClassify and
// LicenseStrengthOf so the two cannot drift on what counts as a token.
func splitLicenseTokens(raw string) []string {
	sep := raw
	for _, s := range []string{" AND ", " and ", " OR ", " or ", " WITH ", " with "} {
		sep = strings.ReplaceAll(sep, s, "|")
	}
	out := make([]string, 0, 4)
	for _, t := range strings.Split(sep, "|") {
		if t = strings.Trim(strings.TrimSpace(t), "() "); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// Classify parses the SPDX expression and returns the set of tags
// that apply. Returns nil for a tag-less expression (the common case
// for MIT / Apache-2.0 / BSD-3-Clause / ISC, which do not trigger any
// of the five rules).
//
// The function never panics and never errors — a malformed expression
// degrades to LicenseTagUnidentified so the caller can still surface
// it to the operator.
func Classify(expression string) []LicenseTag {
	raw := strings.TrimSpace(expression)
	if raw == "" {
		return []LicenseTag{LicenseTagUnidentified}
	}
	upper := strings.ToUpper(raw)
	if upper == "NOASSERTION" || upper == "NONE" {
		return []LicenseTag{LicenseTagUnidentified}
	}

	// Free-text licence NAMES are rewritten to SPDX ids before anything
	// else looks at the string — but ONLY when the string does not already
	// parse, so every already-correct expression is handled by the exact
	// code path it was handled by before. See NormalizeLicenseExpression
	// for why this is a read-side rewrite and not an extractor-side one.
	raw = normalizeIfUnparsed(raw)

	var tags []LicenseTag
	seen := map[LicenseTag]struct{}{}
	add := func(t LicenseTag) {
		if _, ok := seen[t]; ok {
			return
		}
		seen[t] = struct{}{}
		tags = append(tags, t)
	}

	// `WITH` clause detection is a cheap substring scan — go-spdx
	// doesn't expose the exception node directly, but the SPDX grammar
	// reserves ` WITH ` as a keyword so a case-insensitive substring
	// check is safe for the canonical form. Parenthesised forms still
	// carry the keyword, so this catches `(GPL-2.0 WITH Classpath)`.
	if containsWordWith(raw) {
		add(LicenseTagExceptionPresent)
	}

	ids, err := spdxexp.ExtractLicenses(raw)
	if err != nil || len(ids) == 0 {
		// Source-available riders like "Commons-Clause" and mixed
		// NOASSERTION expressions often fail SPDX parsing. Do a
		// token-level fallback: split on AND/OR/WITH and classify
		// each piece independently so we still surface the non-
		// permissive bit and flag compound/ambiguous forms. Only
		// stamp Unidentified when *every* token was unrecognised
		// (so "Apache-2.0 AND Commons-Clause" stays classified).
		unknown := fallbackClassify(raw, add)
		if unknown {
			add(LicenseTagUnidentified)
		}
		return tags
	}

	// Track distinct license families so we can decide "ambiguous".
	families := map[string]struct{}{}
	noassertionMixed := false
	copyleft := false
	sourceAvail := false

	for _, id := range ids {
		lower := strings.ToLower(id)
		if lower == "noassertion" {
			noassertionMixed = true
			continue
		}
		families[familyOf(lower)] = struct{}{}
		if matchesPrefix(lower, copyleftPrefixes) {
			copyleft = true
		}
		if matchesPrefix(lower, sourceAvailablePrefixes) {
			sourceAvail = true
		}
	}
	if copyleft {
		add(LicenseTagCopyleft)
	}
	// Non-permissive is the superset of copyleft + source-available.
	if copyleft || sourceAvail {
		add(LicenseTagNonPermissive)
	}
	// Ambiguous when: >1 distinct family, OR NOASSERTION mixed with
	// real identifiers, OR the parser saw ` OR ` connecting different
	// choices. The go-spdx parser collapses compound clauses into the
	// identifier list, so `MIT OR GPL-2.0-only` yields 2 identifiers.
	if len(families) > 1 || (noassertionMixed && len(families) > 0) {
		add(LicenseTagAmbiguous)
	}
	// If after extraction we saw NOASSERTION on its own, call it
	// unidentified too (this also covers `NOASSERTION OR MIT` where
	// the intent is unclear — ambiguous is already emitted above).
	if noassertionMixed && len(families) == 0 {
		add(LicenseTagUnidentified)
	}
	return tags
}

// ─── FREE-TEXT LICENCE NAMES ────────────────────────────────────────────
//
// Most registries do not carry an SPDX id. They carry the licence's NAME,
// as a human typed it into a POM / setup.py / gemspec:
//
//	Maven      <licenses><license><name>The Apache Software License, Version 2.0
//	PyPI       Info.License, free text: "Apache 2.0", "MIT License", "BSD"
//	RubyGems   licenses[], usually SPDX but not required to be
//	NuGet      licenseUrl fallback
//	Cocoapods  podspec `license` — a name or a {type: …} map
//	HF         cardData.license
//
// Every one of those strings was handed straight to a strict SPDX parser,
// failed, and came back LicenseTagUnidentified. Measured on the 400-package
// benign corpus: 58/70 Maven artifacts (82.9%) — guava, netty, jackson,
// log4j-core — carried license.unidentified while declaring Apache-2.0 in
// plain words.
//
// THE ERROR IS TWO-WAY AND THE SECOND HALF IS WORSE. "Eclipse Public
// License v2.0", "MPL 2.0" and "GNU Lesser General Public License" are all
// genuine copyleft, and all three came back "unidentified" — a -15
// unknown instead of a copyleft classification, and no license.copyleft tag
// for a policy to gate on. Four artifacts in the same 70 are exactly that
// case. Fixing only the Apache/MIT half would have widened that gap.
//
// WHY THIS LIVES IN THE CLASSIFIER AND NOT IN THE EXTRACTORS. The obvious
// alternative is to normalise in provider_registrymetadata.go, at each
// registry's read. Four reasons not to:
//
//  1. It would be ten edit sites (one per registry above) and ten future
//     drift sites. This file exists precisely so "Python/Rust/npm cannot
//     disagree about what counts as copyleft" — the same argument applies
//     to what counts as Apache-2.0.
//  2. LicenseSPDX is STORED and RENDERED. Overwriting the POM's own words
//     with our guess destroys the only evidence an operator has for
//     checking that guess, and makes a normalisation mistake unrecoverable
//     without re-fetching the registry. Normalising on READ leaves the raw
//     string in the report, in the UI and in the signal's evidence map.
//  3. Every Report already persisted carries the raw name. A read-side fix
//     corrects them the moment they are re-projected; an extraction-side
//     fix corrects nothing until each coordinate is re-fetched.
//  4. It is measurable. The server-side FP harness re-projects a frozen
//     corpus of stored reports, so a read-side change moves the numbers on
//     the same bytes. An extraction-side change is invisible to it without
//     rebuilding the corpus against five live registries, which makes the
//     before/after a comparison of two different populations.
//
// The trade this accepts: lic.missing and lic.spdx_present key on
// LicenseSPDX == "", which normalisation does not touch, so a POM name
// string still counts as "SPDX present". That over-claim predates this
// change and is unchanged by it — but the CONTRADICTION it produced
// (spring-core firing lic.spdx_present AND license.unidentified on the same
// report) does go away, because the name now identifies.

// licenseNameAliases maps a normalised free-text licence NAME to the SPDX
// identifier it denotes. Keys are produced by licenseNameKey: lowercased,
// every non-alphanumeric run collapsed to a single space, a leading "the "
// dropped, and a bare "v" stripped from a version token ("v2.0" → "2.0").
//
// Entries are deliberately EXACT-MATCH and deliberately conservative. An
// alias is only listed where the name determines the licence; a name that
// is genuinely ambiguous is left alone so it keeps reporting
// LicenseTagUnidentified, which is the honest answer. In particular:
//
//   - bare "BSD" is NOT here. It does not say 2-clause or 3-clause and the
//     two are different grants.
//   - bare "Apache License" IS here, mapping to Apache-2.0, because
//     Apache-1.1 has not been used for a new release in two decades and the
//     string appears as the first line of the Apache-2.0 licence TEXT.
//
// Versionless copyleft family names map to a BARE family token ("LGPL",
// "GPL", "MPL", …) rather than to an invented version. That token is not a
// valid SPDX id, so it flows through fallbackClassify — which is exactly
// what we want: the family determines the tag set and the strength band,
// and neither depends on the version, so nothing is lost by not guessing
// one.
var licenseNameAliases = map[string]string{
	// Apache
	"apache license 2.0":                  "Apache-2.0",
	"apache license version 2.0":          "Apache-2.0",
	"apache software license 2.0":         "Apache-2.0",
	"apache software license version 2.0": "Apache-2.0",
	"apache software licenses":            "Apache-2.0",
	"apache public license 2.0":           "Apache-2.0",
	"apache 2.0":                          "Apache-2.0",
	"apache 2":                            "Apache-2.0",
	"asl 2.0":                             "Apache-2.0",
	"apache license":                      "Apache-2.0",

	// MIT
	"mit license":     "MIT",
	"mit license mit": "MIT",
	"expat license":   "MIT",

	// BSD
	"bsd 3 clause license":                 "BSD-3-Clause",
	"bsd 3 clause":                         "BSD-3-Clause",
	"3 clause bsd license":                 "BSD-3-Clause",
	"new bsd license":                      "BSD-3-Clause",
	"modified bsd license":                 "BSD-3-Clause",
	"revised bsd license":                  "BSD-3-Clause",
	"bsd 3 clause new or revised license":  "BSD-3-Clause",
	"bsd 2 clause license":                 "BSD-2-Clause",
	"bsd 2 clause":                         "BSD-2-Clause",
	"2 clause bsd license":                 "BSD-2-Clause",
	"simplified bsd license":               "BSD-2-Clause",
	"freebsd license":                      "BSD-2-Clause",
	"bsd 2 clause simplified license":      "BSD-2-Clause",
	"bsd 3 clause clear license":           "BSD-3-Clause-Clear",
	"bsd zero clause license":              "0BSD",
	"bsd 4 clause original or old license": "BSD-4-Clause",

	// Eclipse — weak copyleft, and the version IS in the name.
	"eclipse public license 2.0":         "EPL-2.0",
	"eclipse public license 2.0 epl 2.0": "EPL-2.0",
	"eclipse public license version 2.0": "EPL-2.0",
	"epl 2.0":                            "EPL-2.0",
	"eclipse public license 1.0":         "EPL-1.0",
	"eclipse public license version 1.0": "EPL-1.0",
	"epl 1.0":                            "EPL-1.0",
	"eclipse public license":             "EPL",
	"eclipse distribution license 1.0":   "BSD-3-Clause",

	// Mozilla — weak copyleft.
	"mozilla public license 2.0":         "MPL-2.0",
	"mozilla public license version 2.0": "MPL-2.0",
	"mpl 2.0":                            "MPL-2.0",
	"mozilla public license 1.1":         "MPL-1.1",
	"mpl 1.1":                            "MPL-1.1",
	"mozilla public license":             "MPL",

	// GNU — the false-negative half. Versionless names keep the family.
	"gnu general public license":                    "GPL",
	"gnu general public license gpl":                "GPL",
	"gnu general public license 2.0":                "GPL-2.0-only",
	"gnu general public license version 2":          "GPL-2.0-only",
	"gnu general public license version 2.0":        "GPL-2.0-only",
	"gpl 2.0":                                       "GPL-2.0-only",
	"gnu general public license 3.0":                "GPL-3.0-only",
	"gnu general public license version 3":          "GPL-3.0-only",
	"gnu general public license version 3.0":        "GPL-3.0-only",
	"gpl 3.0":                                       "GPL-3.0-only",
	"gnu lesser general public license":             "LGPL",
	"gnu lesser general public license lgpl":        "LGPL",
	"gnu library general public license":            "LGPL",
	"gnu library or lesser general public license":  "LGPL",
	"gnu lesser general public license 2.1":         "LGPL-2.1-only",
	"gnu lesser general public license version 2.1": "LGPL-2.1-only",
	"lgpl 2.1":                                    "LGPL-2.1-only",
	"gnu lesser general public license 3.0":       "LGPL-3.0-only",
	"lgpl 3.0":                                    "LGPL-3.0-only",
	"gnu affero general public license":           "AGPL",
	"gnu affero general public license 3.0":       "AGPL-3.0-only",
	"gnu affero general public license version 3": "AGPL-3.0-only",
	"agpl 3.0":                                    "AGPL-3.0-only",

	// CDDL — weak copyleft.
	"common development and distribution license":     "CDDL",
	"common development and distribution license 1.0": "CDDL-1.0",
	"common development and distribution license 1.1": "CDDL-1.1",
	"cddl 1.0": "CDDL-1.0",
	"cddl 1.1": "CDDL-1.1",

	// Source-available.
	"business source license 1.1":  "BUSL-1.1",
	"elastic license 2.0":          "Elastic-2.0",
	"server side public license":   "SSPL-1.0",
	"server side public license 1": "SSPL-1.0",

	// Assorted permissive names that showed up as "unidentified".
	"isc license":                                 "ISC",
	"zlib license":                                "Zlib",
	"python software foundation license":          "Python-2.0",
	"psf license":                                 "Python-2.0",
	"the unlicense":                               "Unlicense",
	"unlicense":                                   "Unlicense",
	"cc0 1.0 universal":                           "CC0-1.0",
	"creative commons zero 1.0 universal":         "CC0-1.0",
	"boost software license 1.0":                  "BSL-1.0",
	"academic free license 3.0":                   "AFL-3.0",
	"artistic license 2.0":                        "Artistic-2.0",
	"microsoft public license":                    "MS-PL",
	"do what the fuck you want to public license": "WTFPL",
}

// licenseFamilyTokens are the bare family identifiers licenseNameAliases
// emits for a versionless copyleft NAME. They are not SPDX ids — SPDX has
// no versionless GPL — so nothing else in the tree produces them, and the
// only way one reaches Classify is through the normaliser. See the
// fallbackClassify branch that consumes this for why it exists.
var licenseFamilyTokens = map[string]struct{}{
	"gpl":  {},
	"lgpl": {},
	"agpl": {},
	"mpl":  {},
	"epl":  {},
	"cddl": {},
}

// minFullTextPrefixTokens is the shortest alias, in tokens, that may be
// matched as a PREFIX of a pasted licence body. Three tokens keeps
// "apache license" and "mit license" out of the full-text branch, where a
// two-word head match against several kilobytes of legal text is not
// evidence of anything.
const minFullTextPrefixTokens = 3

// licenseNameKey canonicalises a free-text licence name into the form the
// alias table is keyed on. Everything that is not a letter, digit or dot
// collapses to a single space, so "The Apache Software License, Version
// 2.0" and "The Apache Software License Version 2.0" produce the same key.
// A leading "the " is dropped, and a version token written "v2.0" loses the
// "v" so it matches the "2.0" spelling.
func licenseNameKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := true // leading spaces are suppressed
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.':
			b.WriteRune(r)
			space = false
		default:
			if !space {
				b.WriteByte(' ')
				space = true
			}
		}
	}
	key := strings.TrimSpace(b.String())
	key = strings.TrimPrefix(key, "the ")
	// Drop a "v" prefix on version tokens: "v2.0" → "2.0".
	fields := strings.Fields(key)
	for i, f := range fields {
		if len(f) > 1 && f[0] == 'v' && f[1] >= '0' && f[1] <= '9' {
			fields[i] = f[1:]
		}
	}
	return strings.Join(fields, " ")
}

// NormalizeLicenseExpression rewrites free-text licence NAMES in expr to
// the SPDX identifiers they denote, and returns expr unchanged when nothing
// is recognised. It never invents an identifier for a name that does not
// determine one.
//
// Three passes, cheapest and most certain first:
//
//  1. Whole-string alias. Handles the Maven/PyPI shape, where the entire
//     field is one name containing commas ("The Apache Software License,
//     Version 2.0") that a connective split would mangle.
//  2. Per-operand alias. Splits on the SPDX connectives and rewrites only
//     those operands that are NOT already valid SPDX, so "MIT OR Apache
//     License 2.0" becomes "MIT OR Apache-2.0" and "Apache-2.0 AND MIT" is
//     returned byte-identical.
//  3. Full-text head. Some registries carry the licence BODY in the field
//     (pandas ships the whole BSD-3-Clause text; sglang ships the whole
//     Apache-2.0 text). A body starts with its own title, so the first two
//     non-empty lines are keyed and matched against the LONGEST alias that
//     is a token-prefix of that key, subject to minFullTextPrefixTokens.
func NormalizeLicenseExpression(expr string) string {
	raw := strings.TrimSpace(expr)
	if raw == "" {
		return expr
	}

	// (1) whole-string.
	if id, ok := licenseNameAliases[licenseNameKey(raw)]; ok {
		return id
	}

	// (2) per-operand, connectives preserved.
	if out, changed := normalizeOperands(raw); changed {
		return out
	}

	// (3) full-text head.
	if strings.ContainsAny(raw, "\n\r") || len(raw) > 200 {
		if id, ok := fullTextHeadAlias(raw); ok {
			return id
		}
	}
	return expr
}

// normalizeOperands rewrites each non-SPDX operand of a compound
// expression, keeping the connectives and their spacing intact.
func normalizeOperands(raw string) (string, bool) {
	// Split on the connectives while remembering them, so the rebuilt
	// string is the original with only the operands substituted.
	const marker = "\x00"
	spaced := raw
	for _, c := range []string{" AND ", " and ", " OR ", " or ", " WITH ", " with "} {
		spaced = strings.ReplaceAll(spaced, c, marker+c+marker)
	}
	parts := strings.Split(spaced, marker)
	changed := false
	for i, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" || isConnective(trimmed) {
			continue
		}
		// Never rewrite an operand the SPDX parser already accepts.
		if ok, _ := spdxexp.ValidateLicenses([]string{trimmed}); ok {
			continue
		}
		id, hit := licenseNameAliases[licenseNameKey(trimmed)]
		if !hit {
			continue
		}
		parts[i] = strings.Replace(p, trimmed, id, 1)
		changed = true
	}
	if !changed {
		return raw, false
	}
	return strings.Join(parts, ""), true
}

func isConnective(s string) bool {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "AND", "OR", "WITH":
		return true
	}
	return false
}

// fullTextHeadAlias matches the head of a pasted licence body against the
// longest alias that prefixes it. Longest-wins so "apache license version
// 2.0" beats "apache license" on the Apache-2.0 body, which spells the
// version on its second line.
func fullTextHeadAlias(raw string) (string, bool) {
	lines := make([]string, 0, 2)
	for _, ln := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		if t := strings.TrimSpace(ln); t != "" {
			lines = append(lines, t)
			if len(lines) == 2 {
				break
			}
		}
	}
	if len(lines) == 0 {
		return "", false
	}
	head := licenseNameKey(strings.Join(lines, " "))
	bestKey, bestID := "", ""
	for k, id := range licenseNameAliases {
		if len(strings.Fields(k)) < minFullTextPrefixTokens {
			continue
		}
		if head != k && !strings.HasPrefix(head, k+" ") {
			continue
		}
		if len(k) > len(bestKey) {
			bestKey, bestID = k, id
		}
	}
	return bestID, bestID != ""
}

// normalizeIfUnparsed applies NormalizeLicenseExpression only when the
// expression does not already parse as SPDX. Callers that already parse
// cleanly are returned byte-identical, so this change cannot perturb the
// ~80% of the corpus that was already correct.
func normalizeIfUnparsed(raw string) string {
	if ids, err := spdxexp.ExtractLicenses(raw); err == nil && len(ids) > 0 {
		return raw
	}
	return NormalizeLicenseExpression(raw)
}

// familyOf returns the canonical family prefix of an SPDX id. "gpl-2.0-only"
// -> "gpl"; "apache-2.0" -> "apache". Used so `MIT AND MIT` is not flagged
// as ambiguous while `MIT AND BSD-3-Clause` is.
func familyOf(id string) string {
	if i := strings.Index(id, "-"); i > 0 {
		return id[:i]
	}
	return id
}

func matchesPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// containsWordWith matches ` WITH ` as a whole word (case-insensitive),
// ignoring any occurrences as a substring (e.g. "withdraw").
func containsWordWith(expr string) bool {
	upper := strings.ToUpper(expr)
	return strings.Contains(upper, " WITH ")
}

// fallbackClassify runs when the SPDX parser rejects the expression.
// Splits on AND/OR/WITH and applies prefix matches token-by-token,
// and records compound form for ambiguity.
// Returns true when no SPDX-shaped identifier was found in any token
// (caller then records LicenseTagUnidentified).
func fallbackClassify(raw string, add func(LicenseTag)) bool {
	upper := strings.ToUpper(raw)
	hasCompound := strings.Contains(upper, " AND ") || strings.Contains(upper, " OR ")
	tokens := splitLicenseTokens(raw)
	families := map[string]struct{}{}
	copyleft, sourceAvail, sawNoassertion, sawNonSPDX := false, false, false, false
	for _, t := range tokens {
		if strings.EqualFold(t, "NOASSERTION") {
			sawNoassertion = true
			continue
		}
		low := strings.ToLower(t)
		if matchesPrefix(low, copyleftPrefixes) {
			copyleft = true
		}
		if matchesPrefix(low, sourceAvailablePrefixes) || strings.Contains(low, "commons") {
			sourceAvail = true
		}
		// Validate against SPDX to decide whether this is a canonical
		// family or a non-SPDX rider. A bare family token is neither: it
		// is what NormalizeLicenseExpression emits for a versionless
		// copyleft NAME ("GNU Lesser General Public License" → "LGPL"),
		// where the family is known and the version is not. It counts as
		// a family — otherwise the caller would stamp Unidentified on a
		// licence we just successfully identified, which is the exact
		// false negative this wave exists to remove.
		if _, bare := licenseFamilyTokens[low]; bare {
			families[low] = struct{}{}
			continue
		}
		if ok, _ := spdxexp.ValidateLicenses([]string{t}); ok {
			families[familyOf(low)] = struct{}{}
		} else {
			sawNonSPDX = true
		}
	}
	if copyleft {
		add(LicenseTagCopyleft)
	}
	if copyleft || sourceAvail {
		add(LicenseTagNonPermissive)
	}
	if hasCompound && (len(families) > 1 || (sawNoassertion && len(families) > 0) || (sawNonSPDX && len(families) > 0)) {
		add(LicenseTagAmbiguous)
	}
	// "Unknown" means we saw no SPDX-looking identifiers (purely
	// NOASSERTION or completely free-form strings).
	return len(families) == 0
}
