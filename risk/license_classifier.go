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

// copyleftPrefixes is compared against each SPDX identifier extracted
// from the expression (case-insensitive, after lowercasing). Exact
// GPL-2.0-only matches via the "gpl" prefix; "MPL-2.0" via "mpl".
var copyleftPrefixes = []string{
	"gpl-",
	"agpl-",
	"lgpl-",
	"eupl-",
	"cddl-",
	"mpl-",
	"osl-",
	"sspl-",
	"sleepycat",
	"epl-",
}

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
	// Tokenise on compound connectives.
	sep := raw
	for _, s := range []string{" AND ", " and ", " OR ", " or ", " WITH ", " with "} {
		sep = strings.ReplaceAll(sep, s, "|")
	}
	tokens := strings.Split(sep, "|")
	families := map[string]struct{}{}
	copyleft, sourceAvail, sawNoassertion, sawNonSPDX := false, false, false, false
	for _, t := range tokens {
		t = strings.Trim(strings.TrimSpace(t), "() ")
		if t == "" {
			continue
		}
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
		// family or a non-SPDX rider.
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
