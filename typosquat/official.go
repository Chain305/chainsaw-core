package typosquat

import "strings"

// official.go — the first-party-sibling exemption for the combosquat lane.
//
// ─── THE PROBLEM ────────────────────────────────────────────────────────────
//
// checkCombosquat fires on "candidate CONTAINS a popular name with <= 8 extra
// characters". That is deliberately broad, which is why every hit it produces
// is graded "low" and worth only -8 in the risk registry. But breadth means it
// cannot tell an impostor from a first-party sibling:
//
//	lodash.merge   contains "lodash" + 6 extra   → hit   (published BY lodash)
//	lodash-utils   contains "lodash" + 6 extra   → hit   (registrable by anyone)
//
// The two are byte-for-byte the same SHAPE. No name-level rule separates them,
// so any guard keyed on shape alone — "suppress <popular>.<suffix>", "suppress
// <popular>-<suffix>" — hands an attacker a free bypass: `lodash.evil` and
// `lodash-utils` are both unregistered names on npm today.
//
// ─── WHAT THIS GUARD KEYS ON ────────────────────────────────────────────────
//
// Exact, whole package names on a reviewed list. Nothing pattern-shaped, no
// prefix globs, no delimiter heuristics. An attacker cannot land on this list
// by choosing a name, because every entry is a name that is ALREADY PUBLISHED
// by the first party it sits under — the attacker would have to take over the
// upstream account, at which point the typosquat signal is not the control
// that matters.
//
// ─── WHAT IT DELIBERATELY DOES NOT KEY ON ───────────────────────────────────
//
//   - Name shape. `<popular><delimiter><suffix>` is NOT sufficient. See above.
//   - Membership in the loaded popular corpus. On the server that corpus comes
//     from npm's keyword search (fetcher.go, fetchNPM), which is ranked by a
//     live third-party score and is exactly why `lodash.merge` reaches this
//     code at all: the reviewed 5,000-name seed the CLI guard loads DOES carry
//     lodash.merge and clears it on the exact-match branch, while the server's
//     keyword corpus carries only `lodash`. A corpus that upstream ranking can
//     move is not a trust boundary.
//   - Sibling-family size in the corpus ("suppress if >= N names share the
//     <root><delim> prefix"). Measured, and rejected: with the 5,000-name npm
//     seed it would suppress every `babel-*` name against popular `babel`,
//     which is a real bypass for a -8 signal that buys ~4% of the FP class.
//
// ─── WHAT WOULD ACTUALLY GENERALISE, AND WHY IT IS NOT HERE ─────────────────
//
// The correct key is shared maintainer identity: `lodash.merge`'s npm
// maintainer set overlaps `lodash`'s, `lodash-utils`'s would not. Detector.Check
// takes (ctx, ecosystem, packageName) and NOTHING else, by design — the offline
// CLI install guard (core/cli/guard_eval.go) calls it with no network and no
// registry metadata, and the intelligence typosquat provider is Tier 1, fanning
// out in parallel with the registry-metadata provider rather than after it. So
// maintainer sets are not available on either call path today, and plumbing
// them is a cross-package change (provider tiering + a maintainer index for the
// popular corpus + an offline story for the CLI) well outside this fix.
//
// LoadOfficialSiblings below is the seam for that work: a caller that HAS
// verified maintainer overlap can register the names it verified, and this
// static list becomes the offline floor rather than the whole mechanism.

// officialSiblings maps ecosystem → set of normalized package names that are
// verified first-party siblings of a popular root, and are therefore exempt
// from the combosquat lane (and ONLY from that lane — homoglyph, edit-distance
// and reorder hits are unaffected, because a first-party name should never
// produce one and if it somehow did we would want to see it).
//
// ADDING AN ENTRY. Each name must be (a) currently published, and (b) verified
// to share a maintainer/owner with the popular root it embeds. Record the
// verification in the group comment. Never add a pattern; never add a name you
// have not checked. An entry here is a permanent hole for exactly one string.
var officialSiblings = map[string]map[string]struct{}{
	"npm": nameSet(
		// The lodash v4 modular build. lodash publishes one package per
		// function under the `lodash.` prefix from the same npm org as
		// `lodash` itself; the list below is the subset that appears in the
		// reviewed npm top-5,000 popularity seed (core/cli/seeds/npm_popular.txt),
		// so each one is both first-party and demonstrably in real use.
		// `lodash-es` is the same team's ES-module build.
		"lodash.merge", "lodash.isplainobject", "lodash.once", "lodash.isstring",
		"lodash.camelcase", "lodash.includes", "lodash.isinteger", "lodash.isboolean",
		"lodash.debounce", "lodash.memoize", "lodash.isnumber", "lodash.uniq",
		"lodash.defaults", "lodash.sortby", "lodash.isequal", "lodash.isarguments",
		"lodash.castarray", "lodash.get", "lodash.clonedeep", "lodash.truncate",
		"lodash.flatten", "lodash.escaperegexp", "lodash.throttle", "lodash.difference",
		"lodash.union", "lodash.isfunction", "lodash.snakecase", "lodash.mergewith",
		"lodash.flattendeep", "lodash.groupby", "lodash.isnil", "lodash.startcase",
		"lodash.kebabcase", "lodash.isundefined", "lodash.upperfirst", "lodash.isobject",
		"lodash.uniqby", "lodash.isempty", "lodash.template", "lodash.templatesettings",
		"lodash._reinterpolate", "lodash.ismatch", "lodash.keys",
		"lodash-es",
	),
}

func nameSet(names ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		if n = strings.TrimSpace(strings.ToLower(n)); n != "" {
			m[n] = struct{}{}
		}
	}
	return m
}

// LoadOfficialSiblings registers additional verified first-party names for an
// ecosystem, exempting them from the combosquat lane. Additive: it merges into
// whatever the static list already carries and never removes an entry.
//
// This is the seam for maintainer-verified data. Callers that can prove the
// candidate shares an owner with the popular root it embeds (a registry
// metadata pass, a signed corpus bundle) should register the names they
// verified here rather than widening the shape rules in checkCombosquat.
//
// Names are matched EXACTLY after ecosystem normalization. Passing a pattern,
// a prefix, or a glob does nothing useful — that is intentional.
func (d *Detector) LoadOfficialSiblings(ecosystem string, names []string) {
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
	if ecosystem == "" || len(names) == 0 {
		return
	}
	norm := NormalizerForFormat(ecosystem)

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.siblings == nil {
		d.siblings = make(map[string]map[string]struct{})
	}
	set := d.siblings[ecosystem]
	if set == nil {
		set = make(map[string]struct{}, len(names))
		d.siblings[ecosystem] = set
	}
	for _, n := range names {
		if normalized := norm(n); normalized != "" {
			set[normalized] = struct{}{}
		}
	}
}

// isOfficialSibling reports whether the normalized name is on either the static
// first-party list or the per-detector one. Callers must NOT hold d.mu.
func (d *Detector) isOfficialSibling(ecosystem, normalized string) bool {
	if normalized == "" {
		return false
	}
	if set, ok := officialSiblings[ecosystem]; ok {
		if _, hit := set[normalized]; hit {
			return true
		}
	}
	d.mu.RLock()
	set, ok := d.siblings[ecosystem]
	if ok {
		_, ok = set[normalized]
	}
	d.mu.RUnlock()
	return ok
}
