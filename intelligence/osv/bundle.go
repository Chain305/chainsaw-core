// Package osv loads the offline-bundled OSV.dev advisory index that
// the intelligence layer's `osv` provider consults at runtime.
//
// Why a parallel CVE source: Trivy's DB is great when the OCI updater
// keeps up, but in airgapped or first-boot scenarios the DB can be
// stale or empty. OSV is structured (no NVD-style free-text parsing),
// has solid coverage across npm / PyPI / Cargo / RubyGems / NuGet /
// Packagist / Maven, and ships as plain JSON so we can pre-process the
// dump into a small in-memory map at build time.
//
// The bundle format is deliberately simple — a gzip'd JSON array of
// flat advisory records:
//
//	[
//	  {
//	    "ecosystem":"PyPI",
//	    "package":"idna",
//	    "vulnerable_versions":["3.6","3.15"],
//	    "advisory_id":"GHSA-jjg7-2v4v-x38h",
//	    "summary":"...",
//	    "cvss_score":6.2,
//	    "severity":"MEDIUM",
//	    "fixed_versions":["3.7"],
//	    "aliases":["CVE-2024-3651"],
//	    "published":"2024-04-12T00:00:00Z",
//	    "modified":"2024-04-12T00:00:00Z"
//	  },
//	  ...
//	]
//
// The build-time job (dockerized/build.sh) expands each OSV `affected`
// block's version ranges into concrete `vulnerable_versions` entries
// using the registry's known version list. That keeps the runtime
// matcher trivial: exact string compare against `Version` for that
// (ecosystem, package) key. If a registry version isn't in the
// expanded list, the package is considered clean for that version.
//
// The index is keyed by (canonical-ecosystem, package-name). Canonical
// ecosystem names match the OSV upstream casing collapsed to
// lower-case ("pypi", "npm", "cargo", "rubygems", "nuget",
// "packagist", "maven"). Caller-facing names like "pip", "yarn",
// "bun", "gradle", "composer" are mapped to their OSV canonical via
// CanonicalEcosystem so lookups work regardless of which alias the
// proxy resolver hands us.
package osv

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	gem "github.com/aquasecurity/go-gem-version"
	pep440 "github.com/aquasecurity/go-pep440-version"
	mvn "github.com/masahiro331/go-mvn-version"
)

// Advisory is the flat advisory record the bundle ships. Mirrors the
// subset of fields the runtime provider needs.
//
// Two version-affected representations are carried because OSV's source
// schema mixes them per advisory:
//   - VulnerableVersions: an explicit list ("1.0.0","1.0.1",...). When
//     non-empty the runtime uses exact string equality to match.
//   - VulnerableRanges:   {introduced, fixed, last_affected} tuples that
//     describe a semver range. The build-time job preserves these
//     verbatim from OSV's affected.ranges[].events[] when the source
//     advisory has no enumerated versions list — typical of GHSA imports
//     where the affected block carries `ranges` only.
//
// A previous version of this matcher treated `VulnerableVersions==[]`
// as "matches every version" — which was wrong for the ranges-only case
// because the bundle's empty list meant "ranges are authoritative", not
// "applies to all". That bug inflated lodash 4.17.20's CVE count from
// 5 to 10 in production. See matchesVersion below for the corrected
// shape.
type Advisory struct {
	Ecosystem          string            `json:"ecosystem"`
	Package            string            `json:"package"`
	VulnerableVersions []string          `json:"vulnerable_versions,omitempty"`
	VulnerableRanges   []VulnerableRange `json:"vulnerable_ranges,omitempty"`
	AdvisoryID         string            `json:"advisory_id"`
	Summary            string            `json:"summary,omitempty"`
	CVSSScore          float64           `json:"cvss_score,omitempty"`
	Severity           string            `json:"severity,omitempty"`
	FixedVersions      []string          `json:"fixed_versions,omitempty"`
	Aliases            []string          `json:"aliases,omitempty"`
	Published          string            `json:"published,omitempty"`
	Modified           string            `json:"modified,omitempty"`
}

// VulnerableRange describes a semver range over the affected versions.
// Introduced = "" or "0" means "from the beginning"; Fixed = "" means
// the range is open-ended (advisory has no patched release yet);
// LastAffected = "" unless OSV explicitly marks an inclusive upper
// bound. At least one of Fixed / LastAffected SHOULD be present —
// fully-open ranges are encoded as a single zero-value record so the
// matcher can distinguish "advisory applies to everything" from
// "advisory has no version data".
type VulnerableRange struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// PreferredCVE returns the first CVE-prefixed alias if present, falling
// back to AdvisoryID otherwise. Used by the runtime provider to
// populate VulnSection.CVEs in CVE-id form even when the upstream
// record is keyed by GHSA.
func (a Advisory) PreferredCVE() string {
	for _, alias := range a.Aliases {
		if strings.HasPrefix(strings.ToUpper(alias), "CVE-") {
			return strings.ToUpper(alias)
		}
	}
	return a.AdvisoryID
}

// Index is the in-memory lookup the runtime provider consults. Built
// once at startup from the gzip'd JSON bundle; safe to share across
// goroutines (read-only after construction).
type Index struct {
	// byPackage is keyed by canonicalKey(ecosystem, package) and holds
	// every advisory that mentions that package, regardless of which
	// versions are affected. The provider filters by version at lookup
	// time so a single bundle pass populates the map.
	byPackage map[string][]Advisory
	// loadedAt records when the bundle was read off disk. Useful for
	// observability — operators can see how stale the in-memory copy is.
	loadedAt time.Time
	// path is the on-disk path the bundle was loaded from (for diagnostics).
	path string
	// total is the count of advisory records loaded.
	total int
}

// LoadFile parses the gzip'd JSON bundle at path and returns a populated
// Index. Returns (nil, err) when the file is missing or malformed.
// An empty bundle (`[]`) is valid and returns an empty Index — the
// provider stays dormant but won't fail Scan calls.
func LoadFile(path string) (*Index, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("osv: empty bundle path")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("osv: open %s: %w", path, err)
	}
	defer f.Close()

	idx, err := Load(f)
	if err != nil {
		return nil, err
	}
	idx.path = path
	return idx, nil
}

// Load parses an advisory stream from r. The reader's first two bytes
// are inspected to auto-detect gzip vs. plain JSON — production bundles
// ship gzip'd to keep the image layer small, but the test fixtures and
// `bundle apply --plain` flows pass raw JSON. Both paths succeed.
func Load(r io.Reader) (*Index, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("osv: peek: %w", err)
	}
	var src io.Reader = br
	// gzip magic: 0x1f 0x8b. Anything else is treated as raw JSON so the
	// loader works on either form without a separate code path.
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, gzErr := gzip.NewReader(br)
		if gzErr != nil {
			return nil, fmt.Errorf("osv: gunzip: %w", gzErr)
		}
		defer gz.Close()
		src = gz
	}

	var advisories []Advisory
	dec := json.NewDecoder(src)
	if err := dec.Decode(&advisories); err != nil {
		return nil, fmt.Errorf("osv: parse advisories: %w", err)
	}

	idx := &Index{
		byPackage: make(map[string][]Advisory, len(advisories)),
		loadedAt:  time.Now().UTC(),
		total:     len(advisories),
	}
	for _, a := range advisories {
		key := canonicalKey(a.Ecosystem, a.Package)
		if key == "" {
			continue
		}
		idx.byPackage[key] = append(idx.byPackage[key], a)
	}
	return idx, nil
}

// Lookup returns every advisory affecting (ecosystem, pkg, version).
// Version matching is exact string equality against the bundle's
// pre-expanded VulnerableVersions list — the builder is responsible for
// turning OSV's range syntax into a flat list per package.
//
// A nil receiver returns nil (provider may have been registered without
// a bundle file). An ecosystem the index doesn't know also returns nil.
func (i *Index) Lookup(ecosystem, pkg, version string) []Advisory {
	hits, _, _ := i.LookupEx(ecosystem, pkg, version)
	return hits
}

// LookupEx is Lookup's three-state form. It partitions the advisories
// keyed to (ecosystem, pkg) into:
//
//	hits        — evaluated, and the range/version data says AFFECTED
//	cleared     — evaluated, and the range/version data says NOT AFFECTED
//	undecidable — a bound could not be parsed under this ecosystem's
//	              grammar, so no verdict was reachable either way
//
// The `cleared` bucket is the whole point: it is positive evidence of
// absence for a concrete coordinate, which is what lets the intelligence
// merge VETO a CVE another source got wrong (see mergeVulns). "The
// advisory is not in `hits`" alone can never mean that, because most
// callers of a partial report simply have nothing to say about
// vulnerabilities — see the silence-is-not-veto rule in mergeVulns.
//
// `undecidable` exists because the alternative — folding a parse failure
// into `cleared` — would let a malformed version string silently veto a
// real advisory. Undecidable is surfaced as a warning by the provider,
// deliberately NOT as a severity signal: promoting an unparseable range
// to critical would manufacture the exact false-positive class this
// wave exists to remove.
func (i *Index) LookupEx(ecosystem, pkg, version string) (hits, cleared, undecidable []Advisory) {
	if i == nil {
		return nil, nil, nil
	}
	key := canonicalKey(ecosystem, pkg)
	if key == "" {
		return nil, nil, nil
	}
	candidates, ok := i.byPackage[key]
	if !ok {
		return nil, nil, nil
	}
	for _, a := range candidates {
		affects, undecided := advisoryAffectsEx(a, version)
		switch {
		case affects:
			hits = append(hits, a)
		case undecided:
			undecidable = append(undecidable, a)
		default:
			cleared = append(cleared, a)
		}
	}
	return hits, cleared, undecidable
}

// HasPackage reports whether the index has at least one advisory record
// keyed by (ecosystem, pkg). Used by the provider to distinguish "the
// package is in the index but this version is clean" from "the package
// is not covered at all" — the former should set Vulns to a non-nil
// empty VulnSection (so VulnDataAvailable evaluates true), the latter
// should leave Vulns nil.
func (i *Index) HasPackage(ecosystem, pkg string) bool {
	if i == nil {
		return false
	}
	key := canonicalKey(ecosystem, pkg)
	if key == "" {
		return false
	}
	_, ok := i.byPackage[key]
	return ok
}

// Total returns the count of advisories loaded. Zero on a nil receiver.
func (i *Index) Total() int {
	if i == nil {
		return 0
	}
	return i.total
}

// LoadedAt returns the timestamp the bundle was parsed. Zero on a nil
// receiver.
func (i *Index) LoadedAt() time.Time {
	if i == nil {
		return time.Time{}
	}
	return i.loadedAt
}

// Path returns the on-disk path the index was loaded from, or "" when
// the index was loaded from a non-file source (tests).
func (i *Index) Path() string {
	if i == nil {
		return ""
	}
	return i.path
}

// canonicalKey normalises (ecosystem, package) into a stable map key.
// Empty inputs return "" so the caller skips them.
func canonicalKey(ecosystem, pkg string) string {
	eco := CanonicalEcosystem(ecosystem)
	name := strings.TrimSpace(pkg)
	if eco == "" || name == "" {
		return ""
	}
	// Package names are case-sensitive in some ecosystems (Maven,
	// crates.io) and case-insensitive in others (PyPI normalises to
	// lower-case + collapsed separators). For lookup simplicity we
	// preserve the caller's casing for ecosystems where it matters and
	// downcase for PyPI/NuGet where the registry itself does.
	switch eco {
	case "pypi", "nuget", "packagist":
		name = strings.ToLower(name)
	}
	return eco + "\x00" + name
}

// CanonicalEcosystem maps caller-facing ecosystem names (proxy resolver
// emits "pip", "yarn", "bun", "gradle", "composer") to the OSV
// canonical form. Returns "" for ecosystems the OSV feed doesn't cover
// — the provider's Supports() reads this so unsupported ecosystems
// stay silently absent rather than producing a false-clean verdict.
func CanonicalEcosystem(ecosystem string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm", "yarn", "bun":
		// OSV: "npm". yarn/bun ride the npm registry so the advisory
		// keying matches.
		return "npm"
	case "pip", "pypi":
		return "pypi"
	case "maven", "gradle":
		// OSV: "Maven". gradle resolves through the Maven coordinates.
		return "maven"
	case "cargo", "crates", "crates.io":
		return "cargo"
	case "rubygems", "gem":
		return "rubygems"
	case "nuget":
		return "nuget"
	case "composer", "packagist":
		return "packagist"
	case "pub":
		// OSV: "Pub" (Dart / Flutter). Verified 2026-08-23 that the
		// upstream bucket is exactly "Pub" — "Dart" and lowercase "pub"
		// both 404. The switch lower-cases its input first, so an
		// advisory whose ecosystem field reads "Pub" folds onto the same
		// key as the "pub" the repository format emits.
		return "pub"
	case "go", "gomod":
		// OSV: "Go". gomod is the caller-facing alias the proxy resolver
		// emits for Go module advisories. Go module paths are
		// case-sensitive (per the OSV schema spec) so canonicalKey
		// deliberately does NOT add Go to the lower-casing branch.
		return "go"
	default:
		return ""
	}
}

// advisoryAffects reports whether an advisory applies to the given
// concrete version. The matcher walks two independent inputs:
//
//  1. Exact version list (VulnerableVersions) — the cheap path. When
//     non-empty AND the query is in the list, returns true.
//  2. Version range list (VulnerableRanges) — the structured path.
//     Each range is interpreted as `[Introduced, Fixed)` (or
//     `[Introduced, LastAffected]` when LastAffected is set). The
//     query is compared against bounds using an ECOSYSTEM-AWARE
//     comparator (compareVersions below) — PyPI uses PEP 440,
//     RubyGems uses Gem::Version, Maven/Gradle use Maven version
//     order, Composer/Packagist falls back to Maven-style, every-
//     thing else (npm, cargo, nuget) uses SemVer. Each library
//     handles its own pre-release / qualifier semantics.
//
// When BOTH inputs are empty we deliberately return false. Previously
// this returned true ("OSV uses empty as 'every version'"), but that
// was a misreading of the upstream schema — OSV emits an empty
// affected block ONLY when carrying its info in `ranges` instead. The
// inverted default fixed the lodash 4.17.20 over-count regression
// (10 → 5 CVEs).
func advisoryAffects(a Advisory, version string) bool {
	affects, _ := advisoryAffectsEx(a, version)
	return affects
}

// advisoryAffectsEx is advisoryAffects with the third state broken out.
// `undecidable` is true only when NO range produced a verdict and at
// least one range failed to parse — i.e. we genuinely do not know. An
// advisory with no version data at all is DECIDED clean (the
// return-false default described above), not undecidable: silence in
// the bundle is a statement about the advisory's shape, not a parse
// failure.
func advisoryAffectsEx(a Advisory, version string) (affects bool, undecidable bool) {
	v := strings.TrimSpace(version)
	if v == "" {
		return false, false
	}
	// Exact version list match — preferred when present.
	for _, w := range a.VulnerableVersions {
		if strings.TrimSpace(w) == v {
			return true, false
		}
	}
	// Range match — handles the GHSA-style affected.ranges[] case.
	for _, r := range a.VulnerableRanges {
		hit, undecided := rangeAffectsEx(a.Ecosystem, r, a.FixedVersions, v)
		if hit {
			return true, false
		}
		if undecided {
			undecidable = true
		}
	}
	return false, undecidable
}

// matchesVersion is kept as a shim against the old signature in case
// external callers wired against it. The bundle's own Lookup path now
// uses advisoryAffects directly so it can read the structured ranges.
// New code should call advisoryAffects.
func matchesVersion(affected []string, version string) bool {
	v := strings.TrimSpace(version)
	if v == "" {
		return false
	}
	for _, a := range affected {
		if strings.TrimSpace(a) == v {
			return true
		}
	}
	return false
}

// rangeAffectsEx reports whether the query version falls inside one
// VulnerableRange under the appropriate version-compare semantics for
// the given ecosystem, and whether the question was decidable at all.
// Each ecosystem has its own pre-release / qualifier rules (PyPI uses
// PEP 440, Maven uses qualifier ordering, RubyGems uses Gem::Version,
// NuGet has a fourth numeric segment) — getting this wrong leads to
// either false-positive over-matches or false-negative misses.
// compareVersions dispatches to the right library.
//
// # Why the advisory's FixedVersions is an input
//
// An OSV `affected` block routinely carries MORE THAN ONE range, and the
// bundle flatteners do not tag ranges with their upstream `type`. A GHSA
// import typically ships a GIT range (`{introduced:"<sha or 0>"}`,
// commonly with no closing event because the fix commit was never
// recorded) alongside the real SEMVER range `[0, 4.17.21)`. Flattened,
// the GIT range becomes the version range `{Introduced:"0"}` — an OPEN
// upper bound, which matches EVERY version forever. advisoryAffects ORs
// its ranges, so that one bogus open range overrides the correct
// exclusive-fix verdict of its sibling.
//
// That is the mechanism behind the measured production false positive:
// lodash 4.17.21 carrying CVE-2021-23337, an advisory *fixed in
// 4.17.21*. The `fixed == query` boundary below was never the bug — it
// has been correct since the range-aware matcher landed. The bug is that
// a range claiming "never fixed" outranked an advisory that declares its
// own fix version.
//
// So: when a range has no upper bound at all, and the advisory itself
// declares a fix, we close the range at the EARLIEST declared fix
// strictly above this range's `introduced`. Scoping the clamp to
// open-upper ranges and to fixes above the range's own lower bound is
// what keeps multi-branch advisories correct — an advisory fixed in
// 1.2.3 on the 1.x line and still open on 2.x clamps only the 1.x range,
// because 1.2.3 is not above `introduced: 2.0.0`.
//
// Parse failures return (false, true) rather than plain false. Returning
// "not affected" for a version string we could not read is a silent
// false negative — the caller decides what to do with the uncertainty.
func rangeAffectsEx(ecosystem string, r VulnerableRange, fixedVersions []string, queryRaw string) (bool, bool) {
	// Open-upper-bound clamp — see the FixedVersions rationale above.
	// Applied before the zero-value sentinel check so a fully-open range
	// on an advisory that declares a fix is closed too.
	if r.Fixed == "" && r.LastAffected == "" {
		if clamp := earliestFixAbove(ecosystem, fixedVersions, r.Introduced); clamp != "" {
			r.Fixed = clamp
		}
	}
	// Fully-zero range is the "applies to every published version"
	// sentinel used when OSV upstream emits an empty affected block
	// AND no fix is known. Distinct from "no range info at all" —
	// see advisoryAffects' return-false default.
	if r.Introduced == "" && r.Fixed == "" && r.LastAffected == "" {
		return true, false
	}
	// Cheap exact-match path: query string equals a range anchor
	// literally. Resilient to ecosystems whose parsers reject the
	// version (e.g. Maven "1.0-SNAPSHOT" vs "1.0.SNAPSHOT").
	if r.LastAffected != "" && r.LastAffected == queryRaw {
		return true, false
	}
	// The exclusive-fix anchor is checked BEFORE the introduced anchor:
	// `fixed` is exclusive under every OSV ecosystem, so query == fixed
	// is "not affected" even for the degenerate introduced == fixed
	// range (an empty interval), which the old ordering matched.
	if r.Fixed == queryRaw {
		return false, false // "fixed" is exclusive — query == fix → not affected
	}
	if r.Introduced == queryRaw {
		return true, false
	}
	// introduced bound (default "0" / open lower)
	if intro := strings.TrimSpace(r.Introduced); intro != "" && intro != "0" {
		cmp, err := compareVersions(ecosystem, queryRaw, intro)
		if err != nil {
			return false, true
		}
		if cmp < 0 {
			return false, false
		}
	}
	// fixed bound (exclusive)
	if fix := strings.TrimSpace(r.Fixed); fix != "" {
		cmp, err := compareVersions(ecosystem, queryRaw, fix)
		if err != nil {
			return false, true
		}
		if cmp >= 0 {
			return false, false
		}
	}
	// last_affected bound (inclusive)
	if la := strings.TrimSpace(r.LastAffected); la != "" {
		cmp, err := compareVersions(ecosystem, queryRaw, la)
		if err != nil {
			return false, true
		}
		if cmp > 0 {
			return false, false
		}
	}
	return true, false
}

// earliestFixAbove returns the smallest advisory-declared fix version
// strictly greater than `introduced`, or "" when the advisory declares
// no such fix. "" and "0" both mean "open lower bound", in which case
// every declared fix qualifies.
//
// Unparseable candidates are skipped rather than treated as a bound —
// a fix version we cannot order against `introduced` is not evidence
// that the range closes there, and guessing would re-open the
// false-negative hole from the other side.
func earliestFixAbove(ecosystem string, fixedVersions []string, introduced string) string {
	intro := strings.TrimSpace(introduced)
	openLower := intro == "" || intro == "0"
	best := ""
	for _, raw := range fixedVersions {
		fix := strings.TrimSpace(raw)
		if fix == "" {
			continue
		}
		if !openLower {
			cmp, err := compareVersions(ecosystem, fix, intro)
			if err != nil || cmp <= 0 {
				continue
			}
		}
		if best == "" {
			best = fix
			continue
		}
		cmp, err := compareVersions(ecosystem, fix, best)
		if err != nil {
			continue
		}
		if cmp < 0 {
			best = fix
		}
	}
	return best
}

// compareVersions dispatches version comparison to the per-ecosystem
// library that implements the ecosystem's actual ordering rules.
// Returns -1 / 0 / +1 in the conventional shape, or a non-nil error
// when either operand cannot be parsed under that ecosystem's grammar.
//
// Dispatch table:
//
//	pypi          → PEP 440 (alpha/beta/rc/dev/post; "1.0a1" < "1.0b1")
//	rubygems      → Gem::Version ("1.0.0.beta1" < "1.0.0")
//	maven, gradle → Maven version order ("1.0-SNAPSHOT" < "1.0", and the
//	                full qualifier ladder alpha/beta/milestone/rc/snapshot)
//	packagist     → Maven-flavoured fallback (Composer's rules are close
//	                enough; the few divergences mis-rank pre-releases by
//	                one band, which is acceptable for advisory matching)
//	nuget         → NuGet 4-segment order (Major.Minor.Patch.Revision +
//	                SemVer-style pre-release). NuGet is the one covered
//	                ecosystem whose native version grammar has a fourth
//	                numeric segment, and routing it through the SemVer
//	                default was a FALSE NEGATIVE: parseSemver drops the
//	                4th segment, so "1.2.3.4" and a fix at "1.2.3.5"
//	                both collapsed to "1.2.3" — query >= fixed —
//	                clearing an advisory that does affect the package.
//	npm, yarn, bun, cargo, default → SemVer 2.0 via Masterminds.
//	                A leading `v` and trailing 4th dot-segment are
//	                normalised away — both shapes show up in registry
//	                version strings.
func compareVersions(ecosystem, a, b string) (int, error) {
	a = normalizeVersionPrefix(a)
	b = normalizeVersionPrefix(b)
	switch CanonicalEcosystem(ecosystem) {
	case "nuget":
		va, err := parseNuGet(a)
		if err != nil {
			return 0, err
		}
		vb, err := parseNuGet(b)
		if err != nil {
			return 0, err
		}
		return va.compare(vb), nil
	case "pypi":
		va, err := pep440.Parse(a)
		if err != nil {
			return 0, err
		}
		vb, err := pep440.Parse(b)
		if err != nil {
			return 0, err
		}
		return va.Compare(vb), nil
	case "rubygems":
		va, err := gem.NewVersion(a)
		if err != nil {
			return 0, err
		}
		vb, err := gem.NewVersion(b)
		if err != nil {
			return 0, err
		}
		return va.Compare(vb), nil
	case "maven", "packagist":
		// mvn.NewVersion accepts ANY string: a leading non-numeric run
		// is read as a qualifier and sorts below numeric versions, so
		// "swiftmailer-6.2.5" compares as though it were less than
		// "5.4.5" — a confident, nil-error, inverted answer. Refuse
		// instead. An error here becomes `undecidable` in
		// advisoryAffectsEx, which LookupEx deliberately keeps out of
		// the `cleared` bucket, so an unorderable coordinate can never
		// veto a real advisory. Maven's own meta-versions ("RELEASE",
		// "LATEST") land here too, which is correct: they name no
		// concrete point to compare a bound against.
		if err := requireNumericLead("maven", a, b); err != nil {
			return 0, err
		}
		va, err := mvn.NewVersion(a)
		if err != nil {
			return 0, err
		}
		vb, err := mvn.NewVersion(b)
		if err != nil {
			return 0, err
		}
		return va.Compare(vb), nil
	default:
		// npm / yarn / bun / cargo / unknown → SemVer via
		// Masterminds. The lenient input filter handles `v`-prefix
		// and 4-segment npm anti-patterns the strict parser rejects.
		va, err := parseSemver(a)
		if err != nil {
			return 0, err
		}
		vb, err := parseSemver(b)
		if err != nil {
			return 0, err
		}
		return va.Compare(vb), nil
	}
}

// requireNumericLead rejects operands that do not begin with a digit
// after prefix normalisation. Only the Maven-family parser needs this:
// SemVer, PEP 440, Gem and NuGet all reject a non-numeric lead with a
// real error, while mvn.NewVersion silently reinterprets it as a
// qualifier and returns an inverted ordering. See the call site.
func requireNumericLead(family, a, b string) error {
	for _, v := range [2]string{a, b} {
		if v == "" || v[0] < '0' || v[0] > '9' {
			return fmt.Errorf("%s: version %q does not begin with a digit; refusing to order it", family, v)
		}
	}
	return nil
}

// normalizeVersionPrefix trims whitespace and strips ONE leading "v"/"V"
// when a digit follows it.
//
// WHY THIS IS NOT COSMETIC. Before this existed, compareVersions answered
// CONFIDENTLY AND WRONGLY whenever its two operands disagreed about
// carrying the prefix — and returned a nil error, so every caller's
// error branch was blind to it. Measured 2026-08-23:
//
//	compareVersions("composer", "5.4.5", "v6.3.0")            = +1  WRONG
//	compareVersions("composer", "5.4.5", "swiftmailer-6.2.5") = +1  WRONG
//	compareVersions("composer", "v6.3.0", "v5.4.5")           = +1  right
//	compareVersions("composer", "6.3.0", "5.4.5")             = +1  right
//
// Right when BOTH operands carry the prefix, right when NEITHER does,
// wrong only when they disagree. The cause is the dispatch table: the
// `default` branch launders the prefix through parseSemver, but
// maven/packagist hand the raw string to mvn.NewVersion, which reads a
// leading "v" as a QUALIFIER and sorts qualifier-led versions BELOW
// numeric ones — inverting the comparison.
//
// This is a range-matching correctness bug, not just a display one:
// advisoryAffectsEx compares the queried version against `introduced`,
// `fixed` and `lastAffected` (see the three call sites below), so an
// inverted result silently mis-evaluates a CVE bound — attaching an
// advisory that does not apply, or clearing one that does. The mixed
// case is routine rather than exotic: Go module versions are canonically
// v-prefixed while OSV bounds frequently are not, and 166 of 6,511
// production coordinates (2.5%) carry a non-numeric-leading version.
//
// Normalising BOTH operands identically preserves ordering for
// same-shaped inputs (the two "right" rows above are unchanged) and
// repairs it for mixed ones. Anything that still does not lead with a
// digit — a package-name-prefixed tag like "swiftmailer-6.2.5", a
// date-stamped docker tag — is left untouched here and refused
// downstream (see requireNumericLead for the Maven family, whose parser
// would otherwise accept it as a qualifier), surfacing as UNDECIDABLE. That is the
// safe outcome by construction: LookupEx keeps undecidable out of the
// `cleared` bucket precisely so an unparseable version can never veto a
// real advisory.
func normalizeVersionPrefix(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}
	return v
}

// parseSemver wraps Masterminds/semver with a lenient input filter so
// the matcher accepts the common version-string shapes registries emit
// (leading `v`, build/pre-release suffixes, four-segment npm versions
// like `1.2.3.4` that need the trailing segment dropped). Returns a
// non-nil error when the string cannot be parsed at all; the
// compareVersions caller propagates the error so the range matcher
// falls back to exact-string equality.
func parseSemver(v string) (*semver.Version, error) {
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(s, "v")
	// Drop a fourth dot-segment (`1.2.3.4` -> `1.2.3`) — npm publishes
	// these occasionally and Masterminds rejects them outright.
	if parts := strings.Split(s, "."); len(parts) > 3 {
		head := strings.Join(parts[:3], ".")
		if _, err := semver.NewVersion(head); err == nil {
			s = head
		}
	}
	return semver.NewVersion(s)
}

// nugetVersion is a parsed NuGet version: up to four numeric segments
// plus an optional pre-release label. Build metadata (`+sha`) is parsed
// off and discarded — NuGet, like SemVer, excludes it from ordering.
type nugetVersion struct {
	nums [4]uint64
	pre  string
}

// parseNuGet reads `Major[.Minor[.Patch[.Revision]]][-pre][+build]`.
// Missing trailing segments default to 0, matching NuGet's own
// normalisation ("1.2" and "1.2.0.0" are the same version). A leading
// `v` is tolerated for symmetry with parseSemver. Returns an error when
// any present segment is not a plain integer, so the caller's
// undecidable branch fires rather than a wrong verdict.
func parseNuGet(v string) (nugetVersion, error) {
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return nugetVersion{}, fmt.Errorf("osv: empty nuget version")
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var out nugetVersion
	if i := strings.IndexByte(s, '-'); i >= 0 {
		out.pre = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return nugetVersion{}, fmt.Errorf("osv: nuget version %q has more than 4 segments", v)
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 64)
		if err != nil {
			return nugetVersion{}, fmt.Errorf("osv: nuget version %q segment %q: %w", v, p, err)
		}
		out.nums[i] = n
	}
	return out, nil
}

// compare returns -1/0/+1. Numeric segments first (all four, in order),
// then the pre-release rule: a version WITHOUT a pre-release label
// outranks the same numeric version WITH one.
func (a nugetVersion) compare(b nugetVersion) int {
	for i := range a.nums {
		switch {
		case a.nums[i] < b.nums[i]:
			return -1
		case a.nums[i] > b.nums[i]:
			return 1
		}
	}
	return compareNuGetPrerelease(a.pre, b.pre)
}

// compareNuGetPrerelease orders two pre-release labels. NuGet compares
// them as dot-separated identifiers, case-INsensitively (unlike SemVer),
// with all-numeric identifiers ordering below alphanumeric ones and a
// shorter prefix ordering below a longer one. An empty label means "this
// is the release", which sorts above every pre-release.
func compareNuGetPrerelease(a, b string) int {
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return 1
	case b == "":
		return -1
	}
	as := strings.Split(strings.ToLower(a), ".")
	bs := strings.Split(strings.ToLower(b), ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aErr := strconv.ParseUint(as[i], 10, 64)
		bn, bErr := strconv.ParseUint(bs[i], 10, 64)
		switch {
		case aErr == nil && bErr == nil:
			if an != bn {
				if an < bn {
					return -1
				}
				return 1
			}
		case aErr == nil:
			return -1 // numeric identifier < alphanumeric identifier
		case bErr == nil:
			return 1
		default:
			if c := strings.Compare(as[i], bs[i]); c != 0 {
				return c
			}
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}
