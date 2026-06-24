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
	if i == nil {
		return nil
	}
	key := canonicalKey(ecosystem, pkg)
	if key == "" {
		return nil
	}
	candidates, ok := i.byPackage[key]
	if !ok {
		return nil
	}
	var hits []Advisory
	for _, a := range candidates {
		if advisoryAffects(a, version) {
			hits = append(hits, a)
		}
	}
	return hits
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
	v := strings.TrimSpace(version)
	if v == "" {
		return false
	}
	// Exact version list match — preferred when present.
	for _, w := range a.VulnerableVersions {
		if strings.TrimSpace(w) == v {
			return true
		}
	}
	// Range match — handles the GHSA-style affected.ranges[] case.
	if len(a.VulnerableRanges) > 0 {
		for _, r := range a.VulnerableRanges {
			if rangeAffects(a.Ecosystem, r, v) {
				return true
			}
		}
	}
	return false
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

// rangeAffects reports whether the query version falls inside one
// VulnerableRange under the appropriate version-compare semantics for
// the given ecosystem. Each ecosystem has its own pre-release /
// qualifier rules (PyPI uses PEP 440, Maven uses qualifier ordering,
// RubyGems uses Gem::Version, etc.) — getting this wrong leads to
// either false-positive over-matches or false-negative misses on
// pre-release versions. compareVersions dispatches to the right
// library; on parse failure we fall back to exact-string equality
// against the range anchors so a malformed query doesn't over-match.
func rangeAffects(ecosystem string, r VulnerableRange, queryRaw string) bool {
	// Fully-zero range is the "applies to every published version"
	// sentinel used when OSV upstream emits an empty affected block
	// AND no fix is known. Distinct from "no range info at all" —
	// see advisoryAffects' return-false default.
	if r.Introduced == "" && r.Fixed == "" && r.LastAffected == "" {
		return true
	}
	// Cheap exact-match path: query string equals a range anchor
	// literally. Resilient to ecosystems whose parsers reject the
	// version (e.g. Maven "1.0-SNAPSHOT" vs "1.0.SNAPSHOT").
	if r.LastAffected != "" && r.LastAffected == queryRaw {
		return true
	}
	if r.Introduced == queryRaw {
		return true
	}
	if r.Fixed == queryRaw {
		return false // "fixed" is exclusive — query == fix → not affected
	}
	// introduced bound (default "0" / open lower)
	if intro := strings.TrimSpace(r.Introduced); intro != "" && intro != "0" {
		cmp, err := compareVersions(ecosystem, queryRaw, intro)
		if err != nil {
			return false
		}
		if cmp < 0 {
			return false
		}
	}
	// fixed bound (exclusive)
	if fix := strings.TrimSpace(r.Fixed); fix != "" {
		cmp, err := compareVersions(ecosystem, queryRaw, fix)
		if err != nil {
			return false
		}
		if cmp >= 0 {
			return false
		}
	}
	// last_affected bound (inclusive)
	if la := strings.TrimSpace(r.LastAffected); la != "" {
		cmp, err := compareVersions(ecosystem, queryRaw, la)
		if err != nil {
			return false
		}
		if cmp > 0 {
			return false
		}
	}
	return true
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
//	npm, yarn, bun, cargo, nuget, default → SemVer 2.0 via Masterminds.
//	                A leading `v` and trailing 4th dot-segment are
//	                normalised away — both shapes show up in registry
//	                version strings.
func compareVersions(ecosystem, a, b string) (int, error) {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	switch CanonicalEcosystem(ecosystem) {
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
		// npm / yarn / bun / cargo / nuget / unknown → SemVer via
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
