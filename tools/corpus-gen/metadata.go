package main

// Coordinate resolution and ground-truth ingestion.
//
// Every fact a corpus row carries is resolved here from a neutral source, and
// every resolution writes an Evidence row so `validate` can re-check the
// selection offline without touching the network again.

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/url"
	"sort"
	"strings"
	"time"
)

// depsSystem maps our ecosystem token to deps.dev's. Composer is absent on
// purpose: deps.dev does not index Packagist (verified against a real
// coordinate, not assumed), so Composer resolves through packagistVersions.
var depsSystem = map[string]string{
	"npm": "npm", "pypi": "pypi", "maven": "maven", "cargo": "cargo",
	"nuget": "nuget", "rubygems": "rubygems", "go": "go",
}

// osvEcosystem maps our token to OSV's. These spellings are load-bearing —
// OSV silently returns zero vulnerabilities for an ecosystem name it does not
// recognise, which reads as "this package is clean" and would quietly
// mislabel every row in that ecosystem as presumed_benign.
var osvEcosystem = map[string]string{
	"npm": "npm", "pypi": "PyPI", "maven": "Maven", "cargo": "crates.io",
	"nuget": "NuGet", "rubygems": "RubyGems", "go": "Go", "composer": "Packagist",
}

// VersionInfo is everything the strata need about one exact coordinate.
type VersionInfo struct {
	Eco              string
	Name             string
	Version          string
	PublishedAt      time.Time
	Deprecated       bool
	DeprecatedReason string
	Licenses         []string
	AdvisoryIDs      []string
	SourceRepo       string
	Source           string // which upstream answered
}

func (v VersionInfo) Coord() Coord { return Coord{Eco: v.Eco, Name: v.Name, Version: v.Version} }

// Coord is one exact package coordinate.
type Coord struct {
	Eco     string
	Name    string
	Version string
}

func (c Coord) Key() string { return c.Eco + "\x00" + c.Name + "\x00" + c.Version }

// resolveVersion picks ONE version of name deterministically and returns its
// full metadata.
//
// IT DELIBERATELY DOES NOT PICK `latest`. A corpus of latest-versions measures
// a registry's current state and nothing else: it cannot contain a vulnerable
// version whose fix has shipped, it over-represents actively maintained
// packages, and it makes the corpus change under you between runs. The version
// is drawn from the package's full published history with a per-package
// sub-stream, so adding a package to the pool does not change which version
// every other package contributes.
func (c *client) resolveVersion(eco, name string, rng *rand.Rand) (*VersionInfo, error) {
	if eco == "composer" {
		return c.packagistVersion(name, rng)
	}
	sys, ok := depsSystem[eco]
	if !ok {
		return nil, fmt.Errorf("no version resolver for %q", eco)
	}
	u := "https://api.deps.dev/v3/systems/" + sys + "/packages/" + url.PathEscape(name)
	body, status, err := c.get(u, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		c.record(Evidence{Kind: "versions", Eco: eco, Name: name, Source: "api.deps.dev", Status: status})
		return nil, fmt.Errorf("deps.dev package %s/%s: HTTP %d", eco, name, status)
	}
	var doc struct {
		Versions []struct {
			VersionKey struct {
				Version string `json:"version"`
			} `json:"versionKey"`
			PublishedAt  string `json:"publishedAt"`
			IsDeprecated bool   `json:"isDeprecated"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if len(doc.Versions) == 0 {
		return nil, fmt.Errorf("deps.dev package %s/%s: no versions", eco, name)
	}
	vers := make([]string, 0, len(doc.Versions))
	for _, v := range doc.Versions {
		if v.VersionKey.Version != "" {
			vers = append(vers, v.VersionKey.Version)
		}
	}
	// Sort before sampling. deps.dev returns versions in its own order and
	// relying on it would make the corpus depend on an upstream
	// implementation detail nobody controls.
	sort.Strings(vers)
	if len(vers) == 0 {
		return nil, fmt.Errorf("deps.dev package %s/%s: no usable versions", eco, name)
	}
	pick := vers[rng.IntN(len(vers))]
	c.record(Evidence{Kind: "versions", Eco: eco, Name: name, Source: "api.deps.dev", Status: status,
		BodySHA256: sha256Hex(body), Summary: map[string]any{"versions": len(vers), "picked": pick}})
	return c.depsVersionDetail(eco, sys, name, pick)
}

// depsVersionDetail fetches ONE exact coordinate. This call is also the
// existence proof: a 200 here is what lets the row into the corpus, and the
// exclusion engine drops anything that does not return one.
func (c *client) depsVersionDetail(eco, sys, name, version string) (*VersionInfo, error) {
	u := "https://api.deps.dev/v3/systems/" + sys + "/packages/" + url.PathEscape(name) +
		"/versions/" + url.PathEscape(version)
	body, status, err := c.get(u, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		c.record(Evidence{Kind: "version", Eco: eco, Name: name, Version: version,
			Source: "api.deps.dev", Status: status})
		return nil, fmt.Errorf("deps.dev version %s/%s@%s: HTTP %d", eco, name, version, status)
	}
	var doc struct {
		PublishedAt      string   `json:"publishedAt"`
		IsDeprecated     bool     `json:"isDeprecated"`
		DeprecatedReason string   `json:"deprecatedReason"`
		Licenses         []string `json:"licenses"`
		AdvisoryKeys     []struct {
			ID string `json:"id"`
		} `json:"advisoryKeys"`
		Links []struct {
			Label string `json:"label"`
			URL   string `json:"url"`
		} `json:"links"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	info := &VersionInfo{
		Eco: eco, Name: name, Version: version,
		Deprecated: doc.IsDeprecated, DeprecatedReason: doc.DeprecatedReason,
		Licenses: doc.Licenses, Source: "api.deps.dev",
	}
	if t, err := time.Parse(time.RFC3339, doc.PublishedAt); err == nil {
		info.PublishedAt = t
	}
	for _, a := range doc.AdvisoryKeys {
		info.AdvisoryIDs = append(info.AdvisoryIDs, a.ID)
	}
	for _, l := range doc.Links {
		if l.Label == "SOURCE_REPO" {
			info.SourceRepo = l.URL
		}
	}
	c.record(Evidence{Kind: "version", Eco: eco, Name: name, Version: version,
		Source: "api.deps.dev", Status: status, BodySHA256: sha256Hex(body),
		Summary: map[string]any{
			"published": doc.PublishedAt, "deprecated": doc.IsDeprecated,
			"licenses": doc.Licenses, "advisories": len(doc.AdvisoryKeys),
		}})
	return info, nil
}

// packagistVersion is Composer's resolver. See sources.go for why Composer
// cannot use deps.dev.
func (c *client) packagistVersion(name string, rng *rand.Rand) (*VersionInfo, error) {
	u := "https://repo.packagist.org/p2/" + name + ".json"
	body, status, err := c.get(u, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		c.record(Evidence{Kind: "versions", Eco: "composer", Name: name, Source: "repo.packagist.org", Status: status})
		return nil, fmt.Errorf("packagist %s: HTTP %d", name, status)
	}
	var doc struct {
		Packages map[string][]struct {
			Version string   `json:"version"`
			Time    string   `json:"time"`
			License []string `json:"license"`
			Source  struct {
				URL string `json:"url"`
			} `json:"source"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	entries := doc.Packages[name]
	if len(entries) == 0 {
		return nil, fmt.Errorf("packagist %s: no versions", name)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Version < entries[j].Version })
	e := entries[rng.IntN(len(entries))]
	info := &VersionInfo{
		Eco: "composer", Name: name, Version: e.Version,
		Licenses: e.License, SourceRepo: e.Source.URL, Source: "repo.packagist.org",
	}
	if t, err := time.Parse(time.RFC3339, e.Time); err == nil {
		info.PublishedAt = t
	}
	c.record(Evidence{Kind: "version", Eco: "composer", Name: name, Version: e.Version,
		Source: "repo.packagist.org", Status: status, BodySHA256: sha256Hex(body),
		Summary: map[string]any{"versions": len(entries), "picked": e.Version, "licenses": e.License}})
	return info, nil
}

// verifyCoord proves ONE exact coordinate is published, for any ecosystem.
//
// This is the existence gate for the paired vulnerability stratum. A V2
// control naming a version the registry never published is worse than a
// missing row: it silently converts the pair into a single observation while
// still being counted as a pair.
func (c *client) verifyCoord(eco, name, version string) (*VersionInfo, error) {
	if eco == "composer" {
		return c.packagistCoord(name, version)
	}
	sys, ok := depsSystem[eco]
	if !ok {
		return nil, fmt.Errorf("no verifier for ecosystem %q", eco)
	}
	return c.depsVersionDetail(eco, sys, name, version)
}

// packagistCoord is verifyCoord's Composer arm; deps.dev does not index
// Packagist (see sources.go).
func (c *client) packagistCoord(name, version string) (*VersionInfo, error) {
	u := "https://repo.packagist.org/p2/" + name + ".json"
	body, status, err := c.get(u, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("packagist %s: HTTP %d", name, status)
	}
	var doc struct {
		Packages map[string][]struct {
			Version string   `json:"version"`
			Time    string   `json:"time"`
			License []string `json:"license"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	for _, e := range doc.Packages[name] {
		// Packagist tags carry a leading v on many packages while OSV
		// records the bare number; accept either spelling rather than
		// dropping half of Composer's pairs over a prefix.
		if e.Version == version || strings.TrimPrefix(e.Version, "v") == strings.TrimPrefix(version, "v") {
			info := &VersionInfo{Eco: "composer", Name: name, Version: e.Version,
				Licenses: e.License, Source: "repo.packagist.org"}
			if t, err := time.Parse(time.RFC3339, e.Time); err == nil {
				info.PublishedAt = t
			}
			return info, nil
		}
	}
	return nil, fmt.Errorf("packagist %s: version %s not published", name, version)
}

// ─── OSV ────────────────────────────────────────────────────────────────────

// osvBatchSize is how many coordinates go in one querybatch. OSV documents no
// rate limit today; that is not the same as there being none, so the batcher
// still backs off on 429 rather than assuming it will never see one.
const osvBatchSize = 500

// OSVResult is what OSV said about one coordinate. `Queried` distinguishes
// "OSV answered, no vulnerabilities" from "we never asked" — collapsing those
// two into a single false is how a fetch failure becomes a clean bill of
// health.
type OSVResult struct {
	Coord   Coord
	Queried bool
	VulnIDs []string
}

func (c *client) osvQueryBatch(coords []Coord) (map[string]OSVResult, error) {
	out := make(map[string]OSVResult, len(coords))
	for i := 0; i < len(coords); i += osvBatchSize {
		end := min(i+osvBatchSize, len(coords))
		chunk := coords[i:end]
		type q struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Version string `json:"version"`
		}
		payload := struct {
			Queries []q `json:"queries"`
		}{}
		for _, co := range chunk {
			var one q
			one.Package.Name = co.Name
			one.Package.Ecosystem = osvEcosystem[co.Eco]
			one.Version = co.Version
			payload.Queries = append(payload.Queries, one)
		}
		body, status, err := c.postJSON("https://api.osv.dev/v1/querybatch", payload)
		if err != nil || status != 200 {
			// Record the failure and move on; these coordinates stay
			// Queried:false and the exclusion engine drops them rather
			// than labelling them benign on our silence.
			c.record(Evidence{Kind: "osv", Source: "api.osv.dev", Status: status,
				Summary: map[string]any{"batch": len(chunk), "error": fmt.Sprint(err)}})
			continue
		}
		var doc struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		if json.Unmarshal(body, &doc) != nil || len(doc.Results) != len(chunk) {
			c.record(Evidence{Kind: "osv", Source: "api.osv.dev", Status: status,
				Summary: map[string]any{"batch": len(chunk), "error": "result count mismatch"}})
			continue
		}
		c.record(Evidence{Kind: "osv", Source: "api.osv.dev", Status: status,
			BodySHA256: sha256Hex(body), Summary: map[string]any{"batch": len(chunk)}})
		for j, co := range chunk {
			r := OSVResult{Coord: co, Queried: true}
			for _, v := range doc.Results[j].Vulns {
				r.VulnIDs = append(r.VulnIDs, v.ID)
			}
			sort.Strings(r.VulnIDs)
			out[co.Key()] = r
		}
	}
	return out, nil
}

// OSVVuln is the detail fetch, needed because querybatch returns ids only and
// the V2 control requires the FIXED version — which lives in the advisory's
// affected ranges, not in the query result.
type OSVVuln struct {
	ID        string
	Withdrawn bool
	// Fixed maps "eco\x00name" to the fixed versions the advisory names.
	Fixed map[string][]string
}

func (c *client) osvVuln(id string) (*OSVVuln, error) {
	u := "https://api.osv.dev/v1/vulns/" + url.PathEscape(id)
	body, status, err := c.get(u, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("osv vuln %s: HTTP %d", id, status)
	}
	var doc struct {
		Withdrawn string `json:"withdrawn"`
		Affected  []struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Ranges []struct {
				Type   string `json:"type"`
				Events []struct {
					Introduced string `json:"introduced"`
					Fixed      string `json:"fixed"`
				} `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	v := &OSVVuln{ID: id, Withdrawn: doc.Withdrawn != "", Fixed: map[string][]string{}}
	for _, a := range doc.Affected {
		eco := ""
		for k, o := range osvEcosystem {
			if o == a.Package.Ecosystem {
				eco = k
				break
			}
		}
		if eco == "" {
			continue
		}
		key := eco + "\x00" + a.Package.Name
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					v.Fixed[key] = append(v.Fixed[key], e.Fixed)
				}
			}
		}
	}
	c.record(Evidence{Kind: "osv_vuln", Source: "api.osv.dev", Status: status,
		BodySHA256: sha256Hex(body),
		Summary:    map[string]any{"id": id, "withdrawn": v.Withdrawn, "fixed_packages": len(v.Fixed)}})
	return v, nil
}

// ─── BEHAVIOURAL PROBES FOR THE HARD-BENIGN STRATUM ─────────────────────────
//
// B2 is the stratum that makes a false-positive number mean something. A
// benign package with no risky behaviour is a cheap negative: nothing should
// fire on it, and nothing does. The expensive negative is a LEGITIMATE package
// that genuinely runs install scripts, ships native code, or opens sockets —
// where a vendor's alert is correct as an observation and wrong as a verdict.
//
// This session found exactly that shape: npm/webpack@5.110.3 scored `warn` on
// nine zero-width characters in a minified bundle. Under a corpus with no B2
// stratum, that is an unexplained regression. Under one with B2, it is a row
// whose ground truth reads `malicious: presumed_false, behaviors:
// {hidden_unicode: true}` — and a vendor reporting the behaviour scores
// correct while a vendor reporting a VERDICT scores a false positive.
//
// The behaviour must therefore be OBJECTIVELY ESTABLISHED, never inferred from
// a vendor alert. npm's packument states install hooks and gyp usage
// directly; PyPI's JSON API states native code through wheel platform tags.
// Those two are implemented. The other six ecosystems expose no equivalent
// metadata fact, so B2 is deliberately not sampled there and reports a
// SHORTFALL — padding it with ordinary packages would silently turn the hard
// stratum back into the easy one.

// Behaviors is the objectively-established behaviour set for a B2 row.
type Behaviors map[string]bool

func (c *client) probeBehaviorsNPM(name, version string) (Behaviors, bool) {
	u := "https://registry.npmjs.org/" + strings.ReplaceAll(url.PathEscape(name), "%40", "@")
	body, status, err := c.get(u, nil)
	if err != nil || status != 200 {
		return nil, false
	}
	var doc struct {
		Versions map[string]struct {
			Scripts map[string]string `json:"scripts"`
			GypFile bool              `json:"gypfile"`
			Bin     json.RawMessage   `json:"bin"`
		} `json:"versions"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil, false
	}
	v, ok := doc.Versions[version]
	if !ok {
		return nil, false
	}
	b := Behaviors{}
	for _, hook := range []string{"preinstall", "install", "postinstall"} {
		if s := v.Scripts[hook]; strings.TrimSpace(s) != "" {
			b["install_script"] = true
			if strings.ContainsAny(s, "|&;`$") || strings.Contains(s, "curl") || strings.Contains(s, "wget") {
				b["shell_access"] = true
			}
		}
	}
	if v.GypFile {
		b["native_code"] = true
	}
	if len(v.Bin) > 0 && string(v.Bin) != "null" {
		b["ships_executable"] = true
	}
	c.record(Evidence{Kind: "behaviors", Eco: "npm", Name: name, Version: version,
		Source: "registry.npmjs.org", Status: status, BodySHA256: sha256Hex(body),
		Summary: b})
	return b, len(b) > 0
}

func (c *client) probeBehaviorsPyPI(name, version string) (Behaviors, bool) {
	u := "https://pypi.org/pypi/" + url.PathEscape(name) + "/" + url.PathEscape(version) + "/json"
	body, status, err := c.get(u, nil)
	if err != nil || status != 200 {
		return nil, false
	}
	var doc struct {
		URLs []struct {
			Filename    string `json:"filename"`
			PackageType string `json:"packagetype"`
		} `json:"urls"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil, false
	}
	b := Behaviors{}
	for _, f := range doc.URLs {
		// A wheel carrying a platform tag was built from compiled
		// sources: `manylinux`, `macosx`, `win_amd64`. A pure-Python
		// wheel is tagged `none-any` and means the opposite.
		if f.PackageType == "bdist_wheel" &&
			(strings.Contains(f.Filename, "manylinux") ||
				strings.Contains(f.Filename, "musllinux") ||
				strings.Contains(f.Filename, "macosx") ||
				strings.Contains(f.Filename, "win_amd64") ||
				strings.Contains(f.Filename, "win32")) {
			b["native_code"] = true
		}
		if f.PackageType == "sdist" {
			b["source_build"] = true
		}
	}
	c.record(Evidence{Kind: "behaviors", Eco: "pypi", Name: name, Version: version,
		Source: "pypi.org", Status: status, BodySHA256: sha256Hex(body), Summary: b})
	return b, b["native_code"]
}
