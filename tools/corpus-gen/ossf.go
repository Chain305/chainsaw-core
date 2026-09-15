package main

// OpenSSF malicious-packages ingestion.
//
// This is the only ground truth in the corpus that asserts MALICE, and it is
// pinned by git commit so its half of the corpus re-derives exactly. deps.dev
// and OSV cannot be pinned that way; see main.go.
//
// ─── THREE PROPERTIES OF THIS FEED THAT SHAPE THE STRATA ────────────────────
//
// 1. IT IS ~93% npm. Measured on the pinned tree: npm 221,244 records, pypi
//    11,719, rubygems 3,627, nuget 779, crates.io 19, go 18, maven 2,
//    packagist 1. The malicious strata therefore CANNOT be ecosystem-balanced
//    the way the benign ones are — there is no ground truth to balance with.
//    Quotas fall back to min(equal share, available) and the shortfall is
//    reported in statistics.json rather than padded. Any malware-recall
//    number computed against public ground truth is an npm number wearing a
//    cross-ecosystem headline, whoever computes it. That is a fact about the
//    threat feed, not about the sampler, and it belongs in the write-up.
//
// 2. ~41% OF RECORDS PIN NO VERSION. `introduced: "0"` with no `fixed` means
//    the advisory covers every version, so there is no coordinate to scan.
//    Pinning rates differ enormously by ecosystem — rubygems and nuget are
//    100%, pypi is ~45%, npm is ~10%. Unpinned records are excluded from M1
//    with a reason, never silently dropped, because dropping the hardest rows
//    quietly shrinks the denominator.
//
// 3. WITHDRAWN RECORDS LIVE IN A SIBLING DIRECTORY. osv/withdrawn/ holds 356
//    of them. They are not read at all: a withdrawn advisory is a retraction,
//    and grading a vendor for failing to flag a coordinate the feed itself
//    took back would measure our own carelessness.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ossfEcosystem maps the feed's directory names to our tokens. Entries absent
// from this map (git, vscode, vscode:open-vsx.org) are ecosystems the
// benchmark does not cover and are skipped with a counted reason.
var ossfEcosystem = map[string]string{
	"npm": "npm", "pypi": "pypi", "rubygems": "rubygems", "nuget": "nuget",
	"crates.io": "cargo", "go": "go", "maven": "maven", "packagist": "composer",
}

// identityKeywords derive T1 (identity-attack) classification from the
// advisory's own prose.
//
// TEXT DERIVATION IS WHY T1 ROWS CARRY CONFIDENCE C, NOT A. OSSF has no
// structured attack-type field, so this reads summary+details for the words
// the advisory authors actually use. It is good enough to SELECT a stratum
// and not good enough to assert a mechanism, and the ground-truth file says
// so per row. Anyone quoting T1 as "100 confirmed typosquats" is quoting it
// wrong.
var identityKeywords = map[string]string{
	"typosquat":            "typosquat",
	"typo-squat":           "typosquat",
	"squatting":            "typosquat",
	"dependency confusion": "dependency_confusion",
	"manifest confusion":   "manifest_confusion",
	"impersonat":           "impersonation",
}

// MaliciousRecord is one OSSF advisory, distilled.
type MaliciousRecord struct {
	ID             string
	Eco            string
	Name           string
	Versions       []string // explicit; empty means the advisory covers all versions
	Published      time.Time
	Sources        []string
	Classification []string
	File           string
}

// BehavioralSource marks a record whose origin is OpenSSF's own dynamic
// Package Analysis run rather than a static or vendor report. M3 is drawn
// from these because they are the subset where a BEHAVIOUR was observed
// executing, not merely a pattern matched.
const BehavioralSource = "ossf-package-analysis"

func (r MaliciousRecord) IsBehavioral() bool {
	for _, s := range r.Sources {
		if s == BehavioralSource {
			return true
		}
	}
	return false
}

// loadOSSF walks the pinned clone and returns every usable malicious record
// plus the commit it came from. The commit is what makes this half of the
// corpus reproducible, so a dirty or commit-less tree is a hard refusal
// rather than a warning.
func loadOSSF(dir string) ([]MaliciousRecord, string, map[string]int, error) {
	commit, err := gitCommit(dir)
	if err != nil {
		return nil, "", nil, fmt.Errorf("ossf clone: %w (a corpus built from an unpinned feed is not reproducible)", err)
	}
	root := filepath.Join(dir, "osv", "malicious")
	if _, err := os.Stat(root); err != nil {
		return nil, "", nil, fmt.Errorf("ossf clone: %s not found; is --ossf pointing at a clone of ossf/malicious-packages?", root)
	}
	skipped := map[string]int{}
	var out []MaliciousRecord
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		ecoDir := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
		eco, ok := ossfEcosystem[ecoDir]
		if !ok {
			skipped["ecosystem_not_covered:"+ecoDir]++
			return nil
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			skipped["read_error"]++
			return nil
		}
		var doc struct {
			ID        string `json:"id"`
			Summary   string `json:"summary"`
			Details   string `json:"details"`
			Published string `json:"published"`
			Withdrawn string `json:"withdrawn"`
			Affected  []struct {
				Package struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				} `json:"package"`
				Versions []string `json:"versions"`
				Ranges   []struct {
					Events []struct {
						Introduced string `json:"introduced"`
						Fixed      string `json:"fixed"`
					} `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
			DatabaseSpecific struct {
				Origins []struct {
					Source string `json:"source"`
				} `json:"malicious-packages-origins"`
			} `json:"database_specific"`
		}
		if json.Unmarshal(raw, &doc) != nil {
			skipped["parse_error"]++
			return nil
		}
		if doc.Withdrawn != "" {
			skipped["withdrawn"]++
			return nil
		}
		if len(doc.Affected) == 0 {
			skipped["no_affected"]++
			return nil
		}
		a := doc.Affected[0]
		if a.Package.Name == "" {
			skipped["no_package_name"]++
			return nil
		}
		rec := MaliciousRecord{ID: doc.ID, Eco: eco, Name: a.Package.Name, File: rel}
		if t, err := time.Parse(time.RFC3339, doc.Published); err == nil {
			rec.Published = t
		}
		seen := map[string]bool{}
		for _, v := range a.Versions {
			if v != "" && !seen[v] {
				seen[v] = true
				rec.Versions = append(rec.Versions, v)
			}
		}
		for _, rg := range a.Ranges {
			for _, e := range rg.Events {
				// "0" is the sentinel for "from the beginning", i.e.
				// every version. It is not a version.
				if e.Introduced != "" && e.Introduced != "0" && !seen[e.Introduced] {
					seen[e.Introduced] = true
					rec.Versions = append(rec.Versions, e.Introduced)
				}
			}
		}
		sort.Strings(rec.Versions)
		for _, o := range doc.DatabaseSpecific.Origins {
			if o.Source != "" {
				rec.Sources = append(rec.Sources, o.Source)
			}
		}
		sort.Strings(rec.Sources)
		txt := strings.ToLower(doc.Summary + " " + doc.Details)
		cls := map[string]bool{}
		for kw, class := range identityKeywords {
			if strings.Contains(txt, kw) {
				cls[class] = true
			}
		}
		for k := range cls {
			rec.Classification = append(rec.Classification, k)
		}
		sort.Strings(rec.Classification)
		out = append(out, rec)
		return nil
	})
	if err != nil {
		return nil, "", nil, err
	}
	if len(out) == 0 {
		return nil, "", nil, fmt.Errorf("ossf clone yielded zero usable records")
	}
	// Deterministic order before anything samples it — WalkDir's order is
	// filesystem-dependent and differs between machines.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Eco != out[j].Eco {
			return out[i].Eco < out[j].Eco
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out, commit, skipped, nil
}

func gitCommit(dir string) (string, error) {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse: %w", err)
	}
	c := strings.TrimSpace(string(out))
	if len(c) != 40 {
		return "", fmt.Errorf("git rev-parse returned %q, not a commit", c)
	}
	return c, nil
}
