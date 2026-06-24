package typosquat

import (
	"context"
	"log/slog"
	"strings"
	"sync"
)

// DetectionResult captures the outcome of a typosquatting check.
type DetectionResult struct {
	// IsSuspected is true if the package name is a suspected typosquat.
	IsSuspected bool `json:"isSuspected"`
	// Confidence is "high", "medium", or "low".
	Confidence string `json:"confidence,omitempty"`
	// SimilarTo is the popular package it resembles.
	SimilarTo string `json:"similarTo,omitempty"`
	// Distance is the edit distance to the similar package.
	Distance int `json:"distance,omitempty"`
	// Method describes how the match was found (edit-distance, homoglyph, combosquat).
	Method string `json:"method,omitempty"`
}

// PopularPackage represents a well-known package in an ecosystem.
type PopularPackage struct {
	Name string
	Rank int
}

// ThresholdConfig controls the edit-distance cutoffs used during detection.
// Zero values fall back to the package defaults so that existing callers
// that don't set this struct keep their current behavior.
//
//   - VeryShortNameMaxDistance applies when len(normalized) <= VeryShortNameLenCutoff.
//   - ShortNameMaxDistance applies when len(normalized) <= ShortNameLenCutoff.
//   - LongNameMaxDistance applies when len(normalized) >  ShortNameLenCutoff.
//   - VeryShortNameLenCutoff is the boundary for "very short" names where
//     even a 2-edit typo is more likely a coincidence than an attack.
//   - ShortNameLenCutoff is the name-length boundary between "short" and
//     "long" names (inclusive on the short side).
//   - MaxRelativeDistance is the maximum allowed ratio of edit distance to
//     the longer of the two names. A pair like ("jose","jsr") sits at 50%
//     relative distance — too far apart to be a typo even though the
//     absolute distance fits the short-name bucket. Set to 0 to disable.
type ThresholdConfig struct {
	VeryShortNameMaxDistance int
	ShortNameMaxDistance     int
	LongNameMaxDistance      int
	VeryShortNameLenCutoff   int
	ShortNameLenCutoff       int
	MaxRelativeDistance      float64
}

// Default threshold values.
//
// History: short=2, long=3, boundary=10 was the original tuning. That fired
// false positives on names ≤4 chars where a 2-edit difference is 50% of the
// name (e.g. "jose" vs "jsr" — 4-char query, 3-char candidate, distance 2,
// fired sc.typosquat_medium incorrectly). The very-short tier (≤4 chars,
// max distance 1) and the relative-distance ceiling (40%) close that gap
// without weakening 5+ char detection.
const (
	defaultVeryShortNameMaxDistance = 1
	defaultShortNameMaxDistance     = 2
	defaultLongNameMaxDistance      = 3
	defaultVeryShortNameLenCutoff   = 4
	defaultShortNameLenCutoff       = 10
	defaultMaxRelativeDistance      = 0.4
)

// Detector checks package names for typosquatting against popular packages.
type Detector struct {
	mu         sync.RWMutex
	trees      map[string]*BKTree                 // ecosystem → BK-tree of normalized popular names
	lookup     map[string]map[string]string       // ecosystem → normalized → original popular name
	norms      map[string]Normalizer              // ecosystem → normalizer
	reorder    map[string]map[string]reorderEntry // ecosystem → reorder-canonical form → entry
	confusable map[string]map[string][]string     // ecosystem → confusable-normalized form → original popular names
	logger     *slog.Logger
	thresholds ThresholdConfig
}

// reorderEntry stores the popular package information keyed by its
// reorder-canonical form (sorted tokens joined by '-'). TokenCount lets the
// lookup reject matches where the query has a different number of tokens
// — which would be a strict superset / subset match, not a reorder.
type reorderEntry struct {
	normalized string
	original   string
	tokenCount int
}

// NewDetector creates a new typosquatting detector with default thresholds.
func NewDetector(logger *slog.Logger) *Detector {
	return NewDetectorWithConfig(logger, ThresholdConfig{})
}

// NewDetectorWithConfig creates a detector with custom thresholds. Any
// zero-valued field in cfg is replaced with the package default, preserving
// the behavior of NewDetector for callers that pass an empty struct.
func NewDetectorWithConfig(logger *slog.Logger, cfg ThresholdConfig) *Detector {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.VeryShortNameMaxDistance == 0 {
		cfg.VeryShortNameMaxDistance = defaultVeryShortNameMaxDistance
	}
	if cfg.ShortNameMaxDistance == 0 {
		cfg.ShortNameMaxDistance = defaultShortNameMaxDistance
	}
	if cfg.LongNameMaxDistance == 0 {
		cfg.LongNameMaxDistance = defaultLongNameMaxDistance
	}
	if cfg.VeryShortNameLenCutoff == 0 {
		cfg.VeryShortNameLenCutoff = defaultVeryShortNameLenCutoff
	}
	if cfg.ShortNameLenCutoff == 0 {
		cfg.ShortNameLenCutoff = defaultShortNameLenCutoff
	}
	if cfg.MaxRelativeDistance == 0 {
		cfg.MaxRelativeDistance = defaultMaxRelativeDistance
	}
	return &Detector{
		trees:      make(map[string]*BKTree),
		lookup:     make(map[string]map[string]string),
		norms:      make(map[string]Normalizer),
		reorder:    make(map[string]map[string]reorderEntry),
		confusable: make(map[string]map[string][]string),
		logger:     logger,
		thresholds: cfg,
	}
}

// LoadEcosystem loads popular packages for an ecosystem into the detection index.
// Safe for concurrent use; replaces the previous index for this ecosystem.
func (d *Detector) LoadEcosystem(ecosystem string, packages []PopularPackage) {
	ecosystem = strings.ToLower(ecosystem)
	norm := NormalizerForFormat(ecosystem)

	tree := NewBKTree()
	names := make(map[string]string, len(packages))
	reorderIdx := make(map[string]reorderEntry, len(packages))
	confusableIdx := make(map[string][]string, len(packages))

	for _, pkg := range packages {
		normalized := norm(pkg.Name)
		if normalized == "" {
			continue
		}
		tree.Insert(normalized)
		names[normalized] = pkg.Name

		// Pre-compute the confusable-normalized form once so the
		// per-check homoglyph branch is an O(1) map lookup. Multiple
		// popular names can share a key (e.g. `foo` and `Foo`
		// normalize identically); the slice preserves all of them
		// so the detector can pick the right SimilarTo.
		if cnorm := Normalize(pkg.Name); cnorm != "" {
			confusableIdx[cnorm] = append(confusableIdx[cnorm], pkg.Name)
		}

		// Index the reorder-canonical form for multi-token popular names.
		// Single-token names are skipped: a reorder hit against a one-token
		// name is not a reorder at all, it's an exact match, which the
		// popular-check branch already handles.
		if canonical, count := ReorderTokens(normalized); count >= 2 {
			// First writer wins — popular packages arrive in rank order,
			// so the highest-rank name owns the canonical key. Lower-rank
			// collisions (unlikely but possible for two popular packages
			// with the same token set) are discarded.
			if _, ok := reorderIdx[canonical]; !ok {
				reorderIdx[canonical] = reorderEntry{
					normalized: normalized,
					original:   pkg.Name,
					tokenCount: count,
				}
			}
		}
	}

	d.mu.Lock()
	d.trees[ecosystem] = tree
	d.lookup[ecosystem] = names
	d.norms[ecosystem] = norm
	d.reorder[ecosystem] = reorderIdx
	d.confusable[ecosystem] = confusableIdx
	d.mu.Unlock()

	d.logger.Info("loaded popular packages for typosquat detection",
		"ecosystem", ecosystem, "count", tree.Size())
}

// Check analyzes a package name for potential typosquatting.
// Returns a zero-value result (IsSuspected=false) if no issue is found.
func (d *Detector) Check(_ context.Context, ecosystem, packageName string) DetectionResult {
	ecosystem = strings.ToLower(ecosystem)

	d.mu.RLock()
	tree, ok := d.trees[ecosystem]
	names := d.lookup[ecosystem]
	norm := d.norms[ecosystem]
	reorderIdx := d.reorder[ecosystem]
	confusableIdx := d.confusable[ecosystem]
	d.mu.RUnlock()

	if !ok || tree == nil || tree.Size() == 0 {
		return DetectionResult{} // no index loaded, skip
	}

	normalized := norm(packageName)
	if normalized == "" {
		return DetectionResult{}
	}

	// Exact match with popular package → not a typosquat.
	if _, isPopular := names[normalized]; isPopular {
		return DetectionResult{}
	}

	// Step 0: Unicode homoglyph collision check. Runs before edit
	// distance because a Cyrillic-vs-Latin attack (e.g. `еxpress`
	// with U+0435 vs popular `express`) ALSO fires under edit
	// distance with d=1, and the homoglyph label is more accurate
	// and higher confidence. Lookup is O(1) on the pre-normalized
	// popular index built at LoadEcosystem time. We deliberately
	// confusable-normalize the *raw* package name (not the
	// ecosystem-normalized form) so we can compare against the
	// raw popular name and detect the byte-level difference that
	// distinguishes a homoglyph from an exact match.
	if len(confusableIdx) > 0 {
		cnorm := Normalize(packageName)
		if cnorm != "" {
			if popularNames, hit := confusableIdx[cnorm]; hit {
				for _, popular := range popularNames {
					if popular != packageName {
						return DetectionResult{
							IsSuspected: true,
							Confidence:  "high",
							SimilarTo:   popular,
							Distance:    1,
							Method:      "homoglyph",
						}
					}
				}
			}
		}
	}

	// Step 1: Edit distance check via BK-tree.
	//
	// Tiered threshold:
	//   - very-short (≤4 chars): max distance 1. A 2-edit miss on a 3-4
	//     char name is a coincidence, not an attack — `jose` vs `jsr` is
	//     50% of the name and was the symptom that motivated this tier.
	//   - short (5-10 chars): max distance 2.
	//   - long (>10 chars): max distance 3.
	threshold := d.thresholds.ShortNameMaxDistance
	switch {
	case len(normalized) <= d.thresholds.VeryShortNameLenCutoff:
		threshold = d.thresholds.VeryShortNameMaxDistance
	case len(normalized) > d.thresholds.ShortNameLenCutoff:
		threshold = d.thresholds.LongNameMaxDistance
	}

	matches := tree.Search(normalized, threshold)
	if len(matches) > 0 {
		best := matches[0]
		for _, m := range matches[1:] {
			if m.Distance < best.Distance {
				best = m
			}
		}

		// Relative-distance guard: even when the absolute distance fits
		// the bucket, reject matches whose distance exceeds a fraction
		// of the longer name. This catches the short-name corner where
		// the absolute threshold permits an edit count that's an
		// implausibly large share of either name (e.g. distance 2
		// between a 4-char query and a 3-char candidate is 50% — well
		// above the 40% ceiling, so no match). When the relative guard
		// rejects, we deliberately do NOT try the next-best BK-tree
		// candidate — if the closest match is too far to be a typo, a
		// farther one is too — and we fall through to the reorder /
		// homoglyph / combosquat branches below.
		ok := true
		if d.thresholds.MaxRelativeDistance > 0 {
			longer := len(normalized)
			if len(best.Word) > longer {
				longer = len(best.Word)
			}
			if longer > 0 {
				rel := float64(best.Distance) / float64(longer)
				if rel > d.thresholds.MaxRelativeDistance {
					ok = false
				}
			}
		}

		if ok {
			confidence := "medium"
			if best.Distance == 1 {
				confidence = "high"
			}
			originalName := names[best.Word]
			if originalName == "" {
				originalName = best.Word
			}
			return DetectionResult{
				IsSuspected: true,
				Confidence:  confidence,
				SimilarTo:   originalName,
				Distance:    best.Distance,
				Method:      "edit-distance",
			}
		}
	}

	// Step 1.5: Word-reorder match. Splits the query on '-'/'_'/'.' and
	// looks up the lexicographically-sorted token set against the reorder
	// index built at LoadEcosystem time. Catches "module-library" when
	// "library-module" is popular — a common naming trick that slips past
	// pure edit distance because the character set is identical.
	//
	// Rules:
	//   - Token count must match: `mo_du_le` (3 tokens) does not match
	//     `module` (1 token), and `foo-bar` (2 tokens) does not match
	//     `foo-bar-baz` (3 tokens).
	//   - Single-token queries (no delimiter) skip this branch — a single
	//     token against a single token is just equality, which the
	//     popular-match check above already covered.
	//   - Confidence is `medium` by default; if the matched popular name
	//     is additionally within edit distance 1, we promote to `high`
	//     since the attacker combined a reorder with a tight typo.
	if len(reorderIdx) > 0 {
		if canonical, count := ReorderTokens(normalized); count >= 2 {
			if entry, ok := reorderIdx[canonical]; ok && entry.tokenCount == count && entry.normalized != normalized {
				confidence := "medium"
				dist := DamerauLevenshtein(normalized, entry.normalized)
				if dist <= 1 {
					confidence = "high"
				}
				return DetectionResult{
					IsSuspected: true,
					Confidence:  confidence,
					SimilarTo:   entry.original,
					Distance:    dist,
					Method:      "reorder",
				}
			}
		}
	}

	// Step 2: Homoglyph expansion.
	variants := ExpandHomoglyphs(normalized)
	for _, variant := range variants {
		if original, ok := names[variant]; ok {
			return DetectionResult{
				IsSuspected: true,
				Confidence:  "high",
				SimilarTo:   original,
				Distance:    1,
				Method:      "homoglyph",
			}
		}
	}

	// Step 3: Combosquat check — package name contains a popular name as substring.
	if result := d.checkCombosquat(ecosystem, normalized, names); result.IsSuspected {
		return result
	}

	return DetectionResult{}
}

// checkCombosquat detects packages that embed a popular name with only a
// prefix or suffix added (e.g., "lodash-utils" when "lodash" is popular).
// Only checks popular names of length >= minPopularLen to avoid false positives
// from very short popular names matching many strings.
func (d *Detector) checkCombosquat(ecosystem, normalized string, names map[string]string) DetectionResult {
	if len(normalized) < 4 {
		return DetectionResult{}
	}

	// Only check popular names that could fit inside the query with extra <= 8.
	minPopularLen := len(normalized) - 8
	if minPopularLen < 3 {
		minPopularLen = 3
	}

	var bestResult DetectionResult
	bestExtra := 999

	for popularNorm, popularOrig := range names {
		if len(popularNorm) < minPopularLen {
			continue
		}
		if len(normalized) <= len(popularNorm) {
			continue
		}
		extra := len(normalized) - len(popularNorm)
		if extra > 8 || extra >= bestExtra {
			continue // skip if more extra chars than best found so far
		}
		if strings.Contains(normalized, popularNorm) {
			bestResult = DetectionResult{
				IsSuspected: true,
				Confidence:  "low",
				SimilarTo:   popularOrig,
				Distance:    extra,
				Method:      "combosquat",
			}
			bestExtra = extra
		}
	}

	return bestResult
}

// HasIndex returns true if the detector has a loaded index for the ecosystem.
func (d *Detector) HasIndex(ecosystem string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	tree, ok := d.trees[strings.ToLower(ecosystem)]
	return ok && tree != nil && tree.Size() > 0
}

// EcosystemsWithTyposquatRisk returns ecosystems where typosquatting
// detection should be enabled by default.
//
// Go and Cocoapods were added in PR 4 (plan §"PR 4 — Typosquat detector
// strengthening"). Go modules use their full import path as identity
// (NormalizeGo preserves the prefix), and Cocoapods pods use their spec
// name lowercased — both ecosystems now have popular-list fetchers in
// internal/supplychain/bootstrap.go (seeded lists with future deps.dev /
// cocoapods-trunk integration).
func EcosystemsWithTyposquatRisk() []string {
	return []string{
		"npm", "pip", "cargo", "composer", "rubygems",
		"nuget", "docker", "huggingface", "maven", "gradle", "swift",
		"go", "cocoapods",
		// pub (Dart/Flutter) — flat snake_case names, seeded popular-list
		// fetcher in fetcher.go (pubTopSeed); added in Dart Phase 2.
		"pub",
		// github_actions ecosystem
		"github_actions",
		// github_actions ecosystem
	}
}

// IsLowRiskEcosystem returns true for ecosystems with curated repositories
// where typosquatting is unlikely (APT, DNF/Yum).
func IsLowRiskEcosystem(ecosystem string) bool {
	switch strings.ToLower(ecosystem) {
	case "apt", "dnf", "yum":
		return true
	default:
		return false
	}
}
