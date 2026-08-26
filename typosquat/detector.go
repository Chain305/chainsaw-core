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
	// TargetRank is the popularity rank of SimilarTo within the loaded
	// corpus (1 = most popular), or 0 when unknown. Additive/omitempty so
	// existing JSON consumers are unaffected. Callers use it to weight
	// verdicts: a d=1 neighbour of a top-ranked target is the classic
	// squat shape; a d=1 neighbour of a tail-rank target usually isn't.
	TargetRank int `json:"targetRank,omitempty"`
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
	ranks      map[string]map[string]int          // ecosystem → normalized → popularity rank (1 = top)
	norms      map[string]Normalizer              // ecosystem → normalizer
	reorder    map[string]map[string]reorderEntry // ecosystem → reorder-canonical form → entry
	confusable map[string]map[string][]string     // ecosystem → confusable-normalized form → original popular names
	siblings   map[string]map[string]struct{}     // ecosystem → normalized name → verified first-party sibling of a popular root
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
		ranks:      make(map[string]map[string]int),
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
	rankIdx := make(map[string]int, len(packages))
	reorderIdx := make(map[string]reorderEntry, len(packages))
	confusableIdx := make(map[string][]string, len(packages))

	for i, pkg := range packages {
		normalized := norm(pkg.Name)
		if normalized == "" {
			continue
		}
		tree.Insert(normalized)
		names[normalized] = pkg.Name

		// Popular packages arrive in rank order, so slice position backfills
		// a missing Rank — every loaded name gets one, and callers can rely
		// on TargetRank > 0 whenever SimilarTo is set from this index.
		rank := pkg.Rank
		if rank == 0 {
			rank = i + 1
		}
		if prev, ok := rankIdx[normalized]; !ok || rank < prev {
			rankIdx[normalized] = rank
		}

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
	d.ranks[ecosystem] = rankIdx
	d.norms[ecosystem] = norm
	d.reorder[ecosystem] = reorderIdx
	d.confusable[ecosystem] = confusableIdx
	d.mu.Unlock()

	d.logger.Info("loaded popular packages for typosquat detection",
		"ecosystem", ecosystem, "count", tree.Size())
}

// Check analyzes a package name for potential typosquatting.
// Returns a zero-value result (IsSuspected=false) if no issue is found.
func (d *Detector) Check(ctx context.Context, ecosystem, packageName string) DetectionResult {
	res := d.check(ctx, ecosystem, packageName)
	if res.IsSuspected && res.Confidence != "low" {
		switch {
		case sameOwnerSibling(ecosystem, packageName, res.SimilarTo):
			// DEMOTE, never silence. The similarity is real and still worth
			// showing — `actions/chekout` IS one edit from `actions/checkout`
			// and a reader should see that. What it is not is a reason to
			// QUARANTINE, because the two names have the same publisher.
			//
			// Clearing outright was the first implementation and it deleted an
			// existing contract: TestDetectorGitHubActions asserts
			// IsSuspected+SimilarTo (not confidence) for exactly that pair.
			// Demotion keeps the finding, keeps that test byte-identical, and
			// moves the verdict from sc.typosquat_high (SevCritical, -40,
			// blocking) to sc.typosquat_low (SevLow, -8, advisory).
			res.Confidence = "low"
		case moreEstablishedThanTarget(ecosystem, packageName, res.SimilarTo):
			// Same shape, same reason, different structural fact: the
			// direction of the impersonation claim. A typosquat is a LESS
			// established package wearing the face of a MORE established one,
			// and `ms` is not squatting `msw`. Demoted rather than cleared for
			// the same reason as above — the two names really are one edit
			// apart and a reader should see it — and keyed on a reviewed
			// download ranking an attacker cannot buy into.
			//
			// Read established.go before touching this: in particular why
			// corpus rank cannot answer the question, why a target-rank cutoff
			// was rejected, and why this branch is unreachable on the install
			// guard's path and so cannot move its published FP/recall numbers.
			res.Confidence = "low"
		}
	}
	return res
}

// ownerScopeSeparator returns the byte that separates the owner scope from
// the package name, for ecosystems where the scope is an ACCOUNT BOUNDARY
// enforced by a single host — i.e. where an attacker provably cannot publish
// under the victim's scope.
//
//	github_actions  owner/name   a GitHub org or user; `actions/checkout` and
//	                             `attacker/checkout` are different accounts
//	swift           scope.name   SE-0292 identifier; for a git-hosted package
//	                             the scope is the GitHub owner
//
// DELIBERATELY NOT LISTED, even though the shape fits: npm `@scope/name`,
// Composer `vendor/package`, Maven `groupId:artifactId`, HuggingFace
// `org/model`, Docker `org/name`. The argument applies to those too, but
// their corpora have been firing in production for a long time and their
// false-positive and recall numbers are published against the current
// behaviour (core/cli/guard_typosquat_fp_eval_test.go,
// guard_typosquat_recall_eval_test.go). Extending this exemption to them is
// a separate change that has to re-measure both halves of that trade. The
// two ecosystems here had a permanently empty index and had never produced
// a verdict, so there is no baseline to move.
func ownerScopeSeparator(ecosystem string) (byte, bool) {
	switch strings.ToLower(ecosystem) {
	case "github_actions":
		return '/', true
	case "swift":
		return '.', true
	default:
		return 0, false
	}
}

// sameOwnerSibling reports whether a candidate and the popular name it
// matched are published under the SAME owner scope. Callers DEMOTE such a
// hit to "low" — they do not silence it. See Check.
//
// WHY THIS IS NOT A HOLE. Typosquatting is impersonation of a publisher the
// victim did not mean to install from. When the scope is byte-identical
// there is no second publisher: `reviewdog/action-eclint` and
// `reviewdog/action-eslint` are both reviewdog's, `grpc.grpc-swift-2` and
// `grpc.grpc-swift` are both grpc's. An attacker who already controls the
// scope does not need a lookalike name — they would ship the backdoor in the
// real package. So the demotion cannot cost recall on any attack the
// detector is for.
//
// It is byte equality on the RAW scope, deliberately, so a homoglyph in the
// scope itself (`аpple.swift-nio` with a Cyrillic а) is NOT exempt — that is
// a different account wearing the same face, which is the attack.
//
// Measured effect on the held-out corpora: this is every high-confidence
// false positive both ecosystems produced (swift 2 of 2, github_actions
// 1 of 1). See TestHeldOutFalsePositiveRateByEcosystem.
func sameOwnerSibling(ecosystem, candidate, popular string) bool {
	sep, ok := ownerScopeSeparator(ecosystem)
	if !ok || candidate == "" || popular == "" {
		return false
	}
	cs, cok := ownerScopeOf(candidate, sep)
	ps, pok := ownerScopeOf(popular, sep)
	return cok && pok && cs == ps
}

// ownerScopeOf extracts the lowercased scope prefix ahead of sep. A version
// pin (`actions/checkout@v4`) is trimmed first so a workflow-shaped
// reference resolves to the same scope as a bare one. Returns ok=false when
// the name carries no scope at all, so an unscoped name never matches
// another unscoped name on an empty string.
func ownerScopeOf(name string, sep byte) (string, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if at := strings.IndexByte(name, '@'); at > 0 {
		name = name[:at]
	}
	i := strings.IndexByte(name, sep)
	if i <= 0 {
		return "", false
	}
	return name[:i], true
}

func (d *Detector) check(_ context.Context, ecosystem, packageName string) DetectionResult {
	ecosystem = strings.ToLower(ecosystem)

	d.mu.RLock()
	tree, ok := d.trees[ecosystem]
	names := d.lookup[ecosystem]
	ranks := d.ranks[ecosystem]
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
							TargetRank:  ranks[norm(popular)],
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
			if betterEditMatch(m, best, ranks) {
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
				TargetRank:  ranks[best.Word],
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
					TargetRank:  ranks[entry.normalized],
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
				TargetRank:  ranks[variant],
			}
		}
	}

	// Step 3: Combosquat check — package name contains a popular name as substring.
	if result := d.checkCombosquat(ecosystem, normalized, names, ranks); result.IsSuspected {
		return result
	}

	return DetectionResult{}
}

// betterEditMatch reports whether `cand` should replace `best` as the nearest
// popular name for a query.
//
// WHY A TOTAL ORDER. BKTree.Search walks `node.children`, a Go map, so its
// result slice arrives in a per-run randomized order. Selecting the nearest
// match with a bare `m.Distance < best.Distance` therefore resolves EQUIDISTANT
// targets by map-iteration order: `args` sits at distance 1 from both `yargs`
// (rank #70) and `arg` (rank #263) in the npm corpus, and Check used to return
// whichever one the map handed over first. That used to be cosmetic — only the
// target name in the reason string changed — but every consumer that keys a
// DECISION off SimilarTo/TargetRank (the install guard's block-lane gate, for
// one) inherits the coin flip and blocks a name on some runs and warns on
// others. Check must be a pure function of (corpus, query).
//
// The order is: nearest distance wins; then the more popular target (lower
// rank, i.e. the name an attacker would actually be squatting); then the
// lexicographically smaller name so an unranked corpus is still deterministic.
// Rank 0 means "not in the rank index" and sorts last, never first.
func betterEditMatch(cand, best SearchResult, ranks map[string]int) bool {
	if cand.Distance != best.Distance {
		return cand.Distance < best.Distance
	}
	cr, br := ranks[cand.Word], ranks[best.Word]
	if cr != br {
		if cr == 0 || br == 0 {
			return br == 0 // an unranked incumbent loses to any ranked candidate
		}
		return cr < br
	}
	return cand.Word < best.Word
}

// checkCombosquat detects packages that embed a popular name with only a
// prefix or suffix added (e.g., "lodash-utils" when "lodash" is popular).
// Only checks popular names of length >= minPopularLen to avoid false positives
// from very short popular names matching many strings.
//
// Every hit this produces is graded "low" (worth -8 in the risk registry)
// because the rule is deliberately broad: measured against a held-out corpus of
// 24,206 real download-ranked benign packages, 13.0% of them embed some popular
// name within 8 characters. That breadth is the point — it is a hint, not an
// accusation — and it is the caller's job to present it as one.
//
// Two guards keep the lane from firing on things nobody would call a squat:
//
//  1. TOKEN ALIGNMENT (below). The popular name must sit on at least one token
//     boundary. A popular name buried mid-token — "ent" inside "agent-base",
//     "ini" inside "unicorn-magic" — is a coincidence of spelling, not a squat:
//     nobody reaching for "ent" mistypes it into the middle of another word.
//     Every real combosquat shape survives: "expressjs" (root at index 0),
//     "python3-dateutil" (root at end), "@attacker/react" (root after the
//     scope separator, the case NormalizeNPM's comment depends on).
//
//  2. FIRST-PARTY SIBLINGS (official.go). An exact-name exemption for verified
//     first-party siblings such as `lodash.merge`. Read the header of
//     official.go before touching it — in particular why the exemption is NOT
//     keyed on name shape, corpus membership, or family size.
func (d *Detector) checkCombosquat(ecosystem, normalized string, names map[string]string, ranks map[string]int) DetectionResult {
	if len(normalized) < 4 {
		return DetectionResult{}
	}

	// Guard 2: verified first-party sibling of the name it embeds.
	if d.isOfficialSibling(ecosystem, normalized) {
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
		// Guard 1: token alignment. Replaces a bare strings.Contains.
		if tokenAlignedContains(normalized, popularNorm) {
			bestResult = DetectionResult{
				IsSuspected: true,
				Confidence:  "low",
				SimilarTo:   popularOrig,
				Distance:    extra,
				Method:      "combosquat",
				TargetRank:  ranks[popularNorm],
			}
			bestExtra = extra
		}
	}

	return bestResult
}

// tokenAlignedContains reports whether `root` occurs inside `name` with at
// least one of its edges on a token boundary — the start of the string, the
// end of the string, or adjacent to a delimiter.
//
// "At least one edge", not both: requiring both would drop `expressjs` and
// `reactjs`, which are the canonical combosquat shapes. Requiring neither is
// the status quo, which matches `ent` inside `agent-base`.
func tokenAlignedContains(name, root string) bool {
	if root == "" || len(root) > len(name) {
		return false
	}
	for i := 0; ; {
		j := strings.Index(name[i:], root)
		if j < 0 {
			return false
		}
		start := i + j
		end := start + len(root)
		startAligned := start == 0 || isNameDelimiter(name[start-1])
		endAligned := end == len(name) || isNameDelimiter(name[end])
		if startAligned || endAligned {
			return true
		}
		i = start + 1
		if i+len(root) > len(name) {
			return false
		}
	}
}

// isNameDelimiter reports whether b separates tokens in a package name across
// the ecosystems the detector covers: '-' and '_' (npm, PyPI, Cargo, pub),
// '.' (npm modular names, Maven groupIds, Go import paths), '/' and '@' (npm
// scopes, Go module paths, Composer vendor/package, HuggingFace org/model),
// and ':' (Maven/Gradle coordinates).
func isNameDelimiter(b byte) bool {
	switch b {
	case '-', '_', '.', '/', '@', ':':
		return true
	default:
		return false
	}
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
