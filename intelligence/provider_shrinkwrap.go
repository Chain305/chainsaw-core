package intelligence

// shrinkwrapProvider scans a package artifact for bundled lockfiles
// (npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock, bun.lockb,
// Pipfile.lock, poetry.lock, composer.lock, Cargo.lock, Gemfile.lock).
// Tier-2; zero new network cost — the archive is already decompressed
// once via SharedArtifactMap.
//
// Fires when ANY path in the map matches an ecosystem-appropriate
// lockfile name (case-insensitive, by basename). Nested lockfiles
// under bundled subpackages also count: bundled deps with their own
// pinned graphs are exactly the review-bypass pattern the signal
// targets.
//
// Two context filters reduce false positives:
//
//  1. Path-based: lockfiles living under test/example/docs/templates/
//     samples/fixtures directories are likely intentional artifacts of
//     the package, not a review-bypass attempt. See
//     codesmell.IsLikelyExampleOrDoc for the segment list. NOTE this
//     deliberately does NOT match node_modules/ or vendor/ — a lockfile
//     inside a bundled dep IS the review-bypass pattern.
//
//  2. Manifest-declared (npm/yarn/bun only): when the package's
//     package.json declares a non-empty bundledDependencies (or
//     bundleDependencies — both spellings are valid per
//     https://docs.npmjs.com/cli/v10/configuring-npm/package-json#bundleddependencies)
//     a lockfile at archive root is documented behavior; suppress.
//
// The signal STILL fires when at least one non-suppressed lockfile
// match is found.

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/chain305/chainsaw-core/codesmell"
)

// Warning codes emitted when shrinkwrap suppression engages.
const (
	WarnShrinkwrapPathSuppressed        = "shrinkwrap_path_suppressed"
	WarnShrinkwrapBundledDepsSuppressed = "shrinkwrap_bundled_deps_suppressed"
)

// ecosystemLockfiles maps a normalized ecosystem key to the set of
// lockfile basenames that, when found inside an artifact, indicate a
// bundled pinned dependency graph.
var ecosystemLockfiles = map[string][]string{
	"npm":      {"npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock"},
	"yarn":     {"npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock"},
	"bun":      {"npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock"},
	"pnpm":     {"npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock"},
	"pip":      {"Pipfile.lock", "poetry.lock"},
	"pypi":     {"Pipfile.lock", "poetry.lock"},
	"composer": {"composer.lock"},
	"cargo":    {"Cargo.lock"},
	"rubygems": {"Gemfile.lock"},
}

// npmFamily — ecosystems whose package.json may declare
// bundledDependencies and thus opt out of the shrinkwrap signal.
var npmFamily = map[string]struct{}{
	"npm":  {},
	"yarn": {},
	"bun":  {},
	"pnpm": {},
}

type shrinkwrapProvider struct{}

func newShrinkwrapProvider() *shrinkwrapProvider { return &shrinkwrapProvider{} }

func (p *shrinkwrapProvider) Name() string        { return "shrinkwrap" }
func (p *shrinkwrapProvider) Signal() SignalMask  { return SignalShrinkwrap }
func (p *shrinkwrapProvider) Tier() int           { return 2 }
func (p *shrinkwrapProvider) NeedsArtifact() bool { return true }
func (p *shrinkwrapProvider) Supports(eco string) bool {
	_, ok := ecosystemLockfiles[strings.ToLower(strings.TrimSpace(eco))]
	return ok
}

func (p *shrinkwrapProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if req.Artifact == nil || len(req.Artifact.Bytes) == 0 {
		return PartialReport{}, nil
	}
	eco := strings.ToLower(strings.TrimSpace(req.Key.Ecosystem))
	names, ok := ecosystemLockfiles[eco]
	if !ok || len(names) == 0 {
		return PartialReport{}, nil
	}
	res := req.Artifact.SharedArtifactMap()
	if len(res.Files) == 0 {
		return PartialReport{}, nil
	}
	// TODO: cross-ecosystem path-collision detection — e.g. flag a
	// stray Gemfile.lock inside an npm package as a manifest-confusion
	// signal rather than silently ignoring it here.

	// Collect matched lockfile paths, partitioned into path-suppressed
	// vs. live (not suppressed by path).
	var pathSuppressed []string
	var live []string
	for _, p := range res.Files.SortedPaths() {
		base := path.Base(p)
		if !matchesAny(base, names) {
			continue
		}
		if codesmell.IsLikelyExampleOrDoc(p) {
			pathSuppressed = append(pathSuppressed, p)
			continue
		}
		live = append(live, p)
	}

	// No matches at all — silent.
	if len(pathSuppressed) == 0 && len(live) == 0 {
		return PartialReport{}, nil
	}

	var partial PartialReport

	// Manifest-declared suppression for the npm family. The package.json
	// has already been decompressed into the SharedArtifactMap; one read
	// max, no second scan.
	bundledSuppressed := false
	if _, isNPM := npmFamily[eco]; isNPM && len(live) > 0 {
		if pkgJSON := FirstMatch(res.Files.SelectLower(func(name string) bool {
			return strings.EqualFold(path.Base(name), "package.json")
		}), "package.json"); len(pkgJSON) > 0 {
			if hasBundledDependencies(pkgJSON) {
				bundledSuppressed = true
			}
		}
	}

	if bundledSuppressed {
		// All live matches collapse into the bundled-deps suppression
		// bucket; the warning lists them so an operator can audit.
		bundled := live
		live = nil
		sort.Strings(bundled)
		partial.Warnings = append(partial.Warnings, Warning{
			Provider: "shrinkwrap",
			Code:     WarnShrinkwrapBundledDepsSuppressed,
			Message: fmt.Sprintf(
				"lockfile at archive root suppressed because package.json declares bundledDependencies: [%s]",
				strings.Join(bundled, ", "),
			),
		})
	}

	if len(pathSuppressed) > 0 {
		sort.Strings(pathSuppressed)
		partial.Warnings = append(partial.Warnings, Warning{
			Provider: "shrinkwrap",
			Code:     WarnShrinkwrapPathSuppressed,
			Message: fmt.Sprintf(
				"%d lockfile match(es) suppressed because they're in test/example/docs paths: [%s]",
				len(pathSuppressed), strings.Join(pathSuppressed, ", "),
			),
		})
	}

	scan := &ArtifactScanSection{Performed: true}
	if len(live) > 0 {
		scan.ShrinkwrapPresent = true
	} else {
		// Matches found but all suppressed.
		scan.ShrinkwrapSuppressed = true
	}
	partial.Scan = scan
	return partial, nil
}

func matchesAny(base string, names []string) bool {
	for _, n := range names {
		if strings.EqualFold(base, n) {
			return true
		}
	}
	return false
}

// hasBundledDependencies reports whether the given package.json bytes
// declare a non-empty bundledDependencies (or the alternate spelling
// bundleDependencies) array. Malformed JSON is tolerated: parse
// failure means "not declared", and the signal fires normally.
//
// Per npm docs, the canonical field is "bundledDependencies" but
// "bundleDependencies" (no 'd') is also accepted; both are arrays of
// dependency names.
// https://docs.npmjs.com/cli/v10/configuring-npm/package-json#bundleddependencies
func hasBundledDependencies(pkgJSON []byte) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(pkgJSON, &raw); err != nil {
		return false
	}
	for _, key := range []string{"bundledDependencies", "bundleDependencies"} {
		v, ok := raw[key]
		if !ok {
			continue
		}
		var arr []string
		if err := json.Unmarshal(v, &arr); err != nil {
			// Non-array shape — malformed or boolean form. Don't
			// suppress on something we can't validate.
			continue
		}
		if len(arr) > 0 {
			return true
		}
	}
	return false
}

var _ Provider = (*shrinkwrapProvider)(nil)
