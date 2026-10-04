package intelligence

// shrinkwrapProvider reports a lockfile the INSTALLER will honour when this
// package is installed as a dependency, which lets the package pin its whole
// transitive graph past the consumer's own resolution. Tier-2; zero new
// network cost — the archive is already decompressed once via
// SharedArtifactMap.
//
// That is npm-shrinkwrap.json at the package root, and nothing else:
//
//	npm-shrinkwrap.json (npm, yarn, pnpm, bun)   honoured for a dependency
//	package-lock.json, yarn.lock, pnpm-lock, bun   ignored inside a dependency
//	Pipfile.lock, poetry.lock (pip)                ignored
//	composer.lock                                  ignored for a dependency
//	Gemfile.lock (gem install)                     ignored
//	Cargo.lock                                     only with an opt-in
//	                                               `cargo install --locked`
//	                                               on a binary crate
//
// Until 2026-10-03 every row of that table fired, at -10. On the 1,885-row
// socket.dev corpus that was 129 packages (83 Cargo.lock, 22 composer.lock,
// 13 Gemfile.lock, 10 yarn/package-lock, 1 Pipfile.lock) and not one
// npm-shrinkwrap.json; socket.dev's shrinkwrap alert fired on none of them.
// Restricting it flipped no verdict and raised 90 scores by 3-4 points.
//
// A shrinkwrap anywhere but the root is not read by npm either (one inside a
// bundled node_modules/ ships pre-installed; one under examples/ is a file),
// which is why the old path- and bundledDependencies-based suppressions are
// gone rather than kept: nothing they suppressed can fire any more.

import (
	"context"
	"path"
	"strings"
)

// ecosystemLockfiles maps an ecosystem to the lockfile its installer honours
// inside a dependency. The ecosystems whose installers honour none keep an
// empty entry ON PURPOSE: Supports() stays true, so the ShrinkwrapPresent
// policy condition evaluates (to false, which is the truth) instead of the
// proxy matrix marking it unsupported, which skips the whole policy.
var ecosystemLockfiles = map[string][]string{
	"npm":      {"npm-shrinkwrap.json"},
	"yarn":     {"npm-shrinkwrap.json"},
	"bun":      {"npm-shrinkwrap.json"},
	"pnpm":     {"npm-shrinkwrap.json"},
	"pip":      nil,
	"pypi":     nil,
	"composer": nil,
	"cargo":    nil,
	"rubygems": nil,
}

type shrinkwrapProvider struct{}

func newShrinkwrapProvider() *shrinkwrapProvider { return &shrinkwrapProvider{} }

func (p *shrinkwrapProvider) Name() string        { return "shrinkwrap" }
func (p *shrinkwrapProvider) Signal() SignalMask  { return SignalShrinkwrap }
func (p *shrinkwrapProvider) Tier() int           { return 2 }
func (p *shrinkwrapProvider) NeedsArtifact() bool { return true }

// shrinkwrapAnalyzerVersion — bump when what counts as a shrinkwrap, or what
// is read out of it, changes for identical bytes.
//
// 2: artifactmap maps a .gem's data.tar.gz (6815af8e), so a Gemfile.lock
// shipped inside a gem is now seen. 6815af8e bumped the other map readers
// but not this one.
// 3: only a root npm-shrinkwrap.json fires.
const shrinkwrapAnalyzerVersion = 3

func (p *shrinkwrapProvider) AnalyzerVersion() int { return shrinkwrapAnalyzerVersion }
func (p *shrinkwrapProvider) Supports(eco string) bool {
	_, ok := ecosystemLockfiles[strings.ToLower(strings.TrimSpace(eco))]
	return ok
}

func (p *shrinkwrapProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	// N5: a size/file-capped archive walk must not be reported as a clean
	// absence. Wrapping run() rather than editing each early return is what
	// makes that true for the paths that return PartialReport{} — which are
	// precisely the ones that say "nothing found". Verdict-neutral.
	partial, err := p.run(ctx, req, prior)
	return partial, err
}

func (p *shrinkwrapProvider) run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
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
	for _, p := range res.Files.SortedPaths() {
		// ponytail: "root" is at most one directory deep, which is every
		// registry tarball's shape (package/npm-shrinkwrap.json); reading
		// package.json to find the root would only matter for a tarball
		// with several top-level directories.
		if strings.Count(p, "/") <= 1 && matchesAny(path.Base(p), names) {
			return PartialReport{Scan: &ArtifactScanSection{Performed: true, ShrinkwrapPresent: true}}, nil
		}
	}
	return PartialReport{}, nil
}

func matchesAny(base string, names []string) bool {
	for _, n := range names {
		if strings.EqualFold(base, n) {
			return true
		}
	}
	return false
}

var _ Provider = (*shrinkwrapProvider)(nil)
