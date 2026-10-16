// Package poetry is a vendored copy of
// github.com/aquasecurity/trivy/pkg/dependency/parser/python/poetry.
//
// The import paths are rewritten to point at chainsaw's internal vendor
// tree, and two changes are chainsaw's own (a `diff` against Trivy's main
// branch shows exactly them): each package's Origin and Hash, from its
// [package.source] and its `files` (or the older [metadata.files] table) —
// see docs/PLANS_INTELLIGENCE.md#plan-non-registry-sources; and the
// dependency graph is NOT built. Nothing reads poetry's edges (the analyzer,
// the server lockfile scan, pr-scan and the guard all drop them), and
// upstream's resolution re-parsed every range against every locked version
// of the name: 4,000 entries of one name took 1m41s on the anonymous scan
// endpoint, and `b = {version = 1}` panicked on an unchecked assertion
// (red-team round 2). Everything else is upstream's logic.
//
// Upstream: trivy/pkg/dependency/parser/python/poetry/parse.go
// License: Apache-2.0 (see ../../../NOTICE).
package poetry

import (
	"context"
	"slices"

	"github.com/BurntSushi/toml"
	"golang.org/x/xerrors"

	"github.com/chain305/chainsaw-core/depparser/dependency"
	"github.com/chain305/chainsaw-core/depparser/log"
	"github.com/chain305/chainsaw-core/depparser/origin"
	"github.com/chain305/chainsaw-core/depparser/parser/python"
	xio "github.com/chain305/chainsaw-core/depparser/xio"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type Lockfile struct {
	Packages []struct {
		Category       string   `toml:"category"`
		Groups         []string `toml:"groups"`
		Description    string   `toml:"description"`
		Marker         string   `toml:"marker,omitempty"`
		Name           string   `toml:"name"`
		Optional       bool     `toml:"optional"`
		PythonVersions string   `toml:"python-versions"`
		Version        string   `toml:"version"`
		Metadata       any
		Files          []poetryFile  `toml:"files"`
		Source         *poetrySource `toml:"source"`
	} `toml:"package"`
	// LockMetadata.Files is poetry < 1.5's per-name file list.
	LockMetadata struct {
		Files map[string][]poetryFile `toml:"files"`
	} `toml:"metadata"`
}

type poetryFile struct {
	File string `toml:"file"`
	Hash string `toml:"hash"`
}

// poetrySource is [package.source]: absent for PyPI.
type poetrySource struct {
	Type              string `toml:"type"`
	URL               string `toml:"url"`
	Reference         string `toml:"reference"`
	ResolvedReference string `toml:"resolved_reference"`
}

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("poetry"),
	}
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lockfile Lockfile
	if _, err := toml.NewDecoder(r).Decode(&lockfile); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode poetry.lock: %w", err)
	}

	// chainsaw: [metadata.files] keyed by the normalised name.
	oldFiles := map[string][]poetryFile{}
	for name, fs := range lockfile.LockMetadata.Files {
		oldFiles[python.NormalizePkgName(name, true)] = fs
	}

	// [metadata.files] is per NAME, so every [[package]] of that name gets
	// the same list: join it once per name and share the string, or N
	// packages × K files is retained N×K times.
	oldJoined := map[string]string{}

	var pkgs []ftypes.Package
	for _, pkg := range lockfile.Packages {
		pkgID := packageID(pkg.Name, pkg.Version)
		var hash string
		if len(pkg.Files) > 0 {
			hash = joinFiles(pkg.Files)
		} else {
			name := python.NormalizePkgName(pkg.Name, true)
			h, ok := oldJoined[name]
			if !ok {
				h = joinFiles(oldFiles[name])
				oldJoined[name] = h
			}
			hash = h
		}
		pkgs = append(pkgs, ftypes.Package{
			ID:      pkgID,
			Name:    pkg.Name,
			Version: pkg.Version,
			// TODO upgrade logic for working with groups
			// Mark only:
			// - `category = "dev"`
			// - groups without `main`. e.g. `groups = ["dev"]`
			Dev:    pkg.Category == "dev" || (len(pkg.Groups) > 0 && !slices.Contains(pkg.Groups, "main")),
			Origin: sourceOrigin(pkg.Name, pkg.Version, pkg.Source),
			Hash:   hash,
		})
	}
	return pkgs, nil, nil
}

// joinFiles is the Hash of a poetry file list (origin.JoinHashes): a file
// with no hash we can read (md5 only) stays in it as origin.UnreadableHash
// (python.FileHash).
func joinFiles(files []poetryFile) string {
	hashes := make([]string, 0, len(files))
	for _, f := range files {
		hashes = append(hashes, python.FileHash(f.Hash))
	}
	return origin.JoinHashes(hashes...)
}

// sourceOrigin is a package's Origin from its [package.source] (chainsaw):
// "" for PyPI (no source, or a legacy source that is pypi.org/simple).
//
//   - legacy (a PEP 503 index): registry+<url> — a mirror or a private
//     index, decided by content hash on the server.
//   - git: git+<url>#<resolved commit>.
//   - directory / file: the local path; url: the archive URL (a file on
//     PyPI's own hosts is the PyPI package only when it is this project's
//     file of this version).
//   - anything else: the url if any, else the type, never "" — a source
//     nobody recognised is not PyPI.
func sourceOrigin(name, version string, s *poetrySource) string {
	if s == nil || (s.Type == "" && s.URL == "") {
		return ""
	}
	switch s.Type {
	case "legacy":
		return python.IndexOrigin(s.URL)
	case "git":
		rev := s.ResolvedReference
		if rev == "" {
			rev = s.Reference
		}
		return python.VCSOrigin("git", s.URL, rev)
	case "url":
		return python.ProjectFileOrigin(name, version, s.URL)
	case "directory", "file":
		return python.PathOrigin(s.URL)
	}
	if s.URL != "" {
		return origin.Sanitize(s.URL)
	}
	return s.Type + ":"
}

func packageID(name, ver string) string {
	return dependency.ID(ftypes.Poetry, name, ver)
}
