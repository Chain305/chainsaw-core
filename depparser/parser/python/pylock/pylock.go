// Package pylock parses pylock.toml (PEP 751 — standardized Python lock
// file format). Matches default filename `pylock.toml` and the PEP 751
// variant `pylock.{identifier}.toml`.
//
// Format: TOML. Top-level `packages` is an array of tables with name and
// (for index packages) version, plus exactly one source: `index` with
// `sdist` / `wheels` files, `vcs`, `directory` or `archive`.
//
// Trivy reference: pkg/dependency/parser/python/pylock/parse.go. Trivy
// additionally merges `pyproject.toml` to mark direct deps; that companion
// lookup is out of scope for this minimal port — every package is
// returned without a direct/indirect split.
package pylock

import (
	"io"

	"github.com/BurntSushi/toml"

	"github.com/chain305/chainsaw-core/depparser/origin"
	"github.com/chain305/chainsaw-core/depparser/parser/python"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type file struct {
	URL    string            `toml:"url"`
	Path   string            `toml:"path"`
	Hashes map[string]string `toml:"hashes"`
}

type lockfile struct {
	Packages []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
		Index   string `toml:"index"`
		Sdist   *file  `toml:"sdist"`
		Wheels  []file `toml:"wheels"`
		VCS     *struct {
			Type              string `toml:"type"`
			URL               string `toml:"url"`
			Path              string `toml:"path"`
			RequestedRevision string `toml:"requested-revision"`
			CommitID          string `toml:"commit-id"`
		} `toml:"vcs"`
		Directory *struct {
			Path string `toml:"path"`
		} `toml:"directory"`
		Archive *struct {
			URL    string            `toml:"url"`
			Path   string            `toml:"path"`
			Hashes map[string]string `toml:"hashes"`
		} `toml:"archive"`
	} `toml:"packages"`
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	var lf lockfile
	if _, err := toml.NewDecoder(r).Decode(&lf); err != nil {
		return nil, err
	}
	var out []ftypes.Package
	for _, p := range lf.Packages {
		if p.Name == "" {
			continue
		}
		pkg := ftypes.Package{Name: python.NormalizePkgName(p.Name, true), Version: p.Version}
		switch {
		case p.VCS != nil:
			src := p.VCS.URL
			if src == "" {
				src = p.VCS.Path
			}
			rev := p.VCS.CommitID
			if rev == "" {
				rev = p.VCS.RequestedRevision
			}
			pkg.Origin = python.VCSOrigin(p.VCS.Type, src, rev)
			if pkg.Origin == "" {
				pkg.Origin = p.VCS.Type + ":"
			}
		case p.Directory != nil:
			pkg.Origin = python.PathOrigin(p.Directory.Path)
		case p.Archive != nil:
			src := p.Archive.URL
			if src == "" {
				src = p.Archive.Path
			}
			pkg.Hash = origin.JoinHashes(fileHashes(p.Archive.Hashes)...)
			pkg.Origin = python.ProjectFileOrigin(p.Name, p.Version, src)
		default:
			files := append([]file(nil), p.Wheels...)
			if p.Sdist != nil {
				files = append(files, *p.Sdist)
			}
			var hs []string
			var dfs []python.DistFile
			for _, f := range files {
				hs = append(hs, fileHashes(f.Hashes)...)
				dfs = append(dfs, python.DistFile{URL: f.URL, Path: f.Path})
			}
			pkg.Hash = origin.JoinHashes(hs...)
			pkg.Origin = python.IndexFilesOrigin(p.Name, p.Version, p.Index, dfs)
		}
		if pkg.Version == "" && pkg.Origin == "" {
			continue
		}
		out = append(out, pkg)
	}
	return out, nil
}

// fileHashes is one file's PEP 751 `hashes` table ({sha256 = "<hex>", …})
// as canonical tokens: the ones NormalizeHash reads, or — when it reads none
// (no table, md5 or blake2b only) — one origin.UnreadableHash, so the file
// is never dropped from the entry's Hash (python.FileHash).
func fileHashes(m map[string]string) []string {
	var hs []string
	bad := ""
	for a, h := range m {
		if n := origin.NormalizeHash(a + ":" + h); n != "" {
			hs = append(hs, n)
		} else if bad == "" || a < bad {
			bad = a
		}
	}
	if len(hs) == 0 {
		return []string{origin.UnreadableHash(bad)}
	}
	return hs
}
