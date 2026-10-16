// Package uv parses uv.lock files produced by Astral's uv package manager.
//
// Format: TOML. Top-level is `version = N`, then an array-of-tables
// `[[package]]` with name/version/source/sdist/wheels/dependencies.
//
// Trivy reference: pkg/dependency/parser/python/uv/parse.go.
package uv

import (
	"io"
	"sort"

	"github.com/BurntSushi/toml"

	"github.com/chain305/chainsaw-core/depparser/origin"
	"github.com/chain305/chainsaw-core/depparser/parser/python"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type dist struct {
	URL  string `toml:"url"`
	Path string `toml:"path"`
	Hash string `toml:"hash"`
}

type lockfile struct {
	Packages []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
		// Source is exactly one of registry, git, url, path, directory,
		// editable, virtual (uv's lock format).
		Source map[string]any `toml:"source"`
		Sdist  *dist          `toml:"sdist"`
		Wheels []dist         `toml:"wheels"`
	} `toml:"package"`
}

// Parse returns every package with its Origin and file hashes:
//
//   - registry = "<index>": PyPI → no Origin; another index (a mirror, the
//     PyTorch index, a private one) → "registry+<index>", decided on the
//     server by the sdist/wheel hashes. A wheel or sdist URL on any other
//     host (or a file by path) overrides it: uv fetches the recorded URL.
//   - git = "<url>?…#<commit>": "git+<url>…" (uv records the commit as the
//     fragment, the grammar origin.Label reads).
//   - url = "<archive>": the archive (a file on PyPI's own hosts is PyPI's
//     only when it is this project's file of this version).
//
// Every listed file contributes to Hash; one with no hash we can read
// contributes origin.UnreadableHash (python.FileHash).
//   - path / directory / editable / virtual: local code, including the
//     project itself (editable or virtual "."), which used to be scored as
//     its PyPI namesake. Its Origin is "file:<path>".
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
		pkg := ftypes.Package{
			Name:    python.NormalizePkgName(p.Name, true),
			Version: p.Version,
			Origin:  sourceOrigin(p.Name, p.Version, p.Source),
		}
		files := append([]dist(nil), p.Wheels...)
		if p.Sdist != nil {
			files = append(files, *p.Sdist)
		}
		var hs []string
		var dfs []python.DistFile
		for _, f := range files {
			hs = append(hs, python.FileHash(f.Hash))
			dfs = append(dfs, python.DistFile{URL: f.URL, Path: f.Path})
		}
		pkg.Hash = origin.JoinHashes(hs...)
		if reg, ok := p.Source["registry"].(string); ok {
			// uv installs each file from the URL it recorded, not from the
			// index: every file is read (python.IndexFilesOrigin).
			pkg.Origin = python.IndexFilesOrigin(p.Name, p.Version, reg, dfs)
		}
		if pkg.Version == "" && pkg.Origin == "" {
			continue
		}
		out = append(out, pkg)
	}
	return out, nil
}

func sourceOrigin(name, version string, src map[string]any) string {
	str := func(k string) (string, bool) {
		v, ok := src[k].(string)
		return v, ok
	}
	if v, ok := str("registry"); ok {
		return python.IndexOrigin(v)
	}
	if v, ok := str("git"); ok {
		return python.VCSOrigin("git", v, "")
	}
	if v, ok := str("url"); ok {
		return python.ProjectFileOrigin(name, version, v)
	}
	for _, k := range []string{"editable", "virtual", "directory", "path"} {
		if v, ok := str(k); ok {
			return python.PathOrigin(v)
		}
	}
	if len(src) == 0 {
		return ""
	}
	// A source kind this parser does not know is not PyPI.
	keys := make([]string, 0, len(src))
	for k := range src {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys[0] + ":"
}
