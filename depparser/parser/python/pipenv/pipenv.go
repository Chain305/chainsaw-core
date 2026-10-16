// Package pipenv parses Pipfile.lock (Pipenv).
//
// Format: JSON. Top-level keys are "default" (prod) and "develop" (dev),
// each a map of pkg-name → entry. An index entry is {version: "==1.2.3",
// hashes: [...], index: "<source name>"}, the source named under
// _meta.sources; a VCS entry is {git|hg|svn|bzr: url, ref}; a local one
// {path}; an archive {file: url}.
//
// Trivy reference: pkg/dependency/parser/python/pipenv/parse.go. This
// file is a format-faithful rewrite emitting name+version tuples plus
// where each package comes from (Origin) and its file hashes (Hash);
// licenses and the dependency graph are dropped.
package pipenv

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/chain305/chainsaw-core/depparser/origin"
	"github.com/chain305/chainsaw-core/depparser/parser/python"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type entry struct {
	Version string   `json:"version"`
	Hashes  []string `json:"hashes"`
	Index   string   `json:"index"`
	Git     string   `json:"git"`
	Hg      string   `json:"hg"`
	Svn     string   `json:"svn"`
	Bzr     string   `json:"bzr"`
	Ref     string   `json:"ref"`
	Path    string   `json:"path"`
	File    string   `json:"file"`
}

type lockfile struct {
	Meta struct {
		Sources []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"sources"`
	} `json:"_meta"`
	Default map[string]entry `json:"default"`
	Develop map[string]entry `json:"develop"`
}

// Parse reads a Pipfile.lock from r and returns ftypes.Package entries.
// Dev-only dependencies are marked Dev=true so the caller can filter.
func Parse(r io.Reader) ([]ftypes.Package, error) {
	var lf lockfile
	if err := json.NewDecoder(r).Decode(&lf); err != nil {
		return nil, err
	}
	// An entry with no "index" comes from the first source (pipenv's
	// default); one naming a source missing from _meta cannot be placed,
	// so it is not called PyPI's.
	indexOrigin := map[string]string{}
	defaultOrigin := ""
	for i, s := range lf.Meta.Sources {
		indexOrigin[s.Name] = python.IndexOrigin(s.URL)
		if i == 0 {
			defaultOrigin = indexOrigin[s.Name]
		}
	}
	var out []ftypes.Package
	collect := func(m map[string]entry, dev bool) {
		for name, e := range m {
			p := ftypes.Package{
				Name:    python.NormalizePkgName(name, true),
				Version: strings.TrimPrefix(e.Version, "=="), // Pipenv writes "==1.2.3"
				Dev:     dev,
			}
			if len(e.Hashes) > 0 {
				hs := make([]string, len(e.Hashes))
				for i, h := range e.Hashes {
					hs[i] = python.FileHash(h)
				}
				p.Hash = origin.JoinHashes(hs...)
			}
			switch {
			case e.Git != "":
				p.Origin = python.VCSOrigin("git", e.Git, e.Ref)
			case e.Hg != "":
				p.Origin = python.VCSOrigin("hg", e.Hg, e.Ref)
			case e.Svn != "":
				p.Origin = python.VCSOrigin("svn", e.Svn, e.Ref)
			case e.Bzr != "":
				p.Origin = python.VCSOrigin("bzr", e.Bzr, e.Ref)
			case e.Path != "":
				p.Origin = python.PathOrigin(e.Path)
			case e.File != "":
				if fn, fv := python.DistFilename(e.File); p.Version == "" && python.SameProject(fn, name) {
					p.Version = fv
				}
				p.Origin = python.ProjectFileOrigin(name, p.Version, e.File)
			case e.Index != "":
				o, known := indexOrigin[e.Index]
				if !known {
					o = "registry+(Pipfile source " + e.Index + ")"
				}
				p.Origin = o
			default:
				p.Origin = defaultOrigin
			}
			if p.Version == "" && p.Origin == "" {
				continue // an index entry with no version: nothing to look up
			}
			out = append(out, p)
		}
	}
	collect(lf.Default, false)
	collect(lf.Develop, true)
	return out, nil
}
