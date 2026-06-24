// Package sbt parses build.sbt.lock (sbt-dependency-lock plugin output).
//
// Format: JSON. Top-level schema:
//
//	{
//	  "lockVersion": 1,
//	  "dependencies": [
//	    {"org": "com.example", "name": "foo", "version": "1.2.3",
//	     "configurations": ["compile"], ...}
//	  ]
//	}
//
// We emit "org:name" as the Package.Name to match the Maven coordinate
// shape used elsewhere in chainsaw.
//
// Trivy reference: pkg/dependency/parser/sbt/lockfile/parse.go.
package sbt

import (
	"encoding/json"
	"io"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type dep struct {
	Org     string `json:"org"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type lockfile struct {
	LockVersion  int   `json:"lockVersion"`
	Dependencies []dep `json:"dependencies"`
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	var lf lockfile
	if err := json.NewDecoder(r).Decode(&lf); err != nil {
		return nil, err
	}
	var out []ftypes.Package
	for _, d := range lf.Dependencies {
		if d.Org == "" || d.Name == "" || d.Version == "" {
			continue
		}
		out = append(out, ftypes.Package{
			Name:    d.Org + ":" + d.Name,
			Version: d.Version,
		})
	}
	return out, nil
}
