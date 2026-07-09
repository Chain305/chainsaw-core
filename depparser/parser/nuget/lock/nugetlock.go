// Package nugetlock parses packages.lock.json (NuGet central package
// management).
//
// Format: JSON.
//
//	{
//	  "version": 1,
//	  "dependencies": {
//	    "net6.0": {
//	      "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"}
//	    }
//	  }
//	}
//
// We fan out across target-framework groups and emit every (name, resolved)
// pair. Type="Project" entries (sibling projects in a solution) are
// skipped because they have no independent version that a vuln DB indexes.
//
// Trivy reference: pkg/dependency/parser/nuget/lock/parse.go.
package nugetlock

import (
	"encoding/json"
	"io"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type entry struct {
	Type      string `json:"type"`
	Resolved  string `json:"resolved"`
	Requested string `json:"requested"`
}

type lockfile struct {
	Version      int                         `json:"version"`
	Dependencies map[string]map[string]entry `json:"dependencies"`
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	var lf lockfile
	if err := json.NewDecoder(r).Decode(&lf); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []ftypes.Package
	for _, framework := range lf.Dependencies {
		for name, e := range framework {
			if e.Type == "Project" {
				continue
			}
			ver := e.Resolved
			if ver == "" {
				ver = e.Requested
			}
			if name == "" || ver == "" {
				continue
			}
			k := name + "@" + ver
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, ftypes.Package{Name: name, Version: ver})
		}
	}
	return out, nil
}
