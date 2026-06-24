// Package conan parses conan.lock (Conan C/C++ package manager).
//
// Format: JSON. Conan v2 shape:
//
//	{
//	  "version": "0.5",
//	  "requires": [
//	    "zlib/1.2.13#abc@user/channel",
//	    "openssl/3.1.2#def"
//	  ],
//	  "build_requires": [...],
//	  "python_requires": [...]
//	}
//
// Each ref is "name/version[#revision][@user/channel]". We keep only
// name + version.
//
// Trivy reference: pkg/dependency/parser/c/conan/parse.go.
package conan

import (
	"encoding/json"
	"io"
	"strings"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type lockfile struct {
	Version        string   `json:"version"`
	Requires       []string `json:"requires"`
	BuildRequires  []string `json:"build_requires"`
	PythonRequires []string `json:"python_requires"`
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	var lf lockfile
	if err := json.NewDecoder(r).Decode(&lf); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []ftypes.Package
	for _, list := range [][]string{lf.Requires, lf.BuildRequires, lf.PythonRequires} {
		for _, ref := range list {
			name, ver := splitRef(ref)
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

// splitRef strips the optional "#revision" and "@user/channel" parts and
// returns (name, version) from "name/version[#rev][@user/channel]".
func splitRef(ref string) (string, string) {
	if i := strings.Index(ref, "#"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}
