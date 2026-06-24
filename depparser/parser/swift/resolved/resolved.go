// Package resolved parses Package.resolved (Swift Package Manager).
//
// Format: JSON, two schema versions:
//
//	v1:  { "object": { "pins": [ {"package": "Foo", "state": {"version": "1.0.0"}} ] } }
//	v2+: { "pins": [ {"identity": "foo", "state": {"version": "1.0.0"}} ], "version": 2 }
//
// We support both by reading the top-level "pins" first and then falling
// back to "object.pins". The package name is `identity` in v2+ and
// `package` in v1.
//
// Trivy reference: pkg/dependency/parser/swift/*.
package resolved

import (
	"encoding/json"
	"io"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type state struct {
	Version  string `json:"version"`
	Revision string `json:"revision"`
}

type pin struct {
	Identity string `json:"identity"` // v2+
	Package  string `json:"package"`  // v1
	State    state  `json:"state"`
}

type envelope struct {
	Pins    []pin `json:"pins"`
	Version int   `json:"version"`
	Object  struct {
		Pins []pin `json:"pins"`
	} `json:"object"`
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	var e envelope
	if err := json.NewDecoder(r).Decode(&e); err != nil {
		return nil, err
	}
	pins := e.Pins
	if len(pins) == 0 {
		pins = e.Object.Pins
	}
	var out []ftypes.Package
	for _, p := range pins {
		name := p.Identity
		if name == "" {
			name = p.Package
		}
		// SPM sometimes pins to a branch/revision with no version.
		// Skip those — they have nothing for a vuln DB to match.
		if name == "" || p.State.Version == "" {
			continue
		}
		out = append(out, ftypes.Package{Name: name, Version: p.State.Version})
	}
	return out, nil
}
