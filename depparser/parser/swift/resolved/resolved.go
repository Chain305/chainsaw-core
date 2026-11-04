// Package resolved parses Package.resolved (Swift Package Manager).
//
// Format: JSON, two schema versions:
//
//	v1:  { "object": { "pins": [ {"package": "Foo", "repositoryURL": "https://github.com/x/foo.git", "state": {"version": "1.0.0"}} ] } }
//	v2+: { "pins": [ {"identity": "foo", "kind": "remoteSourceControl", "location": "https://github.com/x/foo.git", "state": {"version": "1.0.0"}} ], "version": 2 }
//
// We support both by reading the top-level "pins" first and then falling
// back to "object.pins".
//
// IDENTITY. SwiftPM's `identity` is the last path segment of the URL
// ("alamofire"), which no advisory database, registry or typosquat seed
// keys on: two forks of one repo share it. A pin from a github.com location
// is re-keyed to the SE-0292 `owner.repo` form, lowercased, the identity the
// Swift proxy (core/formats/swift NormalizeIdentifier), the typosquat seeds
// and the OSV SwiftURL index all use (PLANS_INTELLIGENCE §3 rule 4: Swift
// identity is the normalised location). Any other location (another git
// host, a local checkout, a path) keeps SwiftPM's identity and carries the
// location as Origin, so it is never scored as the github package of the
// same name. A registry pin's identity is already `scope.name`.
//
// Trivy reference: pkg/dependency/parser/swift/*.
package resolved

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/chain305/chainsaw-core/depparser/origin"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type state struct {
	Version  string `json:"version"`
	Revision string `json:"revision"`
}

type pin struct {
	Identity      string `json:"identity"`      // v2+
	Kind          string `json:"kind"`          // v2+
	Location      string `json:"location"`      // v2+
	Package       string `json:"package"`       // v1
	RepositoryURL string `json:"repositoryURL"` // v1
	State         state  `json:"state"`
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
		pkg := ftypes.Package{Name: name, Version: p.State.Version}
		loc := p.Location
		if loc == "" {
			loc = p.RepositoryURL
		}
		if p.Kind != "registry" && loc != "" {
			if id, ok := GitHubIdentity(loc); ok {
				pkg.Name = id
			} else {
				pkg.Origin = origin.Sanitize(loc)
			}
		}
		out = append(out, pkg)
	}
	return out, nil
}

// GitHubIdentity returns the SE-0292 `owner.repo` identity (lowercased) for
// a github.com repository location in any form SwiftPM records
// (https://github.com/Owner/Repo.git, git@github.com:Owner/Repo.git), and
// false for anything else: another host, a deeper path, a local path.
func GitHubIdentity(location string) (string, bool) {
	l := origin.Location(location)
	rest, ok := strings.CutPrefix(l, "github.com/")
	if !ok {
		return "", false
	}
	owner, repo, ok := strings.Cut(rest, "/")
	if !ok || owner == "" || repo == "" || strings.ContainsAny(repo, "/@:") || strings.Contains(owner, ".") {
		return "", false
	}
	return strings.ToLower(owner + "." + repo), true
}
