// Package pom parses Maven pom.xml project files.
//
// Manifest, not a lock file. Unlike Gradle, Maven's "lockfile" is not a
// universal convention — projects with `dependencyManagement` sections
// typically pin versions inside the POM itself, and version-range syntax
// is rare. Entries that reference a property placeholder (${xxx}) are
// skipped because resolving those requires knowing the wider POM
// hierarchy (parent POMs, profiles); that's a Trivy-scale project we
// defer to upstream's `pkg/dependency/parser/java/pom`.
//
// Ported verbatim from internal/cli/scan.go:parsePomXML.
package pom

import (
	"encoding/xml"
	"io"
	"strings"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type xmlDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type xmlProject struct {
	Dependencies []xmlDep `xml:"dependencies>dependency"`
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	var proj xmlProject
	if err := xml.NewDecoder(r).Decode(&proj); err != nil {
		return nil, err
	}
	var out []ftypes.Package
	for _, d := range proj.Dependencies {
		ver := strings.TrimSpace(d.Version)
		// Skip property references — we don't resolve them.
		if ver == "" || strings.HasPrefix(ver, "${") {
			continue
		}
		out = append(out, ftypes.Package{
			Name:    d.GroupID + ":" + d.ArtifactID,
			Version: ver,
		})
	}
	return out, nil
}
