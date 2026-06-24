// Package nugetconfig parses legacy packages.config (pre-PackageReference
// NuGet project format).
//
// Format: XML.
//
//	<packages>
//	  <package id="Newtonsoft.Json" version="13.0.1" targetFramework="..." />
//	</packages>
//
// Trivy reference: pkg/dependency/parser/nuget/config/parse.go.
package nugetconfig

import (
	"encoding/xml"
	"io"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type pkg struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

type config struct {
	Packages []pkg `xml:"package"`
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	var c config
	if err := xml.NewDecoder(r).Decode(&c); err != nil {
		return nil, err
	}
	var out []ftypes.Package
	for _, p := range c.Packages {
		if p.ID == "" || p.Version == "" {
			continue
		}
		out = append(out, ftypes.Package{Name: p.ID, Version: p.Version})
	}
	return out, nil
}
