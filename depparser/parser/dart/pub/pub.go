// Package pub parses pubspec.lock (Dart/Flutter).
//
// Format: YAML.
//
//	packages:
//	  http:
//	    dependency: "direct main"
//	    description: { name: http, url: "https://pub.dev" }
//	    source: hosted
//	    version: "1.1.0"
//	sdks:
//	  dart: ">=2.18.0 <3.0.0"
//
// Trivy reference: pkg/dependency/parser/dart/pub/parse.go.
package pub

import (
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

// pubDevHost is the canonical pub.dev registry URL as it appears in a hosted
// dependency's description.url. pub.dev sometimes omits the url for hosted deps,
// in which case it is treated as pub.dev.
const pubDevHost = "https://pub.dev"

// pubDartlangHost is the legacy canonical host. Before 2021 pub.dev published
// hosted deps with url: "https://pub.dartlang.org"; that host still appears in
// older pubspec.lock files and serves the SAME packages as pub.dev. The
// transformer (transformer.go) and url_mapper (url_mapper.go) already treat
// pub.dartlang.org as pub.dev-equivalent, so excluding it here was a parser
// inconsistency that let legacy-host hosted deps slip past advisory matching.
const pubDartlangHost = "https://pub.dartlang.org"

// isPubDevHost reports whether a hosted dependency's description.url points at
// pub.dev (or its legacy pub.dartlang.org alias). An empty url is treated as
// pub.dev — pub.dev omits the url for its own packages. Trailing slashes are
// trimmed so "https://pub.dev/" matches.
func isPubDevHost(rawURL string) bool {
	u := strings.TrimRight(strings.TrimSpace(rawURL), "/")
	if u == "" {
		return true
	}
	return strings.EqualFold(u, pubDevHost) || strings.EqualFold(u, pubDartlangHost)
}

// pkgDescription captures the description map of a hosted dependency. For
// non-hosted sources the description can be a bare scalar string (e.g. `sdk`
// deps render `description: flutter`) or a different map shape (`git`/`path`),
// so UnmarshalYAML tolerates non-map nodes by leaving the fields empty —
// those entries are skipped by the source filter anyway.
type pkgDescription struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

func (d *pkgDescription) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		// Scalar (sdk deps) or other non-map shapes carry no hosted coordinate.
		return nil
	}
	type rawDescription pkgDescription
	var raw rawDescription
	if err := node.Decode(&raw); err != nil {
		// A foreign map shape (e.g. git's {url, ref, path}) may not decode
		// cleanly into name/url; tolerate it — the source filter excludes it.
		return nil
	}
	*d = pkgDescription(raw)
	return nil
}

type pkgEntry struct {
	Dependency  string         `yaml:"dependency"`
	Source      string         `yaml:"source"`
	Version     string         `yaml:"version"`
	Description pkgDescription `yaml:"description"`
}

type lockfile struct {
	Packages map[string]pkgEntry `yaml:"packages"`
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var lf lockfile
	if err := yaml.Unmarshal(buf, &lf); err != nil {
		return nil, err
	}
	var out []ftypes.Package
	for name, e := range lf.Packages {
		if name == "" || e.Version == "" {
			continue
		}
		// Only `hosted` deps carry a pub.dev coordinate Chainsaw can match
		// against pub.dev advisories. Skip git/path/sdk: their "coordinate" is
		// a VCS ref / local path / SDK marker, not a pub.dev name+version —
		// emitting them produces false-positive CVE matches.
		if !strings.EqualFold(e.Source, "hosted") {
			continue
		}
		// A hosted dep on a private registry can share a pub.dev name. Only
		// emit pub.dev-hosted deps so a same-named private package is NOT
		// matched against pub.dev GHSA advisories. pub.dev sometimes omits the
		// url for its own packages, so an empty url is treated as pub.dev. The
		// legacy pub.dartlang.org host (and trailing-slash variants) is also
		// pub.dev-hosted — see isPubDevHost.
		if !isPubDevHost(e.Description.URL) {
			continue
		}
		// dependency: "transitive" / "direct main" / "direct dev".
		dev := strings.Contains(e.Dependency, "dev")
		out = append(out, ftypes.Package{Name: name, Version: e.Version, Dev: dev})
	}
	return out, nil
}
