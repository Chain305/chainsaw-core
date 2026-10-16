// Package bundler parses Gemfile.lock.
//
// Format: text, one section per source, each with a `specs:` subtree in
// which a line at four-space indent is "<name> (<version>[-<platform>])" and
// deeper lines are that gem's own dependency constraints (ignored):
//
//	GIT
//	  remote: https://github.com/mastodon/webpush.git
//	  revision: 9631ac63045cfabddacc69fc06e919b4c13eb913
//	  specs:
//	    webpush (1.1.0)
//
//	PATH
//	  remote: vendor/gems/omniauth-gitlab
//	  specs:
//	    omniauth-gitlab (4.0.0)
//
//	GEM
//	  remote: https://rubygems.org/
//	  specs:
//	    nokogiri (1.16.0-x86_64-linux)
//	      racc (~> 1.4)
//
//	CHECKSUMS
//	  nokogiri (1.16.0-x86_64-linux) sha256=<hex>
//
// The section decides where a gem comes from
// (docs/PLANS_INTELLIGENCE.md#plan-non-registry-sources):
//
//   - GEM whose remotes are all rubygems.org (origin.Classify): the public
//     registry, no Origin.
//   - GEM with another remote — a mirror (Artifactory, a Chainsaw proxy
//     repository) or a private gem server (packager.dev, Gemfury): Origin
//     "registry+<remote>", decided downstream by content hash or a declared
//     mirror. Bundler 1.x wrote several remotes into ONE GEM section and did
//     not record which served each gem (the dependency-confusion shape), so
//     there the first non-rubygems.org remote is the Origin of every gem.
//   - GIT: Origin "git+<remote>#<revision>".
//   - PATH: Origin "file:<path>" — first-party code in the repository.
//   - Any other source section (PLUGIN SOURCE): Origin "<section> <remotes>".
//
// The platform is not part of the version: Bundler writes a platform gem as
// "<version>-<platform>" and its own lockfile parser splits at the first
// "-" (versions cannot contain one; RubyGems spells a prerelease
// "1.0.0.pre.rc1"). nokogiri (1.16.0-x86_64-linux) and nokogiri (1.16.0) are
// one package, nokogiri@1.16.0.
//
// Hash: the CHECKSUMS section (Bundler 2.6+) gives each platform gem's
// sha256 — the sha256 of the .gem file rubygems.org lists for it. A package
// carries every checksum recorded for its name and version (all platforms),
// space-separated in canonical form. GIT and PATH gems carry none.
//
// Trivy reference: pkg/dependency/parser/ruby/bundler/parse.go.
package bundler

import (
	"bufio"
	"bytes"
	"io"
	"strings"

	"github.com/chain305/chainsaw-core/depparser/origin"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type spec struct{ name, version, origin string }

func Parse(r io.Reader) ([]ftypes.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	// Max token = the whole file: Bundler ignores sections it does not know,
	// so a long line in one (a junk section) must not fail the parse — a
	// lockfile we cannot read is reported unparsed, not checked.
	sc.Buffer(make([]byte, 0, 64*1024), len(data)+1)

	var (
		specs    []spec
		seen     = map[spec]bool{}
		checks   = map[string][]string{} // name@version -> canonical hashes
		section  string
		remotes  []string
		revision string
		src      string
		inSpecs  bool
	)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			inSpecs = false
			continue
		}
		if line[0] != ' ' {
			section, remotes, revision, inSpecs = strings.TrimSpace(line), nil, "", false
			continue
		}
		trimmed := strings.TrimSpace(line)
		if section == "CHECKSUMS" {
			// "  name (version[-platform]) sha256=<hex>[,sha512=<hex>]"
			if name, ver, ok := nameVersion(trimmed); ok {
				if _, sums, ok := strings.Cut(trimmed, ") "); ok {
					for _, tok := range strings.Split(sums, ",") {
						if h := origin.NormalizeHash(tok); h != "" {
							checks[name+"@"+ver] = append(checks[name+"@"+ver], h)
						}
					}
				}
			}
			continue
		}
		if !inSpecs {
			if v, ok := strings.CutPrefix(trimmed, "remote:"); ok {
				remotes = append(remotes, strings.TrimSpace(v))
			} else if v, ok := strings.CutPrefix(trimmed, "revision:"); ok {
				revision = strings.TrimSpace(v)
			} else if trimmed == "specs:" {
				inSpecs = true
				src = sectionOrigin(section, remotes, revision)
			}
			continue
		}
		// Four-space lines are gems; deeper ones are their constraints.
		if !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "     ") {
			continue
		}
		name, ver, ok := nameVersion(trimmed)
		if !ok {
			continue
		}
		s := spec{name, ver, src}
		if !seen[s] {
			seen[s] = true
			specs = append(specs, s)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// One joined string per name@version, shared by every spec of it: N
	// source sections listing one gem against K checksum lines would
	// otherwise retain N×K hashes (2,000×2,000 in a 280 KB file ≈ 288 MB).
	joined := map[string]string{}
	out := make([]ftypes.Package, 0, len(specs))
	for _, s := range specs {
		p := ftypes.Package{Name: s.name, Version: s.version, Origin: s.origin}
		if s.origin == "" || strings.HasPrefix(s.origin, "registry+") {
			key := s.name + "@" + s.version
			h, ok := joined[key]
			if !ok {
				h = origin.JoinHashes(checks[key]...)
				joined[key] = h
			}
			p.Hash = h
		}
		out = append(out, p)
	}
	return out, nil
}

// nameVersion splits "name (1.2.3-x86_64-linux)" into name and version,
// dropping the platform.
func nameVersion(s string) (name, version string, ok bool) {
	i := strings.Index(s, " (")
	j := strings.Index(s, ")")
	if i <= 0 || j < i+2 {
		return "", "", false
	}
	name, version = s[:i], s[i+2:j]
	version, _, _ = strings.Cut(version, "-")
	return name, version, version != ""
}

// sectionOrigin is the Origin of every gem in a source section ("" for the
// public registry).
func sectionOrigin(section string, remotes []string, revision string) string {
	switch section {
	case "GEM":
		for _, r := range remotes {
			if origin.Classify("rubygems", r) != origin.Public {
				return origin.Sanitize("registry+" + r)
			}
		}
		return ""
	case "GIT":
		if len(remotes) == 1 {
			src := "git+" + remotes[0]
			if revision != "" {
				src += "#" + revision
			}
			return origin.Sanitize(src)
		}
	case "PATH":
		if len(remotes) == 1 {
			return origin.Sanitize("file:" + remotes[0])
		}
	}
	return origin.Sanitize(strings.ToLower(section) + " " + strings.Join(remotes, ", "))
}
