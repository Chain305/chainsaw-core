// Package bundler parses Gemfile.lock.
//
// Format: text, section-based. We only read the GEM section's `specs:`
// subtree, where each line at two-space indent is "<name> (<version>)"
// and sub-indented lines are transitive constraints (ignored).
//
//	GEM
//	  remote: https://rubygems.org/
//	  specs:
//	    actioncable (7.0.4)
//	      actionpack (= 7.0.4)
//	    rails (7.0.4)
//
// Other sections (GIT, PATH, PLATFORMS, DEPENDENCIES, BUNDLED WITH) are
// skipped. Gems pulled from GIT/PATH with no upstream version are also
// skipped here — Trivy's parser captures them separately.
//
// Trivy reference: pkg/dependency/parser/ruby/bundler/parse.go.
package bundler

import (
	"bufio"
	"io"
	"strings"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

func Parse(r io.Reader) ([]ftypes.Package, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		out     []ftypes.Package
		inGem   bool
		inSpecs bool
	)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Top-level section headers have no leading space.
		if !strings.HasPrefix(line, " ") {
			inGem = trimmed == "GEM"
			inSpecs = false
			continue
		}
		if !inGem {
			continue
		}
		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}
		// Spec lines are at 4 spaces. Sub-spec constraint lines are
		// at 6 spaces — we skip those.
		if strings.HasPrefix(line, "      ") {
			continue
		}
		if !strings.HasPrefix(line, "    ") {
			inSpecs = false
			continue
		}
		// "    name (1.2.3)" or "    name (1.2.3-platform)"
		entry := strings.TrimSpace(line)
		openIdx := strings.Index(entry, "(")
		closeIdx := strings.LastIndex(entry, ")")
		if openIdx < 0 || closeIdx < 0 || closeIdx <= openIdx {
			continue
		}
		name := strings.TrimSpace(entry[:openIdx])
		ver := strings.TrimSpace(entry[openIdx+1 : closeIdx])
		if name == "" || ver == "" {
			continue
		}
		out = append(out, ftypes.Package{Name: name, Version: ver})
	}
	return out, sc.Err()
}
