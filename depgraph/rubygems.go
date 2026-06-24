package depgraph

// RubyGems: GIT and PATH gems are now graphed (Wave 7 follow-up to the
// Wave 1 limitation).
//
// Bundler ships a real lockfile — Gemfile.lock — but its format is not
// YAML despite the visual similarity. It is a custom, indent-sensitive
// text format with a small set of top-level sections. We use three:
//
//	GEM
//	  remote: https://rubygems.org/
//	  specs:
//	    actionpack (7.0.4)
//	      actionview (= 7.0.4)
//	      rack (~> 2.0, >= 2.2.0)
//	    actionview (7.0.4)
//	      activesupport (= 7.0.4)
//
//	GIT
//	  remote: https://github.com/rails/rails.git
//	  revision: abc1234
//	  specs:
//	    rails (7.1.0)
//	      activesupport (= 7.1.0)
//
//	PATH
//	  remote: ../my-local-gem
//	  specs:
//	    my-local-gem (0.1.0)
//
//	DEPENDENCIES
//	  actionpack (~> 7.0.4)
//	  rails!
//	  my-local-gem!
//	  rake
//
// Indentation rules inside <SECTION>/specs:: are shared across GEM,
// GIT, and PATH:
//   - 4 spaces: a fully-resolved spec, "<name> (<version>)" — this is a
//     graph node. Identity is the gem name; the version is already
//     resolved by Bundler, no constraint solving needed.
//   - 6 spaces: a child dep line, "<dep_name> (<requirement>)" — the
//     requirement string is informational only. The dep name resolves
//     to whichever sibling 4-indent spec shares that name.
//
// Inside DEPENDENCIES, 2-space indent means "this is a root entry"
// (i.e. what the Gemfile literally declared). The "!" suffix marks a
// pin to a GIT/PATH source; we resolve the bare name against any of
// the spec blocks above. The version-or-constraint in parens is
// ignored; we resolve roots by name against the merged specs index to
// recover the locked version.
//
// Edges leading into a GIT- or PATH-sourced gem carry a "source"
// attribute ("git" or "path") via Graph.AddEdgeAttr — the same
// edge-metadata machinery used for Gradle configs and Maven scope.
// GEM-sourced edges carry no source attribute (the absence implies
// rubygems.org).
//
// Other sections (PLATFORMS, BUNDLED WITH, RUBY VERSION, PLUGIN,
// CHECKSUMS, …) are still skipped.

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// ParseGemfileLockfile parses a Bundler Gemfile.lock into a Graph.
// Identity is (ecosystem="rubygems", name=gem name, version=locked
// version from any of the GEM/GIT/PATH specs: blocks). Roots are the
// entries declared in the DEPENDENCIES block, resolved by name against
// the merged specs index.
//
// Edges into GIT- or PATH-sourced gems carry a "source" edge attribute
// ("git" or "path") so callers can distinguish them downstream;
// rubygems.org-sourced edges carry no source attribute.
//
// Limitations:
//   - When the same gem name appears in two different source sections
//     (e.g. GEM and GIT) the lockfile is malformed by Bundler's own
//     rules — we accept the LAST occurrence wins, since Bundler in
//     practice never emits this.
//   - Bundler version requirement strings on child dep lines (e.g.
//     "(~> 2.0, >= 2.2.0)") are not parsed — the name alone is used to
//     resolve the edge endpoint, which is correct because Bundler has
//     already pinned a single resolved version per gem in the same
//     specs: block.
func ParseGemfileLockfile(data []byte) (*Graph, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	type rawDep struct {
		parent string
		child  string
	}
	var (
		section     string // current top-level section name
		inSpecs     bool   // true inside a <section>/specs: subsection
		currentSpec string // most recent 4-indent spec name (parent for 6-indent dep lines)
		specVersion = map[string]string{}
		specSource  = map[string]string{} // gem name → "" | "git" | "path"
		deps        []rawDep
		rootNames   []string
		seenAnyTok  bool
	)

	specsBearing := map[string]bool{"GEM": true, "GIT": true, "PATH": true}

	for scanner.Scan() {
		raw := scanner.Text()
		if strings.TrimSpace(raw) == "" {
			// Blank line resets section context: Bundler separates
			// top-level sections with a blank line.
			section = ""
			inSpecs = false
			currentSpec = ""
			continue
		}
		seenAnyTok = true

		indent := leadingSpaces(raw)
		trimmed := strings.TrimSpace(raw)

		// New top-level section header (no indent, no parens).
		if indent == 0 {
			section = trimmed
			inSpecs = false
			currentSpec = ""
			continue
		}

		switch {
		case specsBearing[section]:
			// GEM, GIT, and PATH all share the same specs: block layout.
			// "specs:" header sits at indent 2; specs at indent 4;
			// child deps at indent 6.
			if indent == 2 && trimmed == "specs:" {
				inSpecs = true
				currentSpec = ""
				continue
			}
			if !inSpecs {
				// "remote:" / "revision:" / "ref:" / "branch:" / etc.
				continue
			}
			if indent == 4 {
				name, version, ok := splitGemSpec(trimmed)
				if !ok {
					return nil, fmt.Errorf("depgraph/rubygems: malformed spec line: %q", raw)
				}
				specVersion[name] = version
				switch section {
				case "GIT":
					specSource[name] = "git"
				case "PATH":
					specSource[name] = "path"
				}
				currentSpec = name
				continue
			}
			if indent == 6 {
				if currentSpec == "" {
					return nil, fmt.Errorf("depgraph/rubygems: child dep without parent spec: %q", raw)
				}
				childName, _, ok := splitGemDep(trimmed)
				if !ok {
					return nil, fmt.Errorf("depgraph/rubygems: malformed dep line: %q", raw)
				}
				deps = append(deps, rawDep{parent: currentSpec, child: childName})
				continue
			}

		case section == "DEPENDENCIES":
			// Each line at indent 2 is a root: "<name>" or
			// "<name> (<requirement>)" or "<name>!" (pinned to GIT/PATH).
			if indent == 2 {
				name := trimmed
				// Bundler appends "!" to deps locked to GIT/PATH sources.
				// Strip it for resolution — the merged specs index covers
				// all three source sections.
				name = strings.TrimSuffix(name, "!")
				if i := strings.Index(name, " "); i >= 0 {
					name = name[:i]
				}
				if name == "" {
					return nil, fmt.Errorf("depgraph/rubygems: malformed dependency line: %q", raw)
				}
				rootNames = append(rootNames, name)
				continue
			}

		default:
			// PLATFORMS, BUNDLED WITH, PLUGIN, CHECKSUMS, etc.
			continue
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("depgraph/rubygems: scan: %w", err)
	}
	if !seenAnyTok {
		return nil, fmt.Errorf("depgraph/rubygems: empty Gemfile.lock input")
	}
	if len(specVersion) == 0 {
		return nil, fmt.Errorf("depgraph/rubygems: no GEM/specs block found")
	}
	if len(rootNames) == 0 {
		return nil, fmt.Errorf("depgraph/rubygems: no DEPENDENCIES block found")
	}

	g := NewGraph()
	for name, version := range specVersion {
		g.AddNode(Key{Ecosystem: "rubygems", Name: name, Version: version}, false, true)
	}
	for _, name := range rootNames {
		version, ok := specVersion[name]
		if !ok {
			// Root referenced from DEPENDENCIES but no matching spec —
			// e.g. PLUGIN-sourced gem we don't model. Skip silently.
			continue
		}
		k := Key{Ecosystem: "rubygems", Name: name, Version: version}
		g.AddNode(k, true, true)
		g.AddRoot(k)
	}
	for _, d := range deps {
		parentVer, ok := specVersion[d.parent]
		if !ok {
			continue
		}
		childVer, ok := specVersion[d.child]
		if !ok {
			// Child is e.g. a bundler self-dep ("bundler") which
			// commonly appears without a spec entry; skip the edge.
			continue
		}
		from := Key{Ecosystem: "rubygems", Name: d.parent, Version: parentVer}
		to := Key{Ecosystem: "rubygems", Name: d.child, Version: childVer}
		g.AddEdge(from, to)
		if src := specSource[d.child]; src != "" {
			g.AddEdgeAttr(from, to, "source", src)
		}
	}

	return g, nil
}

// leadingSpaces counts ASCII spaces at the start of s. Bundler always
// emits spaces (never tabs) so we don't bother tab-expanding.
func leadingSpaces(s string) int {
	n := 0
	for n < len(s) && s[n] == ' ' {
		n++
	}
	return n
}

// splitGemSpec parses "<name> (<version>)" — the resolved-spec form
// inside GEM/specs:.
func splitGemSpec(line string) (string, string, bool) {
	open := strings.LastIndex(line, "(")
	close := strings.LastIndex(line, ")")
	if open <= 0 || close <= open+1 || close != len(line)-1 {
		return "", "", false
	}
	name := strings.TrimSpace(line[:open])
	version := strings.TrimSpace(line[open+1 : close])
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}

// splitGemDep parses a dep line — either "<name>" or
// "<name> (<requirement>)". The requirement is returned for
// completeness but the parser does not act on it; Bundler has already
// resolved every gem in the GEM specs block.
func splitGemDep(line string) (string, string, bool) {
	if line == "" {
		return "", "", false
	}
	open := strings.LastIndex(line, "(")
	if open < 0 {
		// Bare name — valid (e.g. "rake" with no constraint).
		name := strings.TrimSpace(line)
		if name == "" {
			return "", "", false
		}
		return name, "", true
	}
	close := strings.LastIndex(line, ")")
	if close != len(line)-1 || close <= open+1 {
		return "", "", false
	}
	name := strings.TrimSpace(line[:open])
	req := strings.TrimSpace(line[open+1 : close])
	if name == "" {
		return "", "", false
	}
	return name, req, true
}
