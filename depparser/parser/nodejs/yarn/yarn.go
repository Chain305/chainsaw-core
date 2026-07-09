// Package yarn parses yarn.lock files from both v1 (Yarn classic) and
// v2+ (Berry) layouts.
//
// v1 is a custom line-oriented format:
//
//	"@babel/core@^7.0.0", "@babel/core@~7.1":
//	  version "7.22.0"
//	  resolved "https://..."
//
// v2+ writes a YAML-ish header ("__metadata") and then per-descriptor
// entries with similar shape. We parse both by scanning for header lines
// (ending in ":") and a following `version "..."` line inside the
// indented block.
//
// Trivy reference: pkg/dependency/parser/nodejs/yarn/parse.go (richer —
// uses a proper scanner, emits integrity, reconstructs the dep graph).
// This port ignores everything except descriptor→version mapping.
package yarn

import (
	"bufio"
	"io"
	"strings"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

func Parse(r io.Reader) ([]ftypes.Package, error) {
	sc := bufio.NewScanner(r)
	// yarn.lock lines can be long for chained descriptors.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		out          []ftypes.Package
		pendingNames []string // names parsed from the current header
		seen         = map[string]bool{}
	)
	emit := func(name, version string) {
		if name == "" || version == "" {
			return
		}
		key := name + "@" + version
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, ftypes.Package{Name: name, Version: version})
	}

	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Header line: no leading space, ends with ":".
		// e.g. `"@babel/core@^7.0.0", "@babel/core@~7.1":`
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") {
			header := strings.TrimSuffix(trimmed, ":")
			pendingNames = pendingNames[:0]
			for _, desc := range splitDescriptors(header) {
				if name := descriptorName(desc); name != "" {
					pendingNames = append(pendingNames, name)
				}
			}
			continue
		}

		// version line inside an indented block.
		if strings.HasPrefix(trimmed, "version ") || strings.HasPrefix(trimmed, "version:") {
			v := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(trimmed, "version:"), "version"))
			v = strings.Trim(v, "\"")
			for _, n := range pendingNames {
				emit(n, v)
			}
			pendingNames = pendingNames[:0]
		}
	}
	return out, sc.Err()
}

// splitDescriptors splits a yarn header like
//
//	"@babel/core@^7.0.0", "@babel/core@~7.1"
//
// into the individual descriptor strings (without surrounding quotes).
func splitDescriptors(header string) []string {
	var out []string
	for _, raw := range strings.Split(header, ",") {
		raw = strings.TrimSpace(raw)
		raw = strings.Trim(raw, "\"")
		if raw != "" {
			out = append(out, raw)
		}
	}
	return out
}

// descriptorName extracts the package name from a descriptor like
// "@babel/core@^7.0.0" → "@babel/core", or "lodash@4.17.21" → "lodash".
// Yarn v2+ also uses "name@npm:^1.0" / "name@workspace:..." protocols,
// which we treat as normal name lookups (protocol is part of the version
// component, not the name).
func descriptorName(d string) string {
	// Scoped package: name is "@scope/pkg", the separator is the *next*
	// '@' after the scope.
	if strings.HasPrefix(d, "@") {
		idx := strings.Index(d[1:], "@")
		if idx < 0 {
			return d
		}
		return d[:idx+1]
	}
	idx := strings.Index(d, "@")
	if idx < 0 {
		return d
	}
	return d[:idx]
}
