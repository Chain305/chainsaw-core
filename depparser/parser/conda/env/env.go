// Package env parses conda environment.yml files.
//
// Format: YAML.
//
//	name: myenv
//	dependencies:
//	  - python=3.9
//	  - numpy=1.21.0
//	  - pip:
//	    - requests==2.31.0
//
// Conda deps use "name=version" or "name" (unpinned) or "name=version=build".
// Pip sub-lists use PEP 508 syntax ("name==version"). We extract both.
// Unpinned entries are skipped — a vuln scan needs a version.
//
// Trivy reference: pkg/fanal/analyzer/language/python/conda_env (analyzer
// layer; parser is inlined). Conda packages (conda-meta/*.json) are a
// separate format handled by a different analyzer.
package env

import (
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type envFile struct {
	Name         string `yaml:"name"`
	Dependencies []any  `yaml:"dependencies"`
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var f envFile
	if err := yaml.Unmarshal(buf, &f); err != nil {
		return nil, err
	}
	var out []ftypes.Package
	for _, item := range f.Dependencies {
		switch v := item.(type) {
		case string:
			if name, ver := splitConda(v); name != "" && ver != "" {
				out = append(out, ftypes.Package{Name: name, Version: ver})
			}
		case map[string]any:
			// pip sub-list
			if pipDeps, ok := v["pip"].([]any); ok {
				for _, pd := range pipDeps {
					if s, ok := pd.(string); ok {
						if name, ver := splitPip(s); name != "" && ver != "" {
							out = append(out, ftypes.Package{Name: name, Version: ver})
						}
					}
				}
			}
		}
	}
	return out, nil
}

// splitConda: "numpy=1.21.0[=build]" → ("numpy", "1.21.0").
func splitConda(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	parts := strings.Split(s, "=")
	if len(parts) < 2 {
		return "", ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

// splitPip: "requests==2.31.0" → ("requests", "2.31.0"). Strips extras
// like "requests[security]==2.31.0".
func splitPip(s string) (string, string) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "=="); i > 0 {
		name := s[:i]
		if j := strings.Index(name, "["); j > 0 {
			name = name[:j]
		}
		return strings.TrimSpace(name), strings.TrimSpace(s[i+2:])
	}
	return "", ""
}
