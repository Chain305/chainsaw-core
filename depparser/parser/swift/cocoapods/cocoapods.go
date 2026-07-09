// Package cocoapods parses Podfile.lock.
//
// Format: YAML.
//
//	PODS:
//	  - Alamofire (5.6.0)
//	  - SwiftyJSON (5.0.0):
//	    - Alamofire
//	  - MyPod/Subspec (1.0.0)
//	DEPENDENCIES:
//	  - Alamofire (~> 5.0)
//
// The PODS list contains "<name> (<version>)" for each installed pod.
// Subspecs use "<parent>/<subspec>"; we keep only the parent since
// vuln DBs don't distinguish subspecs. Entries that are a mapping
// (pod with its own dep list) carry the "<name> (<ver>):" form.
//
// Trivy reference: pkg/dependency/parser/swift/cocoapods/parse.go.
package cocoapods

import (
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type lockfile struct {
	// PODS is heterogeneous: either strings "name (ver)" or
	// single-entry maps {"name (ver)": ["dep1", "dep2"]}. yaml.v3
	// surfaces both as `any`.
	PODS []any `yaml:"PODS"`
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
	seen := map[string]bool{}
	var out []ftypes.Package
	for _, item := range lf.PODS {
		var entry string
		switch v := item.(type) {
		case string:
			entry = v
		case map[string]any:
			for k := range v {
				entry = k
				break
			}
		}
		name, ver := splitPodEntry(entry)
		if name == "" || ver == "" {
			continue
		}
		k := name + "@" + ver
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, ftypes.Package{Name: name, Version: ver})
	}
	return out, nil
}

// splitPodEntry: "Alamofire (5.6.0)" → ("Alamofire", "5.6.0").
// Subspecs: "Alamofire/Combine (5.6.0)" → ("Alamofire", "5.6.0").
func splitPodEntry(s string) (string, string) {
	open := strings.Index(s, "(")
	close := strings.LastIndex(s, ")")
	if open < 0 || close <= open {
		return "", ""
	}
	name := strings.TrimSpace(s[:open])
	if i := strings.Index(name, "/"); i >= 0 {
		name = name[:i]
	}
	return name, strings.TrimSpace(s[open+1 : close])
}
