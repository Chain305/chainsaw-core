package capability

import "strings"

// scanFunc walks an extracted package directory and returns the detected
// capabilities, their evidence (at most MaxEvidencePerCap each) and the total
// number of matching lines per capability.
type scanFunc func(pkgDir string) (map[Capability][]Evidence, map[Capability]int, error)

// ecosystemScanners maps an ecosystem name (and its aliases) to its scanner.
// Each ecosystem registers itself from its own file's init(), so adding one
// never edits this file.
var ecosystemScanners = map[string]scanFunc{}

// registerScanner wires fn for every named ecosystem. Called from init().
func registerScanner(fn scanFunc, ecosystems ...string) {
	for _, e := range ecosystems {
		ecosystemScanners[strings.ToLower(e)] = fn
	}
}

func init() {
	registerScanner(scanNPMCounted, "npm", "yarn", "bun", "pnpm")
}

// Supported reports whether a capability scanner exists for ecosystem.
func Supported(ecosystem string) bool {
	_, ok := ecosystemScanners[strings.ToLower(strings.TrimSpace(ecosystem))]
	return ok
}

// Analyze walks pkgDir and returns a capability Report for the given
// ecosystem. Ecosystems without a scanner return an unsupported stub so
// callers can distinguish "clean scan" from "not implemented".
//
// pkgDir must be a directory containing the already-extracted package
// contents, with any single wrapping directory (npm's "package/") removed.
//
// A non-nil error is returned only for I/O failures on supported paths.
func Analyze(pkgDir, ecosystem string) (*Report, error) {
	fn, ok := ecosystemScanners[strings.ToLower(strings.TrimSpace(ecosystem))]
	if !ok {
		return &Report{Ecosystem: ecosystem, Unsupported: true}, nil
	}
	caps, counts, err := fn(pkgDir)
	if err != nil {
		return nil, err
	}
	return &Report{Ecosystem: ecosystem, Capabilities: caps, Counts: counts}, nil
}
