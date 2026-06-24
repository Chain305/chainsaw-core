// Package dependency is a minimal vendor of github.com/aquasecurity/trivy/pkg/dependency.
//
// The upstream package exports two helpers:
//   - ID(langType, name, version) — deterministic textual ID for a package.
//   - UID(filePath, pkg) — content hash over a filePath+pkg tuple.
//
// Only ID is vendored. UID pulls in github.com/mitchellh/hashstructure/v2
// and is only used by upstream analyzers that need to disambiguate two
// packages with the same ID from different lock files — something chainsaw's
// current scan pipeline does not do. If that capability is needed later,
// wire in the hash dep and copy UID verbatim.
package dependency

import (
	"strings"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

// ID returns a deterministic, language-appropriate identifier for a package.
// Kept byte-for-byte equivalent to upstream so IDs emitted by chainsaw's
// vendored parsers collide correctly with IDs emitted by the vuln detector.
func ID(ltype ftypes.LangType, name, version string) string {
	if version == "" {
		return name
	}
	sep := "@"
	switch ltype {
	case ftypes.Conan, ftypes.DotNetCore:
		sep = "/"
	case ftypes.GoModule, ftypes.GoBinary:
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
	case ftypes.Jar, ftypes.Pom, ftypes.Gradle, ftypes.Sbt:
		sep = ":"
	}
	return name + sep + version
}
