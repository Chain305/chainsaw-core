// Package types is chainsaw's unified vendor of github.com/aquasecurity/
// trivy/pkg/fanal/types. It is the single source of truth for:
//
//   - LangType constants — ecosystem identifiers used by both the
//     dependency parsers (internal/depparser/**) and the vulnerability
//     detector drivers (internal/vulnscan/internal/detector).
//
//   - Package, Dependency, PkgIdentifier, Location — struct subset
//     referenced by vendored parser code. Upstream carries more fields
//     (OCI layer metadata, file byte ranges, SPDX license lists) that
//     neither of chainsaw's consumers uses.
//
// Consumers import as:
//
//	ftypes "github.com/chain305/chainsaw-core/fanal"
//
// String values for each LangType MUST match Trivy upstream so package
// identifiers emitted by a parser can feed the detector (and the
// trivy-db keyed on those same strings) unchanged.
//
// Prior to unification there were two copies of this file —
// internal/vulnscan/internal/fanal/lang.go and
// internal/depparser/fanal/types.go — whose constants were
// string-equivalent but drift-prone. This file is the union of both.
package types

// LangType is an ecosystem identifier.
type LangType string

const (
	// Ruby
	Bundler LangType = "bundler"
	GemSpec LangType = "gemspec"

	// Rust
	Cargo      LangType = "cargo"
	RustBinary LangType = "rustbinary"

	// PHP
	Composer       LangType = "composer"
	ComposerVendor LangType = "composer-vendor"

	// Node.js
	Npm        LangType = "npm"
	Bun        LangType = "bun"
	Yarn       LangType = "yarn"
	Pnpm       LangType = "pnpm"
	NodePkg    LangType = "node-pkg"
	JavaScript LangType = "javascript"

	// .NET / C#
	NuGet         LangType = "nuget"
	DotNetCore    LangType = "dotnet-core"
	PackagesProps LangType = "packages-props"

	// Python
	Pip       LangType = "pip"
	Pipenv    LangType = "pipenv"
	Poetry    LangType = "poetry"
	Uv        LangType = "uv"
	PyLock    LangType = "pylock"
	PythonPkg LangType = "python-pkg"
	CondaPkg  LangType = "conda-pkg"
	CondaEnv  LangType = "conda-environment"

	// JVM
	Jar    LangType = "jar"
	Pom    LangType = "pom"
	Gradle LangType = "gradle"
	Sbt    LangType = "sbt"

	// Go
	GoBinary LangType = "gobinary"
	GoModule LangType = "gomod"

	// Other
	Conan       LangType = "conan"
	Cocoapods   LangType = "cocoapods"
	Swift       LangType = "swift"
	Pub         LangType = "pub"
	Hex         LangType = "hex"
	Bitnami     LangType = "bitnami"
	Julia       LangType = "julia"
	K8sUpstream LangType = "kubernetes"

	// OS package managers — used by the OCI layer extractors
	// (internal/hooks/docker_oci_extractor_*.go) and by the driver
	// when routing OS-package advisories to a version comparer.
	// Value MUST match trivy-db's bucket prefix convention so the
	// shared advisory store keys line up.
	Dpkg LangType = "dpkg"

	// Red Hat / RHEL-family rpm package databases. Different storage
	// backends ship in different RHEL majors (BDB on RHEL 7,
	// SQLite as default on RHEL 8/9, NDB on some SUSE/Fedora variants,
	// `rpm -qa` text dumps in scratch / non-standard images). All four
	// feed the same rpm comparer and the redhat ecosystem driver.
	RpmQa     LangType = "rpm-qa"
	RpmSqlite LangType = "rpm-sqlite"
	RpmBdb    LangType = "rpm-bdb"
	RpmNdb    LangType = "rpm-ndb"

	// Alpine Linux apk package database. The OCI apk extractor
	// (NewAPKExtractor in internal/hooks/docker_oci_extractor.go)
	// emits packages parsed from /lib/apk/db/installed; this ftype
	// routes them to the alpine ecosystem driver. Branch detection
	// (3.18 vs 3.19 vs edge) is handled separately via
	// /etc/alpine-release in DetectDistro and plumbed via package
	// metadata, not via the ftype.
	Apk LangType = "apk"
)

// PkgIdentifier is the stable identity of a package across ecosystems.
// Only BOMRef is routinely filled by the vendored parsers; UID is
// computed by dependency.UID() (currently not vendored — see
// internal/depparser/dependency/id.go). PURL is a placeholder for the
// upstream packageurl-go.PackageURL type.
type PkgIdentifier struct {
	UID    string
	PURL   any
	BOMRef string
}

// Package is one dependency emitted by a parser. Fields match upstream
// Trivy's ftypes.Package for the subset chainsaw actually reads; upstream
// carries ~15 more fields (maintainer, layer, digest, dev vs prod graph)
// that the current vuln-scan pipeline does not consume.
type Package struct {
	ID         string
	Name       string
	Version    string
	Dev        bool
	Indirect   bool
	Licenses   []string
	Locations  []Location
	FilePath   string
	Identifier PkgIdentifier
}

// Location is a byte-span inside a lock file that produced a Package.
type Location struct {
	StartLine int
	EndLine   int
}

// Dependency is one edge in a dependency graph — "package ID DependsOn
// others". Parsers that don't build graphs (e.g. requirements.txt) emit
// no Dependency records, just Packages.
type Dependency struct {
	ID        string
	DependsOn []string
}
