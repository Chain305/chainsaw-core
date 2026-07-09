package common

// CoordinateResolver extracts package/version information from relative paths.
type CoordinateResolver interface {
	Describe(path string) (PackageCoordinate, bool)
	// Format returns the package-manager format identifier (e.g. "npm", "pip", "docker").
	Format() string
}

// PackageCoordinate mirrors Nexus' Component coordinate concept.
type PackageCoordinate struct {
	Name    string
	Version string
	Format  string
	// Subtype optionally narrows the artifact class within a format. It is
	// empty for traditional package ecosystems (npm, pypi, maven, ...). AI
	// artifact subtypes use stable strings: "model", "dataset", "space",
	// "agent-tool", "mcp-server", "prompt-template". Consumers must treat an
	// unknown value as opaque and not dispatch on it.
	Subtype string
}
