package provenance

import "context"

// EcosystemChecker is the per-ecosystem provenance verifier contract. One
// implementation per file (npm.go, pypi.go, maven.go, ...).
type EcosystemChecker interface {
	// Ecosystem returns the canonical ecosystem name populated on Result
	// (e.g. "npm", "pip", "maven"). Registration aliases are handled by the
	// top-level Checker.
	Ecosystem() string

	// Check performs the verification. Returning StatusUnavailable with a
	// populated Error is valid for ecosystems that cannot (yet) verify but
	// want to explain why to callers.
	Check(ctx context.Context, packageName, version string) Result
}

// SourceAwareChecker is implemented by ecosystem checkers that need a
// repo/registry URL beyond (name, version). OS package ecosystems (APT,
// DNF, YUM) need this because the repository URL determines which
// keyring signs the metadata.
type SourceAwareChecker interface {
	EcosystemChecker
	CheckWithSource(ctx context.Context, packageName, version, sourceURL string) Result
}
