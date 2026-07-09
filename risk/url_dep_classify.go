package risk

// url_dep_classify.go — classifier for npm dependency version strings that
// point outside the registry hash chain.
//
// npm allows version strings to be:
//   - Registry references (semver, "latest", "^1.2.3", …)           → DepURLRegistry
//   - Git URLs (git+https://, git+ssh://, git://, github:user/repo)  → DepURLGit
//   - HTTP/HTTPS tarballs (https://example.com/pkg.tgz, …)          → DepURLHTTP
//   - Other (file:, npm:, …)                                         → DepURLOther
//
// Only Git and HTTP dependencies bypass the npm registry hash chain and are
// therefore of supply-chain interest. Registry-hosted mirrors
// (registry.npmjs.org, registry.yarnpkg.com) are excluded from the HTTP
// bucket so normal npm install commands do not trigger false positives.
//
// The classifier is intentionally kept small and pure (no I/O) so it can be
// unit-tested without external fixtures and called cheaply in the projection
// hot path.

import (
	"net/url"
	"strings"
)

// DepURLKind is the classification of a dependency version string.
type DepURLKind int

const (
	// DepURLRegistry is a normal registry reference (semver, tag, dist-tag).
	DepURLRegistry DepURLKind = iota
	// DepURLGit is a git-URL reference that bypasses the registry hash chain.
	DepURLGit
	// DepURLHTTP is an HTTP/HTTPS tarball URL pointing to a non-registry host.
	DepURLHTTP
	// DepURLOther is any other non-registry, non-git, non-http reference
	// (e.g. file:, npm:, workspace:). Not currently flagged by signals.
	DepURLOther
)

// knownRegistryHosts lists the registry CDN hosts that ship npm-compatible
// tarballs and are part of the normal publish/install chain. An HTTPS URL
// whose host matches one of these is classified as DepURLRegistry.
var knownRegistryHosts = map[string]bool{
	"registry.npmjs.org":     true,
	"registry.yarnpkg.com":   true,
	"registry.npmmirror.com": true, // CNPM mirror
	"r.cnpmjs.org":           true, // cnpmjs.org mirror
}

// gitPrefixes lists the well-known git URL prefixes recognised by npm.
// See https://docs.npmjs.com/cli/v9/configuring-npm/package-json#git-urls-as-dependencies
var gitPrefixes = []string{
	"git+https://",
	"git+ssh://",
	"git+http://",
	"git://",
	"git@",
}

// gitShorthands lists the host-shorthand prefixes that npm resolves as git.
// e.g. "github:user/repo", "bitbucket:user/repo".
var gitShorthands = []string{
	"github:",
	"bitbucket:",
	"gitlab:",
	"gist:",
}

// ClassifyDepURL returns the DepURLKind for a given npm dependency version
// string (the value side of a package.json dependency entry).
func ClassifyDepURL(version string) DepURLKind {
	v := strings.TrimSpace(version)
	if v == "" {
		return DepURLRegistry
	}

	// Git URL prefixes take priority.
	lower := strings.ToLower(v)
	for _, pfx := range gitPrefixes {
		if strings.HasPrefix(lower, pfx) {
			return DepURLGit
		}
	}
	// Git shorthands (github:user/repo etc.).
	for _, pfx := range gitShorthands {
		if strings.HasPrefix(lower, pfx) {
			return DepURLGit
		}
	}

	// HTTP / HTTPS tarball URL.
	if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://") {
		// Exclude known registry mirrors.
		if u, err := url.Parse(v); err == nil {
			if knownRegistryHosts[strings.ToLower(u.Host)] {
				return DepURLRegistry
			}
		}
		return DepURLHTTP
	}

	// Other non-registry forms (file:, npm:, workspace:, …).
	if strings.HasPrefix(lower, "file:") ||
		strings.HasPrefix(lower, "npm:") ||
		strings.HasPrefix(lower, "workspace:") ||
		strings.HasPrefix(lower, "link:") {
		return DepURLOther
	}

	// Everything else is a registry reference (semver range, tag, dist-tag).
	return DepURLRegistry
}
