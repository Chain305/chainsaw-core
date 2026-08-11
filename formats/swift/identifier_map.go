package swift

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// IdentifierMap resolves SPM `scope.name` identifiers to git clone URLs.
//
// Resolution order (first hit wins):
//  1. Explicit user-supplied entries (YAML config or RegisterStatic).
//  2. GitHub convention fallback — `scope.name` → https://github.com/<scope>/<name>.git.
//     Disabled by default because nothing binds an SPM identifier to a
//     repository: an attacker who registers the GitHub org `evil` thereby
//     satisfies every lookup for the identifier `evil.anything`, and the
//     proxy serves their code as the legitimate package. Enabling it
//     REQUIRES a non-empty org allowlist — see NewIdentifierMap.
//
// The SwiftPackageIndex seed mentioned in the plan is intentionally
// deferred to a follow-up: a background refresher with credential/network
// policy concerns doesn't fit into the same change that introduces the
// proxy surface. The static map + opt-in convention covers the two
// realistic production deployments (enterprise map in config, or trusted
// allowlist-of-orgs convention).
type IdentifierMap struct {
	mu                 sync.RWMutex
	static             map[string]string // lowercased id -> git URL
	reverse            map[string]string // lowercased canonical git URL -> id
	githubConvention   bool
	githubOrgAllowList map[string]bool // lowercased org names
}

// IdentifierMapConfig configures IdentifierMap construction.
type IdentifierMapConfig struct {
	// Static maps lowercased `scope.name` identifiers to git clone URLs.
	Static map[string]string
	// EnableGitHubConvention turns on the `scope.name` → github.com/<scope>/<name>
	// fallback. Defaults to false. When true, GitHubOrgAllowList MUST be
	// non-empty — NewIdentifierMap rejects the combination otherwise.
	EnableGitHubConvention bool
	// GitHubOrgAllowList restricts the GitHub convention fallback to the
	// listed (case-insensitive) scopes. Required whenever
	// EnableGitHubConvention is true; it is the only thing standing between
	// the convention and a scope-squatting attacker.
	GitHubOrgAllowList []string
}

// ErrConventionWithoutAllowList is returned when the GitHub convention
// fallback is requested with no org allowlist to constrain it. Callers
// should treat this as a fatal misconfiguration: an unconstrained
// convention lets anyone who registers a GitHub org serve arbitrary code
// as any `<that-org>.<anything>` Swift package.
var ErrConventionWithoutAllowList = errors.New(
	"swift: github_convention requires a non-empty github_org_allowlist " +
		"(an unconstrained name→URL guess is a scope-squatting vector); " +
		"either populate swift.github_org_allowlist or set swift.github_convention=false")

// normalizeOrgAllowList lowercases, trims, and drops empty entries.
func normalizeOrgAllowList(orgs []string) map[string]bool {
	out := make(map[string]bool, len(orgs))
	for _, org := range orgs {
		org = strings.ToLower(strings.TrimSpace(org))
		if org != "" {
			out[org] = true
		}
	}
	return out
}

// NewIdentifierMap constructs an IdentifierMap from config.
//
// It fails closed: enabling EnableGitHubConvention without a non-empty
// GitHubOrgAllowList returns ErrConventionWithoutAllowList rather than
// silently granting the risky mode. This is the single choke point for
// the invariant — every construction path (YAML file, DB settings,
// programmatic) goes through here.
func NewIdentifierMap(cfg IdentifierMapConfig) (*IdentifierMap, error) {
	allowList := normalizeOrgAllowList(cfg.GitHubOrgAllowList)
	if cfg.EnableGitHubConvention && len(allowList) == 0 {
		return nil, ErrConventionWithoutAllowList
	}
	m := &IdentifierMap{
		static:             make(map[string]string),
		reverse:            make(map[string]string),
		githubConvention:   cfg.EnableGitHubConvention,
		githubOrgAllowList: allowList,
	}
	for id, gitURL := range cfg.Static {
		m.RegisterStatic(id, gitURL)
	}
	return m, nil
}

// IdentifierMapFile is the parsed contents of an identifier-map YAML
// file. GitHubConvention is a pointer so callers can distinguish
// "absent" (inherit the deployment-level setting) from an explicit
// `github_convention: false`.
type IdentifierMapFile struct {
	Identifiers        map[string]string `yaml:"identifiers"`
	GitHubConvention   *bool             `yaml:"github_convention"`
	GitHubOrgAllowList []string          `yaml:"github_org_allowlist"`
}

// ParseIdentifierMapYAML reads and parses an identifier-map YAML file of
// the form:
//
//	identifiers:
//	  apple.swift-nio: "https://github.com/apple/swift-nio.git"
//	  vapor.vapor: "https://github.com/vapor/vapor.git"
//	github_convention: false
//	github_org_allowlist: ["apple", "vapor"]
//
// An empty path or a missing file yields a zero-value IdentifierMapFile
// so an unconfigured deployment still works. A malformed file is an
// error.
//
// Parsing is deliberately separated from construction so callers can
// merge these values with deployment-level settings (see
// internal/repository.buildSwiftGitUpstream) before handing the result
// to NewIdentifierMap, which enforces the allowlist invariant.
func ParseIdentifierMapYAML(path string) (IdentifierMapFile, error) {
	var raw IdentifierMapFile
	path = strings.TrimSpace(path)
	if path == "" {
		return raw, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return IdentifierMapFile{}, nil
		}
		return IdentifierMapFile{}, fmt.Errorf("read identifier map: %w", err)
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return IdentifierMapFile{}, fmt.Errorf("parse identifier map: %w", err)
	}
	return raw, nil
}

// LoadIdentifierMapFromYAML parses the file at path and builds an
// IdentifierMap from it alone, with no deployment-level defaults merged
// in. Returns ErrConventionWithoutAllowList if the file turns the GitHub
// convention on without an allowlist.
func LoadIdentifierMapFromYAML(path string) (*IdentifierMap, error) {
	raw, err := ParseIdentifierMapYAML(path)
	if err != nil {
		return nil, err
	}
	convention := raw.GitHubConvention != nil && *raw.GitHubConvention
	return NewIdentifierMap(IdentifierMapConfig{
		Static:                 raw.Identifiers,
		EnableGitHubConvention: convention,
		GitHubOrgAllowList:     raw.GitHubOrgAllowList,
	})
}

// RegisterStatic records a `scope.name` → git URL mapping.
func (m *IdentifierMap) RegisterStatic(identifier, gitURL string) {
	identifier = strings.ToLower(strings.TrimSpace(identifier))
	gitURL = strings.TrimSpace(gitURL)
	if identifier == "" || gitURL == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.static[identifier] = gitURL
	m.reverse[canonicalGitURL(gitURL)] = identifier
}

// Resolve returns the git URL for `scope.name`, or ("", false) if
// unknown and convention fallback is disabled.
func (m *IdentifierMap) Resolve(identifier string) (string, bool) {
	identifier = strings.ToLower(strings.TrimSpace(identifier))
	if identifier == "" {
		return "", false
	}
	m.mu.RLock()
	if u, ok := m.static[identifier]; ok {
		m.mu.RUnlock()
		return u, true
	}
	convention := m.githubConvention
	allowList := m.githubOrgAllowList
	m.mu.RUnlock()

	if !convention {
		return "", false
	}
	scope, name := SplitIdentifier(identifier)
	if scope == "" || name == "" {
		return "", false
	}
	// Strict: an empty allowlist denies everything rather than allowing
	// everything. NewIdentifierMap already refuses that combination, but a
	// same-package struct literal must not be able to reopen the hole.
	if !allowList[scope] {
		return "", false
	}
	return fmt.Sprintf("https://github.com/%s/%s.git", scope, name), true
}

// ReverseLookup returns the identifier for a git URL previously
// registered, or ("", false) if unknown. Used to serve SE-0292
// `/identifiers?url=<git-url>` responses.
//
// Lookup order mirrors Resolve:
//  1. Explicit reverse map (populated by RegisterStatic / YAML config).
//  2. GitHub convention fallback — when GitHubConvention is enabled and the
//     canonical URL is `https://github.com/<scope>/<name>` with `<scope>`
//     in the allowlist, synthesize `<scope>.<name>`. Without this the
//     SwiftPM `/identifiers?url=…` probe would 404 for convention-only
//     packages and SwiftPM would silently fall back to a direct git clone,
//     bypassing the proxy.
func (m *IdentifierMap) ReverseLookup(gitURL string) (string, bool) {
	canon := canonicalGitURL(gitURL)
	if canon == "" {
		return "", false
	}
	m.mu.RLock()
	if id, ok := m.reverse[canon]; ok {
		m.mu.RUnlock()
		return id, true
	}
	convention := m.githubConvention
	allowList := m.githubOrgAllowList
	m.mu.RUnlock()

	if !convention {
		return "", false
	}
	// canonicalGitURL normalises to https://<host><path> with host lowercased,
	// trailing `.git` and trailing `/` stripped, and path lowercased.
	const ghPrefix = "https://github.com/"
	if !strings.HasPrefix(canon, ghPrefix) {
		return "", false
	}
	rest := canon[len(ghPrefix):]
	// rest should be exactly `<scope>/<name>` — anything deeper (subpaths,
	// fragments, etc.) is not a convention-eligible repo URL.
	slash := strings.Index(rest, "/")
	if slash <= 0 || slash == len(rest)-1 {
		return "", false
	}
	scope := rest[:slash]
	name := rest[slash+1:]
	if strings.Contains(name, "/") {
		return "", false
	}
	// Strict, mirroring Resolve: empty allowlist denies.
	if !allowList[scope] {
		return "", false
	}
	return scope + "." + name, true
}

// canonicalGitURL lowercases the host, strips a trailing ".git" and
// trailing slash, and normalizes to https:// so small URL variants
// (http vs https, trailing .git, uppercase org name) map to the same
// reverse-lookup key.
func canonicalGitURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.ToLower(raw)
	}
	host := strings.ToLower(u.Host)
	path := strings.TrimSuffix(u.Path, "/")
	path = strings.TrimSuffix(path, ".git")
	path = strings.ToLower(path)
	return "https://" + host + path
}
