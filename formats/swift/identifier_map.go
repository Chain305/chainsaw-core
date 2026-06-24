package swift

import (
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
//     Disabled by default because an attacker who controls `evil` on GitHub
//     could otherwise satisfy lookups for the identifier `evil.anything`.
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
	// fallback. Defaults to false; if true, prefer also setting
	// GitHubOrgAllowList to constrain which scopes can be auto-translated.
	EnableGitHubConvention bool
	// GitHubOrgAllowList, when non-empty, restricts the GitHub convention
	// fallback to the listed (case-insensitive) scopes.
	GitHubOrgAllowList []string
}

// NewIdentifierMap constructs an IdentifierMap from config.
func NewIdentifierMap(cfg IdentifierMapConfig) *IdentifierMap {
	m := &IdentifierMap{
		static:             make(map[string]string),
		reverse:            make(map[string]string),
		githubConvention:   cfg.EnableGitHubConvention,
		githubOrgAllowList: make(map[string]bool),
	}
	for id, gitURL := range cfg.Static {
		m.RegisterStatic(id, gitURL)
	}
	for _, org := range cfg.GitHubOrgAllowList {
		org = strings.ToLower(strings.TrimSpace(org))
		if org != "" {
			m.githubOrgAllowList[org] = true
		}
	}
	return m
}

// LoadIdentifierMapFromYAML loads a YAML file of the form:
//
//	identifiers:
//	  apple.swift-nio: "https://github.com/apple/swift-nio.git"
//	  vapor.vapor: "https://github.com/vapor/vapor.git"
//	github_convention: false
//	github_org_allowlist: ["apple", "vapor"]
//
// Returns an error if the file is malformed. Missing file returns
// (empty map, nil) so an unconfigured deployment still works.
func LoadIdentifierMapFromYAML(path string) (*IdentifierMap, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return NewIdentifierMap(IdentifierMapConfig{}), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return NewIdentifierMap(IdentifierMapConfig{}), nil
		}
		return nil, fmt.Errorf("read identifier map: %w", err)
	}
	var raw struct {
		Identifiers        map[string]string `yaml:"identifiers"`
		GitHubConvention   bool              `yaml:"github_convention"`
		GitHubOrgAllowList []string          `yaml:"github_org_allowlist"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse identifier map: %w", err)
	}
	return NewIdentifierMap(IdentifierMapConfig{
		Static:                 raw.Identifiers,
		EnableGitHubConvention: raw.GitHubConvention,
		GitHubOrgAllowList:     raw.GitHubOrgAllowList,
	}), nil
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
	if len(allowList) > 0 && !allowList[scope] {
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
	if len(allowList) > 0 && !allowList[scope] {
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
