// Package hook wires the chainsaw CLI into package-manager configuration so
// installs can be audited or proxied through the chainsaw server.
package hook

import (
	"errors"
	"fmt"
)

// Scope picks which config file the manager edits. ScopeUser points at the
// per-user global (e.g. ~/.npmrc); ScopeProject points at the current working
// directory's project-level equivalent (e.g. ./.npmrc). Implementations
// choose the exact path — pip, for instance, prefers $VIRTUAL_ENV/pip.conf
// when that env var is set.
type Scope string

const (
	ScopeUser    Scope = "user"
	ScopeProject Scope = "project"
	// ScopeSystem writes to the machine-wide config location for the
	// manager (/etc/npmrc, /etc/pip.conf, C:\ProgramData\..., etc). Used
	// by MDM enforcement packs that want per-user overrides to be
	// impossible without explicit root/admin action. Managers that have
	// no real system-wide location fall back to ScopeUser with a clear
	// error on write; callers should treat that as "not supported".
	ScopeSystem Scope = "system"
)

// Manager is implemented by each package-manager-specific editor (npm, pip,
// cargo). Implementations edit a single configuration file in an idempotent
// way using a delimited sentinel block.
type Manager interface {
	// Name returns the short identifier of the manager (e.g. "npm").
	Name() string
	// ConfigPath returns the absolute path to the user-scoped config file
	// the manager edits. The file need not exist yet. Kept for callers that
	// don't carry a scope (e.g. Status); equivalent to
	// ConfigPathForScope(ScopeUser).
	ConfigPath() (string, error)
	// ConfigPathForScope returns the absolute path for the given scope.
	ConfigPathForScope(scope Scope) (string, error)
	// IsInstalled reports whether the package-manager binary is on PATH.
	IsInstalled() bool
	// Wire inserts or refreshes the chainsaw-managed block. The target file
	// is determined by opts.Scope (defaults to ScopeUser).
	Wire(opts WireOpts) error
	// Unwire removes a previously installed chainsaw-managed block from the
	// given scope. Returns ErrNotWired if no block is present.
	Unwire(scope Scope) error
	// Status summarises the current state of the config file.
	Status() (Status, error)
}

// WireOpts carries wiring parameters the CLI passes through to Wire.
type WireOpts struct {
	// ChainsawBinary is the absolute path to the chainsaw binary that will
	// service install-time hooks.
	ChainsawBinary string
	// ServerURL is the chainsaw proxy endpoint. An empty string selects
	// no-proxy (local-audit-only) mode.
	ServerURL string
	// Credentials is an optional "client_id:client_secret" pair. When set,
	// each manager embeds it directly into the generated config so the proxy
	// authenticates without the user having to export CHAINSAW_TOKEN. Empty
	// string falls back to the pre-existing env-var-based placeholder.
	Credentials string
	// OrgSlug is the caller's org slug, used by every renderer to build
	// org-scoped repository paths (BUG-A6). The proxy rejects slug-less
	// URLs with CHW-4314. Empty string is allowed and falls back to a
	// visible placeholder ("your-org-slug") so the rendered snippet fails
	// closed at first use rather than silently routing wrong.
	OrgSlug string
	// Scope selects the config file location. Empty string is treated as
	// ScopeUser for backwards compatibility.
	Scope Scope
}

// Status describes a manager's configuration at a point in time.
type Status struct {
	ConfigPath string
	Wired      bool
	Installed  bool
}

// Common errors returned by Manager implementations.
var (
	ErrNotInstalled  = errors.New("package manager is not installed")
	ErrNotWired      = errors.New("no chainsaw-managed block found")
	ErrConfigMissing = errors.New("package-manager config not found")
)

// All returns the set of managers chainsaw knows how to wire.
func All() []Manager {
	return []Manager{
		npmManager{},
		yarnManager{},
		bunManager{},
		pipManager{},
		cargoManager{},
		mavenManager{},
		gradleManager{},
		sbtManager{},
		nugetManager{},
		goModManager{},
		dockerManager{},
	}
}

// ByName looks up a manager by its short name. Returns an error if the name
// is not recognised.
func ByName(name string) (Manager, error) {
	for _, m := range All() {
		if m.Name() == name {
			return m, nil
		}
	}
	return nil, fmt.Errorf("unknown package manager %q", name)
}
