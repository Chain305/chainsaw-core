package hook

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// cargoManager edits $CARGO_HOME/config.toml (or ~/.cargo/config.toml).
type cargoManager struct{}

func (cargoManager) Name() string { return "cargo" }

func (cargoManager) IsInstalled() bool {
	_, err := exec.LookPath("cargo")
	return err == nil
}

func (m cargoManager) ConfigPath() (string, error) {
	return m.ConfigPathForScope(ScopeUser)
}

// ConfigPathForScope returns $CARGO_HOME/config.toml (or ~/.cargo/config.toml)
// for ScopeUser and ./.cargo/config.toml for ScopeProject. cargo discovers
// project config by walking upward from cwd, so dropping the file in the
// current directory is enough — Wire creates the .cargo/ parent on write.
func (cargoManager) ConfigPathForScope(scope Scope) (string, error) {
	switch scope {
	case ScopeProject:
		cwd, err := os.Getwd()
		if err != nil || cwd == "" {
			return "", fmt.Errorf("resolve working dir: %w", err)
		}
		return filepath.Join(cwd, ".cargo", "config.toml"), nil
	case ScopeSystem:
		if runtime.GOOS == "windows" {
			pd := os.Getenv("ProgramData")
			if pd == "" {
				return "", fmt.Errorf("ProgramData not set")
			}
			return filepath.Join(pd, "cargo", "config.toml"), nil
		}
		return "/etc/cargo/config.toml", nil
	}
	if ch := os.Getenv("CARGO_HOME"); ch != "" {
		return filepath.Join(ch, "config.toml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".cargo", "config.toml"), nil
}

func (m cargoManager) Wire(opts WireOpts) error {
	path, err := m.ConfigPathForScope(opts.Scope)
	if err != nil {
		return err
	}
	body, err := cargoBlockBody(opts)
	if err != nil {
		return err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > 0 {
		if _, err := backup(path); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
	}
	block := buildBlock(body)
	return writeAtomic(path, replaceOrAppend(data, block))
}

func (m cargoManager) Unwire(scope Scope) error {
	path, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 || !hasSentinel(data) {
		return ErrNotWired
	}
	if _, err := backup(path); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	newData, removed := removeSentinel(data)
	if !removed {
		return ErrNotWired
	}
	return writeAtomic(path, newData)
}

func (m cargoManager) Status() (Status, error) {
	path, err := m.ConfigPath()
	if err != nil {
		return Status{}, err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return Status{ConfigPath: path, Installed: m.IsInstalled()}, err
	}
	return Status{
		ConfigPath: path,
		Wired:      hasSentinel(data),
		Installed:  m.IsInstalled(),
	}, nil
}

// cargoBlockBody renders the scaffolded body for cargo's config.toml.
//
// The chainsaw proxy exposes cargo traffic as a sparse-protocol index at
// /repository/<repo-name>/ — the default seed.yaml registers index.crates.io
// under the name "crates-io" (see configs/seed.yaml:795). Cargo 1.68+
// prefers the sparse+ scheme which we emit unconditionally; if users run an
// older toolchain they can edit the line to remove the prefix.
//
// Auth: cargo reads registry tokens from CARGO_REGISTRIES_<NAME>_TOKEN env
// vars (mapped from the TOML source name, upper-cased). We document this
// via comment rather than a [registries.chainsaw.token] key because (a)
// token values in config.toml are plaintext-on-disk and (b) the env-var
// path is the only form that works with rustc 1.70+ credential-provider
// defaults. The user populates ${CHAINSAW_TOKEN} with their
// "client_id:client_secret" pair; cargo sends it as
// "Authorization: <token>", which resolveClientCredentials parses
// (internal/server/server_clients.go:634).
//
// A non-empty ServerURL is passed through validateServerURL. The validated
// URL is then fed through strconv.Quote to produce a properly escaped TOML
// basic-string literal — defensive in depth: even though the validator
// already rejects " and \\, Quote handles any future character class TOML
// cares about (non-ASCII, control chars, etc.) without surprise.
func cargoBlockBody(opts WireOpts) (string, error) {
	server := strings.TrimSpace(opts.ServerURL)
	if server == "" {
		return `# Uncomment and re-run ` + "`chainsaw --server <url> install-hook cargo`" + ` to
# populate real proxy URLs. The chainsaw proxy mounts cargo at
# /repository/<repo-name>/ (default repo name: "crates-io").
# [source.crates-io]
# replace-with = "chainsaw"
# [source.chainsaw]
# registry = "sparse+https://<chainsaw-server>/repository/crates-io/"
# For authenticated proxies, also:
#   export CARGO_REGISTRIES_CHAINSAW_TOKEN="${CHAINSAW_TOKEN}"`, nil
	}
	base, err := validateServerURL(server)
	if err != nil {
		return "", err
	}
	// strconv.Quote produces a Go/TOML-compatible basic-string literal:
	// surrounded by ", with ", \, and control characters escaped. TOML
	// basic strings use the same escape syntax as Go string literals for
	// these characters, so this is a valid TOML value.
	// BUG-A6: org-scoped path required (/repository/@<org>/crates-io/).
	registryValue := strconv.Quote("sparse+" + base + "/" + OrgScopedRepoPath(opts.OrgSlug, "crates-io") + "/")
	if creds := strings.TrimSpace(opts.Credentials); creds != "" {
		if _, _, ok := splitCreds(creds); !ok {
			return "", fmt.Errorf("credentials: expected \"client_id:client_secret\"")
		}
		return fmt.Sprintf(`# chainsaw: token embedded below; tighten this file's permissions
# (chmod 600) if your home directory is shared.
[source.crates-io]
replace-with = "chainsaw"

[source.chainsaw]
registry = %s

[registries.chainsaw]
token = %s`, registryValue, strconv.Quote("Bearer "+creds)), nil
	}
	return fmt.Sprintf(`[source.crates-io]
replace-with = "chainsaw"

[source.chainsaw]
registry = %s
# For authenticated proxies, export this before running cargo:
#   export CARGO_REGISTRIES_CHAINSAW_TOKEN="${CHAINSAW_TOKEN}"`, registryValue), nil
}
