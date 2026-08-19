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
	if err := checkSentinelIntegrity("cargo", path, data, hashMarker); err != nil {
		return err
	}
	if conflicts := cargoForeignTables(data); len(conflicts) > 0 {
		return cargoConflictError(path, conflicts)
	}
	if len(data) > 0 {
		if err := backupAndNotify(path, opts); err != nil {
			return err
		}
	}
	block := buildBlock(body)
	return writeConfigFile(path, replaceOrAppend(data, block), opts)
}

// cargoManagedTables are the TOML tables cargoBlockBody declares. TOML forbids
// re-declaring a table, so any of these appearing OUTSIDE our sentinel block
// makes the merged file unparseable.
var cargoManagedTables = []string{"source.crates-io", "source.chainsaw", "registries.chainsaw"}

// cargoForeignTables returns the managed table names already declared outside
// the chainsaw block (H6).
//
// `install-hook cargo` used to append [source.crates-io] unconditionally. On
// the standard shape for anyone already on a corporate mirror —
//
//	[source.crates-io]
//	replace-with = "mirror"
//
// that produced `Cannot declare ('source','crates-io') twice`, and cargo then
// aborts with a config-load error on EVERY subcommand.
//
// Excluding tables INSIDE our own sentinel is load-bearing: without it the
// second `install-hook cargo` would refuse and re-wiring would be impossible.
//
// We refuse rather than merge. Merging means rewriting somebody's
// source-replacement chain, and a wrong guess there silently redirects their
// dependency resolution.
func cargoForeignTables(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	lines, _ := splitLines(data)
	inSentinel := false
	seen := map[string]bool{}
	var found []string
	for _, ln := range lines {
		switch hashMarker(ln) {
		case markerStart:
			inSentinel = true
			continue
		case markerEnd:
			inSentinel = false
			continue
		}
		if inSentinel {
			continue
		}
		name, ok := tomlTableName(ln)
		if !ok {
			continue
		}
		for _, managed := range cargoManagedTables {
			if name == managed && !seen[name] {
				seen[name] = true
				found = append(found, name)
			}
		}
	}
	return found
}

// tomlTableName normalises a TOML table header line to a dotted key, e.g.
// `[ source."crates-io" ]` → `source.crates-io`. Returns false for any line
// that is not a plain table header (comments, key/value pairs, and array-of-
// table `[[...]]` headers, which cannot collide with a plain table).
func tomlTableName(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "[") || !strings.HasSuffix(t, "]") {
		return "", false
	}
	if strings.HasPrefix(t, "[[") {
		return "", false
	}
	inner := strings.TrimSpace(t[1 : len(t)-1])
	if inner == "" {
		return "", false
	}
	parts := strings.Split(inner, ".")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"'`)
		parts[i] = p
	}
	return strings.Join(parts, "."), true
}

func cargoConflictError(path string, conflicts []string) error {
	return fmt.Errorf(`%s already declares [%s] outside the chainsaw-managed block.

TOML forbids declaring a table twice, so adding chainsaw's block would make
the file unparseable and cargo would fail to load its config on every
subcommand. chainsaw will not merge into an existing source-replacement chain
— guessing wrong there silently redirects where your dependencies come from.

Remove or rename the conflicting table(s), then re-run install-hook. If you
are already behind a corporate mirror, point that mirror at the chainsaw
proxy instead of replacing crates-io twice`,
		path, strings.Join(conflicts, "], ["))
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
	cratesPath, err := orgScopedRepoPath(opts.OrgSlug, "crates-io")
	if err != nil {
		return "", err
	}
	registryValue := strconv.Quote("sparse+" + base + "/" + cratesPath + "/")
	if creds := strings.TrimSpace(opts.Credentials); creds != "" {
		if _, _, err := parseCreds(creds); err != nil {
			return "", err
		}
		return fmt.Sprintf(`%s[source.crates-io]
replace-with = "chainsaw"

[source.chainsaw]
registry = %s

[registries.chainsaw]
token = %s`, credentialHeaderNote("the registries.chainsaw token below", opts),
			registryValue, strconv.Quote("Bearer "+creds)), nil
	}
	return fmt.Sprintf(`[source.crates-io]
replace-with = "chainsaw"

[source.chainsaw]
registry = %s
# For authenticated proxies, export this before running cargo:
#   export CARGO_REGISTRIES_CHAINSAW_TOKEN="${CHAINSAW_TOKEN}"`, registryValue), nil
}
