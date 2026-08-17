package telemetry

// install_id is the cross-channel identity anchor. A UUIDv7 is generated
// the first time one is actually needed and persisted under the XDG config
// directory. The ID is emitted as the PostHog distinct_id (prefixed
// "install:") until a user-authenticated request arrives — at that point
// the server issues an Alias(install:<id> → user:<user_id>) so the pre-auth
// events merge into the authenticated person.
//
// We intentionally do NOT hash or derive from hardware identifiers: the
// file is the record, and users can blow it away with
// `chainsaw telemetry reset` (or their own `rm`) if they want to be
// counted as a fresh install.
//
// READ vs MINT — the distinction this file draws, and why:
//
// LoadInstall/ProcessInstall MINT. They are the write path and must only be
// reached when an identifier is legitimately about to be used (the CLI calls
// them from emit(), AFTER its explicit-consent gate, and from the login init
// request, likewise consent-gated).
//
// PeekInstall/PeekProcessInstall READ ONLY. Anything that merely REPORTS the
// install state — `chainsaw telemetry status`, `chainsaw guard status` — must
// use these. Reading a privacy readout is not consent to create the very
// identifier being inspected, and a user who has never been asked ran
// `telemetry status` and got a permanent machine id written to disk for their
// trouble. ResolveMode() cannot close that hole: it consults ENV VARS ONLY, so
// on a box with no kill switch set it returns ModeEnabled for a user who has
// consented to nothing.

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/google/uuid"
)

const (
	installFilename = "install_id"

	// installIDDisabled is written instead of a real ID when the first run
	// happens with CHAINSAW_TELEMETRY_DISABLED set truthy. Subsequent runs
	// read this sentinel and remain silent even if the user later unsets
	// the env var — the decision is sticky until they run
	// `chainsaw telemetry reset`. Only CHAINSAW_TELEMETRY_DISABLED writes
	// it; the per-run umbrellas (CHAINSAW_OFFLINE, DO_NOT_TRACK) do not.
	installIDDisabled = "disabled"

	// envConfigHome mirrors cli/platform.EnvConfigHome. Duplicated as a
	// string rather than imported so core/telemetry keeps no dependency on
	// core/cli; see ConfigDir.
	envConfigHome = "CHAINSAW_CONFIG_HOME"
)

// Install is the persistent install record. ID is the PostHog distinct_id
// material (prefixed "install:" at emit time). Disabled is true when the
// user opted out before the first run was recorded.
type Install struct {
	ID       string
	Disabled bool
}

// PeekInstall reads the persisted install record WITHOUT creating one.
// found reports whether this machine has a record at all; on false the
// returned Install is the zero value and NOTHING was written to dir — the
// property `telemetry status` depends on.
//
// A missing file and an empty one are both reported as not-found, matching
// LoadInstall's own treatment of an empty file as "first run".
//
// A non-nil error is a filesystem problem (permissions, unreadable file);
// callers reporting status should render that as "unknown", not as "none".
func PeekInstall(dir string) (Install, bool, error) {
	raw, err := os.ReadFile(filepath.Join(dir, installFilename))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Install{}, false, nil
		}
		return Install{}, false, err
	}
	switch val := strings.TrimSpace(string(raw)); {
	case val == installIDDisabled:
		return Install{Disabled: true}, true, nil
	case val != "":
		return Install{ID: val}, true, nil
	default:
		return Install{}, false, nil
	}
}

// LoadInstall resolves the install_id for this binary, creating and
// persisting one on first call. dir is the config directory (typically
// from ConfigDir()). A non-nil error indicates a filesystem problem
// (permissions, disk full); callers may treat that as telemetry-off
// rather than hard-failing the process.
//
// THIS MINTS. Call it only when an identifier is about to be used for its
// stated purpose (an event that will be sent, a login init that will be
// aliased) — never to answer a question about the current state. Use
// PeekInstall for that. Note that the ENV-derived ResolveMode() check below
// is a floor, not the consent gate: consent lives above this package (the
// CLI's guard_state.json, which core/telemetry deliberately cannot see), so
// the CALLER owns it. Nothing here can tell a consenting user from a user
// who was never asked.
func LoadInstall(dir string) (Install, error) {
	if install, found, err := PeekInstall(dir); err != nil {
		return Install{}, err
	} else if found {
		return install, nil
	}
	path := filepath.Join(dir, installFilename)

	// First run — either the file is missing or it was empty. Respect
	// CHAINSAW_TELEMETRY_DISABLED at first run so opted-out users never
	// have an ID written.
	//
	// R8: the check used to be an EXACT `== "1"`, so the documented
	// `CHAINSAW_TELEMETRY_DISABLED=true` opted the user out of SENDING
	// (ResolveMode uses envTrue) while still minting and persisting a real
	// UUIDv7 — the identifier the opt-out exists to prevent. Use the same
	// truthy parser as ResolveMode so the two can never disagree again.
	if envTrue("CHAINSAW_TELEMETRY_DISABLED") {
		if err := writeInstallFile(dir, path, installIDDisabled); err != nil {
			return Install{Disabled: true}, err
		}
		return Install{Disabled: true}, nil
	}

	// R8: any OTHER route to ModeDisabled (CHAINSAW_OFFLINE, DO_NOT_TRACK,
	// a self-hosted build without CHAINSAW_TELEMETRY_ENABLED) must not mint
	// an identifier either — telemetry/consent.go's ModeDisabled doc says
	// verbatim "install_id is not persisted on first run", and
	// `CHAINSAW_OFFLINE=1 chainsaw telemetry status` (the FIRST command a
	// privacy-conscious operator runs) was minting the very id being
	// inspected.
	//
	// Deliberately NOT written as the sticky `disabled` sentinel: those
	// signals are PER-RUN umbrellas, not a telemetry decision. Writing the
	// sentinel would make one offline invocation permanently opt the box
	// out, and a code revert could not un-write it. Return the disabled
	// record and leave the directory untouched.
	if ResolveMode() == ModeDisabled {
		return Install{Disabled: true}, nil
	}

	id, err := uuid.NewV7()
	if err != nil {
		return Install{}, err
	}
	value := id.String()
	if err := writeInstallFile(dir, path, value); err != nil {
		return Install{}, err
	}
	return Install{ID: value}, nil
}

// ResetInstall erases the install record so the next run starts fresh.
// Equivalent to `rm ~/.config/chainsaw/install_id` but routed through Go
// for Windows portability.
func ResetInstall(dir string) error {
	path := filepath.Join(dir, installFilename)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ConfigDir returns the config directory for chainsaw, creating it if
// missing. Precedence:
//
//  1. CHAINSAW_CONFIG_HOME (with leading ~ expansion) — the universal
//     override documented for CI, nix, and portable installs.
//  2. XDG_CONFIG_HOME/chainsaw on Unix, %APPDATA%/chainsaw on Windows.
//  3. $HOME/.config/chainsaw.
//
// R9: step 1 used to be missing, so `CHAINSAW_CONFIG_HOME=/tmp/cfg2
// chainsaw …` scoped config.yaml and guard_state.json into /tmp/cfg2 but
// still persisted install_id — a stable machine identifier — outside it,
// and `chainsaw telemetry reset` targeted a directory the operator never
// configured.
//
// The override is read by NAME rather than through cli/platform on
// purpose: core/telemetry sits below core/cli in the dependency graph and
// a new package edge upward is not worth ten lines. The two resolvers
// must stay in lockstep — see cli/platform.ConfigHome, whose override
// branch likewise returns the directory ITSELF with no "chainsaw" suffix.
func ConfigDir() (string, error) {
	if override := strings.TrimSpace(os.Getenv(envConfigHome)); override != "" {
		dir := expandTilde(override)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
		return dir, nil
	}
	var base string
	switch runtime.GOOS {
	case "windows":
		base = strings.TrimSpace(os.Getenv("APPDATA"))
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, "AppData", "Roaming")
		}
	default:
		base = strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, ".config")
		}
	}
	dir := filepath.Join(base, "chainsaw")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

var (
	processInstallOnce sync.Once
	processInstall     Install
	processInstallErr  error
)

// PeekProcessInstall is PeekInstall against the resolved config dir: the
// read-only answer to "does this machine have an install_id, and what is
// it?" with no chance of minting one as a side effect.
//
// Deliberately NOT wired to the processInstall cache. The cache exists to
// make repeated MINTING calls cheap and to freeze one id per process; a peek
// has neither need, and letting a peek populate the cache would let a status
// read decide what a later emit sees. Two file reads in one CLI invocation
// is not a cost worth that coupling.
//
// ConfigDir() still creates the config DIRECTORY (it is shared with
// config.yaml and guard_state.json). A directory is not an identifier; the
// install_id file is what this must not conjure.
func PeekProcessInstall() (Install, bool, error) {
	dir, err := ConfigDir()
	if err != nil {
		return Install{}, false, err
	}
	return PeekInstall(dir)
}

// ProcessInstall returns the install record for the current process,
// loading and persisting one on first call. Subsequent calls are a
// map-lookup cost. Errors are sticky — a transient filesystem issue on
// startup downgrades telemetry for the rest of the process.
//
// THIS MINTS — see LoadInstall. Status/reporting callers want
// PeekProcessInstall instead.
func ProcessInstall() (Install, error) {
	processInstallOnce.Do(func() {
		dir, err := ConfigDir()
		if err != nil {
			processInstallErr = err
			return
		}
		processInstall, processInstallErr = LoadInstall(dir)
	})
	return processInstall, processInstallErr
}

// ResetProcessInstall drops the cached per-process install record so the
// next ProcessInstall() call re-reads (and, if permitted, re-creates) it.
//
// Two callers: `chainsaw telemetry reset`, so the deletion takes effect
// within the same invocation rather than only on the next one; and tests,
// which need each case to start from a known install state rather than
// inheriting whatever the first test in the binary happened to cache.
//
// Not safe to call concurrently with ProcessInstall.
func ResetProcessInstall() {
	processInstallOnce = sync.Once{}
	processInstall = Install{}
	processInstallErr = nil
}

// DistinctID returns the PostHog distinct_id for the current install.
// Empty string when telemetry is disabled (either the sentinel file or
// a load failure) — callers should treat that as "do not send".
func DistinctID(install Install) string {
	if install.Disabled || install.ID == "" {
		return ""
	}
	return "install:" + install.ID
}

// expandTilde resolves a leading "~" in a CHAINSAW_CONFIG_HOME override.
// Mirrors cli/platform.expandTilde; kept byte-compatible with it so the
// two config-home resolvers agree on every input.
func expandTilde(p string) string {
	if p == "~" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return home
		}
		return p
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return p
		}
		return filepath.Join(home, p[2:])
	}
	return p
}

func writeInstallFile(dir, path, value string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(value+"\n"), 0o600)
}
