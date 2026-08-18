package telemetry

// install_id is the cross-channel identity anchor. A UUIDv7 is generated
// the first time one is actually needed and persisted in the chainsaw config
// directory — cli/platform.ConfigHome, the same directory as config.yaml and
// guard_state.json, NOT "the XDG config directory" as this comment used to
// claim (that is one of three answers, and the wrong one on macOS). The ID is
// emitted as the PostHog distinct_id (prefixed
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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/chain305/chainsaw-core/cli/platform"
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

	// envConfigHome is cli/platform.EnvConfigHome. It used to be a
	// hand-copied string literal "so core/telemetry keeps no dependency on
	// core/cli"; the copy is now an alias of the real constant, which is
	// one fewer thing that can drift. See ConfigDir.
	envConfigHome = platform.EnvConfigHome
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
//
// PeekInstall inspects exactly the directory it is given and nothing else.
// The canonical-plus-legacy search lives in PeekProcessInstall; keeping this
// function single-directory is what lets a test point it at a t.TempDir()
// without the developer's real install record leaking in.
func PeekInstall(dir string) (Install, bool, error) {
	install, _, found, err := peekAcross(dir)
	return install, found, err
}

// readInstallFile returns the raw (trimmed) file contents. A missing file and
// an empty one are both reported as not-found, matching LoadInstall's own
// treatment of an empty file as "first run".
func readInstallFile(dir string) (string, bool, error) {
	raw, err := os.ReadFile(filepath.Join(dir, installFilename))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	val := strings.TrimSpace(string(raw))
	if val == "" {
		return "", false, nil
	}
	return val, true, nil
}

func installFromValue(val string) Install {
	if val == installIDDisabled {
		return Install{Disabled: true}
	}
	return Install{ID: val}
}

// peekAcross reads the given directories in priority order and returns the
// first record found, along with the directory it came from. It NEVER writes.
//
// A filesystem error on one directory does not abort the walk: if the
// canonical directory is unreadable but a legacy directory still holds the
// id, honoring the id we can actually see beats reporting a failure and
// letting the caller mint a replacement. The error is surfaced only when no
// directory yielded a record.
func peekAcross(dirs ...string) (Install, string, bool, error) {
	var firstErr error
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		val, found, err := readInstallFile(dir)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if found {
			return installFromValue(val), dir, true, nil
		}
	}
	return Install{}, "", false, firstErr
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
//
// Like PeekInstall, this operates on exactly the directory it is given. The
// canonical-plus-legacy resolution is in ProcessInstall.
func LoadInstall(dir string) (Install, error) {
	if install, found, err := PeekInstall(dir); err != nil {
		return Install{}, err
	} else if found {
		return install, nil
	}
	return mintInstall(dir)
}

// mintInstall is the write path: it is reached only once every directory we
// know about has been searched and none held a record.
func mintInstall(dir string) (Install, error) {
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
// Equivalent to deleting install_id from dir, but routed through Go for
// Windows portability.
//
// dir is whatever the caller resolved — in practice ConfigDir(), whose
// location is platform- and env-dependent; `chainsaw telemetry status`
// prints the resolved directory.
//
// When dir IS the canonical directory this also erases any legacy copy. That
// is load-bearing rather than tidy: migrateInstallFile deliberately leaves
// the legacy file in place, so a reset that cleared only the canonical copy
// would be silently undone by the next run re-reading the legacy one — the
// user asks to be forgotten and gets their old id back. A caller passing some
// other directory (tests) gets exactly that directory touched and no more.
func ResetInstall(dir string) error {
	if err := removeInstallFile(dir); err != nil {
		return err
	}
	canonical, legacy, err := installDirsFn()
	if err != nil || !sameDir(dir, canonical) {
		return nil
	}
	for _, d := range legacy {
		if err := removeInstallFile(d); err != nil {
			return err
		}
	}
	return nil
}

func removeInstallFile(dir string) error {
	if err := os.Remove(filepath.Join(dir, installFilename)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ConfigDir returns the config directory for chainsaw, creating it if
// missing. It is cli/platform.ConfigHome — the ONE resolver — plus a
// MkdirAll. See that function for the precedence rules.
//
// This used to be a second, hand-written resolver that agreed with
// cli/platform on Linux and disagreed everywhere else, so on macOS
// config.yaml sat in ~/.chainsaw while install_id sat in ~/.config/chainsaw.
// A comment on each copy asserted they "must stay in lockstep"; a comment is
// not a mechanism. Calling the other resolver is.
//
// R9 (retained): the CHAINSAW_CONFIG_HOME override must scope install_id too,
// or a CI container that scopes CHAINSAW_CONFIG_HOME still persists a stable
// machine identifier outside it and `chainsaw telemetry reset` targets a
// directory the operator never configured. The override branch returns the
// directory ITSELF, with no "chainsaw" suffix.
func ConfigDir() (string, error) {
	dir, err := configHome()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// configHome resolves the canonical directory without creating it.
//
// cli/platform.ConfigHome documents that it may return an empty or relative
// path when $HOME is unresolvable, and leaves it to callers to cope. Here
// "cope" means refuse: MkdirAll on a relative path would scatter a config
// directory — and a stable machine identifier — into whatever the process's
// working directory happened to be. The old resolver propagated
// os.UserHomeDir's error in that case and so does this.
func configHome() (string, error) {
	dir := platform.ConfigHome()
	if dir == "" {
		return "", errors.New("telemetry: cannot resolve the chainsaw config home")
	}
	if !filepath.IsAbs(dir) && strings.TrimSpace(os.Getenv(envConfigHome)) == "" {
		return "", fmt.Errorf("telemetry: chainsaw config home resolved to the relative path %q (no home directory)", dir)
	}
	return dir, nil
}

// installDirsFn is indirected so tests can drive the read/migrate/mint logic
// against two temp directories instead of depending on the host GOOS — on
// Linux the canonical and legacy locations are the SAME directory, so a
// GOOS-dependent test would silently assert nothing there.
var installDirsFn = installDirs

// installDirs resolves every directory install_id may live in, canonical
// first, WITHOUT creating any of them. Creating the canonical directory is
// the write path's job (mintInstall and migrateInstallFile both MkdirAll);
// a peek that conjured directories would be a smaller version of the bug
// PeekInstall exists to prevent.
func installDirs() (string, []string, error) {
	canonical, err := configHome()
	if err != nil {
		return "", nil, err
	}
	var legacy []string
	for _, dir := range legacyInstallDirs() {
		if dir == "" || sameDir(dir, canonical) {
			continue
		}
		legacy = append(legacy, dir)
	}
	return canonical, legacy, nil
}

// legacyInstallDirs reproduces the directory the pre-lockstep resolver
// returned, so an install_id minted by an older binary is still found.
//
// Dropping this would not "clean up" anything: the id would simply be absent
// from the canonical location, a fresh one would be minted, every affected
// machine would be counted as a brand-new install, and the alias that stitches
// a pre-signup install to its account would point at an id nobody uses. That
// is silent and irreversible, which is why the old locations are load-bearing
// rather than legacy trivia.
//
// Under CHAINSAW_CONFIG_HOME there is deliberately no legacy search: the old
// resolver honored the override too, so nothing can be stranded, and reaching
// outside a scoped directory would undo exactly the isolation R9 established.
func legacyInstallDirs() []string {
	if strings.TrimSpace(os.Getenv(envConfigHome)) != "" {
		return nil
	}
	var base string
	switch runtime.GOOS {
	case "windows":
		base = strings.TrimSpace(os.Getenv("APPDATA"))
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil
			}
			base = filepath.Join(home, "AppData", "Roaming")
		}
	default:
		base = strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil
			}
			base = filepath.Join(home, ".config")
		}
	}
	return []string{filepath.Join(base, "chainsaw")}
}

// sameDir compares two resolved directories. Windows and macOS default to
// case-insensitive filesystems, and on Windows the two resolvers differ only
// in the case of the leaf ("Chainsaw" vs "chainsaw") — treating those as
// distinct would make the code copy a file onto itself.
func sameDir(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// migrateInstallFile copies an existing install record into the canonical
// directory. BEST EFFORT: every failure path returns silently, because the
// caller already holds the id it read from `from` and will keep using it. A
// machine that cannot complete the copy keeps working off the legacy file
// forever, which is a non-event; losing the id is not.
//
// Written to a temp file and renamed so a partial write can never leave a
// truncated file in the canonical location — that file would then shadow the
// intact legacy one and hand back a corrupted id.
//
// The legacy file is deliberately NOT deleted. Deleting it would strand any
// older chainsaw binary on the same machine (a system package alongside a
// `go install`ed build, a pinned CI image), which would find nothing and mint
// a second id for a machine that already has one — the exact failure this
// migration exists to prevent, reintroduced from the other side. A stale
// duplicate is harmless: the canonical copy always wins the read, and
// ResetInstall clears both.
func migrateInstallFile(from, to string) {
	val, found, err := readInstallFile(from)
	if err != nil || !found {
		return
	}
	if err := os.MkdirAll(to, 0o755); err != nil {
		return
	}
	tmp, err := os.CreateTemp(to, ".install_id-*")
	if err != nil {
		return
	}
	name := tmp.Name()
	if _, err := tmp.WriteString(val + "\n"); err != nil {
		tmp.Close()
		os.Remove(name)
		return
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return
	}
	if err := os.Rename(name, filepath.Join(to, installFilename)); err != nil {
		os.Remove(name)
	}
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
// Searches the canonical directory first, then any legacy one. It does NOT
// migrate what it finds: migration is a write, and the whole point of this
// function is that a user inspecting their privacy state triggers no writes
// at all. ProcessInstall does the migration, on the path where a write was
// already going to happen.
//
// This no longer creates the config directory either — installDirs resolves
// without MkdirAll. A directory is not an identifier, so creating one was
// never the bug, but `CHAINSAW_OFFLINE=1 chainsaw telemetry status` leaving
// no trace at all is a cleaner promise than one with a footnote.
func PeekProcessInstall() (Install, bool, error) {
	canonical, legacy, err := installDirsFn()
	if err != nil {
		return Install{}, false, err
	}
	install, _, found, err := peekAcross(append([]string{canonical}, legacy...)...)
	return install, found, err
}

// ProcessInstall returns the install record for the current process,
// loading and persisting one on first call. Subsequent calls are a
// map-lookup cost. Errors are sticky — a transient filesystem issue on
// startup downgrades telemetry for the rest of the process.
//
// THIS MINTS — see LoadInstall. Status/reporting callers want
// PeekProcessInstall instead.
//
// Minting is the LAST resort: every known directory is searched first, and an
// id found in a legacy one is returned unchanged and copied forward. Pointing
// this at the canonical directory alone would have been the obvious one-line
// fix and a data-destroying one — every macOS install would have looked brand
// new on the first run of the new binary.
func ProcessInstall() (Install, error) {
	processInstallOnce.Do(func() {
		canonical, legacy, err := installDirsFn()
		if err != nil {
			processInstallErr = err
			return
		}
		install, from, found, err := peekAcross(append([]string{canonical}, legacy...)...)
		switch {
		case found:
			if !sameDir(from, canonical) {
				migrateInstallFile(from, canonical)
			}
			processInstall = install
		case err != nil:
			processInstallErr = err
		default:
			processInstall, processInstallErr = mintInstall(canonical)
		}
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

// (The local expandTilde copy that used to live here is gone: it existed only
// to be "kept byte-compatible" with cli/platform.expandTilde, and the tilde
// expansion now happens exactly once, inside cli/platform.ConfigHome.)

func writeInstallFile(dir, path, value string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(value+"\n"), 0o600)
}
