package hook

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// credentialFileMode returns the mode a NEWLY CREATED config file should get,
// and whether an existing file should be tightened down to it.
//
// H5: config files that embed a plaintext client secret were created 0644
// while a code comment claimed 0600. The fix is deliberately narrow — the
// seed's "default writeAtomic to 0600" would have made a root-owned
// /etc/npmrc unreadable by every non-root user and broken npm machine-wide.
// So: 0600 only when we are actually embedding a credential AND the target is
// not the machine-wide config every user has to read.
func credentialFileMode(opts WireOpts) (os.FileMode, bool) {
	if strings.TrimSpace(opts.Credentials) != "" && opts.Scope != ScopeSystem {
		return 0o600, true
	}
	return 0o644, false
}

// tightenExistingFile chmods a pre-existing, secret-bearing config down to
// 0600 before we write into it. Needed because writeAtomicMode preserves an
// existing file's mode: without this, a file created 0644 by an older
// chainsaw stays 0644 forever even after a re-wire embeds a fresh secret.
//
// Never called for ScopeSystem (credentialFileMode gates it) — a 0600
// /etc/npmrc breaks npm for every non-root user on the box.
func tightenExistingFile(path string, opts WireOpts) {
	if runtime.GOOS == "windows" {
		// POSIX permission bits aren't meaningful; secureio's Windows path
		// relies on %APPDATA% ACL inheritance instead.
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	perm := info.Mode().Perm()
	if perm&0o077 == 0 {
		return
	}
	if err := os.Chmod(path, 0o600); err != nil {
		opts.notify("warning: could not tighten %s to 0600 (%v); it holds a client secret", path, err)
		return
	}
	opts.notify("tightened %s from %04o to 0600 — it holds a client secret", path, perm)
}

// writeConfigFile is the single write sink for every manager. It applies the
// credential-aware mode policy and reports the outcome through opts.Notify.
func writeConfigFile(path string, data []byte, opts WireOpts) error {
	mode, tighten := credentialFileMode(opts)
	if tighten {
		tightenExistingFile(path, opts)
	}
	return writeAtomicMode(path, data, mode)
}

// checkSentinelIntegrity refuses to write when the target already carries
// chainsaw markers that do not form exactly one well-formed block (H9).
//
// Appending another block (the old behaviour) grows the file without bound
// and leaves Unwire permanently broken; deleting from the marker to EOF would
// destroy user content. Refuse, and point at the opt-in repair path.
func checkSentinelIntegrity(manager, path string, data []byte, classify markerClassifier) error {
	corrupt, reason := sentinelCorrupt(data, classify)
	if !corrupt {
		return nil
	}
	return fmt.Errorf(`%s contains a malformed chainsaw-managed block: %s.

chainsaw will not write over it — appending another block would grow the file
on every run and leave nothing removable. Either fix the markers by hand, or
run:

  chainsaw uninstall-hook %s --repair

which prints the exact lines it would delete and asks before touching the file`,
		path, reason, manager)
}

// writeWithBackup is the Wire-side boilerplate every "#"-comment manager
// shares: read the existing file (may be empty), refuse a malformed block,
// back up if non-empty, then atomically write a sentinel-wrapped block.
func writeWithBackup(manager, path, body string, opts WireOpts) error {
	return writeWithBackupPrefix(manager, path, body, opts, "#", hashMarker)
}

// writeWithBackupPrefix is writeWithBackup with an explicit comment prefix
// and matcher, for managers whose config format is not "#"-commented (gradle
// emits Kotlin "//" comments — see H14).
func writeWithBackupPrefix(manager, path, body string, opts WireOpts, prefix string, classify markerClassifier) error {
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := checkSentinelIntegrity(manager, path, data, classify); err != nil {
		return err
	}
	if len(data) > 0 {
		if err := backupAndNotify(path, opts); err != nil {
			return err
		}
	}
	block := buildBlockWithPrefix(body, prefix)
	return writeConfigFile(path, replaceOrAppendWith(data, block, classify), opts)
}

// unwireBlock is the Unwire-side boilerplate: read, require a sentinel
// block, backup, write without it. Returns ErrNotWired when the file
// doesn't contain a well-formed block.
func unwireBlock(path string) error {
	return unwireBlockWith(path, hashMarker)
}

// unwireBlockWith is unwireBlock for a manager-specific marker dialect.
// removeIfBlank deletes the file when nothing but whitespace survives —
// correct for a dedicated chainsaw-owned file (gradle's init script), wrong
// for a shared one (~/.npmrc).
func unwireBlockWith(path string, classify markerClassifier, removeIfBlank ...bool) error {
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 || !hasMarkedBlock(data, classify) {
		return ErrNotWired
	}
	if _, err := backup(path); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	newData, removed := removeMarkedBlock(data, classify)
	if !removed {
		return ErrNotWired
	}
	if len(removeIfBlank) > 0 && removeIfBlank[0] && strings.TrimSpace(string(newData)) == "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
		return nil
	}
	return writeAtomic(path, newData)
}

// statusForConfig builds a Status by reading the user-scope config path
// once and reporting the installed-ness and wired-ness. configPathFn is
// the manager's ConfigPath() method; isInstalledFn is IsInstalled.
func statusForConfig(configPathFn func() (string, error), isInstalledFn func() bool) (Status, error) {
	return statusForConfigWith(configPathFn, isInstalledFn, hashMarker)
}

// statusForConfigWith is statusForConfig for a manager-specific marker
// dialect.
func statusForConfigWith(configPathFn func() (string, error), isInstalledFn func() bool, classify markerClassifier) (Status, error) {
	path, err := configPathFn()
	if err != nil {
		return Status{}, err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return Status{ConfigPath: path, Installed: isInstalledFn()}, err
	}
	return Status{
		ConfigPath: path,
		Wired:      hasMarkedBlock(data, classify),
		Installed:  isInstalledFn(),
	}, nil
}
