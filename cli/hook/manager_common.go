package hook

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/chain305/chainsaw-core/cli/secureio"
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

// tightenExistingFile restricts a pre-existing, secret-bearing config to the
// owner before we write into it. Needed because writeAtomicMode preserves an
// existing file's mode: without this, a file created 0644 by an older
// chainsaw stays 0644 forever even after a re-wire embeds a fresh secret.
//
// Never called for ScopeSystem (credentialFileMode gates it) — a 0600
// /etc/npmrc breaks npm for every non-root user on the box.
//
// L-09: the Windows arm used to `return` immediately, on the theory that
// %APPDATA% ACL inheritance was enough — while three rendered config bodies
// told the user chainsaw "keeps this file at mode 0600". Inheritance is not a
// guarantee: it is whatever the parent directory happens to grant, which on a
// roamed or re-created profile can include groups the operator never chose.
// secureio already had a working protected-DACL tightener; call it, so the
// promise the file makes is backed on every platform we ship.
func tightenExistingFile(path string, opts WireOpts) {
	if runtime.GOOS == "windows" {
		if _, err := os.Stat(path); err != nil {
			return
		}
		// Warning, never fatal: an unwritable DACL must not block a wire that
		// would otherwise succeed, but the operator has to hear that the
		// owner-only promise did not land on this file.
		if err := secureio.RestrictToCurrentUser(path); err != nil {
			opts.notify("warning: could not restrict %s to your user account (%v); it holds a client secret", path, err)
		}
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
	if err := writeAtomicMode(path, data, mode); err != nil {
		return err
	}
	if tighten {
		// L-09: tightenExistingFile above only covers a file that ALREADY
		// existed. A freshly created one inherits the directory's ACLs on
		// Windows, so it has to be restricted after the atomic write too.
		// No-op on Unix, where writeAtomicMode's 0600 is the mechanism.
		if err := secureio.RestrictToCurrentUser(path); err != nil {
			opts.notify("warning: could not restrict %s to your user account (%v); it holds a client secret", path, err)
		}
	}
	return nil
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

// ── the credential disclosure note (L-09) ────────────────────────────────────
//
// AUDIT THAT PRODUCED THIS: seven managers embed a plaintext secret in a
// config file, and each described it differently. npm, bun and sbt claimed
// chainsaw "keeps this file at mode 0600"; pip and cargo told the user to
// "chmod 600" it themselves (stale advice — writeConfigFile already does);
// maven wrote a cleartext <password> and said nothing at all.
//
// Two problems, not one. The wording had drifted, and the numeric mode was a
// claim we do not honour everywhere: ScopeSystem configs are deliberately left
// 0644 (a 0600 /etc/npmrc breaks npm for every non-root user), and Windows has
// no POSIX mode bits at all. So the note is now generated from ONE helper, and
// it names the GUARANTEE rather than a number: restricted to your user
// account, except machine-wide files, which say plainly that they are not.

// credentialNoteSentences returns the disclosure for a config body that
// embeds a credential, as plain sentences with no comment syntax. `what`
// names where the secret sits in this particular file, e.g. "_authToken
// below".
//
// Returns nil when nothing is embedded — a placeholder-only config has no
// secret to disclose and should not be decorated with a warning about one.
func credentialNoteSentences(what string, opts WireOpts) []string {
	if strings.TrimSpace(opts.Credentials) == "" {
		return nil
	}
	lines := []string{"chainsaw: this file contains a credential in cleartext (" + what + ")."}
	if opts.Scope == ScopeSystem {
		// The honest version of the machine-wide case. This file MUST stay
		// readable by every user or the package manager breaks for all of
		// them, so the secret is readable by every user too. Say so.
		lines = append(lines,
			"This is a machine-wide config, so it stays readable by every user on",
			"this system — and so does the credential. Use a per-user install",
			"instead if that is not acceptable.")
		return lines
	}
	lines = append(lines,
		"chainsaw restricts it to your user account: owner-only permissions on",
		"macOS and Linux, an owner-only ACL on Windows. Machine-wide configs are",
		"deliberately left readable, because every user has to read them.")
	return lines
}

// credentialHeaderNote renders credentialNoteSentences as hash-comment lines,
// ready to prepend to an npm/pip/cargo/sbt/bun style config body. Returns ""
// when nothing is embedded, so callers can interpolate it unconditionally.
func credentialHeaderNote(what string, opts WireOpts) string {
	lines := credentialNoteSentences(what, opts)
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString("# ")
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.String()
}

// credentialNoteXMLBody renders the same disclosure for maven's settings.xml,
// which has no line-comment syntax and must be embedded in an XML comment by
// the caller.
//
// CARE: an XML comment may not contain the two-hyphen sequence, which is why
// none of the sentences above spell a long CLI flag or use "--" as
// punctuation. Keep it that way.
func credentialNoteXMLBody(what string, opts WireOpts) string {
	lines := credentialNoteSentences(what, opts)
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString("\n     ")
		b.WriteString(l)
	}
	return b.String()
}
