package homebrew

// brewrepo.go — is brew's own code on this machine upstream Homebrew/brew?
//
// The first step of the 2026 Binance intrusion was a trojanised Homebrew
// installer, and the prefix is owned by the user, so brew's Ruby can be
// edited by anything running as them. bin/brew is also the script that
// loads /etc/homebrew/brew.env: one deleted line there voids every policy
// setting the MDM wrote, without touching the root-owned file.
//
// The device's git index and object store are user-writable, so `git
// status` proves nothing. Instead every tracked file in scope is hashed the
// way git hashes a blob, and compared with the tree GitHub holds for the
// commit HEAD names (served by Chainsaw's /api/homebrew/brew-tree, which
// also checks the commit is on upstream main). HEAD only nominates which
// tree to compare against; it is never trusted on its own.

import (
	"crypto/sha1" //nolint:gosec // git's blob id, compared with GitHub's; not a security primitive on its own
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// BrewTreeInScope is the set of paths `verify --brew` compares: the brew
// launcher, all of brew's Ruby (vendored gems included) and its completions.
func BrewTreeInScope(p string) bool {
	return p == "bin/brew" || strings.HasPrefix(p, "Library/Homebrew/") || strings.HasPrefix(p, "completions/")
}

// TreeEntry is one tracked path: git mode ("100644", "100755", "120000")
// and blob SHA-1.
type TreeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	SHA  string `json:"sha"`
}

// FindBrewRepo returns brew's git checkout for a prefix: the prefix itself
// on Apple silicon and Linux, prefix/Homebrew for an Intel /usr/local.
func FindBrewRepo(prefix string) (string, error) {
	for _, dir := range []string{filepath.Join(prefix, "Homebrew"), prefix} {
		if fi, err := os.Stat(filepath.Join(dir, "Library", "Homebrew")); err == nil && fi.IsDir() {
			return dir, nil
		}
	}
	return "", fmt.Errorf("no Homebrew checkout (Library/Homebrew) under %s", prefix)
}

var (
	hexSHA  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	refName = regexp.MustCompile(`^refs/[A-Za-z0-9._/-]+$`)
)

// readRegular reads a regular file of at most max bytes, refusing symlinks
// and anything else that is not a plain file (a FIFO would hang the read).
// Errors name the path, never the content.
func readRegular(path string, max int64) ([]byte, error) {
	f, fi, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi.Size() > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), max)
	}
	return io.ReadAll(io.LimitReader(f, max))
}

// openRegular opens path only if it is still the regular file Lstat saw.
// Everything under the prefix is writable by its user and this runs as
// root, so between the Lstat and the open the user can swap in a symlink
// (to /dev/zero, or a root-only file) or a FIFO, which would block forever.
// Callers read at most fi.Size()+1 bytes.
func openRegular(path string) (*os.File, fs.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fi, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	f, err := os.OpenFile(path, os.O_RDONLY|openRegularFlags, 0)
	if err != nil {
		return nil, fi, fmt.Errorf("%s changed while being opened", filepath.Base(path))
	}
	fi2, err := f.Stat()
	if err != nil || !fi2.Mode().IsRegular() || !os.SameFile(fi, fi2) {
		f.Close()
		return nil, fi, fmt.Errorf("%s changed while being opened", filepath.Base(path))
	}
	return f, fi2, nil
}

// ReadHead returns the commit HEAD names, reading .git directly (no git
// binary): a detached SHA, a loose ref, or a packed ref.
//
// .git is writable by the prefix's user and this runs as root under MDM, so
// every file is read through readRegular (no symlinks, size-capped) and no
// file content is ever quoted in an error: a HEAD symlinked to a root-only
// file must not copy that file into the world-readable result.
func ReadHead(repo string) (string, error) {
	gitDir := filepath.Join(repo, ".git")
	b, err := readRegular(filepath.Join(gitDir, "HEAD"), 256)
	if err != nil {
		return "", fmt.Errorf("reading HEAD: %w", err)
	}
	head := strings.TrimSpace(string(b))
	if hexSHA.MatchString(head) {
		return head, nil
	}
	ref, ok := strings.CutPrefix(head, "ref: ")
	if !ok || !refName.MatchString(ref) || strings.Contains(ref, "..") {
		return "", errors.New("unrecognised HEAD (neither a SHA nor a refs/ ref)")
	}
	if b, err := readRegular(filepath.Join(gitDir, filepath.FromSlash(ref)), 256); err == nil {
		if sha := strings.TrimSpace(string(b)); hexSHA.MatchString(sha) {
			return sha, nil
		}
		return "", fmt.Errorf("ref %s is not a SHA", ref)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("reading ref %s: %w", ref, err)
	}
	packed, err := readRegular(filepath.Join(gitDir, "packed-refs"), 8<<20)
	if err != nil {
		return "", fmt.Errorf("ref %s not found", ref)
	}
	for _, line := range strings.Split(string(packed), "\n") {
		if sha, name, ok := strings.Cut(strings.TrimSpace(line), " "); ok && name == ref && hexSHA.MatchString(sha) {
			return sha, nil
		}
	}
	return "", fmt.Errorf("ref %s not found", ref)
}

// UpdateInProgress is true while `brew update` plausibly holds the index
// lock, when a comparison would report a half-applied update. The lock
// counts only if it is under 10 minutes old and not dated in the future: a
// lock left behind or planted must not turn a tamper into "not assessed"
// forever. (A fetch alone does not touch the working tree, and HEAD is
// re-read after hashing, so FETCH_HEAD is not consulted.)
func UpdateInProgress(repo string, now time.Time) bool {
	fi, err := os.Lstat(filepath.Join(repo, ".git", "index.lock"))
	if err != nil {
		return false
	}
	age := now.Sub(fi.ModTime())
	return age >= 0 && age < 10*time.Minute
}

// BrewTreeReport is the result of CompareBrewTree.
type BrewTreeReport struct {
	Repo     string    `json:"repo"`
	Commit   string    `json:"commit"`
	Compared int       `json:"compared"`
	Findings []Finding `json:"findings"`
}

// CompareBrewTree hashes the checkout against the upstream tree for its HEAD.
// Tracked paths that differ in content or mode, or are missing, are TAMPER:
// deleting cmd/install.rb makes brew fall back to a `brew-install` found on
// PATH. Any untracked file under Library/Homebrew is TAMPER too (a 0644
// json.bundle shadows the stdlib, so "looks loadable" is not a safe test).
// Inside vendor/, only directories holding tracked files are checked, and
// only for files Ruby could load (.rb, .so, .bundle, .dylib, executables,
// symlinks): vendored gems carry untracked docs. Installed gems and portable
// Ruby live in untracked directories there and are not covered.
func CompareBrewTree(repo, commit string, upstream []TreeEntry) (BrewTreeReport, error) {
	r := BrewTreeReport{Repo: repo, Commit: commit, Findings: []Finding{}}
	tracked := make(map[string]TreeEntry, len(upstream))
	for _, e := range upstream {
		if e.Mode == "040000" || e.Mode == "160000" {
			continue // directories and submodules have no blob to compare
		}
		if BrewTreeInScope(e.Path) {
			tracked[e.Path] = e
		}
	}
	if len(tracked) == 0 {
		return r, errors.New("upstream tree has no paths in scope; refusing to report a clean comparison")
	}
	for path, want := range tracked {
		r.Compared++
		mode, sha, err := gitBlob(filepath.Join(repo, filepath.FromSlash(path)))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			r.Findings = append(r.Findings, Finding{SeverityTamper, path, "tracked file missing"})
		case err != nil:
			return r, fmt.Errorf("hashing %s: %w", path, err)
		case mode != want.Mode:
			r.Findings = append(r.Findings, Finding{SeverityTamper, path, "mode " + want.Mode + " upstream, " + mode + " here"})
		case sha != want.SHA:
			r.Findings = append(r.Findings, Finding{SeverityTamper, path, "content differs from upstream"})
		}
	}
	trackedDirs, walkDirs := map[string]bool{}, map[string]bool{}
	for path := range tracked {
		trackedDirs[pathpkg.Dir(path)] = true
		for d := pathpkg.Dir(path); d != "." && !walkDirs[d]; d = pathpkg.Dir(d) {
			walkDirs[d] = true
		}
	}
	// bin/brew finds its checkout with `pwd -P`, so a bin/ (or Library/)
	// swapped for a symlink to a copy elsewhere runs other code while every
	// hash below, read through the link, still matches.
	dirs := make([]string, 0, len(walkDirs))
	for d := range walkDirs {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		fi, err := os.Lstat(filepath.Join(repo, filepath.FromSlash(d)))
		if err == nil && !fi.IsDir() {
			r.Findings = append(r.Findings, Finding{SeverityTamper, d, "directory replaced by a symlink or file"})
		}
	}
	lib := filepath.Join(repo, "Library", "Homebrew")
	err := filepath.WalkDir(lib, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(repo, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if strings.HasPrefix(rel, "Library/Homebrew/vendor/") && !walkDirs[rel] {
				return fs.SkipDir // no tracked file below: installed gems, portable Ruby
			}
			return nil
		}
		if d.Name() == ".DS_Store" {
			return nil
		}
		if _, ok := tracked[rel]; ok {
			return nil
		}
		if strings.HasPrefix(rel, "Library/Homebrew/vendor/") {
			// Vendored gems ship docs brew does not track next to tracked
			// code, so only something Ruby could load counts there.
			if !trackedDirs[pathpkg.Dir(rel)] {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			switch pathpkg.Ext(rel) {
			case ".rb", ".so", ".bundle", ".dylib":
			default:
				if info.Mode()&fs.ModeSymlink == 0 && info.Mode().Perm()&0o111 == 0 {
					return nil
				}
			}
		}
		r.Findings = append(r.Findings, Finding{SeverityTamper, rel, "untracked file in brew's code"})
		return nil
	})
	if err != nil {
		return r, fmt.Errorf("walking %s: %w", lib, err)
	}
	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].Path < r.Findings[j].Path })
	return r, nil
}

// gitBlob returns the git mode and blob SHA-1 git would record for path:
// a symlink hashes its target, a file its bytes; 100755 when the owner may
// execute it.
func gitBlob(path string) (mode, sha string, err error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", "", err
	}
	h := sha1.New() //nolint:gosec // see import
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			return "", "", err
		}
		h.Write([]byte("blob " + strconv.Itoa(len(target)) + "\x00" + target))
		return "120000", hex.EncodeToString(h.Sum(nil)), nil
	case !fi.Mode().IsRegular():
		return "000000", "", nil // a directory or device where a file belongs: mode mismatch
	}
	f, fi, err := openRegular(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	h.Write([]byte("blob " + strconv.FormatInt(fi.Size(), 10) + "\x00"))
	if n, err := io.Copy(h, io.LimitReader(f, fi.Size()+1)); err != nil {
		return "", "", err
	} else if n != fi.Size() {
		return "", "", fmt.Errorf("size changed while hashing")
	}
	mode = "100644"
	if fi.Mode().Perm()&0o100 != 0 {
		mode = "100755"
	}
	return mode, hex.EncodeToString(h.Sum(nil)), nil
}

// EnvDrift compares a system brew.env with the file the server compiles, by
// EFFECTIVE value: brew exports every HOMEBREW_ line in order, so the last
// occurrence of a key wins, and a key re-set below a correct block silently
// undoes it. Every key the server sets must end with the server's value;
// keys only the local file sets are returned as extra (an admin's own
// settings), never as drift.
func EnvDrift(local, server string) (drift []string, extra []string) {
	want, l := brewEnvValues(server), brewEnvValues(local)
	for k, v := range want {
		got, ok := l[k]
		switch {
		case !ok:
			drift = append(drift, k+" missing")
		case got != v:
			drift = append(drift, k+" is "+strconv.Quote(got)+", policy says "+strconv.Quote(v))
		}
	}
	for k := range l {
		if _, ok := want[k]; !ok {
			extra = append(extra, k)
		}
	}
	sort.Strings(drift)
	sort.Strings(extra)
	return drift, extra
}

var brewEnvKeyRe = regexp.MustCompile(`^HOMEBREW_[A-Za-z0-9_]+$`)

// brewEnvValues mirrors bin/brew's loader: `read -r` trims surrounding
// whitespace, only HOMEBREW_ lines are exported, and later lines win.
func brewEnvValues(body string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, "=")
		if !ok || !brewEnvKeyRe.MatchString(k) {
			continue
		}
		out[k] = v
	}
	return out
}

// CheckGitConfig flags git settings that could make git run a program. brew
// runs git inside its own checkout on ordinary commands (`git describe
// --dirty`, `git diff`) and on every `brew update`, so `core.fsmonitor=/x`,
// a url.insteadOf to an ext:: transport or a post-merge hook runs attacker
// code inside brew while every tracked file still matches upstream.
//
// The config is checked against an ALLOW-list of the sections brew and git
// themselves write (core, remote, branch, fetch, pull, homebrew, plus
// harmless display settings); anything else is TAMPER. Lines this parser
// cannot read the way git does (text after a section header, a value
// continued with a trailing backslash) are TAMPER too, as are commondir and
// config.worktree, which make git read config and hooks from elsewhere.
func CheckGitConfig(repo string) ([]Finding, error) {
	gitDir := filepath.Join(repo, ".git")
	var out []Finding
	bad := func(path, reason string) { out = append(out, Finding{SeverityTamper, path, reason}) }
	for _, f := range []string{"commondir", "config.worktree"} {
		if _, err := os.Lstat(filepath.Join(gitDir, f)); err == nil {
			bad(".git/"+f, "makes git read config and hooks from another place")
		}
	}
	cfg, err := readRegular(filepath.Join(gitDir, "config"), 1<<20)
	if err != nil {
		return nil, fmt.Errorf(".git/config: %w", err)
	}
	section := ""
	for _, line := range strings.Split(string(cfg), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			bad(".git/config", "a value continued onto the next line")
			continue
		}
		if line[0] == '[' {
			head, rest, ok := strings.Cut(line, "]")
			if !ok || strings.TrimSpace(rest) != "" && rest[0] != '#' && rest[0] != ';' {
				bad(".git/config", "a setting on the same line as its section header")
			}
			section = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(head, "[")))
			if !gitSectionAllowed(section) {
				bad(".git/config", "["+section+"] is not a section brew or git writes here")
			}
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.ToLower(strings.Trim(strings.TrimSpace(v), `"`))
		if gitKeyRunsProgram(section, k, v) {
			bad(".git/config", "["+section+"] "+k+" can run a program inside brew's git calls")
		}
	}
	hooks, err := os.ReadDir(filepath.Join(gitDir, "hooks"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf(".git/hooks: %w", err)
	}
	for _, h := range hooks {
		switch {
		case strings.HasSuffix(h.Name(), ".sample"):
		case brewGitHooks[h.Name()]:
			bad(".git/hooks/"+h.Name(), "git hook that brew's own git calls run")
		default:
			// Org git templates (git-secrets, pre-commit) land here via
			// `git init`; brew never commits, so these never fire.
			out = append(out, Finding{SeverityWarn, ".git/hooks/" + h.Name(), "git hook brew does not run"})
		}
	}
	return out, nil
}

// brewGitHooks are the hooks brew's checkout, fetch, reset, rebase, stash
// and gc can fire.
var brewGitHooks = map[string]bool{
	"post-checkout": true, "post-merge": true, "post-rewrite": true, "pre-rebase": true,
	"reference-transaction": true, "post-index-change": true, "pre-auto-gc": true,
	"fsmonitor-watchman": true,
}

func gitSectionAllowed(section string) bool {
	base, sub, _ := strings.Cut(section, " ")
	switch base {
	case "core", "fetch", "pull", "homebrew", "user", "advice", "color", "init", "index", "gc", "pack", "feature", "safe":
		return sub == ""
	case "remote", "branch":
		return true
	}
	return false
}

// gitKeyRunsProgram: keys inside allowed sections that still run something.
func gitKeyRunsProgram(section, key, value string) bool {
	base, _, _ := strings.Cut(section, " ")
	switch base {
	case "remote":
		switch key {
		case "uploadpack", "receivepack", "proxy", "vcs":
			return true
		case "url", "pushurl":
			return strings.HasPrefix(value, "ext::") || strings.HasPrefix(value, "fd::")
		}
	case "core":
		switch key {
		case "fsmonitor":
			return value != "" && value != "false" && value != "0" && value != "no" && value != "off"
		case "hookspath", "sshcommand", "pager", "editor", "askpass", "gitproxy", "alternaterefscommand", "worktree":
			return true
		}
	}
	return false
}
