package cli

// `chainsaw guard allow` — the local, offline escape hatch for a FALSE BLOCK
// on the install path. P4 in docs/proposal_typosquat_fp_class.md, and a
// standing ruling from the 742-false-positive postmortem.
//
// The problem it solves: the block-lane gate (guard_typosquat_gate.go)
// NARROWS the known false-block class — it does not close it, and no
// name-similarity heuristic reaches zero. Measured on 24,206 real package
// names held out of the seed index, the gate took the block rate from 1.87% to
// 1.02%: 206 false blocks recovered, 247 STILL REFUSED. This file exists for
// those 247 and for the ones the corpus never sampled. A user who hits one has
// exactly two options without it — rename their dependency, or stop running
// their installs through Chainsaw. The second one is what actually happens,
// and a guard that gets uninstalled protects nobody. One recorded, auditable
// decision per coordinate is strictly better than a wholesale bypass.
//
// `nano` and `args`, the two reported false blocks, now WARN and need nothing
// from this file. A survivor does; npm:jsdoc (against jsdom #451) is one:
//
//	$ chainsaw npm install jsdoc
//	chainsaw  ✗ blocked  npm:jsdoc — looks like a typosquat of "jsdom" (distance 1, edit-distance, target rank #451)
//	chainsaw  if you have verified this package is real: chainsaw guard allow npm:jsdoc
//	chainsaw  ✗ refused at the install path — nothing was installed
//
//	$ chainsaw guard allow npm:jsdoc
//	Allowed npm:jsdoc on this machine.
//	  Recorded  looks like a typosquat of "jsdom" (distance 1, edit-distance, target rank #451)
//	  Stored    <config home>/guard_allowlist.json
//
// The "Stored" line prints the RESOLVED path (guardAllowlistPath). The config
// home is platform-dependent — see cli/platform.ConfigHome — so it is
// ~/.chainsaw on macOS, ~/.config/chainsaw on Linux, and
// %APPDATA%\Chainsaw on Windows. Never write one of those as the universal
// answer; `chainsaw status` prints the real one.
//
// TRUST ON FIRST USE. `guard allow` evaluates the coordinate at the moment you
// allow it and records the verdict text verbatim, so the file answers "what
// was waived, and when" a year later without anyone reconstructing it.
//
// ── THE SECURITY BOUNDARY ────────────────────────────────────────────────────
//
// The allowlist clears INFERENCE ONLY. Concretely: the typosquat-* severities,
// and nothing else. Two exclusions carry the weight, and both are structural
// rather than a list someone has to remember to update:
//
//   - known-malicious ("malicious") and known-vulnerable are GROUND TRUTH about
//     a published incident, not a guess about a name. evaluate() returns both
//     BEFORE the typosquat lane, so the consult below is physically downstream
//     of them and cannot clear either. `chainsaw guard allow npm:<malware>` is
//     refused at write time too, so the user is told the truth immediately
//     instead of believing they fixed something.
//
//   - behavioral-* (the byte-level heuristics in guard_artifact.go) are
//     deliberately NOT allowlistable, and this is the judgement call in the
//     file. A typosquat verdict is a property of the NAME: it is identical for
//     every version the coordinate will ever publish, so a version-less "allow
//     npm:jsdoc" is exactly as true next year as today. A behavioral verdict is
//     a property of the BYTES, which change on every release — a version-less
//     allow would silently cover a future compromised version of a package the
//     user vouched for while it was clean. That is the compromised-maintainer
//     attack, handed a permanent exemption. benign_fp_eval_test.go reaches the
//     same conclusion from the false-positive side: "narrowing further would
//     need a per-package allowlist, which is exactly what an attacker targets."
//     Byte-level analysis is also opt-in already (CHAINSAW_GUARD_ARTIFACT_DIR /
//     CHAINSAW_GUARD_DEEP), so an operator who hits a behavioral FP has an
//     env-level lever; the typosquat lane is on for everyone and has none.
//
// The same predicate — guardAllowlistableSeverity — gates the write path, the
// install-path consult, and the "here is your escape hatch" hint in
// guard_install.go, so the three cannot drift apart.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// guardAllowlistEnv overrides the local allowlist path. Mirrors guardDBEnv
// (guard_eval.go), which does the same for the known-malicious cache: one
// variable, one file, so a test or a sandboxed CI runner can point the store
// somewhere hermetic without touching the user's real config.
const guardAllowlistEnv = "CHAINSAW_GUARD_ALLOWLIST"

// guardAllowlistPath resolves the store. Default: next to guard_state.json in
// the config dir, NOT next to known_malicious.json in the cache dir. The
// distinction is deliberate — the malware cache is regenerable data that a
// cache eviction may legitimately delete, while this file is a set of human
// decisions that must survive one. Empty when no config home can be resolved;
// callers treat that as "no allowlist" (the safe direction).
func guardAllowlistPath() string {
	if p := strings.TrimSpace(os.Getenv(guardAllowlistEnv)); p != "" {
		return p
	}
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "guard_allowlist.json")
}

// guardAllowlistSchema is the on-disk format version. A file written by a
// NEWER chainsaw is refused rather than reinterpreted — see loadGuardAllowlist.
const guardAllowlistSchema = 1

// guardAllowEntry is one waived coordinate. Reason and AllowedAt exist so the
// file is an audit trail rather than a bare list of names: six months later,
// "why is this here" has an answer that does not depend on anyone's memory.
type guardAllowEntry struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	// Reason is the guard's OWN verdict text at the moment the entry was
	// written (trust on first use), or a plain note when the guard had no
	// verdict to give.
	Reason string `json:"reason"`
	// AllowedAt is RFC3339, UTC.
	AllowedAt string `json:"allowed_at"`
}

type guardAllowlistFile struct {
	Schema int `json:"schema"`
	// Entries must be non-nil wherever this struct (or the field alone, as in
	// `guard allow --list --json`) is marshalled: `entries` is an ARRAY in
	// every case, including the empty one. A nil slice emits
	// `"entries": null`, which makes `.entries.length` throw and
	// `jq '.entries[]'` fail on the store's most common state — nothing
	// allowed yet. No `omitempty`: dropping the key breaks consumers the
	// other way. loadGuardAllowlist and writeGuardAllowlist both normalise.
	Entries []guardAllowEntry `json:"entries"`
}

// guardAllowSet is the lookup shape used on the install path: canonical
// coordinate key → entry.
type guardAllowSet map[string]guardAllowEntry

// guardAllowlistLoad is a read of the store, including why a present file was
// not usable. The install path only ever looks at Set (an unusable file yields
// an EMPTY set, so every verdict stands); the CLI surfaces Problem loudly,
// because a silently ignored allowlist would look to the user like their fix
// stopped working for no reason.
type guardAllowlistLoad struct {
	Path    string
	Present bool
	Problem string
	File    guardAllowlistFile
	Set     guardAllowSet
}

// loadGuardAllowlist reads the store from disk. It NEVER returns an error and
// NEVER panics: a missing, unreadable, corrupt, or future-schema file degrades
// to an EMPTY allowlist. That is the only safe failure direction — an empty
// allowlist waives nothing, so every verdict the guard would have emitted is
// still emitted. Degrading to "allow everything" would turn a truncated write
// or a stray byte into a total guard bypass.
func loadGuardAllowlist() guardAllowlistLoad {
	l := guardAllowlistLoad{
		Path: guardAllowlistPath(),
		File: guardAllowlistFile{Schema: guardAllowlistSchema, Entries: []guardAllowEntry{}},
		Set:  guardAllowSet{},
	}
	if l.Path == "" {
		l.Problem = "no config directory could be resolved; set " + guardAllowlistEnv
		return l
	}
	// The same lstat refusal the write path takes, for the same reason in the
	// other direction. Reading THROUGH a link is not a clobber, so this is the
	// weaker half — but a link pointing outside the config dir lets a file
	// nobody audits (a world-writable /tmp path, another account's home) decide
	// which packages this machine stops refusing, without anything ever being
	// written where the user would look for it. Degrading to an EMPTY allowlist
	// is the direction every other unusable-file case already takes: nothing is
	// waived, every verdict still stands, and `guard allow --list` says why.
	if err := guardAllowlistPathIsNotASymlink(l.Path); err != nil {
		l.Present = true
		l.Problem = err.Error() + " — treated as empty"
		return l
	}
	data, err := os.ReadFile(l.Path)
	if err != nil {
		if !os.IsNotExist(err) {
			l.Present = true
			l.Problem = fmt.Sprintf("unreadable (%v) — treated as empty", err)
		}
		return l
	}
	l.Present = true

	var f guardAllowlistFile
	if err := json.Unmarshal(data, &f); err != nil {
		l.Problem = fmt.Sprintf("not valid JSON (%v) — treated as empty", err)
		return l
	}
	// A file written by a newer chainsaw may scope entries in ways this binary
	// does not understand (a per-version field, say). Reinterpreting it under
	// the old rules could only ever WIDEN what is waived, so stand down.
	if f.Schema > guardAllowlistSchema {
		l.Problem = fmt.Sprintf("schema %d was written by a newer chainsaw (this binary understands %d) — treated as empty; upgrade chainsaw",
			f.Schema, guardAllowlistSchema)
		return l
	}

	// Same non-nil rule as the initialiser above: this reassignment is the
	// path a PRESENT-but-empty store takes, so it must not put the nil back.
	l.File = guardAllowlistFile{Schema: guardAllowlistSchema, Entries: []guardAllowEntry{}}
	for _, e := range f.Entries {
		e.Ecosystem = guardCanonicalEcosystem(e.Ecosystem)
		e.Name = strings.TrimSpace(e.Name)
		// A hand-edited row missing a coordinate cannot match anything; drop
		// it rather than letting it occupy a key.
		if e.Ecosystem == "" || e.Name == "" {
			continue
		}
		key := guardAllowKey(e.Ecosystem, e.Name)
		if _, dup := l.Set[key]; dup {
			continue
		}
		l.Set[key] = e
		l.File.Entries = append(l.File.Entries, e)
	}
	sortGuardAllowEntries(l.File.Entries)
	return l
}

func sortGuardAllowEntries(entries []guardAllowEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Ecosystem != entries[j].Ecosystem {
			return entries[i].Ecosystem < entries[j].Ecosystem
		}
		return entries[i].Name < entries[j].Name
	})
}

// guardAllowlistPathIsNotASymlink refuses a store path whose final component is
// a symbolic link. The allowlist is this binary's own state file; there is no
// legitimate reason for it to be a link, so saying so out loud is strictly
// better than silently reading or writing somewhere else. A path that does not
// exist yet is fine — that is the first-ever `guard allow`.
func guardAllowlistPathIsNotASymlink(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf(
			"%s is a symbolic link; refusing to use it — delete the link, or point %s at a real file",
			path, guardAllowlistEnv)
	}
	return nil
}

// writeGuardAllowlist persists the store at mode 0600, creating parent dirs.
//
// SYMLINK REFUSAL, THEN AN ATOMIC RENAME. Writing straight to the path with
// os.WriteFile + os.Chmod follows a symlink: a link planted at the allowlist
// path (guardAllowlistPath) turned `chainsaw guard allow` into a
// truncate-and-clobber of whatever it pointed at, with partly attacker-chosen
// JSON as the content and 0600 as the final mode. So:
//
//  1. os.Lstat the destination and refuse outright if it is a link.
//  2. Write a fresh temp file in the SAME directory and os.Rename it into
//     place. rename(2) acts on the link itself and never on its target, so a
//     symlink planted in the window between the lstat and the write is
//     REPLACED rather than followed — the check-then-write race has no
//     exploitable outcome. Same directory, because a rename across filesystems
//     fails; and an atomic replace is also why a killed or crashed write can no
//     longer leave a half-written store on disk, which loadGuardAllowlist would
//     have had to degrade to empty.
//
// THE EXPLICIT CHMOD SURVIVES, it just moves to the temp file. Its original
// reason — os.WriteFile applies its perm argument only when it CREATES the
// file, so a store that already existed with a loose mode kept it — is answered
// even more directly now: every write renames a fresh file over the old one, so
// there is no inherited mode left to re-tighten. What the Chmod still buys is
// the mode the new file lands with: os.CreateTemp asks for 0600 but a umask can
// only ever take bits away, and the mode at rename time is the mode the store
// keeps. This file records which packages a machine has stopped refusing, and a
// group-writable copy is an invitation to edit someone else's exemptions. It is
// the FILE's Chmod (an fd operation), not os.Chmod on the temp path, so it
// cannot itself be redirected by a link swapped in underneath us.
func writeGuardAllowlist(path string, f guardAllowlistFile) error {
	if path == "" {
		return fmt.Errorf("cannot determine an allowlist path; set %s to a writable file path", guardAllowlistEnv)
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := guardAllowlistPathIsNotASymlink(path); err != nil {
		return err
	}

	f.Schema = guardAllowlistSchema
	// The on-disk store is a JSON file users read with jq as readily as the
	// --json output is, so it takes the same non-nil rule: a caller that hands
	// us a nil slice must not produce `"entries": null` on disk. Both current
	// callers build the slice with make(), so this only ever fires for a
	// would-be nil.
	if f.Entries == nil {
		f.Entries = []guardAllowEntry{}
	}
	sortGuardAllowEntries(f.Entries)
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".guard_allowlist-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Every failure from here on removes the temp file. A stray .tmp beside the
	// store would be read by nothing, but it is a confusing residue of a failed
	// write and it is 0600 data about this machine's exemptions.
	abandon := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		return abandon(err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		return abandon(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	invalidateGuardAllowlistCache()
	return nil
}

// ── the install-path consult ────────────────────────────────────────────────

// guardSeverityTyposquat* mirror the severity strings the typosquat lane in
// guard_eval.go emits. TestGuardAllowlistSeverityStringsMatchTheEvaluator pins
// them against a real verdict so a rename there cannot silently make the
// escape hatch (and its hint) stop applying.
const (
	guardSeverityTyposquatPrefix = "typosquat-"
	guardSeverityTyposquatHigh   = guardSeverityTyposquatPrefix + "high"
	guardSeverityTyposquatMedium = guardSeverityTyposquatPrefix + "medium"
	// guardSeverityTyposquatDemoted is a d=1 hit inside the rank cutoff that
	// the block-lane gate (guard_typosquat_gate.go) downgraded on shape or
	// target length. Warn-level like "medium", but printed even under --quiet.
	guardSeverityTyposquatDemoted = guardSeverityTyposquatPrefix + "demoted"
)

// guardAllowlistableSeverity is the ONE definition of what an allowlist entry
// may clear: name-similarity inference, and nothing else. Used by the write
// path (refuse to record a coordinate the guard blocks on other evidence), by
// the install-path consult, and by the block printer's escape-hatch hint.
//
// Everything absent from this predicate is un-waivable by construction:
// "malicious", "known-vulnerable", "coverage", the "server-*" preflight rows,
// and every "behavioral-*" byte-level verdict. See the file header for why
// behavioral-* is excluded on purpose rather than by oversight.
//
// SEVERITY IS NOT THE WHOLE ANSWER — use guardAllowlistableVerdict when a
// verdict is in hand. The homoglyph block carries "typosquat-high" (that is
// what the user is told, and the recall suite pins it) but sets
// guardVerdict.Unwaivable, because a confusable collision is byte-level
// evidence rather than the name-similarity inference this escape hatch is for.
func guardAllowlistableSeverity(severity string) bool {
	return strings.HasPrefix(severity, guardSeverityTyposquatPrefix)
}

// guardAllowlistableVerdict is guardAllowlistableSeverity plus the per-verdict
// veto. Every caller that HAS a verdict must use this one; the severity-only
// form remains for the write path, which has a string and no verdict.
func guardAllowlistableVerdict(v guardVerdict) bool {
	return !v.Unwaivable && guardAllowlistableSeverity(v.Severity)
}

// guardAllowlistCache holds one read of the store per process. A bare
// `npm ci` evaluates every entry in the lockfile, and re-reading the file per
// package would be thousands of syscalls on the install hot path. Keyed by the
// resolved path so a test that repoints guardAllowlistEnv gets a fresh read,
// and invalidated by every write so `guard allow` never observes stale state.
var guardAllowlistCache struct {
	mu     sync.Mutex
	loaded bool
	path   string
	set    guardAllowSet
}

func invalidateGuardAllowlistCache() {
	c := &guardAllowlistCache
	c.mu.Lock()
	c.loaded, c.path, c.set = false, "", nil
	c.mu.Unlock()
}

func cachedGuardAllowSet() guardAllowSet {
	path := guardAllowlistPath()
	c := &guardAllowlistCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loaded && c.path == path {
		return c.set
	}
	c.set = loadGuardAllowlist().Set
	c.path, c.loaded = path, true
	return c.set
}

// guardAllowlistClears reports whether an explicit local decision waives a
// verdict of this severity for this coordinate. BOTH halves must hold: the
// severity must be one the allowlist is permitted to clear, and the coordinate
// must actually be listed.
func guardAllowlistClears(spec packageSpec, severity string) bool {
	if !guardAllowlistableSeverity(severity) {
		return false
	}
	if strings.TrimSpace(spec.Name) == "" {
		return false
	}
	_, ok := cachedGuardAllowSet()[guardAllowKey(spec.Ecosystem, spec.Name)]
	return ok
}

// guardAllowlistClearsTyposquat is the single consult on the install path (see
// evaluate in guard_eval.go). It sits INSIDE the typosquat lane, downstream of
// the known-malicious and known-vulnerable returns and UPSTREAM of nothing:
// clearing a typosquat hit falls through to the byte-level artifact scan
// exactly as a clean name does, so a waiver can never mask a behavioral block.
// That ordering is the same one the "pendingWarn" comment block in evaluate
// exists to protect — a name-level result must not short-circuit the bytes.
func guardAllowlistClearsTyposquat(spec packageSpec) bool {
	return guardAllowlistClears(spec, guardSeverityTyposquatHigh)
}

// ── coordinates ─────────────────────────────────────────────────────────────

// guardAllowlistEcosystems is the set of ecosystems the guard can actually
// produce a verdict for — the ecosystems the five wrappers in guard_install.go
// stamp onto a packageSpec. An entry outside it could never match anything, so
// `guard allow maven:foo` is refused at write time instead of being recorded
// as a permanently inert row the user believes is working.
//
// A NEW guard wrapper must add its ecosystem here.
// TestGuardAllowlistEcosystemsCoverEveryWrapper walks the real parsers and
// fails if one of them emits an ecosystem this map does not list.
var guardAllowlistEcosystems = map[string]bool{
	"npm":      true,
	"pip":      true,
	"go":       true,
	"cargo":    true,
	"rubygems": true,
}

// guardEcosystemAliases maps the spellings people actually type (registry
// names, language names) onto the guard's own ecosystem verbs. Purely a
// convenience at the CLI edge; the stored key is always canonical.
var guardEcosystemAliases = map[string]string{
	"npmjs":     "npm",
	"node":      "npm",
	"nodejs":    "npm",
	"pypi":      "pip",
	"python":    "pip",
	"pip3":      "pip",
	"golang":    "go",
	"gomod":     "go",
	"crates":    "cargo",
	"crates-io": "cargo",
	"cratesio":  "cargo",
	"rust":      "cargo",
	"gem":       "rubygems",
	"gems":      "rubygems",
	"ruby":      "rubygems",
}

func guardCanonicalEcosystem(ecosystem string) string {
	e := strings.ToLower(strings.TrimSpace(ecosystem))
	if canonical, ok := guardEcosystemAliases[e]; ok {
		return canonical
	}
	return e
}

// guardAllowKey is the lookup key for one coordinate.
//
// The ecosystem folds (case + alias); the NAME does not. Case-folding the name
// would be defensible for npm and PyPI, whose registries are case-insensitive,
// and wrong for Go, where module paths are case-sensitive and the
// Sirupsen/sirupsen split is a real historical incident. A security control
// that widens a waiver by guessing is the wrong trade, and the block printer
// emits the coordinate verbatim, so copy-pasting the hint always matches.
func guardAllowKey(ecosystem, name string) string {
	return guardCanonicalEcosystem(ecosystem) + ":" + strings.TrimSpace(name)
}

// guardAllowCoordinate renders a spec as the `ecosystem:name` token
// `guard allow` accepts. Version-less on purpose: a typosquat verdict is a
// property of the name, identical for every version, so the waiver is too.
func guardAllowCoordinate(spec packageSpec) string {
	return guardAllowKey(spec.Ecosystem, spec.Name)
}

// guardHintCoordinate renders a coordinate for the escape-hatch HINT printed
// beside a block (guard_install.go). Pure ASCII names pass through unchanged —
// the line exists to be copied and pasted.
//
// A name carrying ANY non-ASCII rune does not. Printing it raw is how a
// confusable name gets laundered past the reader: `npm:lоdash` with a Cyrillic
// о renders identically to `npm:lodash`, so a hint offering to allow it reads
// as advice to allow the package the user meant to install. Those runes are
// escaped to \uXXXX and the line carries a note saying so. The result is
// deliberately NOT copy-pasteable: a coordinate a human cannot read is one
// they should retype from the registry, not paste from a warning. (Homoglyph
// blocks no longer print the hint at all — guardVerdict.Unwaivable — so this
// covers the residual case: a non-ASCII name that blocked on edit distance.)
func guardHintCoordinate(spec packageSpec) string {
	raw := guardAllowCoordinate(spec)
	if isASCII(raw) {
		return sanitizeForTerminal(raw)
	}
	var b strings.Builder
	for _, r := range raw {
		if r < 0x80 {
			b.WriteRune(r)
			continue
		}
		fmt.Fprintf(&b, "\\u%04X", r)
	}
	return sanitizeForTerminal(b.String()) + "  (name contains non-ASCII runes — it is not the package it resembles)"
}

func isASCII(s string) bool {
	for _, r := range s {
		if r >= 0x80 {
			return false
		}
	}
	return true
}

// parseGuardCoordinate accepts both `<ecosystem>:<name>` and the two-token
// `<ecosystem> <name>` form, and tolerates a version suffix by parsing the
// name through the SAME per-ecosystem parser the install path uses — so
// `npm:@babel/core` keeps its scope, `npm:nano@1.2.3` and `rubygems:rails:7.1`
// drop their version, and the caller can tell the user the entry is
// version-less rather than silently pretending it pinned something.
func parseGuardCoordinate(args []string) (spec packageSpec, hadVersion bool, err error) {
	var ecosystem, rest string
	switch len(args) {
	case 1:
		token := strings.TrimSpace(args[0])
		i := strings.Index(token, ":")
		if i <= 0 || i == len(token)-1 {
			return packageSpec{}, false, fmt.Errorf(
				"expected <ecosystem>:<name> (for example npm:nano), got %q", token)
		}
		ecosystem, rest = token[:i], token[i+1:]
	case 2:
		ecosystem, rest = strings.TrimSpace(args[0]), strings.TrimSpace(args[1])
	default:
		return packageSpec{}, false, errors.New("expected <ecosystem>:<name>, or <ecosystem> <name>")
	}

	canonical := guardCanonicalEcosystem(ecosystem)
	if !guardAllowlistEcosystems[canonical] {
		return packageSpec{}, false, fmt.Errorf(
			"unknown ecosystem %q — the guard evaluates %s (aliases such as pypi and crates-io are accepted)",
			ecosystem, strings.Join(sortedGuardAllowlistEcosystems(), ", "))
	}

	name, version := splitGuardAllowName(canonical, rest)
	if name == "" {
		return packageSpec{}, false, fmt.Errorf("empty package name in %q", strings.Join(args, " "))
	}
	return packageSpec{Ecosystem: canonical, Name: name}, version != "", nil
}

// splitGuardAllowName reuses the install path's own spec parsers so a
// coordinate is read exactly the way the guard would read the install argument
// it came from.
func splitGuardAllowName(canonicalEcosystem, raw string) (name, version string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	switch canonicalEcosystem {
	case "npm":
		s := parseNpmSpec(raw)
		return s.Name, s.Version
	case "pip":
		s := parsePipSpec(raw)
		return s.Name, s.Version
	case "cargo":
		s := parseCargoSpec(raw)
		return s.Name, s.Version
	case "rubygems":
		s := parseGemSpec(raw)
		return s.Name, s.Version
	default: // go module paths: version after the last '@', as `go get` writes it
		if at := strings.LastIndex(raw, "@"); at > 0 {
			return raw[:at], raw[at+1:]
		}
		return raw, ""
	}
}

func sortedGuardAllowlistEcosystems() []string {
	out := make([]string, 0, len(guardAllowlistEcosystems))
	for e := range guardAllowlistEcosystems {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// ── the command ─────────────────────────────────────────────────────────────

var guardAllowCmd = &cobra.Command{
	Use:   "allow [<ecosystem>:<name>]",
	Short: "Clear a false typosquat block for one package, locally and permanently",
	// Long carries one runtime-resolved path, so it is finished in init()
	// below. guardAllowLongTmpl holds the %s.
	Example: `  # clear a false typosquat block
  chainsaw guard allow npm:jsdoc

  # same thing, two-token form
  chainsaw guard allow pip nvidia-cudnn-cu11

  # see what this machine has allowed, and why
  chainsaw guard allow --list

  # undo one
  chainsaw guard allow --remove npm:jsdoc`,
	Args:         cobra.MaximumNArgs(2),
	SilenceUsage: true,
	RunE:         runGuardAllow,
}

// guardAllowLongTmpl is guardAllowCmd.Long with the allowlist location left
// as a %s. The path is platform-dependent (cli/platform.ConfigHome) and
// env-overridable, so hardcoding "~/.chainsaw/guard_allowlist.json" — as this
// help once did — is wrong for every Windows and Linux operator.
const guardAllowLongTmpl = `Record a local decision that one package is NOT a typosquat, so the guard
stops refusing it on this machine.

Typosquat detection is name-similarity inference, and no heuristic reaches
zero false positives. This is the escape hatch that makes a residual one
survivable: instead of turning the guard off, you clear the single coordinate
that was wrong. The decision is written to a small JSON file (mode 0600) next
to the guard's other local state, with the verdict text and a timestamp, so it
reads as an audit trail rather than a list of names.

Offline. Nothing is sent anywhere, and nothing is shared with other machines.%s

WHAT IT CANNOT DO. The allowlist clears typosquat verdicts and nothing else.
A known-malicious package (the OpenSSF feed and the built-in floor) and a
known-vulnerable version are evidence about a published incident, not a guess
about a name, so they are refused here and keep blocking at install time. The
byte-level behavioral checks are excluded too, and deliberately: they read the
package's bytes, which change with every release, so a version-less exemption
would silently cover a future compromised version of a package you vouched for
while it was clean.

Exit codes: 0 on success, 1 when the coordinate is refused on evidence the
allowlist cannot clear, 2 on an IO failure, 4 on a bad invocation.`

func init() {
	// Resolve the store location for the help text. guardAllowlistPath()
	// reads only the environment and $HOME, so it is safe at init() —
	// before viper, flags, or initConfig(). It returns "" when no config
	// home can be resolved at all; in that case say nothing rather than
	// print a dangling "Stored in .".
	if p := displayPath(guardAllowlistPath()); p != "" {
		guardAllowCmd.Long = fmt.Sprintf(guardAllowLongTmpl,
			fmt.Sprintf("\n\nStored in %s (override with "+guardAllowlistEnv+").", p))
	} else {
		guardAllowCmd.Long = fmt.Sprintf(guardAllowLongTmpl, "")
	}

	guardAllowCmd.Flags().Bool("list", false, "list the allowed coordinates and exit")
	// `--remove` rather than a `guard deny` sibling, on purpose. "deny" reads
	// as "add to a denylist" — a control this guard does not have — so
	// `chainsaw guard deny npm:evil` would invite the reasonable expectation
	// that it starts BLOCKING a package that currently passes. It does the
	// opposite job: it undoes an allow. Naming it as the inverse of the verb
	// it undoes keeps the mental model to one command.
	guardAllowCmd.Flags().Bool("remove", false, "remove the coordinate from the allowlist instead of adding it")
	guardCmd.AddCommand(guardAllowCmd)
}

func runGuardAllow(cmd *cobra.Command, args []string) error {
	list, _ := cmd.Flags().GetBool("list")
	remove, _ := cmd.Flags().GetBool("remove")

	switch {
	case list && remove:
		return &ExitCodeError{Code: ExitUsage, Err: errors.New("--list and --remove cannot be combined")}
	case list && len(args) > 0:
		return &ExitCodeError{Code: ExitUsage, Err: errors.New("--list takes no arguments")}
	case list:
		return runGuardAllowList(cmd)
	case len(args) == 0:
		return &ExitCodeError{Code: ExitUsage, Err: errors.New(
			"name a package: chainsaw guard allow <ecosystem>:<name> (or --list to see the current allowlist)")}
	}

	spec, hadVersion, err := parseGuardCoordinate(args)
	if err != nil {
		return &ExitCodeError{Code: ExitUsage, Err: err}
	}
	if remove {
		return runGuardAllowRemove(cmd, spec)
	}
	return runGuardAllowAdd(cmd, spec, hadVersion)
}

func runGuardAllowAdd(cmd *cobra.Command, spec packageSpec, hadVersion bool) error {
	coordinate := guardAllowCoordinate(spec)

	// TRUST ON FIRST USE: ask the guard what it currently thinks of this
	// coordinate and record the answer verbatim. The same call is what makes
	// the refusal below honest — we refuse on the guard's real verdict, not on
	// a second, drifting copy of the "is this waivable" rule.
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	verdict := newLocalGuard().evaluate(ctx, spec)

	// guardAllowlistableVerdict, not the severity-only form: the homoglyph
	// block is "typosquat-high" yet Unwaivable, and recording an entry that
	// the install path will never consult would tell the user they had fixed
	// something they had not.
	if verdict.Block && !guardAllowlistableVerdict(verdict) {
		payload := map[string]any{
			"action":      "refused",
			"ecosystem":   spec.Ecosystem,
			"name":        spec.Name,
			"severity":    verdict.Severity,
			"reason":      verdict.Reason,
			"allowlisted": false,
		}
		human := func() error {
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Refusing to allow %s — nothing was written.\n\n", coordinate)
			fmt.Fprintf(out, "  Verdict   %s\n", sanitizeForTerminal(verdict.Reason))
			fmt.Fprintf(out, "  Severity  %s\n\n", verdict.Severity)
			fmt.Fprintln(out, "The allowlist clears typosquat verdicts, which are name-similarity inference.")
			fmt.Fprintln(out, "This coordinate is refused on harder evidence — a published incident, or a")
			fmt.Fprintln(out, "byte-level Unicode confusable collision with a popular name — so allowing it")
			fmt.Fprintln(out, "would not change the outcome even if it were recorded: the install path")
			fmt.Fprintln(out, "checks that evidence before it ever reaches the allowlist.")
			return nil
		}
		gate := func() error {
			return &ExitCodeError{Code: ExitBlocked, Err: fmt.Errorf(
				"%s cannot be allowed: %s", coordinate, verdict.Reason)}
		}
		return emitAndGate(cmd, payload, human, gate)
	}

	load := loadGuardAllowlist()
	reason := verdict.Reason
	if reason == "" {
		reason = "no verdict at the time it was allowed (recorded ahead of one)"
	}
	entry := guardAllowEntry{
		Ecosystem: spec.Ecosystem,
		Name:      spec.Name,
		Reason:    reason,
		AllowedAt: time.Now().UTC().Format(time.RFC3339),
	}

	key := guardAllowKey(spec.Ecosystem, spec.Name)
	_, existed := load.Set[key]
	entries := make([]guardAllowEntry, 0, len(load.File.Entries)+1)
	for _, e := range load.File.Entries {
		if guardAllowKey(e.Ecosystem, e.Name) == key {
			continue
		}
		entries = append(entries, e)
	}
	entries = append(entries, entry)

	if err := writeGuardAllowlist(load.Path, guardAllowlistFile{Entries: entries}); err != nil {
		return &ExitCodeError{Code: ExitOpError, Err: fmt.Errorf("writing the allowlist: %w", err)}
	}

	action := "allowed"
	if existed {
		action = "reaffirmed"
	}
	payload := map[string]any{
		"action":      action,
		"ecosystem":   entry.Ecosystem,
		"name":        entry.Name,
		"reason":      entry.Reason,
		"allowed_at":  entry.AllowedAt,
		"path":        load.Path,
		"entries":     len(entries),
		"allowlisted": true,
	}
	return emitAndGate(cmd, payload, func() error {
		out := cmd.OutOrStdout()
		if existed {
			fmt.Fprintf(out, "Already allowed: %s (reason and timestamp refreshed).\n", coordinate)
		} else {
			fmt.Fprintf(out, "Allowed %s on this machine.\n", coordinate)
		}
		fmt.Fprintf(out, "  Recorded  %s\n", sanitizeForTerminal(entry.Reason))
		fmt.Fprintf(out, "  Stored    %s\n", load.Path)
		if hadVersion {
			fmt.Fprintln(out, "  Note      the version was dropped: a typosquat verdict is a property of the")
			fmt.Fprintln(out, "            name, so the entry covers every version of this package.")
		}
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Still enforced for this package: known-malicious feed hits, known-vulnerable")
		fmt.Fprintln(out, "versions, and the byte-level checks. Undo with:")
		fmt.Fprintf(out, "  chainsaw guard allow --remove %s\n", coordinate)
		return nil
	}, nil)
}

func runGuardAllowRemove(cmd *cobra.Command, spec packageSpec) error {
	coordinate := guardAllowCoordinate(spec)
	load := loadGuardAllowlist()
	key := guardAllowKey(spec.Ecosystem, spec.Name)

	kept := make([]guardAllowEntry, 0, len(load.File.Entries))
	for _, e := range load.File.Entries {
		if guardAllowKey(e.Ecosystem, e.Name) == key {
			continue
		}
		kept = append(kept, e)
	}
	removed := len(kept) != len(load.File.Entries)

	// Removal is idempotent: asking for a coordinate to stop being waived when
	// it never was is a satisfied request, not an error. It is also the
	// SAFE direction, so failing it would be theatre.
	if removed {
		if err := writeGuardAllowlist(load.Path, guardAllowlistFile{Entries: kept}); err != nil {
			return &ExitCodeError{Code: ExitOpError, Err: fmt.Errorf("writing the allowlist: %w", err)}
		}
	}

	payload := map[string]any{
		"action":      map[bool]string{true: "removed", false: "not-present"}[removed],
		"ecosystem":   spec.Ecosystem,
		"name":        spec.Name,
		"path":        load.Path,
		"entries":     len(kept),
		"allowlisted": false,
	}
	return emitAndGate(cmd, payload, func() error {
		out := cmd.OutOrStdout()
		if removed {
			fmt.Fprintf(out, "Removed %s from the allowlist. The guard will refuse it again if it matches a typosquat.\n", coordinate)
		} else {
			fmt.Fprintf(out, "%s was not in the allowlist; nothing to remove.\n", coordinate)
		}
		return nil
	}, nil)
}

func runGuardAllowList(cmd *cobra.Command) error {
	load := loadGuardAllowlist()

	payload := map[string]any{
		"path":    load.Path,
		"schema":  guardAllowlistSchema,
		"entries": load.File.Entries,
		"problem": load.Problem,
	}
	return emitAndGate(cmd, payload, func() error {
		out := cmd.OutOrStdout()
		if load.Problem != "" {
			// Loud: the install path has already stood down to an empty
			// allowlist, so the user's cleared false block is quietly blocking
			// again. Saying nothing here is how that becomes a mystery.
			fmt.Fprintf(out, "WARNING: %s is %s\n\n", load.Path, load.Problem)
		}
		if len(load.File.Entries) == 0 {
			fmt.Fprintln(out, "No packages are allowed on this machine.")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "If the guard refuses a package you know is real:")
			fmt.Fprintln(out, "  chainsaw guard allow npm:jsdoc")
			return nil
		}
		fmt.Fprintf(out, "Allowed on this machine (%s)\n\n", load.Path)
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  PACKAGE\tALLOWED\tREFUSED AS")
		for _, e := range load.File.Entries {
			fmt.Fprintf(tw, "  %s\t%s\t%s\n",
				sanitizeForTerminal(guardAllowKey(e.Ecosystem, e.Name)),
				sanitizeForTerminal(e.AllowedAt),
				sanitizeForTerminal(e.Reason))
		}
		_ = tw.Flush()
		fmt.Fprintln(out)
		fmt.Fprintln(out, "These clear typosquat verdicts only. Known-malicious and known-vulnerable")
		fmt.Fprintln(out, "packages still block. Remove one with:")
		fmt.Fprintln(out, "  chainsaw guard allow --remove <ecosystem>:<name>")
		return nil
	}, nil)
}
