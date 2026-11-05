package homebrew

// prefixcheck.go — is the Homebrew link farm still pointing where brew put it?
//
// The 2026 Binance intrusion persisted by replacing the pyenv binary under
// /opt/homebrew. The prefix is owned by the user, so nothing stops that
// write; what can be checked is that every name a linked keg exports in
// bin/ and sbin/ is still a symlink into that formula's own Cellar
// directory, and that opt/ links still land on a keg. A swapped-in regular
// file, or a link re-pointed at another directory, is TAMPER.
//
// Scope, stated so a green run is not read as more than it is:
//   - Only the links are checked. A file changed INSIDE a keg
//     (Cellar/<f>/<v>/bin/pyenv itself), or a fake keg directory planted
//     under Cellar, needs the keg-vs-bottle comparison.
//   - Nothing under the prefix is executed: Lstat and Readlink only.
//   - var/homebrew/linked is user-writable too, so it only says which keg
//     a name SHOULD point at. What it cannot be trusted to say is which
//     names brew owns: deleting the record would turn a swapped binary into
//     an "unmanaged" file. That memory is the baseline, a name -> formula
//     map a ROOT run keeps outside the prefix (the caller stores it). A
//     baseline name must stay a link into some keg that ships it.
//   - Entries brew has never been seen to own (pip/npm scripts, Caskroom
//     links, links to other trees) are UNMANAGED: listed, never failed. A
//     healthy Mac has plenty.
//   - A root-owned entry is never TAMPER: the user cannot create one, pkg
//     installers (python.org, nodejs.org, AWS CLI, Docker's helper) do.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Link finding severities.
const (
	SeverityTamper = "tamper" // a managed name no longer points into its keg
	SeverityWarn   = "warn"   // an expected link is missing or dangles
)

// Finding is one problem in the link farm.
type Finding struct {
	Severity string `json:"severity"`
	Path     string `json:"path"` // relative to the prefix, e.g. "bin/pyenv"
	Reason   string `json:"reason"`
}

// LinkReport is the result of CheckLinks.
type LinkReport struct {
	Prefix     string    `json:"prefix"`
	LinkedKegs int       `json:"linked_kegs"`
	Checked    int       `json:"checked"`
	Findings   []Finding `json:"findings"`
	Unmanaged  []string  `json:"unmanaged"`
	// Baseline is the name -> formula map to store for the next run:
	// every name now correctly linked, plus earlier names still present
	// and not cleared as root-owned.
	Baseline map[string]string `json:"-"`
}

// Tampered reports whether any finding is TAMPER.
func (r LinkReport) Tampered() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityTamper {
			return true
		}
	}
	return false
}

// CheckLinks verifies the bin/, sbin/ and opt/ links of the Homebrew prefix
// against the linked registry and the baseline (nil on a first run). An
// error means the check could not run, never that the prefix is clean.
func CheckLinks(prefix string, baseline map[string]string) (LinkReport, error) {
	r := LinkReport{Prefix: prefix, Findings: []Finding{}, Unmanaged: []string{}, Baseline: map[string]string{}}
	cellar := filepath.Join(prefix, "Cellar")
	if fi, err := os.Stat(cellar); err != nil || !fi.IsDir() {
		return r, fmt.Errorf("%s is not a Homebrew prefix: no readable Cellar", prefix)
	}
	linkedDir := filepath.Join(prefix, "var", "homebrew", "linked")
	linked, err := os.ReadDir(linkedDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return r, fmt.Errorf("reading %s: %w", linkedDir, err)
	}

	// exporters["bin/jq"] = formulae whose linked keg ships bin/jq.
	exporters := map[string][]string{}
	for _, e := range linked {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		rel := filepath.Join("var", "homebrew", "linked", name)
		target, err := os.Readlink(filepath.Join(linkedDir, name))
		if err != nil {
			r.Findings = append(r.Findings, Finding{SeverityTamper, rel, "not a symlink"})
			continue
		}
		keg := ResolveLink(linkedDir, target)
		if !insideDir(keg, filepath.Join(cellar, name)) {
			r.Findings = append(r.Findings, Finding{SeverityTamper, rel, "points outside Cellar/" + name + ": " + target})
			continue
		}
		if fi, err := os.Stat(keg); err != nil || !fi.IsDir() {
			r.Findings = append(r.Findings, Finding{SeverityWarn, rel, "keg missing: " + target})
			continue
		}
		r.LinkedKegs++
		for _, sub := range []string{"bin", "sbin"} {
			ents, err := os.ReadDir(filepath.Join(keg, sub))
			if err != nil {
				continue // a keg without bin/ is normal
			}
			for _, x := range ents {
				exporters[sub+"/"+x.Name()] = append(exporters[sub+"/"+x.Name()], name)
			}
		}
	}

	for _, sub := range []string{"bin", "sbin"} {
		ents, err := os.ReadDir(filepath.Join(prefix, sub))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return r, fmt.Errorf("reading %s: %w", filepath.Join(prefix, sub), err)
		}
		present := map[string]bool{}
		for _, e := range ents {
			rel := sub + "/" + e.Name()
			present[rel] = true
			if rel == "bin/brew" || strings.HasPrefix(e.Name(), ".") {
				continue // brew itself is checked against upstream separately
			}
			owners, linkedOwner := exporters[rel]
			prior, baselined := baseline[rel]
			if !linkedOwner && !baselined {
				// A live link into a keg is brew's even without a record.
				if formula := kegFormula(cellar, filepath.Join(prefix, rel)); formula != "" && statOK(filepath.Join(prefix, rel)) {
					r.Checked++
					r.Baseline[rel] = formula
				} else if sys := shadowedSystemCommand(prefix, e.Name()); sys != "" && !entryRootOwned(filepath.Join(prefix, rel)) {
					// The prefix is ahead of /usr/bin on PATH, so a user-owned
					// `sudo` or `ssh` here runs instead of the system one and
					// reads every password typed into it. No formula ships one
					// outside the Cellar, and a pkg installer's would be root's.
					r.Checked++
					r.Findings = append(r.Findings, Finding{SeverityTamper, rel, "not brew's, and shadows " + sys})
				} else {
					r.Unmanaged = append(r.Unmanaged, rel)
				}
				continue
			}
			r.Checked++
			var f Finding
			var bad bool
			if linkedOwner {
				f, bad = checkFarmLink(prefix, cellar, rel, owners)
			} else {
				f, bad = checkBaselineLink(prefix, cellar, rel, prior)
			}
			if bad && f.Severity == SeverityTamper && entryRootOwned(filepath.Join(prefix, rel)) {
				// A user cannot create a root-owned entry; a pkg installer can.
				r.Findings = append(r.Findings, Finding{SeverityWarn, rel, "root-owned, not brew's (a pkg installer took the name?)"})
				continue
			}
			if bad {
				r.Findings = append(r.Findings, f)
				if baselined {
					r.Baseline[rel] = prior // keep flagging it until it is fixed
				}
				continue
			}
			if formula := kegFormula(cellar, filepath.Join(prefix, rel)); formula != "" {
				r.Baseline[rel] = formula
			}
		}
		for rel, owners := range exporters {
			if strings.HasPrefix(rel, sub+"/") && !present[rel] {
				r.Findings = append(r.Findings, Finding{SeverityWarn, rel, "missing link for " + strings.Join(owners, ", ")})
			}
		}
	}

	optDir := filepath.Join(prefix, "opt")
	opts, err := os.ReadDir(optDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return r, fmt.Errorf("reading %s: %w", optDir, err)
	}
	for _, e := range opts {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		rel := "opt/" + e.Name()
		r.Checked++
		target, err := os.Readlink(filepath.Join(optDir, e.Name()))
		if err != nil {
			r.Findings = append(r.Findings, Finding{SeverityTamper, rel, "not a symlink"})
			continue
		}
		dest := ResolveLink(optDir, target)
		if !insideDir(dest, cellar) || dest == cellar {
			r.Findings = append(r.Findings, Finding{SeverityTamper, rel, "points outside Cellar: " + target})
			continue
		}
		if fi, err := os.Stat(dest); err != nil || !fi.IsDir() {
			r.Findings = append(r.Findings, Finding{SeverityWarn, rel, "dangling: " + target})
			continue
		}
		// opt/ is how kegs load each other (dylibs, helpers), and brew's
		// alias links (opt/python3, opt/gpg) point at another formula's
		// keg. Record which formula each one points at; the keg check
		// reports one moved onto a keg no bottle vouches for.
		if parts := strings.Split(strings.TrimPrefix(dest, cellar+string(filepath.Separator)), string(filepath.Separator)); len(parts) == 2 {
			r.Baseline[rel] = parts[0]
		}
	}

	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].Path < r.Findings[j].Path })
	sort.Strings(r.Unmanaged)
	return r, nil
}

// checkFarmLink: a managed bin/sbin entry must be a symlink whose target
// (resolved lexically, one hop) lies inside Cellar/<f>/ for one of the
// formulae that export the name.
func checkFarmLink(prefix, cellar, rel string, owners []string) (Finding, bool) {
	p := filepath.Join(prefix, rel)
	target, err := os.Readlink(p)
	if err != nil {
		return Finding{SeverityTamper, rel, "regular file where " + strings.Join(owners, ", ") + " links its binary"}, true
	}
	dest := ResolveLink(filepath.Dir(p), target)
	for _, f := range owners {
		if insideDir(dest, filepath.Join(cellar, f)) {
			if _, err := os.Stat(p); err != nil {
				return Finding{SeverityWarn, rel, "dangling: " + target}, true
			}
			return Finding{}, false
		}
	}
	return Finding{SeverityTamper, rel, "points at " + target + ", not into Cellar/" + strings.Join(owners, " or Cellar/")}, true
}

// checkBaselineLink: a name brew was seen to own (baseline) must still be a
// symlink to Cellar/<any formula>/<any version>/<rel> that exists. Any
// formula, not only the stored one: python@3.12 -> 3.13 and
// `brew link --overwrite` move names between formulae.
func checkBaselineLink(prefix, cellar, rel, prior string) (Finding, bool) {
	p := filepath.Join(prefix, rel)
	target, err := os.Readlink(p)
	if err != nil {
		return Finding{SeverityTamper, rel, "regular file where " + prior + " linked its binary"}, true
	}
	if kegFormula(cellar, p) == "" {
		return Finding{SeverityTamper, rel, "points at " + target + ", not into a keg (was " + prior + ")"}, true
	}
	if !statOK(p) {
		return Finding{SeverityWarn, rel, "dangling: " + target}, true
	}
	return Finding{}, false
}

// SystemCommandDirs are the macOS system command directories the prefix
// precedes on PATH, and PathHelperDirs the others path_helper puts there
// from /etc/paths and /etc/paths.d (/usr/local/bin, where pkg installers
// put aws, docker, op, ...). Vars so tests can point them at fixtures.
var (
	SystemCommandDirs = []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"}
	PathHelperDirs    = pathHelperDirs()
)

func pathHelperDirs() []string {
	var dirs []string
	files, _ := filepath.Glob("/etc/paths.d/*")
	for _, f := range append([]string{"/etc/paths"}, files...) {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); filepath.IsAbs(l) {
				dirs = append(dirs, filepath.Clean(l))
			}
		}
	}
	return dirs
}

// ShadowedCommand names the command a prefix bin/sbin entry called name
// shadows ("" if none), and whether it is in a system directory (/usr/bin,
// /bin, /usr/sbin, /sbin) rather than another path_helper directory.
func ShadowedCommand(prefix, name string) (string, bool) {
	sys := shadowedSystemCommand(prefix, name)
	if sys == "" {
		return "", false
	}
	for _, d := range SystemCommandDirs {
		if filepath.Dir(sys) == filepath.Clean(d) {
			return sys, true
		}
	}
	return sys, false
}

// shadowedSystemCommand names the command the prefix entry shadows, or "".
// No exemption for cask `binary` links: the Caskroom is the user's to
// write, so a link into it vouches for nothing. A cask binary named like a
// /usr/local/bin command is reported; unlink one of them.
func shadowedSystemCommand(prefix, name string) string {
	dirs := append(append([]string{}, SystemCommandDirs...), PathHelperDirs...)
	for _, d := range dirs {
		if insideDir(filepath.Clean(d), filepath.Clean(prefix)) {
			continue
		}
		if p := filepath.Join(d, name); statOK(p) {
			return p
		}
	}
	return ""
}

func statOK(p string) bool { _, err := os.Stat(p); return err == nil }

// LinkKeg returns the keg ("<f>/<v>") the prefix entry rel links into,
// or "".
func LinkKeg(prefix, rel string) string {
	p := filepath.Join(prefix, filepath.FromSlash(rel))
	cellar := filepath.Join(prefix, "Cellar")
	if strings.HasPrefix(rel, "opt/") {
		t, err := os.Readlink(p)
		if err != nil {
			return ""
		}
		dest := ResolveLink(filepath.Dir(p), t)
		parts := strings.Split(strings.TrimPrefix(dest, cellar+string(filepath.Separator)), string(filepath.Separator))
		if !insideDir(dest, cellar) || len(parts) != 2 {
			return ""
		}
		return parts[0] + "/" + parts[1]
	}
	f := kegFormula(cellar, p)
	if f == "" {
		return ""
	}
	t, _ := os.Readlink(p)
	dest := ResolveLink(filepath.Dir(p), t)
	parts := strings.Split(strings.TrimPrefix(dest, cellar+string(filepath.Separator)), string(filepath.Separator))
	return f + "/" + parts[1]
}

// kegFormula returns <f> when the link at p resolves (one hop, lexically)
// to cellar/<f>/<v>/<bin|sbin>/<basename of p>, else "".
func kegFormula(cellar, p string) string {
	target, err := os.Readlink(p)
	if err != nil {
		return ""
	}
	dest := ResolveLink(filepath.Dir(p), target)
	if !insideDir(dest, cellar) {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(dest, cellar+string(filepath.Separator)), string(filepath.Separator))
	if len(parts) != 4 || parts[3] != filepath.Base(p) ||
		parts[2] != filepath.Base(filepath.Dir(p)) || strings.HasPrefix(parts[0], ".") || strings.HasPrefix(parts[1], ".") {
		return ""
	}
	return parts[0]
}

// ResolveLink resolves a symlink target read from dir, lexically and one
// hop: relative targets are joined to dir, absolute ones taken as they are.
func ResolveLink(dir, target string) string {
	if filepath.IsAbs(target) {
		return filepath.Clean(target)
	}
	return filepath.Clean(filepath.Join(dir, target))
}

// insideDir reports whether path is dir or below it (both already Clean).
func insideDir(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, dir+string(filepath.Separator))
}
