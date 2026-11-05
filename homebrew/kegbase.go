package homebrew

// Root keg baseline: the Binance step. A poured keg's files do not change
// until brew pours that keg again (a reinstall writes a new
// INSTALL_RECEIPT.json; an upgrade is a new version directory). A root run
// records every file of every keg; a later run that finds a file changed,
// added or removed in a keg whose receipt is unchanged reports TAMPER. The
// record stays as it was, so the finding repeats until root resets it.
//
// A keg that is new is Fresh, and one whose receipt changed is Repoured.
// Neither is absorbed here: the receipt is the user's to rewrite, so the
// caller compares it with its bottle (brew verify --kegs) and calls Accept
// only for what a bottle vouches for. Until then a Repoured keg keeps its
// previous record and a Fresh one has none.
//
// Files are re-hashed only when their stat key (inode, size, ctime) moved;
// ctime cannot be set by the prefix's user.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// KegRecord is one keg as a root run saw it.
type KegRecord struct {
	Receipt string `json:"r"`
	// Files maps a keg-relative path to "S|<stat key>|<sha256>|<x or ->",
	// "L|<symlink target>" or "X|<mode>" (anything else).
	Files map[string]string `json:"f"`
	// Vouched: a bottle matched this keg when it was recorded. A keg
	// recorded without one (a tap, or the first run's trust) is not, and a
	// link brew's records gave to another formula moving onto it is
	// reported (see the caller).
	Vouched bool `json:"v,omitempty"`
}

// KegBaseline maps "<name>/<version>" to its record.
type KegBaseline map[string]KegRecord

// KegCheck is the result of CheckKegs.
type KegCheck struct {
	Kegs     int         `json:"kegs"`
	Files    int         `json:"files"`
	Hashed   int         `json:"hashed"`
	Fresh    []string    `json:"fresh"`
	Repoured []string    `json:"repoured"`
	Findings []Finding   `json:"findings"`
	Baseline KegBaseline `json:"-"`
	// Pending holds the current records of Fresh and Repoured kegs, and
	// Changed the paths of a Repoured keg whose content differs from its
	// previous record (the SBOM, rewritten at every pour, left out).
	Pending KegBaseline         `json:"-"`
	Changed map[string][]string `json:"-"`
}

// Accept records a Fresh or Repoured keg as it is now; vouched says a
// bottle matched it.
func (c *KegCheck) Accept(key string, vouched bool) {
	if r, ok := c.Pending[key]; ok {
		r.Vouched = vouched
		c.Baseline[key] = r
	}
}

// runtimeBytecode: files the interpreter writes beside its sources at run
// time. Recorded, and a changed one is TAMPER (Python loads a .pyc whose
// header matches its source, which a user can forge); one appearing or
// going is not a finding.
// NotInBottle: keg files a bottle comparison cannot vouch for. Runtime
// bytecode is written after the pour, and .brew/ and a framework's
// CodeResources are rewritten by it.
func NotInBottle(rel string) bool {
	return runtimeBytecode(rel) || strings.HasPrefix(rel, ".brew/") || strings.HasSuffix(rel, "/_CodeSignature/CodeResources")
}

func runtimeBytecode(rel string) bool {
	return strings.Contains("/"+rel, "/__pycache__/") && strings.HasSuffix(rel, ".pyc")
}

// kegDirs lists Cellar/<f>/<v>. brew creates each level as a real
// directory; a symlink (or a file) at any level is how a keg is swapped for
// an edited copy that every lexical link check still accepts, so it is
// TAMPER and is not followed.
func kegDirs(prefix string) ([]string, []Finding) {
	var dirs []string
	var bad []Finding
	cellar := filepath.Join(prefix, "Cellar")
	check := func(p, rel string) bool {
		fi, err := os.Lstat(p)
		switch {
		case err != nil:
			return false
		case fi.Mode()&fs.ModeSymlink != 0:
			t, _ := os.Readlink(p)
			bad = append(bad, Finding{SeverityTamper, rel, "is a symlink (to " + t + "), not the directory brew created"})
			return false
		case !fi.IsDir():
			if !strings.HasPrefix(filepath.Base(p), ".") {
				bad = append(bad, Finding{SeverityTamper, rel, "is not a directory"})
			}
			return false
		}
		return true
	}
	if !check(cellar, "Cellar") {
		return nil, bad
	}
	formulae, _ := os.ReadDir(cellar)
	for _, f := range formulae {
		fp := filepath.Join(cellar, f.Name())
		if strings.HasPrefix(f.Name(), ".") && !f.IsDir() {
			continue // .keepme
		}
		if !check(fp, "Cellar/"+f.Name()) {
			continue
		}
		versions, _ := os.ReadDir(fp)
		for _, v := range versions {
			if strings.HasPrefix(v.Name(), ".") && !v.IsDir() {
				continue
			}
			if vp := filepath.Join(fp, v.Name()); check(vp, "Cellar/"+f.Name()+"/"+v.Name()) {
				dirs = append(dirs, vp)
			}
		}
	}
	sort.Strings(dirs)
	return dirs, bad
}

// Limits that keep a user from starving the root run: a sparse petabyte
// file is not hashed (it is TAMPER: no keg ships one), and the whole walk
// gives up after KegCheckBudget, which the caller reports as an error.
var (
	KegMaxFileBytes int64 = 4 << 30
	KegCheckBudget        = 30 * time.Minute
	// KegMaxFiles bounds one unit's walk (the largest keg on a measured Mac
	// held 47,176 files): a keg stuffed with millions of entries would hold
	// the root run past its budget, or its memory.
	KegMaxFiles = 500_000
)

// CheckKegs compares every keg under prefix/Cellar with base (nil: first
// run, everything is recorded).
func CheckKegs(prefix string, base KegBaseline) (KegCheck, error) {
	deadline := time.Now().Add(KegCheckBudget)
	res := KegCheck{Findings: []Finding{}, Fresh: []string{}, Repoured: []string{}, Baseline: KegBaseline{},
		Pending: KegBaseline{}, Changed: map[string][]string{}}
	dirs, structural := kegDirs(prefix)
	res.Findings = append(res.Findings, structural...)
	if len(structural) > 0 {
		// Keep the records of anything the structure check could not walk:
		// a keg swapped for a link to an edited copy must not drop out.
		for k, v := range base {
			res.Baseline[k] = v
		}
	}
	units := make([]kegUnit, 0, len(dirs))
	for _, dir := range dirs {
		units = append(units, kegUnit{key: filepath.Base(filepath.Dir(dir)) + "/" + filepath.Base(dir), dir: dir, receipt: "INSTALL_RECEIPT.json"})
	}
	extra, bad := outOfKegTrees(prefix)
	res.Findings = append(res.Findings, bad...)
	units = append(units, extra...)
	for _, u := range units {
		if time.Now().After(deadline) {
			return res, fmt.Errorf("keg check did not finish within %s", KegCheckBudget)
		}
		key, dir := u.key, u.dir
		receipt := u.fixedReceipt
		if u.receipt != "" {
			receipt, _, _ = HashRegular(filepath.Join(dir, u.receipt))
		}
		prev, had := base[key]
		same := had && prev.Receipt == receipt
		var reuse map[string]string
		if same {
			reuse = prev.Files
		}
		rec, hashed, err := recordKeg(dir, reuse, u.only, deadline)
		if err != nil {
			return res, err
		}
		rec.Receipt = receipt
		for rel, v := range rec.Files {
			switch v {
			case "X|oversize":
				res.Findings = append(res.Findings, Finding{SeverityTamper, u.label() + rel, fmt.Sprintf("larger than %d GiB; no keg ships such a file, and it is not hashed", KegMaxFileBytes>>30)})
			case "X|sparse":
				res.Findings = append(res.Findings, Finding{SeverityTamper, u.label() + rel, "a sparse file (mostly unallocated); no keg ships one, and it is not hashed"})
			}
		}
		res.Kegs++
		res.Files += len(rec.Files)
		res.Hashed += hashed
		if !had {
			res.Fresh = append(res.Fresh, key)
			res.Pending[key] = rec
			continue
		}
		if !same {
			res.Repoured = append(res.Repoured, key)
			res.Pending[key] = rec
			res.Baseline[key] = prev
			for _, f := range diffKeg("", prev.Files, rec.Files) {
				if f.Path != "sbom.spdx.json" {
					res.Changed[key] = append(res.Changed[key], f.Path)
				}
			}
			continue
		}
		found := diffKeg(u.label(), prev.Files, rec.Files)
		if len(found) > 0 {
			// (A keg being uninstalled loses its receipt with the rest, so
			// it reads fresh above, never as removed files.)
			res.Findings = append(res.Findings, found...)
			res.Baseline[key] = prev
			continue
		}
		// A recorded .pyc keeps its record after it is removed, so one put
		// back must match it (removing it is not a finding; replacing it
		// with something else then is).
		for rel, v := range prev.Files {
			if _, ok := rec.Files[rel]; !ok && runtimeBytecode(rel) {
				rec.Files[rel] = v
			}
		}
		rec.Vouched = prev.Vouched
		res.Baseline[key] = rec
	}
	// An out-of-keg tree that is gone keeps its record: moving site-packages
	// or npm's tree away for one root run and back edited must read as a
	// change, not as new.
	for k, v := range base {
		if _, ok := res.Baseline[k]; !ok && strings.HasPrefix(k, ":") {
			if _, pending := res.Pending[k]; !pending {
				res.Baseline[k] = v
			}
		}
	}
	return res, nil
}

// StillMatches re-records a Fresh or Repoured unit after the caller's
// bottle or registry comparison and reports whether it is still exactly
// what CheckKegs hashed: the comparison re-reads the disk after network
// calls, so a swap in between must not be recorded as vouched.
func (c *KegCheck) StillMatches(prefix, key string) bool {
	want, ok := c.Pending[key]
	if !ok {
		return false
	}
	dir := filepath.Join(prefix, "Cellar", filepath.FromSlash(key))
	var only func(string) bool // nil: the whole tree, as CheckKegs walked it
	if strings.HasPrefix(key, ":") {
		dir = filepath.Join(prefix, filepath.FromSlash(key[1:]))
		if strings.HasSuffix(key, "/site-packages") {
			only = pythonStartupHook
		}
	}
	got, _, err := recordKeg(dir, want.Files, only, time.Now().Add(KegCheckBudget))
	if err != nil || len(got.Files) != len(want.Files) {
		return false
	}
	for rel, w := range want.Files {
		if g, ok := got.Files[rel]; !ok || !sameEntry(w, g) {
			return false
		}
	}
	return true
}

func diffKeg(label string, was, now map[string]string) []Finding {
	var out []Finding
	since := "since it was poured"
	if !strings.HasPrefix(label, "Cellar/") {
		since = "since root recorded it"
	}
	for rel, w := range was {
		n, ok := now[rel]
		switch {
		case !ok && runtimeBytecode(rel):
		case !ok:
			out = append(out, Finding{SeverityTamper, label + rel, "removed " + since})
		case sameEntry(w, n):
		default:
			out = append(out, Finding{SeverityTamper, label + rel, "changed " + since})
		}
	}
	for rel := range now {
		if _, ok := was[rel]; !ok && !runtimeBytecode(rel) {
			out = append(out, Finding{SeverityTamper, label + rel, "added " + since})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// sameEntry ignores the stat key: a touched or re-copied file with the same
// bytes and exec bit is the same file.
func sameEntry(a, b string) bool {
	pa, pb := strings.Split(a, "|"), strings.Split(b, "|")
	if pa[0] == "S" && pb[0] == "S" && len(pa) == 4 && len(pb) == 4 {
		return pa[2] == pb[2] && pa[3] == pb[3]
	}
	return a == b
}

// kegUnit is one recorded tree: a keg, or brew-managed code outside one.
// Out-of-keg keys start with ":"; only records restricts the walk to the
// top level and the files it accepts.
type kegUnit struct {
	key, dir     string
	receipt      string // file whose hash marks a re-pour ("" = fixedReceipt)
	fixedReceipt string
	only         func(rel string) bool
}

func (u kegUnit) label() string {
	if strings.HasPrefix(u.key, ":") {
		return u.key[1:] + "/"
	}
	return "Cellar/" + u.key + "/"
}

// outOfKegTrees: code brew installs outside a keg that still runs as part
// of a formula. npm's own tree under lib/node_modules (node's post_install
// writes it; bin/npm links into it) is recorded whole, keyed on its
// package.json, which `npm install -g npm` rewrites. Each prefix Python
// site-packages contributes only its startup hooks (*.pth,
// sitecustomize.py, usercustomize.py), which run on every python3 start;
// installed packages there are pip's, not brew's.
func outOfKegTrees(prefix string) ([]kegUnit, []Finding) {
	var units []kegUnit
	var bad []Finding
	realDir := func(p, rel string) bool {
		fi, err := os.Lstat(p)
		if err != nil {
			return false
		}
		if !fi.IsDir() {
			bad = append(bad, Finding{SeverityTamper, rel, "is not the directory brew created"})
			return false
		}
		return true
	}
	if npm := filepath.Join(prefix, "lib", "node_modules", "npm"); realDir(npm, "lib/node_modules/npm") {
		units = append(units, kegUnit{key: ":lib/node_modules/npm", dir: npm, receipt: "package.json"})
	}
	sites, _ := filepath.Glob(filepath.Join(prefix, "lib", "python3*", "site-packages"))
	sort.Strings(sites)
	for _, sp := range sites {
		rel, _ := filepath.Rel(prefix, sp)
		rel = filepath.ToSlash(rel)
		if realDir(sp, rel) {
			units = append(units, kegUnit{key: ":" + rel, dir: sp, fixedReceipt: "startup-hooks", only: pythonStartupHook})
		}
	}
	return units, bad
}

func pythonStartupHook(rel string) bool {
	return !strings.Contains(rel, "/") &&
		(strings.HasSuffix(rel, ".pth") || rel == "sitecustomize.py" || rel == "usercustomize.py")
}

// recordKeg walks one keg without following links. A file whose stat key
// matches its reuse entry keeps that entry's hash. only (nil = everything)
// restricts the walk to top-level files it accepts.
func recordKeg(dir string, reuse map[string]string, only func(string) bool, deadline time.Time) (KegRecord, int, error) {
	rec := KegRecord{Files: map[string]string{}}
	hashed, seen := 0, 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if p == dir {
			return nil
		}
		// The budget holds inside one unit too, not only between them.
		if seen++; seen > KegMaxFiles {
			return fmt.Errorf("%s holds more than %d entries; no keg ships that many", dir, KegMaxFiles)
		}
		if seen%1000 == 0 && time.Now().After(deadline) {
			return fmt.Errorf("keg check did not finish within %s (stopped in %s)", KegCheckBudget, dir)
		}
		if d.IsDir() {
			if only != nil {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if only != nil && !only(rel) {
			return nil
		}
		if rel == "INSTALL_RECEIPT.json" {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil // gone mid-walk
		}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			t, _ := os.Readlink(p)
			rec.Files[rel] = "L|" + t
		case fi.Mode().IsRegular():
			sk := statKey(fi)
			x := map[bool]string{true: "x", false: "-"}[fi.Mode()&0o111 != 0]
			if old := strings.Split(reuse[rel], "|"); len(old) == 4 && old[0] == "S" && old[1] == sk {
				rec.Files[rel] = "S|" + sk + "|" + old[2] + "|" + x
				return nil
			}
			if fi.Size() > KegMaxFileBytes {
				rec.Files[rel] = "X|oversize"
				return nil
			}
			// A sparse file costs nothing to plant and a full read to hash.
			if alloc, ok := allocatedBytes(fi); ok && fi.Size() > 8<<20 && alloc < fi.Size()/8 {
				rec.Files[rel] = "X|sparse"
				return nil
			}
			sum, fi2, err := HashRegular(p)
			if err != nil {
				rec.Files[rel] = "X|unreadable"
				return nil
			}
			hashed++
			rec.Files[rel] = "S|" + statKey(fi2) + "|" + sum + "|" + x
		default:
			rec.Files[rel] = "X|" + fi.Mode().Type().String()
		}
		return nil
	})
	return rec, hashed, err
}

// HashRegular is the hex sha256 of a regular file, opened so a racing user
// cannot swap in a symlink or a FIFO (see openRegular).
func HashRegular(path string) (string, fs.FileInfo, error) {
	f, fi, err := openRegular(path)
	if err != nil {
		return "", fi, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, fi.Size()+1)); err != nil {
		return "", fi, err
	}
	return hex.EncodeToString(h.Sum(nil)), fi, nil
}

// ReadRegular is readRegular for other packages.
func ReadRegular(path string, max int64) ([]byte, error) { return readRegular(path, max) }
