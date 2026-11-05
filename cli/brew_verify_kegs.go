package cli

// brew verify --kegs: every installed keg compared with the bottle ghcr.io
// serves for its version (server: GET /api/homebrew/vendor-manifest
// ?kind=bottle). brew changes a bottle only by relocation and ad-hoc
// re-signing (homebrew.MachOHash), so a keg it poured matches file for file.
//
// Report-only by design: a keg does not record which bottle it was poured
// from, and ghcr tags are re-pointed when a bottle is rebuilt, so a
// mismatch can be a newer build of the same version as easily as a
// tampered file. (Rebuilds get their own ghcr tag, <version>-<n>, so the
// candidates are enumerable; what a keg cannot say is which one it was.)
// A mismatch is UNVERIFIED (the verdict is then incomplete),
// never TAMPER; the files that differ are listed so a person can look.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/chain305/chainsaw-core/homebrew"
)

type brewKegReport struct {
	Verified    int             `json:"verified"`
	Unverified  []brewKegResult `json:"unverified"`
	NotAssessed []brewKegResult `json:"not_assessed"`
	// ExtraBytecode counts runtime-compiled __pycache__ files no bottle
	// ships. They are code, so they are counted rather than ignored.
	ExtraBytecode int `json:"extra_bytecode"`
}

type brewKegResult struct {
	Keg    string   `json:"keg"`
	Tag    string   `json:"tag,omitempty"`
	Reason string   `json:"reason"`
	Files  []string `json:"files,omitempty"`

	// For the keg baseline: whether a bottle was compared at all, whether
	// the failure was a fetch that may succeed next time, and every
	// differing path (Files is capped for display).
	compared, transient bool
	coreUnbottled       bool // a core formula at a version core never bottled (HEAD, or a forged keg)
	differs             []string
	hard                []string // differs minus files only added or links retargeted (post_install's shapes)
}

type kegReceipt struct {
	PouredFromBottle bool `json:"poured_from_bottle"`
	Source           struct {
		Tap string `json:"tap"`
	} `json:"source"`
}

// Seams swapped in tests.
var (
	brewKegsSupported = runtime.GOOS == "darwin" && runtime.GOARCH == "arm64"
	brewMacOSMajor    = macOSMajor
	// brewKegComparePrefix: bottles are relocated for the Apple-silicon
	// prefix only.
	brewKegComparePrefix = "/opt/homebrew"
)

// macOSCodenames maps a macOS major version to its bottle tag name.
var macOSCodenames = map[int]string{26: "tahoe", 15: "sequoia", 14: "sonoma", 13: "ventura", 12: "monterey", 11: "big_sur"}

// kegOnlyChanged are pour artifacts that never match the bottle and are not
// code: brew writes the receipt, the SBOM and .brew/<f>.rb at pour, and
// re-signing a framework rewrites its CodeResources listing.
func kegOnlyChanged(rel string) bool {
	return rel == "INSTALL_RECEIPT.json" || rel == "sbom.spdx.json" || strings.HasPrefix(rel, ".brew/") ||
		strings.HasSuffix(rel, "/_CodeSignature/CodeResources")
}

const brewKegWorkers = 4

func verifyKegs(res *brewVerifyResult, prefixes []string) {
	if !brewKegsSupported {
		res.NotAssessed = append(res.NotAssessed, "kegs: compared only on Apple-silicon Macs (/opt/homebrew)")
		return
	}
	major, err := brewMacOSMajor()
	codename := macOSCodenames[major]
	if err != nil || codename == "" {
		res.NotAssessed = append(res.NotAssessed, fmt.Sprintf("kegs: no bottle tag known for macOS %d", major))
		return
	}
	rep := &brewKegReport{Unverified: []brewKegResult{}, NotAssessed: []brewKegResult{}}
	res.Kegs = rep
	for _, prefix := range prefixes {
		if prefix != brewKegComparePrefix {
			rep.NotAssessed = append(rep.NotAssessed, brewKegResult{Keg: prefix, Reason: "only the Apple-silicon prefix /opt/homebrew is compared"})
			res.NotAssessed = append(res.NotAssessed, "kegs: "+prefix+" not compared (only the Apple-silicon prefix /opt/homebrew is)")
			continue
		}
		kegs, err := filepath.Glob(filepath.Join(prefix, "Cellar", "*", "*"))
		if err != nil {
			res.Errors = append(res.Errors, "kegs: "+err.Error())
			continue
		}
		sort.Strings(kegs)
		results := make([]brewKegResult, len(kegs))
		verified := make([]bool, len(kegs))
		extra := make([]int, len(kegs))
		next := make(chan int)
		var wg sync.WaitGroup
		for w := 0; w < brewKegWorkers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range next {
					results[i], verified[i], extra[i] = verifyKeg(prefix, kegs[i], major)
				}
			}()
		}
		for i := range kegs {
			next <- i
		}
		close(next)
		wg.Wait()
		for i, r := range results {
			rep.ExtraBytecode += extra[i]
			switch {
			case verified[i]:
				rep.Verified++
			case r.Files != nil:
				rep.Unverified = append(rep.Unverified, r)
				res.NotAssessed = append(res.NotAssessed, "keg "+r.Keg+": unverified, "+r.Reason)
			case r.Keg != "":
				// Not compared is never clean: a failed fetch, a tap keg or an
				// unreadable receipt leaves the verdict incomplete.
				rep.NotAssessed = append(rep.NotAssessed, r)
				res.NotAssessed = append(res.NotAssessed, "keg "+r.Keg+": not compared, "+r.Reason)
			}
		}
	}
}

// verifyKeg compares one Cellar/<name>/<version> with its bottle. It returns
// the result, whether the keg verified, and how many runtime bytecode files
// it holds that no bottle ships. A zero result with verified=false is a
// directory that is not a keg.
func verifyKeg(prefix, dir string, macOSMajor int) (brewKegResult, bool, int) {
	name, version := filepath.Base(filepath.Dir(dir)), filepath.Base(dir)
	r := brewKegResult{Keg: name + "/" + version}
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return brewKegResult{}, false, 0
	}
	b, err := homebrew.ReadRegular(filepath.Join(dir, "INSTALL_RECEIPT.json"), 1<<20)
	var rc kegReceipt
	if err == nil {
		err = json.Unmarshal(b, &rc)
	}
	// The receipt is the user's to rewrite, so it only words the reason
	// when no bottle exists; a keg is compared whenever one does.
	why := ""
	switch {
	case err != nil:
		why = "no readable INSTALL_RECEIPT.json"
	case rc.Source.Tap != "homebrew/core":
		why = "from tap " + sanitizeForTerminal(rc.Source.Tap) + ", which ships no bottles to compare"
	case !rc.PouredFromBottle:
		why = "built from source, so there is no bottle to compare"
	}
	// The server relocates perl and java from the bottle's own tab: the
	// receipt here is the user's to rewrite.
	q := url.Values{"kind": {"bottle"}, "name": {name}, "version": {version}, "prefix": {prefix}}
	// The keg records neither its rebuild nor its OS tag, so every published
	// bottle of this version is a candidate: rebuild 0, 1, ... (each its own
	// ghcr index) and, within each, this macOS and every older one (a keg
	// poured before a macOS upgrade came from the older OS's bottle; the
	// server falls back to the next older tag it has, and "all" last).
	var diff []string
	var extra int
	firstFail := ""
	core, postInstall, current := false, false, false
	tried := map[string]bool{}
	for rb := 0; rb <= 9; rb++ {
		q.Set("rebuild", strconv.Itoa(rb))
		indexed := false
		for major := macOSMajor; major >= 11; major-- {
			codename := macOSCodenames[major]
			if codename == "" {
				continue
			}
			q.Set("tag", "arm64_"+codename)
			var m struct {
				Tag         string       `json:"tag"`
				Rebuild     string       `json:"rebuild"`
				Unavailable string       `json:"unavailable"`
				Missing     string       `json:"missing"`
				CoreFormula bool         `json:"core_formula"`
				PostInstall bool         `json:"post_install_defined"`
				Current     bool         `json:"current"`
				Files       []vendorFile `json:"files"`
			}
			if err := brewVerifyFetchVendor(q.Encode(), &m); err != nil {
				if r.Tag == "" {
					r.Reason = "bottle not fetched: " + err.Error()
					r.transient = true
					return r, false, 0
				}
				rb = 10 // a later candidate failing does not erase the comparison made
				break
			}
			if m.Missing != "index" {
				indexed = true
			} else if rb == 0 {
				core = m.CoreFormula
			}
			if m.Unavailable != "" {
				if firstFail == "" {
					firstFail = m.Unavailable
				}
				break
			}
			id := m.Tag + "." + m.Rebuild
			if tried[id] {
				continue
			}
			tried[id] = true
			d, x := compareKeg(dir, m.Files)
			if len(d) == 0 {
				r.Tag = id
				return r, true, x
			}
			if r.Tag == "" || len(d) < len(diff) {
				r.Tag, diff, extra = id, d, x // report the closest candidate
				postInstall, current = m.PostInstall, m.Current
			}
		}
		if !indexed && rb > 0 {
			break
		}
	}
	if r.Tag == "" {
		switch {
		case core:
			r.coreUnbottled = true
			r.Reason = "homebrew/core has " + name + ", but publishes no bottle of " + version
			if why != "" {
				r.Reason += " (the receipt says " + why + ")"
			}
		case why != "":
			r.Reason = why
		default:
			r.Reason = firstFail
		}
		return r, false, 0
	}
	r.compared = true
	// A difference is soft only when something explains it, and only for
	// the formula's current version (the only one brew pours today; an
	// older genuine bottle extracted by hand gets no benefit of the doubt):
	// a file the bottle lacks needs a formula that defines post_install,
	// and a retargeted link must land in this formula's own kegs or npm's
	// recorded tree.
	for _, d := range diff {
		parts := strings.SplitN(d, ": ", 2)
		r.differs = append(r.differs, parts[0])
		soft := current && len(parts) == 2 && (parts[1] == "not in the bottle" && postInstall ||
			parts[1] == "symlink target differs" && linkStaysManaged(prefix, name, filepath.Join(dir, filepath.FromSlash(parts[0]))))
		if !soft {
			r.hard = append(r.hard, parts[0])
		}
	}
	r.Reason = fmt.Sprintf("%d file(s) differ from every bottle ghcr.io publishes for this version (all rebuilds, this macOS and older); shown against %s", len(diff), r.Tag)
	if len(diff) > 10 {
		diff = append(diff[:10], fmt.Sprintf("... and %d more", len(diff)-10))
	}
	r.Files = diff
	return r, false, extra
}

// linkStaysManaged: the link at p resolves (lexically, one hop) into this
// formula's own Cellar directory or npm's recorded tree. Not lib/node_modules
// as a whole (other global packages are the user's) and not Cellar as a
// whole (another, unvouched keg).
func linkStaysManaged(prefix, formula, p string) bool {
	t, err := os.Readlink(p)
	if err != nil {
		return false
	}
	dest := homebrew.ResolveLink(filepath.Dir(p), t)
	if strings.HasPrefix(dest, filepath.Join(prefix, "lib", "node_modules", "npm")+string(filepath.Separator)) {
		return true
	}
	// Inside a version directory of the formula (a recorded keg), never a
	// file sitting directly in Cellar/<formula>/, which nothing records.
	rel, ok := strings.CutPrefix(dest, filepath.Join(prefix, "Cellar", formula)+string(filepath.Separator))
	parts := strings.Split(rel, string(filepath.Separator))
	return ok && len(parts) >= 2 && parts[0] != "" && !strings.HasPrefix(parts[0], ".")
}

// vendorFile mirrors the server's manifest entry.
type vendorFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Link   string `json:"link"`
	Exec   bool   `json:"exec"`
	Subst  string `json:"subst_sha256"`
	MachO  string `json:"macho_sha256"`
}

// compareKeg lists every file that differs from the bottle, is missing, or
// is on disk but not in the bottle; and counts runtime bytecode extras.
func compareKeg(dir string, files []vendorFile) ([]string, int) {
	var diff []string
	want := map[string]bool{}
	for _, f := range files {
		rel := filepath.ToSlash(filepath.Clean(f.Path))
		want[rel] = true
		if kegOnlyChanged(rel) || strings.HasPrefix(rel, "../") {
			continue
		}
		if why := compareKegFile(dir, filepath.Join(dir, filepath.FromSlash(rel)), f); why != "" {
			diff = append(diff, rel+": "+why)
		}
	}
	extra := 0
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		switch {
		case want[rel] || kegOnlyChanged(rel):
		case strings.Contains(rel, "/__pycache__/") && strings.HasSuffix(rel, ".pyc"):
			extra++
		case d.Type()&fs.ModeSymlink != 0 && statIsDir(p):
			// Not a post_install-shaped addition: everything behind it is
			// outside what the keg record hashes.
			diff = append(diff, rel+": symlink to a directory, not in the bottle")
		default:
			diff = append(diff, rel+": not in the bottle")
		}
		return nil
	})
	sort.Strings(diff)
	return diff, extra
}

func compareKegFile(dir, p string, f vendorFile) string {
	// A bottle path reached through a symlinked directory is not the keg's
	// file: a libexec/ swapped for a link to the user's own folder would
	// match the bottle while later edits there go unrecorded.
	if rel, err := filepath.Rel(dir, filepath.Dir(p)); err == nil && rel != "." {
		cur := dir
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			cur = filepath.Join(cur, part)
			if fi, err := os.Lstat(cur); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				return "reached through a symlinked directory"
			}
		}
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return "missing"
	}
	if f.Link != "" {
		if l, err := os.Readlink(p); err != nil || l != f.Link {
			return "symlink target differs"
		}
		return ""
	}
	if !fi.Mode().IsRegular() {
		return "not a regular file"
	}
	// The root daemon gets here for fresh kegs: no symlink, no FIFO.
	b, err := homebrew.ReadRegular(p, 512<<20)
	if err != nil {
		return "unreadable: " + err.Error()
	}
	s := sha256.Sum256(b)
	raw := hex.EncodeToString(s[:])
	same := raw == f.SHA256 || f.Subst != "" && raw == f.Subst || f.MachO != "" && homebrew.MachOHash(b, nil) == f.MachO
	if !same {
		return "content differs"
	}
	// brew keeps a bottle file's mode on pour (measured: jq, pyenv): the
	// bottle's bytes with a changed exec bit are a changed file.
	if f.SHA256 != "" && (fi.Mode()&0o111 != 0) != f.Exec {
		return "executable bit differs"
	}
	return ""
}

func statIsDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
