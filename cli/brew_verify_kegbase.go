package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/homebrew"
)

// verifyKegBaseline compares every keg with the root baseline (see
// homebrew.CheckKegs) and, run as root, stores the next one. Kegs that are
// new or re-poured since the last root run are compared with their bottles
// when that is possible; one that does not verify is not assessed (it may
// be post_install output), never silently trusted.
func verifyKegBaseline(res *brewVerifyResult, prefix, label string, reset bool) {
	sum := sha256.Sum256([]byte(prefix))
	path := filepath.Join(brewLinksBaselineDir, "brew-kegs-"+hex.EncodeToString(sum[:8])+".json")
	var base homebrew.KegBaseline
	trusted := true
	if !reset {
		if _, err := os.Lstat(path); err == nil {
			if err := brewVerifyFileSecure(path); err != nil {
				res.Tamper = append(res.Tamper, label+"keg baseline "+path+": "+err.Error())
				trusted = false
			} else if b, err := homebrew.ReadRegular(path, 512<<20); err != nil {
				res.Errors = append(res.Errors, label+"keg baseline: "+err.Error())
				trusted = false
			} else if err := json.Unmarshal(b, &base); err != nil {
				res.Errors = append(res.Errors, label+"keg baseline "+path+": not valid JSON")
				trusted = false
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			res.Errors = append(res.Errors, label+"keg baseline: "+err.Error())
			trusted = false
		}
	}
	r, err := homebrew.CheckKegs(prefix, base)
	if err != nil {
		// Report what was found before the check gave up, and do not let a
		// user keep it from finishing: a day since the last completed root
		// run is tamper.
		for _, f := range r.Findings {
			res.Tamper = append(res.Tamper, label+f.Path+": "+f.Reason)
		}
		if fi, serr := os.Stat(path); serr == nil && trusted && brewVerifyNow().Sub(fi.ModTime()) > brewCodeStuckAfter {
			res.Tamper = append(res.Tamper, label+"kegs: no keg check has completed since "+fi.ModTime().UTC().Format(time.RFC3339)+" ("+err.Error()+")")
			return
		}
		res.Errors = append(res.Errors, label+"kegs: "+err.Error())
		return
	}
	if res.KegBaseline == nil {
		res.KegBaseline = &r
	}
	for _, f := range r.Findings {
		res.Tamper = append(res.Tamper, label+f.Path+": "+f.Reason)
	}
	if trusted {
		reconcileKegs(res, prefix, label, &r, base == nil)
	}
	if trusted && brewVerifyGeteuid() == 0 {
		// ponytail: plain JSON, 46 MB for 304k files on a 330-keg Mac (first
		// run 47s, later runs 7s with nothing re-hashed); gzip it if size matters.
		body, _ := json.Marshal(r.Baseline)
		err := os.MkdirAll(brewLinksBaselineDir, 0o755)
		if err == nil {
			err = writeFileAtomic(path, body, 0o644)
		}
		if err != nil {
			res.Errors = append(res.Errors, label+"saving keg baseline: "+err.Error())
		}
	}
}

// reconcileKegs decides what the baseline may absorb. Nothing on the
// device vouches for a keg (its receipt is the user's), so only a bottle
// does:
//
//   - re-poured (receipt changed): accepted when no file changed, or the
//     whole keg matches a bottle and every changed file is one a bottle
//     covers. Otherwise each changed file is TAMPER and the previous record
//     stays. A fetch failure is not assessed and retried next run.
//   - new: accepted (vouched) when it matches a bottle, or when every
//     difference is explained at the formula's current version (files
//     post_install adds, links into the formula's own kegs; reported once);
//     accepted unvouched when it has no bottle and core has no formula by
//     its name.
//     Otherwise not assessed on every run until root resets.
//   - the first root run: every keg compared and recorded; a mismatch is
//     reported once and recorded unvouched (trust on first use).
//   - every run: a bin/sbin name root recorded as one formula's that now
//     links into another formula's keg no bottle vouched for is not
//     assessed (a fake tap keg taking over pyenv's name).
func reconcileKegs(res *brewVerifyResult, prefix, label string, r *homebrew.KegCheck, firstRun bool) {
	na := func(k, msg string) { res.NotAssessed = append(res.NotAssessed, label+"keg "+k+": "+msg) }
	comparable := false // set once bottle comparison is known to be possible here
	defer func() { checkLinkTakeover(res, prefix, label, r, comparable) }()
	// accept records a unit only if it is still exactly what was hashed
	// before the comparison that vouches for it re-read the disk.
	accept := func(k string, vouched bool) {
		if !r.StillMatches(prefix, k) {
			na(k, "changed while being checked; compared again next run")
			return
		}
		r.Accept(k, vouched)
	}
	r.Fresh = reconcileOutOfKeg(res, prefix, label, r, r.Fresh, firstRun, accept)
	r.Repoured = reconcileOutOfKeg(res, prefix, label, r, r.Repoured, firstRun, accept)

	major, err := brewMacOSMajor()
	supported := brewKegsSupported && prefix == brewKegComparePrefix
	if supported && err != nil {
		// Not "unsupported": nothing is accepted on a run that cannot compare.
		res.Errors = append(res.Errors, label+"kegs: macOS version unknown, no bottle comparison: "+err.Error())
		return
	}
	comparable = supported && macOSCodenames[major] != ""
	if !comparable {
		// No bottle comparison here (Intel, Linux, the Rosetta prefix, an
		// unknown macOS): a new keg is recorded with a note, but a re-pour
		// that changed files is never absorbed, because the receipt that
		// marks the re-pour is the user's to rewrite.
		for _, k := range r.Fresh {
			r.Accept(k, false)
			if !firstRun {
				na(k, "new since the last root run; bottle comparison covers Apple-silicon /opt/homebrew only")
			}
		}
		for _, k := range r.Repoured {
			if len(r.Changed[k]) == 0 {
				r.Accept(k, r.Baseline[k].Vouched)
				continue
			}
			for _, f := range r.Changed[k] {
				res.Tamper = append(res.Tamper, label+"Cellar/"+k+"/"+f+": changed when the keg was re-poured; no bottle comparison here (Apple-silicon /opt/homebrew only)")
			}
		}
		return
	}
	check := func(k string) brewKegResult {
		v, ok, _ := verifyKeg(prefix, filepath.Join(prefix, "Cellar", filepath.FromSlash(k)), major)
		if ok {
			v.Reason = ""
		}
		return v
	}
	for _, k := range r.Repoured {
		changed := r.Changed[k]
		if len(changed) == 0 {
			r.Accept(k, r.Baseline[k].Vouched)
			continue
		}
		v := check(k)
		if v.transient {
			na(k, "re-poured with changed files; "+v.Reason+" (compared again next run)")
			continue
		}
		// Every changed path is unvouched unless the whole keg matches a
		// bottle, and even then the bottle says nothing about runtime
		// bytecode or the pour's own .brew/ files: a retargeted link, an
		// added file or a forged .pyc behind a touched receipt stays TAMPER.
		var unvouched []string
		for _, f := range changed {
			if v.Reason != "" || homebrew.NotInBottle(f) {
				unvouched = append(unvouched, f)
			}
		}
		if len(unvouched) == 0 {
			accept(k, true)
			continue
		}
		why := "no published bottle has this content (" + v.Reason + ")"
		if v.Reason == "" {
			why = "a bottle cannot vouch for this file"
		}
		for _, f := range unvouched {
			res.Tamper = append(res.Tamper, label+"Cellar/"+k+"/"+f+": changed when the keg was re-poured; "+why)
		}
	}
	for _, k := range r.Fresh {
		v := check(k)
		switch {
		case v.Reason == "":
			accept(k, true)
		case firstRun:
			accept(k, false)
			na(k, "recorded on the first root run without matching a bottle: "+v.Reason)
		case v.transient:
			na(k, "new since the last root run; "+v.Reason+" (compared again next run)")
		case v.compared && len(v.hard) == 0:
			// Every difference is explained (post_install output, links into
			// the formula's own kegs, current version only): vouched.
			accept(k, true)
			na(k, "new since the last root run; matches its bottle except post_install output: "+v.Reason)
		case !v.compared && !v.coreUnbottled:
			accept(k, false)
			na(k, "new since the last root run, with no bottle to compare: "+v.Reason)
		default:
			na(k, "new since the last root run and does not match a published bottle: "+v.Reason)
		}
	}
}

// reconcileOutOfKeg handles the ":"-keyed out-of-keg trees and returns the
// keg keys. npm's tree, new or with a new package.json, is accepted only
// when it matches the registry tarball of the version it names. A
// site-packages new since the last root run is recorded only when it holds
// no startup hook (a .pth there runs on every python3 start); otherwise it
// is not assessed until root resets.
func reconcileOutOfKeg(res *brewVerifyResult, prefix, label string, r *homebrew.KegCheck, keys []string, firstRun bool, accept func(string, bool)) []string {
	var kegs []string
	for _, k := range keys {
		switch {
		case !strings.HasPrefix(k, ":"):
			kegs = append(kegs, k)
		case strings.HasSuffix(k, "/node_modules/npm"):
			reconcileNpmTree(res, prefix, label, r, k, accept)
		case firstRun || len(r.Pending[k].Files) == 0:
			accept(k, false)
		default:
			res.NotAssessed = append(res.NotAssessed, label+k[1:]+": new since the last root run with Python startup hooks ("+strings.Join(hookNames(r.Pending[k].Files), ", ")+"); not recorded until root resets the baseline")
		}
	}
	return kegs
}

func hookNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, sanitizeForTerminal(k))
	}
	sort.Strings(out)
	return out
}

// checkLinkTakeover: links only prove a name points into some keg. A name
// root recorded as formula A's that now points into formula B's keg is
// fine when a bottle vouched for B's keg (python@3.12 -> 3.13); otherwise it
// is how a fake keg takes over a name: reported, and the stored link
// baseline keeps A, so it is reported on every run until B is vouched or
// root resets. A name newly linked after the first run that shadows a
// system command (sudo, ssh, ...) is held to the same rule: into a keg no
// bottle vouches for, it is never adopted.
//
// Where no bottle comparison is possible (Intel, Linux, the Rosetta prefix)
// nothing is ever vouched, so both rules would fire on every routine
// install: a takeover is reported once and adopted, and the shadow rule is
// not applied (a stated limit of those platforms). A keg still pending its
// comparison (a failed fetch) gives "not assessed" for the run, never
// TAMPER, and is not adopted.
func checkLinkTakeover(res *brewVerifyResult, prefix, label string, r *homebrew.KegCheck, comparable bool) {
	res.linkReconciled = true
	names := make([]string, 0, len(res.linkPrior))
	for n := range res.linkPrior {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		owner := res.linkPrior[name]
		keg := homebrew.LinkKeg(prefix, name)
		if keg == "" || strings.SplitN(keg, "/", 2)[0] == owner {
			continue
		}
		if rec, ok := r.Baseline[keg]; ok && rec.Vouched {
			continue
		}
		if comparable && res.linkNext != nil {
			res.linkNext[name] = owner
		}
		res.NotAssessed = append(res.NotAssessed, label+name+": recorded as "+owner+"'s, now links into "+keg+", which no bottle vouches for")
	}
	if res.linkPrior == nil || !comparable {
		return // first run (trust on first use), or nothing can be vouched here
	}
	added := make([]string, 0)
	for n := range res.linkNext {
		if _, was := res.linkPrior[n]; !was && (strings.HasPrefix(n, "bin/") || strings.HasPrefix(n, "sbin/")) {
			added = append(added, n)
		}
	}
	sort.Strings(added)
	for _, name := range added {
		sys, core := homebrew.ShadowedCommand(prefix, filepath.Base(name))
		if sys == "" {
			continue
		}
		keg := homebrew.LinkKeg(prefix, name)
		rec, recorded := r.Baseline[keg]
		if keg == "" || recorded && rec.Vouched {
			continue
		}
		delete(res.linkNext, name)
		if !recorded {
			res.NotAssessed = append(res.NotAssessed, label+name+": newly linked into "+keg+", not yet compared with its bottle, and shadows "+sys+"; checked again next run")
			continue
		}
		msg := label + name + ": newly linked into " + keg + ", which no bottle vouches for, and shadows " + sys
		if core {
			res.Tamper = append(res.Tamper, msg)
		} else {
			res.NotAssessed = append(res.NotAssessed, msg)
		}
	}
}

// reconcileNpmTree accepts a new or replaced npm tree that matches, file for
// file, the registry tarball of the version its package.json names. Only
// brew's npmrc and npm's node_modules/.bin links may be extra.
func reconcileNpmTree(res *brewVerifyResult, prefix, label string, r *homebrew.KegCheck, k string, accept func(string, bool)) {
	dir := filepath.Join(prefix, filepath.FromSlash(k[1:]))
	var pkg struct {
		Version string `json:"version"`
	}
	b, err := homebrew.ReadRegular(filepath.Join(dir, "package.json"), 1<<20)
	if err == nil {
		err = json.Unmarshal(b, &pkg)
	}
	var m struct {
		Unavailable string       `json:"unavailable"`
		Files       []vendorFile `json:"files"`
	}
	if err == nil {
		err = brewVerifyFetchVendor("kind=npm-self&version="+url.QueryEscape(pkg.Version), &m)
	}
	switch {
	case err != nil:
		res.NotAssessed = append(res.NotAssessed, label+k[1:]+": replaced, not yet compared with the npm registry: "+err.Error()+" (compared again next run)")
		return
	case m.Unavailable != "" && len(r.Changed[k]) == 0:
		// A new tree (nothing to compare against but the registry) naming a
		// version the registry does not have: never recorded, never clean.
		res.NotAssessed = append(res.NotAssessed, label+k[1:]+": names npm "+sanitizeForTerminal(pkg.Version)+", and "+m.Unavailable+"; not recorded until root resets the baseline")
		return
	case m.Unavailable != "":
		for _, f := range r.Changed[k] {
			res.Tamper = append(res.Tamper, label+k[1:]+"/"+f+": changed, and "+m.Unavailable)
		}
		return
	}
	diff, _ := compareKeg(dir, m.Files)
	inTarball := map[string]bool{}
	for _, f := range m.Files {
		inTarball[f.Path] = true
	}
	bad := map[string]bool{}
	for _, d := range diff {
		rel := strings.SplitN(d, ": ", 2)[0]
		switch {
		case rel == "npmrc":
			// brew's node post_install writes exactly this line; anything
			// else (script-shell=, node-options=) runs code for every npm.
			if b, err := homebrew.ReadRegular(filepath.Join(dir, "npmrc"), 1<<12); err == nil && string(b) == "prefix = "+prefix+"\n" {
				continue
			}
		case strings.HasPrefix(rel, "node_modules/.bin/"):
			// npm's own bin links: each must land on a file the tarball
			// holds, inside node_modules.
			p := filepath.Join(dir, filepath.FromSlash(rel))
			if t, err := os.Readlink(p); err == nil {
				dest := homebrew.ResolveLink(filepath.Dir(p), t)
				if target, err := filepath.Rel(dir, dest); err == nil && strings.HasPrefix(target, "node_modules/") && inTarball[filepath.ToSlash(target)] {
					continue
				}
			}
		}
		bad[rel] = true
	}
	if len(bad) == 0 {
		accept(k, true)
		return
	}
	paths := make([]string, 0, len(bad))
	for f := range bad {
		paths = append(paths, f)
	}
	sort.Strings(paths)
	for _, f := range paths {
		res.Tamper = append(res.Tamper, label+k[1:]+"/"+f+": differs from npm "+pkg.Version+" on the registry")
	}
}

func intersect(a, b []string) []string {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	var out []string
	for _, x := range a {
		if in[x] {
			out = append(out, x)
		}
	}
	return out
}
