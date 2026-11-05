package homebrew

// rubyload.go — is the Ruby brew runs, and the gems it loads, what the
// tracked pins say?
//
// brew runs on portable Ruby untarred under Library/Homebrew/vendor/
// portable-ruby/<version> and puts each gem directory setup.rb names on
// its load path (vendor/bundle/ruby/<api>/gems/<name-version>/lib). Both are
// git-ignored, so CompareBrewTree never sees them, and both are writable by
// the prefix's owner: a json.rb dropped into a gem there runs inside every
// brew command. The pins are tracked, so once CompareBrewTree has shown the
// checkout is upstream they are upstream's: vendor/portable-ruby-<arch>
// names the portable Ruby blob's sha256, Gemfile.lock's CHECKSUMS each
// .gem's. The server turns a pin into a per-file manifest
// (/api/homebrew/vendor-manifest); CompareVendorDir compares a directory
// with it.
//
// Not covered: native extensions compiled on the device
// (vendor/bundle/ruby/<api>/extensions/…, and the .bundle a gem with
// extensions builds into its own lib/) have no upstream bytes to compare;
// their .bundle files are listed, never failed (CheckExtensionDir fails
// anything else in those directories). Gem directories setup.rb does not name are
// not loaded by brew and are ignored, as are bundler's binstubs and
// gemspecs (brew runs Ruby with --disable=gems; only `brew style` and
// other dev commands use them). The eight gems Homebrew commits to git
// are compared here too: CompareBrewTree skips a new subdirectory in them.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
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
	"strings"
)

// VendorFile is one entry of a server manifest.
type VendorFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Exec   bool   `json:"exec,omitempty"`
	Link   string `json:"link,omitempty"`
}

// VendorDir returns the brew vendor directory of a checkout.
func VendorDir(repo string) string {
	return filepath.Join(repo, "Library", "Homebrew", "vendor")
}

var rubyPinRe = regexp.MustCompile(`(?m)^ruby_SHA=([0-9a-f]{64})\s*$`)

// PortableRubyPin reads the tracked pin for this platform: the version
// (vendor/portable-ruby-version) and the blob sha256
// (vendor/portable-ruby-<processor>-<os>). arch is e.g. "arm64-darwin".
func PortableRubyPin(repo, arch string) (version, sha string, err error) {
	v := VendorDir(repo)
	b, err := readRegular(filepath.Join(v, "portable-ruby-version"), 64)
	if err != nil {
		return "", "", fmt.Errorf("portable-ruby-version: %w", err)
	}
	version = strings.TrimSpace(string(b))
	if !regexp.MustCompile(`^[0-9][0-9A-Za-z._]*$`).MatchString(version) {
		return "", "", errors.New("portable-ruby-version is not a version")
	}
	b, err = readRegular(filepath.Join(v, "portable-ruby-"+arch), 4096)
	if err != nil {
		return "", "", fmt.Errorf("portable-ruby-%s: %w", arch, err)
	}
	m := rubyPinRe.FindSubmatch(b)
	if m == nil {
		return "", "", fmt.Errorf("portable-ruby-%s has no ruby_SHA", arch)
	}
	return version, string(m[1]), nil
}

// GemPin is a gem directory setup.rb puts on the load path, with the .gem
// sha256 Gemfile.lock pins for it ("" when the lock has none).
type GemPin struct {
	Dir    string   // e.g. json-2.21.2, nokogiri-1.18.0-arm64-darwin
	SHA256 string   //
	Loads  []string // the directories inside it on $:, e.g. lib, lib/concurrent-ruby
}

var (
	setupGemRe = regexp.MustCompile(`/gems/([^/"]+)/([^"]+)"\)`)
	setupExtRe = regexp.MustCompile(`/extensions/[^"]*/([^/"]+)"\)`)
	lockSumRe  = regexp.MustCompile(`^  ([^ ]+) \(([^)]+)\) sha256=([0-9a-f]{64})$`)
)

// GemPins lists the gem directories bundler's standalone setup.rb loads and
// the compiled-extension directories it adds, pairing each gem directory
// with its Gemfile.lock checksum.
func GemPins(repo string) (gems []GemPin, extensions []string, err error) {
	lib := filepath.Join(repo, "Library", "Homebrew")
	setup, err := readRegular(filepath.Join(lib, "vendor", "bundle", "bundler", "setup.rb"), 1<<20)
	if err != nil {
		return nil, nil, fmt.Errorf("setup.rb: %w", err)
	}
	lock, err := readRegular(filepath.Join(lib, "Gemfile.lock"), 1<<20)
	if err != nil {
		return nil, nil, fmt.Errorf("Gemfile.lock: %w", err)
	}
	sums := map[string]string{}
	in := false
	sc := bufio.NewScanner(bytes.NewReader(lock))
	for sc.Scan() {
		line := sc.Text()
		if line == "CHECKSUMS" {
			in = true
			continue
		}
		if in && line == "" {
			break
		}
		if m := lockSumRe.FindStringSubmatch(line); in && m != nil {
			sums[m[1]+"-"+m[2]] = m[3]
		}
	}
	// Every line naming a gem directory must parse: a load path this skips
	// is a directory nothing compares.
	idx := map[string]int{}
	for _, line := range bytes.Split(setup, []byte("\n")) {
		if !bytes.Contains(line, []byte("/gems/")) {
			continue
		}
		m := setupGemRe.FindSubmatch(line)
		if m == nil || !validVendorName(string(m[1])) || !validRelPath(string(m[2])) {
			return nil, nil, errors.New("setup.rb has a gem load path this check does not understand; refusing to report a clean comparison")
		}
		d, load := string(m[1]), string(m[2])
		i, ok := idx[d]
		if !ok {
			i = len(gems)
			idx[d] = i
			gems = append(gems, GemPin{Dir: d, SHA256: sums[d]})
		}
		gems[i].Loads = append(gems[i].Loads, load)
	}
	for _, m := range setupExtRe.FindAllSubmatch(setup, -1) {
		if d := string(m[1]); validVendorName(d) {
			extensions = append(extensions, d)
		}
	}
	if len(gems) == 0 {
		return nil, nil, errors.New("setup.rb names no gem directories; refusing to report a clean comparison")
	}
	return gems, extensions, nil
}

func validVendorName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, `/\`)
}

// CompareVendorDir compares dir with a manifest whose paths start with
// strip. A changed or re-pointed file Ruby could load or run is TAMPER, as
// is any such file the manifest does not hold, and any directory on the way
// that is a symlink. A missing one is TAMPER only under loadDirs ("" = all):
// a deleted lib/ file lets a require fall through to a later load path
// entry, while gems Homebrew commits to git are pruned to lib/ and LICENSE,
// so their test/ and examples/ are missing by design. compiled: the gem
// builds native code on install, so an extra .bundle/.so/.o is WARN.
func CompareVendorDir(dir, label, strip string, loadDirs []string, files []VendorFile, compiled bool) (compared int, findings []Finding, err error) {
	want := map[string]VendorFile{}
	for _, f := range files {
		p := strings.TrimPrefix(f.Path, strip)
		if p == f.Path && strip != "" {
			continue // outside the directory this manifest describes
		}
		if p != "" && validRelPath(p) {
			want[p] = f
		}
	}
	if len(want) == 0 {
		return 0, nil, errors.New("manifest lists no files; refusing to report a clean comparison")
	}
	add := func(sev, rel, why string) {
		findings = append(findings, Finding{sev, label + "/" + rel, why})
	}
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		if err == nil || !errors.Is(err, fs.ErrNotExist) {
			add(SeverityTamper, ".", "not a real directory")
			return 0, findings, nil
		}
		return 0, nil, err
	}
	dirs := map[string]bool{}
	for p := range want {
		for d := pathpkg.Dir(p); d != "."; d = pathpkg.Dir(d) {
			dirs[d] = true
		}
	}
	for d := range dirs {
		if fi, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(d))); err == nil && !fi.IsDir() {
			add(SeverityTamper, d, "directory replaced by a symlink or file")
		}
	}
	for p, f := range want {
		compared++
		local := filepath.Join(dir, filepath.FromSlash(p))
		fi, err := os.Lstat(local)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if (f.Link != "" || loadableName(p) || f.Exec) && underAny(p, loadDirs) {
				add(SeverityTamper, p, "missing")
			}
			continue
		case err != nil:
			return compared, findings, err
		}
		if f.Link != "" {
			if t, err := os.Readlink(local); err != nil || t != f.Link {
				add(SeverityTamper, p, "should be a symlink to "+f.Link)
			}
			continue
		}
		if !fi.Mode().IsRegular() {
			add(SeverityTamper, p, "not a regular file")
			continue
		}
		// Every file is hashed, not only .rb: some gems Marshal.load their
		// data files, so a changed data file can be code.
		if sum, err := fileSHA256(local); err != nil {
			add(SeverityTamper, p, "could not be read safely: "+err.Error())
		} else if sum != f.SHA256 {
			add(SeverityTamper, p, "content differs from the pinned artifact")
		}
	}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() || d.Name() == ".DS_Store" {
			return nil
		}
		if _, ok := want[rel]; ok {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		symlink := info.Mode()&fs.ModeSymlink != 0
		if !symlink && !loadableName(rel) && info.Mode().Perm()&0o111 == 0 && pathpkg.Ext(rel) != ".o" {
			return nil // build logs, Makefiles, gem docs
		}
		if compiled && !symlink && (pathpkg.Ext(rel) == ".bundle" || pathpkg.Ext(rel) == ".so" || pathpkg.Ext(rel) == ".o" || pathpkg.Ext(rel) == ".dylib") {
			add(SeverityWarn, rel, "compiled on this device, not compared")
			return nil
		}
		add(SeverityTamper, rel, "not in the pinned artifact")
		return nil
	})
	sort.Slice(findings, func(i, j int) bool { return findings[i].Path < findings[j].Path })
	return compared, findings, err
}

// underAny: p lies in one of dirs ("" matches everything).
func underAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if d == "" || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// CheckExtensionDir walks a compiled-extension directory setup.rb puts on
// the load path (vendor/bundle/ruby/<api>/extensions/<platform>/<abi>/<gem>).
// RubyGems writes only the compiled .bundle/.so there (WARN: no upstream
// bytes to compare) and its build logs. Anything else Ruby could load, an
// executable or a symlink is TAMPER: an open3.rb there shadows the stdlib.
func CheckExtensionDir(dir, label string) ([]Finding, error) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return []Finding{{SeverityTamper, label, "not a real directory"}}, nil
	}
	var out []Finding
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		ext := pathpkg.Ext(rel)
		switch {
		case info.Mode().IsRegular() && (ext == ".bundle" || ext == ".so"):
			out = append(out, Finding{SeverityWarn, label + "/" + rel, "compiled on this device, not compared"})
		case info.Mode().IsRegular() && info.Mode().Perm()&0o111 == 0 && !loadableName(rel):
			// gem.build_complete, gem_make.out, mkmf.log
		default:
			out = append(out, Finding{SeverityTamper, label + "/" + rel, "not something RubyGems builds into an extension directory"})
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, err
}

func loadableName(p string) bool {
	switch pathpkg.Ext(p) {
	case ".rb", ".so", ".bundle", ".dylib":
		return true
	}
	return false
}

func validRelPath(p string) bool {
	return !pathpkg.IsAbs(p) && pathpkg.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../")
}

func fileSHA256(p string) (string, error) {
	f, fi, err := openRegular(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if n, err := io.Copy(h, io.LimitReader(f, fi.Size()+1)); err != nil {
		return "", err
	} else if n != fi.Size() {
		return "", errors.New("size changed while hashing")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
