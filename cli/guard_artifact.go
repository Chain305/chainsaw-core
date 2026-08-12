package cli

// Offline inline behavioral analysis for the install guard (W1, plan_competitive_depth).
//
// The malware/typosquat path in guard_eval.go reasons over name+version only —
// the same class of thing a cloud-blocklist competitor does, just sourced
// offline. This file adds the differentiator: when the package's actual bytes
// are available locally, run the real behavioral detectors over them — so the
// guard catches a malicious install script or a hidden-unicode payload that is
// in NO feed yet, which a name lookup never can.
//
// Everything here is offline and pure: artifactmap.Build is stdlib unpack, and
// installscripts/hiddenunicode are pure functions over bytes. No network, no DB.
// Bytes come from CHAINSAW_GUARD_ARTIFACT_DIR — a pre-staged tarball directory.
// That keeps the "nothing leaves the box" guarantee intact and doubles as the
// air-gap story (operators stage the tarballs they allow). Auto-acquiring bytes
// from the package-manager cache, or an opt-in pinned-version fetch, are the
// next increments tracked in docs/plan_competitive_depth.md.
//
// Fail-open is absolute: any missing dir, unreadable file, or empty analysis
// degrades to "no behavioral verdict" and the install proceeds — a guard that
// breaks `npm install` gets uninstalled.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chain305/chainsaw-core/hiddenunicode"
	"github.com/chain305/chainsaw-core/installscripts"
	"github.com/chain305/chainsaw-core/intelligence"
	"github.com/chain305/chainsaw-core/intelligence/artifactmap"
	"github.com/chain305/chainsaw-core/iocscan"
)

// guardArtifactDirEnv points at a directory of pre-staged package tarballs the
// guard may analyse offline. Layout: <dir>/<ecosystem>/<name>-<version>.<ext>
// (e.g. npm/lodash-4.17.21.tgz). Unset disables behavioral analysis entirely.
const guardArtifactDirEnv = "CHAINSAW_GUARD_ARTIFACT_DIR"

// behavioralVerdict is the outcome of inline artifact analysis for one spec.
type behavioralVerdict struct {
	Block    bool
	Severity string // "behavioral-high" | "behavioral-medium" when set
	Reason   string
}

// analyzeArtifact runs the offline behavioral detectors over a package
// archive's bytes and returns a BLOCK verdict for a remote-fetching or
// eval-encoded install script, or a hidden-unicode payload. A clean package, an
// unparseable archive, or an unsupported ecosystem all return a no-block
// verdict — the function never errors, so callers stay fail-open. Pure: no
// network, no DB.
func analyzeArtifact(ecosystem string, archive []byte) behavioralVerdict {
	if len(archive) == 0 {
		return behavioralVerdict{}
	}
	files := artifactmap.Build(archive, artifactmap.Options{}).Files
	var warning behavioralVerdict

	// Install-script analysis on the package manifest.
	switch strings.ToLower(ecosystem) {
	case "npm":
		if pj := rootFileBytes(files, "package.json"); pj != nil {
			scan := installscripts.NPM(pj)
			if v := installVerdict(scan); v.Block {
				return v
			} else if v.Severity != "" {
				warning = v
			}
			if v := referencedScriptVerdict(files, scan.ScriptBody); v.Block {
				return v
			} else if v.Severity != "" {
				warning = v
			}
		}
	case "pip", "pypi":
		setup := rootFileBytes(files, "setup.py")
		pyproject := rootFileBytes(files, "pyproject.toml")
		if setup != nil || pyproject != nil {
			scan := installscripts.Pip(setup, pyproject)
			if v := installVerdict(scan); v.Block {
				return v
			} else if v.Severity != "" {
				warning = v
			}
			if v := referencedScriptVerdict(files, scan.ScriptBody); v.Block {
				return v
			} else if v.Severity != "" {
				warning = v
			}
		}
	case "cargo":
		// Rust: build.rs is arbitrary code rustc runs at build time — the exact
		// vector (rustdecimal). This is depth Aikido's feed is near-empty on.
		cargoToml := rootFileBytes(files, "Cargo.toml")
		buildRs := rootFileBytes(files, "build.rs")
		if cargoToml != nil || buildRs != nil {
			if v := installVerdict(installscripts.Cargo(cargoToml, buildRs)); v.Block {
				return v
			} else if v.Severity != "" {
				warning = v
			}
		}
	case "composer", "php":
		if cj := rootFileBytes(files, "composer.json"); cj != nil {
			if v := installVerdict(installscripts.Composer(cj)); v.Block {
				return v
			} else if v.Severity != "" {
				warning = v
			}
		}
	}

	// Hidden-unicode over the artifact's text files, any ecosystem. Same
	// file set (WantsHiddenUnicodeText) and same benign-context suppression
	// as the server-side intelligence provider, so guard and server never
	// drift on what counts as benign: typescript's Korean-catalog ZWSPs and
	// JSDoc ZWJs — the canonical false positives — suppress here exactly as
	// they do server-side. Surviving hits are tiered by kind×location in
	// hiddenUnicodeVerdict rather than blocking on any hit.
	if txt := files.Select(artifactmap.WantsHiddenUnicodeText); len(txt) > 0 {
		hu := hiddenunicode.Scan(txt)
		intelligence.SuppressBenignHiddenUnicode(&hu, txt)
		if hu.Hits >= hiddenunicode.Threshold() {
			if v := hiddenUnicodeVerdict(hu); v.Block {
				return v
			} else if v.Severity != "" && warning.Severity == "" {
				warning = v
			}
		}
	}

	// Embedded-IOC scan over the artifact's source bodies, any ecosystem (an
	// exfil webhook or coupled stealer string is malicious in any package, so
	// this lives OUTSIDE the ecosystem switch). Same detector the server-side
	// intelligence provider runs (core/intelligence/provider_iocscan.go), so
	// guard and server never drift on what counts as an indicator. A hit is
	// high-confidence and dispositive — block outright rather than warn.
	if src := sourceFileMap(files); len(src) > 0 {
		if r := iocscan.Scan(src); r.Detected {
			// A Weak hit is an indicator found ONLY in the package's own tests,
			// docs examples, or vendored third-party code. Warn — do not refuse
			// the install. Measured on 860 real top packages, treating these as
			// dispositive refused langchain-core (its SSRF-protection test),
			// huggingface-hub (API tests) and rapidfuzz (vendored bootstrap.js).
			if r.Weak {
				return behavioralVerdict{Severity: "behavioral-medium",
					Reason: "embedded malicious indicator (" + r.Kind + ": " + r.Detail + ")"}
			}
			return behavioralVerdict{Block: true, Severity: "behavioral-high",
				Reason: "embedded malicious indicator (" + r.Kind + ": " + r.Detail + ")"}
		}
	}

	return warning
}

// hiddenUnicodeVerdict tiers post-suppression hidden-unicode hits by kind and
// file location instead of treating every hit as a payload:
//
//   - tag runes (U+E0000–E007F): BLOCK anywhere — no benign use exists.
//   - bidi_override in a code file: BLOCK (the Trojan-Source shape; i18n
//     catalogs were already suppressed). In a data file: WARN — data files
//     don't execute, but a bidi mark that reaches a human reviewer is still
//     worth surfacing.
//   - zero_width in a code file: BLOCK only with the byte-encoded payload
//     shape — a contiguous run longer than the benign word-break ceiling or
//     per-file volume at/above the density ceiling. A lone survivor WARNs.
//   - zero_width in a data file: WARN.
//
// The thresholds are the intelligence package's exported constants so the
// guard and the server tier on the same numbers.
func hiddenUnicodeVerdict(hu hiddenunicode.Result) behavioralVerdict {
	var blockReason, warnReason string
	// Sort paths so the reported file is deterministic across runs.
	paths := make([]string, 0, len(hu.PerFile))
	for p := range hu.PerFile {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, path := range paths {
		hits := hu.PerFile[path]
		isCode := artifactmap.WantsSourceCode(path)
		zwOffsets := make(map[int]struct{})
		for _, h := range hits {
			if h.Kind == hiddenunicode.KindZeroWidth {
				zwOffsets[h.Offset] = struct{}{}
			}
		}
		dense := len(zwOffsets) >= intelligence.HiddenUnicodeZeroWidthDensityCeiling

		for _, h := range hits {
			switch h.Kind {
			case hiddenunicode.KindTag:
				return behavioralVerdict{Block: true, Severity: "behavioral-high",
					Reason: fmt.Sprintf("hidden-unicode payload (tag characters in %s)", path)}
			case hiddenunicode.KindBidiOverride:
				if isCode {
					return behavioralVerdict{Block: true, Severity: "behavioral-high",
						Reason: fmt.Sprintf("hidden-unicode payload (bidi override in code: %s)", path)}
				}
				if warnReason == "" {
					warnReason = fmt.Sprintf("bidi override in %s", path)
				}
			case hiddenunicode.KindZeroWidth:
				if isCode && (dense || zeroWidthHitRun(zwOffsets, h.Offset) > intelligence.HiddenUnicodeMaxBenignRun) {
					blockReason = fmt.Sprintf("hidden-unicode payload (zero-width payload encoding in code: %s)", path)
				} else if warnReason == "" {
					warnReason = fmt.Sprintf("zero-width characters in %s", path)
				}
			}
		}
		if blockReason != "" {
			return behavioralVerdict{Block: true, Severity: "behavioral-high", Reason: blockReason}
		}
	}
	if warnReason != "" {
		return behavioralVerdict{Block: false, Severity: "behavioral-medium",
			Reason: fmt.Sprintf("hidden-unicode characters (%d after benign-context filtering: %s)", hu.Hits, warnReason)}
	}
	return behavioralVerdict{}
}

// zeroWidthHitRun returns the length of the contiguous zero-width run that
// contains the hit at byte offset off. The suspect zero-width runes
// (U+200B–U+200F) all encode to 3 UTF-8 bytes and Scan records every suspect
// rune, so members of a run appear as hits exactly 3 bytes apart — the run
// length falls out of the offsets alone, no re-read of the file bytes.
func zeroWidthHitRun(offsets map[int]struct{}, off int) int {
	n := 1
	for o := off - 3; ; o -= 3 {
		if _, ok := offsets[o]; !ok {
			break
		}
		n++
	}
	for o := off + 3; ; o += 3 {
		if _, ok := offsets[o]; !ok {
			break
		}
		n++
	}
	return n
}

// installVerdict promotes an install-script Result to a BLOCK only for the two
// high-confidence kinds — a script that fetches remote code or that hides
// behind eval/encoding. A merely-present lifecycle script is normal and must
// not block, or the guard breaks half the registry.
func installVerdict(r installscripts.Result) behavioralVerdict {
	switch {
	case r.InstallScriptFetchesRemote:
		return behavioralVerdict{Block: true, Severity: "behavioral-high", Reason: "install script fetches and runs remote code"}
	case r.EvalEncoded:
		return behavioralVerdict{Block: true, Severity: "behavioral-high", Reason: "install script hides behind eval/encoded payload"}
	case r.Kind == installscripts.KindMutatesDependency:
		return behavioralVerdict{Block: false, Severity: "behavioral-medium", Reason: "install script mutates files under node_modules"}
	default:
		return behavioralVerdict{}
	}
}

func referencedScriptVerdict(files artifactmap.ArtifactFileMap, scriptBody string) behavioralVerdict {
	refs := installscripts.ReferencedScripts(scriptBody)
	if len(refs) == 0 {
		return behavioralVerdict{}
	}
	src := sourceFileMap(files)
	if len(src) == 0 {
		return behavioralVerdict{}
	}
	var warning behavioralVerdict
	seen := map[string]struct{}{}
	const maxResolve = 16
	resolved := 0
	for _, ref := range refs {
		if resolved >= maxResolve {
			break
		}
		for _, name := range resolveLocalScriptNames(src, ref) {
			if resolved >= maxResolve {
				break
			}
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			resolved++
			switch installscripts.ScanReferencedBody(string(src[name])) {
			case installscripts.KindFetchesRemote, installscripts.KindEvalEncoded:
				return behavioralVerdict{Block: true, Severity: "behavioral-high", Reason: "referenced install script fetches or hides executable payload"}
			case installscripts.KindMutatesDependency:
				warning = behavioralVerdict{Block: false, Severity: "behavioral-medium", Reason: "referenced install script mutates files under node_modules"}
			}
		}
	}
	return warning
}

func sourceFileMap(files artifactmap.ArtifactFileMap) map[string][]byte {
	out := map[string][]byte{}
	for name, f := range files {
		if f.Kind == artifactmap.KindSource {
			out[name] = f.Bytes
		}
	}
	return out
}

func resolveLocalScriptNames(src map[string][]byte, ref string) []string {
	lowerRef := strings.ToLower(strings.TrimPrefix(filepath.ToSlash(ref), "./"))
	var names []string
	for name := range src {
		ln := strings.ToLower(filepath.ToSlash(name))
		if ln == lowerRef || strings.HasSuffix(ln, "/"+lowerRef) {
			names = append(names, name)
		}
	}
	if len(names) == 0 && !strings.Contains(lowerRef, "/") {
		for name := range src {
			if strings.EqualFold(filepath.Base(name), lowerRef) {
				names = append(names, name)
			}
		}
	}
	sort.Slice(names, func(i, j int) bool {
		si, sj := strings.Count(names[i], "/"), strings.Count(names[j], "/")
		if si != sj {
			return si < sj
		}
		return names[i] < names[j]
	})
	if len(names) > 8 {
		names = names[:8]
	}
	return names
}

// packageRoot returns the archive's single top-level directory — the path the
// package manager actually extracts (npm's `strip:1`, a pypi sdist's
// <name>-<version>/, a .crate's <name>-<version>/) — or "" when the archive has
// no directory entries at all (flat: a bare composer.json, a .gem) or more than
// one (a wheel carries pkg/ AND pkg-1.0.dist-info/).
//
// Depth-0 files are deliberately NOT treated as disqualifying. A stray
// root-level entry sitting next to a single top-level dir is precisely the
// decoy shape this function exists to defeat: npm's strip:1 extract DISCARDS
// that entry, so it is invisible to npm and must be invisible to the guard.
func packageRoot(files artifactmap.ArtifactFileMap) string {
	root := ""
	// Map keys are the lower-cased archive paths, so the comparison below is
	// already case-insensitive.
	for key := range files {
		i := strings.Index(key, "/")
		if i <= 0 {
			continue // depth-0 entry: contributes no top-level directory
		}
		top := key[:i]
		if root == "" {
			root = top
			continue
		}
		if root != top {
			return "" // several top-level dirs — no single extract root
		}
	}
	return root
}

// rootFileBytes returns the bytes of the archive entry named target that the
// package manager would actually install.
//
// Resolution is anchored to the archive's single top-level directory
// (packageRoot), not to path depth. Depth alone is exploitable: an
// attacker-published tarball that carries the real malicious
// package/package.json AND a benign root-level package.json wins the
// shallowest-path race, yet npm's strip:1 extract throws the root entry away —
// so the guard would read a manifest npm never sees and the whole behavioral
// scan goes blind. A depth-0 entry therefore never wins over <root>/<target>.
// Same shape for setup.py, pyproject.toml, Cargo.toml, build.rs and
// composer.json, and for all three byte sources (staged dir, package-manager
// cache, deep fetch — all attacker-published bytes).
//
// Archives with no single root fall back to shallowest-wins: flat archives
// (a bare composer.json, a .gem) legitimately keep their manifest at depth 0,
// and multi-root archives (a wheel's pkg/ + pkg-1.0.dist-info/) have no
// strip:1 root to anchor to. Ties are broken lexicographically so the choice is
// deterministic across runs. nil when absent.
func rootFileBytes(files artifactmap.ArtifactFileMap, target string) []byte {
	if root := packageRoot(files); root != "" {
		if f, ok := files[root+"/"+strings.ToLower(target)]; ok {
			return f.Bytes
		}
	}
	var best string
	var bestBytes []byte
	for path, f := range files {
		if !strings.EqualFold(filepath.Base(path), target) {
			continue
		}
		if best == "" || shallowerArchivePath(path, best) {
			best, bestBytes = path, f.Bytes
		}
	}
	return bestBytes
}

// shallowerArchivePath orders archive paths by depth, tie-broken
// lexicographically so two same-depth matches resolve to the same file on every
// run (Go map iteration order is randomised).
func shallowerArchivePath(a, b string) bool {
	da, db := strings.Count(a, "/"), strings.Count(b, "/")
	if da != db {
		return da < db
	}
	return a < b
}

// localArtifactBytes returns a pre-staged tarball for spec from
// CHAINSAW_GUARD_ARTIFACT_DIR, or nil (fail-open) when the dir is unset, the
// file is absent, or it can't be read. Looks for <eco>/<name>-<version>.* and,
// when the spec is unpinned, <eco>/<name>.* as a fallback.
func localArtifactBytes(spec packageSpec) []byte {
	dir := strings.TrimSpace(os.Getenv(guardArtifactDirEnv))
	if dir == "" {
		return nil
	}
	eco := strings.ToLower(spec.Ecosystem)
	name := strings.ReplaceAll(spec.Name, "/", "-") // scoped npm names -> filesystem-safe
	bases := []string{}
	if spec.Version != "" {
		bases = append(bases, name+"-"+spec.Version)
	}
	bases = append(bases, name) // unpinned fallback
	ecoDirs := ecoArtifactAliases(eco)
	for _, base := range bases {
		for _, ed := range ecoDirs {
			for _, ext := range []string{".tgz", ".tar.gz", ".gem", ".zip", ".whl", ".crate"} {
				p := filepath.Join(dir, ed, base+ext)
				if data, err := os.ReadFile(p); err == nil && len(data) > 0 {
					return data
				}
			}
		}
	}
	return nil
}

// ecoArtifactAliases returns the ecosystem subdirectory names to try when
// resolving a staged artifact, canonical name first. The guard's ecosystem
// string is the package-manager verb ("pip", "rubygems", ...), but an operator
// staging artifacts naturally reaches for the registry name ("pypi", "gem").
// Without aliasing, that mismatch made the byte scan silently no-op (fail-open,
// no verdict) — a footgun that reads as "behavioral analysis isn't catching
// anything". Aliasing keeps the offline byte-scan coverage claim robust
// regardless of which reasonable directory name is used.
func ecoArtifactAliases(eco string) []string {
	switch eco {
	case "pip", "pypi":
		return []string{"pip", "pypi"}
	case "rubygems", "gem":
		return []string{"rubygems", "gem", "rubygem"}
	case "cargo", "crates":
		return []string{"cargo", "crates", "crates-io", "cratesio"}
	case "go", "gomod":
		return []string{"go", "gomod", "golang"}
	case "npm":
		return []string{"npm", "node"}
	default:
		return []string{eco}
	}
}

// guardArtifactBytes returns a package's archive bytes from the best available
// source, in order of least to most intrusive: an operator-staged dir
// (CHAINSAW_GUARD_ARTIFACT_DIR), then npm's on-disk cache (both fully offline),
// then — only when deep mode is explicitly enabled — a network fetch. nil
// (fail-open) when no source has it; behavioral analysis simply doesn't run.
func guardArtifactBytes(spec packageSpec) []byte {
	if b := localArtifactBytes(spec); len(b) > 0 {
		return b
	}
	if b := npmCacheArtifactBytes(spec); len(b) > 0 {
		return b
	}
	if b := cargoCacheArtifactBytes(spec); len(b) > 0 {
		return b
	}
	if b := pipCacheArtifactBytes(spec); len(b) > 0 {
		return b
	}
	if b := fetchArtifactBytes(spec); len(b) > 0 {
		return b
	}
	return nil
}

// cargoCacheArtifactBytes reads a pinned crate's .crate archive straight out of
// cargo's on-disk registry cache, so behavioral analysis works with zero
// pre-staging on any machine that has already fetched the crate. Cargo stores
// the download at $CARGO_HOME/registry/cache/<registry-hash>/<name>-<ver>.crate
// (a gzip tarball analyzeArtifact("cargo", …) already unpacks). The
// <registry-hash> segment is an opaque per-source hash, so we can't template the
// exact path — a BOUNDED one-level walk under registry/cache/ matches the crate
// by filename. Fully offline (local disk only). nil on any miss — fail-open.
func cargoCacheArtifactBytes(spec packageSpec) []byte {
	if !strings.EqualFold(spec.Ecosystem, "cargo") || spec.Version == "" {
		return nil // need a pinned version to match the crate file deterministically
	}
	home := strings.TrimSpace(os.Getenv("CARGO_HOME"))
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil || h == "" {
			return nil
		}
		home = filepath.Join(h, ".cargo")
	}
	cacheRoot := filepath.Join(home, "registry", "cache")
	if fi, err := os.Stat(cacheRoot); err != nil || !fi.IsDir() {
		return nil
	}
	want := spec.Name + "-" + spec.Version + ".crate"
	// One level of <registry-hash> subdirs, each holding the .crate files.
	// Bounded by the same PROCESS-WIDE budget as the npm fallback walk so a
	// giant cache can't turn a single `cargo build` into a stat storm.
	if guardCacheWalk.exhausted() {
		return nil
	}
	start := time.Now()
	defer func() { guardCacheWalk.spend(time.Since(start)) }()
	deadline := start.Add(guardCacheWalk.remaining())
	var found []byte
	_ = filepath.WalkDir(cacheRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || found != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if guardCacheWalk.exhausted() || time.Now().After(deadline) {
			return fs.SkipAll
		}
		guardCacheWalk.chargeFile()
		if strings.EqualFold(filepath.Base(p), want) {
			if data, rerr := os.ReadFile(p); rerr == nil && len(data) > 0 {
				found = data
				return fs.SkipAll
			}
		}
		return nil
	})
	return found
}

// pipCacheArtifactBytes reads a pinned wheel out of pip's on-disk HTTP/wheel
// cache. pip stores built/downloaded wheels under <cache>/wheels/**, sharded by
// hash, named per PEP 427 (<normalized_name>-<version>-<pytag>-…-<platform>.whl).
// A .whl is a zip that analyzeArtifact("pip", …) handles. Fully offline.
//
// Coverage is partial by design: wheels rarely carry setup.py, so a wheel-cache
// hit mainly feeds the hidden-unicode and embedded-IOC detectors (which read the
// package's source bodies) rather than the install-script detector. Still worth
// it — those are exactly the in-no-feed-yet payloads the byte scan exists for.
// nil on any miss — fail-open.
func pipCacheArtifactBytes(spec packageSpec) []byte {
	if !strings.EqualFold(spec.Ecosystem, "pip") && !strings.EqualFold(spec.Ecosystem, "pypi") {
		return nil
	}
	if spec.Version == "" {
		return nil // need a pinned version to match the wheel deterministically
	}
	root := pipCacheDir()
	if root == "" {
		return nil
	}
	wheels := filepath.Join(root, "wheels")
	if fi, err := os.Stat(wheels); err != nil || !fi.IsDir() {
		return nil
	}
	// PEP 503 normalization of the distribution name for the wheel filename:
	// lowercase, runs of -_. collapsed to a single _.
	prefix := pep503WheelName(spec.Name) + "-" + spec.Version + "-"
	// Shares the process-wide fallback-walk budget with the npm and cargo walks.
	if guardCacheWalk.exhausted() {
		return nil
	}
	start := time.Now()
	defer func() { guardCacheWalk.spend(time.Since(start)) }()
	deadline := start.Add(guardCacheWalk.remaining())
	var found []byte
	_ = filepath.WalkDir(wheels, func(p string, d fs.DirEntry, err error) error {
		if err != nil || found != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if guardCacheWalk.exhausted() || time.Now().After(deadline) {
			return fs.SkipAll
		}
		guardCacheWalk.chargeFile()
		base := filepath.Base(p)
		if strings.HasSuffix(strings.ToLower(base), ".whl") && strings.HasPrefix(strings.ToLower(base), prefix) {
			if data, rerr := os.ReadFile(p); rerr == nil && len(data) > 0 {
				found = data
				return fs.SkipAll
			}
		}
		return nil
	})
	return found
}

// pipCacheDir resolves pip's cache root: $PIP_CACHE_DIR when set, else the
// per-OS default (~/.cache/pip on Linux, ~/Library/Caches/pip on macOS).
// Returns "" if none exists.
func pipCacheDir() string {
	if c := strings.TrimSpace(os.Getenv("PIP_CACHE_DIR")); c != "" {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			return c
		}
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	candidates := []string{
		filepath.Join(home, ".cache", "pip"),
		filepath.Join(home, "Library", "Caches", "pip"),
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			return c
		}
	}
	return ""
}

// pep503WheelName lowercases a distribution name and collapses runs of -_. into
// a single _, the escaping wheel filenames use for the name component.
func pep503WheelName(name string) string {
	var b strings.Builder
	prevSep := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('_')
				prevSep = true
			}
			continue
		}
		b.WriteRune(r)
		prevSep = false
	}
	return b.String()
}

// guardDeepFetchEnv opts the guard into fetching a pinned package's archive from
// the registry to analyse it BEFORE the install runs. OFF by default: this makes
// a network call, trading the guard's "nothing leaves the box" guarantee for
// true pre-execution blocking on a cold cache. For explicit opt-in only (a CI
// gate, a security team that accepts the trade) — never the default path.
const guardDeepFetchEnv = "CHAINSAW_GUARD_DEEP"

// Registry bases are overridable so a private mirror (or a test) can redirect
// the fetch; defaults are the public registries.
const (
	guardNpmRegistryEnv = "CHAINSAW_GUARD_NPM_REGISTRY"
	guardCargoBaseEnv   = "CHAINSAW_GUARD_CARGO_BASE"
	guardFetchMaxBytes  = 64 * 1024 * 1024
	guardFetchTimeout   = 4 * time.Second
)

// deepFetchEnabled gates the network fetch. CHAINSAW_OFFLINE always wins: a box
// declared offline never reaches out, even if deep mode was left on.
func deepFetchEnabled() bool {
	if envTruthy(os.Getenv("CHAINSAW_OFFLINE")) {
		return false
	}
	return envTruthy(os.Getenv(guardDeepFetchEnv))
}

// fetchArtifactBytes downloads a pinned package's archive for analysis when deep
// mode is on. npm and cargo only — their archive URLs template from name+version
// with no metadata round-trip. Time-boxed, size-capped, and fail-open: any
// error, non-200, or oversize body yields nil and the install proceeds.
func fetchArtifactBytes(spec packageSpec) []byte {
	if !deepFetchEnabled() || spec.Version == "" {
		return nil
	}
	var url string
	switch strings.ToLower(spec.Ecosystem) {
	case "npm":
		reg := strings.TrimRight(envOr(guardNpmRegistryEnv, "https://registry.npmjs.org"), "/")
		last := spec.Name
		if i := strings.LastIndex(last, "/"); i >= 0 {
			last = last[i+1:]
		}
		url = fmt.Sprintf("%s/%s/-/%s-%s.tgz", reg, spec.Name, last, spec.Version)
	case "cargo":
		base := strings.TrimRight(envOr(guardCargoBaseEnv, "https://static.crates.io"), "/")
		url = fmt.Sprintf("%s/crates/%s/%s-%s.crate", base, spec.Name, spec.Name, spec.Version)
	default:
		return nil
	}
	// Opt-in deep mode reaches the network: name the egress host once on stderr
	// and record a local audit entry so an operator who accepted the trade can
	// see exactly what left the box and where. Best-effort, fail-open.
	recordDeepFetchEgress(spec, url)
	ctx, cancel := context.WithTimeout(context.Background(), guardFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "chainsaw-guard")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, guardFetchMaxBytes))
	if err != nil {
		return nil
	}
	return data
}

// deepFetchEgressNoticeOnce makes the human-facing egress notice fire at most
// once per process — the audit ring in guard_state.json keeps the durable,
// per-package record.
var deepFetchEgressNoticeOnce sync.Once

// recordDeepFetchEgress is the audit side-effect of an opt-in deep fetch. It
// (a) prints a one-time stderr line naming the egress host the FIRST time the
// guard reaches the network this process, and (b) appends a capped audit entry
// to guard_state.json so the operator can later see what was fetched and where
// it egressed. Both are best-effort and never block or fail the install.
func recordDeepFetchEgress(spec packageSpec, rawURL string) {
	host := rawURL
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		host = u.Host
	}
	deepFetchEgressNoticeOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "chainsaw: deep-fetch is ON (CHAINSAW_GUARD_DEEP=1) — fetching package bytes from %s to analyze before install. This is the one network egress; disable by unsetting CHAINSAW_GUARD_DEEP.\n", host)
	})
	st := loadGuardState()
	st.DeepFetchEgress = append(st.DeepFetchEgress, deepFetchEgressRecord{
		Ecosystem: spec.Ecosystem,
		Name:      spec.Name,
		Version:   spec.Version,
		Host:      host,
		AtUnix:    time.Now().Unix(),
	})
	if n := len(st.DeepFetchEgress); n > guardDeepFetchEgressMax {
		st.DeepFetchEgress = st.DeepFetchEgress[n-guardDeepFetchEgressMax:]
	}
	saveGuardState(st)
}

func envOr(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

// npmCacheArtifactBytes reads a pinned npm package's tarball straight out of
// npm's on-disk content-addressable cache (cacache), so behavioral analysis
// works with zero pre-staging on any machine that has already fetched the
// package. Fully offline (local disk only). Returns nil on any miss or parse
// problem — never errors, so the guard stays fail-open.
func npmCacheArtifactBytes(spec packageSpec) []byte {
	if !strings.EqualFold(spec.Ecosystem, "npm") || spec.Version == "" {
		return nil // need a pinned version to match the cache key deterministically
	}
	cacache := npmCacacheDir()
	if cacache == "" {
		return nil
	}
	// npm's cache key is the tarball URL; its path ends in /-/<base>-<ver>.tgz.
	// For scoped names (@scope/pkg) the file base is the last segment only.
	last := spec.Name
	if i := strings.LastIndex(last, "/"); i >= 0 {
		last = last[i+1:]
	}
	indexDir := filepath.Join(cacache, "index-v5")

	// Fast path — O(1) direct shard lookup. cacache stores each index entry at
	// index-v5/<h[0:2]>/<h[2:4]>/<h[4:]> where h = hex(sha256(KEY)) and KEY is
	// make-fetch-happen's request-cache key "make-fetch-happen:request-cache:<url>"
	// (verified against a real ~/.npm/_cacache: 289/289 entries matched sha256).
	// The tarball URL templates from the registry base + name + version, so we
	// can compute the exact shard and read ONE file instead of walking the tree.
	// We try the configured registry and the public default (npm keys on whatever
	// registry it resolved).
	wantKeySuffix := "/-/" + last + "-" + spec.Version + ".tgz"
	for _, reg := range npmCacheRegistryCandidates() {
		url := fmt.Sprintf("%s/%s/-/%s-%s.tgz", reg, spec.Name, last, spec.Version)
		key := "make-fetch-happen:request-cache:" + url
		if integrity := cacacheIntegrityForKey(indexDir, key); integrity != "" {
			if b := readCacacheContent(cacache, integrity); len(b) > 0 {
				return b
			}
		}
	}

	// Slow path — bounded fallback walk. The direct lookup misses when npm keyed
	// on a registry/URL shape we didn't template (private mirror with auth in the
	// URL, a non-default port, etc.). Rather than ship a broken O(1), fall back to
	// a BOUNDED scan (capped files + a short deadline) that matches by key suffix.
	// Still fail-open: a miss just means behavioral analysis doesn't run.
	integrity := findNpmCacheIntegrity(indexDir, wantKeySuffix)
	if integrity == "" {
		return nil
	}
	return readCacacheContent(cacache, integrity)
}

// npmCacheRegistryCandidates returns the registry bases to template the cache
// key against, most-specific first: the operator-configured guard registry
// (if any) then the public default. Trailing slashes are trimmed to match the
// URL shape npm stores.
func npmCacheRegistryCandidates() []string {
	out := make([]string, 0, 2)
	seen := map[string]bool{}
	add := func(r string) {
		r = strings.TrimRight(strings.TrimSpace(r), "/")
		if r == "" || seen[r] {
			return
		}
		seen[r] = true
		out = append(out, r)
	}
	add(os.Getenv(guardNpmRegistryEnv))
	add("https://registry.npmjs.org")
	return out
}

// cacacheIntegrityForKey computes the sha256-sharded index path for a cacache
// KEY and reads that ONE file, returning the integrity string of the matching
// entry. O(1) — no tree walk. Returns "" on any miss/parse problem.
func cacacheIntegrityForKey(indexDir, key string) string {
	h := sha256.Sum256([]byte(key))
	hexsum := hex.EncodeToString(h[:])
	p := filepath.Join(indexDir, hexsum[0:2], hexsum[2:4], hexsum[4:])
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	// A shard file can hold multiple newline-delimited "<digest>\t<json>" entries
	// (hash collisions on the bucket prefix); pick the one whose key matches.
	for _, line := range strings.Split(string(data), "\n") {
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		var entry struct {
			Key       string `json:"key"`
			Integrity string `json:"integrity"`
		}
		if json.Unmarshal([]byte(line[tab+1:]), &entry) != nil {
			continue
		}
		if entry.Integrity != "" && entry.Key == key {
			return entry.Integrity
		}
	}
	return ""
}

// npmCacacheDir resolves npm's cacache root: $npm_config_cache/_cacache when
// set (npm exports it to lifecycle scripts and the guard runs in that context),
// else ~/.npm/_cacache. Returns "" if neither exists.
func npmCacacheDir() string {
	var root string
	if c := strings.TrimSpace(os.Getenv("npm_config_cache")); c != "" {
		root = filepath.Join(c, "_cacache")
	} else if home, err := os.UserHomeDir(); err == nil && home != "" {
		root = filepath.Join(home, ".npm", "_cacache")
	}
	if root == "" {
		return ""
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return ""
	}
	return root
}

// guardCacheWalkMaxFiles and guardCacheWalkDeadline bound the fallback index
// walk so a huge cacache (tens of thousands of shards) can never turn a single
// `npm install` into a multi-second stat storm. The O(1) shard lookup in
// npmCacheArtifactBytes handles the common case; this walk only runs on a miss.
//
// The budget is PROCESS-WIDE, not per-call. It used to be allocated fresh on
// every invocation, and all three fallback walks (npm cacache, cargo registry
// cache, pip wheel cache) run once per SPEC — so a 200-package `npm ci` bought
// 200 × 250ms of stat storm. Measured against a 6,000-shard synthetic cacache:
// 30.36s with the cache present vs 1.37s without it. The comment above always
// said "a single npm install"; only the implementation disagreed.
//
// TRADEOFF, stated plainly: once the shared budget is spent, later specs in the
// same invocation get no cache bytes and therefore NO behavioral scan. That is
// fail-open — identical to how a cache miss already behaves — and it is the
// right trade for a tool that sits on the install hot path, but it is a real
// reduction in behavioral coverage on very large installs, not a free win. The
// O(1) shard lookup is unbudgeted and still covers the common case for every
// spec; only the miss path degrades.
const (
	guardCacheWalkMaxFiles = 4096
	guardCacheWalkDeadline = 250 * time.Millisecond
)

// cacheWalkBudget is the shared allowance for the cacache/registry fallback
// walks. Time is tracked as CUMULATIVE SPEND rather than as a wall-clock
// deadline latched at first use: an idle process must not burn the budget, and
// spend-based accounting keeps a long-lived process (the test binary) from
// starving walks that legitimately need it.
type cacheWalkBudget struct {
	spentNanos atomic.Int64
	filesRead  atomic.Int64
}

var guardCacheWalk cacheWalkBudget

// remaining reports the wall-clock still available to fallback walks.
func (b *cacheWalkBudget) remaining() time.Duration {
	return guardCacheWalkDeadline - time.Duration(b.spentNanos.Load())
}

// exhausted reports whether the shared file or time allowance is spent.
func (b *cacheWalkBudget) exhausted() bool {
	return b.filesRead.Load() >= guardCacheWalkMaxFiles || b.remaining() <= 0
}

// chargeFile accounts one file read against the shared allowance.
func (b *cacheWalkBudget) chargeFile() { b.filesRead.Add(1) }

// spend accounts elapsed wall-clock for one completed walk.
func (b *cacheWalkBudget) spend(d time.Duration) {
	if d > 0 {
		b.spentNanos.Add(int64(d))
	}
}

// files exposes the shared counter (test hook).
func (b *cacheWalkBudget) files() int64 { return b.filesRead.Load() }

// reset clears the shared allowance (test hook). Never called in production —
// a guard process is one install.
func (b *cacheWalkBudget) reset() {
	b.spentNanos.Store(0)
	b.filesRead.Store(0)
}

// findNpmCacheIntegrity is the BOUNDED fallback for the O(1) shard lookup: it
// walks the cacache index shards looking for the entry whose key (the tarball
// URL) ends with wantKeySuffix, and returns its integrity string (e.g.
// "sha512-…"). Index entries are newline-delimited "<digest>\t<json>" lines.
// Capped at guardCacheWalkMaxFiles files and guardCacheWalkDeadline wall-clock,
// shared PROCESS-WIDE with the cargo and pip walks — a cap hit just yields ""
// (fail-open, so later specs simply get no behavioral scan; see the budget's
// tradeoff note). Best-effort: any read/parse error skipped.
func findNpmCacheIntegrity(indexDir, wantKeySuffix string) string {
	if guardCacheWalk.exhausted() {
		return ""
	}
	found := ""
	start := time.Now()
	defer func() { guardCacheWalk.spend(time.Since(start)) }()
	deadline := start.Add(guardCacheWalk.remaining())
	_ = filepath.WalkDir(indexDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || found != "" {
			return nil
		}
		if guardCacheWalk.exhausted() || time.Now().After(deadline) {
			return fs.SkipAll
		}
		guardCacheWalk.chargeFile()
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		for _, line := range strings.Split(string(data), "\n") {
			tab := strings.IndexByte(line, '\t')
			if tab < 0 {
				continue
			}
			var entry struct {
				Key       string `json:"key"`
				Integrity string `json:"integrity"`
			}
			if json.Unmarshal([]byte(line[tab+1:]), &entry) != nil {
				continue
			}
			if entry.Integrity != "" && strings.HasSuffix(entry.Key, wantKeySuffix) {
				found = entry.Integrity
				return fs.SkipAll
			}
		}
		return nil
	})
	return found
}

// readCacacheContent maps an integrity string to cacache's content-addressed
// path and returns the bytes. cacache stores content at
// content-v2/<algo>/<hex[0:2]>/<hex[2:4]>/<hex[4:]> where hex is the digest.
// nil on any decode/read failure.
func readCacacheContent(cacache, integrity string) []byte {
	// Integrity may list multiple algos space-separated; take the first.
	first := strings.Fields(integrity)
	if len(first) == 0 {
		return nil
	}
	algo, b64, ok := strings.Cut(first[0], "-")
	if !ok || algo == "" || b64 == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) < 3 {
		return nil
	}
	h := hex.EncodeToString(raw)
	p := filepath.Join(cacache, "content-v2", algo, h[0:2], h[2:4], h[4:])
	if data, err := os.ReadFile(p); err == nil && len(data) > 0 {
		return data
	}
	return nil
}
