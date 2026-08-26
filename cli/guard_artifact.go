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
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
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

// acquireResult reports WHY the byte-acquisition layer produced no bytes.
// The distinction is load-bearing and was previously collapsed: every path
// returned a bare nil, so "there was nothing to analyze" and "we should have
// been able to analyze and couldn't" were indistinguishable at the call site.
//
// That collapse is a bypass primitive. A cache miss is not attacker-
// influenceable — the package simply isn't staged or cached. A truncated walk,
// a transport failure, or an unreadable file at a resolved content-addressed
// path IS: an attacker who can exhaust the walk budget or wedge the read gets
// the same silent ALLOW as a package the guard was never asked about.
//
// Splitting the two does NOT decide what happens next. Per the 2026-08-24
// ruling in docs/plan_competitive_depth.md, warn-vs-block on acquireIncomplete
// is a policy question (it maps onto input.signalsUnavailable, which already
// exists), not a Go constant and not a per-surface table. This type only
// produces the fact honestly; guard_eval.go decides.
type acquireResult uint8

const (
	// acquireOK — bytes were returned.
	acquireOK acquireResult = iota
	// acquireMiss — there were no bytes to analyze. Wrong ecosystem for this
	// source, an unpinned spec, no cache directory, or the coordinate is
	// genuinely not in the index. Benign and common; the guard's other lanes
	// (feed, typosquat, metadata) still ran.
	acquireMiss
	// acquireIncomplete — acquisition was attempted and could not finish.
	// A truncated cache index scan, a transport failure, a corrupt cache
	// index, or an unreadable file at a path that resolved.
	// The guard cannot say the bytes are clean; it can only say it did not
	// get to look at them.
	acquireIncomplete
	// acquireDigestMismatch — bytes WERE obtained and they are not the bytes
	// that will be installed. The archive did not hash to the expected
	// digest: either the project's own lockfile integrity (packageSpec.
	// Integrity, the anchor an attacker with cache write access cannot
	// rewrite) or, on the no-lockfile path, the integrity npm's own index
	// claims for the content it stored.
	//
	// It is DELIBERATELY its own constant rather than a reuse of
	// acquireIncomplete, and it DELIBERATELY does not decide anything.
	//
	//   - Distinct, because "the cache walk ran out of budget" and "the
	//     artifact on disk is not the artifact npm will run" are different
	//     facts, and collapsing them makes the second unreportable. Callers
	//     that only care about severity use degraded(); callers that want to
	//     say WHY compare the constant.
	//   - Not a block, because per the 2026-08-24 ruling in
	//     docs/plan_competitive_depth.md warn-vs-block on a degraded
	//     analysis is a POLICY decision. This lane produces the SIGNAL; the
	//     built-in bundle answers "monitor" and an operator who wants
	//     fail-closed ships a rule that answers "block". Hardcoding a
	//     refusal here would violate the exact ruling the acquireResult
	//     split exists to serve — and would hard-fail installs on any
	//     machine whose cache legitimately disagrees with a stale lockfile.
	acquireDigestMismatch
)

// worse returns the more severe of two results, ordered
// acquireOK < acquireMiss < acquireIncomplete < acquireDigestMismatch. Used to
// fold the per-source results in guardArtifactBytes: one source failing to
// complete outranks another simply not having the package, and a source that
// produced the WRONG bytes outranks one that produced none.
func (r acquireResult) worse(o acquireResult) acquireResult {
	if o > r {
		return o
	}
	return r
}

// degraded reports whether the guard wanted to analyze an artifact and could
// not honestly say it analyzed the right bytes. True for acquireIncomplete and
// acquireDigestMismatch, false for acquireOK and acquireMiss.
//
// This is the predicate policy keys on (guard_policy.go maps it onto
// input.signalsUnavailable). Every new degraded-acquisition constant must be
// added here or it silently becomes a bypass: a fact nothing asks about is a
// fact that allows the install.
func (r acquireResult) degraded() bool {
	return r == acquireIncomplete || r == acquireDigestMismatch
}

// guardAnalysisIncomplete counts, per process, how many times byte
// acquisition returned acquireIncomplete — the guard wanted to analyze an
// artifact and could not finish. Same reasoning as
// internal/server.EnforcementFailOpenCount: a silent degradation that is only
// ever inferred is invisible in aggregate, and a sustained rate means the
// behavioral lane is not running for reasons nobody chose. Process-local
// atomic, no dependency on the subsystem being counted.
//
// Counting is NOT enforcement. The guard now HAS a policy decision point
// (guard_policy.go) and a degraded acquisition reaches it as
// input.signalsUnavailable, so the verdict does change when a rule says it
// should. This counter is orthogonal: it makes the RATE visible.
var guardAnalysisIncomplete atomic.Uint64

// GuardAnalysisIncompleteCount returns the cumulative degraded-acquisition
// count since process start (acquireIncomplete AND acquireDigestMismatch — see
// acquireResult.degraded).
//
// Exposed for tests. The OPERATOR-facing surface for this fact is not a status
// command — it is the per-package policy line printGuardVerdicts emits for the
// builtin/degraded-analysis rule, on the install itself. Stated plainly because
// the previous comment claimed `chainsaw status` read this and nothing did.
func GuardAnalysisIncompleteCount() uint64 { return guardAnalysisIncomplete.Load() }

// guardDigestMismatch counts the acquireDigestMismatch subset: the guard got
// bytes and they were not the bytes that will be installed. Counted separately
// from guardAnalysisIncomplete because the two demand different responses — a
// sustained incomplete rate means the index scan cannot finish on this
// machine, while ANY mismatch means the local cache and the project's lockfile
// disagree about what a package is. The second is the interesting number and it
// would be invisible folded into the first.
var guardDigestMismatch atomic.Uint64

// GuardDigestMismatchCount returns the cumulative acquireDigestMismatch count
// since process start.
//
// Exposed for tests. The OPERATOR-facing surface for this fact is the
// "! integrity" summary printGuardVerdicts emits, unsuppressable by --quiet,
// whenever any verdict carries guardVerdict.DigestMismatch — which is the same
// fact counted here, but scoped to the invocation being printed rather than to
// the process. That distinction matters: reading this counter from the printer
// made a clean allow inherit an earlier install's integrity warning.
//
// `chainsaw status` does not read this and never did; the previous comment
// named a reader that does not exist.
func GuardDigestMismatchCount() uint64 { return guardDigestMismatch.Load() }

// localArtifactBytes returns a pre-staged tarball for spec from
// CHAINSAW_GUARD_ARTIFACT_DIR. Looks for <eco>/<name>-<version>.* and, when the
// spec is unpinned, <eco>/<name>.* as a fallback.
//
// Every LOOKUP path here is acquireMiss, deliberately (the anchor check at the
// end is the one exception and reports for itself). The probe loop tries
// many candidate paths and most are absent by design, so a failed ReadFile
// cannot be told apart from a file that was never staged without an extra stat
// per candidate. The staging directory is operator-controlled — an attacker who
// can make a staged file unreadable can equally delete it — so the ambiguity
// buys nothing and the cheaper read stays.
//
// THE LOCKFILE ANCHOR APPLIES HERE TOO. This source is tried FIRST, so it used
// to be the one byte source that could hand the analyzer un-anchored bytes even
// on a lockfile-driven install — which made "anchor analyzed bytes to the
// lockfile" broader as a claim than as an implementation. The staging dir is
// operator-controlled and so is a lower-risk source than the package-manager
// cache, but the failure it is exposed to is not an attack at all: a STALE
// staged tarball (the operator staged 4.17.20, the lockfile pins 4.17.21) is
// silently analyzed in place of the bytes that will actually be installed, and
// the guard reports acquireOK on an analysis of the wrong artifact. When an
// anchor exists it is checked, and a disagreement is acquireDigestMismatch —
// the same fact, reported the same way, as every other source.
func localArtifactBytes(spec packageSpec) ([]byte, acquireResult) {
	dir := strings.TrimSpace(os.Getenv(guardArtifactDirEnv))
	if dir == "" {
		return nil, acquireMiss
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
				data, err := os.ReadFile(p)
				if err != nil || len(data) == 0 {
					continue
				}
				if res := anchorVerdict(data, spec.Integrity); res != acquireOK {
					return nil, res
				}
				return data, acquireOK
			}
		}
	}
	return nil, acquireMiss
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
// then — only when deep mode is explicitly enabled — a network fetch.
//
// The second return folds every source's result: bytes from any source is
// acquireOK; otherwise the WORST result any source reported wins. One source
// failing to complete outranks another simply not having the package, because
// "the npm cache walk ran out of budget" is a materially different fact from
// "this is a cargo package so the npm source didn't apply" — and only the first
// is attacker-influenceable. See acquireResult.
//
// A later source producing VERIFIED bytes does clear an earlier source's
// acquireDigestMismatch, and that is correct rather than a leak: the only way
// to reach it is a tampered npm cache followed by an opt-in deep fetch whose
// bytes matched the lockfile — which is precisely the sequence npm itself
// performs (ssri rejects the cache entry, pacote calls cleanupCached() and
// refetches). The guard then analyzed the bytes that will actually run.
func guardArtifactBytes(spec packageSpec) ([]byte, acquireResult) {
	worst := acquireOK
	for _, src := range []func(packageSpec) ([]byte, acquireResult){
		localArtifactBytes,
		npmCacheArtifactBytes,
		cargoCacheArtifactBytes,
		pipCacheArtifactBytes,
		fetchArtifactBytes,
	} {
		b, res := src(spec)
		if len(b) > 0 {
			return b, acquireOK
		}
		worst = worst.worse(res)
	}
	return nil, worst
}

// cargoCacheArtifactBytes reads a pinned crate's .crate archive straight out of
// cargo's on-disk registry cache, so behavioral analysis works with zero
// pre-staging on any machine that has already fetched the crate. Cargo stores
// the download at $CARGO_HOME/registry/cache/<registry-hash>/<name>-<ver>.crate
// (a gzip tarball analyzeArtifact("cargo", …) already unpacks). The
// <registry-hash> segment is an opaque per-source hash, so we can't template the
// exact path — a BOUNDED scan under registry/cache/, indexed once per process,
// matches the crate by filename. Fully offline (local disk only).
//
// A TRUNCATED index is acquireIncomplete, not acquireMiss: the scan did not get
// to see the whole cache, so "not found" is unproven. A COMPLETE index makes
// "not found" proven and therefore a plain miss. This is the case an attacker
// could previously drive by spending the process-wide budget earlier in the
// same run; the budget is now spent at most once per cache root, so draining it
// requires a cache pathological enough to exhaust 262,144 files or 3s on its own.
func cargoCacheArtifactBytes(spec packageSpec) ([]byte, acquireResult) {
	if !strings.EqualFold(spec.Ecosystem, "cargo") || spec.Version == "" {
		return nil, acquireMiss // need a pinned version to match the crate file deterministically
	}
	home := strings.TrimSpace(os.Getenv("CARGO_HOME"))
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil || h == "" {
			return nil, acquireMiss
		}
		home = filepath.Join(h, ".cargo")
	}
	cacheRoot := filepath.Join(home, "registry", "cache")
	if fi, err := os.Stat(cacheRoot); err != nil || !fi.IsDir() {
		return nil, acquireMiss
	}
	want := strings.ToLower(spec.Name + "-" + spec.Version + ".crate")
	// One level of <registry-hash> subdirs, each holding the .crate files.
	// Indexed ONCE per process (dirIndex) and shared with the npm and pip
	// scans through the same budget, so a giant cache can't turn a single
	// `cargo build` into a stat storm — and a COMPLETE index makes "this crate
	// is not cached" a proven miss instead of an unproven one.
	p, res := guardCargoCacheIndex.lookup(cacheRoot, want, collectCargoCacheIndex)
	if res != acquireOK {
		return nil, res
	}
	data, rerr := os.ReadFile(p)
	if rerr != nil || len(data) == 0 {
		// Filename matched and the read failed: the crate is here and we could
		// not look at it. Not a miss.
		return nil, acquireIncomplete
	}
	return data, acquireOK
}

// collectCargoCacheIndex records every file in cargo's registry cache under its
// lowercased basename. No file is read during the scan — the value is the path.
func collectCargoCacheIndex(p string, add func(k, v string)) error {
	add(strings.ToLower(filepath.Base(p)), p)
	return nil
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
// A truncated index is acquireIncomplete — see cargoCacheArtifactBytes for why.
func pipCacheArtifactBytes(spec packageSpec) ([]byte, acquireResult) {
	if !strings.EqualFold(spec.Ecosystem, "pip") && !strings.EqualFold(spec.Ecosystem, "pypi") {
		return nil, acquireMiss
	}
	if spec.Version == "" {
		return nil, acquireMiss // need a pinned version to match the wheel deterministically
	}
	root := pipCacheDir()
	if root == "" {
		return nil, acquireMiss
	}
	wheels := filepath.Join(root, "wheels")
	if fi, err := os.Stat(wheels); err != nil || !fi.IsDir() {
		return nil, acquireMiss
	}
	// PEP 503 normalization of the distribution name for the wheel filename:
	// lowercase, runs of -_. collapsed to a single _. A wheel filename is
	// {name}-{version}-{pytag}-{abi}-{platform}.whl and the escaped name never
	// contains a hyphen, so the first two hyphen-separated fields ARE the
	// coordinate — which makes the old prefix match expressible as an exact key.
	key := pep503WheelName(spec.Name) + "-" + strings.ToLower(spec.Version)
	// Indexed ONCE per process, sharing the budget with the npm and cargo scans.
	p, res := guardPipCacheIndex.lookup(wheels, key, collectPipCacheIndex)
	if res != acquireOK {
		return nil, res
	}
	data, rerr := os.ReadFile(p)
	if rerr != nil || len(data) == 0 {
		// Wheel matched and the read failed: present but unreadable.
		return nil, acquireIncomplete
	}
	return data, acquireOK
}

// collectPipCacheIndex records every .whl in pip's wheel cache under its
// "<escaped-name>-<version>" coordinate. No file is read during the scan.
func collectPipCacheIndex(p string, add func(k, v string)) error {
	base := strings.ToLower(filepath.Base(p))
	if !strings.HasSuffix(base, ".whl") {
		return nil
	}
	parts := strings.SplitN(strings.TrimSuffix(base, ".whl"), "-", 3)
	if len(parts) < 2 {
		return nil
	}
	add(parts[0]+"-"+parts[1], p)
	return nil
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
// with no metadata round-trip. Time-boxed and size-capped.
//
// A 404 is acquireMiss: the pinned coordinate is genuinely not on this
// registry, which is the normal shape for a private package resolved against
// the public default. Every OTHER failure — request build, transport, non-404
// status, body read — is acquireIncomplete, because the fetch was attempted
// and did not complete. A network attacker who can reset the connection must
// not be able to buy the same silence as a package that simply isn't there.
//
// INTEGRITY. This path used to perform a plain GET and analyze whatever came
// back, with no check of any kind — the guard's own opt-in network lane was the
// least verified byte source it had. It now checks the response against
// spec.Integrity, the SRI string the project's lockfile records, and reports
// acquireDigestMismatch when they disagree: a mirror (or anything on the wire
// that TLS did not stop, e.g. an operator-redirected CHAINSAW_GUARD_NPM_REGISTRY
// pointing at a compromised proxy) serving different bytes than the lockfile
// pins is exactly the substitution the deep lane must not analyze past.
//
// The check is only as available as the anchor: spec.Integrity is "" for any
// non-lockfile install (see packageSpec.Integrity), and there is no other
// expected digest to compare against without the packument round-trip the
// guard avoids. On that path the fetch is still unverified, and saying so is
// better than implying a check that is not happening.
func fetchArtifactBytes(spec packageSpec) ([]byte, acquireResult) {
	if !deepFetchEnabled() || spec.Version == "" {
		return nil, acquireMiss
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
		return nil, acquireMiss
	}
	// Opt-in deep mode reaches the network: name the egress host once on stderr
	// and record a local audit entry so an operator who accepted the trade can
	// see exactly what left the box and where. Best-effort, fail-open.
	recordDeepFetchEgress(spec, url)
	ctx, cancel := context.WithTimeout(context.Background(), guardFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, acquireIncomplete
	}
	req.Header.Set("User-Agent", "chainsaw-guard")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, acquireIncomplete
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, acquireMiss
	}
	if resp.StatusCode != http.StatusOK {
		return nil, acquireIncomplete
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, guardFetchMaxBytes))
	if err != nil {
		return nil, acquireIncomplete
	}
	if res := anchorVerdict(data, spec.Integrity); res != acquireOK {
		return nil, res
	}
	return data, acquireOK
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
// package. Fully offline (local disk only). Never errors.
//
// This is the digest-VERIFIED path. It used to be described as "digest-bound"
// on the grounds that the integrity string addresses the content store — but
// addressing is not verification, and the index that supplies the address is
// itself in the cache the attacker is assumed to control. readCacacheContent
// now re-hashes the bytes against that index integrity AND against the
// project's lockfile anchor (spec.Integrity) before returning them; see its
// doc comment and packageSpec.Integrity for the attack each check closes and
// for the coverage limit on the second.
//
// An integrity that RESOLVES but whose content cannot be read is
// acquireIncomplete, never acquireMiss — the artifact is present and the guard
// failed to look at it. Content that resolves and does not hash to the expected
// digest is acquireDigestMismatch.
func npmCacheArtifactBytes(spec packageSpec) ([]byte, acquireResult) {
	if !strings.EqualFold(spec.Ecosystem, "npm") || spec.Version == "" {
		return nil, acquireMiss // need a pinned version to match the cache key deterministically
	}
	cacache := npmCacacheDir()
	if cacache == "" {
		return nil, acquireMiss
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
	wantFile := last + "-" + spec.Version + ".tgz"
	worst := acquireMiss
	for _, reg := range npmCacheRegistryCandidates() {
		url := fmt.Sprintf("%s/%s/-/%s", reg, spec.Name, wantFile)
		key := npmCacheKeyPrefix + url
		if integrity := cacacheIntegrityForKey(indexDir, key); integrity != "" {
			b, res := readCacacheContent(cacache, integrity, spec.Integrity)
			if len(b) > 0 {
				return b, acquireOK
			}
			// The index resolved and the content did not. Remember that even
			// if a later candidate registry misses outright.
			worst = worst.worse(res)
		}
	}

	// Slow path — the memoized, bounded index scan. The direct lookup misses when
	// npm keyed on a registry/URL shape we didn't template (private mirror with
	// auth in the URL, a non-default port, an Artifactory path prefix). Rather
	// than ship a broken O(1), fall back to a scan that is performed ONCE per
	// process and matches on the package COORDINATE the request URL names. A
	// miss against a COMPLETE index means behavioral analysis doesn't run; a
	// truncated index means the miss is unproven, and findNpmCacheIntegrity
	// reports which it was.
	integrity, walkRes := findNpmCacheIntegrity(indexDir, spec.Name, wantFile)
	if integrity == "" {
		return nil, worst.worse(walkRes)
	}
	b, res := readCacacheContent(cacache, integrity, spec.Integrity)
	if len(b) > 0 {
		return b, acquireOK
	}
	return nil, worst.worse(res)
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

// guardCacheWalkMaxFiles and guardCacheWalkDeadline bound the fallback cache
// scans so a huge cacache (tens of thousands of shards) can never turn a single
// `npm install` into an unbounded stat storm. The O(1) shard lookup in
// npmCacheArtifactBytes handles the common case; a scan only runs on a miss.
//
// The budget is PROCESS-WIDE, and — since the 2026-08-24 re-measurement — it is
// now spent AT MOST ONCE PER CACHE ROOT rather than once per spec. Each of the
// three fallback sources (npm cacache, cargo registry cache, pip wheel cache)
// builds a MEMOIZED index on first need (see dirIndex) and answers every later
// spec from a map. That is what makes the numbers below affordable.
//
// WHY THE OLD NUMBERS (4096 files / 250ms) WERE A DEFECT, not a conservative
// choice. They were harmless while acquireIncomplete was inert; commit 1f3c4709
// made it policy-actionable (input.signalsUnavailable) without re-measuring.
// A real ~/.npm/_cacache on this machine holds 9,859 index files / 8.6 MB, and
// one COMPLETE warm scan of it costs 250ms — i.e. the whole old deadline bought
// exactly one partial walk, after which every later spec reported
// acquireIncomplete. Replaying a real 924-entry package-lock.json against that
// cache produced INCOMPLETE:31 OK:59 over the first 90 specs: a third of an
// HONEST install marked "signals unavailable", which builtin.rego tells
// operators to convert into a refusal if they want fail-closed coverage.
//
// The numbers now: 262,144 files and 3s of wall-clock, TOTAL, for the life of
// the process and shared across all three index builds. 3s is ~2.6x the cold
// full-scan cost of the real cache measured above (1.13s cold, 250ms warm), so
// a normal machine completes and "not in the index" becomes a PROVEN miss
// rather than an unproven one. A pathological or network-mounted cache still
// truncates, and truncation is still acquireIncomplete — but it now costs the
// process one scan instead of one per spec.
const (
	guardCacheWalkMaxFiles = 262144
	guardCacheWalkDeadline = 3 * time.Second
)

// cacheWalkBudget is the shared allowance for the cacache/registry index
// builds. Time is tracked as CUMULATIVE SPEND rather than as a wall-clock
// deadline latched at first use: an idle process must not burn the budget, and
// spend-based accounting keeps a long-lived process (the test binary) from
// starving scans that legitimately need it.
type cacheWalkBudget struct {
	spentNanos atomic.Int64
	filesRead  atomic.Int64
}

var guardCacheWalk cacheWalkBudget

// remaining reports the wall-clock still available to cache index builds.
func (b *cacheWalkBudget) remaining() time.Duration {
	return guardCacheWalkDeadline - time.Duration(b.spentNanos.Load())
}

// exhausted reports whether the shared file or time allowance is spent.
func (b *cacheWalkBudget) exhausted() bool {
	return b.filesRead.Load() >= guardCacheWalkMaxFiles || b.remaining() <= 0
}

// chargeFile accounts one file read against the shared allowance.
func (b *cacheWalkBudget) chargeFile() { b.filesRead.Add(1) }

// spend accounts elapsed wall-clock for one completed scan.
func (b *cacheWalkBudget) spend(d time.Duration) {
	if d > 0 {
		b.spentNanos.Add(int64(d))
	}
}

// files exposes the shared counter (test hook).
func (b *cacheWalkBudget) files() int64 { return b.filesRead.Load() }

// exhaustForTest spends the whole file allowance in one step (test hook), so a
// test can exercise the budget-exhausted branch without staging hundreds of
// thousands of index files. Never called in production.
func (b *cacheWalkBudget) exhaustForTest() { b.filesRead.Store(guardCacheWalkMaxFiles) }

// reset clears the shared allowance (test hook). Never called in production —
// a guard process is one install.
func (b *cacheWalkBudget) reset() {
	b.spentNanos.Store(0)
	b.filesRead.Store(0)
}

// dirIndex is a MEMOIZED, bounded, one-time scan of a package-manager cache
// directory.
//
// It replaces the previous design, which re-walked the whole cache tree on
// every spec that missed the O(1) lookup. Two things were wrong with that:
//
//   - Cost. N specs × one full tree walk. The shared budget capped the damage
//     by giving up, which converted a performance problem into a CORRECTNESS
//     one the moment acquireIncomplete became policy-actionable.
//   - Provability. A walk that gave up cannot say a coordinate is absent, so
//     every later spec reported acquireIncomplete regardless of what was
//     actually in the cache.
//
// Scanning once and answering from a map fixes both: the budget is spent at
// most once, and a COMPLETE scan turns "not in the map" into a proven
// acquireMiss. complete=false is the only thing that can still produce
// acquireIncomplete, and it is now a property of the process rather than of
// where in the spec list you happen to be.
type dirIndex struct {
	mu       sync.Mutex
	built    bool
	root     string
	entries  map[string]string
	complete bool
}

// lookup returns the value recorded for key, building the index first if this
// process has not scanned root yet.
//
//   - found            → acquireOK
//   - absent, complete → acquireMiss (PROVEN absent: the whole tree was read)
//   - absent, partial  → acquireIncomplete (absence is unproven)
func (x *dirIndex) lookup(root, key string, collect func(path string, add func(k, v string)) error) (string, acquireResult) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if !x.built || x.root != root {
		x.build(root, collect)
	}
	if v := x.entries[key]; v != "" {
		return v, acquireOK
	}
	if !x.complete {
		return "", acquireIncomplete
	}
	return "", acquireMiss
}

// build performs the single bounded scan. collect is invoked for each regular
// file and records zero or more key→value pairs; returning an error marks the
// index INCOMPLETE, because a shard we could not read is a shard whose entries
// we cannot prove absent.
//
// Caller holds x.mu.
func (x *dirIndex) build(root string, collect func(path string, add func(k, v string)) error) {
	x.built, x.root = true, root
	x.entries = make(map[string]string, 1024)
	x.complete = true
	add := func(k, v string) {
		if k == "" || v == "" {
			return
		}
		if _, dup := x.entries[k]; !dup {
			x.entries[k] = v
		}
	}
	if guardCacheWalk.exhausted() {
		x.complete = false
		return
	}
	start := time.Now()
	defer func() { guardCacheWalk.spend(time.Since(start)) }()
	deadline := start.Add(guardCacheWalk.remaining())
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			x.complete = false
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if guardCacheWalk.exhausted() || time.Now().After(deadline) {
			x.complete = false
			return fs.SkipAll
		}
		guardCacheWalk.chargeFile()
		if cerr := collect(p, add); cerr != nil {
			x.complete = false
		}
		return nil
	})
}

// resetForTest drops the memoized scan (test hook). Never called in
// production — a guard process is one install.
func (x *dirIndex) resetForTest() {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.built, x.root, x.entries, x.complete = false, "", nil, false
}

// The three memoized cache indexes, one per fallback source.
var (
	guardNpmCacheIndex   dirIndex
	guardCargoCacheIndex dirIndex
	guardPipCacheIndex   dirIndex
)

// resetGuardCacheIndexesForTest clears every memoized scan AND the shared
// budget. Never called in production.
func resetGuardCacheIndexesForTest() {
	guardNpmCacheIndex.resetForTest()
	guardCargoCacheIndex.resetForTest()
	guardPipCacheIndex.resetForTest()
	guardCacheWalk.reset()
}

// npmCacheKeyPrefix is make-fetch-happen's request-cache key namespace. The
// cacache KEY is this prefix followed by the request URL.
const npmCacheKeyPrefix = "make-fetch-happen:request-cache:"

// npmTarballCoordinate decomposes a registry tarball URL PATH into the package
// name npm resolved and the tarball filename, or ok=false when the path is not
// a tarball URL.
//
// WHY THIS IS NOT A SUFFIX MATCH. The fallback scan used to match with
// strings.HasSuffix(entry.Key, "/-/"+<last path segment>+"-"+version+".tgz"),
// which does not contain the SCOPE. Two consequences, both live:
//
//   - It analyzed the WRONG PACKAGE. Asked for @attacker/lodash@4.17.21 on a
//     real cache it returned the genuine unscoped lodash tarball and reported
//     acquireOK — a false ALLOW in the behavioral lane, since the bytes that
//     get scanned are a popular clean package and the bytes that get installed
//     are the attacker's.
//   - With a lockfile anchor present it did the inverse, manufacturing a
//     FALSE acquireDigestMismatch on a clean install, because the colliding
//     tarball naturally fails the anchor check.
//
// Adding the scope to the suffix does NOT fix it: "/react-dom/-/react-dom-19
// .0.0.tgz" is still a suffix of "/@types/react-dom/-/react-dom-19.0.0.tgz",
// and ten such collisions exist on this machine's real cache (@types/react-dom
// vs react-dom, @types/pg vs pg, four d3-* pairs, …), with the winner decided
// by filesystem order. Only decomposing the path and comparing the NAME
// identifies the package.
//
// The decomposition is exact because npm package names are at most two path
// segments and a scope always begins with '@'. Everything to the left of that
// is a registry path prefix (an Artifactory/Nexus mount point), which is
// precisely the case the fallback scan exists to serve and precisely the case
// an exact full-path comparison would break.
func npmTarballCoordinate(path string) (name, file string, ok bool) {
	i := strings.LastIndex(path, "/-/")
	if i < 0 {
		return "", "", false
	}
	file = path[i+len("/-/"):]
	if file == "" || strings.Contains(file, "/") {
		return "", "", false
	}
	segs := strings.Split(strings.Trim(path[:i], "/"), "/")
	name = segs[len(segs)-1]
	if name == "" {
		return "", "", false
	}
	if n := len(segs); n >= 2 && strings.HasPrefix(segs[n-2], "@") {
		name = segs[n-2] + "/" + name
	}
	return name, file, true
}

// npmCacheKeyCoordinate decomposes a cacache KEY into the package coordinate it
// addresses. Non-URL keys and non-tarball requests (packuments, audit posts)
// are simply not tarball entries and report ok=false.
func npmCacheKeyCoordinate(key string) (name, file string, ok bool) {
	raw := strings.TrimPrefix(key, npmCacheKeyPrefix)
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return "", "", false
	}
	return npmTarballCoordinate(u.Path)
}

// npmCacheIndexKey joins the two halves of a package identity with a byte
// neither a package name nor a filename can contain.
func npmCacheIndexKey(name, file string) string { return name + "\x00" + file }

// collectNpmCacheIndex is the per-file half of the cacache index build. Index
// entries are newline-delimited "<digest>\t<json>" lines; each tarball entry
// contributes name+filename → integrity.
func collectNpmCacheIndex(p string, add func(k, v string)) error {
	data, err := os.ReadFile(p)
	if err != nil {
		// Present and unreadable: absence of anything it holds is unproven.
		return err
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
		if entry.Integrity == "" {
			continue
		}
		name, file, ok := npmCacheKeyCoordinate(entry.Key)
		if !ok {
			continue
		}
		add(npmCacheIndexKey(name, file), entry.Integrity)
	}
	return nil
}

// findNpmCacheIntegrity is the fallback for the O(1) shard lookup: it consults
// the memoized cacache index for the entry whose request URL names exactly this
// package and tarball file, and returns its integrity string (e.g. "sha512-…").
//
// The match identifies the PACKAGE, not just the filename — see
// npmTarballCoordinate for the false-allow that motivated the change.
func findNpmCacheIntegrity(indexDir, name, file string) (string, acquireResult) {
	return guardNpmCacheIndex.lookup(indexDir, npmCacheIndexKey(name, file), collectNpmCacheIndex)
}

// sriRank orders the SRI hash algorithms this build can recompute, strongest
// last. An algorithm absent from this table cannot be verified at all — see
// verifySRI's "checked" return.
//
// WHY sha384 IS HERE even though npm never emits it. An algorithm missing from
// this table is INVISIBLE to verifySRI's pass 1, so it cannot raise `best` —
// which means "sha384-<valid> sha1-<valid>" let the sha1 entry decide the
// verdict, the exact downgrade the two-pass rewrite exists to prevent. SRI
// names sha384 as a first-class algorithm (it is one of the three in the W3C
// spec) and ssri implements it, so any producer other than npm proper — a
// private mirror, an Artifactory proxy that re-hashes, a lockfile converted
// from another tool — may legitimately put one in front of us. Two lines of
// Go turn a silent downgrade AND (since anchorVerdict) a would-be false
// "could not verify" into a real check. Leaving it out saves nothing.
var sriRank = map[string]int{"sha1": 1, "sha256": 2, "sha384": 3, "sha512": 4}

// sriDigest hashes data with one named SRI algorithm. ok=false for an algorithm
// this build does not implement.
func sriDigest(algo string, data []byte) ([]byte, bool) {
	switch strings.ToLower(algo) {
	case "sha512":
		s := sha512.Sum512(data)
		return s[:], true
	case "sha384":
		s := sha512.Sum384(data)
		return s[:], true
	case "sha256":
		s := sha256.Sum256(data)
		return s[:], true
	case "sha1":
		// Weak, and verified anyway: npm still emits sha1 integrity for
		// packages published before 2017 and a weak check beats none. A
		// preimage attack on sha1 is a materially harder ask than
		// "overwrite a file in ~/.npm".
		s := sha1.Sum(data)
		return s[:], true
	default:
		return nil, false
	}
}

// verifySRI recomputes data's hash and checks it against a Subresource-Integrity
// string ("sha512-<base64>", optionally several space-separated and optionally
// carrying "?opts" suffixes).
//
// checked reports whether verification was POSSIBLE — false when sri is empty
// or names only algorithms this build cannot recompute. ok reports the result
// and is meaningless when checked is false. The split matters: "I could not
// check" must never be reported as "it matched", which is precisely the
// conflation that made the old path's integrity handling decorative.
//
// Matching follows ssri.checkData: among the entries whose algorithm we
// support, the STRONGEST algorithm present is the one that decides, and any
// entry of that algorithm matching is a pass. Taking the strongest present
// stops an attacker from appending a weak-but-matching entry to downgrade the
// check.
//
// TWO PASSES, and the split is the security-relevant part.
//
// Pass 1 picks the strongest algorithm NAMED, regardless of whether its digest
// parses. Pass 2 then only looks at entries of that algorithm. The single-pass
// version raised `best` only after a successful decode, so a MALFORMED strong
// entry was skipped entirely and a weak entry beside it decided the verdict:
// "sha512-@@@notbase64@@@ sha1-<valid>" returned checked=true ok=true, which is
// exactly the downgrade the "strongest present decides" rule exists to prevent
// — and indexIntegrity is attacker-controlled under readCacacheContent's own
// threat model.
//
// Pass 2 also validates the digest LENGTH before letting an entry decide.
// Raising `best` on a truncated digest made a malformed lockfile entry return
// checked=true ok=false, i.e. a manufactured acquireDigestMismatch on bytes
// nobody tampered with. "I cannot check this" is checked=false; the whole point
// of the checked/ok split is to keep those two apart.
func verifySRI(data []byte, sri string) (checked, ok bool) {
	entries := strings.Fields(sri)

	// Pass 1 — the strongest algorithm NAMED by any entry we can recompute.
	best := 0
	for _, entry := range entries {
		algo, _, ok := splitSRIEntry(entry)
		if !ok {
			continue
		}
		if rank, known := sriRank[algo]; known && rank > best {
			best = rank
		}
	}
	if best == 0 {
		return false, false
	}

	// Pass 2 — only entries at that rank decide. A well-formed one makes the
	// answer authoritative; if none is well-formed we could not check at all.
	for _, entry := range entries {
		algo, b64, ok := splitSRIEntry(entry)
		if !ok || sriRank[algo] != best {
			continue
		}
		want, derr := decodeSRIDigest(b64)
		if derr != nil {
			continue
		}
		sum, impl := sriDigest(algo, data)
		if !impl || len(want) != len(sum) {
			continue
		}
		checked = true
		if subtleEqual(want, sum) {
			return true, true
		}
	}
	return checked, false
}

// anchorVerdict says what a lockfile anchor implies about bytes the guard is
// about to analyze. It exists so the three byte sources that consult
// packageSpec.Integrity (staged dir, npm cacache, deep fetch) cannot drift on
// the answer, and so the answer has THREE outcomes rather than two.
//
// Every one of those call sites used to be written as
//
//	if checked, match := verifySRI(data, anchor); checked && !match { … }
//
// which collapses "no anchor was supplied" and "an anchor was supplied and I
// could not check it" into the same silent acquireOK. The first is honest and
// extremely common; the second is a report of verification on bytes nothing
// verified.
//
//   - anchor EMPTY → acquireOK. This is the load-bearing case and it must
//     stay non-degraded. packageSpec.Integrity is populated only on a
//     LOCKFILE-DRIVEN install; a git dep, a `file:` dep, a bare
//     `npm install newpkg`, and every pnpm/yarn path legitimately carry no
//     anchor at all (see packageSpec.Integrity's coverage limit). Reporting
//     those as degraded would fire input.signalsUnavailable on ordinary
//     honest installs — which builtin.rego turns into a warn line today and
//     which any operator running the fail-closed posture turns into a
//     REFUSAL. That is the 2026-08-24 ruling's failure mode, not its intent:
//     the lane must produce the fact honestly, and the honest fact about a
//     package with no anchor is "there was nothing to check", not "the check
//     failed".
//   - anchor PRESENT and unverifiable (checked=false: it names only
//     algorithms this build cannot recompute, or every entry at the strongest
//     named rank is malformed) → acquireIncomplete. An anchor WAS supplied,
//     so the guard was asked to bind these bytes to something outside the
//     cache and did not manage it. That is the acquireIncomplete story
//     verbatim: attempted, could not finish, cannot claim the bytes are the
//     ones that will run. It is deliberately not acquireDigestMismatch —
//     unverifiable is not disproven.
//   - anchor PRESENT and disagrees → acquireDigestMismatch, unchanged.
func anchorVerdict(data []byte, anchor string) acquireResult {
	if strings.TrimSpace(anchor) == "" {
		return acquireOK
	}
	checked, match := verifySRI(data, anchor)
	switch {
	case !checked:
		return acquireIncomplete
	case !match:
		return acquireDigestMismatch
	default:
		return acquireOK
	}
}

// splitSRIEntry splits one SRI entry into its lowercased algorithm and base64
// digest, dropping the "?option" suffix SRI permits (cacache and npm both emit
// "?size=…"). ok=false for anything that is not "<algo>-<digest>".
func splitSRIEntry(entry string) (algo, b64 string, ok bool) {
	if q := strings.IndexByte(entry, '?'); q >= 0 {
		entry = entry[:q]
	}
	algo, b64, cut := strings.Cut(entry, "-")
	if !cut || algo == "" || b64 == "" {
		return "", "", false
	}
	return strings.ToLower(algo), b64, true
}

// decodeSRIDigest decodes an SRI digest, tolerating the unpadded form some
// tools emit.
func decodeSRIDigest(b64 string) ([]byte, error) {
	if raw, err := base64.StdEncoding.DecodeString(b64); err == nil {
		return raw, nil
	}
	return base64.RawStdEncoding.DecodeString(b64)
}

// subtleEqual is a constant-time byte compare. Digest comparison is not a
// secret-dependent operation here (both sides are public), but using the
// constant-time primitive costs nothing and keeps the next reader from
// "optimising" a timing leak into a future caller.
func subtleEqual(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// readCacacheContent maps an integrity string to cacache's content-addressed
// path, reads the bytes, and VERIFIES them before returning. cacache stores
// content at content-v2/<algo>/<hex[0:2]>/<hex[2:4]>/<hex[4:]> where hex is the
// digest.
//
// Two independent checks run, in increasing order of strength:
//
//  1. indexIntegrity — the digest npm's own index claims for this content. The
//     bytes are re-hashed and compared. This is what closes the plain
//     content-file-overwrite attack: an attacker who swaps benign bytes into
//     the content store gets a guard verdict on bytes that npm itself will
//     reject on read (ssri.checkData, no opt-out), after which pacote calls
//     cleanupCached() and REFETCHES the real, malicious tarball. Without this
//     check the guard analyzed one artifact and npm installed another.
//     Recomputing costs ~5.6ms/op on a typical tarball against the ~124ms/op
//     gunzip+tar unpack the guard already performs over the same buffer — 4.5%
//     of work already being done, or 35–130ms across a 1000-package `npm ci`.
//
//  2. expected — the SRI string the project's own LOCKFILE records for this
//     coordinate (packageSpec.Integrity), when there is one. This is the
//     stronger anchor because it is outside the cache: check (1) is
//     self-referential, so an attacker who rewrites the index alongside the
//     content passes it, and only the lockfile catches that. "" means no
//     lockfile anchor was available (see packageSpec.Integrity's coverage
//     limit) and this check is skipped rather than failed.
//
// A DISAGREEMENT in either is acquireDigestMismatch, not acquireIncomplete:
// the guard did get bytes, and they are demonstrably not the bytes that will
// be installed. An INABILITY to run either check is a third thing and reports
// acquireIncomplete — "I could not verify" is neither "it matched" nor "it
// did not". Every OTHER failure stays acquireIncomplete, and the caller only
// reaches this function with an integrity string npm's own index produced. A
// malformed integrity means a corrupt index; an unreadable file at a path that
// computed cleanly means the artifact is present and unreadable. Neither is
// "there is nothing to analyze" — in both cases npm has bytes it intends to
// install and the guard did not get to see them.
func readCacacheContent(cacache, indexIntegrity, expected string) ([]byte, acquireResult) {
	// Integrity may list multiple algos space-separated; the content path is
	// addressed by the first.
	first := strings.Fields(indexIntegrity)
	if len(first) == 0 {
		return nil, acquireIncomplete
	}
	// splitSRIEntry, not a bare strings.Cut, for two reasons that used to be
	// bugs:
	//
	//   - It drops the "?opts" suffix. cacache and npm both emit
	//     "sha512-<b64>?size=21", and the bare Cut fed "<b64>?size=21" to the
	//     base64 decoder, which failed — turning a perfectly ordinary cache
	//     entry into acquireIncomplete, i.e. a FALSE degraded signal on an
	//     honest install. verifySRI has always stripped it; the two disagreed.
	//   - It lowercases the algorithm, which is then used for BOTH the
	//     allowlist check and the content path below. Checking a lowercased
	//     algo while building the path from the raw one made "SHA512-…" resolve
	//     on case-insensitive macOS and report acquireIncomplete on Linux —
	//     the same cache producing different verdicts per platform.
	algo, b64, ok := splitSRIEntry(first[0])
	if !ok {
		return nil, acquireIncomplete
	}
	// The algo segment is JSON out of the cache index — i.e. attacker-supplied
	// under this function's own threat model — and it is about to become a
	// filesystem path component. Allowlisting it to the algorithms cacache
	// actually uses closes the traversal ("../../../../tmp-YWJjZA==" resolves
	// to algo "../../../../tmp").
	//
	// WHAT IT DOES NOT GUARANTEE. This check used to also claim it made the
	// verifySRI call below "always CHECKED rather than silently skipped". That
	// stopped being true when verifySRI was rewritten to two passes: it now
	// ranks across EVERY entry in the string, so a second entry naming a
	// STRONGER algorithm with a malformed digest ("sha256-<valid, and it is
	// the entry that addressed the content> sha512-@@@bad@@@") raises `best`
	// to a rank at which nothing decodes, and verifySRI returns checked=false
	// however well-formed first[0] was. The allowlist only ever constrained
	// first[0]. The guarantee is now enforced below, where it belongs: an
	// unCHECKED index verification is acquireIncomplete, not acquireOK on
	// bytes nothing hashed.
	if _, known := sriRank[algo]; !known {
		return nil, acquireIncomplete
	}
	raw, err := decodeSRIDigest(b64)
	if err != nil || len(raw) < 3 {
		return nil, acquireIncomplete
	}
	h := hex.EncodeToString(raw)
	p := filepath.Join(cacache, "content-v2", algo, h[0:2], h[2:4], h[4:])
	data, rerr := os.ReadFile(p)
	if rerr != nil || len(data) == 0 {
		return nil, acquireIncomplete
	}
	// Check (1), the index integrity. UnCHECKED is acquireIncomplete here and
	// NOT acquireOK, and the asymmetry with the anchor below is deliberate:
	// indexIntegrity is never legitimately absent on this path — it is the
	// string that just resolved the content address, it is non-empty, and its
	// first entry's algorithm is in sriRank. So the only way to reach
	// checked=false is a corrupt or tampered index entry, which is the same
	// fact every other malformed-index branch above already reports.
	checked, match := verifySRI(data, indexIntegrity)
	if !checked {
		return nil, acquireIncomplete
	}
	if !match {
		return nil, acquireDigestMismatch
	}
	// Check (2), the lockfile anchor. Absent is normal and stays acquireOK;
	// present-and-unverifiable is acquireIncomplete. See anchorVerdict.
	if res := anchorVerdict(data, expected); res != acquireOK {
		return nil, res
	}
	return data, acquireOK
}
