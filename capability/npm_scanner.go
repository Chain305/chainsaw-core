package capability

// npm_scanner.go implements capability detection for npm (and yarn/bun)
// packages. It is part of the capability package rather than a sub-package
// to avoid circular imports (the dispatcher in scanner.go needs to call
// scanNPM, and scanNPM uses the Capability/Evidence types defined in
// types.go — both in this package).
//
// See the package doc in types.go for design rationale and TODO ecosystems.

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/chain305/chainsaw-core/codesmell"
)

// sourceExts is the set of file extensions scanned for JS capability patterns.
var sourceExts = map[string]bool{
	".js":  true,
	".cjs": true,
	".mjs": true,
	".ts":  true,
}

// skipDirs are directory names that are never descended into when scanning npm
// package source trees.
//   - node_modules: transitive deps are a separate concern.
//   - test/tests/__tests__/spec/specs: test-only code is not shipped to
//     downstream consumers and frequently exercises dangerous APIs to test
//     sandboxing.
//   - __mocks__: jest mock directories.
var skipDirs = map[string]bool{
	"node_modules": true,
	"test":         true,
	"tests":        true,
	"__tests__":    true,
	"__mocks__":    true,
	"spec":         true,
	"specs":        true,
}

// testFileSuffixes are filename suffixes that mark test/spec files. These
// are skipped even when they appear outside a dedicated test directory.
var testFileSuffixes = []string{
	".test.js", ".test.cjs", ".test.mjs", ".test.ts",
	".spec.js", ".spec.cjs", ".spec.mjs", ".spec.ts",
}

// npmCapPattern associates a compiled regexp with the Capability it detects.
// ignore, when set, is stripped from the line before re runs: it names a
// benign idiom that re would otherwise match.
type npmCapPattern struct {
	re     *regexp.Regexp
	cap    Capability
	ignore *regexp.Regexp
}

// npmCapPatterns is the ordered list of per-capability patterns evaluated
// against each source line. Simple regex matching — no AST, no type
// resolution. False positives are tolerable; false negatives are the
// failure mode we minimise.
var npmCapPatterns = []*npmCapPattern{
	// Network — import/require of networking modules or global fetch/XHR.
	mkNPMPat(CapNetwork,
		`require\s*\(\s*['"]net['"]\s*\)|require\s*\(\s*['"]http['"]\s*\)|require\s*\(\s*['"]https['"]\s*\)|require\s*\(\s*['"]dgram['"]\s*\)|require\s*\(\s*['"]tls['"]\s*\)|\bfetch\s*\(|XMLHttpRequest`),

	// Shell — child_process import or common exec/spawn variants. A bare
	// `exec(`/`spawn(` call only: a method call such as `re.exec(` is
	// RegExp.prototype.exec in the overwhelming majority of shipped code,
	// and is handled by npmShellMethodCall below instead.
	mkNPMPat(CapShell,
		`require\s*\(\s*['"]child_process['"]\s*\)|\bexecSync\s*\(|\bspawnSync\s*\(|(?:^|[^.\w$])(?:exec|spawn)\s*\(`),

	// Filesystem write.
	mkNPMPat(CapFilesystemWrite,
		`fs\.writeFile\b|fs\.writeFileSync\b|fs\.appendFile\b|fs\.createWriteStream\b|fs\.unlink\b|fs\.rename\b`),

	// Filesystem read.
	mkNPMPat(CapFilesystemRead,
		`fs\.readFile\b|fs\.readFileSync\b|fs\.createReadStream\b|fs\.readdir\b`),

	// Environment access.
	mkNPMPat(CapEnvAccess, `process\.env\b`),

	// Dynamic eval — rarely benign in shipped libraries.
	// `Function('return this')()` is the standard pre-globalThis way to reach
	// the global object (lodash _root.js, core-js, most UMD wrappers). It
	// compiles a constant, so it is not dynamic code.
	{
		re:     regexp.MustCompile(`\beval\s*\(|\bFunction\s*\(|vm\.runInThisContext\b|vm\.runInNewContext\b`),
		cap:    CapDynamicEval,
		ignore: regexp.MustCompile(`\bFunction\s*\(\s*['"]return this['"]\s*\)`),
	},
}

// npmShellMethodCall is `x.exec(` / `x.spawn(`. It counts as shell access only
// in a file that also references child_process: otherwise it is RegExp exec
// (lodash _cloneRegExp.js fired cap.shell this way, 2026-09-30).
var npmShellMethodCall = regexp.MustCompile(`\.(?:exec|spawn)\s*\(`)

// npmChildProcessRef is any mention of the module in code: require, import,
// or the node: specifier.
var npmChildProcessRef = regexp.MustCompile(`child_process`)

func mkNPMPat(cap Capability, pattern string) *npmCapPattern {
	return &npmCapPattern{re: regexp.MustCompile(pattern), cap: cap}
}

// ScanNPM walks pkgDir and returns a map of detected capabilities to their
// evidence. The map is nil (not empty) when no capabilities are detected.
// An error is returned only for failures accessing the root directory
// itself — per-file I/O errors are silently skipped.
//
// This is called by Analyze() in scanner.go for npm/yarn/bun ecosystems.
func ScanNPM(pkgDir string) (map[Capability][]Evidence, error) {
	caps, _, err := scanNPMCounted(pkgDir)
	return caps, err
}

// scanNPMCounted is ScanNPM plus the number of matching lines per capability.
// Evidence stops at MaxEvidencePerCap; the count does not, so a report can say
// "3 of 41 locations" instead of implying there were only three.
func scanNPMCounted(pkgDir string) (map[Capability][]Evidence, map[Capability]int, error) {
	if _, err := os.Stat(pkgDir); err != nil {
		return nil, nil, err
	}

	caps := make(map[Capability][]Evidence)
	counts := make(map[Capability]int)

	err := filepath.WalkDir(pkgDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		name := d.Name()
		ext := strings.ToLower(filepath.Ext(name))

		// .node binary — native capability, file-level detection.
		if ext == ".node" {
			rel, _ := filepath.Rel(pkgDir, p)
			addNPMEvidence(caps, CapNativeCode, Evidence{
				File:    rel,
				Snippet: ".node native addon",
			})
			return nil
		}

		// Only scan recognised source extensions.
		if !sourceExts[ext] {
			return nil
		}

		// Skip test files by suffix.
		lowerName := strings.ToLower(name)
		for _, suffix := range testFileSuffixes {
			if strings.HasSuffix(lowerName, suffix) {
				return nil
			}
		}

		// Large files are likely minified/vendored bundles — skip content
		// scan and record cap.minified_or_bundled instead.
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		if info.Size() > MaxFileScanBytes {
			rel, _ := filepath.Rel(pkgDir, p)
			addNPMEvidence(caps, CapMinifiedOrBundled, Evidence{
				File:    rel,
				Snippet: "file exceeds 5 MB — likely minified or vendored bundle",
			})
			return nil
		}

		// Scan line by line.
		rel, _ := filepath.Rel(pkgDir, p)
		scanNPMFile(rel, p, caps, counts)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	checkNPMNativeMarkers(pkgDir, caps)

	if len(caps) == 0 {
		return nil, nil, nil
	}
	return caps, counts, nil
}

// scanNPMFile scans a single source file line by line, matching all
// npmCapPatterns and accumulating evidence in caps and match counts in counts.
//
// Comment lines are skipped: lodash's JSDoc example `* fs.writeFileSync(...)`
// fired cap.filesystem_write. Only comments that START a line are masked. A
// mid-line `/*` is left alone, because glob strings such as "src/**/*.js" would
// otherwise swallow real code until the next `*/`.
// ponytail: line-level masking, not a lexer. A full JS lexer has to decide
// regex-vs-division, and one wrong guess on a minified file masks the rest of
// it — a fail-open. Upgrade only with a real parser.
func scanNPMFile(rel, absPath string, caps map[Capability][]Evidence, counts map[Capability]int) {
	f, err := os.Open(absPath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Files up to MaxFileScanBytes are scanned, so one line may be that long.
	// With bufio's default 64 KiB limit, any longer line (minified or
	// obfuscated code) stopped the scan with an error nobody checked.
	scanner.Buffer(make([]byte, 64*1024), MaxFileScanBytes+1)

	var pendingShell []Evidence
	sawChildProcess := false
	inBlock := false
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		code, stillInBlock := stripLeadingComment(line, inBlock)
		inBlock = stillInBlock
		if len(bytes.TrimSpace(code)) == 0 {
			continue
		}
		snippet := func() string { return truncateBytes(bytes.TrimSpace(line), MaxSnippetLen) }
		if npmChildProcessRef.Match(code) {
			sawChildProcess = true
		}
		shellHit := false
		for _, pat := range npmCapPatterns {
			target := code
			if pat.ignore != nil {
				target = pat.ignore.ReplaceAll(code, nil)
			}
			if pat.re.Match(target) {
				counts[pat.cap]++
				if pat.cap == CapShell {
					shellHit = true
				}
				addNPMEvidence(caps, pat.cap, Evidence{File: rel, Line: lineNum, Snippet: snippet()})
			}
		}
		if !shellHit && npmShellMethodCall.Match(code) {
			pendingShell = append(pendingShell, Evidence{File: rel, Line: lineNum, Snippet: snippet()})
		}
	}
	if err := scanner.Err(); err != nil {
		// Unreadable past this point: say so rather than report a clean file.
		addNPMEvidence(caps, CapMinifiedOrBundled, Evidence{File: rel, Line: lineNum, Snippet: "scan stopped: " + err.Error()})
	}
	if sawChildProcess {
		for _, ev := range pendingShell {
			counts[CapShell]++
			addNPMEvidence(caps, CapShell, ev)
		}
	}
}

// stripLeadingComment returns the part of line that is code, given whether
// the previous line ended inside a block comment that started a line.
func stripLeadingComment(line []byte, inBlock bool) ([]byte, bool) {
	if inBlock {
		end := bytes.Index(line, []byte("*/"))
		if end < 0 {
			return nil, true
		}
		line = line[end+2:]
	}
	trimmed := bytes.TrimLeft(line, " \t")
	if bytes.HasPrefix(trimmed, []byte("//")) {
		return nil, false
	}
	if bytes.HasPrefix(trimmed, []byte("/*")) {
		end := bytes.Index(trimmed[2:], []byte("*/"))
		if end < 0 {
			return nil, true
		}
		return stripLeadingComment(trimmed[2+end+2:], false)
	}
	return line, false
}

// checkNPMNativeMarkers checks for file-level native-code indicators:
//   - binding.gyp present (node-gyp build descriptor).
//   - "node-gyp" or "bindings" reference in package.json.
func checkNPMNativeMarkers(pkgDir string, caps map[Capability][]Evidence) {
	if _, err := os.Stat(filepath.Join(pkgDir, "binding.gyp")); err == nil {
		addNPMEvidence(caps, CapNativeCode, Evidence{
			File:    "binding.gyp",
			Snippet: "binding.gyp present — native addon build descriptor",
		})
	}
	pkgJSON, err := os.ReadFile(filepath.Join(pkgDir, "package.json"))
	if err == nil {
		content := string(pkgJSON)
		if strings.Contains(content, "node-gyp") || strings.Contains(content, `"bindings"`) {
			addNPMEvidence(caps, CapNativeCode, Evidence{
				File:    "package.json",
				Snippet: "node-gyp or bindings reference in package.json",
			})
		}
	}
}

// addNPMEvidence appends ev to caps[cap] up to MaxEvidencePerCap entries.
// Beyond that the key still exists in caps but no further evidence is stored.
func addNPMEvidence(caps map[Capability][]Evidence, cap Capability, ev Evidence) {
	existing := caps[cap]
	if len(existing) >= MaxEvidencePerCap {
		return
	}
	caps[cap] = append(existing, ev)
}

// truncateBytes returns s truncated to maxLen bytes (appending "..." when
// truncation occurs). Operates on a []byte for efficiency in the hot scan path.
//
// URL credentials are redacted here, first (codesmell.RedactURLCredentials).
// Every source-derived snippet in this package is built through this
// function, and redacting after the cut could miss a secret whose '@' was
// cut off.
func truncateBytes(b []byte, maxLen int) string {
	s := codesmell.RedactURLCredentials(string(b))
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
