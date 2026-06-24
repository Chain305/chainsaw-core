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
type npmCapPattern struct {
	re  *regexp.Regexp
	cap Capability
}

// npmCapPatterns is the ordered list of per-capability patterns evaluated
// against each source line. Simple regex matching — no AST, no type
// resolution. False positives are tolerable; false negatives are the
// failure mode we minimise.
var npmCapPatterns = []*npmCapPattern{
	// Network — import/require of networking modules or global fetch/XHR.
	mkNPMPat(CapNetwork,
		`require\s*\(\s*['"]net['"]\s*\)|require\s*\(\s*['"]http['"]\s*\)|require\s*\(\s*['"]https['"]\s*\)|require\s*\(\s*['"]dgram['"]\s*\)|require\s*\(\s*['"]tls['"]\s*\)|\bfetch\s*\(|XMLHttpRequest`),

	// Shell — child_process import or common exec/spawn variants.
	mkNPMPat(CapShell,
		`require\s*\(\s*['"]child_process['"]\s*\)|\bexecSync\s*\(|\bspawnSync\s*\(|\bexec\s*\(|\bspawn\s*\(`),

	// Filesystem write.
	mkNPMPat(CapFilesystemWrite,
		`fs\.writeFile\b|fs\.writeFileSync\b|fs\.appendFile\b|fs\.createWriteStream\b|fs\.unlink\b|fs\.rename\b`),

	// Filesystem read.
	mkNPMPat(CapFilesystemRead,
		`fs\.readFile\b|fs\.readFileSync\b|fs\.createReadStream\b|fs\.readdir\b`),

	// Environment access.
	mkNPMPat(CapEnvAccess, `process\.env\b`),

	// Dynamic eval — rarely benign in shipped libraries.
	mkNPMPat(CapDynamicEval,
		`\beval\s*\(|\bFunction\s*\(|vm\.runInThisContext\b|vm\.runInNewContext\b`),
}

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
	if _, err := os.Stat(pkgDir); err != nil {
		return nil, err
	}

	caps := make(map[Capability][]Evidence)

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
		scanNPMFile(rel, p, caps)
		return nil
	})
	if err != nil {
		return nil, err
	}

	checkNPMNativeMarkers(pkgDir, caps)

	if len(caps) == 0 {
		return nil, nil
	}
	return caps, nil
}

// scanNPMFile scans a single source file line by line, matching all
// npmCapPatterns and accumulating evidence in caps.
func scanNPMFile(rel, absPath string, caps map[Capability][]Evidence) {
	f, err := os.Open(absPath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		for _, pat := range npmCapPatterns {
			if pat.re.Match(line) {
				snippet := truncateBytes(bytes.TrimSpace(line), MaxSnippetLen)
				addNPMEvidence(caps, pat.cap, Evidence{
					File:    rel,
					Line:    lineNum,
					Snippet: snippet,
				})
			}
		}
	}
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
func truncateBytes(b []byte, maxLen int) string {
	s := string(b)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
