package risk

// minified.go — filesystem-based minification detector.
//
// DetectMinified walks a package directory and returns the list of JS/MJS/CJS
// files that look minified according to three heuristics (any one is enough):
//
//  1. Average line length > 500 chars.
//  2. Any single line longer than 50 000 chars.
//  3. No comment lines AND average line length > 200 chars.
//
// The helper is exported so downstream projection layers can call it when they
// have access to an unpacked artifact directory. The risk signal registration
// in registry_quality.go consumes the result via risk.Input.IsMinifiedCode /
// risk.Input.MinifiedFiles, which are populated by callers — this function
// itself does not mutate any Input.

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	minifiedMaxFileSize       = 5 * 1024 * 1024 // 5 MB
	minifiedAvgLineLenHigh    = 500
	minifiedMaxLineLenAbsHigh = 50_000
	minifiedAvgLineLenMed     = 200
)

// jsExtensions is the set of file extensions DetectMinified inspects.
var jsExtensions = map[string]bool{
	".js":  true,
	".mjs": true,
	".cjs": true,
}

// skipDirs lists directory names that DetectMinified never descends into.
var skipDirs = map[string]bool{
	"node_modules": true,
	"test":         true,
	"tests":        true,
	"__tests__":    true,
}

// DetectMinified walks pkgDir looking for minified JS files. Only the
// top-level directory, dist/, and lib/ are scanned. Files larger than 5 MB
// and files whose names match *.test.js or *.spec.js are skipped.
//
// Returns the list of paths (relative to pkgDir) that triggered a heuristic.
// Returns nil when no minified files are found. Returns nil and a non-nil
// error only on fatal I/O failures (e.g. pkgDir is not readable).
func DetectMinified(pkgDir string) ([]string, error) {
	var flagged []string
	err := filepath.WalkDir(pkgDir, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil // skip unreadable entries; don't abort the walk
		}
		if d.IsDir() {
			name := d.Name()
			// Always skip excluded dirs.
			if skipDirs[name] {
				return filepath.SkipDir
			}
			// Only scan top-level, dist/, and lib/. Any other subdir is
			// skipped unless it's the root itself.
			rel, relErr := filepath.Rel(pkgDir, path)
			if relErr != nil {
				return nil
			}
			if rel != "." && rel != "dist" && rel != "lib" {
				// Allow top-level entries but not deeper ones unless
				// they are dist/ or lib/.
				parts := strings.SplitN(rel, string(filepath.Separator), 2)
				if len(parts) > 1 {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Skip non-JS files.
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !jsExtensions[ext] {
			return nil
		}

		// Skip test / spec files.
		base := strings.ToLower(d.Name())
		if strings.HasSuffix(base, ".test.js") ||
			strings.HasSuffix(base, ".test.mjs") ||
			strings.HasSuffix(base, ".test.cjs") ||
			strings.HasSuffix(base, ".spec.js") ||
			strings.HasSuffix(base, ".spec.mjs") ||
			strings.HasSuffix(base, ".spec.cjs") {
			return nil
		}

		// Skip files larger than 5 MB.
		info, statErr := os.Stat(path)
		if statErr != nil {
			return nil
		}
		if info.Size() > minifiedMaxFileSize {
			return nil
		}

		if looksMinifiedOnDisk(path) {
			rel, relErr := filepath.Rel(pkgDir, path)
			if relErr != nil {
				rel = path
			}
			flagged = append(flagged, rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return flagged, nil
}

// looksMinifiedOnDisk opens path and applies the three heuristics.
func looksMinifiedOnDisk(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Increase the default scanner buffer to handle very long lines without
	// treating a buffer-overflow as EOF. We cap at 512 KB per line — enough
	// to see a 50 000-char line without reading the whole file.
	sc.Buffer(make([]byte, 64*1024), 512*1024)

	var (
		totalLines   int
		totalChars   int64
		commentLines int
		maxLineLen   int
	)
	for sc.Scan() {
		line := sc.Text()
		totalLines++
		l := len(line)
		totalChars += int64(l)
		if l > maxLineLen {
			maxLineLen = l
		}
		// Count lines that look like comments (// or /* after trim).
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			commentLines++
		}
	}
	// Ignore scanner errors — partial reads are fine for the heuristic.

	if totalLines == 0 {
		return false
	}
	avg := int(totalChars / int64(totalLines))

	// Heuristic 1: avg line length > 500.
	if avg > minifiedAvgLineLenHigh {
		return true
	}
	// Heuristic 2: any single line > 50 000 chars.
	if maxLineLen > minifiedMaxLineLenAbsHigh {
		return true
	}
	// Heuristic 3: no comment lines AND avg > 200.
	if commentLines == 0 && avg > minifiedAvgLineLenMed {
		return true
	}
	return false
}
