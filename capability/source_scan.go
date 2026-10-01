package capability

// Shared walkers for the per-ecosystem scanners. An ecosystem file declares
// its patterns and comment syntax and calls one of these; it never
// re-implements the walk, the evidence cap, the counting or the comment
// masking. npm_scanner.go predates these and keeps its own loop because of
// its child_process gating.

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// linePattern is one capability rule matched against a line of source.
// ignore, when set, is stripped from the line before re runs: it names a
// benign idiom re would otherwise match.
type linePattern struct {
	cap    Capability
	re     *regexp.Regexp
	ignore *regexp.Regexp
}

func pat(c Capability, re string) linePattern {
	return linePattern{cap: c, re: regexp.MustCompile(re)}
}

// commentSyntax describes a language's comments. Only comments that START a
// line are masked (see npm_scanner.go for why a mid-line opener is not).
type commentSyntax struct {
	line       []string // e.g. "#", "//"
	blockOpen  string   // e.g. "/*", "=begin", `"""`
	blockClose string   // e.g. "*/", "=end", `"""`
}

var (
	hashComments  = commentSyntax{line: []string{"#"}}
	cComments     = commentSyntax{line: []string{"//"}, blockOpen: "/*", blockClose: "*/"}
	phpComments   = commentSyntax{line: []string{"//", "#"}, blockOpen: "/*", blockClose: "*/"}
	rubyComments  = commentSyntax{line: []string{"#"}, blockOpen: "=begin", blockClose: "=end"}
	pythonComment = commentSyntax{line: []string{"#"}}
)

// sourceScanSpec is everything an ecosystem supplies to scanSourceTree.
type sourceScanSpec struct {
	exts     map[string]bool // lower-case, with the dot
	skipDirs map[string]bool // directory names never descended into
	skipFile func(rel string) bool
	comments commentSyntax
	patterns []linePattern
}

// commonSkipDirs are test, example and vendored trees shipped in archives.
// Test code exercises dangerous APIs on purpose and does not run for users.
var commonSkipDirs = map[string]bool{
	"test": true, "tests": true, "testing": true, "__tests__": true, "spec": true, "specs": true,
	"example": true, "examples": true, "testdata": true, "vendor": true, "node_modules": true,
	"benches": true, "docs": true, ".git": true,
}

// scanSourceTree walks pkgDir, scans every file whose extension is in spec.exts
// line by line, and returns evidence and counts in the same shape as ScanNPM.
func scanSourceTree(pkgDir string, spec sourceScanSpec) (map[Capability][]Evidence, map[Capability]int, error) {
	if _, err := os.Stat(pkgDir); err != nil {
		return nil, nil, err
	}
	skip := spec.skipDirs
	if skip == nil {
		skip = commonSkipDirs
	}
	caps := map[Capability][]Evidence{}
	counts := map[Capability]int{}
	err := filepath.WalkDir(pkgDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if p != pkgDir && skip[strings.ToLower(d.Name())] {
				return filepath.SkipDir
			}
			return nil
		}
		if !spec.exts[strings.ToLower(filepath.Ext(d.Name()))] {
			return nil
		}
		rel, _ := filepath.Rel(pkgDir, p)
		if spec.skipFile != nil && spec.skipFile(filepath.ToSlash(rel)) {
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > MaxFileScanBytes {
			if err == nil {
				addNPMEvidence(caps, CapMinifiedOrBundled, Evidence{File: filepath.ToSlash(rel), Snippet: "file exceeds 5 MB — not scanned"})
			}
			return nil
		}
		scanSourceFile(filepath.ToSlash(rel), p, spec, caps, counts)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if len(caps) == 0 {
		return nil, nil, nil
	}
	return caps, counts, nil
}

func scanSourceFile(rel, abs string, spec sourceScanSpec, caps map[Capability][]Evidence, counts map[Capability]int) {
	f, err := os.Open(abs)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), MaxFileScanBytes+1)
	inBlock := false
	n := 0
	for sc.Scan() {
		n++
		line := sc.Bytes()
		code, still := stripCommentLine(line, inBlock, spec.comments)
		inBlock = still
		if len(bytes.TrimSpace(code)) == 0 {
			continue
		}
		for _, pt := range spec.patterns {
			target := code
			if pt.ignore != nil {
				target = pt.ignore.ReplaceAll(code, nil)
			}
			if pt.re.Match(target) {
				counts[pt.cap]++
				addNPMEvidence(caps, pt.cap, Evidence{File: rel, Line: n, Snippet: truncateBytes(bytes.TrimSpace(line), MaxSnippetLen)})
			}
		}
	}
	if err := sc.Err(); err != nil {
		addNPMEvidence(caps, CapMinifiedOrBundled, Evidence{File: rel, Line: n, Snippet: "scan stopped: " + err.Error()})
	}
}

// stripCommentLine is stripLeadingComment generalised over a comment syntax.
func stripCommentLine(line []byte, inBlock bool, cs commentSyntax) ([]byte, bool) {
	if inBlock {
		end := bytes.Index(line, []byte(cs.blockClose))
		if end < 0 {
			return nil, true
		}
		line = line[end+len(cs.blockClose):]
	}
	trimmed := bytes.TrimLeft(line, " \t")
	for _, lc := range cs.line {
		if bytes.HasPrefix(trimmed, []byte(lc)) {
			return nil, false
		}
	}
	if cs.blockOpen != "" && bytes.HasPrefix(trimmed, []byte(cs.blockOpen)) {
		rest := trimmed[len(cs.blockOpen):]
		end := bytes.Index(rest, []byte(cs.blockClose))
		if end < 0 {
			return nil, true
		}
		return stripCommentLine(rest[end+len(cs.blockClose):], false, cs)
	}
	return line, false
}

// binaryStringPattern matches the raw bytes of a compiled file: a JVM class
// constant pool or a .NET metadata string heap stores type and method names as
// plain UTF-8, so `java/lang/ProcessBuilder` or `System.Diagnostics.Process`
// is a byte-exact reference to the API.
type binaryStringPattern struct {
	cap Capability
	re  *regexp.Regexp
}

func binPat(c Capability, re string) binaryStringPattern {
	return binaryStringPattern{cap: c, re: regexp.MustCompile(re)}
}

// scanBinaryTree scans every file with an extension in exts as bytes. Evidence
// has Line 0 and the matched name as its snippet; counts are per file.
func scanBinaryTree(pkgDir string, exts map[string]bool, skipDirs map[string]bool, patterns []binaryStringPattern) (map[Capability][]Evidence, map[Capability]int, error) {
	if _, err := os.Stat(pkgDir); err != nil {
		return nil, nil, err
	}
	if skipDirs == nil {
		skipDirs = commonSkipDirs
	}
	caps := map[Capability][]Evidence{}
	counts := map[Capability]int{}
	err := filepath.WalkDir(pkgDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if p != pkgDir && skipDirs[strings.ToLower(d.Name())] {
				return filepath.SkipDir
			}
			return nil
		}
		if !exts[strings.ToLower(filepath.Ext(d.Name()))] {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > MaxFileScanBytes*4 {
			return nil
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(pkgDir, p)
		for _, bp := range patterns {
			if m := bp.re.Find(body); m != nil {
				counts[bp.cap]++
				addNPMEvidence(caps, bp.cap, Evidence{File: filepath.ToSlash(rel), Snippet: truncateBytes(m, MaxSnippetLen)})
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if len(caps) == 0 {
		return nil, nil, nil
	}
	return caps, counts, nil
}
