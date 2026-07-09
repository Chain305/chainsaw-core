// Package artifactmap provides a single-pass, shared decompression +
// classification of an artifact archive for Tier-2 intelligence providers.
//
// Previously each Tier-2 scanner (install scripts, hidden unicode, ...)
// walked req.Artifact.Bytes on its own. With the 9 additional scanners
// planned for Wave 3 of the Socket gap matrix, per-scanner walks mean
// 11× decompress + byte-copy work per Scan over a potentially 256 MiB
// archive. Consolidating the walk once up-front lets every downstream
// scanner read the map as a pure function.
//
// The package is intentionally dependency-free (stdlib only) so it can
// be imported by low-level intelligence providers without introducing
// cycles. Archive format support matches what provider_installscripts.go
// ships today: zip, gzipped tar, and plain tar.
package artifactmap

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"path"
	"sort"
	"strings"
)

// Kind tags an ArtifactFile by its likely role inside the archive. The
// tags are intentionally coarse so downstream scanner predicates can do
// fast O(1) prefilters without re-examining every filename themselves.
type Kind uint8

const (
	// KindOther is the zero value — catch-all for files whose extension
	// we do not recognise.
	KindOther Kind = iota
	// KindManifest is a package-level manifest the installscripts
	// parsers speak: package.json, setup.py, pyproject.toml, Cargo.toml,
	// build.rs, composer.json, *.gemspec.
	KindManifest
	// KindSource is human-written source code — *.js, *.py, *.go, etc.
	// Exactly the extensions hiddenunicode.Scan walks plus a few more
	// for Wave 3 scanners.
	KindSource
	// KindText is documentation, configuration, or other text content
	// that is not executable source but that still benefits from a
	// hidden-unicode style inspection (*.md, *.yaml, *.json, ...).
	KindText
	// KindBinary is a file whose bytes smell binary (NUL probe inside
	// the first 4 KiB) — compiled artefacts, images, shared libraries.
	KindBinary
)

// ArtifactFile is a single entry extracted from the archive. Bytes is
// bounded by PerFileCap so a pathological 2 GiB entry cannot blow up
// memory. Size reflects the declared archive header (or the read byte
// count when no header was available) — callers that need to know
// whether Bytes was truncated can compare len(Bytes) < Size.
type ArtifactFile struct {
	Path  string
	Bytes []byte
	Size  int64
	Kind  Kind
}

// ArtifactFileMap is keyed by the lower-cased archive-internal path so
// callers can do case-insensitive lookups without rebuilding the map.
type ArtifactFileMap map[string]ArtifactFile

// Default caps. These are intentionally the loosest sensible budgets
// that still prevent adversarial artefacts from DoS'ing the proxy. The
// hidden-unicode scanner layers its own tighter budget (500 files /
// 50 MiB) on top of this map.
const (
	// MaxArtifactBytes caps the total archive payload we are willing to
	// decompress. Mirrors the legacy maxArtifactBytesForInspection in
	// provider_installscripts.go.
	MaxArtifactBytes = 256 * 1024 * 1024
	// MaxFiles caps the number of file entries we will retain. Anything
	// past this is dropped silently — the caller sees a Truncated flag.
	MaxFiles = 10000
	// PerFileCap caps the bytes we read out of a single archive entry.
	// Matches the historical maxManifestFileBytes.
	PerFileCap = 2 * 1024 * 1024
)

// Options tunes a Build. Zero values fall back to the constants above.
type Options struct {
	MaxArtifactBytes int64
	MaxFiles         int
	PerFileCap       int64
}

func (o Options) normalize() Options {
	if o.MaxArtifactBytes <= 0 {
		o.MaxArtifactBytes = MaxArtifactBytes
	}
	if o.MaxFiles <= 0 {
		o.MaxFiles = MaxFiles
	}
	if o.PerFileCap <= 0 {
		o.PerFileCap = PerFileCap
	}
	return o
}

// Result is the output of Build: the map plus book-keeping useful for
// logging and for the SWR / benchmarks.
type Result struct {
	Files     ArtifactFileMap
	Truncated bool
	// TotalBytes is the sum of bytes actually retained (post per-file
	// cap), not the archive size.
	TotalBytes int64
}

// Build consumes artifact bytes once and returns the populated map.
// Unknown archive formats yield an empty map rather than an error so
// callers can degrade gracefully to "nothing to say".
func Build(payload []byte, opts Options) Result {
	opts = opts.normalize()
	res := Result{Files: ArtifactFileMap{}}
	if len(payload) == 0 {
		return res
	}
	if int64(len(payload)) > opts.MaxArtifactBytes {
		payload = payload[:opts.MaxArtifactBytes]
		res.Truncated = true
	}
	switch {
	case looksLikeZip(payload):
		buildFromZip(payload, opts, &res)
	case looksLikeGzip(payload):
		gzr, err := gzip.NewReader(bytes.NewReader(payload))
		if err != nil {
			return res
		}
		defer gzr.Close()
		buildFromTar(gzr, opts, &res)
	default:
		// Plain tar? Try it; tar.NewReader will fail gracefully if not.
		buildFromTar(bytes.NewReader(payload), opts, &res)
	}
	return res
}

func looksLikeZip(p []byte) bool {
	return len(p) >= 4 && bytes.Equal(p[:4], []byte("PK\x03\x04"))
}

func looksLikeGzip(p []byte) bool {
	return len(p) >= 2 && p[0] == 0x1f && p[1] == 0x8b
}

func buildFromTar(r io.Reader, opts Options, res *Result) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			// Malformed tar — return whatever we have so far.
			return
		}
		// Only regular files. tar.TypeRegA is the legacy "regular" flag
		// some old npm tarballs still use.
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		if len(res.Files) >= opts.MaxFiles {
			res.Truncated = true
			return
		}
		name := sanitizePath(hdr.Name)
		if name == "" {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(tr, opts.PerFileCap))
		if err != nil {
			continue
		}
		addFile(res, name, body, hdr.Size)
	}
}

func buildFromZip(payload []byte, opts Options, res *Result) {
	zr, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if len(res.Files) >= opts.MaxFiles {
			res.Truncated = true
			return
		}
		name := sanitizePath(f.Name)
		if name == "" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(rc, opts.PerFileCap))
		rc.Close()
		if rerr != nil {
			continue
		}
		addFile(res, name, body, int64(f.UncompressedSize64))
	}
}

// sanitizePath strips leading slashes / drive letters and rejects
// absolute paths. Also caps overly long names at 4096 bytes so a
// pathological entry can't cause runaway string work in callers.
func sanitizePath(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if len(name) > 4096 {
		return ""
	}
	// Drop leading "./" prefixes, reject absolute paths, reject .. segments.
	name = strings.TrimPrefix(name, "./")
	if strings.HasPrefix(name, "/") {
		return ""
	}
	clean := path.Clean(name)
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." {
		return ""
	}
	return clean
}

func addFile(res *Result, name string, body []byte, declaredSize int64) {
	size := declaredSize
	if size <= 0 {
		size = int64(len(body))
	}
	kind := classify(name, body)
	res.Files[strings.ToLower(name)] = ArtifactFile{
		Path:  name,
		Bytes: body,
		Size:  size,
		Kind:  kind,
	}
	res.TotalBytes += int64(len(body))
}

// classify inspects the path extension and, for ambiguous cases, the
// first 4 KiB of the body to decide Kind. Order matters: manifests win
// over source, source wins over text, binary wins over everything when
// the body smells binary.
func classify(name string, body []byte) Kind {
	base := strings.ToLower(path.Base(name))
	if isManifestBase(base) {
		return KindManifest
	}
	ext := strings.ToLower(path.Ext(base))
	if _, ok := sourceExts[ext]; ok {
		if isBinary(body) {
			return KindBinary
		}
		return KindSource
	}
	if _, ok := textExts[ext]; ok {
		if isBinary(body) {
			return KindBinary
		}
		return KindText
	}
	if isBinary(body) {
		return KindBinary
	}
	return KindOther
}

func isManifestBase(base string) bool {
	switch base {
	case "package.json", "setup.py", "pyproject.toml",
		"cargo.toml", "build.rs", "composer.json":
		return true
	}
	return strings.HasSuffix(base, ".gemspec")
}

// sourceExts is the code-like extension set. Callers asking "give me
// source files" (Wave 3) filter on Kind == KindSource.
var sourceExts = map[string]struct{}{
	".js": {}, ".ts": {}, ".jsx": {}, ".tsx": {}, ".mjs": {}, ".cjs": {},
	".py": {}, ".rb": {}, ".rs": {}, ".go": {}, ".java": {}, ".php": {},
	".cs": {}, ".cr": {}, ".coffee": {},
	".swift": {}, ".kt": {}, ".kts": {}, ".gradle": {}, ".scala": {},
}

// textExts is the documentation / config extension set. hiddenunicode
// treats these the same as source — mirror the scan.go allowlist.
var textExts = map[string]struct{}{
	".md": {}, ".txt": {}, ".json": {}, ".yaml": {}, ".yml": {},
	".toml": {}, ".xml": {}, ".gemspec": {}, ".nuspec": {},
}

// isBinary is the same cheap heuristic hiddenunicode uses — a NUL byte
// inside the first 4 KiB. Kept local so the artifactmap package has
// zero internal deps.
func isBinary(data []byte) bool {
	const probe = 4096
	n := len(data)
	if n > probe {
		n = probe
	}
	for i := 0; i < n; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

// --- filter helpers -------------------------------------------------------

// WantsInstallManifest reports whether name is a manifest the
// installscripts parsers understand. Mirrors the pre-refactor filter in
// provider_installscripts.go.
func WantsInstallManifest(name string) bool {
	base := strings.ToLower(path.Base(strings.TrimSpace(name)))
	switch base {
	case "package.json", "setup.py", "pyproject.toml",
		"cargo.toml", "build.rs", "composer.json":
		return true
	}
	return strings.HasSuffix(base, ".gemspec")
}

// WantsHiddenUnicodeText reports whether name has an extension the
// hidden-unicode scanner cares about. Mirrors wantsHiddenUnicodeText
// in the pre-refactor provider_hiddenunicode.go — changes here must be
// kept in sync with internal/hiddenunicode/scan.go sourceExtensions.
func WantsHiddenUnicodeText(name string) bool {
	ext := strings.ToLower(path.Ext(strings.TrimSpace(name)))
	switch ext {
	case ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
		".py", ".rb", ".rs", ".go", ".java", ".php", ".cs", ".cr", ".coffee",
		".md", ".txt", ".json", ".yaml", ".yml", ".toml",
		".xml", ".gemspec", ".nuspec", ".swift", ".kt", ".kts", ".gradle", ".scala":
		return true
	}
	return false
}

// WantsSourceCode returns true for files Wave-3 code-scanners will want
// to inspect. Preparatory filter — today only hiddenunicode consumes
// source text, but the eval/obfuscation detectors queued for Wave 3 use
// this same predicate. Kept intentionally narrower than
// WantsHiddenUnicodeText: excludes .md / .txt / config-like extensions.
func WantsSourceCode(name string) bool {
	ext := strings.ToLower(path.Ext(strings.TrimSpace(name)))
	_, ok := sourceExts[ext]
	return ok
}

// --- map-level helpers ----------------------------------------------------

// Select returns a submap of files for which want(name) is true. The
// returned map shares byte slices with the parent map — do not mutate.
func (m ArtifactFileMap) Select(want func(name string) bool) map[string][]byte {
	out := make(map[string][]byte, len(m)/4+1)
	for _, f := range m {
		if want(f.Path) {
			out[f.Path] = f.Bytes
		}
	}
	return out
}

// SelectLower is like Select but the returned map is keyed by the
// lower-cased path — convenient for the pre-refactor installscripts
// call sites that did firstMatch() lookups that way.
func (m ArtifactFileMap) SelectLower(want func(name string) bool) map[string][]byte {
	out := make(map[string][]byte, len(m)/4+1)
	for key, f := range m {
		if want(f.Path) {
			out[key] = f.Bytes
		}
	}
	return out
}

// SortedPaths returns the file paths in deterministic order. Handy for
// tests and any scanner that needs reproducible iteration.
func (m ArtifactFileMap) SortedPaths() []string {
	out := make([]string, 0, len(m))
	for _, f := range m {
		out = append(out, f.Path)
	}
	sort.Strings(out)
	return out
}
