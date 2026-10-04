package intelligence

import (
	"context"
	"path"
	"regexp"
	"sort"
	"strings"
)

// licenseFileProvider identifies the licence in a package's own top-level
// LICENSE / COPYING file. Registries are often silent where the bytes are
// not: pypi khoj-assistant 1.14.0 and npm @yancyyu/agentcli 1.9.33 declare
// no licence in their metadata and ship GPL/AGPL text at the package root.
//
// The fact is only CONSULTED when the manifest is empty or unidentified
// (projectLicenseFile): a declared licence always wins.
//
// TOP-LEVEL ONLY. A bundled dependency's licence (gollum's vendored ace and
// sizzle, a Go module's LICENSE under a sub-package) describes that
// dependency, not this package, and socket.dev firing copyleftLicense on
// those is its false positive, not a coverage gap.
type licenseFileProvider struct{}

func newLicenseFileProvider() *licenseFileProvider { return &licenseFileProvider{} }

func (p *licenseFileProvider) Name() string         { return "licensefile" }
func (p *licenseFileProvider) Signal() SignalMask   { return SignalLicenseFile }
func (p *licenseFileProvider) Tier() int            { return 2 }
func (p *licenseFileProvider) NeedsArtifact() bool  { return true }
func (p *licenseFileProvider) Supports(string) bool { return true }

// licenseFileAnalyzerVersion — bump when file selection or text
// identification changes what this reports for identical bytes.
//
// 2: several identified files are joined with OR instead of collapsing a
// permissive set to one id (Rust's LICENSE-MIT + LICENSE-APACHE now reads
// "Apache-2.0 OR MIT").
const licenseFileAnalyzerVersion = 2

func (p *licenseFileProvider) AnalyzerVersion() int { return licenseFileAnalyzerVersion }

// licenseFileMaxPaths bounds the recorded paths.
const licenseFileMaxPaths = 5

func (p *licenseFileProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if req.Artifact == nil || len(req.Artifact.Bytes) == 0 {
		return PartialReport{}, nil
	}
	files := req.Artifact.SharedArtifactMap().Files
	if len(files) == 0 {
		return PartialReport{}, nil
	}
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	root := commonDir(paths)
	var found []string
	var ids []string
	for _, f := range files {
		if !isTopLevelLicenseFile(f.Path, root) {
			continue
		}
		found = append(found, f.Path)
		if id := identifyLicenseText(f.Bytes); id != "" {
			ids = append(ids, id)
		}
	}
	// Nothing found writes nothing. That is the right answer even for a
	// truncated walk: absence is never reported as a fact here, so a walk
	// that stopped early cannot turn into "this package has no licence".
	if len(found) == 0 {
		return PartialReport{}, nil
	}
	sort.Strings(found)
	if len(found) > licenseFileMaxPaths {
		found = found[:licenseFileMaxPaths]
	}
	return PartialReport{Scan: &ArtifactScanSection{
		Performed:             true,
		LicenseFileExpression: combineLicenseFileIDs(ids),
		LicenseFilePaths:      found,
	}}, nil
}

// commonDir is the directory every path shares: npm's "package/", an sdist's
// "name-1.0/", a Go module zip's "example.com/m@v1.0.0/". "" when the
// archive has more than one top-level entry (wheels, jars, gems, nupkgs).
func commonDir(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	prefix := path.Dir(paths[0])
	for _, p := range paths[1:] {
		for prefix != "." && !strings.HasPrefix(p, prefix+"/") {
			prefix = path.Dir(prefix)
		}
		if prefix == "." {
			return ""
		}
	}
	if prefix == "." {
		return ""
	}
	return prefix
}

// licenseFileNameRe matches LICENSE, LICENCE, COPYING, COPYING.LESSER,
// UNLICENSE and their -MIT / .txt / .md variants, case-insensitively.
var licenseFileNameRe = regexp.MustCompile(`^(?:(?:un)?licen[cs]e|copying)(?:[-._][a-z0-9.-]+)?$`)

// licenseFileDocExts are the only extensions a licence file may carry; a
// license.js or license.json is code or data.
var licenseFileDocExts = map[string]bool{"": true, ".md": true, ".txt": true, ".rst": true, ".markdown": true,
	".lesser": true, ".lib": true, ".mit": true, ".apache": true, ".bsd": true, ".gpl": true, ".lgpl": true}

// isTopLevelLicenseFile: the file sits in the package root (the archive
// root, or the single directory every entry shares), or in the metadata
// directories that carry the package's own licence: a wheel's
// *.dist-info/ (and its PEP 639 licenses/ subdirectory) and a jar's
// META-INF/.
func isTopLevelLicenseFile(p, root string) bool {
	base := strings.ToLower(path.Base(p))
	if !licenseFileNameRe.MatchString(base) || strings.Contains(base, "third") {
		return false
	}
	if !licenseFileDocExts[path.Ext(base)] && !strings.HasPrefix(base, "license-") && !strings.HasPrefix(base, "licence-") {
		return false
	}
	dir := path.Dir(p)
	rel := dir
	if root != "" {
		if dir != root && !strings.HasPrefix(dir, root+"/") {
			return false
		}
		rel = strings.TrimPrefix(strings.TrimPrefix(dir, root), "/")
	} else if rel == "." {
		rel = ""
	}
	if rel == "" {
		return true
	}
	segs := strings.Split(strings.ToLower(rel), "/")
	switch {
	case len(segs) == 1 && (strings.HasSuffix(segs[0], ".dist-info") || segs[0] == "meta-inf"):
		return true
	case len(segs) == 2 && strings.HasSuffix(segs[0], ".dist-info") && segs[1] == "licenses":
		return true
	}
	return false
}

// licenseTextRules map a licence's own title or operative sentence to its
// SPDX id. Matched against the uppercased, whitespace-collapsed head of the
// file; the EARLIEST match wins, so GPL-3.0's closing pointer to "the GNU
// Lesser General Public License" and a later bundled-notice section cannot
// outrank the title on line one.
var licenseTextRules = []struct {
	phrase string
	id     func(head string) string
}{
	{"GNU AFFERO GENERAL PUBLIC LICENSE", func(string) string { return "AGPL-3.0-only" }},
	{"GNU LESSER GENERAL PUBLIC LICENSE", func(h string) string {
		if strings.Contains(h, "VERSION 2.1") {
			return "LGPL-2.1-only"
		}
		return "LGPL-3.0-only"
	}},
	{"GNU LIBRARY GENERAL PUBLIC LICENSE", func(string) string { return "LGPL-2.0-only" }},
	{"GNU GENERAL PUBLIC LICENSE", func(h string) string {
		if strings.Contains(h, "VERSION 2,") || strings.Contains(h, "VERSION 2 ") {
			return "GPL-2.0-only"
		}
		return "GPL-3.0-only"
	}},
	{"MOZILLA PUBLIC LICENSE", func(h string) string {
		if strings.Contains(h, "VERSION 1.1") {
			return "MPL-1.1"
		}
		return "MPL-2.0"
	}},
	{"ECLIPSE PUBLIC LICENSE", func(h string) string {
		if strings.Contains(h, "V 1.0") || strings.Contains(h, "VERSION 1.0") {
			return "EPL-1.0"
		}
		return "EPL-2.0"
	}},
	{"THE APACHE SOFTWARE LICENSE, VERSION 1.1", func(string) string { return "Apache-1.1" }},
	{"APACHE LICENSE", func(h string) string {
		if strings.Contains(h, "VERSION 2.0") {
			return "Apache-2.0"
		}
		return ""
	}},
	{"PERMISSION IS HEREBY GRANTED, FREE OF CHARGE, TO ANY PERSON OBTAINING A COPY", func(string) string { return "MIT" }},
	{"PERMISSION TO USE, COPY, MODIFY, AND/OR DISTRIBUTE THIS SOFTWARE FOR ANY PURPOSE", func(string) string { return "ISC" }},
	{"PERMISSION TO USE, COPY, MODIFY, AND DISTRIBUTE THIS SOFTWARE FOR ANY PURPOSE", func(string) string { return "ISC" }},
	{"REDISTRIBUTION AND USE IN SOURCE AND BINARY FORMS, WITH OR WITHOUT MODIFICATION, ARE PERMITTED", func(h string) string {
		if strings.Contains(h, "NEITHER THE NAME") || strings.Contains(h, "ENDORSE OR PROMOTE") {
			return "BSD-3-Clause"
		}
		return "BSD-2-Clause"
	}},
	{"THIS IS FREE AND UNENCUMBERED SOFTWARE RELEASED INTO THE PUBLIC DOMAIN", func(string) string { return "Unlicense" }},
}

// licenseTextHead bounds the scan: every rule's phrase sits in the first few
// hundred bytes of its licence, and a NOTICE-style appendix of bundled
// third-party licences sits after it.
const licenseTextHead = 4096

var whitespaceRe = regexp.MustCompile(`\s+`)

// licenseCommentRe strips a comment leader from each line: licences pasted
// into a source-style header ("// Redistribution and use ...", Apache 1.1's
// " * " block) would otherwise break every multi-line phrase.
var licenseCommentRe = regexp.MustCompile(`(?m)^[ \t]*(?:/\*+|\*+/?|//+|#+|;+|--)`)

// identifyLicenseText returns the SPDX id of a licence text, or "" when
// none of the rules match. ponytail: phrase rules, not a full SPDX text
// matcher — twelve families that decide the copyleft / permissive question;
// anything else is "present but unrecognised".
func identifyLicenseText(body []byte) string {
	if len(body) > licenseTextHead {
		body = body[:licenseTextHead]
	}
	head := strings.ToUpper(whitespaceRe.ReplaceAllString(licenseCommentRe.ReplaceAllString(string(body), ""), " "))
	best, bestAt := "", -1
	for _, r := range licenseTextRules {
		at := strings.Index(head, r.phrase)
		if at < 0 || (bestAt >= 0 && at >= bestAt) {
			continue
		}
		if id := r.id(head); id != "" {
			best, bestAt = id, at
		}
	}
	return best
}

// combineLicenseFileIDs turns the per-file ids into one expression.
//
// COPYING (GPL text) next to COPYING.LESSER is how an LGPL project ships —
// the LGPL is written as additional permissions on the GPL — so GPL is
// dropped when an LGPL file is present. Anything else is joined with OR,
// the conventional meaning of several top-level licence files, in sorted
// order so the same bytes always give the same expression. An OR of
// permissive licences (Rust's LICENSE-MIT + LICENSE-APACHE) does not fire
// license.ambiguous_classifier: risk.IsPermissiveChoice exempts it.
func combineLicenseFileIDs(ids []string) string {
	seen := map[string]bool{}
	var uniq []string
	hasLGPL := false
	for _, id := range ids {
		if strings.HasPrefix(id, "LGPL-") {
			hasLGPL = true
		}
	}
	for _, id := range ids {
		if seen[id] || (hasLGPL && strings.HasPrefix(id, "GPL-")) {
			continue
		}
		seen[id] = true
		uniq = append(uniq, id)
	}
	sort.Strings(uniq)
	return strings.Join(uniq, " OR ")
}

var _ Provider = (*licenseFileProvider)(nil)
