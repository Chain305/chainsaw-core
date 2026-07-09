package intelligence

// pypiManifestConfusionProvider compares PyPI's registry-side info{}
// JSON view against the ground-truth metadata shipped inside the
// distribution itself. Same threat model as the npm manifest-confusion
// provider: a publisher (or a compromised credential) can edit
// registry-side fields after upload, leaving the static-review picture
// out of sync with what `pip install` actually consumes from PKG-INFO /
// pyproject.toml [project] inside the sdist.
//
// Tarball-side priority:
//  1. PKG-INFO at the archive root (RFC822 / PEP 643). Sdists always
//     ship one; wheels ship METADATA under <name>-<ver>.dist-info/.
//  2. pyproject.toml [project] table — fallback when PKG-INFO is
//     malformed or absent (rare).
//  3. setup.py / setup.cfg are NOT parsed here — setup.py is arbitrary
//     Python and statically extracting fields is unreliable. Best-effort
//     would create false positives; we'd rather stay silent.
//
// Comparable fields (intersection of what registry info{} exposes and
// what PKG-INFO / pyproject reliably carry):
//   - name (PEP 503 normalized: lowercase, [._-]+ → "-")
//   - version (string-equal after trim)
//   - requires_python
//   - requires_dist (set comparison after light normalization)
//   - summary (presence)
//   - home_page (presence)
//   - project_urls (key-set)
//
// Entry points / console_scripts are NOT compared: the PyPI JSON
// info{} block does not expose them, so a registry-vs-tarball diff is
// impossible without the dist-info METADATA file and that lives only
// on the tarball side. Wheel coverage is intentionally limited — sdist
// is the priority per the task spec; for wheels we still attempt the
// dist-info METADATA path because the parser for PKG-INFO and METADATA
// is identical (both RFC822). No setup.py / setup.cfg coverage.
//
// Zero new network calls: registry JSON arrives via
// Request.RegistryMetadataBytes; archive bytes come from the shared
// artifact map.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"path"
	"sort"
	"strings"

	"github.com/chain305/chainsaw-core/intelligence/artifactmap"
)

type pypiManifestConfusionProvider struct{}

func newPyPIManifestConfusionProvider() *pypiManifestConfusionProvider {
	return &pypiManifestConfusionProvider{}
}

func (p *pypiManifestConfusionProvider) Name() string        { return "manifestconfusion-pypi" }
func (p *pypiManifestConfusionProvider) Signal() SignalMask  { return SignalManifestConfusion }
func (p *pypiManifestConfusionProvider) Tier() int           { return 2 }
func (p *pypiManifestConfusionProvider) NeedsArtifact() bool { return true }

func (p *pypiManifestConfusionProvider) Supports(eco string) bool {
	e := strings.ToLower(strings.TrimSpace(eco))
	return e == "pip" || e == "pypi"
}

func (p *pypiManifestConfusionProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if req.Artifact == nil || len(req.Artifact.Bytes) == 0 {
		return PartialReport{}, nil
	}
	if len(req.RegistryMetadataBytes) == 0 {
		return PartialReport{}, nil
	}
	res := req.Artifact.SharedArtifactMap()
	pkgInfo := pickPyPIDistMetadata(res.Files)
	if len(pkgInfo) == 0 {
		// No PKG-INFO / METADATA. Skip pyproject.toml fallback unless
		// PKG-INFO is truly absent; sdists almost always ship one.
		pkgInfo = firstMatchByBase(res.Files, "pyproject.toml")
		if len(pkgInfo) == 0 {
			return PartialReport{}, nil
		}
	}
	divergent := ComparePyPIManifests(req.RegistryMetadataBytes, pkgInfo)
	if len(divergent) == 0 {
		return PartialReport{}, nil
	}
	return PartialReport{Scan: &ArtifactScanSection{
		Performed:               true,
		ManifestConfusion:       true,
		ManifestConfusionFields: divergent,
	}}, nil
}

var _ Provider = (*pypiManifestConfusionProvider)(nil)

// pickPyPIDistMetadata returns the bytes of the most authoritative
// metadata file in the archive. Preference order:
//  1. PKG-INFO at the archive root (basename PKG-INFO).
//  2. METADATA inside a .dist-info/ directory (wheel).
func pickPyPIDistMetadata(files artifactmap.ArtifactFileMap) []byte {
	// First pass: PKG-INFO basename match.
	if b := firstMatchByBase(files, "PKG-INFO"); len(b) > 0 {
		return b
	}
	// Second pass: <name>-<ver>.dist-info/METADATA from a wheel.
	for _, f := range files {
		lower := strings.ToLower(f.Path)
		if strings.HasSuffix(lower, ".dist-info/metadata") || strings.HasSuffix(lower, ".dist-info\\metadata") {
			return f.Bytes
		}
	}
	return nil
}

func firstMatchByBase(files artifactmap.ArtifactFileMap, basename string) []byte {
	want := strings.ToLower(basename)
	for _, f := range files {
		if strings.ToLower(path.Base(f.Path)) == want {
			return f.Bytes
		}
	}
	return nil
}

// ComparePyPIManifests is the pure core of the provider — exported
// for tests. registryJSON is the body of pypi.org/pypi/<pkg>/<ver>/json.
// distMetadata is PKG-INFO (or wheel METADATA / pyproject.toml as a
// best-effort fallback). Returns the sorted list of fields that disagree.
func ComparePyPIManifests(registryJSON, distMetadata []byte) []string {
	type pypiInfo struct {
		Name           string            `json:"name"`
		Version        string            `json:"version"`
		Summary        string            `json:"summary"`
		HomePage       string            `json:"home_page"`
		RequiresPython string            `json:"requires_python"`
		RequiresDist   []string          `json:"requires_dist"`
		ProjectURLs    map[string]string `json:"project_urls"`
	}
	var root struct {
		Info pypiInfo `json:"info"`
	}
	if err := json.Unmarshal(registryJSON, &root); err != nil {
		// Allow callers to pass a bare info{} object directly.
		var bare pypiInfo
		if err2 := json.Unmarshal(registryJSON, &bare); err2 != nil {
			return nil
		}
		root.Info = bare
	}
	reg := root.Info

	tar := parsePyPIDistMetadata(distMetadata)
	if tar == nil {
		return nil
	}

	var diffs []string
	if pep503Name(reg.Name) != pep503Name(tar.Name) {
		diffs = append(diffs, "name")
	}
	if strings.TrimSpace(reg.Version) != strings.TrimSpace(tar.Version) {
		diffs = append(diffs, "version")
	}
	if strings.TrimSpace(reg.RequiresPython) != strings.TrimSpace(tar.RequiresPython) {
		diffs = append(diffs, "requires_python")
	}
	if !sameRequiresDist(reg.RequiresDist, tar.RequiresDist) {
		diffs = append(diffs, "requires_dist")
	}
	// Presence-only checks: comparing full text false-fires too often
	// (PyPI rewraps Description, Summary truncates, etc.).
	if (strings.TrimSpace(reg.Summary) == "") != (strings.TrimSpace(tar.Summary) == "") {
		diffs = append(diffs, "summary")
	}
	if (strings.TrimSpace(reg.HomePage) == "") != (strings.TrimSpace(tar.HomePage) == "") {
		diffs = append(diffs, "home_page")
	}
	if !sameStringSet(projectURLKeys(reg.ProjectURLs), projectURLKeys(tar.ProjectURLs)) {
		diffs = append(diffs, "project_urls")
	}
	sort.Strings(diffs)
	return diffs
}

// pyDistMetadata is the parsed view of PKG-INFO / METADATA / pyproject.
type pyDistMetadata struct {
	Name           string
	Version        string
	Summary        string
	HomePage       string
	RequiresPython string
	RequiresDist   []string
	ProjectURLs    map[string]string
}

// parsePyPIDistMetadata routes to the RFC822 parser for PKG-INFO /
// METADATA, falling back to a tiny pyproject.toml [project] reader if
// the input doesn't look like RFC822 headers (no "Metadata-Version:"
// or "Name:" line near the top).
func parsePyPIDistMetadata(b []byte) *pyDistMetadata {
	if looksLikeRFC822(b) {
		return parseRFC822Metadata(b)
	}
	return parsePyProjectFallback(b)
}

func looksLikeRFC822(b []byte) bool {
	// Quick sniff: one of the first ~10 lines starts with a known
	// PKG-INFO header.
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for i := 0; i < 20 && sc.Scan(); i++ {
		line := sc.Text()
		if strings.HasPrefix(line, "Metadata-Version:") ||
			strings.HasPrefix(line, "Name:") ||
			strings.HasPrefix(line, "Version:") {
			return true
		}
	}
	return false
}

// parseRFC822Metadata reads PKG-INFO / METADATA. Multi-line continuation
// (a header value can wrap across lines if the continuation is indented
// with whitespace) is folded back. The Description body — everything
// after the first blank line — is captured separately and used only for
// presence detection.
func parseRFC822Metadata(b []byte) *pyDistMetadata {
	out := &pyDistMetadata{ProjectURLs: map[string]string{}}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var lastKey, lastVal string
	flush := func() {
		if lastKey == "" {
			return
		}
		key := strings.ToLower(lastKey)
		val := strings.TrimSpace(lastVal)
		switch key {
		case "name":
			out.Name = val
		case "version":
			out.Version = val
		case "summary":
			out.Summary = val
		case "home-page":
			out.HomePage = val
		case "requires-python":
			out.RequiresPython = val
		case "requires-dist":
			if val != "" {
				out.RequiresDist = append(out.RequiresDist, val)
			}
		case "project-url":
			// "Label, https://..." form per PEP 621.
			if i := strings.Index(val, ","); i >= 0 {
				label := strings.TrimSpace(val[:i])
				url := strings.TrimSpace(val[i+1:])
				out.ProjectURLs[label] = url
			}
		}
		lastKey, lastVal = "", ""
	}
	inBody := false
	for sc.Scan() {
		line := sc.Text()
		if inBody {
			if strings.TrimSpace(line) != "" && out.Summary == "" {
				// Description body content acts as fallback "summary"
				// for presence-only purposes; explicit Summary header
				// already captured above wins.
			}
			continue
		}
		if line == "" {
			flush()
			inBody = true
			continue
		}
		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && lastKey != "" {
			// Continuation line.
			lastVal += " " + strings.TrimSpace(line)
			continue
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		flush()
		lastKey = strings.TrimSpace(line[:idx])
		lastVal = strings.TrimSpace(line[idx+1:])
	}
	flush()
	return out
}

// parsePyProjectFallback is a hand-rolled scanner that pulls just the
// fields we care about from a pyproject.toml [project] table. We avoid
// pulling go-toml in here because the codebase lists it as an indirect
// dependency only and a full parse is overkill for six string fields.
// Limitations: comments inside a value, escaped quotes, and inline
// arrays-of-tables are not handled — we accept "good enough" because
// pyproject.toml falls back behind PKG-INFO and is rarely the only
// metadata source in a sdist.
func parsePyProjectFallback(b []byte) *pyDistMetadata {
	out := &pyDistMetadata{ProjectURLs: map[string]string{}}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	section := ""
	var inDeps bool
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			inDeps = false
			continue
		}
		if section == "project" {
			if k, v, ok := splitTOMLPair(line); ok {
				switch k {
				case "name":
					out.Name = v
				case "version":
					out.Version = v
				case "description":
					out.Summary = v
				case "requires-python":
					out.RequiresPython = v
				case "dependencies":
					if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
						out.RequiresDist = parseTOMLStringArray(v)
					} else if v == "[" {
						inDeps = true
					}
				}
			} else if inDeps {
				if line == "]" {
					inDeps = false
					continue
				}
				if s, ok := stripTOMLString(strings.TrimSuffix(line, ",")); ok {
					out.RequiresDist = append(out.RequiresDist, s)
				}
			}
		}
		if section == "project.urls" {
			if k, v, ok := splitTOMLPair(line); ok {
				out.ProjectURLs[k] = v
				if strings.EqualFold(k, "homepage") || strings.EqualFold(k, "home-page") {
					out.HomePage = v
				}
			}
		}
	}
	return out
}

func splitTOMLPair(line string) (string, string, bool) {
	idx := strings.Index(line, "=")
	if idx <= 0 {
		return "", "", false
	}
	k := strings.TrimSpace(line[:idx])
	v := strings.TrimSpace(line[idx+1:])
	if s, ok := stripTOMLString(v); ok {
		return k, s, true
	}
	return k, v, true
}

func stripTOMLString(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1], true
	}
	return v, false
}

func parseTOMLStringArray(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "[")
	v = strings.TrimSuffix(v, "]")
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s, ok := stripTOMLString(strings.TrimSpace(p)); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// pep503Name normalizes a project name per PEP 503: lowercase, then
// collapse runs of [._-] to a single "-".
func pep503Name(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	b.Grow(len(s))
	prevDash := false
	for _, r := range s {
		if r == '_' || r == '.' || r == '-' {
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
			continue
		}
		b.WriteRune(r)
		prevDash = false
	}
	return strings.Trim(b.String(), "-")
}

// sameRequiresDist compares two dependency lists as a normalized set —
// whitespace and key order don't matter, but a real addition or removal
// of a requirement does.
func sameRequiresDist(a, b []string) bool {
	return sameStringSet(normalizeRequiresDist(a), normalizeRequiresDist(b))
}

func normalizeRequiresDist(in []string) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		s := strings.TrimSpace(r)
		if s == "" {
			continue
		}
		// Collapse all whitespace so "foo>=1" and "foo >= 1" match.
		// PEP 508 allows arbitrary whitespace around operators; the
		// only semantic content is the non-whitespace tokens.
		s = strings.Join(strings.Fields(s), "")
		out = append(out, s)
	}
	return out
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func projectURLKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, strings.ToLower(strings.TrimSpace(k)))
	}
	return out
}
