package intelligence

// hiddenUnicodeProvider wraps hiddenunicode.Scan. It is Tier-2 because it
// operates on the raw artifact bytes (text files extracted from the
// archive). The wrapped detector is pure.
//
// Wave 0a: archive walk is consolidated via
// ArtifactHandle.SharedArtifactMap so this provider shares one
// decompression pass with installscripts (and with the Wave-3 scanners
// scheduled to land next).

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/codesmell"
	"github.com/chain305/chainsaw-core/hiddenunicode"
	"github.com/chain305/chainsaw-core/intelligence/artifactmap"
)

// hiddenUnicodeProvider holds no state — the detector is a pure function
// over a file map.
type hiddenUnicodeProvider struct{}

func newHiddenUnicodeProvider() *hiddenUnicodeProvider {
	return &hiddenUnicodeProvider{}
}

func (p *hiddenUnicodeProvider) Name() string { return "hiddenunicode" }

func (p *hiddenUnicodeProvider) Signal() SignalMask { return SignalHiddenUnicode }

func (p *hiddenUnicodeProvider) Tier() int { return 2 }

// NeedsArtifact: true — the scanner is only meaningful when we have text
// files to inspect.
func (p *hiddenUnicodeProvider) NeedsArtifact() bool { return true }

// supportedHiddenUnicodeEcosystems is the text-file ecosystem whitelist per
// POLICY_PROXY_MATRIX.md. HuggingFace is warn-tier (text files only) but we
// include it so a repo config that sends us a model-card .md still lights
// up. Docker / apt / yum / dnf are excluded: those are binary-only.
var supportedHiddenUnicodeEcosystems = map[string]struct{}{
	"npm":         {},
	"yarn":        {},
	"bun":         {},
	"pip":         {},
	"pypi":        {},
	"rubygems":    {},
	"cargo":       {},
	"composer":    {},
	"go":          {},
	"gomod":       {},
	"nuget":       {},
	"maven":       {},
	"gradle":      {},
	"swift":       {},
	"cocoapods":   {},
	"huggingface": {},
}

func (p *hiddenUnicodeProvider) Supports(ecosystem string) bool {
	_, ok := supportedHiddenUnicodeEcosystems[strings.ToLower(strings.TrimSpace(ecosystem))]
	return ok
}

// Run pulls every text-ish file out of the artifact archive, hands them to
// hiddenunicode.Scan, and translates the Result into an ArtifactScanSection.
func (p *hiddenUnicodeProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if req.Artifact == nil || len(req.Artifact.Bytes) == 0 {
		return PartialReport{}, nil
	}

	files := textFilesFor(req.Artifact)
	if len(files) == 0 {
		// Empty archive or no text files — emit a "performed but clean"
		// section so consumers can distinguish from "never scanned".
		return PartialReport{Scan: &ArtifactScanSection{Performed: true}}, nil
	}

	result := hiddenunicode.Scan(files)
	suppressed := suppressI18nBidi(&result)

	scan := &ArtifactScanSection{
		Performed:          true,
		HiddenUnicodeHits:  result.Hits,
		HiddenUnicodeKinds: result.Kinds,
	}

	partial := PartialReport{Scan: scan}
	if suppressed > 0 {
		partial.Warnings = append(partial.Warnings, Warning{
			Provider: p.Name(),
			Code:     WarnHiddenUnicodeI18nSuppressed,
			Message:  fmt.Sprintf("%d bidi-override hits in i18n files suppressed", suppressed),
			At:       time.Now().UTC(),
		})
	}
	return partial, nil
}

// WarnHiddenUnicodeI18nSuppressed is emitted when context-aware filtering
// drops bidi-override hits found in known-i18n locations. Always-suspicious
// kinds (zero_width, tag) are NEVER suppressed even in i18n files — those
// remain the steganography attack vector.
const WarnHiddenUnicodeI18nSuppressed = "hidden_unicode_i18n_suppressed"

// suppressI18nBidi mutates result in place to drop bidi_override hits found
// in i18n-context files (translation catalogs, locale resources, message
// bundles). Returns the count of suppressed hits.
//
// Rule (per-hit predicate):
//
//	suppress  iff  codesmell.IsLikelyI18nFile(path)
//	            && hit.Kind == hiddenunicode.KindBidiOverride
//
// zero_width and tag hits are NEVER suppressed under any path — those are
// the steganography vector and one occurrence is a real attack signal.
//
// After filtering the per-file map, the aggregate Hits count and Kinds set
// are recomputed from the surviving hits so downstream consumers see only
// the post-suppression state.
func suppressI18nBidi(r *hiddenunicode.Result) int {
	if r == nil || len(r.PerFile) == 0 {
		return 0
	}
	var suppressed int
	kinds := make(map[string]struct{})
	totalHits := 0

	for path, hits := range r.PerFile {
		if !codesmell.IsLikelyI18nFile(path) {
			for _, h := range hits {
				kinds[h.Kind] = struct{}{}
			}
			totalHits += len(hits)
			continue
		}
		// i18n file: keep only always-suspicious kinds.
		kept := hits[:0:0]
		for _, h := range hits {
			if h.Kind == hiddenunicode.KindBidiOverride {
				suppressed++
				continue
			}
			kept = append(kept, h)
			kinds[h.Kind] = struct{}{}
		}
		if len(kept) == 0 {
			delete(r.PerFile, path)
			continue
		}
		r.PerFile[path] = kept
		totalHits += len(kept)
	}

	r.Hits = totalHits
	if len(kinds) == 0 {
		r.Kinds = nil
	} else {
		r.Kinds = r.Kinds[:0]
		for k := range kinds {
			r.Kinds = append(r.Kinds, k)
		}
		sort.Strings(r.Kinds)
	}
	return suppressed
}

var _ Provider = (*hiddenUnicodeProvider)(nil)

// textFilesFor returns the hiddenunicode text-file subset of the shared
// artifact map. Keys are lower-cased to match the pre-refactor walker's
// behaviour — hiddenunicode.Scan sorts its input lexicographically and
// surfaces keys verbatim in Result.PerFile, so preserving the legacy
// casing convention keeps Scan output bit-identical.
func textFilesFor(h *ArtifactHandle) map[string][]byte {
	res := h.SharedArtifactMap()
	if len(res.Files) == 0 {
		return legacyWalkHiddenUnicodeText(h)
	}
	return res.Files.SelectLower(artifactmap.WantsHiddenUnicodeText)
}
