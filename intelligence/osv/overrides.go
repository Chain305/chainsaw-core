package osv

// overrides.go applies a short, hand-reviewed list of corrections to
// upstream advisory records at match time.
//
// It exists for records whose upstream shape is wrong for a coordinate in
// a way no general matcher rule can fix without breaking others. Each case
// was measured before it was added here: a general alias-clear rule would
// drop a true positive elsewhere, and a Go-only "GHSA wins" rule touches
// 1,079 open-ended pairs. A per-advisory entry changes exactly the
// coordinates it names and nothing else.
//
// Two kinds:
//
//	not_affected — the advisory is wrong for [introduced, fixed). A hit
//	               moves to the cleared bucket, so the provider's veto
//	               retracts a CVE an earlier scan stored.
//	notice       — the advisory is real but not a vulnerability of the
//	               package as a whole (GO-2026-5932: unsafe only for
//	               importers of one subpackage). It also moves to cleared,
//	               so it never feeds IsVulnerable, and Notices returns it
//	               so the provider can report it as information.
//
// STALENESS. Every entry records the exact upstream ranges it was
// reviewed against, and applies only while the live record still has
// them. When upstream edits the record, the override goes inert and the
// upstream answer wins. That is the safe direction: a stale override
// never suppresses a changed record. Index.StaleOverrides names the inert
// ones so the bundle load can log them.

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Override kinds.
const (
	OverrideNotAffected = "not_affected"
	OverrideNotice      = "notice"
)

// Override is one reviewed correction. See overrides.json.
type Override struct {
	Kind       string `json:"kind"`
	AdvisoryID string `json:"advisory_id"`
	Ecosystem  string `json:"ecosystem"`
	Package    string `json:"package"`
	// Introduced and Fixed bound the versions the override covers,
	// [Introduced, Fixed). "" or "0" for Introduced and "" for Fixed
	// mean unbounded.
	Introduced string   `json:"introduced"`
	Fixed      string   `json:"fixed,omitempty"`
	Reason     string   `json:"reason"`
	Evidence   []string `json:"evidence"`
	Reviewed   string   `json:"reviewed"`
	// UpstreamRanges is the advisory's vulnerable_ranges at review time.
	UpstreamRanges []VulnerableRange `json:"upstream_ranges"`
}

//go:embed overrides.json
var overridesJSON []byte

var overrides = mustParseOverrides(overridesJSON)

func mustParseOverrides(raw []byte) []Override {
	out, err := parseOverrides(raw)
	if err != nil {
		panic(err)
	}
	return out
}

func parseOverrides(raw []byte) ([]Override, error) {
	var out []Override
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("osv: parse overrides: %w", err)
	}
	for _, o := range out {
		switch {
		case o.Kind != OverrideNotAffected && o.Kind != OverrideNotice:
			return nil, fmt.Errorf("osv: override %s: unknown kind %q", o.AdvisoryID, o.Kind)
		case o.AdvisoryID == "", canonicalKey(o.Ecosystem, o.Package) == "",
			strings.TrimSpace(o.Reason) == "", len(o.Evidence) == 0,
			o.Reviewed == "", len(o.UpstreamRanges) == 0:
			return nil, fmt.Errorf("osv: override %q: every field is required", o.AdvisoryID)
		}
	}
	return out, nil
}

// overrideFor returns the override that applies to advisory a at version,
// or nil.
func overrideFor(a Advisory, version string) *Override {
	for i := range overrides {
		o := &overrides[i]
		if o.AdvisoryID != a.AdvisoryID ||
			canonicalKey(o.Ecosystem, o.Package) != canonicalKey(a.Ecosystem, a.Package) ||
			!slices.Equal(o.UpstreamRanges, a.VulnerableRanges) {
			continue
		}
		if o.Introduced != "" && o.Introduced != "0" {
			c, err := compareVersions(a.Ecosystem, version, o.Introduced)
			if err != nil || c < 0 {
				continue
			}
		}
		if o.Fixed != "" {
			c, err := compareVersions(a.Ecosystem, version, o.Fixed)
			if err != nil || c >= 0 {
				continue
			}
		}
		return o
	}
	return nil
}

// Notices returns the notice overrides that apply to (ecosystem, pkg,
// version): advisories that matched upstream and were moved to the cleared
// bucket as information rather than a vulnerability.
func (i *Index) Notices(ecosystem, pkg, version string) []Override {
	if i == nil {
		return nil
	}
	var out []Override
	for _, a := range i.byPackage[canonicalKey(ecosystem, pkg)] {
		if o := overrideFor(a, version); o != nil && o.Kind == OverrideNotice {
			if affects, _ := advisoryAffectsEx(a, version); affects {
				out = append(out, *o)
			}
		}
	}
	return out
}

// StaleOverrides returns the ids of overrides whose package this index
// carries but whose advisory is missing or no longer has the reviewed
// ranges. Those overrides are inert.
func (i *Index) StaleOverrides() []string {
	if i == nil {
		return nil
	}
	var out []string
	for _, o := range overrides {
		candidates, ok := i.byPackage[canonicalKey(o.Ecosystem, o.Package)]
		if !ok {
			continue
		}
		if !slices.ContainsFunc(candidates, func(a Advisory) bool {
			return a.AdvisoryID == o.AdvisoryID && slices.Equal(a.VulnerableRanges, o.UpstreamRanges)
		}) {
			out = append(out, o.AdvisoryID)
		}
	}
	return out
}
