package osv

import (
	"slices"
	"testing"
)

// SemVer 2.0 prerelease precedence, through the comparator the matcher
// uses for npm, Go and Cargo. Before the fix parseSemver cut every string
// at its third dot, so a dotted prerelease kept only its first
// identifier: beta.2 == beta.10, and every Go pseudo-version on a
// prerelease line compared equal to the line's fix bound.
func TestCompareVersions_DottedPrerelease(t *testing.T) {
	cases := []struct {
		eco, a, b string
		want      int
	}{
		// numeric identifiers compare numerically
		{"npm", "1.0.0-beta.2", "1.0.0-beta.10", -1},
		{"npm", "1.0.0-beta.10", "1.0.0-beta.2", 1},
		{"npm", "1.0.0-alpha.1", "1.0.0-alpha.1", 0},
		// alphanumeric identifiers compare lexically
		{"npm", "1.0.0-alpha.beta", "1.0.0-alpha.gamma", -1},
		// numeric sorts below alphanumeric
		{"npm", "1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		// a shorter list sorts below a longer one with the same prefix
		{"npm", "1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"crates.io", "0.10.0-alpha.1", "0.10.0-alpha.2", -1},
		{"crates.io", "0.10.0-alpha.5", "0.10.0-alpha.2", 1},
		// prerelease below its release; build metadata ignored
		{"npm", "1.0.0-rc.1", "1.0.0", -1},
		{"npm", "1.0.0+build.1.2", "1.0.0+build.9.9", 0},
		// Go pseudo-versions: the timestamp identifier orders them
		{"Go", "v1.85.0-dev.0.20260801000000-aaaaaaaaaaaa", "1.85.0-dev.0.20260825072537-93e31b48545e", -1},
		{"Go", "v1.85.0-dev.0.20260901000000-bbbbbbbbbbbb", "1.85.0-dev.0.20260825072537-93e31b48545e", 1},
		{"Go", "v1.85.0-dev.0.20260801000000-aaaaaaaaaaaa", "1.85.0-dev", 1},
		{"Go", "v1.2.4-0.20230101000000-aaaaaaaaaaaa", "1.2.4-0.20240101000000-bbbbbbbbbbbb", -1},
		// a 4-segment npm core still drops its fourth segment, and now keeps
		// the prerelease that follows it
		{"npm", "1.2.3.4", "1.2.3", 0},
		{"npm", "1.2.3.4-beta.2", "1.2.3-beta.10", -1},
	}
	for _, c := range cases {
		got, err := compareVersions(c.eco, c.a, c.b)
		if err != nil {
			t.Errorf("%s %s vs %s: %v", c.eco, c.a, c.b, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s %s vs %s = %d, want %d", c.eco, c.a, c.b, got, c.want)
		}
	}
}

// The grpc dev lines, on the real records: affected before each line's
// fix, clean after it.
func TestLookup_GRPCDevLinesAroundTheFix(t *testing.T) {
	idx := indexOf(t, loadOverrideRecords(t))
	const grpc = "google.golang.org/grpc"
	cases := []struct {
		name, ver string
		hits      []string
	}{
		{"1.85 line before 93e31b48545e", "v1.85.0-dev.0.20260801000000-aaaaaaaaaaaa",
			[]string{"GHSA-2v4p-qf9q-27wj", "GO-2026-6443"}},
		{"1.85 line after 93e31b48545e", "v1.85.0-dev.0.20260901000000-bbbbbbbbbbbb", nil},
		{"1.84 line before d5a41119e0e3", "v1.84.0-dev.0.20260801000000-aaaaaaaaaaaa",
			[]string{"GHSA-2v4p-qf9q-27wj", "GO-2026-6443"}},
		// GHSA clears it. GO-2026-6443 still claims it: its merged range
		// runs to the 1.85 fix, and the override covers released 1.84.x
		// only.
		{"1.84 line after d5a41119e0e3", "v1.84.0-dev.0.20260901000000-bbbbbbbbbbbb",
			[]string{"GO-2026-6443"}},
	}
	for _, c := range cases {
		hits, _, und := idx.LookupEx("go", grpc, c.ver)
		got := ids(hits)
		slices.Sort(got)
		if !slices.Equal(got, c.hits) || len(und) != 0 {
			t.Errorf("%s (%s): hits = %v undecidable = %v, want %v", c.name, c.ver, got, ids(und), c.hits)
		}
	}
}
