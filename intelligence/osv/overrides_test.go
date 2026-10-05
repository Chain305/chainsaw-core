package osv

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// testdata/overrides_records.json is the seven grpc and x/crypto records
// the overrides reason about, copied verbatim from the OSV bundle of
// 2026-10-04 (322,316 records).

func loadOverrideRecords(t *testing.T) []Advisory {
	t.Helper()
	raw, err := os.ReadFile("testdata/overrides_records.json")
	if err != nil {
		t.Fatal(err)
	}
	var advs []Advisory
	if err := json.Unmarshal(raw, &advs); err != nil {
		t.Fatal(err)
	}
	return advs
}

func indexOf(t *testing.T, advs []Advisory) *Index {
	t.Helper()
	raw, err := json.Marshal(advs)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := Load(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

func ids(advs []Advisory) []string {
	out := make([]string, 0, len(advs))
	for _, a := range advs {
		out = append(out, a.AdvisoryID)
	}
	return out
}

func TestOverrides_FileHasTheReviewedEntries(t *testing.T) {
	got := map[string]string{}
	for _, o := range overrides {
		got[o.AdvisoryID] = o.Kind
	}
	want := map[string]string{
		"GO-2026-6443": OverrideNotAffected,
		"GO-2026-5932": OverrideNotice,
	}
	if len(got) != len(want) {
		t.Fatalf("overrides = %v, want %v", got, want)
	}
	for id, kind := range want {
		if got[id] != kind {
			t.Errorf("override %s kind = %q, want %q", id, got[id], kind)
		}
	}
}

func TestOverrides_ParseRejectsIncompleteEntries(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown kind": `[{"kind":"ignore","advisory_id":"X","ecosystem":"Go","package":"p","reason":"r","evidence":["u"],"reviewed":"d","upstream_ranges":[{"introduced":"0"}]}]`,
		"no evidence":  `[{"kind":"notice","advisory_id":"X","ecosystem":"Go","package":"p","reason":"r","reviewed":"d","upstream_ranges":[{"introduced":"0"}]}]`,
		"no shape":     `[{"kind":"notice","advisory_id":"X","ecosystem":"Go","package":"p","reason":"r","evidence":["u"],"reviewed":"d"}]`,
	} {
		if _, err := parseOverrides([]byte(raw)); err == nil {
			t.Errorf("%s: parse accepted it", name)
		}
	}
}

// Fixtures for the four cases the override was specified against, plus
// the bounds around them.
func TestOverrides_Fixtures(t *testing.T) {
	idx := indexOf(t, loadOverrideRecords(t))
	const grpc, crypto = "google.golang.org/grpc", "golang.org/x/crypto"
	cases := []struct {
		name, pkg, ver string
		hits           []string
		notices        []string
	}{
		// GO-2026-6443 claims all of 1.84; GHSA records the 1.84-line fix
		// before v1.84.0.
		{"grpc v1.84.0 clean", grpc, "v1.84.0", nil, nil},
		{"grpc v1.84.3 clean", grpc, "v1.84.3", nil, nil},
		// Outside the override's range: untouched.
		{"grpc v1.82.1", grpc, "v1.82.1", []string{"GHSA-2v4p-qf9q-27wj", "GO-2026-6443"}, nil},
		// x/crypto: the openpgp notice is information, never a hit.
		{"x/crypto v0.57.0 note only", crypto, "v0.57.0", nil, []string{"GO-2026-5932"}},
		// A real x/crypto/ssh CVE (Terrapin, GO-2023-2402) still fires.
		{"x/crypto v0.16.0 terrapin", crypto, "v0.16.0", []string{"GO-2023-2402"}, []string{"GO-2026-5932"}},
	}
	for _, c := range cases {
		hits, cleared, undecided := idx.LookupEx("go", c.pkg, c.ver)
		got := ids(hits)
		slices.Sort(got)
		if !slices.Equal(got, c.hits) {
			t.Errorf("%s: hits = %v, want %v", c.name, got, c.hits)
		}
		if len(undecided) != 0 {
			t.Errorf("%s: undecidable = %v", c.name, ids(undecided))
		}
		var notes []string
		for _, n := range idx.Notices("go", c.pkg, c.ver) {
			notes = append(notes, n.AdvisoryID)
		}
		if !slices.Equal(notes, c.notices) {
			t.Errorf("%s: notices = %v, want %v", c.name, notes, c.notices)
		}
		// An overridden hit must land in cleared, not vanish: the veto
		// is what retracts a stored copy.
		for _, id := range c.notices {
			if !slices.Contains(ids(cleared), id) {
				t.Errorf("%s: %s not in cleared %v", c.name, id, ids(cleared))
			}
		}
		if c.pkg == grpc && c.hits == nil && !slices.Contains(ids(cleared), "GO-2026-6443") {
			t.Errorf("%s: GO-2026-6443 not in cleared %v", c.name, ids(cleared))
		}
	}
}

// The override covers released 1.84.x only. Development pseudo-versions
// before either line's fix stay affected, so the override must not match
// them. TestLookup_GRPCDevLinesAroundTheFix checks the same coordinates
// end to end through LookupEx.
func TestOverrides_DoNotCoverPreFixDevLines(t *testing.T) {
	var rec Advisory
	for _, a := range loadOverrideRecords(t) {
		if a.AdvisoryID == "GO-2026-6443" {
			rec = a
		}
	}
	for _, v := range []string{
		"v1.85.0-dev.0.20260801000000-aaaaaaaaaaaa", // 1.85 line, before 93e31b48545e
		"v1.84.0-dev.0.20260801000000-aaaaaaaaaaaa", // 1.84 line, before d5a41119e0e3
		"v1.84.0-dev",
		"v1.85.0-dev",
		"v1.84.0-rc.1",
	} {
		if o := overrideFor(rec, v); o != nil {
			t.Errorf("override %s applies to %s; it must cover released 1.84.x only", o.AdvisoryID, v)
		}
	}
	for _, v := range []string{"v1.84.0", "v1.84.3"} {
		if overrideFor(rec, v) == nil {
			t.Errorf("override does not apply to %s", v)
		}
	}
}

// Staleness guard, one subtest per entry. Each override names the exact
// upstream ranges it was reviewed against. When upstream edits them, the
// override must go inert (the upstream answer wins) and StaleOverrides
// must name it, which the bundle load logs.
func TestOverrides_GoInertWhenUpstreamChanges(t *testing.T) {
	records := loadOverrideRecords(t)
	if stale := indexOf(t, records).StaleOverrides(); len(stale) != 0 {
		t.Fatalf("StaleOverrides on the reviewed records = %v, want none", stale)
	}
	probes := map[string]struct{ pkg, ver string }{
		"GO-2026-6443": {"google.golang.org/grpc", "v1.84.0"},
		"GO-2026-5932": {"golang.org/x/crypto", "v0.57.0"},
	}
	for _, o := range overrides {
		t.Run(o.AdvisoryID, func(t *testing.T) {
			probe, ok := probes[o.AdvisoryID]
			if !ok {
				t.Fatalf("no probe for override %s: add one", o.AdvisoryID)
			}
			changed := slices.Clone(records)
			found := false
			for i, a := range changed {
				if a.AdvisoryID == o.AdvisoryID {
					// Upstream adds a range; any edit must do.
					a.VulnerableRanges = append(slices.Clone(a.VulnerableRanges),
						VulnerableRange{Introduced: "99.0.0", Fixed: "99.0.1"})
					changed[i] = a
					found = true
				}
			}
			if !found {
				t.Fatalf("snapshot has no record for %s", o.AdvisoryID)
			}
			idx := indexOf(t, changed)
			if stale := idx.StaleOverrides(); !slices.Equal(stale, []string{o.AdvisoryID}) {
				t.Errorf("StaleOverrides = %v, want [%s]", stale, o.AdvisoryID)
			}
			hits, _, _ := idx.LookupEx("go", probe.pkg, probe.ver)
			if !slices.Contains(ids(hits), o.AdvisoryID) {
				t.Errorf("changed record: %s at %s not a hit (%v); a stale override must not suppress it",
					o.AdvisoryID, probe.ver, ids(hits))
			}
			if n := idx.Notices("go", probe.pkg, probe.ver); len(n) != 0 {
				t.Errorf("changed record: notices = %v, want none", n)
			}
		})
	}
}

// Against a real bundle. CI has no bundle (prod fetches it at build and
// refreshes it daily), so this is opt-in; the runtime check above is the
// guard that binds in prod.
func TestOverrides_MatchLiveBundle(t *testing.T) {
	path := os.Getenv("CHAINSAW_OSV_BUNDLE_PATH")
	if path == "" {
		t.Skip("set CHAINSAW_OSV_BUNDLE_PATH=<osv-bundle.json.gz> to check the overrides against a real bundle")
	}
	idx, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range overrides {
		if !idx.HasPackage(o.Ecosystem, o.Package) {
			t.Errorf("bundle has no %s %s; override %s cannot be checked", o.Ecosystem, o.Package, o.AdvisoryID)
		}
	}
	if stale := idx.StaleOverrides(); len(stale) != 0 {
		t.Errorf("overrides inert against this bundle (upstream record changed): %v", stale)
	}
}
