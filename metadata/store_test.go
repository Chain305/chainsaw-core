package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
	"github.com/chain305/chainsaw-core/tenancy"
)

// openTestStore skip-gates on CHAINSAW_DATABASE_URL, matching the pattern
// used elsewhere in the tree (server_test.go, pgstore/store_test.go).
func openTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping metadata DB test")
	}
	pg, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { pg.Close() })
	store, err := NewStore(pg)
	if err != nil {
		t.Fatalf("new metadata store: %v", err)
	}
	return store.ForOrg(tenancy.DefaultOrgID)
}

// TestSetPackageMetadataYankedRoundTrip verifies the new yanked column
// persists on insert and is readable on re-fetch — both for true and false.
func TestSetPackageMetadataYankedRoundTrip(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC()
	pkg := "pkg-yanked-roundtrip-" + now.Format("20060102150405.000000000")

	for _, yanked := range []bool{true, false} {
		meta := PackageMetadata{
			Repository: "npm",
			Package:    pkg,
			Version:    "1.0.0",
			Yanked:     yanked,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := s.SetPackageMetadata(meta); err != nil {
			t.Fatalf("SetPackageMetadata yanked=%v: %v", yanked, err)
		}
		got, err := s.GetPackageMetadata("npm", pkg, "1.0.0")
		if err != nil {
			t.Fatalf("GetPackageMetadata yanked=%v: %v", yanked, err)
		}
		if got.Yanked != yanked {
			t.Errorf("yanked round-trip: got %v, want %v", got.Yanked, yanked)
		}
	}
}

// TestPublishCountByPublishersExcludesYanked is the central guarantee of
// this PR: a yanked-and-republished recovery flurry must NOT trip the
// >20/24h velocity threshold. The query counts only non-yanked rows even
// when the yanked row's publisher_set matches.
func TestPublishCountByPublishersExcludesYanked(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC()
	stamp := now.Format("20060102150405.000000000")
	pub := "publisher-yank-test-" + stamp
	pkg := "pkg-yank-velocity-" + stamp

	insert := func(version string, yanked bool) {
		t.Helper()
		meta := PackageMetadata{
			Repository:   "npm",
			Package:      pkg,
			Version:      version,
			PublisherSet: []string{pub},
			Yanked:       yanked,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		if err := s.SetPackageMetadata(meta); err != nil {
			t.Fatalf("insert %s yanked=%v: %v", version, yanked, err)
		}
	}
	insert("1.0.0", false)
	insert("1.0.1", true)

	since := now.Add(-1 * time.Hour)
	count, err := s.PublishCountByPublishers(context.Background(), []string{pub}, since)
	if err != nil {
		t.Fatalf("PublishCountByPublishers: %v", err)
	}
	if count != 1 {
		t.Errorf("expected only the non-yanked row to count, got %d (want 1)", count)
	}
}

// CVEDetail is the storage-layer twin of intelligence.CVEDetail. The
// JSONB blob persisted in vulnerability_metadata.cve_details must
// round-trip byte-for-byte across the layer boundary so the v2 risk
// engine's SignalVulnFixAvailable consumes the exact tags the Trivy
// ingestion path wrote. Tag drift here would silently disable the
// signal on real CVE rows even though the schema migration succeeded.
func TestCVEDetailJSONRoundTrip(t *testing.T) {
	in := []CVEDetail{
		{CVE: "CVE-2024-0001", FixedVersion: "1.2.4", FixAvailable: true},
		{CVE: "CVE-2024-0002"},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `[{"cve":"CVE-2024-0001","fixedVersion":"1.2.4","fixAvailable":true},{"cve":"CVE-2024-0002"}]`
	if string(b) != want {
		t.Fatalf("unexpected JSON shape\n got: %s\nwant: %s", string(b), want)
	}
	var out []CVEDetail
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("length: got %d want %d", len(out), len(in))
	}
	for i := range in {
		if out[i] != in[i] {
			t.Fatalf("detail[%d] mismatch:\n got %+v\nwant %+v", i, out[i], in[i])
		}
	}
}

// TestSupplyChainUpdateNoDuplicateSetColumns is the Wave V regression
// guard for the SQLSTATE 42601 "ERROR: multiple assignments to same
// column \"checksum_declared\"" log line that fired on every docker
// manifest/blob fetch (qa/smoke-evidence/20260523-wave-S-deep/
// 08_proxy_logs_docker_block.txt). The enforcer always passes both
// ChecksumDeclared and ChecksumActual on the docker audit path, which
// previously emitted two SET fragments for each — Postgres rejects the
// duplicate at parse time. The fix lives in buildSupplyChainUpdateSQL;
// this test asserts no column appears twice in the SET clause for the
// dual-checksum payload, and for a broad "everything-set" payload that
// would catch any future copy-paste regression on any column.
func TestSupplyChainUpdateNoDuplicateSetColumns(t *testing.T) {
	str := func(s string) *string { return &s }
	intp := func(i int) *int { return &i }
	boolp := func(b bool) *bool { return &b }
	timep := func(tm time.Time) *time.Time { return &tm }
	slicep := func(s []string) *[]string { return &s }

	cases := []struct {
		name   string
		update SupplyChainUpdate
	}{
		{
			name: "docker audit dual-checksum payload (the original repro)",
			update: SupplyChainUpdate{
				ChecksumVerified: boolp(true),
				ChecksumDeclared: str("sha256:aaaa"),
				ChecksumActual:   str("sha256:aaaa"),
			},
		},
		{
			name: "every optional field set",
			update: SupplyChainUpdate{
				ProvenanceStatus:           str("verified"),
				TyposquatStatus:            str("clean"),
				TyposquatSimilarTo:         str(""),
				MalwareStatus:              str("clean"),
				MalwareID:                  str(""),
				ChecksumVerified:           boolp(true),
				SourceRepo:                 str("https://example/x"),
				RepoLinkStatus:             str("linked"),
				RepoLinkLastCheckedAt:      timep(time.Now()),
				InstallScriptKind:          str("none"),
				PublisherSet:               slicep([]string{"a"}),
				VersionAnomalyFlags:        slicep([]string{}),
				HiddenUnicodeHits:          intp(0),
				PublishVelocity24h:         intp(1),
				ChecksumDeclared:           str("sha256:b"),
				ChecksumActual:             str("sha256:b"),
				SLSALevel:                  intp(3),
				AttestationBuilderID:       str("gh"),
				AttestationIssuer:          str("sigstore"),
				AttestationSourceRepo:      str("https://example/x"),
				AttestationTransparencyLog: str("rekor"),
				AttestationCacheStale:      boolp(false),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			query, _, ok := buildSupplyChainUpdateSQL(time.Now(), tc.update)
			if !ok {
				t.Fatalf("expected ok=true for non-empty update")
			}
			// Extract the SET ... WHERE region.
			setIdx := strings.Index(query, " SET ")
			whereIdx := strings.Index(query, " WHERE ")
			if setIdx < 0 || whereIdx < 0 || whereIdx <= setIdx {
				t.Fatalf("malformed query: %s", query)
			}
			setBody := query[setIdx+len(" SET ") : whereIdx]
			seen := map[string]int{}
			for _, frag := range strings.Split(setBody, ", ") {
				eq := strings.Index(frag, "=")
				if eq <= 0 {
					t.Fatalf("malformed SET fragment %q in query %s", frag, query)
				}
				col := strings.TrimSpace(frag[:eq])
				seen[col]++
			}
			for col, n := range seen {
				if n > 1 {
					t.Errorf("column %q appears %d times in SET clause (Postgres rejects with SQLSTATE 42601). Full query:\n%s",
						col, n, query)
				}
			}
			// Spot-check the original offender by name so the failure
			// message is actionable if the regression returns.
			if tc.update.ChecksumDeclared != nil && seen["checksum_declared"] != 1 {
				t.Errorf("checksum_declared appeared %d times, want 1", seen["checksum_declared"])
			}
			if tc.update.ChecksumActual != nil && seen["checksum_actual"] != 1 {
				t.Errorf("checksum_actual appeared %d times, want 1", seen["checksum_actual"])
			}
		})
	}
}

// VulnerabilityMetadata embeds CVEDetails. Empty slices must omit on
// marshal so legacy callers reading this JSON outside the DB path don't
// see a noisy "cveDetails":null payload, and so the Trivy ingestion path
// can leave the field unset on rows that never had fix data.
func TestVulnerabilityMetadataCVEDetailsOmitEmpty(t *testing.T) {
	meta := VulnerabilityMetadata{
		Repository: "r",
		Package:    "p",
		Version:    "v",
	}
	b, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "cveDetails") {
		t.Fatalf("expected cveDetails to be omitted, got %s", string(b))
	}
}

// TestPublishCountByPublishersCountsDistinctPackages is the S-5
// regression: the one and only production firing of
// sc.publish_velocity_anomaly was a FALSE POSITIVE produced by this
// query counting rows.
//
// maven:org.apache.commons:commons-lang3:3.18.0 reported velocity 22 >
// 20. Apache Commons did not push 22 releases in a day. WE ingested 22
// versions of ONE package inside one window and COUNT(*) read our own
// backfill as publishing activity.
//
// The signal is titled "Shai-Hulud worm signature". A worm's shape is
// many DISTINCT PACKAGES from one maintainer -- the 2026-08-04 campaign
// was ten packages in 43 minutes. Many versions of a single package is
// the opposite shape: a normal release train, or our own re-scan.
func TestPublishCountByPublishersCountsDistinctPackages(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC()
	stamp := now.Format("20060102150405.000000000")
	pub := "publisher-distinct-" + stamp

	insert := func(pkg, version string) {
		t.Helper()
		if err := s.SetPackageMetadata(PackageMetadata{
			Repository:   "maven",
			Package:      pkg,
			Version:      version,
			PublisherSet: []string{pub},
			CreatedAt:    now,
			UpdatedAt:    now,
		}); err != nil {
			t.Fatalf("insert %s@%s: %v", pkg, version, err)
		}
	}

	// The commons-lang3 shape: one package, many versions. This is a
	// release train or a backfill, and it must not read as velocity.
	one := "commons-lang3-" + stamp
	for i := 0; i < 22; i++ {
		insert(one, fmt.Sprintf("3.%d.0", i))
	}

	since := now.Add(-1 * time.Hour)
	count, err := s.PublishCountByPublishers(context.Background(), []string{pub}, since)
	if err != nil {
		t.Fatalf("PublishCountByPublishers: %v", err)
	}
	if count != 1 {
		t.Errorf("22 versions of ONE package counted as %d publishes, want 1. "+
			"Counting rows here is what produced the commons-lang3 false positive; "+
			"the threshold is 20, so %d would fire the signal.", count, count)
	}

	// The worm shape: one maintainer, many distinct packages. THIS is
	// what the signal is named for and it must still be visible.
	for i := 0; i < 9; i++ {
		insert(fmt.Sprintf("wormpkg-%d-%s", i, stamp), "1.0.0")
	}
	count, err = s.PublishCountByPublishers(context.Background(), []string{pub}, since)
	if err != nil {
		t.Fatalf("PublishCountByPublishers: %v", err)
	}
	if count != 10 {
		t.Errorf("one maintainer across 10 distinct packages counted as %d, want 10 — "+
			"this is the 2026-08-04 campaign's exact shape and the signal must be able to see it", count)
	}
}
