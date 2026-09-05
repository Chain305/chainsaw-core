package pgstore

// Tests for the local-guard block ledger (P9F-UD-06 / P9F-252).
//
// Split deliberately: NormalizeGuardBlock is pure and always runs, so the
// tenancy and clamping rules are exercised on every `go test ./core/...`
// even with no database in reach. The round-trip test needs Postgres and
// SKIPS without CHAINSAW_DATABASE_URL — matching the convention in
// store_test.go and migrate_drop_trust_score_test.go, and honouring
// CHAINSAW_TEST_REQUIRE_DB so a run that was supposed to hit the database
// fails loudly instead of skipping while reporting the package ok.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNormalizeGuardBlock_RejectsRowsWithNoTenant(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name  string
		block GuardBlock
	}{
		{
			// The anonymous ingest tier. Storing this would need an org
			// invented from nothing — and the nearest thing to hand is the
			// DEFAULT org, i.e. one tenant's dashboard filling up with
			// strangers' package names (the L-02 shape).
			name:  "no org",
			block: GuardBlock{InstallID: "machine-a", PackageName: "left-pad"},
		},
		{
			name:  "whitespace org",
			block: GuardBlock{OrgID: "   ", InstallID: "machine-a"},
		},
		{
			// Nothing to attribute the block to.
			name:  "no install id",
			block: GuardBlock{OrgID: "org-alpha", PackageName: "left-pad"},
		},
		{
			name:  "whitespace install id",
			block: GuardBlock{OrgID: "org-alpha", InstallID: "\t \n"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := NormalizeGuardBlock(tc.block, now); ok {
				t.Fatalf("NormalizeGuardBlock accepted %+v; a row with no tenant must never be stored", tc.block)
			}
		})
	}
}

func TestNormalizeGuardBlock_KeepsPartialPayloads(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

	// Refusal sharing is opt-out (CHAINSAW_REFUSAL_SHARING_DISABLED), so a
	// consenting operator can legitimately withhold the package identity.
	// The block still happened and must still be counted.
	got, ok := NormalizeGuardBlock(GuardBlock{
		OrgID:     " org-alpha ",
		InstallID: " machine-a ",
		Bin:       "npm",
		Ecosystem: "npm",
		Severity:  "critical",
	}, now)
	if !ok {
		t.Fatal("a block with no package identity was rejected; refusal sharing is opt-out and the block still counts")
	}
	if got.OrgID != "org-alpha" || got.InstallID != "machine-a" {
		t.Errorf("org/install not trimmed: %q / %q", got.OrgID, got.InstallID)
	}
	if got.PackageName != "" || got.PackageVersion != "" {
		t.Errorf("invented package identity: %q@%q", got.PackageName, got.PackageVersion)
	}
	if !got.BlockedAt.Equal(now) {
		t.Errorf("blocked_at = %v, want the supplied now (%v) when the event carried no timestamp", got.BlockedAt, now)
	}
}

func TestNormalizeGuardBlock_ClampsOverlongFieldsWithoutSplittingRunes(t *testing.T) {
	now := time.Now().UTC()

	// A multi-byte name longer than the cap. Truncating by BYTES here would
	// cut a rune in half and store invalid UTF-8, which Postgres rejects on
	// a TEXT column — turning a cosmetic cap into a dropped block.
	long := strings.Repeat("é", guardBlockFieldMax+50)
	got, ok := NormalizeGuardBlock(GuardBlock{
		OrgID:       "org-alpha",
		InstallID:   "machine-a",
		PackageName: long,
	}, now)
	if !ok {
		t.Fatal("clamping rejected an otherwise valid block")
	}
	if n := len([]rune(got.PackageName)); n != guardBlockFieldMax {
		t.Errorf("clamped to %d runes, want %d", n, guardBlockFieldMax)
	}
	if !utf8Valid(got.PackageName) {
		t.Error("clamped package name is not valid UTF-8 — a byte-wise truncation split a rune")
	}
}

func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

func TestNormalizeGuardBlock_NormalisesTimestampToUTC(t *testing.T) {
	loc := time.FixedZone("UTC+7", 7*60*60)
	ts := time.Date(2026, 9, 4, 19, 0, 0, 0, loc)
	got, ok := NormalizeGuardBlock(GuardBlock{
		OrgID: "org-alpha", InstallID: "machine-a", BlockedAt: ts,
	}, time.Now())
	if !ok {
		t.Fatal("rejected")
	}
	if got.BlockedAt.Location() != time.UTC {
		t.Errorf("blocked_at location = %v, want UTC", got.BlockedAt.Location())
	}
	if !got.BlockedAt.Equal(ts) {
		t.Errorf("blocked_at = %v, want the same instant as %v", got.BlockedAt, ts)
	}
}

// TestGuardBlockLedger_RoundTripIsOrgScoped is the SQL half: two orgs write
// blocks, neither can read the other's, and an install that only ever ran
// clean still registers as reporting.
func TestGuardBlockLedger_RoundTripIsOrgScoped(t *testing.T) {
	base := strings.TrimSpace(os.Getenv("CHAINSAW_DATABASE_URL"))
	if base == "" {
		if os.Getenv("CHAINSAW_TEST_REQUIRE_DB") != "" {
			t.Fatal("CHAINSAW_TEST_REQUIRE_DB is set but CHAINSAW_DATABASE_URL is empty — " +
				"this run was supposed to exercise Postgres and would otherwise have " +
				"skipped while still reporting the package ok")
		}
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping integration test")
	}
	dsn, cleanup := provisionScratchDatabase(t, base)
	defer cleanup()

	store, err := Open(dsn)
	if err != nil {
		t.Fatalf("open scratch store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)

	mk := func(org, install, pkg string, at time.Time) GuardBlock {
		return GuardBlock{
			OrgID: org, InstallID: install, Bin: "npm", Ecosystem: "npm",
			PackageName: pkg, PackageVersion: "1.0.0", Reason: "malware.known_bad",
			Severity: "critical", BlockedAt: at,
		}
	}
	for _, b := range []GuardBlock{
		mk("org-alpha", "machine-a", "left-pad", now.Add(-time.Hour)),
		mk("org-alpha", "machine-a", "colors", now.Add(-2*time.Hour)),
		// Outside the 24h window — must not be counted.
		mk("org-alpha", "machine-a", "ancient", now.Add(-72*time.Hour)),
		mk("org-beta", "machine-b", "event-stream", now.Add(-time.Hour)),
	} {
		if err := store.RecordGuardBlock(ctx, b); err != nil {
			t.Fatalf("record %s/%s: %v", b.OrgID, b.PackageName, err)
		}
	}

	alpha, err := store.CountGuardBlocksSince(ctx, "org-alpha", since)
	if err != nil {
		t.Fatalf("count alpha: %v", err)
	}
	if alpha != 2 {
		t.Errorf("org-alpha 24h blocks = %d, want 2 (the 72h-old row must fall outside the window)", alpha)
	}
	beta, err := store.CountGuardBlocksSince(ctx, "org-beta", since)
	if err != nil {
		t.Fatalf("count beta: %v", err)
	}
	if beta != 1 {
		t.Errorf("org-beta 24h blocks = %d, want 1 (org-alpha's rows must not be visible)", beta)
	}
	gamma, err := store.CountGuardBlocksSince(ctx, "org-gamma", since)
	if err != nil {
		t.Fatalf("count gamma: %v", err)
	}
	if gamma != 0 {
		t.Errorf("org-gamma blocks = %d, want 0", gamma)
	}

	// A block registers its install; a clean install registers via Touch.
	if err := store.TouchGuardInstall(ctx, "org-alpha", "machine-clean", now); err != nil {
		t.Fatalf("touch clean install: %v", err)
	}
	installs, err := store.CountGuardInstallsSince(ctx, "org-alpha", since)
	if err != nil {
		t.Fatalf("count installs: %v", err)
	}
	if installs != 2 {
		t.Errorf("org-alpha consented installs = %d, want 2 (the blocking machine plus the clean one)", installs)
	}

	// Out-of-order delivery must not walk last_seen_at backwards: the guard
	// buffers and flushes, so an older event can arrive after a newer one.
	if err := store.TouchGuardInstall(ctx, "org-alpha", "machine-clean", now.Add(-48*time.Hour)); err != nil {
		t.Fatalf("late touch: %v", err)
	}
	installs, err = store.CountGuardInstallsSince(ctx, "org-alpha", since)
	if err != nil {
		t.Fatalf("recount installs: %v", err)
	}
	if installs != 2 {
		t.Errorf("consented installs = %d after a late out-of-order event, want 2 (last_seen_at moved backwards)", installs)
	}

	// Retention prune keeps only what is inside the window it is given.
	n, err := store.PruneGuardBlocksBefore(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned %d rows, want 1 (the 72h-old row)", n)
	}
}

func TestRecordGuardBlock_RefusesUninitialisedStore(t *testing.T) {
	var s *Store
	if err := s.RecordGuardBlock(context.Background(), GuardBlock{OrgID: "o", InstallID: "i"}); err == nil {
		t.Error("nil store accepted a write")
	}
	if _, err := s.CountGuardBlocksSince(context.Background(), "o", time.Now()); err == nil {
		t.Error("nil store answered a count; a source that did not run must not report zero")
	}
}

func TestCountGuardBlocksSince_RefusesEmptyOrg(t *testing.T) {
	// An empty org must be an ERROR, not an unscoped count. This is the read
	// side of the same rule NormalizeGuardBlock enforces on writes.
	s := &Store{}
	if _, err := s.CountGuardBlocksSince(context.Background(), "  ", time.Now()); err == nil {
		t.Error("empty org id accepted")
	}
}
