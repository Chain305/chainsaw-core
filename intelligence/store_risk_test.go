package intelligence

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
	"github.com/chain305/chainsaw-core/risk"
)

// TestStore_RoundTripRiskEvaluation verifies that a Report with a
// populated Risk evaluation survives Upsert → Get unchanged, and that
// rows written with Risk=nil deserialise back to Risk=nil (not an empty
// Evaluation struct). Gated on CHAINSAW_DATABASE_URL to match the
// convention already used by internal/policy/store_test.go — when the
// DSN is absent the test simply skips rather than failing on every local
// `go test ./...` invocation.
func TestStore_RoundTripRiskEvaluation(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := NewStore(db)
	ctx := context.Background()
	orgID := "test-intel-risk-" + strings.ReplaceAll(
		time.Now().UTC().Format("20060102150405.000000000"), ".", "",
	)
	// intelligence_reports is now universal (no org_id column); clean up
	// by the package coordinate(s) the test writes to avoid bleeding
	// rows into parallel runs. Each test keys on a unique ecosystem
	// suffixed with orgID to stay isolated.
	key := Key{
		Ecosystem: "npm-" + orgID,
		Package:   "example-pkg",
		Version:   "1.0.0",
	}
	t.Cleanup(func() {
		_, _ = db.DB().Exec(
			`DELETE FROM intelligence_reports WHERE ecosystem=$1 AND package_name=$2 AND version=$3`,
			key.Ecosystem, key.Package, key.Version,
		)
	})

	collectedAt := time.Now().UTC().Truncate(time.Second)

	// Case 1: Report WITH Risk populated.
	withRisk := &Report{
		Identity: IdentitySection{
			Ecosystem: key.Ecosystem, Package: key.Package, Version: key.Version,
		},
		SupplyChain: SupplyChainSection{MalwareStatus: "clean", TrustScore: 72},
		Observation: ObservationSection{
			CollectedAt: collectedAt,
			FreshUntil:  collectedAt.Add(24 * time.Hour),
		},
		Risk: &risk.Evaluation{
			Key: risk.Key{
				Ecosystem: key.Ecosystem, Package: key.Package, Version: key.Version,
			},
			RolledUp:      risk.Score{Overall: 72},
			DirectScore:   risk.Score{Overall: 72},
			Verdict:       risk.VerdictAllow,
			Resolution:    risk.Resolution{Verdict: risk.VerdictAllow, Summary: "ok"},
			EvaluatedAt:   collectedAt,
			EngineVersion: risk.EngineVersion,
		},
	}
	if err := store.Upsert(ctx, orgID, withRisk); err != nil {
		t.Fatalf("Upsert with risk: %v", err)
	}
	got, err := store.Get(ctx, orgID, key)
	if err != nil {
		t.Fatalf("Get with risk: %v", err)
	}
	if got.Risk == nil {
		t.Fatalf("expected Risk populated after round-trip, got nil")
	}
	if got.Risk.RolledUp.Overall != 72 {
		t.Fatalf("RolledUp.Overall: got %d, want 72", got.Risk.RolledUp.Overall)
	}
	if got.Risk.Verdict != risk.VerdictAllow {
		t.Fatalf("Verdict: got %q, want %q", got.Risk.Verdict, risk.VerdictAllow)
	}
	if got.Risk.EngineVersion != risk.EngineVersion {
		t.Fatalf("EngineVersion: got %q, want %q", got.Risk.EngineVersion, risk.EngineVersion)
	}

	// Case 2: Upsert without Risk — row should come back with Risk=nil,
	// not a zero-value Evaluation struct. This is the critical nil-safety
	// guarantee for rows predating Phase 2.
	key2 := Key{Ecosystem: "pypi", Package: "no-risk", Version: "0.1.0"}
	noRisk := &Report{
		Identity: IdentitySection{
			Ecosystem: key2.Ecosystem, Package: key2.Package, Version: key2.Version,
		},
		Observation: ObservationSection{
			CollectedAt: collectedAt,
			FreshUntil:  collectedAt.Add(24 * time.Hour),
		},
	}
	if err := store.Upsert(ctx, orgID, noRisk); err != nil {
		t.Fatalf("Upsert without risk: %v", err)
	}
	got2, err := store.Get(ctx, orgID, key2)
	if err != nil {
		t.Fatalf("Get without risk: %v", err)
	}
	if got2.Risk != nil {
		t.Fatalf("expected Risk=nil for row without risk, got %+v", got2.Risk)
	}
}
