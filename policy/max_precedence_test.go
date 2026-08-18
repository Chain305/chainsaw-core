package policy

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
)

// maxPrecedenceTestOrg opens a store scoped to an org nobody else uses and
// drops its rows afterwards. A per-run org matters more than usual here:
// MaxPrecedence is an aggregate over the WHOLE org, so a single row left by
// another test — or by an earlier run of this one — silently changes the
// answer, which is exactly the class of bug this file exists to pin.
func maxPrecedenceTestOrg(t *testing.T, label string) (*pgstore.Store, *Store) {
	t.Helper()
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("new policy store: %v", err)
	}
	orgID := "test-maxprec-" + label + "-" +
		strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	// Registered before any insert so a mid-test t.Fatalf still drops
	// whatever landed. t.Errorf, not t.Fatalf, so a cleanup failure can
	// never mask the test's own result.
	t.Cleanup(func() {
		if _, err := db.DB().Exec(`DELETE FROM policies WHERE org_id=?`, orgID); err != nil {
			t.Errorf("cleanup policies for %s: %v", orgID, err)
		}
	})
	return db, store.ForOrg(orgID)
}

// exceptionPrecedence mirrors the sentinel the exceptions API stamps on the
// policy rows it creates (internal/server/exceptions_api.go and
// bulk_actions_api.go both use `int(-time.Now().UnixNano())`). It is
// deliberately a huge negative number so List()'s `ORDER BY precedence ASC`
// returns exceptions ahead of every ordinary policy.
func exceptionPrecedence() int { return int(-time.Now().UnixNano()) }

// TestMaxPrecedenceIgnoresExceptionSentinels is the regression guard for a
// live defect: MaxPrecedence took `MAX(precedence)` over ALL rows in the org,
// including the negative exception sentinels.
//
// The consequence was not a cosmetic off-by-one. The REST create handler
// defaults an omitted precedence to MaxPrecedence()+10 (see F23 in
// internal/server/server_policies.go). For an org whose only rows are
// exceptions, that MAX is around -1.7e18, so the next policy created without
// an explicit precedence was stamped NEGATIVE — which sorts it ahead of every
// real policy under `ORDER BY precedence ASC`. A rule the user expected to be
// appended last silently became the first thing evaluated. If that rule
// allows, it shadows every block behind it.
//
// The defect surfaced as a test failure rather than a report, and only under
// a `-run` filter, because a full-suite run happened to clean up the
// exception rows before the assertion ran. The assertion itself
// (`expected precedence > 0`, rest_hygiene_regression_test.go) was correct
// and had been in the tree the whole time; what was missing was any direct
// coverage of MaxPrecedence, which had none at all.
func TestMaxPrecedenceIgnoresExceptionSentinels(t *testing.T) {
	_, orgStore := maxPrecedenceTestOrg(t, "excl")

	// An org holding ONLY exceptions. This is the shape that broke:
	// every row carries the negative sentinel, so an unfiltered MAX is
	// negative and MAX+10 is still negative.
	for i, pkg := range []string{"left-pad", "lodash", "requests"} {
		if _, err := orgStore.Create(Policy{
			Name:       "Exception: " + pkg + "@1.0.0",
			Precedence: exceptionPrecedence() + i, // +i keeps the unique index happy
			Mode:       ModeAllow,
			Status:     StatusEnabled,
			Identifier: Identifier{
				TargetPackageName:    pkg,
				TargetPackageVersion: "1.0.0",
			},
			Conditions: Conditions{IsVulnerable: boolPtr(true)},
		}); err != nil {
			t.Fatalf("seed exception policy for %s: %v", pkg, err)
		}
	}

	got, err := orgStore.MaxPrecedence()
	if err != nil {
		t.Fatalf("MaxPrecedence: %v", err)
	}
	// 0 — "no ordinary policies here" — NOT the least-negative sentinel.
	if got != 0 {
		t.Fatalf("MaxPrecedence over an exceptions-only org: got %d, want 0 "+
			"(a negative result means the exception sentinel won the MAX, and "+
			"the create handler's MAX+10 default would stamp the next policy "+
			"with a negative precedence, seating it ahead of every real rule)", got)
	}
	// The property the caller actually depends on.
	if next := got + 10; next <= 0 {
		t.Fatalf("MAX+10 default = %d, want > 0", next)
	}
}

// TestMaxPrecedenceUsesOrdinaryPoliciesWhenBothPresent covers the mixed org —
// the common shape — and pins that excluding the sentinels did not also
// exclude anything real. Without this, a fix that returned a constant 0 would
// satisfy the test above.
func TestMaxPrecedenceUsesOrdinaryPoliciesWhenBothPresent(t *testing.T) {
	_, orgStore := maxPrecedenceTestOrg(t, "mixed")

	if _, err := orgStore.Create(Policy{
		Name:       "Exception: left-pad@1.0.0",
		Precedence: exceptionPrecedence(),
		Mode:       ModeAllow,
		Status:     StatusEnabled,
		Identifier: Identifier{TargetPackageName: "left-pad", TargetPackageVersion: "1.0.0"},
		Conditions: Conditions{IsVulnerable: boolPtr(true)},
	}); err != nil {
		t.Fatalf("seed exception: %v", err)
	}
	if _, err := orgStore.Create(Policy{
		Name:       "block-vulnerable",
		Precedence: 40,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		Conditions: Conditions{IsVulnerable: boolPtr(true)},
	}); err != nil {
		t.Fatalf("seed ordinary policy: %v", err)
	}

	got, err := orgStore.MaxPrecedence()
	if err != nil {
		t.Fatalf("MaxPrecedence: %v", err)
	}
	if got != 40 {
		t.Fatalf("MaxPrecedence with both kinds present: got %d, want 40", got)
	}
}

// TestMaxPrecedenceCountsPrecedenceZero pins the boundary. The filter is
// `>= 0`, not `> 0`, so a genuine precedence-0 row still anchors the
// sequence — the seeded baseline rules are created at precedence 0
// (core/policy/system_policies.go), and treating them as absent would hand
// the next policy 10 and collide with whatever already sits there.
func TestMaxPrecedenceCountsPrecedenceZero(t *testing.T) {
	_, orgStore := maxPrecedenceTestOrg(t, "zero")

	if _, err := orgStore.Create(Policy{
		Name:       "baseline-at-zero",
		Precedence: 0,
		Mode:       ModeMonitor,
		Status:     StatusEnabled,
		Conditions: Conditions{IsVulnerable: boolPtr(true)},
	}); err != nil {
		t.Fatalf("seed precedence-0 policy: %v", err)
	}

	got, err := orgStore.MaxPrecedence()
	if err != nil {
		t.Fatalf("MaxPrecedence: %v", err)
	}
	if got != 0 {
		t.Fatalf("MaxPrecedence with a single precedence-0 row: got %d, want 0", got)
	}
}

// TestMaxPrecedenceEmptyOrgReturnsZero pins the no-rows case, which reaches a
// different branch (sql.NullInt64 invalid) than the all-filtered-out case
// above even though both answer 0.
func TestMaxPrecedenceEmptyOrgReturnsZero(t *testing.T) {
	_, orgStore := maxPrecedenceTestOrg(t, "empty")

	got, err := orgStore.MaxPrecedence()
	if err != nil {
		t.Fatalf("MaxPrecedence: %v", err)
	}
	if got != 0 {
		t.Fatalf("MaxPrecedence on an empty org: got %d, want 0", got)
	}
}
