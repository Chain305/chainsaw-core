package policy

// The guard for the failure that crashlooped production on 2026-09-18.
//
// configs/seed.yaml renamed three rules ("Block brand-new versions ..." ->
// "Flag brand-new versions ...") while changing their mode to monitor. Every
// unit test passed, the image verified, and the new pod entered
// CrashLoopBackOff on the first org that already had the old rows:
//
//   Failed to seed policies: duplicate key value violates unique constraint
//   "idx_policies_org_precedence_unique" (SQLSTATE 23505)
//
// SeedPoliciesIfNeededTx dedups by NAME and INSERTs at the precedence the
// config names. A renamed rule is therefore a NEW rule competing for a
// precedence the orphaned old row still occupies.
//
// Nothing caught it because every existing test seeds into an EMPTY org. The
// upgrade path — an org carrying the previous release's rows — was untested,
// and that is the only path where this fires. This test seeds twice: once with
// the old config, then with the new one.

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
)

func seedUpgradeTestOrg(t *testing.T) (*pgstore.Store, string) {
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

	// NewStore runs ensurePolicyIntegrity, which is what CREATEs
	// idx_policies_org_precedence_unique. Opening the pool alone does NOT:
	// a bare migrate leaves only the non-unique idx_policies_org_precedence.
	// The first version of this file skipped that step, so the rename case
	// "passed" against a database with no constraint to violate — the exact
	// did-not-run-reads-as-a-pass shape this whole test is about.
	if _, err := NewStore(db); err != nil {
		t.Fatalf("new policy store: %v", err)
	}
	assertPrecedenceUniqueIndexExists(t, db)

	orgID := "test-seedupgrade-" +
		strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	t.Cleanup(func() {
		if _, err := db.DB().Exec(`DELETE FROM policies WHERE org_id=?`, orgID); err != nil {
			t.Errorf("cleanup policies for %s: %v", orgID, err)
		}
	})
	return db, orgID
}

// assertPrecedenceUniqueIndexExists refuses to let these tests run against a
// database where the constraint is absent. Without it a green run means
// nothing.
func assertPrecedenceUniqueIndexExists(t *testing.T, db *pgstore.Store) {
	t.Helper()
	var n int
	if err := db.DB().QueryRow(
		`SELECT count(*) FROM pg_indexes WHERE tablename='policies' AND indexname='idx_policies_org_precedence_unique'`,
	).Scan(&n); err != nil {
		t.Fatalf("look up precedence unique index: %v", err)
	}
	if n != 1 {
		t.Fatalf("idx_policies_org_precedence_unique is ABSENT — these tests cannot " +
			"exercise what they exist to guard. This is a DID NOT RUN, not a pass.")
	}
}

func seedInto(t *testing.T, db *pgstore.Store, orgID string, policies []Policy) (int, error) {
	t.Helper()
	tx, err := db.DB().Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	n, seedErr := SeedPoliciesIfNeededTx(tx, orgID, policies)
	if seedErr != nil {
		_ = tx.Rollback()
		return n, seedErr
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return n, nil
}

// releaseNMinus1 is the shape configs/seed.yaml shipped before this change:
// the same three rules, at the same precedences, in block mode.
func releaseNMinus1() []Policy {
	yes := true
	ten := 10
	return []Policy{
		{Name: "Block vulnerable packages", Precedence: 100, Mode: ModeBlock, Status: StatusEnabled,
			Conditions: Conditions{IsVulnerable: &yes}},
		{Name: "Block publisher-changed versions", Precedence: 130, Mode: ModeBlock, Status: StatusEnabled,
			Conditions: Conditions{PublisherChanged: &yes}},
		{Name: "Block brand-new versions (account-takeover / zero-hour)", Precedence: 140,
			Mode: ModeBlock, Status: StatusEnabled, Conditions: Conditions{CooldownDays: &ten}},
	}
}

// TestSeedIsIdempotentAcrossAReleaseThatChangesMode is the shipping path: the
// mode changed, the names did not. Re-seeding an org that already has the old
// rows must be a no-op, not a constraint violation.
func TestSeedIsIdempotentAcrossAReleaseThatChangesMode(t *testing.T) {
	db, orgID := seedUpgradeTestOrg(t)

	if n, err := seedInto(t, db, orgID, releaseNMinus1()); err != nil || n != 3 {
		t.Fatalf("first seed: created=%d err=%v; want 3, nil", n, err)
	}

	// Same names, same precedences, monitor instead of block — what this
	// release actually ships.
	yes := true
	ten := 10
	next := []Policy{
		{Name: "Block vulnerable packages", Precedence: 100, Mode: ModeMonitor, Status: StatusEnabled,
			Conditions: Conditions{IsVulnerable: &yes}},
		{Name: "Block publisher-changed versions", Precedence: 130, Mode: ModeMonitor, Status: StatusEnabled,
			Conditions: Conditions{PublisherChanged: &yes}},
		{Name: "Block brand-new versions (account-takeover / zero-hour)", Precedence: 140,
			Mode: ModeMonitor, Status: StatusEnabled, Conditions: Conditions{CooldownDays: &ten}},
	}
	n, err := seedInto(t, db, orgID, next)
	if err != nil {
		t.Fatalf("re-seeding an existing org failed: %v\n"+
			"This is the startup path for EVERY org that already has these rules. "+
			"A failure here crashloops the proxy.", err)
	}
	if n != 0 {
		t.Errorf("re-seed created %d rows, want 0 — dedup by name should make this a no-op", n)
	}
}

// TestSeedRenamedRuleDuplicatesInsteadOfCrashing reproduces the 2026-09-18
// case. A renamed rule at an occupied precedence used to violate
// idx_policies_org_precedence_unique and stop the proxy at boot. Since
// v0.22.107 the seeder moves a new rule off a taken precedence, so the boot
// survives, but a rename is still not a rename: the old row stays and the
// renamed one lands beside it as a second rule. That is why configs/seed.yaml
// keeps its DO-NOT-RENAME banner.
func TestSeedRenamedRuleDuplicatesInsteadOfCrashing(t *testing.T) {
	db, orgID := seedUpgradeTestOrg(t)

	if _, err := seedInto(t, db, orgID, releaseNMinus1()); err != nil {
		t.Fatalf("first seed: %v", err)
	}

	ten := 10
	renamed := []Policy{
		{Name: "Flag brand-new versions (account-takeover / zero-hour)", Precedence: 140,
			Mode: ModeMonitor, Status: StatusEnabled, Conditions: Conditions{CooldownDays: &ten}},
	}
	n, err := seedInto(t, db, orgID, renamed)
	if err != nil || n != 1 {
		t.Fatalf("renamed seed rule: created=%d err=%v; want 1 row at a free precedence, no error", n, err)
	}
	pols, err := (&Store{sql: db, orgID: orgID}).List()
	if err != nil {
		t.Fatal(err)
	}
	var oldPrec, newPrec int
	for _, p := range pols {
		switch p.Name {
		case "Block brand-new versions (account-takeover / zero-hour)":
			oldPrec = p.Precedence
		case renamed[0].Name:
			newPrec = p.Precedence
		}
	}
	if oldPrec != 140 || newPrec == 0 || newPrec == 140 {
		t.Fatalf("old rule at %d, renamed rule at %d; want the old row kept at 140 and the renamed one beside it", oldPrec, newPrec)
	}
}

// A brand-new org on a deployment whose config seeds cooldown and
// publisher-change must NOT also receive the demo copies of those signals.
// Before this, the policy list opened at eleven rules with two near-duplicate
// cooldown rules differing only in window.
func TestSeedDemoSkipsSignalsTheConfigAlreadyCovers(t *testing.T) {
	db, orgID := seedUpgradeTestOrg(t)

	// Stand in for configs/seed.yaml: cooldown + publisher-change, monitor.
	yes := true
	ten := 10
	configPolicies := []Policy{
		{Name: "Block brand-new versions (account-takeover / zero-hour)", Precedence: 140,
			Mode: ModeMonitor, Status: StatusEnabled, Conditions: Conditions{CooldownDays: &ten}},
		{Name: "Block publisher-changed versions", Precedence: 130,
			Mode: ModeMonitor, Status: StatusEnabled, Conditions: Conditions{PublisherChanged: &yes}},
	}
	if n, err := seedInto(t, db, orgID, configPolicies); err != nil || n != 2 {
		t.Fatalf("config seed: created=%d err=%v; want 2, nil", n, err)
	}

	tx, err := db.DB().Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	created, err := SeedDemoPoliciesIfNeededTx(tx, orgID, nil)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("seed demo policies: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Malware + typosquat survive; cooldown + publisher-change do not.
	if created != 2 {
		t.Errorf("demo seed created %d policies, want 2 (malware + typosquat only).\n"+
			"4 means the covered-signal dedup did not run; 0 means it dropped too much "+
			"and a new org has nothing that demonstrates a block.", created)
	}

	rows, err := db.DB().Query(`SELECT name FROM policies WHERE org_id=? ORDER BY name`, orgID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		names = append(names, n)
	}
	if len(names) != 4 {
		t.Errorf("org has %d policies (%v), want 4", len(names), names)
	}
	for _, n := range names {
		if strings.Contains(n, "Demo: Cooldown") || strings.Contains(n, "Demo: Flag publisher change") {
			t.Errorf("redundant demo rule %q was seeded beside the config rule covering the same signal", n)
		}
	}
}

// hiddenUnicodeSeed returns the hidden-unicode block rule as a given release
// seeded it: kinds is the only thing v0.22.99 changed.
func hiddenUnicodeSeed(precedence int, kinds ...string) Policy {
	yes := true
	return Policy{Name: "Block bidi-override hidden Unicode payloads", Precedence: precedence,
		Mode: ModeBlock, Status: StatusEnabled,
		Conditions: Conditions{HasHiddenUnicode: &yes, HiddenUnicodeKinds: kinds}}
}

// TestSupersededSeedUpgradeDecision is the non-DB half of F19: which stored
// rows the startup upgrade rewrites. Only an exact earlier seeded definition
// qualifies; any edit leaves the row alone.
func TestSupersededSeedUpgradeDecision(t *testing.T) {
	disabled := hiddenUnicodeSeed(150, "bidi_override")
	disabled.Status = StatusDisabled
	described := hiddenUnicodeSeed(150, "bidi_override")
	described.Description = "ours now"
	monitor := hiddenUnicodeSeed(150, "bidi_override")
	monitor.Mode = ModeMonitor
	scoped := hiddenUnicodeSeed(150, "bidi_override")
	scoped.Identifier.TargetPackageRepo = "npmjs"
	renamed := hiddenUnicodeSeed(150, "bidi_override")
	renamed.Name = "Block bidi only"
	cased := hiddenUnicodeSeed(150, "bidi_override")
	cased.Name = "  block BIDI-override hidden unicode payloads "

	cases := []struct {
		name string
		row  Policy
		want bool
	}{
		{"pre-v0.22.99 seed at 150", hiddenUnicodeSeed(150, "bidi_override"), true},
		{"earliest seed at 120", hiddenUnicodeSeed(120, "bidi_override"), true},
		{"disabled seed: conditions upgraded, status kept", disabled, true},
		{"name folded as seeding folds it", cased, true},
		{"current seed is not upgraded again", hiddenUnicodeSeed(150, "bidi_override", "variation_selector"), false},
		{"user moved precedence", hiddenUnicodeSeed(155, "bidi_override"), false},
		{"user widened kinds", hiddenUnicodeSeed(150, "bidi_override", "zero_width"), false},
		{"user added a description", described, false},
		{"user switched to monitor", monitor, false},
		{"user scoped it to one repo", scoped, false},
		{"different name", renamed, false},
	}
	for _, c := range cases {
		got, ok := SupersededSeedUpgrade(c.row)
		if ok != c.want {
			t.Errorf("%s: upgrade=%v, want %v", c.name, ok, c.want)
			continue
		}
		if ok && !slicesEqual(got.HiddenUnicodeKinds, []string{"bidi_override", "variation_selector"}) {
			t.Errorf("%s: upgraded kinds = %v", c.name, got.HiddenUnicodeKinds)
		}
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSupersededSeedUpgradeOnStartup is the DB half of F19. Three orgs: one
// seeded by a pre-v0.22.99 release, one whose operator edited that rule, and
// one seeded fresh. Opening the store (what every startup does) upgrades the
// first only, and a second open changes nothing.
func TestSupersededSeedUpgradeOnStartup(t *testing.T) {
	db, oldOrg := seedUpgradeTestOrg(t)
	editedOrg, freshOrg := oldOrg+"-edited", oldOrg+"-fresh"
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM policies WHERE org_id IN (?, ?)`, editedOrg, freshOrg)
	})

	if n, err := seedInto(t, db, oldOrg, []Policy{hiddenUnicodeSeed(150, "bidi_override")}); err != nil || n != 1 {
		t.Fatalf("seed old org: created=%d err=%v", n, err)
	}
	edited := hiddenUnicodeSeed(150, "bidi_override")
	edited.Description = "kept bidi-only on purpose"
	if n, err := seedInto(t, db, editedOrg, []Policy{edited}); err != nil || n != 1 {
		t.Fatalf("seed edited org: created=%d err=%v", n, err)
	}
	if n, err := seedInto(t, db, freshOrg, []Policy{hiddenUnicodeSeed(150, "bidi_override", "variation_selector")}); err != nil || n != 1 {
		t.Fatalf("seed fresh org: created=%d err=%v", n, err)
	}

	read := func(orgID string) (Policy, string) {
		t.Helper()
		pols, err := (&Store{sql: db, orgID: orgID}).List()
		if err != nil || len(pols) != 1 {
			t.Fatalf("list %s: %d rows, err=%v", orgID, len(pols), err)
		}
		var hash string
		if err := db.DB().QueryRow(`SELECT parameter_hash FROM policies WHERE id=?`, pols[0].ID).Scan(&hash); err != nil {
			t.Fatalf("read hash: %v", err)
		}
		return pols[0], hash
	}
	_, editedHashBefore := read(editedOrg)
	freshBefore, freshHashBefore := read(freshOrg)

	type recorded struct {
		orgID, summary string
		pol            Policy
	}
	var calls []recorded
	recorder := WithSeedUpgradeRecorder(func(orgID string, pol Policy, summary string) {
		if orgID == oldOrg || orgID == editedOrg || orgID == freshOrg {
			calls = append(calls, recorded{orgID, summary, pol})
		}
	})
	if _, err := NewStore(db, recorder); err != nil {
		t.Fatalf("startup: %v", err)
	}
	first, _ := read(oldOrg)
	if _, err := NewStore(db, recorder); err != nil {
		t.Fatalf("second startup: %v", err)
	}
	// The recorder (wired to the policy version history by the proxy) hears
	// about the one rewrite, once, with the full upgraded row.
	if len(calls) != 1 || calls[0].orgID != oldOrg || calls[0].pol.ID != first.ID ||
		!strings.Contains(calls[0].summary, "F19") ||
		!slicesEqual(normalizeHashStrings(calls[0].pol.Conditions.HiddenUnicodeKinds), []string{"bidi_override", "variation_selector"}) {
		t.Fatalf("seed-upgrade recorder calls = %+v, want one for %s/%s naming F19", calls, oldOrg, first.ID)
	}

	up, upHash := read(oldOrg)
	if !up.UpdatedAt.Equal(first.UpdatedAt) {
		t.Fatalf("second startup rewrote the upgraded row again (updated_at %v -> %v): not idempotent", first.UpdatedAt, up.UpdatedAt)
	}
	if !slicesEqual(normalizeHashStrings(up.Conditions.HiddenUnicodeKinds), []string{"bidi_override", "variation_selector"}) {
		t.Fatalf("old org rule not upgraded: kinds=%v", up.Conditions.HiddenUnicodeKinds)
	}
	if want, _ := PolicyParameterHash(up); upHash != want {
		t.Fatalf("upgraded row parameter_hash %q != recomputed %q", upHash, want)
	}
	if up.Mode != ModeBlock || up.Precedence != 150 || up.Status != StatusEnabled {
		t.Fatalf("upgrade changed more than the conditions: %+v", up)
	}
	ed, edHash := read(editedOrg)
	if !slicesEqual(ed.Conditions.HiddenUnicodeKinds, []string{"bidi_override"}) || edHash != editedHashBefore {
		t.Fatalf("user-edited rule was rewritten: kinds=%v", ed.Conditions.HiddenUnicodeKinds)
	}
	fr, frHash := read(freshOrg)
	if frHash != freshHashBefore || !fr.UpdatedAt.Equal(freshBefore.UpdatedAt) {
		t.Fatalf("fresh org's current rule was touched (updated_at %v -> %v)", freshBefore.UpdatedAt, fr.UpdatedAt)
	}
}
