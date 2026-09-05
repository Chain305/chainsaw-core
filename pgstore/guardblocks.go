package pgstore

// Local-guard block ledger (P9F-UD-06 / P9F-252).
//
// The free local guard already emits `install.guard.block` to
// /api/telemetry/ingest — but ONLY after the operator explicitly consented
// (see core/cli/telemetry_runtime.go's cliTelemetryConsented), and until now
// the server did nothing with it but forward it to PostHog. That is why
// `chainsaw guard status` could show 17 blocks while the dashboard showed a
// bare 0: nothing in internal/ or ui_new/ read the event. This file is the
// persistence half of closing that gap. Nothing new leaves the machine — the
// event already arrived; we now keep it.
//
// Two tables, because "no blocks" and "we cannot know" are different answers
// and the dashboard has to be able to tell them apart:
//
//   guard_block_events  — one row per refused install, org-scoped.
//   guard_installs      — one row per (org, install) that has sent ANY
//                         consented guard event. Zero rows means the org has
//                         no consented, signed-in installs, so a zero block
//                         count means "we cannot know", not "nothing was
//                         blocked".
//
// Identity model. The row is keyed on the org resolved SERVER-SIDE from the
// credential the event carried (the CLI sends `APIKey: cfgToken()`), never on
// the client-supplied `org_id` property, which is attacker-controlled. An
// event with no credential — the anonymous install: tier the ingest route
// deliberately accepts — resolves to no org and is NOT stored.
//
// What is deliberately NOT stored: no user_id, no IP, no hostname, no path.
// install_id is a per-machine opaque UUID the operator can reset, and it is
// the only identifier here. A guard block is a machine event; attributing it
// to a named human would be a new disclosure the consent prompt never asked
// for. The package payload (name/version/reason) is exactly what the D-NUDGE
// prompt describes as being shared on a block.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// GuardBlockRetentionDays mirrors the `retention: hot` tier the event
// registry assigns to install.guard.block (core/telemetry/events.yaml — hot
// is "90d, full resolution"). internal/datacleanup enforces it on a
// schedule; PruneGuardBlocksBefore is the in-process equivalent. See that
// method's doc comment for the split.
const GuardBlockRetentionDays = 90

// guardBlockFieldMax caps every free-text column so a hostile or buggy
// client cannot turn one accepted event into an unbounded row. Package
// names, versions and rule ids are all far below this in practice; the cap
// is a backstop, not a validation rule, so an over-long value is TRUNCATED
// rather than rejected (dropping a real block to protect a column would be
// the worse failure).
const guardBlockFieldMax = 256

// GuardBlock is one refused install, as persisted. Field names track the
// install.guard.block property names in core/telemetry/events.yaml
// (required: bin, ecosystem, severity; optional: package, version, reason —
// optional because refusal sharing is opt-out via
// CHAINSAW_REFUSAL_SHARING_DISABLED, so a consenting operator can still
// withhold the package identity and we must store the row anyway).
type GuardBlock struct {
	// OrgID is resolved server-side from the request credential. Never the
	// client-supplied org_id property.
	OrgID string
	// InstallID is the per-machine opaque UUID, with the "install:" prefix
	// already stripped.
	InstallID string
	// Bin is the package manager the guard fronted ("npm", "pip", …).
	Bin       string
	Ecosystem string
	// PackageName / PackageVersion are empty when the operator opted out of
	// refusal sharing.
	PackageName    string
	PackageVersion string
	// Reason is the guard's refusal reason / rule id.
	Reason string
	// Severity is the verdict severity the guard assigned.
	Severity string
	// BlockedAt is the event's own timestamp (when the block HAPPENED),
	// not when the batch reached the server. A guard flush can lag the
	// block by minutes, and the 24h dashboard window has to count the
	// block, not the delivery.
	BlockedAt time.Time
}

// NormalizeGuardBlock trims, caps and validates a block before it reaches
// SQL. Returns ok=false when the row must NOT be stored:
//
//   - no org  → the event was anonymous or the credential resolved to no
//     org. Storing it would either invent a tenant or leak into the default
//     org, which is the exact shape of the L-02 cross-tenant bug.
//   - no install id → nothing to attribute the block to.
//
// Everything else is best-effort: missing package identity is legitimate
// (refusal sharing opted out) and a zero timestamp falls back to `now` so a
// client with a broken clock still counts.
//
// Pure function on purpose — it is the half of this file that can be tested
// without a database.
func NormalizeGuardBlock(b GuardBlock, now time.Time) (GuardBlock, bool) {
	b.OrgID = strings.TrimSpace(b.OrgID)
	b.InstallID = clampGuardField(b.InstallID)
	if b.OrgID == "" || b.InstallID == "" {
		return GuardBlock{}, false
	}
	b.Bin = clampGuardField(b.Bin)
	b.Ecosystem = clampGuardField(b.Ecosystem)
	b.PackageName = clampGuardField(b.PackageName)
	b.PackageVersion = clampGuardField(b.PackageVersion)
	b.Reason = clampGuardField(b.Reason)
	b.Severity = clampGuardField(b.Severity)
	if b.BlockedAt.IsZero() {
		b.BlockedAt = now
	}
	b.BlockedAt = b.BlockedAt.UTC()
	return b, true
}

// clampGuardField trims whitespace and truncates to guardBlockFieldMax
// runes. Rune-based, not byte-based: cutting a multi-byte package name
// mid-rune would store invalid UTF-8, which Postgres rejects outright on a
// TEXT column and would turn a cosmetic cap into a dropped row.
func clampGuardField(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= guardBlockFieldMax {
		return s
	}
	r := []rune(s)
	if len(r) <= guardBlockFieldMax {
		return s
	}
	return string(r[:guardBlockFieldMax])
}

// RecordGuardBlock appends one block row and refreshes the sending
// install's last_seen_at in the same transaction, so an org can never end up
// with blocks it is told it cannot know about.
func (s *Store) RecordGuardBlock(ctx context.Context, b GuardBlock) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("pgstore: store not initialized")
	}
	norm, ok := NormalizeGuardBlock(b, time.Now().UTC())
	if !ok {
		return fmt.Errorf("pgstore: guard block missing org_id or install_id")
	}
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO guard_block_events
			   (org_id, install_id, bin, ecosystem, package_name, package_version, reason, severity, blocked_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			norm.OrgID, norm.InstallID, norm.Bin, norm.Ecosystem,
			norm.PackageName, norm.PackageVersion, norm.Reason, norm.Severity,
			norm.BlockedAt,
		); err != nil {
			return fmt.Errorf("insert guard block: %w", err)
		}
		if err := touchGuardInstallTx(ctx, tx, norm.OrgID, norm.InstallID, norm.BlockedAt); err != nil {
			return err
		}
		return nil
	})
}

// TouchGuardInstall records that (orgID, installID) is a consented,
// signed-in install that is sending guard telemetry right now. Called for
// EVERY accepted install.guard.* event, not just blocks — an install that is
// running clean and blocking nothing still has to register, otherwise a
// healthy org would be indistinguishable from an org with telemetry off.
func (s *Store) TouchGuardInstall(ctx context.Context, orgID, installID string, seenAt time.Time) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("pgstore: store not initialized")
	}
	orgID = strings.TrimSpace(orgID)
	installID = clampGuardField(installID)
	if orgID == "" || installID == "" {
		return fmt.Errorf("pgstore: guard install missing org_id or install_id")
	}
	if seenAt.IsZero() {
		seenAt = time.Now()
	}
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		return touchGuardInstallTx(ctx, tx, orgID, installID, seenAt.UTC())
	})
}

func touchGuardInstallTx(ctx context.Context, tx *sql.Tx, orgID, installID string, seenAt time.Time) error {
	// GREATEST on the update so an out-of-order batch (the guard buffers and
	// flushes, so events can arrive older than a row already written) cannot
	// walk last_seen_at backwards and make a live install look stale.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO guard_installs (org_id, install_id, first_seen_at, last_seen_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT (org_id, install_id) DO UPDATE
		   SET last_seen_at = GREATEST(guard_installs.last_seen_at, EXCLUDED.last_seen_at),
		       first_seen_at = LEAST(guard_installs.first_seen_at, EXCLUDED.first_seen_at)`,
		orgID, installID, seenAt, seenAt,
	); err != nil {
		return fmt.Errorf("upsert guard install: %w", err)
	}
	return nil
}

// CountGuardBlocksSince returns how many local-guard blocks the org's
// consented installs reported at or after `since`. Org-scoped by an equality
// predicate on the server-resolved org id — there is no code path that reads
// this table without one.
func (s *Store) CountGuardBlocksSince(ctx context.Context, orgID string, since time.Time) (int, error) {
	// The tenant check runs BEFORE the store check, deliberately: an empty
	// org is a caller bug that must surface even in a unit test with no
	// database, and there is no code path where an unscoped count is a
	// reasonable answer.
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return 0, fmt.Errorf("pgstore: empty org_id")
	}
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("pgstore: store not initialized")
	}
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM guard_block_events WHERE org_id = ? AND blocked_at >= ?`,
		orgID, since.UTC(),
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count guard blocks: %w", err)
	}
	return n, nil
}

// CountGuardInstallsSince returns how many of the org's installs have sent a
// consented guard event at or after `since`. This is the number that makes a
// zero block count honest: zero installs means the dashboard cannot know.
func (s *Store) CountGuardInstallsSince(ctx context.Context, orgID string, since time.Time) (int, error) {
	// Tenant check first — see CountGuardBlocksSince.
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return 0, fmt.Errorf("pgstore: empty org_id")
	}
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("pgstore: store not initialized")
	}
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM guard_installs WHERE org_id = ? AND last_seen_at >= ?`,
		orgID, since.UTC(),
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count guard installs: %w", err)
	}
	return n, nil
}

// PruneGuardBlocksBefore deletes block rows older than cutoff and returns
// how many went. It exists so the 90-day `hot` retention tier this table
// inherits from the event registry is ENFORCEABLE.
//
// Retention IS enforced now: internal/datacleanup prunes guard_block_events
// (and guard_installs behind it) on every pass, at
// datacleanup.DefaultGuardBlockDays, which is pinned equal to
// GuardBlockRetentionDays below by a test. The worker still runs only when
// an operator sets CHAINSAW_DATACLEANUP_ENABLED — default-off is the whole
// package's contract, not an oversight here — so on a deployment that never
// enables it this table still grows monotonically.
//
// The worker does NOT call this method. Its Store adapter holds a plain
// *sql.DB rather than a *pgstore.Store, so it issues the equivalent DELETE
// itself (datacleanup.SQLStore.PruneGuardBlockEvents), keyed on the same
// blocked_at column and the same window. This method is the in-process
// helper for pgstore-level callers and tests. Two statements deleting from
// one table on one policy is a drift risk: change one and change the other.
func (s *Store) PruneGuardBlocksBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("pgstore: store not initialized")
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM guard_block_events WHERE blocked_at < ?`, cutoff.UTC())
	if err != nil {
		return 0, fmt.Errorf("prune guard blocks: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return n, nil
}
