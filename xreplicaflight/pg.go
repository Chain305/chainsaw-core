package xreplicaflight

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// PGFlight is the Postgres-advisory-lock-backed Flight implementation.
//
// Coordination protocol:
//
//  1. Hash the key to a 64-bit namespace (split into two int32s for
//     pg_advisory_xact_lock(hi, lo)). Collision is a false contention,
//     not a correctness issue — two unrelated keys that hash to the
//     same lock will serialize instead of running concurrently.
//
//  2. BEGIN a dedicated transaction and try pg_try_advisory_xact_lock.
//     If true, the caller is the leader: run fn, COMMIT (which
//     releases the lock), return fn's result.
//
//  3. If pg_try_advisory_xact_lock returned false, the caller is a
//     follower. Set a per-statement timeout, issue the blocking
//     pg_advisory_xact_lock. When it returns, the leader has
//     released — immediately COMMIT (we don't want to re-run fn,
//     only to re-read the cache) and call peek.
//
// We use the *_xact_lock variants so the lock is released automatically
// on commit or rollback. The session-scoped pg_advisory_lock variant
// would leak the lock if the replica crashed before explicit unlock.
type PGFlight struct {
	db  *sql.DB
	log *slog.Logger
}

// NewPG constructs a PGFlight. Pass the writable *sql.DB from the
// shared pgstore. A nil logger falls back to slog.Default.
func NewPG(db *sql.DB, log *slog.Logger) *PGFlight {
	if log == nil {
		log = slog.Default()
	}
	return &PGFlight{db: db, log: log}
}

// Do implements Flight against Postgres advisory locks.
func (p *PGFlight) Do(
	ctx context.Context,
	key string,
	timeout time.Duration,
	fn func(ctx context.Context) (any, error),
	peek func(ctx context.Context) (any, error),
) (any, error) {
	if p == nil || p.db == nil {
		// Belt and suspenders: if the caller wired a nil PGFlight we
		// still want correct behaviour, not a panic.
		return fn(ctx)
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	hi, lo := hashKey(key)

	// Leader attempt: separate transaction scoped to the duration of
	// fn. COMMIT at the end releases the lock.
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		// If we can't even open a tx, fall through and run fn directly
		// — we'd rather do N upstream fetches than fail the Scan.
		p.log.Debug("xreplicaflight: BeginTx failed, running fn directly", "err", err)
		return fn(ctx)
	}

	var acquired bool
	if err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock($1, $2)`, hi, lo).Scan(&acquired); err != nil {
		_ = tx.Rollback()
		p.log.Debug("xreplicaflight: pg_try_advisory_xact_lock failed, running fn directly", "err", err)
		return fn(ctx)
	}

	if acquired {
		// Leader path.
		result, fnErr := fn(ctx)
		// Always COMMIT to release the lock, even if fn errored — we
		// don't want followers blocked on a permanently-held lock.
		if cErr := tx.Commit(); cErr != nil {
			p.log.Warn("xreplicaflight: leader commit failed (lock released on connection close)", "err", cErr)
		}
		return result, fnErr
	}

	// Follower path: we already opened a tx but didn't get the lock.
	// Roll it back cleanly before the blocking wait so we don't hold
	// a transaction slot while we wait.
	_ = tx.Rollback()

	return p.waitAndPeek(ctx, hi, lo, timeout, peek)
}

// waitAndPeek is the follower path. It opens a fresh short-lived
// transaction, sets statement_timeout, issues the blocking
// pg_advisory_xact_lock, and on success immediately commits (releasing
// the lock) before calling peek.
func (p *PGFlight) waitAndPeek(
	ctx context.Context,
	hi, lo int32,
	timeout time.Duration,
	peek func(ctx context.Context) (any, error),
) (any, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("xreplicaflight: follower BeginTx: %w", err)
	}
	// statement_timeout must be LOCAL so it only applies to this tx.
	// Postgres accepts integer milliseconds via a literal.
	ms := timeout.Milliseconds()
	if ms <= 0 {
		ms = 1
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`SET LOCAL statement_timeout = %d`, ms)); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("xreplicaflight: set statement_timeout: %w", err)
	}

	// Blocking wait — will return when the leader commits, the
	// statement_timeout expires, or ctx is cancelled (pg's own
	// statement-level cancellation is wired through the driver).
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1, $2)`, hi, lo); err != nil {
		_ = tx.Rollback()
		if isTimeoutErr(err) {
			return nil, ErrFlightTimeout
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, fmt.Errorf("xreplicaflight: wait for leader: %w", err)
	}

	// We now hold the lock briefly — release it immediately so the
	// next follower isn't blocked on our peek. Commit is the release
	// path for xact-scoped locks.
	if err := tx.Commit(); err != nil {
		// Non-fatal: the lock will release when the connection goes
		// back to the pool (connection reset == session end).
		p.log.Debug("xreplicaflight: follower commit failed", "err", err)
	}

	// Re-read the cache. If peek returns nil, signal ErrLeaderCrashed
	// so callers can distinguish "I asked the follower to wait for
	// the leader and there's nothing to show for it" from a normal
	// cache miss.
	result, err := peek(ctx)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, ErrLeaderCrashed
	}
	return result, nil
}

// hashKey derives two 32-bit halves from a SHA-256 prefix of the key.
//
// Choice of SHA-256: we don't need cryptographic strength here — any
// well-mixed hash would do — but the stdlib already imports SHA-256 in
// several other places (internal/checksum, artifact digests), so this
// keeps the dependency surface flat. The top 8 bytes provide 2^64
// namespace; at chainsaw scale (~10^5 distinct package@version keys in
// flight), the Birthday-Paradox collision probability is ~3×10^-10.
// A collision causes false serialization, not a correctness bug.
//
// We return int32 (not uint32) because the stdlib's database/sql
// driver layer binds Go int32 → Postgres int4, which is the type
// pg_advisory_xact_lock(int, int) expects. uint32 > 2^31-1 would
// need an explicit cast on the Go side.
func hashKey(key string) (int32, int32) {
	sum := sha256.Sum256([]byte(key))
	hi := int32(binary.BigEndian.Uint32(sum[0:4]))
	lo := int32(binary.BigEndian.Uint32(sum[4:8]))
	return hi, lo
}

// isTimeoutErr recognises the Postgres statement_timeout SQLSTATE.
// Code "57014" = query_canceled. pgx surfaces it via its PgError type,
// but the stdlib sql package abstracts the driver layer, so we match
// on the error message instead of importing pgx here (keeping this
// package driver-agnostic matches the rest of internal/*).
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// "canceling statement due to statement timeout" — the canonical
	// message pg emits on statement_timeout.
	return contains(msg, "statement timeout") || contains(msg, "query_canceled") || contains(msg, "57014")
}

func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// Ensure PGFlight satisfies Flight at compile time.
var _ Flight = (*PGFlight)(nil)
