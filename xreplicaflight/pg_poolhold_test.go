package xreplicaflight

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

// A stub driver, so this test needs no Postgres. It answers exactly the
// four statements PGFlight issues (BEGIN/COMMIT/ROLLBACK are handled by
// database/sql itself) and reports pg_try_advisory_xact_lock as
// ACQUIRED, which puts PGFlight on its leader path.
//
// The point is not the SQL. It is db.Stats(): a *sql.DB hands out a
// finite number of connections, and this test measures how long the
// leader keeps one.

type stubConnector struct{}

func (stubConnector) Connect(context.Context) (driver.Conn, error) { return &stubConn{}, nil }
func (stubConnector) Driver() driver.Driver                        { return stubDriver{} }

type stubDriver struct{}

func (stubDriver) Open(string) (driver.Conn, error) { return &stubConn{}, nil }

type stubConn struct{}

func (c *stubConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c *stubConn) Close() error                        { return nil }
func (c *stubConn) Begin() (driver.Tx, error)           { return stubTx{}, nil }
func (c *stubConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return stubTx{}, nil
}
func (c *stubConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(0), nil
}
func (c *stubConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	// pg_try_advisory_xact_lock -> true (leader path)
	return &boolRows{val: true}, nil
}

type stubTx struct{}

func (stubTx) Commit() error   { return nil }
func (stubTx) Rollback() error { return nil }

type boolRows struct {
	val  bool
	done bool
}

func (r *boolRows) Columns() []string { return []string{"ok"} }
func (r *boolRows) Close() error      { return nil }
func (r *boolRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.val
	return nil
}

// TestPGFlight_LeaderDoesNotPinAConnectionAcrossFn pins the property the
// production pool depends on: a Scan's UPSTREAM work (registry HTTP, OSV,
// advisory feeds -- seconds to a minute) must not occupy a pooled database
// connection while it runs.
//
// PGFlight's leader path is BeginTx -> pg_try_advisory_xact_lock -> fn ->
// Commit. The lock is transaction-scoped, so the transaction -- and
// therefore one connection out of MaxOpenConns -- stays checked out for
// the whole of fn.
//
// THIS IS A LANDMINE, NOT A LIVE BUG. PGFlight is installed only when
// CHAINSAW_XREPLICA_SINGLEFLIGHT is set (core/intelligence/bootstrap.go);
// production does not set it and runs NoopFlight, whose Do calls fn
// directly and touches no database. This test was briefly published as a
// root cause of the 2026-09-14 outage and that claim is WITHDRAWN -- the
// mechanism there was volume from an unbounded cache-warm recursion, not
// held connections. See docs/PLANS_INTELLIGENCE.md#plan-scan-backpressure M1-B.
//
// It stays because the flag exists to be turned on. The day a
// multi-replica rollout sets it, every concurrent Scan begins pinning a
// connection for its whole fan-out, the pool ceiling silently becomes a
// concurrency ceiling, and crossing it sheds 503s onto every OTHER caller
// of the same pool -- including the unauthenticated public read path,
// which needs no scanning at all. Fix that before enabling the flag.
func TestPGFlight_LeaderDoesNotPinAConnectionAcrossFn(t *testing.T) {
	if os.Getenv("CHAINSAW_REPRO_M1") != "1" {
		t.Skip("REPRODUCTION, NOT A GUARD. This test FAILS on purpose today: it is the " +
			"red half of the red-before-green pair for docs/PLANS_INTELLIGENCE.md M1-B, " +
			"which is a LANDMINE in dormant code, not a live production bug -- PGFlight is " +
			"only installed when CHAINSAW_XREPLICA_SINGLEFLIGHT is set, and production does " +
			"not set it. Run with CHAINSAW_REPRO_M1=1 to watch it fail; it becomes an " +
			"always-on guard when the leader stops holding a pooled connection across fn, " +
			"which must happen BEFORE that flag is ever enabled.")
	}
	db := sql.OpenDB(stubConnector{})
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(4)

	f := NewPG(db, nil)

	var inUseDuringFn int
	var mu sync.Mutex
	running := make(chan struct{})
	release := make(chan struct{})

	go func() {
		_, _ = f.Do(context.Background(), "poolhold", time.Second,
			func(ctx context.Context) (any, error) {
				close(running)
				<-release // stand in for the upstream fan-out
				return "ok", nil
			},
			func(ctx context.Context) (any, error) { return nil, nil },
		)
	}()

	<-running
	// Let database/sql settle the checkout accounting.
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	inUseDuringFn = db.Stats().InUse
	mu.Unlock()
	close(release)

	if inUseDuringFn != 0 {
		t.Fatalf("leader holds %d pooled connection(s) for the entire duration of fn; "+
			"fn is the upstream fan-out, so N concurrent scans pin N connections and the "+
			"pool ceiling becomes a hidden concurrency ceiling for every other caller", inUseDuringFn)
	}
}
