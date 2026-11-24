package intelligence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/chain305/chainsaw-core/pgstore"
)

// recordingDB is a database/sql driver that answers every query with no rows
// and records every write statement. It stands in for Postgres so a test can
// see EVERY shared table a Scan touches, not only intelligence_reports: the
// verdict_history insert inside Upsert, the artifact_analyses side table,
// the latest-probe table. The report sink (package_metadata) is counted
// separately by the caller.
type recordingDB struct {
	mu     sync.Mutex
	writes []string
}

func (d *recordingDB) record(q string) {
	if verb := strings.ToUpper(strings.Fields(strings.TrimSpace(q) + " x")[0]); verb == "INSERT" ||
		verb == "UPDATE" || verb == "DELETE" || verb == "MERGE" || verb == "WITH" {
		d.mu.Lock()
		d.writes = append(d.writes, strings.Join(strings.Fields(q), " "))
		d.mu.Unlock()
	}
}

func (d *recordingDB) Writes() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.writes...)
}

func (d *recordingDB) Connect(context.Context) (driver.Conn, error) { return recConn{d}, nil }
func (d *recordingDB) Driver() driver.Driver                        { return recDriver{d} }

type recDriver struct{ d *recordingDB }

func (r recDriver) Open(string) (driver.Conn, error) { return recConn(r), nil }

type recConn struct{ d *recordingDB }

func (c recConn) Prepare(q string) (driver.Stmt, error) { return recStmt{c.d, q}, nil }
func (c recConn) Close() error                          { return nil }
func (c recConn) Begin() (driver.Tx, error)             { return recTx{}, nil }
func (c recConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return recTx{}, nil
}
func (c recConn) ExecContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Result, error) {
	c.d.record(q)
	return driver.RowsAffected(1), nil
}
func (c recConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	c.d.record(q) // INSERT … RETURNING arrives here
	return emptyRows{}, nil
}

type recTx struct{}

func (recTx) Commit() error   { return nil }
func (recTx) Rollback() error { return nil }

type recStmt struct {
	d *recordingDB
	q string
}

func (s recStmt) Close() error  { return nil }
func (s recStmt) NumInput() int { return -1 }
func (s recStmt) Exec([]driver.Value) (driver.Result, error) {
	s.d.record(s.q)
	return driver.RowsAffected(1), nil
}
func (s recStmt) Query([]driver.Value) (driver.Rows, error) {
	s.d.record(s.q)
	return emptyRows{}, nil
}

type emptyRows struct{}

func (emptyRows) Columns() []string         { return []string{"c"} }
func (emptyRows) Close() error              { return nil }
func (emptyRows) Next([]driver.Value) error { return io.EOF }

// TestSecurityGuard_SharedIntelWriteSource is the RC3 class guard (pentest
// #39/#41/#4/#6/#15/#16/N-5/RT-N7): a Scan carrying bytes that did not come
// from the canonical public registry writes NOTHING shared — no
// intelligence_reports row, no verdict_history, no side table, no
// package_metadata projection — whatever Options the caller passed. The
// zero-value Source counts as tenant bytes (fail closed).
//
// The positive control is load-bearing: without it, a harness in which
// persistence never runs at all would pass the negative cases vacuously.
func TestSecurityGuard_SharedIntelWriteSource(t *testing.T) {
	key := Key{Ecosystem: "npm", Package: "left-pad", Version: "1.3.0"}

	scan := func(t *testing.T, src ArtifactSource) (writes []string, sinks int64) {
		t.Helper()
		rec := &recordingDB{}
		db := sql.OpenDB(rec)
		t.Cleanup(func() { _ = db.Close() })
		p := &fakeProvider{
			name:   "fake-bytes",
			signal: SignalMalware,
			partial: PartialReport{
				SupplyChain: &SupplyChainSection{MalwareStatus: "malicious"},
			},
		}
		svc := New(Config{Store: NewStore(pgstore.NewFromDB(db)), Providers: []Provider{p}})
		var n int64
		svc.SetReportSink(func(context.Context, string, *Report) { atomic.AddInt64(&n, 1) })
		rep, err := svc.Scan(context.Background(), Request{
			Key:   key,
			OrgID: "org-a",
			Artifact: &ArtifactHandle{
				Bytes:          []byte("org-controlled bytes"),
				ComputedSHA256: "deadbeef",
				Source:         src,
			},
			Options: Options{RefreshReason: "proxy_artifact"},
		})
		if err != nil || rep == nil {
			t.Fatalf("Scan(%q) = %v, %v", src, rep, err)
		}
		// The scan itself still runs: the org that owns the bytes gets a verdict.
		if rep.SupplyChain.MalwareStatus != "malicious" {
			t.Fatalf("Scan(%q) dropped the byte verdict: %+v", src, rep.SupplyChain)
		}
		return rec.Writes(), atomic.LoadInt64(&n)
	}

	t.Run("positive control: canonical registry bytes are persisted", func(t *testing.T) {
		writes, sinks := scan(t, ArtifactSourcePublicRegistry)
		upserted := false
		for _, w := range writes {
			if strings.Contains(w, "intelligence_reports") {
				upserted = true
			}
		}
		if !upserted || sinks != 1 {
			t.Fatalf("registry-sourced scan must upsert the shared row and run the sink once; "+
				"upserted=%v sinks=%d writes=%q", upserted, sinks, writes)
		}
	})

	for _, src := range []ArtifactSource{
		ArtifactSourceTenantUpload,
		ArtifactSourceTenantRemote,
		ArtifactSourceUnknown,
		ArtifactSource("registry"), // a near-miss spelling is still not the canonical source
	} {
		t.Run("no shared write for source "+string(src), func(t *testing.T) {
			writes, sinks := scan(t, src)
			if len(writes) != 0 || sinks != 0 {
				t.Fatalf("source %q reached shared state: %d write(s) %q, %d sink call(s)",
					src, len(writes), writes, sinks)
			}
		})
	}
}
