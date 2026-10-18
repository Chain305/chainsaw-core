package policy

// Guards for H-2 of plan_helm_chart: boot-time seeding runs under an
// advisory lock so two replicas cold-booting against one database cannot
// both read an empty org and collide on idx_policies_org_precedence_unique
// (which exits the process at boot).

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

// recordingDriver is a database/sql driver that records every statement
// and transaction boundary in order. Queries return no rows (an empty org),
// so seedPolicies takes its INSERT path.
type recordingDriver struct {
	mu  sync.Mutex
	log []string
}

func (d *recordingDriver) record(s string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.log = append(d.log, s)
}

func (d *recordingDriver) Open(string) (driver.Conn, error) { return &recordingConn{d: d}, nil }

type recordingConn struct{ d *recordingDriver }

func (c *recordingConn) Prepare(q string) (driver.Stmt, error) {
	return &recordingStmt{d: c.d, q: q}, nil
}
func (c *recordingConn) Close() error { return nil }
func (c *recordingConn) Begin() (driver.Tx, error) {
	c.d.record("BEGIN")
	return &recordingTx{d: c.d}, nil
}

type recordingTx struct{ d *recordingDriver }

func (t *recordingTx) Commit() error   { t.d.record("COMMIT"); return nil }
func (t *recordingTx) Rollback() error { t.d.record("ROLLBACK"); return nil }

type recordingStmt struct {
	d *recordingDriver
	q string
}

func (s *recordingStmt) Close() error  { return nil }
func (s *recordingStmt) NumInput() int { return -1 }
func (s *recordingStmt) Exec([]driver.Value) (driver.Result, error) {
	s.d.record(s.q)
	return driver.RowsAffected(1), nil
}
func (s *recordingStmt) Query([]driver.Value) (driver.Rows, error) {
	s.d.record(s.q)
	return emptyRows{}, nil
}

type emptyRows struct{}

func (emptyRows) Columns() []string         { return []string{"name", "precedence"} }
func (emptyRows) Close() error              { return nil }
func (emptyRows) Next([]driver.Value) error { return io.EOF }

func lockTestSeed() []Policy {
	yes := true
	return []Policy{{Name: "Block vulnerable packages", Precedence: 100, Mode: ModeBlock,
		Status: StatusEnabled, Conditions: Conditions{IsVulnerable: &yes}}}
}

// TestSeedTakesAdvisoryLockBeforeReading pins the order that makes the
// seed safe: BEGIN, the advisory lock, THEN the read of existing rows, the
// INSERT, COMMIT — all on one transaction. A lock taken after the read, or
// outside the transaction, leaves the race open.
func TestSeedTakesAdvisoryLockBeforeReading(t *testing.T) {
	d := &recordingDriver{}
	db := sql.OpenDB(driverConnector{d})
	defer db.Close()
	db.SetMaxOpenConns(1)

	n, err := seedPoliciesLocked(db, "org-lock", lockTestSeed())
	if err != nil || n != 1 {
		t.Fatalf("seedPoliciesLocked: created=%d err=%v; want 1, nil", n, err)
	}

	var kinds []string
	for _, s := range d.log {
		switch {
		case s == "BEGIN", s == "COMMIT", s == "ROLLBACK":
			kinds = append(kinds, s)
		case strings.Contains(s, "pg_advisory_xact_lock"):
			kinds = append(kinds, "LOCK")
		case strings.HasPrefix(strings.TrimSpace(s), "SELECT name, precedence FROM policies"):
			kinds = append(kinds, "READ")
		case strings.HasPrefix(strings.TrimSpace(s), "INSERT INTO policies"):
			kinds = append(kinds, "INSERT")
		default:
			kinds = append(kinds, "OTHER:"+s)
		}
	}
	got := strings.Join(kinds, " ")
	if want := "BEGIN LOCK READ INSERT COMMIT"; got != want {
		t.Fatalf("seed statement order = %q, want %q.\n"+
			"Two replicas seeding without the lock (or reading before it) both "+
			"see an empty org and the second INSERT exits the process at boot.", got, want)
	}
}

// driverConnector adapts recordingDriver to driver.Connector so the test
// needs no global sql.Register.
type driverConnector struct{ d *recordingDriver }

func (c driverConnector) Connect(context.Context) (driver.Conn, error) {
	return c.d.Open("")
}
func (c driverConnector) Driver() driver.Driver { return c.d }

// TestSeedConcurrentColdBootsDoNotCollide is the real race: several seeders
// at once against one empty org, as N replicas booting together. Without
// the lock some return the unique-precedence violation.
func TestSeedConcurrentColdBootsDoNotCollide(t *testing.T) {
	db, orgID := seedUpgradeTestOrg(t)
	seed := releaseNMinus1()

	const seeders = 8
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		errs  []error
		total int
		start = make(chan struct{})
	)
	for i := 0; i < seeders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			n, err := seedPoliciesLocked(db.DB(), orgID, seed)
			mu.Lock()
			defer mu.Unlock()
			total += n
			if err != nil {
				errs = append(errs, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if len(errs) > 0 {
		t.Fatalf("%d of %d concurrent seeders failed; first: %v", len(errs), seeders, errors.Join(errs...))
	}
	if total != len(seed) {
		t.Fatalf("concurrent seeders created %d rows in total, want %d", total, len(seed))
	}
	pols, err := (&Store{sql: db, orgID: orgID}).List()
	if err != nil || len(pols) != len(seed) {
		t.Fatalf("list: %d rows, err=%v; want %d", len(pols), err, len(seed))
	}
}
