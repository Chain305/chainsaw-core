package sbom

// snapshot_store.go owns the versioned-SBOM persistence layer (Pain 7).
//
// Design:
//   - One row per snapshot in `sbom_snapshots`. The CycloneDX 1.6 doc is
//     stored verbatim as JSON so /sbom Download serves the byte-equal
//     artifact the snapshotter generated, no rebuild required.
//   - Every read is hard-scoped by org_id at the SQL level. The handler
//     layer is REQUIRED to pass the caller's org through; there is no
//     "list all orgs" path. AuthZ is the snapshot store's load-bearing
//     property — leaking another tenant's SBOM exposes their dependency
//     surface, which is the same data class as a cross-tenant inventory
//     leak.
//   - Triggers are constrained at the schema level (see
//     ensureSBOMSnapshotsSchema). Pass one of the four exported Trigger*
//     constants and the CHECK constraint guards against typos at INSERT.
//   - Schema creation lives in pgstore.Store.ensureSBOMSnapshotsSchema
//     so the migrate() path is the single source of truth.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Trigger taxonomy. Mirrors the CHECK constraint in
// ensureSBOMSnapshotsSchema so a misspelled trigger fails at INSERT
// rather than silently corrupting the histogram.
const (
	TriggerScheduled        = "scheduled"
	TriggerManual           = "manual"
	TriggerPolicyViolation  = "policy_violation"
	TriggerIncidentResponse = "incident_response"
)

// ErrSnapshotNotFound is returned by GetSnapshot when no row matches the
// (org_id, snapshot_id) pair. Distinct from a SQL error so handler code
// can map it to 404 cleanly without inspecting driver-specific shapes.
var ErrSnapshotNotFound = errors.New("sbom snapshot not found")

// Snapshot is the in-memory projection of one sbom_snapshots row.
//
// SBOMDoc is the raw JSON CycloneDX 1.6 document — kept as []byte so the
// dashboard download path returns it untouched (byte-identical to what
// the snapshotter generated). When callers need the parsed shape they
// json.Unmarshal into *CycloneDXBOM themselves.
type Snapshot struct {
	SnapshotID      int64     `json:"snapshot_id"`
	OrgID           string    `json:"org_id"`
	ClientID        string    `json:"client_id,omitempty"`
	Repo            string    `json:"repo,omitempty"`
	TakenAt         time.Time `json:"taken_at"`
	Trigger         string    `json:"trigger"`
	ComponentsCount int       `json:"components_count"`
	SBOMDoc         []byte    `json:"-"` // omitted from list responses; surface separately

	// DepGraphDoc is the compact index-based dependency-graph document
	// (ADR-012 Item 4) — the transitive edge set plus per-package fired
	// signals frozen at snapshot time, for point-in-time audit. Stored in
	// a SEPARATE nullable column (dep_graph_doc) so the byte-identical
	// sbom_doc download path is untouched. Produced by
	// depgraph.Graph.Serialize and read back via depgraph.Deserialize.
	//
	// Additive / back-compat: nil on legacy rows written before the
	// column existed (and on ecosystems without a graph). Like SBOMDoc it
	// is omitted from list responses (size) and only loaded by
	// GetSnapshot.
	DepGraphDoc []byte `json:"-"`
}

// SnapshotFilters narrows ListSnapshots. Empty = no filter on that axis.
// Limit is capped to 200 by the store regardless of the caller value so
// a misbehaved client cannot exhaust memory listing the whole table.
type SnapshotFilters struct {
	ClientID string
	Repo     string
	Trigger  string
	Since    time.Time
	Limit    int
}

const maxSnapshotListLimit = 200

// validTrigger reports whether trigger is one of the four documented
// values. Returning a typed error here keeps the failure mode crisp at
// the API boundary instead of bouncing back from the DB CHECK constraint
// with a Postgres-specific error string.
func validTrigger(trigger string) bool {
	switch trigger {
	case TriggerScheduled, TriggerManual, TriggerPolicyViolation, TriggerIncidentResponse:
		return true
	default:
		return false
	}
}

// InsertSnapshot persists a new SBOM snapshot row and returns the
// generated snapshot_id. The caller owns the CycloneDX document — pass
// the bytes the SBOM generator emitted (or the JSON-marshalled
// *CycloneDXBOM) and the row stores them as-is.
//
// Empty org_id is rejected — it would be a tenant-isolation breach
// (every other-tenant query that filters WHERE org_id = ” would match).
func InsertSnapshot(ctx context.Context, db *sql.DB, snap Snapshot) (int64, error) {
	if db == nil {
		return 0, errors.New("sbom: nil db handle")
	}
	if strings.TrimSpace(snap.OrgID) == "" {
		return 0, errors.New("sbom: org_id required")
	}
	if !validTrigger(snap.Trigger) {
		return 0, fmt.Errorf("sbom: invalid trigger %q", snap.Trigger)
	}
	if len(snap.SBOMDoc) == 0 {
		// Stash an empty-bom marker rather than failing — a snapshot
		// with zero components is legitimate (a brand-new client that
		// hasn't installed anything yet) and the dashboard's Snapshots
		// tab still benefits from a row to anchor "last snapshot at".
		snap.SBOMDoc = []byte(`{}`)
	}
	if !json.Valid(snap.SBOMDoc) {
		return 0, errors.New("sbom: sbom_doc is not valid JSON")
	}
	if snap.TakenAt.IsZero() {
		snap.TakenAt = time.Now().UTC()
	}

	// dep_graph_doc is a SEPARATE nullable column (ADR-012 Item 4). When
	// the caller has no graph (legacy ecosystems, hot-path stubs) we store
	// NULL rather than a placeholder so GetSnapshot reads it back as an
	// empty graph — matching how a pre-column legacy row reads.
	var depGraphArg any
	if len(snap.DepGraphDoc) > 0 {
		depGraphArg = string(snap.DepGraphDoc)
	}

	var id int64
	// We use RETURNING because pgx/Postgres supports it cleanly; the
	// in-process tests that exercise this path use the same dialect.
	err := db.QueryRowContext(ctx,
		`INSERT INTO sbom_snapshots (org_id, client_id, repo, taken_at, trigger, components_count, sbom_doc, dep_graph_doc)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 RETURNING snapshot_id`,
		snap.OrgID, nullIfEmpty(snap.ClientID), nullIfEmpty(snap.Repo),
		snap.TakenAt, snap.Trigger, snap.ComponentsCount, string(snap.SBOMDoc), depGraphArg,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert sbom snapshot: %w", err)
	}
	return id, nil
}

// HasRecentScheduledSnapshot reports whether a `scheduled`-trigger snapshot
// exists for orgID with taken_at >= since. Pain 7 P1 fix (Validator A.3):
// the periodic snapshotter calls this before inserting an empty-component
// row so brand-new tenants don't accumulate dozens of empty-bom rows over
// the rollout window. A returning row counts regardless of components_count
// — the existence of any recent scheduled write is what we suppress on.
func HasRecentScheduledSnapshot(ctx context.Context, db *sql.DB, orgID string, since time.Time) (bool, error) {
	if db == nil {
		return false, errors.New("sbom: nil db handle")
	}
	if strings.TrimSpace(orgID) == "" {
		return false, errors.New("sbom: org_id required")
	}
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM sbom_snapshots
		 WHERE org_id = ? AND trigger = ? AND taken_at >= ?`,
		orgID, TriggerScheduled, since,
	).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("query recent scheduled snapshots: %w", err)
	}
	return n > 0, nil
}

// ListSnapshots returns metadata for snapshots owned by orgID, newest
// first. The SBOMDoc field is intentionally NOT populated — the body can
// be many MB per snapshot; loading the full set would punish the
// dashboard's Snapshots-list tab. Callers that want the body call
// GetSnapshot.
func ListSnapshots(ctx context.Context, db *sql.DB, orgID string, filters SnapshotFilters) ([]Snapshot, error) {
	if db == nil {
		return nil, errors.New("sbom: nil db handle")
	}
	if strings.TrimSpace(orgID) == "" {
		return nil, errors.New("sbom: org_id required")
	}
	limit := filters.Limit
	if limit <= 0 || limit > maxSnapshotListLimit {
		limit = maxSnapshotListLimit
	}

	// Compose dynamic WHERE clause. We append parameter placeholders only
	// for filters that were set; this keeps the query plan stable on the
	// common "no filters" path.
	var (
		conds = []string{"org_id = ?"}
		args  = []any{orgID}
	)
	if v := strings.TrimSpace(filters.ClientID); v != "" {
		conds = append(conds, "client_id = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(filters.Repo); v != "" {
		conds = append(conds, "repo = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(filters.Trigger); v != "" {
		if !validTrigger(v) {
			return nil, fmt.Errorf("sbom: invalid trigger filter %q", v)
		}
		conds = append(conds, "trigger = ?")
		args = append(args, v)
	}
	if !filters.Since.IsZero() {
		conds = append(conds, "taken_at >= ?")
		args = append(args, filters.Since)
	}
	args = append(args, limit)

	q := `SELECT snapshot_id, org_id, COALESCE(client_id, ''), COALESCE(repo, ''), taken_at, trigger, components_count
	      FROM sbom_snapshots
	      WHERE ` + strings.Join(conds, " AND ") + `
	      ORDER BY taken_at DESC
	      LIMIT ?`

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list sbom snapshots: %w", err)
	}
	defer rows.Close()

	var out []Snapshot
	for rows.Next() {
		var s Snapshot
		if err := rows.Scan(&s.SnapshotID, &s.OrgID, &s.ClientID, &s.Repo, &s.TakenAt, &s.Trigger, &s.ComponentsCount); err != nil {
			return nil, fmt.Errorf("scan sbom snapshot: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sbom snapshots: %w", err)
	}
	return out, nil
}

// GetSnapshot returns one snapshot — including the full SBOMDoc body —
// constrained to orgID. Returns ErrSnapshotNotFound when nothing matches
// so the handler layer can map it cleanly to HTTP 404.
//
// AuthZ: the (org_id, snapshot_id) pair MUST match. Even an admin
// inspecting another tenant's snapshot ID returns 404 — admins switch
// org context explicitly via the existing /admin path; cross-tenant
// reads do not silently succeed here.
func GetSnapshot(ctx context.Context, db *sql.DB, orgID string, snapshotID int64) (Snapshot, error) {
	if db == nil {
		return Snapshot{}, errors.New("sbom: nil db handle")
	}
	if strings.TrimSpace(orgID) == "" {
		return Snapshot{}, errors.New("sbom: org_id required")
	}
	if snapshotID <= 0 {
		return Snapshot{}, ErrSnapshotNotFound
	}
	var (
		snap        Snapshot
		docTxt      string
		depGraphTxt sql.NullString // nullable: legacy rows + non-graph ecosystems
	)
	err := db.QueryRowContext(ctx,
		`SELECT snapshot_id, org_id, COALESCE(client_id, ''), COALESCE(repo, ''),
		        taken_at, trigger, components_count, sbom_doc, dep_graph_doc
		   FROM sbom_snapshots
		  WHERE org_id = ? AND snapshot_id = ?`,
		orgID, snapshotID,
	).Scan(&snap.SnapshotID, &snap.OrgID, &snap.ClientID, &snap.Repo,
		&snap.TakenAt, &snap.Trigger, &snap.ComponentsCount, &docTxt, &depGraphTxt)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, ErrSnapshotNotFound
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("get sbom snapshot: %w", err)
	}
	snap.SBOMDoc = []byte(docTxt)
	// NULL dep_graph_doc (legacy row / no graph available) leaves
	// DepGraphDoc nil, which depgraph.Deserialize reads as an empty graph.
	if depGraphTxt.Valid && depGraphTxt.String != "" {
		snap.DepGraphDoc = []byte(depGraphTxt.String)
	}
	return snap, nil
}

// nullIfEmpty maps "" to a nil interface so the column stores NULL
// rather than an empty string. Keeps the (org_id, client_id, taken_at)
// index selective on the dashboard "all clients" path — empty client_id
// values would otherwise cluster under one btree entry.
func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}
