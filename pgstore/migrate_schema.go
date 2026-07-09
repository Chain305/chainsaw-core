package pgstore

import "fmt"

// ensureAnalyticsRollupSchema creates the analytics_daily_rollups table
// that materialises per-org daily aggregates for the customer-facing
// Insights dashboard (GTM W3). The rollup goroutine in
// internal/server/analytics_rollup.go is the sole writer; the read
// layer in internal/analytics/ falls back to scanning `events` directly
// when the rollup is empty (cold start, fresh installs, tests).
//
// The (org_id, date, metric_key) primary key keeps the table compact
// (4 metrics × 1 row/day/org) and the (org_id, date DESC) index serves
// the common "last 7d for my org" query pattern.
//
// metric_key values currently written: 'blocks', 'allowed', 'flagged',
// 'cache_hits'. `value` is JSONB so we can extend per-metric breakdowns
// (e.g. {"count": 42, "by_ecosystem": {"npm": 30, "pypi": 12}}) without
// another schema bump.
func (s *Store) ensureAnalyticsRollupSchema() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS analytics_daily_rollups (
		org_id TEXT NOT NULL,
		date DATE NOT NULL,
		metric_key TEXT NOT NULL,
		value TEXT NOT NULL DEFAULT '{}',
		updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (org_id, date, metric_key)
	)`); err != nil {
		return fmt.Errorf("create analytics_daily_rollups: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_analytics_daily_rollups_org_date ON analytics_daily_rollups(org_id, date DESC)`); err != nil {
		return fmt.Errorf("create analytics_daily_rollups org_date index: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_analytics_daily_rollups_metric ON analytics_daily_rollups(org_id, metric_key, date DESC)`); err != nil {
		return fmt.Errorf("create analytics_daily_rollups metric index: %w", err)
	}
	// Chain the intelligence-reports denorm-column migration so it runs
	// inside the same migrate() pass as the other Open-time schema
	// enforcements. Documented in docs/architecture/package-intelligence.md
	// (intelligence_reports table — `verdict`, `overall_score`); production
	// schemas were observed without them, which made the list-page filter
	// SQL fall back to scanning the JSONB column. Idempotent — see comment
	// on ensureIntelligenceReportsDenormColumns.
	if err := s.ensureIntelligenceReportsDenormColumns(); err != nil {
		return err
	}
	return nil
}

// ensureIntelligenceReportsDenormColumns adds the denormalised
// `verdict TEXT` and `overall_score INT` columns to
// `intelligence_reports`, plus their supporting indexes, and backfills
// both from the existing `risk_evaluation` JSONB column. Idempotent on
// every Open() — every statement uses `IF NOT EXISTS` and the backfill
// UPDATE is no-op when the columns are already populated.
//
// Why this exists: the architecture doc lists these columns as part of
// the table, but production schemas were observed without them, which
// meant the admin list-page filter API
// (?verdict=quarantine&sort=overall_score) was reading from the JSONB
// column on every row — fine on a fresh install, painful at scale.
// Adding the columns + indexes is the regression-proof fix.
func (s *Store) ensureIntelligenceReportsDenormColumns() error {
	if _, err := s.db.Exec(`ALTER TABLE intelligence_reports ADD COLUMN IF NOT EXISTS verdict TEXT`); err != nil {
		return fmt.Errorf("add intelligence_reports.verdict: %w", err)
	}
	if _, err := s.db.Exec(`ALTER TABLE intelligence_reports ADD COLUMN IF NOT EXISTS overall_score INT`); err != nil {
		return fmt.Errorf("add intelligence_reports.overall_score: %w", err)
	}
	// Backfill from the JSONB risk_evaluation column. Safe to re-run —
	// the WHERE clause skips rows that are already populated. The cast
	// to INT is on a JSON number, so jsonb arithmetic does not apply;
	// we extract as text and cast.
	if _, err := s.db.Exec(`UPDATE intelligence_reports
		SET verdict = COALESCE(verdict, risk_evaluation->>'verdict'),
		    overall_score = COALESCE(overall_score, NULLIF(risk_evaluation->'rolledUp'->>'overall', '')::INT)
		WHERE risk_evaluation IS NOT NULL
		  AND (verdict IS NULL OR overall_score IS NULL)`); err != nil {
		return fmt.Errorf("backfill intelligence_reports denorm: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_intelligence_reports_verdict ON intelligence_reports(verdict)`); err != nil {
		return fmt.Errorf("create idx_intelligence_reports_verdict: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_intelligence_reports_overall_score ON intelligence_reports(overall_score)`); err != nil {
		return fmt.Errorf("create idx_intelligence_reports_overall_score: %w", err)
	}
	return nil
}

// ensureSBOMSnapshotsSchema creates the sbom_snapshots table that backs the
// versioned SBOM store (Pain 7 — SBOM operationalization). Each row captures
// a frozen CycloneDX 1.6 BOM document plus the trigger that produced it. The
// pattern mirrors ensureComplianceAttestationsSchema — `CREATE TABLE IF NOT
// EXISTS` so a fresh DB and an upgraded DB converge to the same shape.
//
// AuthZ: every read MUST filter by org_id (callers are in
// internal/sbom/snapshot_store.go). The (org_id, taken_at DESC) index is the
// hot path for the /sbom Snapshots tab; the second index supports
// per-client snapshot history on the inventory by-client view.
//
// `trigger` is constrained to the four documented values so a typo at the
// call site fails loud at INSERT time rather than silently accumulating
// garbage data the dashboard can't classify.
//
// `sbom_doc` is JSONB on Postgres (we hint it via the column type; SQLite —
// used by tests — accepts JSONB transparently and stores it as TEXT).
func (s *Store) ensureSBOMSnapshotsSchema() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS sbom_snapshots (
		snapshot_id BIGSERIAL PRIMARY KEY,
		org_id TEXT NOT NULL,
		client_id TEXT,
		repo TEXT,
		taken_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
		trigger TEXT NOT NULL CHECK (trigger IN ('scheduled','manual','policy_violation','incident_response')),
		components_count INTEGER NOT NULL DEFAULT 0,
		sbom_doc TEXT NOT NULL DEFAULT '{}'
	)`); err != nil {
		return fmt.Errorf("create sbom_snapshots: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_sbom_snapshots_org_taken ON sbom_snapshots(org_id, taken_at DESC)`); err != nil {
		return fmt.Errorf("create sbom_snapshots org_taken index: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_sbom_snapshots_org_client_taken ON sbom_snapshots(org_id, client_id, taken_at DESC)`); err != nil {
		return fmt.Errorf("create sbom_snapshots org_client_taken index: %w", err)
	}
	// ADR-012 Item 4: persist the frozen transitive dependency graph +
	// per-package fired signals alongside each snapshot for point-in-time
	// audit. Additive nullable column — old rows stay NULL and read back
	// as an empty graph (see sbom.GetSnapshot / depgraph.Deserialize). It
	// is a SEPARATE column from sbom_doc so the byte-identical SBOM
	// download path is untouched. addColumnIfMissing is idempotent.
	if err := s.addColumnIfMissing("sbom_snapshots", "dep_graph_doc", "TEXT"); err != nil {
		return fmt.Errorf("backfill sbom_snapshots.dep_graph_doc: %w", err)
	}
	return nil
}

func (s *Store) ensurePlanAssignmentAndAuditSchema() error {
	// Referential integrity for org_plan_assignments.
	//   - plan_id: RESTRICT delete — prevents silently downgrading every
	//     affected org when a plan row vanishes.
	//   - org_id : CASCADE delete — orphan rows should not outlive the org.
	// Dedupe first to avoid FK violations on legacy rows that reference a
	// plan id that no longer exists.
	if _, err := s.db.Exec(`
		UPDATE org_plan_assignments
		SET plan_id = (SELECT id FROM pricing_plans WHERE is_default = 1 LIMIT 1),
		    assigned_at = CURRENT_TIMESTAMP
		WHERE plan_id IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM pricing_plans p WHERE p.id = org_plan_assignments.plan_id)
		  AND EXISTS (SELECT 1 FROM pricing_plans WHERE is_default = 1)
	`); err != nil {
		return fmt.Errorf("reconcile orphan plan assignments: %w", err)
	}
	if err := s.addConstraintIfMissing(
		"org_plan_assignments",
		"fk_org_plan_assignments_plan",
		"FOREIGN KEY (plan_id) REFERENCES pricing_plans(id) ON DELETE RESTRICT",
	); err != nil {
		return fmt.Errorf("add plan_id FK: %w", err)
	}
	if err := s.addConstraintIfMissing(
		"org_plan_assignments",
		"fk_org_plan_assignments_org",
		"FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE",
	); err != nil {
		return fmt.Errorf("add org_id FK: %w", err)
	}

	// Plan-change audit trail (fix 11). Separate from the repository `events`
	// table — that one is repo-op-only, this one captures admin / billing
	// surface mutations.
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS audit_events (
		id TEXT PRIMARY KEY,
		org_id TEXT NOT NULL,
		actor_user_id TEXT,
		actor_role TEXT,
		action TEXT NOT NULL,
		target_type TEXT,
		target_id TEXT,
		metadata TEXT NOT NULL DEFAULT '{}',
		created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
		correlation_id TEXT,
		prev_value TEXT,
		new_value TEXT
	)`); err != nil {
		return fmt.Errorf("create audit_events: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_events_org_created ON audit_events(org_id, created_at DESC)`); err != nil {
		return fmt.Errorf("create audit_events index: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action, created_at DESC)`); err != nil {
		return fmt.Errorf("create audit_events action index: %w", err)
	}
	// DESIGN.md §19 (D5/D6): backfill audit_events with correlation+diff
	// columns for older installs. addColumnIfMissing is idempotent and
	// nullable so pre-backfill rows remain legal.
	if err := s.addColumnIfMissing("audit_events", "correlation_id", "TEXT"); err != nil {
		return fmt.Errorf("backfill audit_events.correlation_id: %w", err)
	}
	if err := s.addColumnIfMissing("audit_events", "prev_value", "TEXT"); err != nil {
		return fmt.Errorf("backfill audit_events.prev_value: %w", err)
	}
	if err := s.addColumnIfMissing("audit_events", "new_value", "TEXT"); err != nil {
		return fmt.Errorf("backfill audit_events.new_value: %w", err)
	}
	// W7 — action-source tagging. Records the surface that triggered a
	// quarantine / exception / config mutation so retros can answer
	// "did this come from the inventory page, the coverage drawer, or
	// a bulk action?". Nullable (legacy rows stay NULL); writes are
	// validated against allowedActionSources in
	// internal/server/action_source.go.
	if err := s.addColumnIfMissing("audit_events", "source", "TEXT"); err != nil {
		return fmt.Errorf("backfill audit_events.source: %w", err)
	}
	if err := s.addColumnIfMissing("policies", "source", "TEXT"); err != nil {
		return fmt.Errorf("backfill policies.source: %w", err)
	}
	if err := s.addColumnIfMissing("index_entries", "quarantine_source", "TEXT"); err != nil {
		return fmt.Errorf("backfill index_entries.quarantine_source: %w", err)
	}

	if err := s.backfillDefaultPlanAssignment(); err != nil {
		return fmt.Errorf("backfill default plan: %w", err)
	}

	return nil
}

// ensureAgentActionLogSchema creates the agent_action_log table that records
// every mutating MCP tool call so undo_last_action and list_recent_actions
// can provide rollback and audit over the agent-driven surface.
func (s *Store) ensureAgentActionLogSchema() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS agent_action_log (
		id TEXT PRIMARY KEY,
		org_id TEXT NOT NULL,
		user_id TEXT NOT NULL DEFAULT '',
		agent_kind TEXT NOT NULL DEFAULT '',
		tool_name TEXT NOT NULL,
		action_type TEXT NOT NULL,
		target_id TEXT,
		target_name TEXT,
		before_state TEXT,
		after_state TEXT,
		undone_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("create agent_action_log: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_agent_action_log_org_created ON agent_action_log(org_id, created_at DESC)`); err != nil {
		return fmt.Errorf("create agent_action_log org index: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_agent_action_log_tool ON agent_action_log(tool_name, created_at DESC)`); err != nil {
		return fmt.Errorf("create agent_action_log tool index: %w", err)
	}
	// Backfill columns for existing deployments that have the old schema.
	if err := s.addColumnIfMissing("agent_action_log", "user_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("add agent_action_log.user_id: %w", err)
	}
	if err := s.addColumnIfMissing("agent_action_log", "before_state", "TEXT"); err != nil {
		return fmt.Errorf("add agent_action_log.before_state: %w", err)
	}
	if err := s.addColumnIfMissing("agent_action_log", "after_state", "TEXT"); err != nil {
		return fmt.Errorf("add agent_action_log.after_state: %w", err)
	}
	return nil
}

// ensureComplianceAttestationsSchema creates the compliance_attestations table
// that stores the latest posture report from each enrolled endpoint / CI runner.
// One row per (org_id, device_id) — reports upsert on conflict. Historical
// attestations are recorded as audit_events with action=compliance_reported,
// so this table only keeps the current state for fast dashboard queries.
func (s *Store) ensureComplianceAttestationsSchema() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS compliance_attestations (
		org_id TEXT NOT NULL,
		device_id TEXT NOT NULL,
		user_identifier TEXT NOT NULL DEFAULT '',
		mode TEXT NOT NULL DEFAULT 'monitor',
		ecosystems TEXT NOT NULL DEFAULT '{}',
		direct_registry_egress TEXT NOT NULL DEFAULT 'unknown',
		config_hash TEXT NOT NULL DEFAULT '',
		chainsaw_version TEXT NOT NULL DEFAULT '',
		platform TEXT NOT NULL DEFAULT '',
		last_remediated_at TIMESTAMPTZ,
		last_reported_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (org_id, device_id)
	)`); err != nil {
		return fmt.Errorf("create compliance_attestations: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_compliance_attestations_org_reported ON compliance_attestations(org_id, last_reported_at DESC)`); err != nil {
		return fmt.Errorf("create compliance_attestations reported index: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_compliance_attestations_egress ON compliance_attestations(org_id, direct_registry_egress)`); err != nil {
		return fmt.Errorf("create compliance_attestations egress index: %w", err)
	}
	return nil
}

// ensureInventoryOwnershipSchema creates the inventory_ownership_overrides
// table (ADR-006 Item 1). It records manual ownership claims that take
// precedence over CODEOWNERS resolution for an inventory repo (and,
// optionally, a single package within it). The canonical owning team is
// otherwise derived live from CODEOWNERS at read time
// (internal/server/inventory_ownership.go resolveOwningTeam); this table is
// only consulted as the highest-precedence override and is empty by default.
//
// AuthZ: every read/write MUST filter by org_id — the (org_id, repository,
// package_name) primary key is the tenant + target boundary. A row can claim
// an entire repo (package_name = ” sentinel) or a single named package. We
// use the empty-string sentinel rather than SQL NULL because Postgres forces
// every PRIMARY KEY column NOT NULL; ” is the portable "whole repo" key and
// is what resolveOwningTeam / upsertOwnershipOverride match on. Additive new
// table only — no existing table is altered.
func (s *Store) ensureInventoryOwnershipSchema() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS inventory_ownership_overrides (
		org_id TEXT NOT NULL,
		repository TEXT NOT NULL,
		package_name TEXT NOT NULL DEFAULT '',
		owning_team TEXT NOT NULL,
		claimed_by TEXT,
		claimed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (org_id, repository, package_name)
	)`); err != nil {
		return fmt.Errorf("create inventory_ownership_overrides: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_inventory_ownership_overrides_org_repo ON inventory_ownership_overrides(org_id, repository)`); err != nil {
		return fmt.Errorf("create inventory_ownership_overrides org_repo index: %w", err)
	}
	return nil
}

// ensureBillyProposalsSchema creates the billy_proposals table (ADR-002
// Item 5a). It records agent-proposed mutations through their approval
// lifecycle (pending → approved / rejected). This item ONLY persists the
// proposal + its approval decision — no mutation is executed here; the
// execute dispatcher (Item 5b) is a separately flagged, later item, so the
// executed_at / error columns exist for forward-compatibility but are never
// written by the propose/list/approve/reject surface.
//
// AuthZ: every read/write MUST filter by org_id. The
// (org_id, status, created_at DESC) index serves the hot "list my pending
// proposals" query. Additive new table only — no existing table is altered.
func (s *Store) ensureBillyProposalsSchema() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS billy_proposals (
		id TEXT PRIMARY KEY,
		org_id TEXT NOT NULL,
		proposed_by TEXT,
		action_type TEXT,
		params TEXT,
		reasoning TEXT,
		evidence TEXT,
		status TEXT NOT NULL DEFAULT 'pending',
		approver_id TEXT,
		decided_at TIMESTAMPTZ,
		executed_at TIMESTAMPTZ,
		error TEXT,
		created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("create billy_proposals: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_billy_proposals_org_status_created ON billy_proposals(org_id, status, created_at DESC)`); err != nil {
		return fmt.Errorf("create billy_proposals org_status_created index: %w", err)
	}
	return nil
}
