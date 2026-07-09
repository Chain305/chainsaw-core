package pgstore

import (
	"fmt"

	"github.com/chain305/chainsaw-core/tenancy"
)

// migrate applies the chainsaw schema idempotently via CREATE TABLE IF NOT EXISTS.
// This function is the SOURCE OF TRUTH for the schema. There is no separate
// migration-runner; every release boots through this function.
//
// TODO(migrations): wire a real migration runner (golang-migrate or goose) when
// schema needs go beyond what idempotent CREATE TABLE supports — i.e., when
// any of the following are required:
//   - ALTER TABLE on existing rows
//   - Data backfills
//   - Schema rollback
//
// See docs/MIGRATIONS.md for the documentary per-release record.
//
// by release just trades lines for files; the inline record is the per-release
// canonical history. Re-evaluate if it crosses 1500. TODO: refactor when a
// real migration runner lands (see "no migration runner" TODO above).
//
//nolint:funlen // Idempotent DDL list at 1043 lines (limit 1000). Splitting
func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT NOT NULL,
			value TEXT NOT NULL,
			org_id TEXT NOT NULL DEFAULT '` + tenancy.DefaultOrgID + `',
			PRIMARY KEY (org_id, key)
		)`,
		`CREATE TABLE IF NOT EXISTS orgs (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			slug TEXT NOT NULL UNIQUE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMPTZ
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			name TEXT,
			password_hash TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			disabled_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`,
		`CREATE TABLE IF NOT EXISTS memberships (
			org_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			role TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (org_id, user_id),
			FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_memberships_user_id ON memberships(user_id)`,
		`CREATE TABLE IF NOT EXISTS invitations (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			email TEXT NOT NULL,
			role TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			accepted_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_invitations_org_id ON invitations(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(email)`,
		`CREATE TABLE IF NOT EXISTS client_credentials (
			org_id TEXT NOT NULL,
			client_id TEXT NOT NULL,
			secret_hash TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			name TEXT,
			created_by_user_id TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ,
			disabled_at TIMESTAMPTZ,
			expiry_date TIMESTAMPTZ,
			authorized_repositories TEXT,
			PRIMARY KEY (org_id, client_id)
		)`,
		`CREATE TABLE IF NOT EXISTS repositories (
			org_id TEXT NOT NULL DEFAULT '` + tenancy.DefaultOrgID + `',
			name TEXT NOT NULL,
			format TEXT NOT NULL,
			type TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			anonymous_access INTEGER NOT NULL DEFAULT 0,
			remote_url TEXT NOT NULL,
			remote_proxy_url TEXT,
			remote_skip_tls INTEGER NOT NULL DEFAULT 0,
			remote_timeout_seconds INTEGER NOT NULL DEFAULT 60,
			remote_headers TEXT,
			cache_negative_ttl_seconds INTEGER NOT NULL DEFAULT 300,
			client_configuration_guide_template TEXT,
			public_base_url TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (org_id, name)
		)`,
		`CREATE TABLE IF NOT EXISTS index_entries (
			org_id TEXT NOT NULL,
			repository TEXT NOT NULL,
			package TEXT NOT NULL,
			version TEXT NOT NULL,
			format TEXT NOT NULL,
			logical_paths TEXT,
			quarantine_reason TEXT,
			quarantine_at TIMESTAMPTZ,
			quarantine_removed_artifacts INTEGER,
			PRIMARY KEY (org_id, repository, package, version)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_index_entries_org_repo ON index_entries(org_id, repository)`,
		`CREATE TABLE IF NOT EXISTS events (
			id BIGSERIAL PRIMARY KEY,
			org_id TEXT NOT NULL,
			recorded_at TIMESTAMPTZ NOT NULL,
			repository TEXT,
			format TEXT,
			logical_path TEXT,
			method TEXT,
			client_id TEXT,
			action TEXT,
			outcome TEXT,
			status_code INTEGER NOT NULL,
			package_name TEXT,
			package_version TEXT,
			version_requested TEXT,
			version_resolved TEXT,
			cache_status TEXT,
			bytes_upstream BIGINT,
			bytes_to_client BIGINT,
			failure_reason TEXT,
			rule_id TEXT,
			latency_ms BIGINT,
			requesting_ip TEXT,
			request_user_agent TEXT,
			requesting_country TEXT,
			scanner TEXT,
			severity TEXT,
			scanner_payload TEXT,
			correlation_id TEXT,
			prev_value TEXT,
			new_value TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_events_org_recorded_at ON events(org_id, recorded_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_events_org_client_id ON events(org_id, client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_events_bom ON events(org_id, package_name, format, client_id)`,
		// Composite indexes for common query patterns: violations, event listing, and install filters
		`CREATE INDEX IF NOT EXISTS idx_events_org_outcome_status ON events(org_id, outcome, status_code)`,
		`CREATE INDEX IF NOT EXISTS idx_events_org_repo_package ON events(org_id, repository, package_name)`,
		`CREATE INDEX IF NOT EXISTS idx_events_org_action_recorded ON events(org_id, action, recorded_at DESC)`,
		// Functional index for case-insensitive package name search (avoids LOWER() preventing index use)
		`CREATE INDEX IF NOT EXISTS idx_events_org_package_lower ON events(org_id, LOWER(package_name))`,
		`CREATE TABLE IF NOT EXISTS traffic_views (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			name TEXT NOT NULL,
			search_term TEXT,
			repository TEXT,
			start TEXT,
			"end" TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_views_org_created_at ON traffic_views(org_id, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS package_metadata (
			org_id TEXT NOT NULL,
			repository TEXT NOT NULL,
			package TEXT NOT NULL,
			version TEXT NOT NULL,
			license_spdx TEXT,
			package_release_date TIMESTAMPTZ,
			version_release_date TIMESTAMPTZ,
			sha256_hash TEXT,
			upstream_url TEXT,
			internal_package INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (org_id, repository, package, version)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_package_metadata_org_repo ON package_metadata(org_id, repository)`,
		`CREATE INDEX IF NOT EXISTS idx_package_metadata_org_internal ON package_metadata(org_id, internal_package)`,
		`CREATE TABLE IF NOT EXISTS vulnerability_metadata (
			org_id TEXT NOT NULL,
			repository TEXT NOT NULL,
			package TEXT NOT NULL,
			version TEXT NOT NULL,
			is_vulnerable INTEGER NOT NULL DEFAULT 0,
			cvss_score DOUBLE PRECISION,
			epss_score DOUBLE PRECISION,
			cves TEXT,
			cve_details JSONB,
			scanner_db_digest TEXT,
			scanned_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (org_id, repository, package, version)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vulnerability_metadata_org_vulnerable ON vulnerability_metadata(org_id, is_vulnerable)`,
		`CREATE INDEX IF NOT EXISTS idx_vulnerability_metadata_org_cvss ON vulnerability_metadata(org_id, cvss_score)`,
		// intelligence_reports is the canonical per-version record written
		// by internal/intelligence.DefaultService. Column mirrors are kept
		// for list/search (avoiding JSONB scans); the full Report lives in
		// the `report` JSONB blob. The table is universal — a report is
		// a fact about a package coordinate, not about a tenant — so the
		// primary key does not include org_id. Older installs that still
		// carry an org_id column are migrated below.
		`CREATE TABLE IF NOT EXISTS intelligence_reports (
			ecosystem         TEXT        NOT NULL,
			package_name      TEXT        NOT NULL,
			version           TEXT        NOT NULL,
			report            JSONB       NOT NULL,
			collected_at      TIMESTAMPTZ NOT NULL,
			fresh_until       TIMESTAMPTZ NOT NULL,
			artifact_sha256   TEXT,
			has_artifact_scan BOOLEAN     NOT NULL DEFAULT FALSE,
			is_malicious      BOOLEAN     NOT NULL DEFAULT FALSE,
			is_typosquat      BOOLEAN     NOT NULL DEFAULT FALSE,
			trust_score       INTEGER,
			max_cvss          REAL,
			warning_count     INTEGER     NOT NULL DEFAULT 0,
			PRIMARY KEY (ecosystem, package_name, version)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_intelligence_reports_collected_at ON intelligence_reports(collected_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_intelligence_reports_ecosystem ON intelligence_reports(ecosystem)`,
		`CREATE INDEX IF NOT EXISTS idx_intelligence_reports_malicious ON intelligence_reports(is_malicious) WHERE is_malicious = TRUE`,
		// Daily latest-version probe results, decoupled from per-version
		// reports so probing once per day works even when no single
		// version has been scanned yet. Universal cache — same rationale
		// as intelligence_reports above.
		`CREATE TABLE IF NOT EXISTS intelligence_latest_probes (
			ecosystem      TEXT        NOT NULL,
			package_name   TEXT        NOT NULL,
			latest_version TEXT,
			probed_at      TIMESTAMPTZ NOT NULL,
			fresh_until    TIMESTAMPTZ NOT NULL,
			error          TEXT,
			PRIMARY KEY (ecosystem, package_name)
		)`,
		// attestations stores verified provenance and SBOM attestations
		// produced by internal/provenance and internal/sbom. Like
		// intelligence_reports it is universal (a fact about a package
		// coordinate, not about a tenant) — the primary key does not
		// include org_id. Multiple attestation_types can coexist per
		// version (e.g. "sigstore" provenance plus "sbom"); within a
		// type the most-recent verification wins (UPSERT semantics).
		// The bundle column carries the raw signed envelope so callers
		// can re-verify offline or surface the full chain in audit views.
		`CREATE TABLE IF NOT EXISTS attestations (
			ecosystem            TEXT        NOT NULL,
			package_name         TEXT        NOT NULL,
			version              TEXT        NOT NULL,
			attestation_type     TEXT        NOT NULL,
			subject_digest       TEXT,
			bundle_format        TEXT,
			slsa_level           SMALLINT    NOT NULL DEFAULT 0,
			builder_id           TEXT,
			source_repo          TEXT,
			source_commit        TEXT,
			transparency_log_url TEXT,
			cache_stale          BOOLEAN     NOT NULL DEFAULT FALSE,
			bundle               BYTEA,
			verified_at          TIMESTAMPTZ NOT NULL,
			created_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (ecosystem, package_name, version, attestation_type)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_attestations_slsa_level
			ON attestations(slsa_level) WHERE slsa_level > 0`,
		`CREATE INDEX IF NOT EXISTS idx_attestations_builder_id
			ON attestations(builder_id) WHERE builder_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_attestations_source_repo
			ON attestations(source_repo) WHERE source_repo IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_attestations_verified_at
			ON attestations(verified_at DESC)`,
		// risk_engine_divergences was the shadow-mode delta table
		// between the (retired) legacy trustscore engine and the v2 risk
		// engine. Risk-V2 is now authoritative and nothing writes to or
		// reads from this table; the schema is retained as a no-op so
		// older deployments don't fail the IF-NOT-EXISTS migration step.
		// Drop in a future migration once all environments have been
		// observed empty.
		`CREATE TABLE IF NOT EXISTS risk_engine_divergences (
			org_id           TEXT        NOT NULL,
			ecosystem        TEXT        NOT NULL,
			package_name     TEXT        NOT NULL,
			version          TEXT        NOT NULL,
			legacy_score     INTEGER     NOT NULL,
			v2_score         INTEGER     NOT NULL,
			delta            INTEGER     NOT NULL,
			sample_count     INTEGER     NOT NULL DEFAULT 1,
			last_observed_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (org_id, ecosystem, package_name, version)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_risk_divergences_abs_delta
			ON risk_engine_divergences (org_id, abs(delta) DESC)`,
		// running_artifacts records observations from the K8s admission
		// webhook (when --enable-deployment-correlation is set on the
		// webhook side AND correlation.enabled=true on the proxy side).
		// One row per distinct (cluster, namespace, workload, image,
		// package coordinate) tuple; re-observing refreshes
		// last_observed_at. Backs internal/deploycorr.PGRecorder and
		// the "Running in production" badge on the dashboard CVE /
		// violation views. Pruned by the periodic sweeper after 30
		// days. The table is created unconditionally so toggling the
		// feature on at runtime is purely a flag flip — the schema
		// is always present, the writes / reads are flag-gated.
		`CREATE TABLE IF NOT EXISTS running_artifacts (
			org_id            TEXT        NOT NULL DEFAULT '',
			cluster           TEXT        NOT NULL DEFAULT '',
			namespace         TEXT        NOT NULL DEFAULT '',
			workload          TEXT        NOT NULL DEFAULT '',
			image_digest      TEXT        NOT NULL DEFAULT '',
			package_ecosystem TEXT        NOT NULL,
			package_name      TEXT        NOT NULL,
			package_version   TEXT        NOT NULL,
			last_observed_at  TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (org_id, cluster, namespace, workload, image_digest,
			             package_ecosystem, package_name, package_version)
		)`,
		// Idempotent migration for installs that created the table before
		// per-tenant scoping. Adds org_id with the same default as the
		// CREATE TABLE above, and rewrites the primary key to include it.
		// All three statements use IF [NOT] EXISTS so the migration runs
		// safely on every boot regardless of starting state.
		`ALTER TABLE running_artifacts ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE running_artifacts DROP CONSTRAINT IF EXISTS running_artifacts_pkey`,
		`ALTER TABLE running_artifacts ADD PRIMARY KEY (org_id, cluster, namespace, workload, image_digest, package_ecosystem, package_name, package_version)`,
		`CREATE INDEX IF NOT EXISTS idx_running_artifacts_pkg
			ON running_artifacts (org_id, package_ecosystem, package_name, package_version, last_observed_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_running_artifacts_observed
			ON running_artifacts (last_observed_at)`,
		// org_risk_weight_overrides stores per-org overrides for the v2
		// risk engine's category weights. Keyed on org_id so each org
		// holds at most one active override; populated/read via
		// internal/orgweights.PGStore and the /api/v1/intel/weights HTTP
		// surface. The weights JSONB is a sparse {category: weight} map
		// (only categories that differ from the package-level defaults
		// need to be stored).
		`CREATE TABLE IF NOT EXISTS org_risk_weight_overrides (
			org_id     TEXT PRIMARY KEY,
			weights    JSONB NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL,
			updated_by TEXT NOT NULL DEFAULT ''
		)`,
		// Per-signal weight overrides — finer-grained than the per-category
		// JSONB above. The read path is the bootstrap closure in
		// cmd/chainsaw-proxy/init_server.go that wires
		// intelligence.OrgSignalWeightsResolver against this table when
		// CHAINSAW_RISK_THRESHOLD_OVERRIDES_ENABLED is set; absent a row the
		// engine uses the const defaults from the registry.
		`CREATE TABLE IF NOT EXISTS risk_weight_overrides (
			id         BIGSERIAL PRIMARY KEY,
			org_id     TEXT NOT NULL,
			signal_id  TEXT NOT NULL,
			weight     INTEGER NOT NULL,
			updated_by TEXT,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_risk_weight_overrides_org_signal
			ON risk_weight_overrides(org_id, signal_id)`,
		`CREATE INDEX IF NOT EXISTS idx_risk_weight_overrides_org
			ON risk_weight_overrides(org_id)`,
		// W0+ slice: audit linkage for the simulate-required gate.
		// When PUT /api/v1/intel/weights ships with a simulate_id,
		// we record it here so an audit consumer can join the saved
		// override to the preview that gated it. Nullable for legacy
		// rows that pre-date the column.
		`ALTER TABLE risk_weight_overrides ADD COLUMN IF NOT EXISTS simulate_id TEXT`,
		`ALTER TABLE org_risk_weight_overrides ADD COLUMN IF NOT EXISTS simulate_id TEXT`,
		`CREATE TABLE IF NOT EXISTS data_source_status (
			org_id TEXT NOT NULL,
			source TEXT NOT NULL,
			last_attempt_at TIMESTAMPTZ,
			last_success_at TIMESTAMPTZ,
			next_run_at TIMESTAMPTZ,
			version_or_digest TEXT,
			last_error TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (org_id, source)
		)`,
		`CREATE TABLE IF NOT EXISTS cve_epss (
			cve TEXT PRIMARY KEY,
			score DOUBLE PRECISION NOT NULL DEFAULT 0,
			percentile DOUBLE PRECISION NOT NULL DEFAULT 0,
			published_date TEXT,
			fetched_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			raw_payload TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS policies (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			name TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			-- BUG-MCP-5: BIGINT (not INTEGER). Exception policies use
			-- int(-time.Now().UnixNano()) as their precedence (see
			-- exceptionsAPI.buildExceptionPolicy) so the column must
			-- accommodate the full int64 range. INTEGER (int4) overflows
			-- as soon as the nanos timestamp exceeds 2^31, which has
			-- been true for every wall clock for decades, and surfaced
			-- as a Postgres "encode ... into binary format for int4"
			-- error every time an agent called chainsaw_request_exception
			-- or propose_exception.
			precedence BIGINT NOT NULL DEFAULT 0,
			mode TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'enabled',
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			identifier TEXT,
			conditions TEXT,
			policy_scope TEXT,
			parameter_hash TEXT NOT NULL DEFAULT '',
			decision TEXT,
			cve TEXT,
			note TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_policies_org_precedence ON policies(org_id, precedence ASC, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_policies_org_status ON policies(org_id, status)`,
		`CREATE TABLE IF NOT EXISTS groups (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			type TEXT NOT NULL,
			name TEXT NOT NULL,
			members TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_groups_org_type ON groups(org_id, type)`,
		`CREATE INDEX IF NOT EXISTS idx_groups_org_name ON groups(org_id, name)`,
		`CREATE TABLE IF NOT EXISTS custom_roles (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			slug TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			permissions TEXT NOT NULL DEFAULT '[]',
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMPTZ,
			UNIQUE(org_id, slug)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_custom_roles_org_slug ON custom_roles(org_id, slug)`,
		`CREATE INDEX IF NOT EXISTS idx_custom_roles_org_deleted ON custom_roles(org_id, deleted_at)`,
		`CREATE TABLE IF NOT EXISTS revoked_tokens (
			token_hash TEXT PRIMARY KEY,
			expires_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens(expires_at)`,
		`CREATE TABLE IF NOT EXISTS password_reset_tokens (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			email TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			used_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_hash ON password_reset_tokens(token_hash)`,
		`CREATE TABLE IF NOT EXISTS email_verification_tokens (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			email TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			used_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_hash ON email_verification_tokens(token_hash)`,
		`CREATE TABLE IF NOT EXISTS webhooks (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			url TEXT NOT NULL,
			secret TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webhooks_org_user ON webhooks(org_id, user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_webhooks_org_enabled ON webhooks(org_id, enabled)`,
		`CREATE TABLE IF NOT EXISTS siem_integrations (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			name TEXT NOT NULL,
			provider TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			config TEXT NOT NULL DEFAULT '{}',
			secret TEXT,
			last_event_id BIGINT NOT NULL DEFAULT 0,
			last_delivery_at TIMESTAMPTZ,
			last_error TEXT,
			created_by_user_id TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_siem_integrations_org_enabled ON siem_integrations(org_id, enabled)`,
		`CREATE INDEX IF NOT EXISTS idx_siem_integrations_provider ON siem_integrations(provider)`,
		`CREATE TABLE IF NOT EXISTS recovery_codes (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			code_hash TEXT NOT NULL,
			used_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_recovery_codes_user_id ON recovery_codes(user_id)`,

		// SSO tables
		`CREATE TABLE IF NOT EXISTS sso_providers (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL UNIQUE,
			issuer_url TEXT NOT NULL,
			client_id TEXT NOT NULL,
			client_secret TEXT NOT NULL,
			scopes TEXT NOT NULL DEFAULT 'openid email profile',
			allowed_domains TEXT,
			jit_provisioning INTEGER NOT NULL DEFAULT 0,
			default_role TEXT NOT NULL DEFAULT 'org-member',
			skip_2fa INTEGER NOT NULL DEFAULT 1,
			enabled INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sso_providers_org_id ON sso_providers(org_id)`,
		`CREATE TABLE IF NOT EXISTS sso_identities (
			id TEXT PRIMARY KEY,
			provider_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			external_sub TEXT NOT NULL,
			external_email TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(provider_id, external_sub),
			FOREIGN KEY (provider_id) REFERENCES sso_providers(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sso_identities_user_id ON sso_identities(user_id)`,
		`CREATE TABLE IF NOT EXISTS sso_states (
			state_hash TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			nonce_hash TEXT NOT NULL,
			code_verifier TEXT NOT NULL,
			redirect_uri TEXT,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,

		// Internal package registry tables
		`CREATE TABLE IF NOT EXISTS package_slugs (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			repository TEXT NOT NULL,
			package_name TEXT NOT NULL,
			format TEXT NOT NULL,
			description TEXT,
			created_by TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMPTZ,
			UNIQUE (org_id, repository, package_name)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_package_slugs_org_repo ON package_slugs(org_id, repository)`,
		`CREATE INDEX IF NOT EXISTS idx_package_slugs_org_name ON package_slugs(org_id, package_name)`,
		`CREATE TABLE IF NOT EXISTS package_versions (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			repository TEXT NOT NULL,
			package_name TEXT NOT NULL,
			version TEXT NOT NULL,
			format TEXT NOT NULL,
			logical_path TEXT NOT NULL,
			sha256_hash TEXT,
			size_bytes BIGINT,
			content_type TEXT,
			uploaded_by_client_id TEXT,
			uploaded_by_user_id TEXT,
			metadata TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMPTZ,
			UNIQUE (org_id, repository, package_name, version)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_package_versions_org_repo ON package_versions(org_id, repository)`,
		`CREATE INDEX IF NOT EXISTS idx_package_versions_org_pkg ON package_versions(org_id, repository, package_name)`,
		`CREATE INDEX IF NOT EXISTS idx_package_versions_deleted ON package_versions(org_id, deleted_at)`,
		`CREATE TABLE IF NOT EXISTS package_permissions (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			client_id TEXT NOT NULL,
			pattern TEXT NOT NULL,
			repository TEXT,
			allow_read INTEGER NOT NULL DEFAULT 1,
			allow_write INTEGER NOT NULL DEFAULT 0,
			created_by TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_package_permissions_unique ON package_permissions(org_id, client_id, pattern, COALESCE(repository, ''))`,
		`CREATE INDEX IF NOT EXISTS idx_package_permissions_org_client ON package_permissions(org_id, client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_package_permissions_org_pattern ON package_permissions(org_id, pattern)`,

		// Billy chat agent conversation history
		`CREATE TABLE IF NOT EXISTS billy_messages (
			id BIGSERIAL PRIMARY KEY,
			org_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			role TEXT NOT NULL,
			content TEXT NOT NULL,
			tool_call_id TEXT,
			tool_calls JSONB,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_billy_messages_org_user ON billy_messages(org_id, user_id, created_at)`,

		// Billy LLM-call ledger. One row per OpenRouter Complete() call —
		// the durable companion to the OTel span at billy.llm_complete.
		// Spans are great for debugging a single trace; this table is the
		// queryable source of truth for "how much are we spending per org",
		// "what's the failover %", "which iteration did the agent loop
		// actually answer on". Schema is intentionally narrow — fields we
		// know we need today, more land alongside the failover-envelope
		// work (see plan_*.md remediation backlog).
		`CREATE TABLE IF NOT EXISTS billy_call_logs (
			id BIGSERIAL PRIMARY KEY,
			org_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			model TEXT NOT NULL DEFAULT '',
			iteration INTEGER NOT NULL DEFAULT 0,
			duration_ms BIGINT NOT NULL DEFAULT 0,
			input_msg_count INTEGER NOT NULL DEFAULT 0,
			input_chars BIGINT NOT NULL DEFAULT 0,
			output_chars BIGINT NOT NULL DEFAULT 0,
			tool_call_count INTEGER NOT NULL DEFAULT 0,
			error_class TEXT NOT NULL DEFAULT '',
			attempt_count INTEGER NOT NULL DEFAULT 1,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		// Idempotent backfill for existing deployments that ran the
		// pre-failover schema. NULL is impossible (NOT NULL) so we
		// rely on the column being absent on the old shape.
		`ALTER TABLE billy_call_logs ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 1`,
		`CREATE INDEX IF NOT EXISTS idx_billy_call_logs_org_created_at ON billy_call_logs(org_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_billy_call_logs_error_class ON billy_call_logs(error_class) WHERE error_class <> ''`,
		// created_at-leading index for the ledger-retention worker's
		// `DELETE ... WHERE created_at < NOW() - INTERVAL` prune. The
		// org-leading index above can't drive that range scan; this one
		// lets the retention DELETE find expired rows without a seq scan.
		`CREATE INDEX IF NOT EXISTS idx_billy_call_logs_created_at ON billy_call_logs(created_at)`,

		// Billy safety-event ledger. Persists every guard rejection,
		// rate-limit denial, and schema violation surfaced on Billy's
		// request path. Distinct from billy_call_logs — that table is the
		// "what happened to the LLM call" log; this is the "what did we
		// refuse to do, and why" log. Auditors and ops both want to see
		// these, and slog lines aren't queryable.
		`CREATE TABLE IF NOT EXISTS billy_safety_events (
			id BIGSERIAL PRIMARY KEY,
			org_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			tool_name TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL DEFAULT '',
			excerpt TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_billy_safety_events_org_created_at ON billy_safety_events(org_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_billy_safety_events_kind ON billy_safety_events(kind, created_at DESC)`,
		// created_at-leading index for the ledger-retention worker's prune
		// DELETE; see the matching index on billy_call_logs above.
		`CREATE INDEX IF NOT EXISTS idx_billy_safety_events_created_at ON billy_safety_events(created_at)`,

		// SSO group-to-role mappings (PAM integration)
		`CREATE TABLE IF NOT EXISTS sso_group_mappings (
			id TEXT PRIMARY KEY,
			provider_id TEXT NOT NULL,
			org_id TEXT NOT NULL,
			idp_group_value TEXT NOT NULL,
			chainsaw_role TEXT NOT NULL,
			priority INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(provider_id, idp_group_value),
			FOREIGN KEY (provider_id) REFERENCES sso_providers(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sso_group_mappings_provider ON sso_group_mappings(provider_id)`,
		`ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS group_claim_name TEXT NOT NULL DEFAULT 'groups'`,

		// SAML SSO support columns
		`ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS protocol TEXT NOT NULL DEFAULT 'oidc'`,
		`ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS saml_idp_metadata_url TEXT`,
		`ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS saml_idp_metadata_xml TEXT`,
		`ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS saml_sp_cert TEXT`,
		`ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS saml_sp_key TEXT`,
		`ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS saml_name_id_format TEXT DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'`,
		`ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS saml_attribute_email TEXT DEFAULT 'email'`,
		`ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS saml_attribute_name TEXT DEFAULT 'displayName'`,
		`ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS saml_attribute_groups TEXT DEFAULT 'groups'`,

		// Break-glass support — UX_AUDIT §8.7 / Principle 8 (lock-out is
		// impossible by design). break_glass_user_id references the org-owner
		// who keeps password-login as a fallback once SSO is enabled.
		// notify_owners controls whether an email summary is fired when this
		// row changes.
		`ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS break_glass_user_id TEXT`,
		`ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS notify_owners INTEGER NOT NULL DEFAULT 1`,

		// SCIM provisioning tables
		`CREATE TABLE IF NOT EXISTS scim_tokens (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			last_used_at TIMESTAMPTZ,
			created_by_user_id TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMPTZ,
			FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_scim_tokens_org ON scim_tokens(org_id)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS scim_external_id TEXT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS provisioned_by TEXT DEFAULT 'manual'`,

		// Usage-based pricing tables
		`CREATE TABLE IF NOT EXISTS usage_rollups (
			org_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			period_start TIMESTAMPTZ NOT NULL,
			bandwidth_bytes_in BIGINT NOT NULL DEFAULT 0,
			bandwidth_bytes_out BIGINT NOT NULL DEFAULT 0,
			request_count BIGINT NOT NULL DEFAULT 0,
			download_count BIGINT NOT NULL DEFAULT 0,
			upload_count BIGINT NOT NULL DEFAULT 0,
			PRIMARY KEY (org_id, user_id, period_start)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_usage_rollups_org_period ON usage_rollups(org_id, period_start DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_usage_rollups_user_period ON usage_rollups(user_id, period_start DESC)`,

		`CREATE TABLE IF NOT EXISTS pricing_plans (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			storage_bytes_limit BIGINT NOT NULL DEFAULT 0,
			bandwidth_bytes_limit BIGINT NOT NULL DEFAULT 0,
			price_per_gb_storage_cents BIGINT NOT NULL DEFAULT 0,
			price_per_gb_bandwidth_cents BIGINT NOT NULL DEFAULT 0,
			base_price_cents BIGINT NOT NULL DEFAULT 0,
			billing_period TEXT NOT NULL DEFAULT 'monthly',
			is_default INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS org_plan_assignments (
			org_id TEXT PRIMARY KEY,
			plan_id TEXT NOT NULL,
			billing_period_start TIMESTAMPTZ NOT NULL,
			billing_period_end TIMESTAMPTZ NOT NULL,
			assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,

		// Per-repository usage rollups for repo-level breakdown
		`CREATE TABLE IF NOT EXISTS repo_usage_rollups (
			org_id TEXT NOT NULL,
			repository TEXT NOT NULL,
			period_start TIMESTAMPTZ NOT NULL,
			bandwidth_bytes_in BIGINT NOT NULL DEFAULT 0,
			bandwidth_bytes_out BIGINT NOT NULL DEFAULT 0,
			request_count BIGINT NOT NULL DEFAULT 0,
			download_count BIGINT NOT NULL DEFAULT 0,
			upload_count BIGINT NOT NULL DEFAULT 0,
			PRIMARY KEY (org_id, repository, period_start)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_repo_usage_rollups_org_period ON repo_usage_rollups(org_id, period_start DESC)`,

		// High-watermark storage tracking per billing period
		`CREATE TABLE IF NOT EXISTS storage_watermarks (
			org_id TEXT NOT NULL,
			billing_month TEXT NOT NULL,
			peak_storage_bytes BIGINT NOT NULL DEFAULT 0,
			current_storage_bytes BIGINT NOT NULL DEFAULT 0,
			measured_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (org_id, billing_month)
		)`,

		// Configurable org-level usage limits (overrides plan defaults)
		`CREATE TABLE IF NOT EXISTS org_usage_limits (
			org_id TEXT PRIMARY KEY,
			storage_limit_bytes BIGINT NOT NULL DEFAULT 0,
			bandwidth_limit_bytes BIGINT NOT NULL DEFAULT 0,
			overage_policy TEXT NOT NULL DEFAULT 'warn',
			overage_cap_percent INTEGER NOT NULL DEFAULT 200,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,

		// Performance indexes: violation timeline queries (dashboard.go)
		`CREATE INDEX IF NOT EXISTS idx_events_org_repo_pkg_recorded ON events(org_id, repository, package_name, recorded_at DESC)`,
		// Performance indexes: violation listing ORDER BY recorded_at (violations_query.go)
		`CREATE INDEX IF NOT EXISTS idx_events_org_outcome_recorded ON events(org_id, outcome, recorded_at DESC)`,
		// Performance indexes: covering index for auth hot-path role lookups (auth.go)
		`CREATE INDEX IF NOT EXISTS idx_memberships_user_org_role ON memberships(user_id, org_id, role)`,
		// Performance indexes: usage analytics client credential grouping (usage.go)
		`CREATE INDEX IF NOT EXISTS idx_client_credentials_org_created_by ON client_credentials(org_id, created_by_user_id)`,
		// Performance indexes: usage analytics package uploads by user (usage.go)
		`CREATE INDEX IF NOT EXISTS idx_package_versions_org_uploaded_by ON package_versions(org_id, uploaded_by_user_id)`,

		// Onboarding redesign — see /ONBOARDING_REDESIGN_BACKEND.md §2.
		// Persona is UX tailoring only; never used for permission decisions.
		// Stored as free-form TEXT (not CHECK-constrained) to stay permissive
		// on future persona additions.
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS persona TEXT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS persona_inferred INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_skipped_at TIMESTAMPTZ`,
		`ALTER TABLE orgs ADD COLUMN IF NOT EXISTS default_persona TEXT`,
		`ALTER TABLE orgs ADD COLUMN IF NOT EXISTS allow_nonbusiness_invites INTEGER NOT NULL DEFAULT 0`,
		// WS4 #4 — opt-in public "blocked N packages" badge. OFF by
		// default (0): the badge endpoint (/api/public/badge/blocked/{slug})
		// 404s for any org that hasn't explicitly opted in, so a per-org
		// block count is never leaked on the public surface without consent.
		// An org admin flips it via PATCH /api/orgs/{id}/settings
		// {"badge_blocked_public": true}. See docs/plan_10of10_surfaces.md.
		`ALTER TABLE orgs ADD COLUMN IF NOT EXISTS badge_blocked_public INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE invitations ADD COLUMN IF NOT EXISTS suggested_persona TEXT`,
		// Pending-invitations management surface (UX_AUDIT.md §8.4 P0):
		// the manager dashboard needs to list, resend, and revoke pending
		// invitations. revoked_at marks an invitation soft-deleted (we
		// keep the row for audit). last_action / last_action_at track the
		// most recent admin action so the UI can show "resent 2h ago".
		`ALTER TABLE invitations ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ`,
		`ALTER TABLE invitations ADD COLUMN IF NOT EXISTS last_action TEXT`,
		`ALTER TABLE invitations ADD COLUMN IF NOT EXISTS last_action_at TIMESTAMPTZ`,
		// WS4 #7 — referral attribution. invited_by records the inviting
		// user so an accepted invitation can be attributed back to the
		// referrer (the org is already on invitations.org_id). Nullable:
		// pre-existing rows and non-invite membership paths leave it NULL.
		`ALTER TABLE invitations ADD COLUMN IF NOT EXISTS invited_by TEXT`,
		// WS4 #7 — referral attribution ledger. One row per invited user
		// who accepted, capturing WHO referred them (referring org +
		// inviter). alias_completed_at stays NULL until that user's install
		// aliases to their user_id — the "completed alias" that makes the
		// referral incentive-eligible. incentive_status starts 'pending'
		// and is advanced by a separate (follow-up) incentive-crediting
		// path; NOTHING here credits an incentive. user_id is the PK so an
		// accept + re-accept is idempotent (one attribution per referred
		// user).
		`CREATE TABLE IF NOT EXISTS referral_attributions (
			user_id            TEXT PRIMARY KEY,
			referring_org_id   TEXT NOT NULL,
			inviter_user_id    TEXT,
			invitation_id      TEXT,
			attributed_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			alias_completed_at TIMESTAMPTZ,
			incentive_status   TEXT NOT NULL DEFAULT 'pending',
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (referring_org_id) REFERENCES orgs(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_referral_attr_org ON referral_attributions(referring_org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_referral_attr_completed ON referral_attributions(alias_completed_at)`,
		`ALTER TABLE client_credentials ADD COLUMN IF NOT EXISTS first_request_at TIMESTAMPTZ`,
		`ALTER TABLE client_credentials ADD COLUMN IF NOT EXISTS last_request_ip TEXT`,

		// Cargo sparse-index yank state. The synthesizer in
		// internal/server/cargo_local_metadata.go reads this column to
		// emit `"yanked": true` lines so cargo's resolver short-circuits
		// past yanked versions while still letting existing lockfiles
		// download the underlying .crate. INTEGER (0/1) keeps the
		// column compatible with both the SQLite and PG drivers.
		`ALTER TABLE package_versions ADD COLUMN IF NOT EXISTS yanked INTEGER NOT NULL DEFAULT 0`,

		// Paddle Billing integration. Prices live in the Paddle dashboard; we
		// map our plan rows to one Price per billing cycle. Customers and
		// subscriptions are created via the Paddle API the first time an org
		// checks out a paid plan; webhook events then become the source of
		// truth for subscription state.
		`ALTER TABLE pricing_plans ADD COLUMN IF NOT EXISTS paddle_price_id_monthly TEXT`,
		`ALTER TABLE pricing_plans ADD COLUMN IF NOT EXISTS paddle_price_id_annual TEXT`,
		`ALTER TABLE orgs ADD COLUMN IF NOT EXISTS paddle_customer_id TEXT`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_orgs_paddle_customer_id ON orgs(paddle_customer_id) WHERE paddle_customer_id IS NOT NULL`,

		`CREATE TABLE IF NOT EXISTS paddle_subscriptions (
			org_id TEXT PRIMARY KEY,
			subscription_id TEXT NOT NULL UNIQUE,
			status TEXT NOT NULL,
			price_id TEXT NOT NULL,
			plan_id TEXT NOT NULL,
			billing_cycle TEXT NOT NULL,
			current_period_start TIMESTAMPTZ,
			current_period_end TIMESTAMPTZ,
			cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_paddle_subscriptions_status ON paddle_subscriptions(status)`,

		// Idempotency ledger for Paddle webhook deliveries. event_id is
		// Paddle's evt_... identifier; duplicates are no-ops.
		`CREATE TABLE IF NOT EXISTS paddle_webhook_events (
			event_id TEXT PRIMARY KEY,
			event_type TEXT NOT NULL,
			received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			payload JSONB NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_paddle_webhook_events_type_received ON paddle_webhook_events(event_type, received_at DESC)`,

		// Outbound Postmark send log. One row per Send*Email call —
		// status='sent' on a 2xx response from Postmark, 'failed' on any
		// non-2xx, 'disabled' when the service was a no-op (config
		// missing). last_event/last_event_at are updated by the inbound
		// webhook handler when Postmark posts a Delivery/Bounce/
		// SpamComplaint for the corresponding message_id, so a single
		// SELECT against this table answers "what happened to this
		// user's signup email?" without a join.
		`CREATE TABLE IF NOT EXISTS postmark_messages (
			id TEXT PRIMARY KEY,
			template TEXT NOT NULL,
			to_email TEXT NOT NULL,
			from_email TEXT NOT NULL,
			subject TEXT NOT NULL,
			message_id TEXT,
			status TEXT NOT NULL,
			postmark_error_code INTEGER,
			postmark_message TEXT,
			http_status INTEGER,
			latency_ms INTEGER,
			request_id TEXT,
			org_id TEXT,
			user_id TEXT,
			attempted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_event TEXT,
			last_event_at TIMESTAMPTZ
		)`,
		`CREATE INDEX IF NOT EXISTS idx_postmark_messages_message_id ON postmark_messages(message_id)`,
		`CREATE INDEX IF NOT EXISTS idx_postmark_messages_to_email ON postmark_messages(to_email)`,
		`CREATE INDEX IF NOT EXISTS idx_postmark_messages_attempted_at ON postmark_messages(attempted_at DESC)`,

		// Inbound Postmark webhook event log. Postmark can re-deliver
		// the same event so the primary key is a hash of the raw
		// payload; INSERT ... ON CONFLICT DO NOTHING makes replays
		// 200 no-ops. message_id links back to postmark_messages so
		// a single SELECT joins outbound + inbound history.
		`CREATE TABLE IF NOT EXISTS postmark_delivery_events (
			id TEXT PRIMARY KEY,
			message_id TEXT NOT NULL,
			record_type TEXT NOT NULL,
			recipient TEXT,
			bounce_type TEXT,
			bounce_description TEXT,
			payload JSONB NOT NULL,
			received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_postmark_delivery_events_message_id ON postmark_delivery_events(message_id)`,
		`CREATE INDEX IF NOT EXISTS idx_postmark_delivery_events_record_type ON postmark_delivery_events(record_type)`,

		// Phase 2 of the scalability plan: move the per-blob `.meta.json`
		// sidecar files into Postgres so the S3 backend (which has no
		// efficient sidecar pattern) can read metadata without a second
		// object GET per request. The local file backend continues to fall
		// back to sidecar files when a row is missing — see
		// internal/storage/meta_store.go for the read-path logic.
		`CREATE TABLE IF NOT EXISTS cached_content_meta (
			blob_key      TEXT PRIMARY KEY,
			org_id        TEXT NOT NULL,
			repository    TEXT NOT NULL,
			logical_path  TEXT NOT NULL,
			metadata      JSONB NOT NULL,
			cached_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_cached_content_meta_org_repo ON cached_content_meta(org_id, repository)`,

		// API keys for management-API access (PATs and AI agent credentials).
		// Distinct from client_credentials, which is registry-side proxy auth.
		// key_type: 'personal' (human PAT) or 'agent' (AI agent credential).
		// agent_kind is required iff key_type='agent'; validated in Go.
		// scopes JSONB shape:
		//   { "allow_mutations": bool,
		//     "tools": ["*"] or ["get_package_info", ...],
		//     "permissions": ["policies:manage", ...]  // explicit subset of issuer perms
		//   }
		// Effective permissions on each request are intersected with the
		// CURRENT permissions of the issuing user — see internal/apikeys.
		`CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			key_type TEXT NOT NULL,
			agent_kind TEXT,
			prefix TEXT NOT NULL UNIQUE,
			secret_hash TEXT NOT NULL,
			scopes JSONB NOT NULL DEFAULT '{}'::jsonb,
			expires_at TIMESTAMPTZ,
			last_used_at TIMESTAMPTZ,
			revoked_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			signing_key_pub BYTEA,
			signing_alg TEXT,
			FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_org_type ON api_keys(org_id, key_type)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(org_id) WHERE revoked_at IS NULL`,

		// Per-day request counter for API keys. UX_AUDIT.md §8.6 (P0):
		// the api-keys list view shows `request_count_7d` so operators
		// can spot dormant keys at a glance. One row per (key, UTC day)
		// — RecordUsage upserts and the read path SUMs over the
		// trailing window. Cascading delete keeps the counter aligned
		// with the parent key's lifecycle.
		`CREATE TABLE IF NOT EXISTS api_key_usage (
			key_id TEXT NOT NULL,
			day DATE NOT NULL,
			count BIGINT NOT NULL DEFAULT 0,
			PRIMARY KEY (key_id, day),
			FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_api_key_usage_day ON api_key_usage(day DESC)`,

		// Trial-abuse dedupe: a separate dedupe key that collapses RFC 5233
		// sub-addresses (alice+trial@acme.com → alice@acme.com) and case so
		// an attacker can't take repeated free trials on the same inbox.
		// Raw `email` is kept as-typed for delivery — this column is ONLY
		// consulted for uniqueness checks at signup. See
		// internal/emailcanon for the canonicalization rules.
		//
		// The column is nullable and the index is non-unique on purpose:
		// existing rows could contain historical abuse pairs that would
		// collide on backfill and break the startup migration. Uniqueness
		// is enforced in the application (handleSignup SELECT EXISTS ...)
		// which is sufficient — every write path that creates a user goes
		// through that check. A future cleanup migration can promote the
		// index to UNIQUE once operators have reconciled legacy rows.
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS canonical_email TEXT`,
		// Backfill using the same rules as emailcanon.Canonical: strip
		// `+tag` from the local part and lowercase the whole address.
		// IDNA domain normalization is not reproduced in SQL — domains in
		// existing rows are expected to already be ASCII; any unicode
		// holdout will simply fail to collide with its ASCII twin, an
		// acceptable edge case for a legacy backfill.
		`UPDATE users
		   SET canonical_email = regexp_replace(lower(email), '\+[^@]*@', '@')
		 WHERE canonical_email IS NULL AND email IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_users_canonical_email ON users(canonical_email)`,

		// email_class tags each account as "business" | "free_email" |
		// "google_personal" | "ms_personal_tenant" so growth can segment
		// business-email signups — the likeliest champions — from the OSS /
		// personal tail. Nullable and NOT backfilled: only new signups and
		// SSO-provisioned users populate it (see authapi.auth_signup /
		// ResolveSSSOUser); legacy rows and invite/SCIM/admin-created users
		// stay NULL, which the admin UI renders as "unknown". The free-email
		// gate is otherwise off — free/personal now sign up and are merely
		// tagged; only disposable/invalid remain rejected.
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_class TEXT`,
		// Partial index: the admin champion view filters on the populated
		// classes, so a NULL-excluding index stays small on a table where most
		// legacy rows are NULL.
		`CREATE INDEX IF NOT EXISTS idx_users_email_class ON users(email_class) WHERE email_class IS NOT NULL`,

		// MCP agent action log — records every state-changing MCP tool call so
		// agents can list and roll back their own mutations. See
		// internal/actionlog for the read/write layer.
		`CREATE TABLE IF NOT EXISTS agent_action_log (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			tool_name TEXT NOT NULL,
			action_type TEXT NOT NULL,
			before_state JSONB,
			after_state JSONB,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			undone_at TIMESTAMPTZ
		)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_action_log_org_created ON agent_action_log(org_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_action_log_org_undone ON agent_action_log(org_id, undone_at) WHERE undone_at IS NULL`,

		// Hardening bundles — every bundle the wizard streams gets a
		// row keyed on its content-addressable bundle_id. Persisted so
		// the actionlog can reference the bundle by id and the undo
		// path can regenerate the inverse from the recorded inputs.
		// Insert is best-effort relative to the operator's download:
		// a row that fails to commit must NOT fail the tar stream.
		// See internal/hardening/store for the read/write layer.
		`CREATE TABLE IF NOT EXISTS hardening_bundles (
			bundle_id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			scope TEXT NOT NULL,
			inputs_json JSONB NOT NULL,
			created_by TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			applied_at TIMESTAMPTZ,
			reverted_at TIMESTAMPTZ,
			attestation_seen_at TIMESTAMPTZ
		)`,
		`CREATE INDEX IF NOT EXISTS hardening_bundles_org_created ON hardening_bundles(org_id, created_at DESC)`,

		// W6 — admission shadow-mode telemetry. Closes the
		// `zero_admission_errors_24h` stub on the K8s Fail-mode soak gate.
		// The K8s admission webhook posts every admission decision here
		// in shadow mode (see enforcement/k8s-admission); the gate's
		// AdmissionErrors hook now queries this table for the
		// "internal_error" decision count over the last 24h. Append-only;
		// no dedup at the storage layer. See internal/admissionshadow.
		`CREATE TABLE IF NOT EXISTS admission_decisions_shadow (
			id UUID PRIMARY KEY,
			org_id TEXT NOT NULL,
			cluster TEXT NOT NULL,
			ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			namespace TEXT,
			kind TEXT,
			resource_name TEXT,
			decision TEXT NOT NULL,
			reason TEXT,
			policy_id TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS admission_shadow_org_ts ON admission_decisions_shadow(org_id, ts DESC)`,
		`CREATE INDEX IF NOT EXISTS admission_shadow_org_decision_ts ON admission_decisions_shadow(org_id, decision, ts DESC)`,

		// Hardening approval nonces — multi-key (two-admin) approval
		// flow for the K8s Fail-mode soak-gate override. A primary admin
		// mints a nonce by POSTing /api/hardening/approval/request; a
		// SECOND admin (different user_id) signs it via POST /api/
		// hardening/approval/{nonce}/sign; the primary admin then
		// includes override.approval_nonce on the hardening bundle
		// request and the gate's validator (internal/hardening/gate.
		// ValidateApprovalNonce) clears the soak gate when the row
		// passes every check (signed by a different admin, not expired,
		// not consumed, cluster matches). consumed_at is stamped on a
		// successful override so the nonce cannot be replayed. Schema
		// is additive — older rows in hardening_bundles are unaffected.
		`CREATE TABLE IF NOT EXISTS hardening_approval_nonces (
			nonce TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			cluster_name TEXT NOT NULL,
			reason TEXT NOT NULL,
			requested_by TEXT NOT NULL,
			signed_by TEXT,
			signed_at TIMESTAMPTZ,
			consumed_at TIMESTAMPTZ,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS hardening_approval_nonces_org_signed ON hardening_approval_nonces(org_id, signed_at)`,

		// Findings — first-class supply-chain security findings
		// synthesised from blocking events. Dedups on (org, policy,
		// package, version) via the partial unique index so a repeat
		// block does not mint a duplicate row while the existing
		// finding is still open (new | acknowledged). A finding can
		// transition through a small state machine (see internal/
		// finding/state.go) and is the source of truth for the
		// Findings UI surface and the exception reconciliation path.
		// chainsaw-fnd 0.17.0 — additive, nullable-friendly; self-
		// hosters upgrading from 0.16.x pick up the table on first
		// boot with no ALTER required.
		`CREATE TABLE IF NOT EXISTS findings (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			event_id TEXT NOT NULL,
			policy_id TEXT,
			package_name TEXT NOT NULL,
			package_version TEXT NOT NULL,
			severity TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'new',
			snoozed_until TIMESTAMPTZ,
			assignee_id TEXT,
			suppressed_reason TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_org_status ON findings (org_id, status)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_dedup ON findings (org_id, policy_id, package_name, package_version)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_dedup_window ON findings (org_id, policy_id, package_name, package_version) WHERE status IN ('new','acknowledged')`,

		// Domain verification for SSO provider `allowed_domains`. An admin
		// claims a domain, receives a DNS TXT challenge token, and must prove
		// ownership before email-based SSO discovery treats the domain as
		// belonging to their org. Unverified rows do not count for
		// /api/auth/discover lookup — this is the gate that prevents a
		// malicious tenant from claiming `@rival.com` and intercepting SSO
		// redirects for users who type that email.
		`CREATE TABLE IF NOT EXISTS sso_provider_domain_verifications (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			domain TEXT NOT NULL,
			challenge_token TEXT NOT NULL,
			verified_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(domain),
			FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sso_domain_verifications_org_id ON sso_provider_domain_verifications(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sso_domain_verifications_verified ON sso_provider_domain_verifications(domain) WHERE verified_at IS NOT NULL`,

		// Magic-link login tokens. Hashed at rest, single-use, short TTL,
		// bound to the UA+IP-prefix that requested them so intercepting the
		// email doesn't let an attacker consume the link from elsewhere.
		`CREATE TABLE IF NOT EXISTS login_tokens (
			token_hash TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			ua_hash TEXT NOT NULL,
			ip_prefix TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			consumed_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_login_tokens_user_id ON login_tokens(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_login_tokens_expires_at ON login_tokens(expires_at)`,

		// WebAuthn (passkey) credentials. One user can enroll many passkeys
		// (primary laptop + phone + recovery key). sign_count guards against
		// cloned authenticators per the WebAuthn spec. public_key is the CBOR
		// COSE-encoded key as returned by the authenticator; credential_id is
		// the raw bytes stored b64-encoded for DB portability.
		`CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			credential_id TEXT NOT NULL UNIQUE,
			public_key TEXT NOT NULL,
			sign_count BIGINT NOT NULL DEFAULT 0,
			transports TEXT NOT NULL DEFAULT '',
			aaguid TEXT NOT NULL DEFAULT '',
			label TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used_at TIMESTAMPTZ,
			-- WebAuthn Backup Eligible (BE) / Backup State (BS) flags. These MUST
			-- be round-tripped: go-webauthn rejects a login whose BE flag differs
			-- from the value stored at registration ("Backup Eligible flag
			-- inconsistency"), which silently breaks every synced passkey
			-- (Google Password Manager, iCloud Keychain) if we drop them.
			backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
			backup_state BOOLEAN NOT NULL DEFAULT FALSE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials(user_id)`,
		// Backfill the BE/BS columns for tables created before the flags were
		// tracked. Existing rows default to FALSE; a synced passkey enrolled
		// before this fix must be removed and re-added to store the real BE
		// value (there is no way to learn it without a successful assertion,
		// which the missing flag itself blocks).
		`ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS backup_eligible BOOLEAN NOT NULL DEFAULT FALSE`,
		`ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS backup_state BOOLEAN NOT NULL DEFAULT FALSE`,

		// WebAuthn challenge storage. Each registration/authentication attempt
		// creates a one-shot challenge row; the browser's response must match
		// what we issued. Short TTL (5 min) and single-use via DELETE RETURNING.
		`CREATE TABLE IF NOT EXISTS webauthn_challenges (
			challenge TEXT PRIMARY KEY,
			user_id TEXT,
			purpose TEXT NOT NULL,
			session_data TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires_at ON webauthn_challenges(expires_at)`,

		// risk-engine v2 evaluation blob — additive, nullable. Phase 2 of
		// the v2 rollout writes this from internal/intelligence.Store.Upsert
		// when Report.Risk is populated. Left NULL when the flag is off or
		// the evaluator declined to score (e.g., empty Input). Stored as
		// JSONB so future consumers can query inside the evaluation shape
		// without re-deserialising the whole report.
		`ALTER TABLE intelligence_reports ADD COLUMN IF NOT EXISTS risk_evaluation JSONB`,

		// --- intelligence cache: per-tenant → universal migration ---
		// Package facts (CVEs, malware verdicts, typosquat signals, risk
		// evaluations) are universal across tenants. Existing installs
		// had org_id on the primary key which caused /admin/intelligence
		// detail lookups to 404 whenever the viewer's resolved org didn't
		// own a particular row. These statements strip org_id from the PK
		// and deduplicate collisions by keeping the most-recently-collected
		// row per (ecosystem, package_name, version).
		//
		// Each statement is idempotent: re-running after the migration
		// has landed is a no-op.
		`ALTER TABLE intelligence_reports DROP CONSTRAINT IF EXISTS intelligence_reports_pkey`,
		`DELETE FROM intelligence_reports a USING intelligence_reports b
			WHERE a.ctid < b.ctid
			  AND a.ecosystem = b.ecosystem
			  AND a.package_name = b.package_name
			  AND a.version = b.version`,
		`ALTER TABLE intelligence_reports DROP COLUMN IF EXISTS org_id`,
		`DO $mig$ BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint WHERE conname = 'intelligence_reports_pkey'
			) THEN
				ALTER TABLE intelligence_reports
					ADD CONSTRAINT intelligence_reports_pkey
					PRIMARY KEY (ecosystem, package_name, version);
			END IF;
		END $mig$`,
		`DROP INDEX IF EXISTS idx_intelligence_reports_collected_at`,
		`DROP INDEX IF EXISTS idx_intelligence_reports_ecosystem`,
		`DROP INDEX IF EXISTS idx_intelligence_reports_malicious`,
		`CREATE INDEX IF NOT EXISTS idx_intelligence_reports_collected_at ON intelligence_reports(collected_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_intelligence_reports_ecosystem ON intelligence_reports(ecosystem)`,
		`CREATE INDEX IF NOT EXISTS idx_intelligence_reports_malicious ON intelligence_reports(is_malicious) WHERE is_malicious = TRUE`,

		`ALTER TABLE intelligence_latest_probes DROP CONSTRAINT IF EXISTS intelligence_latest_probes_pkey`,
		`DELETE FROM intelligence_latest_probes a USING intelligence_latest_probes b
			WHERE a.ctid < b.ctid
			  AND a.ecosystem = b.ecosystem
			  AND a.package_name = b.package_name`,
		`ALTER TABLE intelligence_latest_probes DROP COLUMN IF EXISTS org_id`,
		`DO $mig$ BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint WHERE conname = 'intelligence_latest_probes_pkey'
			) THEN
				ALTER TABLE intelligence_latest_probes
					ADD CONSTRAINT intelligence_latest_probes_pkey
					PRIMARY KEY (ecosystem, package_name);
			END IF;
		END $mig$`,

		// Telemetry opt-out, per-org. Default TRUE so existing orgs stay
		// instrumented after migration; an admin flips this at
		// /settings/telemetry when they want to stop emitting analytics
		// for their org. Enforced server-side in handleTelemetryIngest.
		`ALTER TABLE orgs ADD COLUMN IF NOT EXISTS telemetry_enabled BOOLEAN NOT NULL DEFAULT TRUE`,

		// Reverse-ETL destination: nightly job populates this from
		// PostHog's Persons API. Dashboard layout renders contextual
		// prompts ("You haven't configured SIEM — takes 3 min") off
		// this table. Missing steps live as a JSON array so the shape
		// can evolve without another migration.
		// funnel_position carries the highest-order activation step
		// the org has reached ("", "signup", "first_login", "aha",
		// "multi_channel"). updated_at caps staleness for the UI
		// (older than 48h ⇒ UI treats it as "unknown" to avoid
		// stale prompts).
		`CREATE TABLE IF NOT EXISTS org_engagement_state (
			org_id TEXT PRIMARY KEY,
			funnel_position TEXT NOT NULL DEFAULT '',
			missing_onboarding_steps TEXT NOT NULL DEFAULT '[]',
			last_event_at TIMESTAMPTZ,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE
		)`,

		// Policy versions — append-only changelog of every
		// create/update/delete on a policy row. Supports the version-
		// history panel and the revert endpoint (DESIGN.md §16). A
		// revert creates a NEW version equal to the historical
		// snapshot rather than rewinding the sequence, so the
		// monotonic version_number stays stable for audit.
		`CREATE TABLE IF NOT EXISTS policy_versions (
			id TEXT PRIMARY KEY,
			policy_id TEXT NOT NULL,
			org_id TEXT NOT NULL,
			version_number BIGINT NOT NULL,
			snapshot TEXT NOT NULL,
			change_summary TEXT,
			actor_id TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (policy_id, version_number)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_versions_policy ON policy_versions (policy_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_versions_org ON policy_versions (org_id, created_at DESC)`,

		// scan_jobs / scan_job_pending — persistence backing the
		// lockfile-scan endpoint when CHAINSAW_SCAN_STORE=postgres.
		// Mirrors the in-memory shape in internal/scan/jobs.go so HA
		// deployments don't pin polling clients to a single replica
		// and so jobs survive a rolling restart. JSONB columns hold
		// the parsed key set (all_keys), parse warnings, and the
		// final aggregate so re-aggregation on completion can run on
		// any replica without round-trips to a sibling.
		`CREATE TABLE IF NOT EXISTS scan_jobs (
			id TEXT PRIMARY KEY,
			status TEXT NOT NULL,
			ecosystem TEXT NOT NULL DEFAULT '',
			filename TEXT NOT NULL DEFAULT '',
			lockfile_sha256 TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMPTZ NOT NULL,
			total INTEGER NOT NULL DEFAULT 0,
			resolved INTEGER NOT NULL DEFAULT 0,
			owner_kind TEXT NOT NULL DEFAULT '',
			owner_id TEXT NOT NULL DEFAULT '',
			parse_warnings JSONB,
			result JSONB,
			all_keys JSONB
		)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_jobs_dedupe ON scan_jobs (owner_kind, owner_id, lockfile_sha256)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_jobs_expires_at ON scan_jobs (expires_at)`,
		// failure_reason + failed_packages added after initial migration:
		// idempotent ALTER ... ADD COLUMN IF NOT EXISTS so existing
		// deployments pick up the columns on next boot.
		`ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS failure_reason TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS failed_packages INTEGER NOT NULL DEFAULT 0`,
		`CREATE TABLE IF NOT EXISTS scan_job_pending (
			job_id TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
			ecosystem TEXT NOT NULL,
			name TEXT NOT NULL,
			version TEXT NOT NULL,
			PRIMARY KEY (job_id, ecosystem, name, version)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_job_pending_job_id ON scan_job_pending (job_id)`,

		// codeowners_mappings persists parsed GitHub CODEOWNERS files
		// keyed by repo_id (the GitHub "owner/name" slug). Each row is
		// one pattern → owners line; ordinal preserves source order so
		// the "last match wins" rule survives re-reads. Sync replaces
		// the whole set per repo, so there is no UNIQUE constraint —
		// duplicate patterns on different lines are valid CODEOWNERS.
		`CREATE TABLE IF NOT EXISTS codeowners_mappings (
			id BIGSERIAL PRIMARY KEY,
			repo_id TEXT NOT NULL,
			ordinal INTEGER NOT NULL,
			pattern TEXT NOT NULL,
			owners TEXT[] NOT NULL,
			updated_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_codeowners_mappings_repo_ordinal ON codeowners_mappings (repo_id, ordinal)`,

		// device_code_grants persists in-flight CLI device-code grants
		// (RFC 8628). Previously held in an in-process map in
		// internal/server/auth_cli.go; on restart the map was lost and
		// users hit a silent 404 on the next poll. Persisting here makes
		// the 15-minute TTL survive restarts and (eventually) lets us
		// run the API on more than one replica without sticky routing.
		//
		// device_code is the secret per RFC 8628 §6.1; stored raw because
		// the codes are 24-byte (48 hex char) crypto/rand values with a
		// 15-minute lifetime — the raw-vs-hash threat (DB-leak + same-
		// window replay) is dominated by the attacker also needing to
		// race the user before the grant is consumed. Treat the column
		// the same as session tokens: do not log, scrub from dumps.
		//
		// state machine: pending → approved → consumed. expired rows are
		// filtered out by WHERE expires_at > now() rather than mutated
		// in-place; a periodic cleanup pass purges stale rows.
		`CREATE TABLE IF NOT EXISTS device_code_grants (
			device_code TEXT PRIMARY KEY,
			user_code TEXT NOT NULL UNIQUE,
			state TEXT NOT NULL CHECK (state IN ('pending','approved','consumed')),
			hostname TEXT NOT NULL DEFAULT '',
			install_id TEXT NOT NULL DEFAULT '',
			org_id TEXT,
			user_id TEXT,
			token TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMPTZ NOT NULL,
			approved_at TIMESTAMPTZ,
			consumed_at TIMESTAMPTZ
		)`,
		`CREATE INDEX IF NOT EXISTS idx_device_code_grants_expires_at ON device_code_grants(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_device_code_grants_user_code ON device_code_grants(user_code)`,
		// regression-check: F10 — invariant: a 'consumed' row must
		// carry the JWT we issued. Pre-fix the consume UPDATE wiped
		// token to NULL while transitioning state, leaving auditors
		// with consumed rows whose token field was empty (observed
		// on staging for codes XW77-EX4D and VKE2-US3H). The CHECK
		// pins the contract at the database boundary so a code-path
		// regression here surfaces as an INSERT/UPDATE failure
		// rather than a silent data hole.
		//
		// Idempotent via DO block: ALTER TABLE ... ADD CONSTRAINT
		// has no IF NOT EXISTS in older Postgres, so we look up
		// pg_constraint first and only add when absent.
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint
				WHERE conname = 'device_code_grants_consumed_has_token'
			) THEN
				ALTER TABLE device_code_grants
					ADD CONSTRAINT device_code_grants_consumed_has_token
					CHECK (state <> 'consumed' OR (token IS NOT NULL AND token <> ''));
			END IF;
		END
		$$`,
		// Repo→Team routing (opt-in). Default OFF: an empty table means
		// the violation pipeline records team='' exactly as before. The
		// admin maintains rows via the /api/repo-team-mappings CRUD
		// surface and the `chainsaw team` CLI subcommand.
		`CREATE TABLE IF NOT EXISTS repo_team_mappings (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			repo_pattern TEXT NOT NULL,
			team TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			created_by TEXT
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_repo_team_mappings_org_pattern_unique ON repo_team_mappings(org_id, repo_pattern)`,
		`CREATE INDEX IF NOT EXISTS idx_repo_team_mappings_org ON repo_team_mappings(org_id)`,
		// Pain 5 — exception-expiry reminder-loop ledger + dashboard-
		// banner queue. The (exception_id, milestone) PRIMARY KEY on
		// exception_reminders_sent is the load-bearing idempotency
		// invariant: concurrent leaders' INSERT … ON CONFLICT DO
		// NOTHING cannot double-fire a milestone. See docs/MIGRATIONS.md
		// for the per-release documentary record.
		`CREATE TABLE IF NOT EXISTS exception_reminders_sent (
			exception_id TEXT NOT NULL,
			milestone    TEXT NOT NULL,
			org_id       TEXT NOT NULL,
			sent_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (exception_id, milestone)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_exception_reminders_sent_org ON exception_reminders_sent(org_id, sent_at DESC)`,
		`CREATE TABLE IF NOT EXISTS exception_expiry_banners (
			id            TEXT NOT NULL PRIMARY KEY,
			exception_id  TEXT NOT NULL,
			org_id        TEXT NOT NULL,
			milestone     TEXT NOT NULL,
			expires_at    TIMESTAMPTZ NOT NULL,
			package_name  TEXT NOT NULL DEFAULT '',
			package_ver   TEXT NOT NULL DEFAULT '',
			repository    TEXT NOT NULL DEFAULT '',
			created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			dismissed_at  TIMESTAMPTZ
		)`,
		`CREATE INDEX IF NOT EXISTS idx_exception_expiry_banners_org_pending ON exception_expiry_banners(org_id, expires_at) WHERE dismissed_at IS NULL`,
		// Feedback-loop foundation — append-only event ledger that
		// records every implicit / explicit FP / TP signal the system
		// observes (today: exception creates as implicit FPs; later
		// slices: finding mark-FP / mark-TP, undo, retraction). This
		// table is the producer surface for the feedback-tuner worker
		// (internal/feedbacktune) which reads the rows on a cadence to
		// derive policy-tuning suggestions. APPEND-ONLY — there is no
		// UPDATE / DELETE path; retractions are NEW rows that reference
		// the prior id in payload. Producer wiring is ON by default
		// (the table grows even when nobody is tuning); the consumer
		// worker is OFF by default behind CHAINSAW_FEEDBACK_TUNER_ENABLED.
		`CREATE TABLE IF NOT EXISTS feedback_events (
			id UUID PRIMARY KEY,
			org_id TEXT NOT NULL,
			signal_id TEXT NOT NULL,
			package_ecosystem TEXT,
			package_name TEXT,
			package_version TEXT,
			decision_id TEXT,
			finding_id TEXT,
			exception_id TEXT,
			event_kind TEXT NOT NULL,
			event_class TEXT NOT NULL,
			actor_user_id TEXT,
			actor_kind TEXT,
			source_path TEXT,
			confidence SMALLINT NOT NULL DEFAULT 50,
			payload JSONB,
			recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS feedback_events_org_signal_time ON feedback_events(org_id, signal_id, recorded_at DESC)`,
		`CREATE INDEX IF NOT EXISTS feedback_events_org_kind_time ON feedback_events(org_id, event_kind, recorded_at DESC)`,
		// W5 — tuning_suggestions is the operator-visible output of the
		// feedbacktune consumer worker. The worker computes a Bayesian
		// posterior FP-rate per (org, signal) over a recent window and
		// — when the 95% credible interval excludes the implied baseline
		// FP rate — writes ONE OPEN row per (org, signal). The unique
		// partial index on state='open' collapses repeated firings so
		// the operator UI never shows "you have 17 suggestions for the
		// same signal". State transitions: open → accepted (writes the
		// suggested weight via /api/risk/overrides) or open → dismissed
		// (no weight change). Accept/dismiss is HUMAN-IN-LOOP only —
		// the worker NEVER auto-mutates orgweights.
		`CREATE TABLE IF NOT EXISTS tuning_suggestions (
			id UUID PRIMARY KEY,
			org_id TEXT NOT NULL,
			signal_id TEXT NOT NULL,
			current_weight INTEGER NOT NULL,
			suggested_weight INTEGER NOT NULL,
			posterior_fp_rate REAL NOT NULL,
			ci_low REAL NOT NULL,
			ci_high REAL NOT NULL,
			evidence_event_ids TEXT NOT NULL,
			fires INTEGER NOT NULL,
			window_days INTEGER NOT NULL,
			state TEXT NOT NULL DEFAULT 'open',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			decided_at TIMESTAMPTZ,
			decided_by TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS tuning_suggestions_org_state ON tuning_suggestions(org_id, state, created_at DESC)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS tuning_suggestions_org_signal_open ON tuning_suggestions(org_id, signal_id) WHERE state = 'open'`,
		// Pain 4 (ownership routing) — idempotent CREATE TABLE /
		// CREATE INDEX statements for the team_webhook_destinations
		// and ownership_glob_rules tables. This is the schema source
		// of truth (docs/MIGRATIONS.md is the per-release documentary
		// record).
		//
		// team_webhook_destinations: per-team outbound webhook destination
		// map. Default-OFF — empty table = routing emits no team-targeted
		// webhook (existing per-user fan-out unchanged).
		`CREATE TABLE IF NOT EXISTS team_webhook_destinations (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			team TEXT NOT NULL,
			destination_url TEXT NOT NULL,
			secret TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_team_webhook_destinations_org_team_unique ON team_webhook_destinations(org_id, team)`,
		`CREATE INDEX IF NOT EXISTS idx_team_webhook_destinations_org ON team_webhook_destinations(org_id)`,
		// ownership_glob_rules: path-pattern fallback for shops without
		// CODEOWNERS (GitLab/Bitbucket monorepos, etc.). Distinct from
		// repo_team_mappings (which keys on repo_pattern); this keys on
		// org-scoped path glob with explicit priority ordering. Empty
		// table → ResolveOwners falls through to ('', false) exactly as
		// before.
		`CREATE TABLE IF NOT EXISTS ownership_glob_rules (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			glob_pattern TEXT NOT NULL,
			team TEXT NOT NULL,
			priority INTEGER NOT NULL DEFAULT 100,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_ownership_glob_rules_org_pattern_unique ON ownership_glob_rules(org_id, glob_pattern)`,
		`CREATE INDEX IF NOT EXISTS idx_ownership_glob_rules_org_priority ON ownership_glob_rules(org_id, priority)`,
		// ownership_client_mappings: client-pattern (workstation/laptop
		// identifier) → team resolver. Sibling to ownership_glob_rules,
		// but keyed on client_id glob — coverage's silent-row pipeline
		// has no repo path to feed the path-glob matcher. Empty table →
		// ResolveClientOwner returns ('', false) and the dashboard's
		// `send_hardening_bundle` action stays disabled with the
		// existing "no owner resolved" reason.
		`CREATE TABLE IF NOT EXISTS ownership_client_mappings (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			client_pattern TEXT NOT NULL,
			team TEXT NOT NULL,
			priority INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ownership_client_mappings_org_pattern ON ownership_client_mappings(org_id, client_pattern)`,
		`CREATE INDEX IF NOT EXISTS ownership_client_mappings_org_priority ON ownership_client_mappings(org_id, priority DESC)`,

		// simulate_results: persisted preview/dry-run results for the
		// simulate primitive (W0). Every successful Run() in
		// internal/simulate is stored here so the downstream write
		// handler can verify a preview-before-commit token without
		// re-running the simulation. TTL is enforced on read
		// (ErrSimulateStale) — no cleanup cron required for
		// correctness. id is a UUID generated by the caller. See
		// internal/simulate/store.go for the read/write layer.
		`CREATE TABLE IF NOT EXISTS simulate_results (
			id           TEXT PRIMARY KEY,
			kind         TEXT NOT NULL,
			org_id       TEXT NOT NULL,
			inputs_hash  TEXT NOT NULL,
			result_json  JSONB NOT NULL,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at   TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_simulate_results_org_kind_created ON simulate_results(org_id, kind, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_simulate_results_expires ON simulate_results(expires_at)`,

		// Pain 4 — ownership routing lifecycle (MVP).
		//
		// routed_violations is the per-violation lifecycle ledger that
		// powers MTTA / ack / SLA-escalation. Default-OFF: rows are
		// only ever inserted when the `ownership_routing_lifecycle`
		// feature flag is ON. Empty table = pre-Decision-3 behaviour
		// (fan-out only, no MTTA), exactly as today.
		//
		// dedup_key is sha256(org_id|package|version|owner_team|week_bucket)
		// at the call site; the unique index keeps a flapping repo
		// from generating thousands of routed rows for the same
		// (team, package) tuple inside the dedup window.
		`CREATE TABLE IF NOT EXISTS routed_violations (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			event_id TEXT NOT NULL,
			owner_team TEXT NOT NULL,
			severity TEXT NOT NULL,
			status TEXT NOT NULL,
			routed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			ack_at TIMESTAMPTZ,
			resolved_at TIMESTAMPTZ,
			escalated_at TIMESTAMPTZ,
			escalation_level INTEGER NOT NULL DEFAULT 0,
			external_ticket_url TEXT,
			sla_hours INTEGER NOT NULL,
			dedup_key TEXT NOT NULL,
			ack_token_hash TEXT NOT NULL,
			ack_token_expires_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS routed_violations_org_status_routed ON routed_violations(org_id, status, routed_at)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS routed_violations_dedup_window ON routed_violations(dedup_key)`,
		`CREATE INDEX IF NOT EXISTS routed_violations_team_status ON routed_violations(owner_team, status)`,
		`CREATE INDEX IF NOT EXISTS routed_violations_ack_token_hash ON routed_violations(ack_token_hash)`,

		// W14 — per-org SLA policy. Operator-managed override of the
		// hardcoded severity → hours mapping in
		// internal/ownership.SLAHoursForSeverity. Empty table = legacy
		// hardcoded defaults (the OFF-flag default state). Snapshotted
		// AT INSERT TIME into routed_violations.sla_hours so a later
		// policy edit doesn't retroactively change open rows.
		`CREATE TABLE IF NOT EXISTS ownership_sla_policies (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			sla_hours INTEGER NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_by TEXT
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ownership_sla_policies_org_severity ON ownership_sla_policies(org_id, severity)`,
		`CREATE INDEX IF NOT EXISTS ownership_sla_policies_org ON ownership_sla_policies(org_id)`,

		// W14 — multi-step escalation chain. Operator-defined ordered
		// list of (level, target_kind, target_ref) rows the SLA worker
		// walks past each escalation tick. Empty table = legacy
		// single-step "ping same team destination" fallback. Levels
		// are 1-based; level 1 fires when the initial SLA expires,
		// level 2 fires `delay_hours` after level 1, and so on.
		`CREATE TABLE IF NOT EXISTS ownership_escalation_chains (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			level INTEGER NOT NULL,
			target_kind TEXT NOT NULL,
			target_ref TEXT NOT NULL,
			delay_hours INTEGER NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_by TEXT
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ownership_escalation_chains_org_level ON ownership_escalation_chains(org_id, level)`,
		`CREATE INDEX IF NOT EXISTS ownership_escalation_chains_org ON ownership_escalation_chains(org_id)`,

		// W7 — request-level idempotency cache. Backs the
		// internal/idempotency middleware: any mutating endpoint that opts
		// in can dedup retries within a 24h TTL. The (org_id, key)
		// primary key tenant-isolates cache rows so a key collision
		// across orgs is impossible. response_body is BYTEA on Postgres,
		// transparently TEXT on SQLite (used by tests).
		`CREATE TABLE IF NOT EXISTS idempotency_keys (
			org_id TEXT NOT NULL,
			key TEXT NOT NULL,
			request_hash TEXT NOT NULL,
			response_status INTEGER NOT NULL,
			response_body BYTEA NOT NULL,
			response_headers TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (org_id, key)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_idempotency_keys_created_at ON idempotency_keys(created_at)`,

		// W7 follow-up — coverage flag-for-triage log. Records that an
		// operator looked at a silent client_pattern row and flagged it
		// for follow-up. Pure paper-trail; never read on the hot path.
		`CREATE TABLE IF NOT EXISTS coverage_flags (
			id BIGSERIAL PRIMARY KEY,
			org_id TEXT NOT NULL,
			client_id TEXT NOT NULL,
			actor_user_id TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL DEFAULT '',
			flagged_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_coverage_flags_org_client_time ON coverage_flags(org_id, client_id, flagged_at DESC)`,

		// W7 follow-up — bypass-exemption rows. PK is (org_id, client_id)
		// — only one active exemption per client per org. Resolving
		// updates the row in-place; re-exempting after resolve overwrites.
		`CREATE TABLE IF NOT EXISTS bypass_exemptions (
			org_id TEXT NOT NULL,
			client_id TEXT NOT NULL,
			reason TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			signed_by TEXT NOT NULL,
			resolved_at TIMESTAMPTZ,
			resolved_by TEXT,
			resolution_evidence TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (org_id, client_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_bypass_exemptions_org_active ON bypass_exemptions(org_id, expires_at) WHERE resolved_at IS NULL`,

		// W7 follow-up — bypass-confidence history. One row per snapshot
		// per (org, client) tuple. The Snapshotter writes here on a
		// cadence; canResolveBypassExemption reads it to enforce the
		// "stayed below threshold for ≥24h" gate before mark_resolved
		// is allowed. Closes the W7 punt — see canResolveBypassExemption.
		`CREATE TABLE IF NOT EXISTS bypass_confidence_history (
			org_id TEXT NOT NULL,
			client_id TEXT NOT NULL,
			ts TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			confidence TEXT NOT NULL,
			delta INTEGER NOT NULL,
			PRIMARY KEY (org_id, client_id, ts)
		)`,
		`CREATE INDEX IF NOT EXISTS bypass_history_org_client_ts ON bypass_confidence_history(org_id, client_id, ts DESC)`,

		// D.12 — bypass-report ingest. External signal sources (the
		// Prometheus alertmanager webhook emitted in the hardening bundle
		// from the admin hardening wizard, or any custom log shipper) POST
		// candidate bypass observations
		// to /api/v1/bypass/report. Stored here for triage on the
		// /chainsaw/insights/coverage/bypass surface. status transitions:
		//   pending  → initial state when ingested.
		//   confirmed → an admin clicked "Confirm bypass" — the client
		//               is added to the quarantine list. (Decision-engine
		//               gating is a follow-up; the table records the
		//               admin intent today.)
		//   dismissed → an admin clicked "False alarm" — suppressed for
		//               30d (suppression window enforced at query time
		//               by joining on dismissed_until).
		// confidence is the source-provided score in [0,1]; the UI
		// filter slider defaults to 0.7.
		`CREATE TABLE IF NOT EXISTS bypass_reports (
			id BIGSERIAL PRIMARY KEY,
			org_id TEXT NOT NULL,
			client_hint TEXT NOT NULL,
			evidence TEXT NOT NULL DEFAULT '',
			confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
			source TEXT NOT NULL DEFAULT 'unknown',
			status TEXT NOT NULL DEFAULT 'pending',
			seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			confirmed_at TIMESTAMPTZ,
			confirmed_by TEXT NOT NULL DEFAULT '',
			dismissed_until TIMESTAMPTZ
		)`,
		`CREATE INDEX IF NOT EXISTS idx_bypass_reports_org_status ON bypass_reports(org_id, status, seen_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_bypass_reports_org_client ON bypass_reports(org_id, client_hint)`,

		// GTM W5 — marketing lead capture. One row per form submission.
		// `source` distinguishes lead surfaces ("procurement_kit", future
		// values for other forms). `ip` is the last-resort rate-limit
		// fingerprint when X-Forwarded-For is absent. No FK to users:
		// leads are NOT signed-up accounts, and downstream CRM handles
		// dedupe.
		`CREATE TABLE IF NOT EXISTS leads (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			company TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT '',
			comments TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL DEFAULT 'procurement_kit',
			ip TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_leads_source_created_at ON leads(source, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_leads_email ON leads(email)`,

		// Launch C1 — owned-audience capture for the "monthly supply-chain
		// teardown" list. One row per opted-in email. SECURITY/PRIVACY: the
		// public POST /teardowns/subscribe handler is unauthenticated and
		// internet-facing, so this table is the only thing it writes; it
		// stores NOTHING but the email, a coarse `source` label, and a
		// timestamp — no IP, no user-agent, no request metadata. `email` is
		// the natural key and carries a UNIQUE constraint so the handler's
		// `INSERT ... ON CONFLICT (email) DO NOTHING` dedups silently and the
		// surface can't be used as an email-enumeration oracle (same response
		// for a new vs. existing address). We normalise to lower-case in the
		// handler before insert rather than using citext — citext is not an
		// installed extension anywhere in this schema, so a plain TEXT UNIQUE
		// on a pre-lowercased value is the dependency-free equivalent.
		// No FK to users: subscribers are NOT accounts.
		// FOLLOW-UP: confirmed (double) opt-in — a verification email with a
		// one-time token and a `confirmed_at TIMESTAMPTZ` column — is a
		// deliberate follow-up, not shipped here. Today this is single opt-in.
		`CREATE TABLE IF NOT EXISTS teardown_subscribers (
			id BIGSERIAL PRIMARY KEY,
			email TEXT NOT NULL UNIQUE,
			source TEXT NOT NULL DEFAULT 'teardowns',
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_teardown_subscribers_created_at ON teardown_subscribers(created_at DESC)`,

		// Wave AA-2 — relax `package_versions` uniqueness so Maven/Gradle
		// can persist one row per physical file (pom, jar, sources,
		// javadoc) at the same GAV. Wave W left the version-level UNIQUE
		// in place and silently skipped the per-file INSERT, so the jar
		// row was never persisted (BUG_REPORT_maven_jar_row_not_persisted.md).
		// We replace the version-level UNIQUE with a logical_path-scoped
		// one so non-maven formats still single-row per version (the
		// upload handler enforces that explicitly in step 5; the index
		// is a safety net). Forward-only — the prior UNIQUE was a
		// strict subset of the new one, so dropping it cannot orphan
		// rows. The constraint name `package_versions_org_id_repository_package_name_version_key`
		// is the Postgres auto-generated name for the inline
		// `UNIQUE (org_id, repository, package_name, version)` on the
		// `CREATE TABLE` above.
		`ALTER TABLE package_versions DROP CONSTRAINT IF EXISTS package_versions_org_id_repository_package_name_version_key`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_package_versions_org_repo_pkg_ver_path
			ON package_versions (org_id, repository, package_name, version, logical_path)
			WHERE deleted_at IS NULL`,

		// P0-1 (connectors) — canonicalize the `webhooks` schema. The
		// store's SELECT/INSERT paths previously carried a five-rung
		// runtime schema-detection ladder (hasCiphertextCol probe +
		// isMissing*Column sniffs) to tolerate self-hosted DBs whose
		// `webhooks` table predated the M-SEC-05 ciphertext column or the
		// format/topic columns — those columns were only ever added by an
		// out-of-band manual ALTER (docs/MIGRATIONS.md "[Unreleased]"),
		// never by migrate(). These idempotent ALTERs make migrate() the
		// single source of truth so the collapsed store can assume the
		// canonical schema unconditionally. The legacy plaintext-bridge in
		// the store is retired alongside this; see docs/MIGRATIONS.md. Each
		// is ADD COLUMN IF NOT EXISTS, so re-running migrate() (and running
		// against a DB where the column already exists from the manual
		// ALTER) is a no-op. New rows are written with secret='' +
		// secret_ciphertext set; pre-existing rows keep their plaintext
		// `secret` and a NULL `secret_ciphertext`, which resolveSecret
		// still reads correctly.
		`ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS secret_ciphertext TEXT`,
		`ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS format TEXT`,
		`ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS topic TEXT`,

		// P2 (connectors — Slack OAuth) — single-use CSRF state nonce store
		// for the Slack install/callback handshake. Modeled on sso_states
		// (state_hash PK, org_id, expires_at) per plan §3.2 finding #5: the
		// nonce is stored only as its sha256 hash, bound to org_id, and
		// consumed exactly once on callback (replay/reuse → rejected). A
		// dedicated table (vs. reusing sso_states) avoids satisfying
		// sso_states' NOT-NULL nonce_hash/code_verifier columns that have no
		// meaning for the Slack flow. `consumed_at` is the single-use latch:
		// the callback flips it via a conditional UPDATE; rows-affected==0
		// means already-consumed/expired/unknown. Idempotent CREATE.
		`CREATE TABLE IF NOT EXISTS oauth_states (
			state_hash  TEXT PRIMARY KEY,
			org_id      TEXT NOT NULL,
			provider    TEXT NOT NULL,
			expires_at  TIMESTAMPTZ NOT NULL,
			consumed_at TIMESTAMPTZ,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_states_expires ON oauth_states(expires_at)`,

		// P4 (connectors — bidirectional sync) — Migration W-CONN-2.
		//
		// connector_conversations ties a Chainsaw lifecycle object (finding
		// or routed_violation) to its external conversation handle (a Slack
		// thread `<channel>:<ts>` or a Jira issue key) so an inbound reply /
		// button click / status webhook routes back to exactly one subject.
		// `org_id` here is the AUTHORITATIVE tenant for every inbound mutation
		// — it is resolved from this row (via the connector), never from the
		// untrusted inbound payload (plan §3.2/§3.3 Tenancy). Idempotent
		// CREATE. See plan_connectors_wizard.md §3.1.
		`CREATE TABLE IF NOT EXISTS connector_conversations (
			id                 TEXT PRIMARY KEY,
			org_id             TEXT NOT NULL,
			connector_id       TEXT NOT NULL,
			subject_kind       TEXT NOT NULL,
			subject_id         TEXT NOT NULL,
			external_kind      TEXT NOT NULL,
			external_ref       TEXT NOT NULL,
			state              TEXT NOT NULL DEFAULT 'open',
			inbound_token_hash TEXT,
			created_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		// Inbound join key: a Slack event carries channel+thread_ts, a Jira
		// webhook carries the issue key — both resolve to exactly one subject.
		//
		// SECURITY (cross-tenant write defense): this UNIQUE is kept GLOBAL on
		// (external_kind, external_ref) — deliberately NOT widened to
		// (connector_id, external_kind, external_ref). The global uniqueness is
		// itself a tenancy control: an external_ref (e.g. an enumerable Jira
		// issue key) can map to AT MOST ONE conversation across the whole
		// deployment, so a second connector/org can never register a colliding
		// mapping for a victim's issue key. ResolveByExternalRef is additionally
		// scoped to (connector_id, org_id) in its WHERE clause, so an attacker's
		// connector resolving a victim's ref simply yields
		// ErrConversationNotFound. Widening this index to per-connector would
		// REMOVE the global-collision guarantee (two orgs could each claim the
		// same ref), trading a hard DB invariant for reliance on the
		// application-layer scope alone — strictly weaker. Outbound upsert
		// (UpsertForSubject) keys on the subject-uq index, so this decision does
		// not affect the upsert path.
		`CREATE UNIQUE INDEX IF NOT EXISTS connector_conv_external
			ON connector_conversations(external_kind, external_ref)`,
		// finding #9: subject-level dedup so a second emit for the same
		// subject re-uses the existing thread instead of orphaning a new one.
		`CREATE UNIQUE INDEX IF NOT EXISTS connector_conv_subject_uq
			ON connector_conversations(connector_id, subject_kind, subject_id)`,
		`CREATE INDEX IF NOT EXISTS connector_conv_subject
			ON connector_conversations(subject_kind, subject_id)`,
		`CREATE INDEX IF NOT EXISTS connector_conv_org
			ON connector_conversations(org_id, state)`,

		// finding #3/#11: per-connector inbound dedup ledger (mirrors
		// paddle_webhook_events:869). First-insert-wins gates ALL inbound
		// handling — including additive note-appends, which have no natural
		// idempotency — so a Slack/Jira retry of an already-processed event
		// is a 200 no-op. The composite PK is the idempotency latch.
		`CREATE TABLE IF NOT EXISTS connector_inbound_events (
			connector_id      TEXT NOT NULL,
			external_event_id TEXT NOT NULL,
			received_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (connector_id, external_event_id)
		)`,

		// Intelligence-flywheel per-org consent (T0). DISTINCT from
		// telemetry_enabled above: telemetry_enabled consents to "anonymous
		// usage events" only, whereas flywheel_sharing_enabled consents to
		// contributing this org's blocked-package detections (name + version)
		// to the cross-org malware-detection flywheel. Default FALSE so the
		// migration opts NO existing org in — sharing is strictly opt-in,
		// flipped at /settings/flywheel by a settings:update-gated admin.
		// Read fail-closed (default FALSE) by isFlywheelSharingEnabledForOrg.
		`ALTER TABLE orgs ADD COLUMN IF NOT EXISTS flywheel_sharing_enabled BOOLEAN NOT NULL DEFAULT FALSE`,

		// Intelligence-flywheel capture store (T1). One row per
		// (ecosystem, package, version) blocked-as-malicious across ALL
		// consenting orgs. PRIVACY INVARIANT: there is NO org_id column —
		// the table stores only the COUNT of distinct orgs that blocked a
		// package (distinct_org_count) plus a weighted score, never which
		// org. Populated by the leader-elected flywheel_capture_worker from
		// the events ledger, filtered to orgs with flywheel_sharing_enabled.
		// weighted_org_score == distinct_org_count for v0 (org-trust
		// weighting is T2, out of scope here).
		`CREATE TABLE IF NOT EXISTS flywheel_signals (
			ecosystem          TEXT NOT NULL,
			package_name       TEXT NOT NULL,
			package_version    TEXT NOT NULL,
			first_seen_at      TIMESTAMPTZ,
			last_seen_at       TIMESTAMPTZ,
			distinct_org_count INTEGER NOT NULL DEFAULT 0,
			weighted_org_score DOUBLE PRECISION NOT NULL DEFAULT 0,
			PRIMARY KEY (ecosystem, package_name, package_version)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_flywheel_signals_org_count ON flywheel_signals(distinct_org_count DESC)`,

		// Intelligence-flywheel curation queue (T3). One row per
		// (ecosystem, package, version) signal that the tiering pass has
		// taken a curation decision on. Keyed identically to
		// flywheel_signals so the curator joins 1:1. status is the lifecycle
		// state:
		//   - 'candidate'      — eligible per the T2 gate, awaiting tiering
		//                        (transient; the pass advances it the same tick).
		//   - 'auto_promoted'  — tiered for automatic publish (ONLY reachable
		//                        when CHAINSAW_FLYWHEEL_AUTOPROMOTE_ENABLED is
		//                        on; default OFF so this is unreachable today).
		//   - 'human_pending'  — queued for a human confirm/reject decision.
		//   - 'confirmed'      — a human (or an enabled auto-promote) confirmed
		//                        it malicious; T4 publishes confirmed rows.
		//   - 'rejected'       — a human rejected it; never published.
		// decided_by/reason/decided_at record the last transition for audit.
		// PRIVACY INVARIANT preserved: like flywheel_signals, there is NO
		// org_id column — the queue is keyed on the aggregate signal only.
		`CREATE TABLE IF NOT EXISTS flywheel_curation (
			ecosystem          TEXT NOT NULL,
			package_name       TEXT NOT NULL,
			package_version    TEXT NOT NULL,
			status             TEXT NOT NULL,
			distinct_org_count INTEGER NOT NULL DEFAULT 0,
			weighted_org_score DOUBLE PRECISION NOT NULL DEFAULT 0,
			created_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			decided_by         TEXT,
			reason             TEXT,
			malware_id         TEXT,
			withdrawn          BOOLEAN NOT NULL DEFAULT FALSE,
			PRIMARY KEY (ecosystem, package_name, package_version)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_flywheel_curation_status ON flywheel_curation(status)`,

		// Intelligence-flywheel published-feed versioning (T5). Each
		// confirmed-and-published OSV entry (MAL-CHAINSAW-<n>) is appended
		// here as an immutable, monotonically-versioned snapshot so a
		// kill-switch/rollback can revert to the prior version of a given
		// entry. version is per-(ecosystem,package,version) entry; the
		// MAX(version) row is the live state. withdrawn carries the
		// per-entry kill-switch (maps to OSVEntry.Withdrawn at load time).
		// canary_only flags an entry that is rolling out to the canary
		// cohort only — T5 promotes it to global (canary_only=false) once
		// the block-rate monitor clears it, or auto-halts (withdrawn=true)
		// on a spike.
		`CREATE TABLE IF NOT EXISTS flywheel_published (
			id                 BIGSERIAL PRIMARY KEY,
			malware_id         TEXT NOT NULL,
			ecosystem          TEXT NOT NULL,
			package_name       TEXT NOT NULL,
			package_version    TEXT NOT NULL,
			summary            TEXT,
			version            INTEGER NOT NULL DEFAULT 1,
			withdrawn          BOOLEAN NOT NULL DEFAULT FALSE,
			canary_only        BOOLEAN NOT NULL DEFAULT TRUE,
			published_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_flywheel_published_entry ON flywheel_published(ecosystem, package_name, package_version, version DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_flywheel_published_malware_id ON flywheel_published(malware_id)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("apply migration %q: %w", stmt[:min(len(stmt), 60)], err)
		}
	}
	if err := s.ensureDefaultOrg(); err != nil {
		return err
	}
	if err := s.ensureEnhancedColumns(); err != nil {
		return err
	}
	// Record the schema revision after every table/column change
	// above has been applied. ensureSchemaVersion runs last so the
	// stored version only advances when the rest of migrate()
	// succeeded.
	if err := s.ensureSchemaVersion(); err != nil {
		return err
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
