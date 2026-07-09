package pgstore

import (
	"fmt"

	"github.com/chain305/chainsaw-core/tenancy"
)

func (s *Store) ensureEnhancedColumns() error {
	if err := s.ensureClientCredentialColumns(); err != nil {
		return err
	}
	if err := s.ensurePolicyColumns(); err != nil {
		return err
	}
	if err := s.ensureEventColumns(); err != nil {
		return err
	}
	if err := s.ensureTenancyAndRepoColumns(); err != nil {
		return err
	}
	if err := s.ensureUserAndRoleColumns(); err != nil {
		return err
	}
	if err := s.ensureSIEMAndSCIMColumns(); err != nil {
		return err
	}
	if err := s.ensurePackageRegistryColumns(); err != nil {
		return err
	}
	if err := s.ensurePricingPlanColumns(); err != nil {
		return err
	}
	if err := s.ensurePlanAssignmentAndAuditSchema(); err != nil {
		return err
	}
	if err := s.ensureAgentActionLogSchema(); err != nil {
		return err
	}
	if err := s.ensureComplianceAttestationsSchema(); err != nil {
		return err
	}
	if err := s.ensureFindingsCodeownersColumns(); err != nil {
		return err
	}
	if err := s.ensureSBOMSnapshotsSchema(); err != nil {
		return err
	}
	if err := s.ensureWebhookNotificationColumns(); err != nil {
		return err
	}
	if err := s.ensureAnalyticsRollupSchema(); err != nil {
		return err
	}
	if err := s.ensureAPIKeySigningColumns(); err != nil {
		return err
	}
	// ADR-006 Item 1 — manual ownership claim overrides (additive new table).
	if err := s.ensureInventoryOwnershipSchema(); err != nil {
		return err
	}
	// ADR-002 Item 5a — Billy proposals store (additive new table).
	if err := s.ensureBillyProposalsSchema(); err != nil {
		return err
	}
	return nil
}

// ensureAPIKeySigningColumns adds the per-key ed25519 signing material
// columns to api_keys. Used by the hardening MANIFEST signing flow:
// signing_key_pub holds the 32-byte ed25519 public key, signing_alg
// names the algorithm ("ed25519"). Both are NULL on legacy rows — the
// org keyset endpoint filters on signing_alg IS NOT NULL so non-signing
// keys never leak into the public surface.
//
// We intentionally do NOT persist the private key half. Storing it
// server-side would require encryption-at-rest infrastructure that
// doesn't exist yet; instead the create-key response returns the
// private key ONCE alongside the bearer token and the operator stashes
// it the same way (one-time secret display). See TODO.md for the
// server-side privkey-vault follow-up.
func (s *Store) ensureAPIKeySigningColumns() error {
	if err := s.addColumnIfMissing("api_keys", "signing_key_pub", "BYTEA"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("api_keys", "signing_alg", "TEXT"); err != nil {
		return err
	}
	// Index supports the org keyset endpoint's "active keys for org X"
	// query. Partial index skips legacy rows so it stays compact.
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_api_keys_org_signing ON api_keys(org_id) WHERE signing_alg IS NOT NULL`); err != nil {
		return fmt.Errorf("create idx_api_keys_org_signing: %w", err)
	}
	return nil
}

func (s *Store) ensureClientCredentialColumns() error {
	if err := s.addColumnIfMissing("client_credentials", "name", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("client_credentials", "created_by_user_id", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("client_credentials", "updated_at", "TIMESTAMPTZ"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("client_credentials", "expiry_date", "TIMESTAMPTZ"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("client_credentials", "authorized_repositories", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("client_credentials", "client_type", "TEXT NOT NULL DEFAULT 'end-user'"); err != nil {
		return err
	}
	return nil
}

func (s *Store) ensurePolicyColumns() error {
	if err := s.addColumnIfMissing("policies", "name", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("policies", "description", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("policies", "parameter_hash", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	// Exception-mode metadata: nullable (no DEFAULT) so existing rows aren't
	// rewritten and empty/NULL on the read path falls through to the VEX
	// adapter's "decision='' → allow" back-compat fallback. See
	// internal/cli/sbom.go::exceptionItemsToVEXInput and
	// internal/sbom/vex.go::analyzeException.
	if err := s.addColumnIfMissing("policies", "decision", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("policies", "cve", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("policies", "note", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("policies", "org_id", fmt.Sprintf("TEXT NOT NULL DEFAULT '%s'", tenancy.DefaultOrgID)); err != nil {
		return err
	}
	// Wave-1 Agent B: per-row provenance metadata for the in-app exception
	// inbox (Wave-2 Agent C consumer). Both columns are nullable text so
	// existing rows stay legal — created_by carries the user_id that
	// originally created the policy, approver_id carries the user_id that
	// approved an exception (NULL for non-exception policies and for
	// pre-approval rows). The kind column carries the rule discriminator
	// — empty/NULL means a regular enforcement rule, "routing" means the
	// rule is consulted by the routing evaluator only and never blocks.
	if err := s.addColumnIfMissing("policies", "created_by", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("policies", "approver_id", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("policies", "kind", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("policies", "routing", "TEXT"); err != nil {
		return err
	}
	// Per-row expiry override for exception-mode policies. Nullable so
	// non-exception rows (and pre-migration exception rows) stay legal
	// — when NULL the legacy createdAt + org ExceptionAge fallback runs.
	// This is what makes `chainsaw exception create --expires-at` (and
	// --days) durable across `list`/`renew`.
	if err := s.addColumnIfMissing("policies", "expires_at", "TIMESTAMPTZ"); err != nil {
		return err
	}
	// Item-3b (ADR-008) per-policy grace window for ModeBlockAfterGrace
	// rules. Nullable INTEGER — NULL means "use DefaultGraceDays (7)".
	// Additive-only: pre-existing rows read back NULL and behave as the
	// default. No mode is ever rewritten; the column is inert until an
	// operator authors a `block_after_grace` policy AND enables the
	// `policy_grace_mode` flag.
	if err := s.addColumnIfMissing("policies", "grace_days", "INTEGER"); err != nil {
		return err
	}
	// BUG-MCP-5: widen policies.precedence from INTEGER (int4) to
	// BIGINT (int8) for existing databases. Exception policies write
	// int(-time.Now().UnixNano()) which always overflows int4 — the
	// fresh schema in migrate.go is already BIGINT; this catches the
	// upgrade path. Best-effort: idempotent ALTER, ignore "already
	// bigint" / driver-incompatibility errors so a re-run is safe.
	if _, err := s.db.Exec(`ALTER TABLE policies ALTER COLUMN precedence TYPE BIGINT`); err != nil {
		_ = err
	}
	return nil
}

func (s *Store) ensureEventColumns() error {
	if err := s.addColumnIfMissing("events", "requesting_ip", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("events", "request_user_agent", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("events", "requesting_country", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("events", "scanner", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("events", "severity", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("events", "scanner_payload", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("events", "org_id", fmt.Sprintf("TEXT NOT NULL DEFAULT '%s'", tenancy.DefaultOrgID)); err != nil {
		return err
	}
	// DESIGN.md §19 (audit gap G4 / deferred items D5, D6): the audit drawer
	// exposes the request correlation id and the prev/new config projections
	// for mutation events. Added as nullable TEXT so pre-backfill rows stay
	// legal and readers can distinguish "never set" from "set to empty".
	if err := s.addColumnIfMissing("events", "correlation_id", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("events", "prev_value", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("events", "new_value", "TEXT"); err != nil {
		return err
	}
	// UX_AUDIT.md §8.5 (compliance pivot, P0 for SOC2/SOX): the audit panel
	// exposes a per-actor pivot. Both columns nullable: install events
	// recorded by an unauthenticated client have no actor, while admin
	// mutations populate at least actor_user_id. The HTTP `actor` filter
	// matches either column to support free-text combobox input.
	if err := s.addColumnIfMissing("events", "actor_user_id", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("events", "actor_email", "TEXT"); err != nil {
		return err
	}
	// Repo→Team routing (opt-in): nullable, empty string when no mapping
	// matched. Always written (even when blank) so downstream queries can
	// distinguish "feature off" from "feature on, no match".
	if err := s.addColumnIfMissing("events", "team", "TEXT"); err != nil {
		return err
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_org_team ON events(org_id, team) WHERE team IS NOT NULL AND team <> ''`); err != nil {
		return fmt.Errorf("create idx_events_org_team: %w", err)
	}
	// Index actor + correlation lookups so the audit panel pivot stays
	// fast on large event tables. Partial-style indexes keep the size
	// modest by ignoring rows where the column is NULL (the common case
	// for unauthenticated install events).
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_org_actor_user ON events(org_id, actor_user_id) WHERE actor_user_id IS NOT NULL`); err != nil {
		return fmt.Errorf("create idx_events_org_actor_user: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_org_actor_email ON events(org_id, LOWER(actor_email)) WHERE actor_email IS NOT NULL`); err != nil {
		return fmt.Errorf("create idx_events_org_actor_email: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_org_correlation ON events(org_id, correlation_id) WHERE correlation_id IS NOT NULL`); err != nil {
		return fmt.Errorf("create idx_events_org_correlation: %w", err)
	}
	return nil
}

func (s *Store) ensureTenancyAndRepoColumns() error {
	if err := s.addColumnIfMissing("traffic_views", "org_id", fmt.Sprintf("TEXT NOT NULL DEFAULT '%s'", tenancy.DefaultOrgID)); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("repositories", "client_configuration_guide_template", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("repositories", "public_base_url", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("repositories", "anonymous_access", "INTEGER DEFAULT 0"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("repositories", "org_id", fmt.Sprintf("TEXT NOT NULL DEFAULT '%s'", tenancy.DefaultOrgID)); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("settings", "org_id", fmt.Sprintf("TEXT NOT NULL DEFAULT '%s'", tenancy.DefaultOrgID)); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("groups", "org_id", fmt.Sprintf("TEXT NOT NULL DEFAULT '%s'", tenancy.DefaultOrgID)); err != nil {
		return err
	}
	return nil
}

func (s *Store) ensureUserAndRoleColumns() error {
	if err := s.addColumnIfMissing("custom_roles", "description", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("custom_roles", "deleted_at", "TIMESTAMPTZ"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("users", "name", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("users", "enabled", "INTEGER NOT NULL DEFAULT 1"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("users", "disabled_at", "TIMESTAMPTZ"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("users", "totp_secret", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("users", "totp_enabled", "INTEGER DEFAULT 0"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("users", "totp_verified_at", "TIMESTAMPTZ"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("users", "two_fa_dismissed", "INTEGER DEFAULT 0"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("users", "email_verified", "INTEGER DEFAULT 0"); err != nil {
		return err
	}
	return nil
}

func (s *Store) ensureSIEMAndSCIMColumns() error {
	if err := s.addColumnIfMissing("siem_integrations", "last_event_id", "BIGINT NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("siem_integrations", "last_delivery_at", "TIMESTAMPTZ"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("siem_integrations", "last_error", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("siem_integrations", "created_by_user_id", "TEXT"); err != nil {
		return err
	}
	// hash_algo identifies how the row's token_hash was computed so the
	// verifier can pick the right algorithm. Legacy rows with NULL /
	// empty value are treated as raw SHA-256 (pre-HMAC); new rows use
	// HMAC-SHA256 with a server-side pepper.
	if err := s.addColumnIfMissing("scim_tokens", "hash_algo", "TEXT"); err != nil {
		return err
	}

	// Make password_hash nullable for SSO-only users (JIT provisioned).
	if _, err := s.db.Exec(`ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL`); err != nil {
		// Ignore errors — column may already be nullable or DB may not support this syntax.
		_ = err
	}
	return nil
}

func (s *Store) ensurePricingPlanColumns() error {
	// Usage-based pricing: plan and limit enhancements.
	if err := s.addColumnIfMissing("pricing_plans", "max_members_per_org", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("pricing_plans", "upload_bandwidth_limit", "BIGINT NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("pricing_plans", "download_bandwidth_limit", "BIGINT NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// Feature flags for plan-gated capabilities (e.g. external integrations,
	// on-prem eligibility). Stored as a JSON object so new features can be
	// added without a schema change. Webhooks are intentionally NOT listed
	// here — they are available on every tier.
	if err := s.addColumnIfMissing("pricing_plans", "features", "TEXT NOT NULL DEFAULT '{}'"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("org_usage_limits", "max_members_per_org", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}

	if err := s.seedPricingPlans(); err != nil {
		return fmt.Errorf("seed pricing plans: %w", err)
	}
	// Enforce single-default invariant before the unique index is created —
	// otherwise a legacy DB with two `is_default=1` rows would fail the index
	// migration. Prefer the seeded `free` row, fall back to lowest id.
	if _, err := s.db.Exec(`
		UPDATE pricing_plans
		SET is_default = 0, updated_at = CURRENT_TIMESTAMP
		WHERE is_default = 1
		  AND id <> (
		      SELECT id FROM pricing_plans
		      WHERE is_default = 1
		      ORDER BY (id = 'free') DESC, id ASC
		      LIMIT 1
		  )
	`); err != nil {
		return fmt.Errorf("demote duplicate default plans: %w", err)
	}
	// Partial unique index guarantees at most one is_default=1 row going
	// forward. Matches the fallback queries in plan_features.go / billing.go.
	if _, err := s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS uq_pricing_plans_default ON pricing_plans(is_default) WHERE is_default = 1`); err != nil {
		return fmt.Errorf("create unique index on pricing_plans.is_default: %w", err)
	}
	return nil
}

// ensureFindingsCodeownersColumns wires CODEOWNERS-resolved ownership
// onto the findings table. repo_id + logical_path are captured at
// creation time so downstream dispatchers (webhook, SIEM, future
// notifications) can route by repository/path without a second hop;
// owners is the pre-resolved CODEOWNERS owner list, computed once on
// the write path (see fanOutFindingFromEvent) so reads are free of the
// matcher cost. All three are nullable/empty for legacy rows.
func (s *Store) ensureFindingsCodeownersColumns() error {
	if err := s.addColumnIfMissing("findings", "repo_id", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("findings", "logical_path", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("findings", "owners", "TEXT[]"); err != nil {
		return err
	}
	// Heal legacy rows + lock in a default. The original migration added
	// `owners` as TEXT[] with no DEFAULT and no NOT NULL, so any row
	// written before this column existed has owners=NULL. The findings
	// scanner targets `[]string`, which pgx/v5 stdlib refuses to populate
	// from a NULL — every List call against a DB with even one legacy
	// row 500s with CHW-5307. Backfill once, then SET DEFAULT so the
	// post-default Create path can never reintroduce a NULL.
	if _, err := s.db.Exec(`UPDATE findings SET owners = '{}' WHERE owners IS NULL`); err != nil {
		return fmt.Errorf("backfill findings.owners: %w", err)
	}
	if _, err := s.db.Exec(`ALTER TABLE findings ALTER COLUMN owners SET DEFAULT '{}'`); err != nil {
		return fmt.Errorf("set findings.owners default: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_findings_codeowners ON findings(org_id, repo_id, logical_path)`); err != nil {
		return fmt.Errorf("create findings codeowners index: %w", err)
	}
	return nil
}

// ensureWebhookNotificationColumns extends the legacy `webhooks` table with
// the metadata the multi-key approval notify path (CHW-4833 follow-up) needs
// to fan out to Slack / Teams alongside the existing per-user
// install.blocked dispatch:
//
//   - format ('generic'|'slack'|'teams'): selects the body shape the
//     dispatcher emits. Default 'generic' preserves the
//     BlockedInstallPayload behavior every existing row already relied on.
//   - topic   ('all'|'hardening_approvals'|...): a coarse subscription
//     filter so a destination opted into hardening alerts only doesn't
//     start receiving install-block deliveries (or vice versa). Default
//     'all' matches every fan-out, again preserving legacy behavior.
//
// We deliberately avoid a parallel destinations table: every consumer
// already keys off webhooks(id, org_id, user_id, url, secret_ciphertext)
// and adding two TEXT columns is the lowest-risk schema delta. The
// dispatcher's SSRF re-validation, HMAC signing, retry budget, per-org
// rate limit, and circuit breaker all continue to apply unchanged.
func (s *Store) ensureWebhookNotificationColumns() error {
	if err := s.addColumnIfMissing("webhooks", "format", "TEXT NOT NULL DEFAULT 'generic'"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("webhooks", "topic", "TEXT NOT NULL DEFAULT 'all'"); err != nil {
		return err
	}
	// secret_ciphertext (M-SEC-05) — the encrypted-at-rest signing secret.
	// Historically added by a manual ALTER documented in MIGRATIONS.md;
	// folding it into the idempotent column set guarantees a fresh
	// migrate() lands the canonical schema the webhook Store reads.
	if err := s.addColumnIfMissing("webhooks", "secret_ciphertext", "TEXT"); err != nil {
		return err
	}
	// Migration W-CONN-1 (connectors Phase 1). The `webhooks` row is the
	// connector entity (finding #20: `format` IS the connector kind — no
	// `connector_kind` mirror). These columns let each connector kind store
	// typed config + display metadata without a column-per-kind explosion.
	//
	//   - config: per-kind JSON blob (decoded by `format`). Mirrors the
	//     SIEM `config TEXT` pattern.
	//   - display_name: human label shown in the wizard gallery.
	//   - template_id: which catalog entry seeded the connector.
	//   - oauth_token_ciphertext: Slack bot token at rest (Phase 2).
	//   - last_error / last_delivery_at: delivery health surfaced in the UI.
	if err := s.addColumnIfMissing("webhooks", "config", "TEXT NOT NULL DEFAULT '{}'"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("webhooks", "display_name", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("webhooks", "template_id", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("webhooks", "oauth_token_ciphertext", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("webhooks", "last_error", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("webhooks", "last_delivery_at", "TIMESTAMPTZ"); err != nil {
		return err
	}
	return nil
}
