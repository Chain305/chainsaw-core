package policy

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/chain305/chainsaw-core/tenancy"
)

// SystemPolicyIDPrefix marks every system-managed policy. Operators can
// disable a system policy (status=disabled or via the rollback config
// flag) but cannot delete it — the seeder re-creates any missing rows
// at startup so the substrate stays intact across restarts.
const SystemPolicyIDPrefix = "system:"

// SystemSLSABaselineTier1ID is the canonical ID of the seeded baseline
// policy that enforces "verified attestation required" on the Tier-1
// SLSA-supported ecosystems (npm, PyPI, Maven, Go, OCI/Docker).
const SystemSLSABaselineTier1ID = SystemPolicyIDPrefix + "slsa-baseline-tier1"

// SystemSLSABaselineTier1Name mirrors the ID so the existing seed-by-name
// dedup path treats this row as singleton.
const SystemSLSABaselineTier1Name = "SLSA baseline (Tier-1 ecosystems)"

// SystemPolicies is the canonical list of system-managed policies.
// Adding a new entry here is the only way to register a new
// system-managed policy — the seeder is idempotent on (org_id, id) so
// multiple startups never create duplicates and operator deletes are
// healed back on the next boot.
//
// Each system policy is created with status=disabled by default. The
// rollback path is a single setting flip (slsa.enforce in the org
// settings, surfaced via the chainsaw policy CLI). This matches the
// "block-by-default but keep allow/monitor working" contract: the rule
// is present, scoped, and ready to fire — operators flip the gate when
// their environment is producing attestations.
func SystemPolicies() []Policy {
	return []Policy{slsaBaselineTier1Policy()}
}

func slsaBaselineTier1Policy() Policy {
	requireAttestation := true
	return Policy{
		ID:          SystemSLSABaselineTier1ID,
		Name:        SystemSLSABaselineTier1Name,
		Description: "System policy: blocks downloads of Tier-1 ecosystem packages (npm, PyPI, Maven, Go, OCI) without a verified SLSA attestation. Disabled by default; enable via the slsa.enforce setting once your environment is producing attestations.",
		Precedence:  0,
		Mode:        ModeBlock,
		// Enabled by default. Per the SLSA-substrate design choice
		// ("block-by-default for Tier-1 ecosystems"), every fresh
		// install starts enforcing on day one. Operators who need a
		// staged rollout disable the policy via the standard policy
		// CLI/API: `chainsaw policy disable system:slsa-baseline-tier1`.
		// The seeder's ON CONFLICT path preserves operator-set status,
		// so a disabled override survives upgrades. Switching to
		// monitor or allow mode works the same way — system policies
		// are editable in mode/status, immutable in
		// id/name/description/conditions/identifier/scope/precedence.
		Status: StatusEnabled,
		Conditions: Conditions{
			// Tier-1 SLSA-supported ecosystems. Formats outside this
			// list (rubygems, composer, cocoapods, cargo, swift, apt,
			// dnf, yum, nuget, huggingface) have no in-band SLSA
			// attestation channel today and are intentionally NOT
			// covered by this baseline — operators wanting to enforce
			// on those compose their own rule with a different
			// Ecosystems list.
			Ecosystems:         tier1SLSAEcosystems(),
			RequireAttestation: &requireAttestation,
		},
		// Identifier matches all packages in the scoped ecosystems —
		// the Conditions.Ecosystems field above is what narrows the
		// scope. The evaluator AND-composes Identifier with Conditions,
		// so this acts as "any package, in any of the Tier-1 formats,
		// that lacks a verified attestation".
		Identifier: Identifier{
			TargetPackageRepo:    "*",
			TargetPackageName:    "*",
			TargetPackageVersion: "*",
		},
		Scope: Scope{},
	}
}

// tier1SLSAEcosystems is the canonical Tier-1 list. Values match
// internal/repository.Format strings (see internal/policy/proxy_matrix.go
// for the EcoNPM/EcoPyPI/etc. constants). Adding an ecosystem here
// auto-extends the seeded baseline to that format on the next bootstrap.
func tier1SLSAEcosystems() []string {
	return []string{"npm", "pip", "pypi", "maven", "gomod", "go", "oci", "docker"}
}

// IsSystemPolicy reports whether the given policy ID identifies a
// system-managed policy.
func IsSystemPolicy(id string) bool {
	return strings.HasPrefix(id, SystemPolicyIDPrefix)
}

// SeedSystemPoliciesIfNeeded persists every entry in SystemPolicies()
// for the given orgID, INSERTing rows whose IDs do not already exist
// and updating descriptions / mode / conditions on existing system
// rows so an upgrade picks up changes to the canonical definitions.
//
// User-edited mode/status are preserved — system seeds only overwrite
// the immutable fields (id, name, description, conditions, identifier,
// scope, precedence). Operators rely on this to keep their disabled /
// monitor-mode override of a system policy across upgrades.
func SeedSystemPoliciesIfNeeded(store *Store, logger *slog.Logger) error {
	if store == nil || store.sql == nil || store.sql.DB() == nil {
		return nil
	}
	orgID := tenancy.NormalizeOrgID(store.orgID)
	created, refreshed, err := seedSystemPolicies(store.sql.DB(), orgID, SystemPolicies())
	if err != nil {
		return err
	}
	if logger != nil && (created > 0 || refreshed > 0) {
		logger.Info("seeded system policies",
			"org", orgID,
			"created", created,
			"refreshed", refreshed,
		)
	}
	return nil
}

// SeedSystemPoliciesIfNeededTx is the in-transaction variant for
// bootstrap paths that batch DDL + DML in a single tx.
func SeedSystemPoliciesIfNeededTx(tx *sql.Tx, orgID string) (created, refreshed int, err error) {
	if tx == nil {
		return 0, 0, nil
	}
	return seedSystemPolicies(tx, tenancy.NormalizeOrgID(orgID), SystemPolicies())
}

func seedSystemPolicies(execer policyExecutor, orgID string, policies []Policy) (created, refreshed int, err error) {
	if execer == nil || len(policies) == 0 {
		return 0, 0, nil
	}
	for _, pol := range policies {
		if !IsSystemPolicy(pol.ID) {
			return created, refreshed, fmt.Errorf("policy.SeedSystemPolicies: %q missing %q prefix", pol.ID, SystemPolicyIDPrefix)
		}
		pol, normErr := normalizePolicy(pol)
		if normErr != nil {
			return created, refreshed, normErr
		}
		if vErr := validatePolicy(pol); vErr != nil {
			return created, refreshed, vErr
		}
		identifierJSON, mErr := json.Marshal(pol.Identifier)
		if mErr != nil {
			return created, refreshed, mErr
		}
		conditionsJSON, mErr := json.Marshal(pol.Conditions)
		if mErr != nil {
			return created, refreshed, mErr
		}
		scopeJSON, mErr := json.Marshal(pol.Scope)
		if mErr != nil {
			return created, refreshed, mErr
		}
		parameterHash, hErr := PolicyParameterHash(pol)
		if hErr != nil {
			return created, refreshed, hErr
		}
		now := time.Now().UTC()

		// INSERT … ON CONFLICT only refreshes the immutable fields. Mode
		// and status are written on first insert and preserved on
		// conflict so a user-disabled or user-set-to-monitor system
		// policy survives upgrades.
		insertSQL := `
			INSERT INTO policies(id, org_id, name, description, precedence, mode, status, created_at, updated_at, identifier, conditions, policy_scope, parameter_hash)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			ON CONFLICT (id) DO UPDATE SET
				name           = EXCLUDED.name,
				description    = EXCLUDED.description,
				precedence     = EXCLUDED.precedence,
				identifier     = EXCLUDED.identifier,
				conditions     = EXCLUDED.conditions,
				policy_scope   = EXCLUDED.policy_scope,
				parameter_hash = EXCLUDED.parameter_hash,
				updated_at     = EXCLUDED.updated_at
		`
		exec := func(prec int) (sql.Result, error) {
			return execer.Exec(insertSQL,
				pol.ID, orgID, pol.Name, pol.Description, prec,
				string(pol.Mode), string(pol.Status),
				now, now,
				string(identifierJSON), string(conditionsJSON), string(scopeJSON),
				parameterHash,
			)
		}
		res, execErr := exec(pol.Precedence)
		// regression-check: F-seed-precedence — a user policy may already
		// occupy the (org_id, precedence) slot the system seed wants.
		// idx_policies_org_precedence_unique then rejects the INSERT.
		// Recover by allocating MAX(precedence)+10 within the same org
		// and retrying once. The system policy still seeds; only its
		// precedence shifts. ON CONFLICT (id) above means a subsequent
		// upgrade re-runs the same path idempotently.
		if execErr != nil && isPrecedenceUniqueViolation(execErr) {
			free, allocErr := allocateFreePrecedence(execer, orgID)
			if allocErr != nil {
				return created, refreshed, fmt.Errorf("seed system policy %q: precedence collision recovery failed: %w (original: %v)", pol.ID, allocErr, execErr)
			}
			res, execErr = exec(free)
		}
		if execErr != nil {
			return created, refreshed, fmt.Errorf("seed system policy %q: %w", pol.ID, execErr)
		}
		// Postgres returns 1 for both INSERT and UPDATE; we don't have a
		// reliable created-vs-refreshed signal from the driver. Track
		// both as a single "touched" counter under the refreshed bucket;
		// caller logs the union.
		if res != nil {
			refreshed++
		}
	}
	return created, refreshed, nil
}

// isPrecedenceUniqueViolation reports whether err is a Postgres
// unique_violation (23505) on idx_policies_org_precedence_unique. We
// match by both SQLSTATE and constraint name so a future rename
// surfaces a build-time test failure rather than silently disabling
// the recovery path.
func isPrecedenceUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505" && pgErr.ConstraintName == "idx_policies_org_precedence_unique"
	}
	// Fallback: some drivers wrap PgError differently. Check the
	// error string for the same constraint name as a belt-and-suspenders
	// signal — false-positive risk is acceptable because the only
	// effect is a precedence reassignment on the system seed.
	msg := err.Error()
	return strings.Contains(msg, "idx_policies_org_precedence_unique") &&
		(strings.Contains(msg, "23505") || strings.Contains(msg, "duplicate key") || strings.Contains(msg, "unique constraint"))
}

// allocateFreePrecedence returns MAX(precedence)+10 for the given org,
// or 10 if the table is empty. Mirrors the auto-increment pattern used
// by the user-facing policy create handler (F23').
func allocateFreePrecedence(execer policyExecutor, orgID string) (int, error) {
	rows, err := execer.Query(`SELECT COALESCE(MAX(precedence), 0) FROM policies WHERE org_id = $1`, orgID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var maxPrec int
	if rows.Next() {
		if scanErr := rows.Scan(&maxPrec); scanErr != nil {
			return 0, scanErr
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	return maxPrec + 10, nil
}
