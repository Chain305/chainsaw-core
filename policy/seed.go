package policy

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/tenancy"
)

type policyExecutor interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
}

// SeedPoliciesIfNeeded persists policies for the store's org when they do not already exist.
func SeedPoliciesIfNeeded(store *Store, policies []Policy, logger *slog.Logger) error {
	if store == nil || len(policies) == 0 {
		return nil
	}
	created, err := seedPolicies(store.sql.DB(), tenancy.NormalizeOrgID(store.orgID), policies)
	if err != nil {
		return err
	}
	if created > 0 && logger != nil {
		logger.Info("Seeded policies into database", "count", created)
	}
	return nil
}

// SeedPoliciesIfNeededTx persists policies for an org inside the provided transaction.
func SeedPoliciesIfNeededTx(tx *sql.Tx, orgID string, policies []Policy) (int, error) {
	if tx == nil || len(policies) == 0 {
		return 0, nil
	}
	return seedPolicies(tx, tenancy.NormalizeOrgID(orgID), policies)
}

func seedPolicies(execer policyExecutor, orgID string, policies []Policy) (int, error) {
	if execer == nil || len(policies) == 0 {
		return 0, nil
	}
	orgID = tenancy.NormalizeOrgID(orgID)
	rows, err := execer.Query(`SELECT name FROM policies WHERE org_id=?`, orgID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	existingNames := make(map[string]struct{})
	for rows.Next() {
		var name sql.NullString
		if err := rows.Scan(&name); err != nil {
			return 0, err
		}
		if !name.Valid {
			continue
		}
		normalized := strings.ToLower(strings.TrimSpace(name.String))
		if normalized != "" {
			existingNames[normalized] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	created := 0
	for _, pol := range policies {
		name := strings.ToLower(strings.TrimSpace(pol.Name))
		if name != "" {
			if _, ok := existingNames[name]; ok {
				continue
			}
		}
		if pol.Status == "" {
			pol.Status = StatusEnabled
		}
		pol, err = normalizePolicy(pol)
		if err != nil {
			return created, err
		}
		if err := validatePolicy(pol); err != nil {
			return created, err
		}
		id, err := newID()
		if err != nil {
			return created, err
		}
		now := time.Now().UTC()
		pol.ID = id
		pol.Name = strings.TrimSpace(pol.Name)
		pol.Description = strings.TrimSpace(pol.Description)
		pol.CreatedAt = now
		pol.UpdatedAt = now
		parameterHash, err := PolicyParameterHash(pol)
		if err != nil {
			return created, err
		}

		identifierJSON, err := json.Marshal(pol.Identifier)
		if err != nil {
			return created, err
		}
		conditionsJSON, err := json.Marshal(pol.Conditions)
		if err != nil {
			return created, err
		}
		scopeJSON, err := json.Marshal(pol.Scope)
		if err != nil {
			return created, err
		}
		_, err = execer.Exec(`INSERT INTO policies(id, org_id, name, description, precedence, mode, status, created_at, updated_at, identifier, conditions, policy_scope, parameter_hash)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			pol.ID, orgID, pol.Name, pol.Description, pol.Precedence, string(pol.Mode), string(pol.Status),
			pol.CreatedAt, pol.UpdatedAt, string(identifierJSON), string(conditionsJSON), string(scopeJSON), parameterHash)
		if err != nil {
			return created, err
		}
		if pol.Name != "" {
			existingNames[strings.ToLower(pol.Name)] = struct{}{}
		}
		created++
	}
	return created, nil
}
