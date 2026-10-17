package policy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
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
	rows, err := execer.Query(`SELECT name, precedence FROM policies WHERE org_id=?`, orgID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	existingNames := make(map[string]struct{})
	// takenPrecedence: a rule added to the seed lands on orgs seeded long
	// before it, where an operator's own rule may already hold its slot.
	// idx_policies_org_precedence_unique would reject the INSERT and, at
	// boot, stop the proxy (2026-09-18), so the seed rule moves to a free
	// slot instead. Read up front: inside a Postgres transaction a failed
	// INSERT cannot be retried.
	takenPrecedence := make(map[int]struct{})
	maxPrecedence := 0
	for rows.Next() {
		var name sql.NullString
		var prec sql.NullInt64
		if err := rows.Scan(&name, &prec); err != nil {
			return 0, err
		}
		if prec.Valid {
			takenPrecedence[int(prec.Int64)] = struct{}{}
			maxPrecedence = max(maxPrecedence, int(prec.Int64))
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
		// A1 — this path INSERTs directly rather than via Store.Create, so
		// the numeric bounds have to be applied here too or a seed could
		// land a value the REST surface would refuse.
		if violations := policyRangeViolations(pol); len(violations) > 0 {
			return created, violations[0]
		}
		if _, taken := takenPrecedence[pol.Precedence]; taken {
			pol.Precedence = maxPrecedence + 10
		}
		takenPrecedence[pol.Precedence] = struct{}{}
		maxPrecedence = max(maxPrecedence, pol.Precedence)
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

// supersededSeed is a seeded rule whose definition a later release changed.
type supersededSeed struct {
	name        string
	precedences []int // every precedence an earlier seed used for the rule
	old         Policy
	current     Conditions
	summary     string // the policy-history change summary for the rewrite
}

// SeedUpgradeActor is the actor id the startup seed upgrade records in the
// policy version history.
const SeedUpgradeActor = "system:seed-upgrade"

// supersededSeeds closes the hole seedPolicies' skip-by-name leaves: an org
// seeded before a seed change keeps the old definition forever (F19). Since
// v0.22.99 the hidden-unicode block rule also refuses variation_selector, the
// GlassWorm encoding; every org seeded earlier kept bidi_override only.
//
// Entries are added only where the old definition is strictly weaker. A mode
// change the other way (block -> monitor) is deliberately NOT upgraded: an
// existing org keeps the stricter rule it already enforces. A function, not a
// var, so a caller mutating the returned conditions cannot poison the next.
func supersededSeeds() []supersededSeed {
	yes := true
	return []supersededSeed{{
		name:        "Block bidi-override hidden Unicode payloads",
		precedences: []int{120, 150},
		old: Policy{Mode: ModeBlock, Conditions: Conditions{
			HasHiddenUnicode: &yes, HiddenUnicodeKinds: []string{"bidi_override"}}},
		current: Conditions{
			HasHiddenUnicode: &yes, HiddenUnicodeKinds: []string{"bidi_override", "variation_selector"}},
		summary: "Seed upgrade (v0.22.106, F19): hiddenUnicodeKinds bidi_override -> bidi_override, variation_selector",
	}}
}

// SupersededSeedUpgrade returns the conditions to write over row when row
// still carries an earlier seeded definition EXACTLY: same name, same
// behaviour hash (mode, identifier, conditions, scope), no description, and a
// precedence an earlier seed used. Anything else means someone edited the
// rule, and it is never touched. Status is not compared and never changed: a
// disabled seeded rule stays disabled and is stronger when re-enabled.
func SupersededSeedUpgrade(row Policy) (Conditions, bool) {
	s, ok := matchSupersededSeed(row)
	return s.current, ok
}

func matchSupersededSeed(row Policy) (supersededSeed, bool) {
	name := strings.ToLower(strings.TrimSpace(row.Name))
	for _, s := range supersededSeeds() {
		if name != strings.ToLower(s.name) || strings.TrimSpace(row.Description) != "" {
			continue
		}
		if !slices.Contains(s.precedences, row.Precedence) {
			continue
		}
		got, err := PolicyParameterHash(row)
		if err != nil {
			continue
		}
		want, err := PolicyParameterHash(s.old)
		if err != nil || got != want {
			continue
		}
		return s, true
	}
	return supersededSeed{}, false
}

// upgradeSupersededSeeds rewrites, in every org, the seeded rows that still
// carry a superseded definition. It runs from ensurePolicyIntegrity on every
// startup and is idempotent: an upgraded row no longer matches the old hash.
// A row whose upgraded hash would collide with another rule in the same org
// (an operator already wrote the stronger rule by hand) is left alone rather
// than failing startup on the parameter-hash unique index. Each rewrite is
// handed to the store's seedUpgraded recorder (WithSeedUpgradeRecorder), which
// the proxy wires to the policy version history so the change shows in the
// changelog like any other update.
func (s *Store) upgradeSupersededSeeds() error {
	policiesByOrg, err := s.listPoliciesForIntegrity()
	if err != nil {
		return err
	}
	for orgID, policies := range policiesByOrg {
		for _, pol := range policies {
			seed, ok := matchSupersededSeed(pol)
			if !ok {
				continue
			}
			conditions := seed.current
			pol.Conditions = conditions
			hash, err := PolicyParameterHash(pol)
			if err != nil {
				return err
			}
			var taken int
			if err := s.sql.DB().QueryRow(`SELECT count(*) FROM policies WHERE org_id=? AND parameter_hash=? AND id<>?`,
				orgID, hash, pol.ID).Scan(&taken); err != nil {
				return err
			}
			if taken > 0 {
				continue
			}
			conditionsJSON, err := json.Marshal(conditions)
			if err != nil {
				return err
			}
			if _, err := s.sql.DB().Exec(`UPDATE policies SET conditions=?, parameter_hash=?, updated_at=? WHERE org_id=? AND id=?`,
				string(conditionsJSON), hash, time.Now().UTC(), orgID, pol.ID); err != nil {
				return fmt.Errorf("upgrade seeded policy %s: %w", pol.ID, err)
			}
			slog.Info("Upgraded seeded policy to the current definition", "org_id", orgID, "policy_id", pol.ID, "name", pol.Name)
			if s.seedUpgraded != nil {
				upgraded, err := s.ForOrg(orgID).Get(pol.ID)
				if err != nil {
					slog.Warn("seed upgrade: re-read for history failed", "org_id", orgID, "policy_id", pol.ID, "error", err)
					continue
				}
				s.seedUpgraded(orgID, upgraded, seed.summary)
			}
		}
	}
	return nil
}
