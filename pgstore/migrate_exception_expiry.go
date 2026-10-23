package pgstore

import (
	"fmt"
	"log/slog"

	"github.com/chain305/chainsaw-core/tenancy"
)

// One-shot stamp of expires_at on legacy exceptions that were about to
// lapse the moment the 30-day default started applying to every org.
//
// THE DEFECT THIS RELEASE FIXES. internal/server's settingsForOrg loaded a
// non-default org's config from a zero Config and assigned
// ExceptionAgeDays() raw, so an org with no exception.age settings row read
// 0, and policy.IsExpiredException treats 0 as "never expire". Renew sets
// expires_at = NULL, so a renew made even an explicitly dated exception
// permanent. org-default was unaffected: its age comes from
// initialExceptionAge, which maps 0 to 30.
//
// WHY A BACKFILL. The fix changes verdicts for rows already in the table:
// every such exception older than 30 days lapses at deploy, and the package
// it covered blocks again with no warning (the reminder loop skipped orgs
// without an exception.age row too). Younger ones lapse 0-30 days later,
// though they read "no expiry" until the deploy. This stamps every such
// row expires_at = now() + 30 days, so each gets a 30-day window from the
// deploy, not from a creation date nobody was counting from. The reminder
// loop prefers expires_at, so the stamped date is the one it announces.
//
// A stamped row no longer follows a later exception.age change: an
// explicit expires_at outranks the org age. Renew clears it and puts the
// row back on the org age.
//
// THE PREDICATE, AND WHY EACH CLAUSE IS LOAD-BEARING.
//
//   - Exceptions only: kind = 'exception' or the legacy isVulnerable:true
//     shape — exactly IsExpiredException's discriminator. IsExpiredException
//     honours expires_at on ANY allow row, so stamping a plain allow rule
//     would make a rule that never expired start expiring.
//   - expires_at IS NULL: a row with an explicit expiry already ages on it.
//   - not org-default (nor the legacy '' spelling): its age never read 0.
//   - no positive exception.age row for the org: such orgs already expired
//     their rows on that age; their verdicts do not change.
//   - no created_at clause: a row created 29 days ago would otherwise
//     re-block a day after deploy. Every row gets now() + 30, which is
//     never earlier than created_at + 30.
//   - status = 'enabled' only. Pending rows decide no verdict, and both
//     approve paths refuse a NULL-expiry row ("an approved exception must
//     expire"), so stamping one would make it approvable with an expiry
//     no reviewer chose and no audit row. Disabled rows decide nothing.
//
// WHY ONE-SHOT AND NOT IDEMPOTENT. Unlike clearUnverifiedAttestationIdentity,
// re-running this is not a no-op: every exception created after the deploy
// carries expires_at NULL and ages on the org default — a second boot
// would match it and push its expiry to that boot + 30 days, and every
// restart after would do it again, so nothing would ever expire. The data_backfills marker is inserted in the
// same statement as the UPDATE, so the stamp happens on the first boot of
// this binary and never again. Callers hold the migrate() advisory lock,
// so concurrent replicas cannot both win the insert.
//
// Forward-only like everything else here (see the TODO at the top of
// migrate.go). To size it before deploy, run CountLapsingLegacyExceptions
// or the same SQL by hand (exceptionExpiryBackfillPredicate).

const exceptionExpiryBackfillName = "exception_expiry_default_2026_10"

// exceptionExpiryBackfillPredicate is shared by the stamp and the census so
// the two cannot drift.
const exceptionExpiryBackfillPredicate = `
	p.mode = 'allow'
	AND p.status = 'enabled'
	AND p.expires_at IS NULL
	AND p.org_id NOT IN ('', '` + tenancy.DefaultOrgID + `')
	AND (p.kind = 'exception'
	     OR replace(lower(coalesce(p.conditions, '')), ' ', '') LIKE '%"isvulnerable":true%')
	AND NOT EXISTS (
		SELECT 1 FROM settings s
		 WHERE s.org_id = p.org_id
		   AND s.key = 'exception.age'
		   AND (CASE WHEN btrim(s.value) ~ '^[0-9]{1,9}$'
		             THEN btrim(s.value)::int ELSE 0 END) > 0
	)`

// stampLapsingLegacyExceptions applies the one-shot stamp. Returns the
// number of rows stamped; 0 on every boot after the first.
func (s *Store) stampLapsingLegacyExceptions() (int64, error) {
	return s.stampLapsingLegacyExceptionsScoped(exceptionExpiryBackfillName, "")
}

// stampLapsingLegacyExceptionsScoped is the stamp with its marker name and
// an extra predicate as parameters, so the DB test can run it against its
// own orgs and its own marker on a shared database. scope is ANDed onto
// the predicate; its placeholders start at $2 ($1 is the marker).
func (s *Store) stampLapsingLegacyExceptionsScoped(marker, scope string, scopeArgs ...any) (int64, error) {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS data_backfills (
		name TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return 0, fmt.Errorf("create data_backfills: %w", err)
	}
	res, err := s.db.Exec(`
		WITH marker AS (
			INSERT INTO data_backfills (name) VALUES ($1)
			ON CONFLICT (name) DO NOTHING
			RETURNING 1
		)
		UPDATE policies p
		   SET expires_at = now() + interval '30 days'
		 WHERE EXISTS (SELECT 1 FROM marker)
		   AND `+exceptionExpiryBackfillPredicate+` `+scope,
		append([]any{marker}, scopeArgs...)...)
	if err != nil {
		return 0, fmt.Errorf("stamp lapsing legacy exceptions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	if n > 0 {
		slog.Info("pgstore: stamped expires_at on legacy exceptions that the 30-day default would have lapsed",
			"rows", n, "expires_in_days", 30)
	}
	return n, nil
}

// CountLapsingLegacyExceptions is the read-only census: the rows the stamp
// would touch if it had not run yet. Before the deploy it is the number of
// exceptions that would otherwise lapse at deploy; after it, 0.
func (s *Store) CountLapsingLegacyExceptions() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT count(*) FROM policies p WHERE ` + exceptionExpiryBackfillPredicate).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count lapsing legacy exceptions: %w", err)
	}
	return n, nil
}
