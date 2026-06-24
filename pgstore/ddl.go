package pgstore

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ddlIdentRe matches the subset of identifiers we ever pass as table, column,
// or constraint names: lowercase ASCII letters, digits, and underscores,
// starting with a letter or underscore. Anything outside this grammar is
// rejected by validateDDLIdentifier rather than sanitised, so a future caller
// cannot smuggle interpolation tricks through addColumnIfMissing /
// addConstraintIfMissing.
var ddlIdentRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// ddlColumnDefRe accepts the column-type/default grammar actually used today:
//
//	TYPE [NOT NULL] [DEFAULT <literal>]
//
// where TYPE is one of a short whitelist, and <literal> is either a
// single-quoted string with any embedded single quotes doubled, an integer,
// or one of the keyword literals TRUE / FALSE / NULL. The regex is
// intentionally strict; new shapes must be added here explicitly.
var ddlColumnDefRe = regexp.MustCompile(
	`^(?:TEXT|TEXT\[\]|SMALLINT|INTEGER|BIGINT|BOOLEAN|TIMESTAMPTZ|JSONB|BYTEA)` +
		`(?:\s+NOT\s+NULL)?` +
		`(?:\s+DEFAULT\s+(?:'(?:[^'\\]|'')*'|-?[0-9]+|TRUE|FALSE|NULL))?$`,
)

// ddlCheckInListRe matches the CHECK-constraint shape we use today:
//
//	CHECK (<col> IS NULL OR <col> IN ('a','b',...))
//
// or the simpler `CHECK (<col> IN (...))`. Literals are single-quoted
// strings with doubled embedded quotes.
var ddlCheckInListRe = regexp.MustCompile(
	`^CHECK\s+\(\s*` +
		`(?:([a-z_][a-z0-9_]*)\s+IS\s+NULL\s+OR\s+)?` +
		`([a-z_][a-z0-9_]*)\s+IN\s+\(\s*` +
		`'(?:[^'\\]|'')*'(?:\s*,\s*'(?:[^'\\]|'')*')*` +
		`\s*\)\s*\)$`,
)

// ddlForeignKeyRe matches the FK shape we use today:
//
//	FOREIGN KEY (<col>) REFERENCES <table>(<col>) ON DELETE <action>
var ddlForeignKeyRe = regexp.MustCompile(
	`^FOREIGN\s+KEY\s+\(\s*([a-z_][a-z0-9_]*)\s*\)\s+` +
		`REFERENCES\s+([a-z_][a-z0-9_]*)\s*\(\s*([a-z_][a-z0-9_]*)\s*\)` +
		`\s+ON\s+DELETE\s+(?:RESTRICT|CASCADE|SET\s+NULL|NO\s+ACTION)$`,
)

// validateDDLIdentifier is the single chokepoint used by addColumnIfMissing
// and addConstraintIfMissing before any value is interpolated into a DDL
// string. Rejecting here means even a mistakenly-user-sourced caller cannot
// produce a string that escapes the identifier grammar.
func validateDDLIdentifier(kind, ident string) error {
	if ident == "" {
		return fmt.Errorf("pgstore: empty %s identifier", kind)
	}
	if len(ident) > 63 {
		// Postgres identifier limit; reject rather than silently truncate.
		return fmt.Errorf("pgstore: %s identifier %q exceeds 63 chars", kind, ident)
	}
	if !ddlIdentRe.MatchString(ident) {
		return fmt.Errorf("pgstore: %s identifier %q is not a safe identifier", kind, ident)
	}
	return nil
}

// validateColumnDefinition enforces the whitelist grammar for column-type
// fragments. See ddlColumnDefRe for the accepted shapes.
func validateColumnDefinition(def string) error {
	trimmed := strings.TrimSpace(def)
	if trimmed == "" {
		return fmt.Errorf("pgstore: empty column definition")
	}
	if !ddlColumnDefRe.MatchString(trimmed) {
		return fmt.Errorf("pgstore: column definition %q is not in the allowed grammar", def)
	}
	return nil
}

// validateConstraintDefinition enforces the small set of constraint shapes
// we actually emit today: bounded IN-list CHECK constraints and simple
// FOREIGN KEY clauses.
func validateConstraintDefinition(def string) error {
	trimmed := strings.TrimSpace(def)
	if trimmed == "" {
		return fmt.Errorf("pgstore: empty constraint definition")
	}
	if ddlCheckInListRe.MatchString(trimmed) || ddlForeignKeyRe.MatchString(trimmed) {
		return nil
	}
	return fmt.Errorf("pgstore: constraint definition %q is not in the allowed grammar", def)
}

func (s *Store) addColumnIfMissing(table, column, definition string) error {
	if err := validateDDLIdentifier("table", table); err != nil {
		return err
	}
	if err := validateDDLIdentifier("column", column); err != nil {
		return err
	}
	if err := validateColumnDefinition(definition); err != nil {
		return fmt.Errorf("add column %s.%s: %w", table, column, err)
	}
	exists, err := s.columnExists(table, column)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	// Identifiers are double-validated: they match ddlIdentRe AND are
	// re-quoted via pgx.Identifier.Sanitize so any future identifier-grammar
	// drift still can't escape quoting.
	qTable := pgx.Identifier{table}.Sanitize()
	qColumn := pgx.Identifier{column}.Sanitize()
	stmt := fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s`, qTable, qColumn, strings.TrimSpace(definition))
	if _, err := s.db.Exec(stmt); err != nil {
		return fmt.Errorf("add column %s.%s: %w", table, column, err)
	}
	return nil
}

func (s *Store) columnExists(table, column string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name=? AND column_name=?)`,
		strings.ToLower(table), strings.ToLower(column)).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// addConstraintIfMissing is the FK/CHECK sibling of addColumnIfMissing — Postgres
// has no `ADD CONSTRAINT IF NOT EXISTS` for non-UNIQUE constraints, so we look
// up information_schema and skip if the constraint already lives on the table.
func (s *Store) addConstraintIfMissing(table, name, definition string) error {
	if err := validateDDLIdentifier("table", table); err != nil {
		return err
	}
	if err := validateDDLIdentifier("constraint", name); err != nil {
		return err
	}
	if err := validateConstraintDefinition(definition); err != nil {
		return fmt.Errorf("add constraint %s.%s: %w", table, name, err)
	}
	var exists bool
	err := s.db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM information_schema.table_constraints
		               WHERE table_schema='public' AND table_name=? AND constraint_name=?)`,
		strings.ToLower(table), strings.ToLower(name)).Scan(&exists)
	if err != nil {
		return fmt.Errorf("check constraint %s.%s: %w", table, name, err)
	}
	if exists {
		return nil
	}
	qTable := pgx.Identifier{table}.Sanitize()
	qName := pgx.Identifier{name}.Sanitize()
	stmt := fmt.Sprintf(`ALTER TABLE %s ADD CONSTRAINT %s %s`, qTable, qName, strings.TrimSpace(definition))
	if _, err := s.db.Exec(stmt); err != nil {
		return fmt.Errorf("add constraint %s.%s: %w", table, name, err)
	}
	return nil
}
