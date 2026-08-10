package pgstore

import (
	"fmt"
	"strings"
)

// PgTextArray scans a Postgres `text[]` column literal into a Go []string.
//
// Why this exists: neither direction of the text[] conversion is handled
// for us. Scanning into *[]string is not covered by database/sql's default
// conversion, so the read path needs this Scanner; writing a []string is
// rejected by database/sql's argument converter before pgx ever sees it
// ("unsupported type []string, a slice of string"), so the write path
// needs encodePgTextArray below. Without this Scanner the read path errors
// with:
//
//	sql: Scan error on column index N, name "X":
//	  unsupported Scan, storing driver.Value type string into type *[]string
//
// Postgres returns text[] as a literal string in the format `{}` (empty),
// `{a,b,c}` (unquoted simple), or `{"a,b","c\"d"}` (quoted with embedded
// commas / quotes). NULL elements come through as the literal `NULL`
// keyword. We accept all three but treat NULL elements as empty strings —
// callers that store text[] today never write NULL elements.
//
// Exported because the same pgx/v5 asymmetry bites every package that
// scans text[] (CHW-5307 originally hit findings.owners, then surfaced
// in package_metadata.version_anomaly_flags). Cross-package callers
// import this rather than rolling a third copy.
//
// A parallel copy still lives in internal/finding/pg_store.go because
// that package was originally written to avoid any cross-package coupling
// for the read path. The two implementations MUST stay in lockstep —
// the matching test in internal/finding/pg_store_test.go is the canary.
type PgTextArray []string

func (p *PgTextArray) Scan(src any) error {
	if src == nil {
		*p = nil
		return nil
	}
	var s string
	switch v := src.(type) {
	case string:
		s = v
	case []byte:
		s = string(v)
	default:
		return fmt.Errorf("PgTextArray: unsupported Scan source type %T", src)
	}
	if s == "" || s == "{}" {
		*p = []string{}
		return nil
	}
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return fmt.Errorf("PgTextArray: malformed array literal %q", s)
	}
	inner := s[1 : len(s)-1]
	out := make([]string, 0, 4)
	var b strings.Builder
	inQuote := false
	i := 0
	for i < len(inner) {
		c := inner[i]
		if !inQuote && c == ',' {
			out = append(out, b.String())
			b.Reset()
			i++
			continue
		}
		if c == '"' {
			inQuote = !inQuote
			i++
			continue
		}
		if inQuote && c == '\\' && i+1 < len(inner) {
			b.WriteByte(inner[i+1])
			i += 2
			continue
		}
		b.WriteByte(c)
		i++
	}
	out = append(out, b.String())
	for j, e := range out {
		if e == "NULL" {
			out[j] = ""
		}
	}
	*p = out
	return nil
}

// encodePgTextArray renders a []string as a Postgres array literal so it
// can be passed as a bind parameter for a `text[]` column.
//
// database/sql's default argument converter rejects []string outright —
// the Exec fails with
//
//	sql: converting argument $N type: unsupported type []string,
//	  a slice of string
//
// before pgx/v5/stdlib gets a chance to encode it. Postgres accepts the
// text input form `{a,b,"c with comma"}` for array columns, so we format
// the value here and hand the driver a plain string. Nil / empty → `{}`.
// Elements that are empty, match the literal `NULL` keyword, or contain
// `"`, `\`, `,`, `{`, `}`, or whitespace are double-quoted with
// backslash escaping, per the array_in() input syntax.
//
// Mirrors ownersForArray in internal/finding/pg_store.go — that copy was
// written first (CHW-5307, findings.owners) and the two must stay in
// lockstep, the same way the Scan halves already do.
func encodePgTextArray(vals []string) string {
	if len(vals) == 0 {
		return "{}"
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, v := range vals {
		if i > 0 {
			b.WriteByte(',')
		}
		if !pgTextArrayElementNeedsQuoting(v) {
			b.WriteString(v)
			continue
		}
		b.WriteByte('"')
		for _, r := range v {
			if r == '"' || r == '\\' {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// pgTextArrayElementNeedsQuoting reports whether an element must be
// wrapped in double quotes inside a Postgres array literal. Conservative:
// when in doubt, quote.
func pgTextArrayElementNeedsQuoting(s string) bool {
	if s == "" || strings.EqualFold(s, "NULL") {
		return true
	}
	for _, r := range s {
		switch r {
		case ',', '{', '}', '"', '\\', ' ', '\t', '\n', '\r':
			return true
		}
	}
	return false
}
