package pgstore

import (
	"fmt"
	"strings"
)

// PgTextArray scans a Postgres `text[]` column literal into a Go []string.
//
// Why this exists: pgx/v5/stdlib (the driver wired in store.go) supports
// []string as an INSERT param for text[] columns out of the box, but the
// reverse (Scan into *[]string) is not handled by database/sql's default
// conversion. Without this Scanner the read path errors with:
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
