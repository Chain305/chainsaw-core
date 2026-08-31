// Package csvsafe neutralises spreadsheet formula injection at the CSV
// serialization boundary.
//
// # WHY THIS EXISTS
//
// Every CSV this product emits is assembled from values the product does not
// control. `package_name`, `repository`, `client_id` and
// `typosquat_similar_to` come from an upstream registry: anyone can publish a
// package named `=cmd|'/c calc'!A1`, and until this package existed that name
// landed verbatim in a bom export an analyst then opened in Excel. Excel,
// LibreOffice Calc and Google Sheets all evaluate a cell whose first character
// is one of `= + - @`, TAB or CR, and DDE payloads in that position have been
// a remote-code-execution primitive for a decade. Quoting the field does NOT
// stop it — the spreadsheet parses the CSV first and evaluates the cell
// afterwards, so `"=cmd|…"` is still a formula.
//
// Three properties are load-bearing:
//
//   - AT THE SINK, NEVER AT THE FIELD. Escaping belongs to the CSV rendering
//     and to nothing else. The same string must stay byte-identical in the
//     JSON API, in HTML, in headers, and in the database — a package really is
//     named what it is named, and a verdict keyed on a mangled name is a
//     wrong verdict. Every caller applies this immediately before
//     csv.Writer.Write and nowhere upstream of it.
//   - TOTAL AND IDEMPOTENT. No error return, no panic. Output re-fed through
//     Field is unchanged (the escape prefix is itself not a dangerous
//     character), so a row may pass through more than one layer without
//     growing a second prefix.
//   - ORDINARY DATA SURVIVES. A leading `-` is overwhelmingly a negative
//     number, not a formula. Numeric literals are exempt, so `-1`, `+2.5`
//     and `-1.5e3` are emitted untouched while `-1+cmd|…` is escaped.
//
// # NEUTRALISATION AND ITS COST
//
// A dangerous value is prefixed with a single quote (U+0027), the OWASP
// recommendation. The spreadsheet consumes the quote as its "treat the rest
// as literal text" marker and displays the original string. The cost is real
// and deliberate: a NON-spreadsheet consumer (pandas, awk, a SIEM CSV reader)
// sees the extra byte, because CSV carries no way to say "text, not formula"
// that only spreadsheets can hear. The alternatives are worse — stripping the
// character destroys data, and quoting does not work at all. Escaping fires
// only on the dangerous prefix set, so the overwhelming majority of rows are
// unchanged and the JSON export remains the lossless format.
//
// The one visible cost is scoped npm packages: `@babel/core` starts with a
// dangerous character and is escaped like any other. That is deliberate. A
// spreadsheet does not display `@babel/core` as text anyway — Excel reads the
// leading `@` as a formula start and renders #NAME? — so the prefix improves
// what the analyst sees. A carve-out for "looks like a package name" would be
// a second parser, and an attacker only has to satisfy it.
package csvsafe

import (
	"strconv"
	"strings"
	"unicode"
)

// escapePrefix is what a neutralised field is prefixed with. See the package
// doc for why this and not something less intrusive.
const escapePrefix = "'"

// dangerous reports whether r, appearing first in a cell, makes a spreadsheet
// treat the cell as a formula. This is the standard OWASP set. TAB and CR are
// included because a leading control character shifts the parse in some
// readers and lets the next character land in formula position.
func dangerous(r rune) bool {
	switch r {
	case '=', '+', '-', '@', '\t', '\r':
		return true
	}
	return false
}

// numericLiteral reports whether s is an ordinary number. Used to keep
// `-1` and `+2.5` out of the escape path: they begin with a dangerous
// character but a spreadsheet evaluates them to themselves, so escaping
// them would corrupt real data (a negative count read as text sorts and
// sums wrongly) for no security gain. Anything a formula could hide behind —
// `-1+1`, `-1)`, `@SUM(1)` — fails ParseFloat and is escaped.
func numericLiteral(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" {
		return false
	}
	_, err := strconv.ParseFloat(t, 64)
	return err == nil
}

// Field returns v rendered safe to place in a CSV cell.
//
// Empty and ordinary values are returned unchanged — this is not a
// transformation applied to every cell, it is a guard that fires on the
// dangerous prefixes only.
func Field(v string) string {
	if v == "" {
		return v
	}
	// Look past leading whitespace. Excel itself will not evaluate " =1+1",
	// but a reader configured to skip initial space hands the spreadsheet a
	// cell that starts at the `=`. Escaping the whitespace-led form costs a
	// prefix on a value nobody deliberately writes.
	first := rune(-1)
	for _, r := range v {
		if unicode.IsSpace(r) && r != '\t' && r != '\r' {
			continue
		}
		first = r
		break
	}
	if first == -1 || !dangerous(first) {
		return v
	}
	if numericLiteral(v) {
		return v
	}
	return escapePrefix + v
}

// Row applies Field to every cell, returning a new slice. The input is not
// mutated: callers hand us rows built from live structs, and a mutating
// escape would corrupt the value for every later consumer of that struct —
// exactly the "escape at the field" mistake this package exists to prevent.
func Row(cells []string) []string {
	if cells == nil {
		return nil
	}
	out := make([]string, len(cells))
	for i, c := range cells {
		out[i] = Field(c)
	}
	return out
}
