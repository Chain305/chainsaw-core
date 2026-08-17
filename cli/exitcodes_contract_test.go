package cli

// exitcodes_contract_test.go — the guard that stops the PUBLISHED exit-code
// contract from drifting away from the code.
//
// The failure this exists to prevent: `make check-cli-docs-sync` diffs the
// generated reference against ExitCodesForDocs(), so the two agree by
// construction. Nothing checked that ExitCodesForDocs() was COMPLETE with
// respect to exitcodes.go. It was not — ExitManifestParseError(30) was declared
// right beside the constants that were published and never appeared in the
// table, and 10 was published as though ExitSoakNotCleared were its only
// meaning while three other commands used it for something else.
//
// Why an AST parse rather than reflection or a hand-kept registry:
//
//   - Reflection cannot see these at all. They are untyped package-level
//     constants; the reflect package has no access to a package's constant set
//     at runtime, so there is nothing to enumerate.
//   - A hand-kept registry of names would be a second source of truth for the
//     SET of constants. Adding a constant and forgetting to register it is the
//     exact accident this test exists to catch, and a registry cannot catch it.
//   - Parsing the source finds every constant that is actually declared,
//     whether or not the author remembered anything. The only way to defeat it
//     is to name a new exit code without the substring "exit", which is both
//     unlikely and against the file's own convention.
//
// The ledger (exitCodeAllocations) is still a written table, but it is not a
// second source of truth: its Code column is constant references (so values
// track the constants) and its Consts column is checked against this AST parse
// (so its membership tracks the constants too).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/doctor"
)

// parseExitConstants AST-parses the named files in this package's directory and
// returns every declared constant whose name contains "exit" (case-insensitive)
// and whose value resolves to an integer.
//
// Values resolve either from an integer literal or from a reference to another
// constant already collected (prScanExitParseError = ExitManifestParseError),
// so an alias is reported with the value it actually has.
func parseExitConstants(t *testing.T, files []string) map[string]int {
	t.Helper()

	fset := token.NewFileSet()
	values := map[string]int{}
	var pending [][2]string // name -> referenced identifier

	for _, name := range files {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, ident := range vs.Names {
					if !strings.Contains(strings.ToLower(ident.Name), "exit") {
						continue
					}
					if i >= len(vs.Values) {
						// Implicit repetition (iota or a repeated
						// expression). No exit code uses this today; if
						// one starts to, this test must learn about it
						// rather than silently skipping the constant.
						t.Fatalf("%s: exit-code constant %q has no explicit value (iota/implicit repetition is not supported by the contract test — give it an explicit value or teach this test)",
							name, ident.Name)
					}
					switch v := vs.Values[i].(type) {
					case *ast.BasicLit:
						if v.Kind != token.INT {
							t.Fatalf("%s: exit-code constant %q is not an integer literal (%s)", name, ident.Name, v.Value)
						}
						n, err := strconv.Atoi(v.Value)
						if err != nil {
							t.Fatalf("%s: exit-code constant %q value %q: %v", name, ident.Name, v.Value, err)
						}
						values[ident.Name] = n
					case *ast.Ident:
						pending = append(pending, [2]string{ident.Name, v.Name})
					default:
						t.Fatalf("%s: exit-code constant %q has an unsupported value expression %T — the contract test must be able to resolve it", name, ident.Name, v)
					}
				}
			}
		}
	}

	// Resolve alias references to constants collected above. One pass is
	// enough for a single level of aliasing; loop to a fixpoint so a chain
	// also resolves.
	for progress := true; progress; {
		progress = false
		rest := pending[:0]
		for _, p := range pending {
			if n, ok := values[p[1]]; ok {
				values[p[0]] = n
				progress = true
				continue
			}
			rest = append(rest, p)
		}
		pending = rest
	}
	for _, p := range pending {
		t.Fatalf("exit-code constant %q references %q, which is not a resolvable exit-code constant in this package", p[0], p[1])
	}

	return values
}

// packageGoFiles lists the non-test .go files in this package's directory.
func packageGoFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		t.Fatalf("no non-test .go files found in package dir — the AST guard is not actually scanning anything")
	}
	return out
}

// TestExitCodesForDocsIsComplete is the core guard: every Exit* constant
// declared in exitcodes.go must appear in the published table with its real
// value. ExitManifestParseError(30) failed this before the ledger landed.
func TestExitCodesForDocsIsComplete(t *testing.T) {
	declared := parseExitConstants(t, []string{"exitcodes.go"})
	if len(declared) < 8 {
		t.Fatalf("only %d exit-code constants parsed from exitcodes.go (%v) — the AST scan is not finding them, so this guard would pass vacuously", len(declared), declared)
	}

	published := map[string]int{}
	for _, e := range ExitCodesForDocs() {
		published[e.Name] = e.Code
	}

	for name, want := range declared {
		got, ok := published[name]
		if !ok {
			t.Errorf("exitcodes.go declares %s = %d but ExitCodesForDocs() does not publish it — the reference table would omit a code customers can receive", name, want)
			continue
		}
		if got != want {
			t.Errorf("ExitCodesForDocs() publishes %s = %d; exitcodes.go declares %d", name, got, want)
		}
	}
}

// TestExitCodeAllocationsCoverEveryConstant checks the other half: the ledger
// must account for every exit-code constant anywhere in package cli, not just
// the shared ones. This is what stops a seventh command from quietly minting a
// fourth meaning for 10.
func TestExitCodeAllocationsCoverEveryConstant(t *testing.T) {
	declared := parseExitConstants(t, packageGoFiles(t))

	owner := map[string]int{} // constant name -> ledger index
	for i, a := range exitCodeAllocations {
		for _, c := range a.Consts {
			if prev, dup := owner[c]; dup {
				t.Errorf("constant %q is listed in two ledger rows (%d and %d) — one number, one row", c, prev, i)
				continue
			}
			owner[c] = i
		}
	}

	for name, value := range declared {
		i, ok := owner[name]
		if !ok {
			t.Errorf("exit-code constant %s = %d is declared in package cli but missing from exitCodeAllocations in exitcodes.go — add a one-line row so the number has a documented owner (and, if it is >= 5, so it reaches the published table)", name, value)
			continue
		}
		if got := exitCodeAllocations[i].Code; got != value {
			t.Errorf("exitCodeAllocations row for %s says Code=%d but the constant is %d", name, got, value)
		}
	}

	for name := range owner {
		if _, ok := declared[name]; !ok {
			t.Errorf("exitCodeAllocations lists constant %q, which is not declared anywhere in package cli — a stale ledger row", name)
		}
	}
}

// TestExitCodeAllocationsShape pins the invariants the published tables and the
// generator's own prose depend on.
func TestExitCodeAllocationsShape(t *testing.T) {
	for i, a := range exitCodeAllocations {
		if a.Desc == "" || a.Owner == "" {
			t.Errorf("exitCodeAllocations[%d] (code %d) has an empty Owner or Desc", i, a.Code)
		}
		if len(a.Consts) == 0 {
			t.Errorf("exitCodeAllocations[%d] (code %d) names no constant", i, a.Code)
		}
		switch a.Kind {
		case "shared":
			if a.Code < 0 || a.Code > 4 {
				t.Errorf("exitCodeAllocations[%d]: code %d is Kind=shared but outside the 0–4 cross-cutting buckets", i, a.Code)
			}
		case "command":
			// cmd/gen-cli-docs prints "Command-specific outcomes start at
			// 10 so they never collide with the shared buckets" above this
			// table. A row below 10 would make that sentence false.
			if a.Code < 10 {
				t.Errorf("exitCodeAllocations[%d]: code %d is Kind=command but below 10; the generated reference states command-specific outcomes start at 10", i, a.Code)
			}
		case "":
			if a.Code >= 5 {
				t.Errorf("exitCodeAllocations[%d]: code %d is in the command-specific space but is not published (Kind is empty) — an undocumented claim on a number is how 10 acquired three meanings", i, a.Code)
			}
		default:
			t.Errorf("exitCodeAllocations[%d]: unknown Kind %q (want \"shared\", \"command\", or \"\")", i, a.Kind)
		}
	}
}

// TestExitCodesForDocsRowsAreDistinct guards the rendered table itself: two
// rows may share a Code (10 and 30 legitimately do, which is the point of
// publishing them), but never a Code AND a Name.
func TestExitCodesForDocsRowsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range ExitCodesForDocs() {
		key := strconv.Itoa(e.Code) + "|" + e.Name
		if seen[key] {
			t.Errorf("ExitCodesForDocs() emits a duplicate row for %d/%s", e.Code, e.Name)
		}
		seen[key] = true
		if e.Name == "" || e.Desc == "" {
			t.Errorf("ExitCodesForDocs() row %d has an empty Name or Desc", e.Code)
		}
	}
}

// TestExitCodesForDocsPublishEveryOverloadedMeaning pins that the numbers we know
// carry several meanings ship with every meaning in the table. Publishing 10
// as only ExitSoakNotCleared, while `pr-scan --help` told a different user 10
// meant warning-level findings, is the defect this file exists for.
func TestExitCodesForDocsPublishEveryOverloadedMeaning(t *testing.T) {
	byCode := map[int][]string{}
	for _, e := range ExitCodesForDocs() {
		byCode[e.Code] = append(byCode[e.Code], e.Name)
	}
	for code, wantAtLeast := range map[int]int{10: 3, 30: 2} {
		if got := len(byCode[code]); got < wantAtLeast {
			t.Errorf("exit code %d is published with %d meaning(s) (%v); it has at least %d — a single-meaning row makes the reference contradict the commands' own --help",
				code, got, byCode[code], wantAtLeast)
		}
	}
}

// TestDoctorUpgradeCheckExitCodesMatchPublishedCaveat pins the one overload
// that is NOT a constant in this package: `doctor --upgrade-check` gets its
// code from core/doctor's Report.ExitCode(), which returns 1 for warnings and
// 2 for breaking changes. The ExitBlocked and ExitOpError rows tell readers so;
// if those values ever change, the caveat text must change with them.
func TestDoctorUpgradeCheckExitCodesMatchPublishedCaveat(t *testing.T) {
	cases := []struct {
		name string
		sev  doctor.Severity
		want int
	}{
		{"clean", doctor.SeverityOK, 0},
		{"warnings", doctor.SeverityWarn, ExitBlocked},
		{"breaking", doctor.SeverityBreaking, ExitOpError},
	}
	for _, tc := range cases {
		r := &doctor.Report{Findings: []doctor.Finding{{Severity: tc.sev}}}
		if got := r.ExitCode(); got != tc.want {
			t.Errorf("doctor --upgrade-check %s exits %d; the published ExitBlocked/ExitOpError caveats say %d", tc.name, got, tc.want)
		}
	}
}
