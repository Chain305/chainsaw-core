package cli

// Y3/Y4 — bare os.Exit inside a RunE breaks two contracts at once.
//
//	(a) exitcodes.go is bypassed: the process leaves on a number no
//	    classifier ever saw.
//	(b) Execute() never reaches markSessionEnd + flushTelemetry, so the WHOLE
//	    telemetry batch is dropped — including cli.session.completed, the one
//	    event carrying exit_code and error_class. Measured on the commands
//	    fixed in the preceding wave: pr-scan (exit 10), scan-repo (exit 10)
//	    and doctor --strict (exit 30) each emitted ZERO cli.session.completed
//	    before their fix.
//
// The remedy in every case is `return &ExitCodeError{Code: …}`. ExitCodeError
// carries arbitrary codes, so the domain-specific numbers (lintExitError=2,
// doctor's 1/2, scan-actions' 1, verify-hook's 1) survive untouched — they are
// a published contract.
//
// TestPackage_NoBareOSExitOutsideTheAllowlist is the set-completeness guard:
// it reads the package's own source, so a NEW bare exit fails here instead of
// silently shipping. The four behavioural tests below prove the returned
// errors carry the exact published codes.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// bareExitAllowlist maps a file to why a direct os.Exit is correct there.
// Every entry is a place OUTSIDE a cobra RunE, or one that flushes telemetry
// itself before leaving.
var bareExitAllowlist = map[string]string{
	// Execute() IS the process boundary: it calls markSessionEnd and
	// flushTelemetry and then exits. Plus the --cargo-plugin fast path, which
	// runs before cobra parses anything and has no session to end.
	"root.go": "Execute() is the process boundary; it flushes telemetry first",
	// The guard wrappers proxy a real package manager and must reproduce its
	// exit status verbatim. Both sites call flushTelemetry() first, so the
	// batch is not dropped.
	"guard_install.go": "guard wrappers mirror the wrapped tool's status; both sites flushTelemetry() first",
}

func TestPackage_NoBareOSExitOutsideTheAllowlist(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	var offenders []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if _, ok := bareExitAllowlist[name]; ok {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Exit" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "os" {
				return true
			}
			offenders = append(offenders, name+":"+
				itoa(fset.Position(call.Lparen).Line))
			return true
		})
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("bare os.Exit outside the allowlist: %v\n\n"+
			"A RunE that exits directly bypasses exitcodes.go AND leaves the process "+
			"before Execute() reaches markSessionEnd + flushTelemetry, dropping the whole "+
			"telemetry batch including cli.session.completed (which carries exit_code and "+
			"error_class). Return &ExitCodeError{Code: …} instead — it carries arbitrary "+
			"codes, so a domain-specific number survives unchanged. If the site genuinely "+
			"belongs outside a RunE, add it to bareExitAllowlist with the reason.", offenders)
	}
}

// ── the four converted sites keep their published exit codes ─────────────────

func TestScanActionsCmd_HighSeverityReturnsExitCodeErrorNotOSExit(t *testing.T) {
	dir := t.TempDir()
	wf := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// A known-malicious action is the high-severity trigger scan_actions'
	// help documents as "exit 1".
	body := "name: ci\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n" +
		"      - uses: tj-actions/changed-files@v35\n"
	if err := os.WriteFile(filepath.Join(wf, "ci.yml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	cmd := newScanActionsTestCmd()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	code, err := runScanActions(cmd, []string{dir})
	if err != nil {
		t.Fatalf("runScanActions: %v", err)
	}
	if code == 0 {
		t.Skipf("fixture produced no high-severity finding; the exit assertion needs one:\n%s", out.String())
	}

	// The RunE wrapper is what used to call os.Exit. Drive it directly.
	runErr := scanActionsCmd.RunE(cmd, []string{dir})
	var coded *ExitCodeError
	if !errors.As(runErr, &coded) {
		t.Fatalf("RunE returned %T (%v), want *ExitCodeError — a bare os.Exit here would "+
			"kill this test binary and drop cli.session.completed in production", runErr, runErr)
	}
	if coded.Code != ExitBlocked {
		t.Errorf("exit code = %d, want ExitBlocked(%d) — scan-actions publishes 1 for a "+
			"high-severity finding", coded.Code, ExitBlocked)
	}
	if coded.Err != nil {
		t.Errorf("Err = %v, want nil so renderError adds nothing on top of the findings table", coded.Err)
	}
}

func TestPolicyLint_FindingsReturnExitCodeErrorNotOSExit(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{
			// Standalone codesmell gate → ERROR → the published "2 any errors".
			name: "error",
			body: "- name: smell-only\n  action: block\n  conditions:\n    usesEval: true\n",
			want: lintExitError,
		},
		{
			// Three-state nil-as-false reliance → WARNING → "1 warnings only".
			name: "warning",
			body: "- name: archived-false\n  action: block\n  conditions:\n" +
				"    identifier: lodash\n    repoArchived: false\n",
			want: lintExitWarning,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "policy.yaml")
			if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write policy: %v", err)
			}

			cmd := &cobra.Command{Use: "lint", RunE: runPolicyLint}
			cmd.Flags().String("input", p, "")
			cmd.Flags().String("format", "text", "")
			cmd.Flags().String("output", "", "")
			var out, errb bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&errb)

			err := runPolicyLint(cmd, nil)
			var coded *ExitCodeError
			if !errors.As(err, &coded) {
				t.Fatalf("runPolicyLint returned %T (%v), want *ExitCodeError.\nlint output:\n%s",
					err, err, out.String())
			}
			if coded.Code != tc.want {
				t.Errorf("exit code = %d, want %d — `policy lint --help` publishes "+
					"\"0 clean, 1 warnings only, 2 any errors\"\noutput:\n%s",
					coded.Code, tc.want, out.String())
			}
		})
	}
}

func TestPolicyLint_CleanTreeStillReturnsNil(t *testing.T) {
	// The control for the two above: a lint that finds nothing must not
	// manufacture a non-zero code.
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	body := "- name: pinned\n  action: block\n  conditions:\n    identifier: lodash\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	cmd := &cobra.Command{Use: "lint", RunE: runPolicyLint}
	cmd.Flags().String("input", p, "")
	cmd.Flags().String("format", "json", "")
	cmd.Flags().String("output", "", "")
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	if err := runPolicyLint(cmd, nil); err != nil {
		t.Fatalf("clean lint returned %v, want nil\noutput:\n%s", err, out.String())
	}
}

func TestDoctorUpgradeCheck_NonZeroReturnsExitCodeErrorWithoutOverride(t *testing.T) {
	// doctorExitOverride exists ONLY because the failing path used to end in
	// os.Exit, which a test cannot observe. Clear it: the path must now be
	// observable as a returned error.
	prev := doctorExitOverride
	doctorExitOverride = nil
	t.Cleanup(func() { doctorExitOverride = prev })

	t.Setenv("CHAINSAW_DATABASE_URL", "postgres://x")
	t.Setenv("CHAINSAW_STRICT_JWT", "1")
	t.Setenv("CHAINSAW_FLAGS", "--embedded-ui")

	cmd := newDoctorCmd()
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("no-color", true, "")
	_ = cmd.Flags().Set("upgrade-check", "true")
	_ = cmd.Flags().Set("skip-network", "true")

	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	err := cmd.Execute()
	var coded *ExitCodeError
	if !errors.As(err, &coded) {
		t.Fatalf("doctor --upgrade-check returned %T (%v), want *ExitCodeError.\noutput:\n%s",
			err, err, out.String())
	}
	if coded.Code != 2 {
		t.Errorf("exit code = %d, want 2 (breaking) — report.ExitCode() is unchanged by the "+
			"os.Exit removal\noutput:\n%s", coded.Code, out.String())
	}
}

func TestVerifyHookCmd_FailReturnsExitCodeErrorWithoutOverride(t *testing.T) {
	// Reachable audit API that never shows the sentinel → genuine FAIL.
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"total": 0, "events": []map[string]any{}})
	})
	withConfiguredServer(t, srv.URL)

	prev := verifyExitOverride
	verifyExitOverride = nil
	t.Cleanup(func() { verifyExitOverride = prev })

	// Stub the driver so this never shells out to the developer's REAL `pip`.
	// The assertions below are about output shape and exit code, not about
	// pip itself; without the stub this test reached the network and let the
	// machine's own chainsaw install-hook write to the real config home.
	withStubVerifyDriver(t, "pip")
	cmd := newDoctorVerifyHookCmd()
	cmd.Flags().Bool("json", true, "")
	cmd.SetArgs([]string{"pip", "--json", "--timeout", "1s"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetContext(context.Background())
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	err := cmd.Execute()
	if !strings.Contains(out.String(), string(verifyFail)) {
		t.Skipf("environment did not produce a FAIL verdict (stdout=%q); the exit assertion needs one", out.String())
	}
	var coded *ExitCodeError
	if !errors.As(err, &coded) {
		t.Fatalf("verify-hook FAIL returned %T (%v), want *ExitCodeError.\nstdout:\n%s\nstderr:\n%s",
			err, err, out.String(), errb.String())
	}
	if coded.Code != 1 {
		t.Errorf("exit code = %d, want 1 — CI gates key on it", coded.Code)
	}
}
