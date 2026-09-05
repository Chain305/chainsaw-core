package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/policy"
)

// TestPolicyLint exercises the three core matrix rows of the lint
// engine: standalone context-only condition (error), the same
// condition paired with a real gate (clean), and an explicit
// nil-as-false reliance on a three-state field (warning). Driven by a
// table of synthetic policy JSON files so a regression on any one row
// fails its own subtest.
func TestPolicyLint(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantErrors  int
		wantWarns   int
		wantTypeSub string // substring of finding type, "" = expect none
	}{
		{
			name: "standalone-uses-eval-is-error",
			body: `{
				"id": "p1", "name": "standalone-eval", "mode": "block", "status": "enabled", "precedence": 100,
				"conditions": {"usesEval": true}
			}`,
			wantErrors:  1,
			wantTypeSub: "standalone-codesmell",
		},
		{
			name: "uses-eval-paired-with-install-script-is-clean",
			body: `{
				"id": "p2", "name": "paired", "mode": "block", "status": "enabled", "precedence": 100,
				"conditions": {"usesEval": true, "hasInstallScript": true}
			}`,
		},
		{
			name: "uses-eval-with-identifier-is-clean",
			body: `{
				"id": "p3", "name": "scoped-eval", "mode": "block", "status": "enabled", "precedence": 100,
				"identifier": {"targetPackageName": "evil-pkg"},
				"conditions": {"usesEval": true}
			}`,
		},
		{
			name: "first-time-collaborator-false-is-warning",
			body: `{
				"id": "p4", "name": "ftc-false", "mode": "block", "status": "enabled", "precedence": 100,
				"identifier": {"targetPackageName": "*"},
				"conditions": {"firstTimeCollaborator": false}
			}`,
			wantWarns:   1,
			wantTypeSub: "three-state-nil-as-false",
		},
		{
			name: "all-five-codesmell-standalone-still-one-finding",
			body: `{
				"id": "p5", "name": "kitchen-sink", "mode": "block", "status": "enabled", "precedence": 100,
				"conditions": {
					"usesEval": true, "networkAccess": true, "shellAccess": true,
					"filesystemAccess": true, "envVarAccess": true
				}
			}`,
			wantErrors:  1,
			wantTypeSub: "standalone-codesmell",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fp := filepath.Join(dir, "policy.json")
			if err := os.WriteFile(fp, []byte(tc.body), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
			findings, _, err := lintPolicyFile(fp)
			if err != nil {
				t.Fatalf("lintPolicyFile: %v", err)
			}
			var errs, warns int
			for _, f := range findings {
				switch f.Severity {
				case lintFindingError:
					errs++
				case lintFindingWarning:
					warns++
				}
			}
			if errs != tc.wantErrors {
				t.Errorf("errors: got %d, want %d (findings=%+v)", errs, tc.wantErrors, findings)
			}
			if warns != tc.wantWarns {
				t.Errorf("warnings: got %d, want %d (findings=%+v)", warns, tc.wantWarns, findings)
			}
			if tc.wantTypeSub != "" {
				found := false
				for _, f := range findings {
					if strings.Contains(f.Type, tc.wantTypeSub) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected finding of type %q, got %+v", tc.wantTypeSub, findings)
				}
			}
		})
	}
}

// TestPolicyLint_ArrayBundle confirms that a bundle file containing
// an array of policies is iterated end-to-end and that each entry
// gets its own line number for diffable output.
func TestPolicyLint_ArrayBundle(t *testing.T) {
	body := `[
  {"id":"a","name":"a","mode":"block","status":"enabled","precedence":100,"conditions":{"usesEval":true}},
  {"id":"b","name":"b","mode":"block","status":"enabled","precedence":100,"identifier":{"targetPackageName":"x"},"conditions":{"firstTimeCollaborator":false}}
]`
	dir := t.TempDir()
	fp := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(fp, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, rules, err := lintPolicyFile(fp)
	if err != nil {
		t.Fatalf("lintPolicyFile: %v", err)
	}
	if rules != 2 {
		t.Errorf("rules: got %d, want 2", rules)
	}
	var errs, warns int
	for _, f := range findings {
		switch f.Severity {
		case lintFindingError:
			errs++
		case lintFindingWarning:
			warns++
		}
	}
	if errs != 1 || warns != 1 {
		t.Errorf("got errors=%d warnings=%d, want 1/1 (findings=%+v)", errs, warns, findings)
	}
}

// TestPolicyLint_DirectoryWalk confirms a directory input is walked
// recursively, deterministically sorted, and that non-policy files
// are ignored.
func TestPolicyLint_DirectoryWalk(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"),
		[]byte(`{"id":"a","name":"a","mode":"block","status":"enabled","precedence":100,"conditions":{"usesEval":true}}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "readme.md"), []byte("ignore me"), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := collectPolicyFiles(dir)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(set.Files) != 1 {
		t.Fatalf("expected 1 policy file, got %v", set.Files)
	}
	if !set.Swept {
		t.Error("a directory input must be marked as a sweep")
	}
	if len(set.Skipped) != 0 {
		t.Errorf("clean tree should skip nothing, got %+v", set.Skipped)
	}
}

// TestPolicyLint_WildcardIdentifierIsNotAPairing is P11. The save-time
// validator's hasMeaningfulValue rejects "", "*" and "all" alike, but
// lint carried its own hasIdentifier that accepted any non-empty string.
// So this policy linted "No findings — policies are clean" and was then
// rejected by rejectStandaloneContextOnlyConditions on POST — the exact
// rejection lint exists to surface first.
func TestPolicyLint_WildcardIdentifierIsNotAPairing(t *testing.T) {
	cases := []struct {
		name       string
		identifier string
		scope      string
		wantErrors int
	}{
		{"wildcard name is not a pairing", `{"targetPackageName": "*"}`, "", 1},
		{`"all" is not a pairing`, `{"targetPackageRepo": "all"}`, "", 1},
		{"whitespace-only is not a pairing", `{"targetPackageName": "   "}`, "", 1},
		{"real name IS a pairing", `{"targetPackageName": "evil-pkg"}`, "", 0},
		{"wildcard scope is not a pairing", "", `{"targetClient": ["*"]}`, 1},
		{"real scope IS a pairing", "", `{"targetClient": ["ci-runner"]}`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"id":"p","name":"p","mode":"block","status":"enabled","precedence":100,` +
				`"conditions":{"usesEval":true}`
			if tc.identifier != "" {
				body += `,"identifier":` + tc.identifier
			}
			if tc.scope != "" {
				body += `,"scope":` + tc.scope
			}
			body += `}`

			fp := filepath.Join(t.TempDir(), "policy.json")
			if err := os.WriteFile(fp, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			findings, _, err := lintPolicyFile(fp)
			if err != nil {
				t.Fatalf("lintPolicyFile: %v", err)
			}
			var errs int
			for _, f := range findings {
				if f.Severity == lintFindingError {
					errs++
				}
			}
			if errs != tc.wantErrors {
				t.Errorf("errors: got %d, want %d — lint must agree with the server's save-time validator (findings=%+v)",
					errs, tc.wantErrors, findings)
			}
		})
	}
}

// TestPolicyLint_RepoArchivedCheckFires is P12. rawHasField re-marshalled
// the TYPED policy.Policy, and policy.Conditions has no repoArchived
// field — encoding/json had already dropped the key on the way IN, so the
// check could never fire and the warning advertised in the command's Long
// help was dead code from the day it was written.
func TestPolicyLint_RepoArchivedCheckFires(t *testing.T) {
	body := `{
		"id": "p", "name": "archived-repo", "mode": "block", "status": "enabled", "precedence": 100,
		"identifier": {"targetPackageName": "evil-pkg"},
		"conditions": {"repoArchived": false, "hasInstallScript": true}
	}`
	fp := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(fp, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, _, err := lintPolicyFile(fp)
	if err != nil {
		t.Fatalf("lintPolicyFile: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Type == "three-state-nil-as-false" && strings.Contains(f.Message, "repoArchived") {
			found = true
		}
	}
	if !found {
		t.Errorf("a policy referencing repoArchived must produce the three-state warning; got %+v", findings)
	}

	// Negative control: a policy that does NOT mention repoArchived must
	// not produce it — the raw-bytes search must stay keyed to the file.
	fp2 := filepath.Join(t.TempDir(), "clean.json")
	if err := os.WriteFile(fp2, []byte(`{"id":"q","name":"q","mode":"block","status":"enabled","precedence":100,
		"identifier":{"targetPackageName":"evil-pkg"},"conditions":{"hasInstallScript":true}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	findings2, _, err := lintPolicyFile(fp2)
	if err != nil {
		t.Fatalf("lintPolicyFile: %v", err)
	}
	for _, f := range findings2 {
		if strings.Contains(f.Message, "repoArchived") {
			t.Errorf("false positive: %+v", f)
		}
	}
}

// --------------------------------------------------------------------------
// Directory-sweep robustness. Everything below covers the two defects the
// external QA walk surfaced:
//
//	(1) the walker returned WalkDir's error verbatim, so the first
//	    permission-denied entry killed the command with no partial results
//	    (reported from a Windows home directory: AppData\Local\Razer\...);
//	(2) the walker had no directory skip-list and no notion of "this JSON
//	    isn't a policy", so a sweep of an ordinary project counted
//	    package.json as a rule and hard-ERRORed on tsconfig.json — a
//	    false-positive break of the CI gate docs/policy-audit.md documents.
// --------------------------------------------------------------------------

// newLintTestCmd builds a cobra command wired to runPolicyLint with the same
// flag set init() registers, writing into buf.
func newLintTestCmd(buf *bytes.Buffer) *cobra.Command {
	cmd := &cobra.Command{Use: "lint", RunE: runPolicyLint}
	cmd.Flags().String("input", "", "")
	cmd.Flags().String("format", "text", "")
	cmd.Flags().String("output", "", "")
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	return cmd
}

const lintTestGoodPolicy = `{"id":"p1","name":"block-eval","mode":"block","status":"enabled",` +
	`"precedence":100,"identifier":{"targetPackageName":"evil-pkg"},"conditions":{"usesEval":true}}`

func lintWriteFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestPolicyLint_UnreadableDirectoryIsSkippedNotFatal is the reported crash.
// A chmod-000 directory in the tree must NOT abort the walk: the readable
// policy still gets linted, the unreadable path is named in the report, and
// the exit code says INCOMPLETE rather than pretending the tree was clean.
func TestPolicyLint_UnreadableDirectoryIsSkippedNotFatal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-000 does not model Windows ACL denial")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not deny access")
	}
	dir := t.TempDir()
	lintWriteFile(t, filepath.Join(dir, "good.json"), lintTestGoodPolicy)
	locked := filepath.Join(dir, "locked")
	lintWriteFile(t, filepath.Join(locked, "hidden.json"), lintTestGoodPolicy)
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	// Collector level: partial results, and the loss is recorded.
	set, err := collectPolicyFiles(dir)
	if err != nil {
		t.Fatalf("an unreadable directory must not fail the walk: %v", err)
	}
	if len(set.Files) != 1 {
		t.Fatalf("expected the readable policy to survive the walk, got %v", set.Files)
	}
	lost := unreadablePolicySkips(set.Skipped)
	if len(lost) != 1 {
		t.Fatalf("expected 1 unreadable path recorded, got %+v", set.Skipped)
	}
	if !strings.Contains(lost[0].Path, "locked") {
		t.Errorf("skip must name the path, got %+v", lost[0])
	}
	if lost[0].Reason != "permission denied" {
		t.Errorf("reason: got %q, want %q", lost[0].Reason, "permission denied")
	}

	// Command level: exit 12, not a fatal error and not clean.
	var buf bytes.Buffer
	cmd := newLintTestCmd(&buf)
	_ = cmd.Flags().Set("input", dir)
	runErr := runPolicyLint(cmd, nil)

	var coded *ExitCodeError
	if !errors.As(runErr, &coded) {
		t.Fatalf("expected an ExitCodeError, got %v\n%s", runErr, buf.String())
	}
	if coded.Code != policyScanIncompleteExitCode {
		t.Fatalf("exit code: got %d, want %d (INCOMPLETE, distinct from %d = policies have errors)\n%s",
			coded.Code, policyScanIncompleteExitCode, lintExitError, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "INCOMPLETE") || !strings.Contains(out, "locked") {
		t.Errorf("report must say the scan was incomplete and name the path, got:\n%s", out)
	}
	if strings.Contains(out, "policies are clean") {
		t.Errorf("a half-read tree must never be reported as clean, got:\n%s", out)
	}
}

// TestPolicyLint_UnreadableCandidateFileEscalates: an unreadable FILE that
// matched the policy extension filter is a rule we could not evaluate.
// Mirrors scan_repo.go's report.Unreadable escalation — a candidate we cannot
// read must not read as clean.
func TestPolicyLint_UnreadableCandidateFileEscalates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-000 does not model Windows ACL denial")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not deny access")
	}
	dir := t.TempDir()
	lintWriteFile(t, filepath.Join(dir, "good.json"), lintTestGoodPolicy)
	bad := filepath.Join(dir, "secret.json")
	lintWriteFile(t, bad, lintTestGoodPolicy)
	if err := os.Chmod(bad, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0o644) })

	var buf bytes.Buffer
	cmd := newLintTestCmd(&buf)
	_ = cmd.Flags().Set("input", dir)
	var coded *ExitCodeError
	if err := runPolicyLint(cmd, nil); !errors.As(err, &coded) || coded.Code != policyScanIncompleteExitCode {
		t.Fatalf("expected exit %d for an unreadable candidate, got %v\n%s",
			policyScanIncompleteExitCode, err, buf.String())
	}
}

// TestPolicyLint_RealisticProjectTree is the bigger defect, and it needs no
// permission errors at all. Sweeping an ordinary project directory used to
// report "Scanned 5 file(s), 4 rule(s)" and a hard ERROR (exit 2) on
// tsconfig.json. Every one of those numbers was fiction and the exit code
// broke the gate.
func TestPolicyLint_RealisticProjectTree(t *testing.T) {
	dir := t.TempDir()
	lintWriteFile(t, filepath.Join(dir, "package.json"),
		`{"name":"my-app","version":"1.0.0","scripts":{"build":"tsc"},"dependencies":{"react":"^18.0.0"}}`)
	// JSONC — comments are legal in tsconfig.json and fatal to a YAML parser.
	lintWriteFile(t, filepath.Join(dir, "tsconfig.json"), `{
  // the compiler options, with a comment because tsconfig allows them
  "compilerOptions": {"target": "es2020", "strict": true}
}`)
	lintWriteFile(t, filepath.Join(dir, "node_modules", "left-pad", "package.json"),
		`{"name":"left-pad","version":"1.3.0"}`)
	lintWriteFile(t, filepath.Join(dir, ".github", "workflows", "ci.yml"),
		"name: ci\non:\n  push:\n    branches: [main]\njobs:\n  test:\n    runs-on: ubuntu-latest\n")
	lintWriteFile(t, filepath.Join(dir, ".git", "config.json"), `{"core":{"bare":false}}`)
	// ...and one actual policy, which must still be found and linted.
	lintWriteFile(t, filepath.Join(dir, "policies", "block-eval.json"), lintTestGoodPolicy)

	var buf bytes.Buffer
	cmd := newLintTestCmd(&buf)
	_ = cmd.Flags().Set("input", dir)
	_ = cmd.Flags().Set("format", "json")
	if err := runPolicyLint(cmd, nil); err != nil {
		t.Fatalf("a sweep of an ordinary project must exit 0, got %v\n%s", err, buf.String())
	}

	var report lintReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, buf.String())
	}
	if report.Errors != 0 || report.Warnings != 0 {
		t.Errorf("zero false findings expected, got %d error(s) %d warning(s): %+v",
			report.Errors, report.Warnings, report.Findings)
	}
	// One real policy file, one real rule. Not "5 file(s), 4 rule(s)".
	if report.Files != 1 {
		t.Errorf("files: got %d, want 1 (only policies/block-eval.json is a policy)", report.Files)
	}
	if report.Rules != 1 {
		t.Errorf("rules: got %d, want 1 — package.json must not inflate the rule count", report.Rules)
	}
	// .git and node_modules are pruned, so their JSON never reaches the parser.
	for _, s := range report.Skipped {
		if strings.Contains(s.Path, "node_modules") || strings.Contains(s.Path, ".git"+string(filepath.Separator)) {
			t.Errorf("%s should have been pruned by the directory skip-list, not parsed: %+v", s.Path, s)
		}
		if s.Unreadable {
			t.Errorf("nothing in this tree is unreadable, got %+v", s)
		}
	}
	// package.json / tsconfig.json / ci.yml are reported as skipped, not as
	// policy errors — the operator can still see what the sweep passed over.
	skipped := map[string]bool{}
	for _, s := range report.Skipped {
		skipped[filepath.Base(s.Path)] = true
	}
	for _, want := range []string{"package.json", "tsconfig.json", "ci.yml"} {
		if !skipped[want] {
			t.Errorf("%s should appear in the skip list, got %+v", want, report.Skipped)
		}
	}
}

// TestPolicyLint_ExplicitBadFileIsStillAnError keeps the distinction that
// makes the sweep fix safe: --input naming a file is a statement that the file
// IS a policy, so an unparseable one is a hard error with exit 2. Only the
// sweep is forgiving.
func TestPolicyLint_ExplicitBadFileIsStillAnError(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "tsconfig.json")
	lintWriteFile(t, fp, "{\n  // comment\n  \"compilerOptions\": {}\n}")

	var buf bytes.Buffer
	cmd := newLintTestCmd(&buf)
	_ = cmd.Flags().Set("input", fp)

	err := runPolicyLint(cmd, nil)
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != lintExitError {
		t.Fatalf("an explicitly named unparseable file must exit %d, got %v\n%s",
			lintExitError, err, buf.String())
	}
	if !strings.Contains(buf.String(), "parse") {
		t.Errorf("expected a parse error finding, got:\n%s", buf.String())
	}
}

// TestPolicyLint_ExplicitNonPolicyJSONIsNotSilentlySkipped: a file that PARSES
// but is not a policy is still accepted when named explicitly (the shape
// filter is a sweep-only heuristic and must never make `--input my-policy.json`
// silently do nothing).
func TestPolicyLint_ExplicitNonPolicyJSONIsNotSilentlySkipped(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "package.json")
	lintWriteFile(t, fp, `{"name":"my-app","version":"1.0.0"}`)

	_, rules, err := lintPolicyFile(fp)
	if err != nil {
		t.Fatalf("lintPolicyFile: %v", err)
	}
	if rules != 1 {
		t.Errorf("an explicitly named file is taken at its word: rules=%d, want 1", rules)
	}
}

// TestLooksLikePolicyEntry pins the sweep-only shape heuristic.
func TestLooksLikePolicyEntry(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"policy with conditions", `{"id":"p","conditions":{"usesEval":true}}`, true},
		{"policy with mode only", `{"id":"p","mode":"block"}`, true},
		{"routing rule", `{"id":"r","kind":"routing","routing":{}}`, true},
		{"package.json", `{"dependencies":{"react":"^18"},"name":"my-app","version":"1.0.0"}`, false},
		{"tsconfig", `{"compilerOptions":{"strict":true}}`, false},
		{"empty", `{}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikePolicyEntry([]byte(tc.raw)); got != tc.want {
				t.Errorf("looksLikePolicyEntry(%s) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestPolicyLint_ZeroThresholdMatchesEverything (A1): cvssMin: 0 and
// epssMin: 0 read like "only vulnerable packages" but the evaluator's
// raw `ctx.CVSSScore < *cond.CVSSMin` compare is never true at 0, so
// the rule fires on every package — including ones with no CVE at all.
func TestPolicyLint_ZeroThresholdMatchesEverything(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantWarns int
	}{
		{
			name: "cvssMin-zero-warns",
			body: `{
				"id": "z1", "name": "cvss-zero", "mode": "block", "status": "enabled", "precedence": 100,
				"conditions": {"cvssMin": 0}
			}`,
			wantWarns: 1,
		},
		{
			name: "epssMin-zero-warns",
			body: `{
				"id": "z2", "name": "epss-zero", "mode": "block", "status": "enabled", "precedence": 100,
				"conditions": {"epssMin": 0}
			}`,
			wantWarns: 1,
		},
		{
			name: "both-zero-two-warnings",
			body: `{
				"id": "z3", "name": "both-zero", "mode": "block", "status": "enabled", "precedence": 100,
				"conditions": {"cvssMin": 0, "epssMin": 0}
			}`,
			wantWarns: 2,
		},
		{
			name: "positive-threshold-is-clean",
			body: `{
				"id": "z4", "name": "cvss-seven", "mode": "block", "status": "enabled", "precedence": 100,
				"conditions": {"cvssMin": 7, "epssMin": 0.1}
			}`,
		},
		{
			name: "omitted-threshold-is-clean",
			body: `{
				"id": "z5", "name": "no-threshold", "mode": "block", "status": "enabled", "precedence": 100,
				"conditions": {"isVulnerable": true}
			}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fp := filepath.Join(dir, "policy.json")
			if err := os.WriteFile(fp, []byte(tc.body), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
			findings, _, err := lintPolicyFile(fp)
			if err != nil {
				t.Fatalf("lintPolicyFile: %v", err)
			}
			var warns int
			for _, f := range findings {
				if f.Type == "match-all-threshold" {
					if f.Severity != lintFindingWarning {
						t.Errorf("severity: got %q, want warning", f.Severity)
					}
					// The message must still say WHY. Its wording now comes
					// from policy.AuditPolicyRanges rather than lint's own
					// template, which is the point of routing lint through
					// the classifier — and it is more precise than the
					// sentence it replaced, which said "including ones with
					// no CVE" even for epssMin and would have said it for
					// trustScoreMin too. What is asserted is the claim and
					// the derivation, not the old phrasing.
					if !strings.Contains(f.Message, "matches every package") ||
						!strings.Contains(f.Message, "is at or above 0") {
						t.Errorf("message must say why: %q", f.Message)
					}
					warns++
				}
			}
			if warns != tc.wantWarns {
				t.Errorf("match-all-threshold warnings: got %d, want %d (findings=%+v)", warns, tc.wantWarns, findings)
			}
		})
	}
}

// --------------------------------------------------------------------------
// Range-classifier parity (§5 follow-up of docs/plan_qa_phase9_fresh_remediation.md).
//
// `policy lint` used to hand-roll a two-field check (cvssMin: 0, epssMin: 0)
// while `policy audit` classified NINE bounded fields through
// policy.AuditPolicyRanges. So the same thresholds read one way in a FILE and
// another way once the row was stored. These tests pin that lint now asks the
// classifier, so the two surfaces cannot disagree.
// --------------------------------------------------------------------------

// lintRangeFindings returns the findings lint attributes to the range
// classifier, by type.
func lintRangeFindings(t *testing.T, body string) []lintFinding {
	t.Helper()
	fp := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(fp, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, _, err := lintPolicyFile(fp)
	if err != nil {
		t.Fatalf("lintPolicyFile: %v", err)
	}
	var out []lintFinding
	for _, f := range findings {
		if f.Type == lintTypeMatchAllThreshold || f.Type == lintTypeNeverFiresThreshold {
			out = append(out, f)
		}
	}
	return out
}

func TestPolicyLint_RangeAuditParity(t *testing.T) {
	cases := []struct {
		name string
		// conds is the "conditions" object body.
		conds string
		// wantType/wantSeverity describe the single expected range finding.
		wantType     string
		wantSeverity string
		wantField    string
		// wantMsgSub are substrings the message must carry.
		wantMsgSub []string
		// wantNone: the classifier must report nothing for this policy.
		wantNone bool
	}{
		{
			// The whole gap in one row: an out-of-range floor the store's
			// Create would refuse today, sitting in a file, reported by
			// `policy audit` and by nothing on the file path.
			name:         "cvssMin-999-never-fires",
			conds:        `{"cvssMin": 999}`,
			wantType:     lintTypeNeverFiresThreshold,
			wantSeverity: lintFindingError,
			wantField:    "conditions.cvssMin",
			wantMsgSub:   []string{"never fires", "the highest possible is 10", "blocks nothing"},
		},
		{
			name:         "cvssMin-zero-matches-everything",
			conds:        `{"cvssMin": 0}`,
			wantType:     lintTypeMatchAllThreshold,
			wantSeverity: lintFindingWarning,
			wantField:    "conditions.cvssMin",
			wantMsgSub:   []string{"matches every package", "nothing else on this policy narrows it"},
		},
		{
			// AND-ed conditions: a match-all floor beside a real narrowing
			// condition decides nothing, and the report must say that
			// rather than claiming the policy blocks everything.
			name:         "cvssMin-zero-beside-a-narrowing-condition-is-inert",
			conds:        `{"cvssMin": 0, "hasInstallScript": true}`,
			wantType:     lintTypeMatchAllThreshold,
			wantSeverity: lintFindingWarning,
			wantField:    "conditions.cvssMin",
			wantMsgSub:   []string{"narrows nothing"},
		},
		{
			name:         "trustScoreMin-zero-is-now-reported",
			conds:        `{"trustScoreMin": 0}`,
			wantType:     lintTypeMatchAllThreshold,
			wantSeverity: lintFindingWarning,
			wantField:    "conditions.trustScoreMin",
			wantMsgSub:   []string{"trust score"},
		},
		{
			// requireSlsaLevel is bounded [1,4] but SLSALevel is 0 for an
			// unattested package: outside the bound (error) AND match-all.
			name:         "requireSlsaLevel-zero-is-now-reported",
			conds:        `{"requireSlsaLevel": 0}`,
			wantType:     lintTypeMatchAllThreshold,
			wantSeverity: lintFindingError,
			wantField:    "conditions.requireSlsaLevel",
			wantMsgSub:   []string{"SLSA build level"},
		},
		{
			name:         "min-above-max-is-now-reported",
			conds:        `{"cvssMin": 9, "cvssMax": 5}`,
			wantType:     lintTypeNeverFiresThreshold,
			wantSeverity: lintFindingError,
			wantField:    "conditions.cvssMin",
			wantMsgSub:   []string{"never fires"},
		},
		{
			name:         "cooldownDays-negative-is-now-reported",
			conds:        `{"cooldownDays": -3}`,
			wantType:     lintTypeNeverFiresThreshold,
			wantSeverity: lintFindingError,
			wantField:    "conditions.cooldownDays",
			wantMsgSub:   []string{"never fires"},
		},
		{
			name:     "healthy-thresholds-report-nothing",
			conds:    `{"cvssMin": 7, "epssMin": 0.1, "trustScoreMin": 40, "requireSlsaLevel": 2, "cooldownDays": 7}`,
			wantNone: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"id":"r","name":"range","mode":"block","status":"enabled","precedence":100,` +
				`"conditions":` + tc.conds + `}`
			got := lintRangeFindings(t, body)
			if tc.wantNone {
				if len(got) != 0 {
					t.Fatalf("expected no range findings, got %+v", got)
				}
				return
			}
			// One value, one finding: the classifier and lint must not each
			// report the same threshold.
			if len(got) != 1 {
				t.Fatalf("expected exactly 1 range finding (no double-report), got %d: %+v", len(got), got)
			}
			f := got[0]
			if f.Type != tc.wantType {
				t.Errorf("type: got %q, want %q", f.Type, tc.wantType)
			}
			if f.Severity != tc.wantSeverity {
				t.Errorf("severity: got %q, want %q (finding=%+v)", f.Severity, tc.wantSeverity, f)
			}
			if !strings.Contains(f.Message, tc.wantField) {
				t.Errorf("message must name the field %q, got %q", tc.wantField, f.Message)
			}
			for _, sub := range tc.wantMsgSub {
				if !strings.Contains(f.Message, sub) {
					t.Errorf("message must contain %q, got %q", sub, f.Message)
				}
			}
			if f.Suggestion == "" {
				t.Errorf("a range finding must carry the classifier's suggestion, got %+v", f)
			}
		})
	}
}

// TestPolicyLint_RangeAuditAgreesWithClassifier is the parity assertion
// itself: for a policy carrying every bounded field at a degenerate value,
// lint reports exactly the set policy.AuditPolicyRanges reports — same
// fields, same severities, same count. A field added to the classifier
// shows up here without touching lint.
func TestPolicyLint_RangeAuditAgreesWithClassifier(t *testing.T) {
	body := `{"id":"r","name":"range","mode":"block","status":"enabled","precedence":100,
		"conditions":{"cvssMin":0,"cvssMax":10,"epssMin":0,"epssMax":1,
		"trustScoreMin":0,"trustScoreMax":100,"requireSlsaLevel":0,
		"packageAge":-1,"cooldownDays":-2}}`
	fp := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(fp, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, _, err := lintPolicyFile(fp)
	if err != nil {
		t.Fatalf("lintPolicyFile: %v", err)
	}
	got := map[string]string{}
	for _, f := range findings {
		if f.Type != lintTypeMatchAllThreshold && f.Type != lintTypeNeverFiresThreshold {
			continue
		}
		field := rangeFieldOfLintMessage(f.Message)
		if field == "" {
			t.Fatalf("range finding must name its field: %q", f.Message)
		}
		if prev, dup := got[field]; dup {
			t.Errorf("double-report on %s: %q and %q", field, prev, f.Message)
		}
		got[field] = f.Severity
	}

	var doc struct {
		Conditions policy.Conditions `json:"conditions"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for _, a := range policy.AuditPolicyRanges("", []policy.Policy{{
		ID: "r", Name: "range", Mode: policy.ModeBlock, Status: policy.StatusEnabled,
		Conditions: doc.Conditions,
	}}) {
		want[a.Field] = a.Severity
	}
	if len(want) == 0 {
		t.Fatal("fixture must be degenerate on several fields")
	}
	if len(got) != len(want) {
		t.Errorf("lint reported %d field(s), the classifier reports %d\nlint=%v\nclassifier=%v", len(got), len(want), got, want)
	}
	for field, sev := range want {
		if got[field] != sev {
			t.Errorf("field %s: lint severity %q, classifier severity %q", field, got[field], sev)
		}
	}
}

// rangeFieldOfLintMessage pulls the dotted field name out of a range
// finding's message ("rule sets conditions.cvssMin: 0 — ...").
func rangeFieldOfLintMessage(msg string) string {
	const prefix = "rule sets "
	i := strings.Index(msg, prefix)
	if i < 0 {
		return ""
	}
	rest := msg[i+len(prefix):]
	j := strings.Index(rest, ":")
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// TestPolicyLint_RangeAuditExitLadder pins that routing lint through the
// classifier did not move the exit ladder: a match-all warning is still 1,
// an out-of-range error is 2, and a healthy file is still 0.
func TestPolicyLint_RangeAuditExitLadder(t *testing.T) {
	cases := []struct {
		name  string
		conds string
		want  int // 0 means "no error returned"
	}{
		{"clean", `{"cvssMin": 7}`, 0},
		{"match-all is a warning", `{"cvssMin": 0}`, lintExitWarning},
		{"out of range is an error", `{"cvssMin": 999}`, lintExitError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fp := filepath.Join(dir, "policy.json")
			lintWriteFile(t, fp, `{"id":"r","name":"range","mode":"block","status":"enabled","precedence":100,`+
				`"conditions":`+tc.conds+`}`)
			var buf bytes.Buffer
			cmd := newLintTestCmd(&buf)
			_ = cmd.Flags().Set("input", fp)
			err := runPolicyLint(cmd, nil)
			if tc.want == 0 {
				if err != nil {
					t.Fatalf("expected exit 0, got %v\n%s", err, buf.String())
				}
				return
			}
			var coded *ExitCodeError
			if !errors.As(err, &coded) || coded.Code != tc.want {
				t.Fatalf("exit code: got %v, want %d\n%s", err, tc.want, buf.String())
			}
		})
	}
}
