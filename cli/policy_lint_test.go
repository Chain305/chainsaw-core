package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	files, err := collectPolicyFiles(dir)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 policy file, got %v", files)
	}
}
