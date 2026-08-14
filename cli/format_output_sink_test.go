package cli

// S9b — the --output SINK contract for every command that shadows --format.
//
// root.go's formatIsMachineReadable exempts a --format-shadowing command from
// the --output refusal wholesale, on this stated ground:
//
//	"every one of those commands writes its result through a sink that
//	 honours --output (outWriter / outWriterOr), so the refusal is skipped
//	 for them wholesale — including their human-ish `text` format"
//
// That was an assumption, not a fact. Four of the eleven did not, and removing
// the refusal turned a loud (if wrong) rc=4 into a silent no-op: rc=0, no file,
// the result on stdout. Measured against a live server before this change:
//
//	audit export --format csv|json|ndjson --output A   rc=0  NO FILE (55 KB on stdout)
//	policy lint  --format text|json       --output R   rc=2  NO FILE
//	report {multiversion,provenance,exposure,sla} --format text --output R
//	                                                  rc=0  NO FILE (8.4 KB on stdout)
//	scan-actions --format text            --output Y   rc=0  NO FILE
//
// TestOutputSink_EveryShadowingFormatWritesAFile closes that hole as a SET
// property, not a list of four fixes: the command set is derived from the live
// cobra tree, and a command that shadows --format without registering a recipe
// here FAILS. A future `chainsaw thing --format toml` cannot ship exempt from
// the validator and unwired to the sink at the same time.
//
// Complement to TestFormatValidation_ExemptSetIsExactlyTheShadowingCommands
// (output_flags_contract_test.go), which pins WHICH commands are exempt. This
// one pins that being exempt is EARNED.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// outputSinkRecipe is everything needed to drive one command to the point
// where it writes its result.
type outputSinkRecipe struct {
	// formats is the command's ENTIRE --format vocabulary. Every value must
	// produce a non-empty file under --output.
	formats []string
	// args are the positional arguments, resolved per-run against a temp dir.
	args func(t *testing.T, dir string) []string
	// flags are local flags to set before the run.
	flags func(t *testing.T, dir string) map[string]string
	// unwiredElsewhere lists formats that are STILL broken and live in a file
	// this change does not own. Each entry asserts the gap is still present,
	// so it cannot rot into a permanent exemption: the day the owner wires the
	// sink, this test fails and the entry must be deleted.
	unwiredElsewhere map[string]string
}

// outputSinkRecipes is keyed by cobra CommandPath(). Every command the tree
// walk finds must appear here.
var outputSinkRecipes = map[string]outputSinkRecipe{
	"chainsaw audit export": {formats: []string{"csv", "json", "ndjson"}},
	"chainsaw policy export": {
		// Declares its OWN --output (no -o shorthand), so it never reached the
		// global flag; the sink is its own os.WriteFile. Covered here anyway —
		// the property is "--output produces a file", not "via outWriterOr".
		formats: []string{"yaml", "json"},
	},
	"chainsaw policy lint": {
		formats: []string{"text", "json"},
		flags: func(t *testing.T, dir string) map[string]string {
			return map[string]string{"input": writeSinkPolicyFile(t, dir)}
		},
	},
	"chainsaw report multiversion": {formats: []string{"text", "json"}},
	"chainsaw report provenance":   {formats: []string{"text", "json"}},
	"chainsaw report sla":          {formats: []string{"text", "json"}},
	"chainsaw report exposure": {
		formats: []string{"text", "json"},
		flags: func(t *testing.T, dir string) map[string]string {
			return map[string]string{
				"start": "2020-01-01T00:00:00Z",
				"end":   "2030-01-01T00:00:00Z",
			}
		},
	},
	"chainsaw sbom export": {formats: []string{"cyclonedx", "spdx"}},
	"chainsaw sbom diff": {
		formats: []string{"text", "json"},
		args: func(t *testing.T, dir string) []string {
			return []string{writeSinkBOM(t, dir, "a.json", "4.17.20"), writeSinkBOM(t, dir, "b.json", "4.17.21")}
		},
		// The `text` gap recorded here is CLOSED: runSBOMDiff's text branch now
		// routes through outWriterOr like its json branch, so both formats are
		// asserted normally.
	},
	"chainsaw scan-actions": {
		formats: []string{"text", "json", "sarif"},
		args: func(t *testing.T, dir string) []string {
			return []string{writeSinkWorkflow(t, dir)}
		},
	},
}

func TestOutputSink_EveryShadowingFormatWritesAFile(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)

	srv := httptest.NewServer(http.HandlerFunc(outputSinkStubServer))
	t.Cleanup(srv.Close)
	prevURL, prevTok := viper.GetString("server_url"), viper.GetString("token")
	t.Cleanup(func() { viper.Set("server_url", prevURL); viper.Set("token", prevTok) })
	viper.Set("server_url", srv.URL)
	viper.Set("token", "test-token")

	for _, cmd := range outputSinkShadowingCommands(t) {
		path := cmd.CommandPath()
		recipe, ok := outputSinkRecipes[path]
		if !ok {
			t.Errorf("%s shadows --format but has no outputSinkRecipe.\n"+
				"Shadowing --format exempts a command from root.go's --output refusal on the "+
				"grounds that it routes its result through a sink honouring --output. Add a "+
				"recipe proving it does — for EVERY format in its vocabulary — or the command "+
				"ships accepting --output and silently writing nothing.", path)
			continue
		}
		for _, format := range recipe.formats {
			t.Run(strings.ReplaceAll(path, " ", "_")+"_"+format, func(t *testing.T) {
				dir := t.TempDir()
				out := filepath.Join(dir, "result.out")
				runOutputSinkCase(t, cmd, recipe, format, dir, out)

				info, err := os.Stat(out)
				if reason, known := recipe.unwiredElsewhere[format]; known {
					// Asserted as STILL BROKEN on purpose — see
					// outputSinkRecipe.unwiredElsewhere.
					if err == nil {
						t.Fatalf("%s --format %s now honors --output; delete its unwiredElsewhere "+
							"entry (recorded gap: %s)", path, format, reason)
					}
					t.Skipf("known gap owned elsewhere: %s", reason)
				}
				if err != nil {
					t.Fatalf("%s --format %s --output %s created no file: %v\n"+
						"The command exited without writing the file it was told to write — a "+
						"silent no-op. Route the RESULT through outWriterOr(cmd, cmd.OutOrStdout()).",
						path, format, out, err)
				}
				if info.Size() == 0 {
					t.Fatalf("%s --format %s --output %s created an EMPTY file", path, format, out)
				}
			})
		}
	}
}

// runOutputSinkCase sets the flags for one (command, format) pair, checks the
// global validator accepts the combination, then drives the command's RunE.
func runOutputSinkCase(t *testing.T, cmd *cobra.Command, recipe outputSinkRecipe, format, dir, out string) {
	t.Helper()

	set := map[string]string{"format": format, "output": out, "json": "false"}
	if recipe.flags != nil {
		for k, v := range recipe.flags(t, dir) {
			set[k] = v
		}
	}
	for name, value := range set {
		f := cmd.Flags().Lookup(name)
		if f == nil {
			t.Fatalf("%s has no --%s flag", cmd.CommandPath(), name)
		}
		prev, prevChanged := f.Value.String(), f.Changed
		t.Cleanup(func() { _ = f.Value.Set(prev); f.Changed = prevChanged })
		if err := cmd.Flags().Set(name, value); err != nil {
			t.Fatalf("set --%s=%s on %s: %v", name, value, cmd.CommandPath(), err)
		}
	}

	// The sink is only reachable if the validator lets the invocation through
	// in the first place; assert both halves of the contract in one place.
	if err := validateOutputFlags(cmd); err != nil {
		t.Fatalf("%s --format %s --output %s rejected by validateOutputFlags: %v",
			cmd.CommandPath(), format, out, err)
	}

	var args []string
	if recipe.args != nil {
		args = recipe.args(t, dir)
	}
	// A non-zero ExitCodeError is a legitimate verdict (policy lint returns 2
	// on findings, scan-actions 1 on a high-severity finding) and must not
	// stop the file from being written — that is half the point.
	if err := cmd.RunE(cmd, args); err != nil {
		var coded *ExitCodeError
		if !errors.As(err, &coded) {
			t.Fatalf("%s --format %s: %v", cmd.CommandPath(), format, err)
		}
	}
}

// outputSinkShadowingCommands walks the live cobra tree for every runnable
// command that declares its OWN --format flag. Deriving the set here (rather
// than hand-listing it) is what makes this a completeness check: a new
// shadowing command joins the table automatically and fails for want of a
// recipe.
func outputSinkShadowingCommands(t *testing.T) []*cobra.Command {
	t.Helper()
	var found []*cobra.Command
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		if c.Parent() == nil {
			return // the root OWNS --format; it is not a shadow
		}
		if c.RunE == nil {
			return // a group parent renders no result
		}
		if c.DisableFlagParsing {
			return // guard wrappers forward argv untouched; --format is npm's
		}
		// Force cobra's persistent-flag merge so the inherited --output is
		// visible and ownsGlobalFlag's pointer identity test is meaningful.
		_ = c.InheritedFlags()
		f := c.Flags().Lookup("format")
		if f == nil || ownsGlobalFlag(c, "format") {
			return
		}
		if f.Deprecated != "" {
			// `repo create --format` is a deprecated alias for --ecosystem, not
			// an output format — it selects npm/pypi/maven. It has no result
			// vocabulary to redirect. (Kept deliberately: un-deprecating it
			// would pull it back into this sweep.)
			return
		}
		found = append(found, c)
	}
	walk(rootCmd)
	sort.Slice(found, func(i, j int) bool { return found[i].CommandPath() < found[j].CommandPath() })
	if len(found) == 0 {
		t.Fatal("tree walk found no --format-shadowing commands; the walk is broken, not the tree")
	}
	return found
}

// outputSinkStubServer answers the handful of read endpoints these commands
// hit, with the smallest non-empty payload each decoder accepts.
func outputSinkStubServer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	truncated := false
	count := 1
	switch {
	case strings.HasPrefix(r.URL.Path, "/api/audit/logs"):
		_ = json.NewEncoder(w).Encode(auditLogResponse{
			Events:    sampleEvents(),
			Count:     &count,
			Total:     &count,
			Truncated: &truncated,
		})
	case strings.HasPrefix(r.URL.Path, "/api/policies"):
		_, _ = w.Write([]byte(`{"policies":[{"id":"p-1","name":"block-criticals","action":"block"}]}`))
	case strings.HasPrefix(r.URL.Path, "/api/sbom"):
		_, _ = w.Write([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,` +
			`"components":[{"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"}]}`))
	case strings.HasPrefix(r.URL.Path, "/api/v1/reports/multiversion"):
		_, _ = w.Write([]byte(`{"data":[{"ecosystem":"npm","package":"lodash","versions":` +
			`[{"version":"4.17.20","repos":["app"],"count":1}]}]}`))
	case strings.HasPrefix(r.URL.Path, "/api/v1/reports/provenance"):
		_, _ = w.Write([]byte(`{"data":[{"ecosystem":"npm","totalInstalls":10,"withProvenance":4,"coverage":0.4}]}`))
	case strings.HasPrefix(r.URL.Path, "/api/v1/reports/exposure"):
		_, _ = w.Write([]byte(`{"data":[{"ecosystem":"npm","package":"lodash","version":"4.17.20",` +
			`"repository":"app","at":"2026-01-02T03:04:05Z"}]}`))
	case strings.HasPrefix(r.URL.Path, "/api/v1/reports/sla"):
		_, _ = w.Write([]byte(`{"data":[{"owners":["platform"],"resolved":3,"meanSeconds":7200,"medianSeconds":3600}]}`))
	default:
		http.NotFound(w, r)
	}
}

func writeSinkPolicyFile(t *testing.T, dir string) string {
	t.Helper()
	// A standalone-codesmell rule: lint reports an ERROR finding, which also
	// exercises the exit-code path (lintExitError) alongside the sink.
	p := filepath.Join(dir, "policy.yaml")
	body := "- name: smell-only\n  action: block\n  conditions:\n    usesEval: true\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy fixture: %v", err)
	}
	return p
}

func writeSinkBOM(t *testing.T, dir, name, version string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	body := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[` +
		`{"type":"library","name":"lodash","version":"` + version + `","purl":"pkg:npm/lodash@` + version + `"}]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write bom fixture: %v", err)
	}
	return p
}

func writeSinkWorkflow(t *testing.T, dir string) string {
	t.Helper()
	root := filepath.Join(dir, "repo")
	wf := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o750); err != nil {
		t.Fatalf("mkdir workflows: %v", err)
	}
	// An unpinned `@main` ref guarantees at least one finding, so the text and
	// sarif renderers have rows to emit rather than only a summary line.
	body := "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n" +
		"      - uses: actions/checkout@v4\n      - uses: actions/setup-node@main\n"
	if err := os.WriteFile(filepath.Join(wf, "ci.yml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write workflow fixture: %v", err)
	}
	return root
}
