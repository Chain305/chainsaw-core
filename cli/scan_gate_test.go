package cli

// P8-27 — the CI contract for the scan-shaped commands.
//
// Two defects are pinned here.
//
// (a) `scan-repo` — the command the CI persona and the bundled GitHub Action
// are built on — produced its verdict from three bare `return`s sitting after
// an `if useJSON(cmd) { … } else { … }`. Correct by inspection, structural by
// nothing: it is the exact shape scan-remote had when a repo-wide
// `--format json` disarmed its gate on every invocation (S1). It also had no
// control over the gate at all: no monitor mode, and no way to opt out of the
// fail-closed coverage exit that X2 added unconditionally.
//
// (b) Four scan-shaped commands declared a LOCAL --json (or --format) that
// shadowed the root persistent one. On scan-remote that shadow is named in the
// S1 comment as the mechanism of a shipped gate-disarm; the fix at the time
// addressed the consequence and left the mechanism in the tree.
//
// The tests below assert the properties, not the fixes: a gate fires, no
// rendering choice weakens it, and the flags come from one place.

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// scanShapedCommands is the set P8-27 names. Keyed by CommandPath so a rename
// fails loudly rather than silently dropping a command from the sweep.
var scanShapedCommands = []string{
	"chainsaw scan",
	"chainsaw scan-repo",
	"chainsaw scan-remote",
	"chainsaw scan-actions",
	"chainsaw pr-scan",
	"chainsaw intel scan",
}

func findScanShaped(t *testing.T, path string) *cobra.Command {
	t.Helper()
	c, rest, err := rootCmd.Find(strings.Fields(strings.TrimPrefix(path, "chainsaw ")))
	if err != nil || c == nil || len(rest) > 0 || c.CommandPath() != path {
		t.Fatalf("%q does not resolve to a command (got %v, rest %v, err %v)", path, c, rest, err)
	}
	// Force cobra's persistent-flag merge so Flags() sees the inherited set and
	// ownsGlobalFlag's pointer-identity test is meaningful.
	_ = c.InheritedFlags()
	return c
}

// ── (b) the shadow itself ──────────────────────────────────────────────────

// TestScanShapedCommands_DoNotShadowTheRootJSONFlag is the structural half of
// (b). --json is a ROOT PERSISTENT flag documented as sugar for --format=json;
// resolveFormat and useJSON read it. A local redeclaration makes the two flags
// two different variables on the one command that declares it, which is what
// scan_remote.go's S1 comment records as the reason a repo-wide --format json
// reached the gate through a different door than --json did.
//
// `policy gate` had the same shadow removed for the same reason
// (qa_w3456_test.go). This generalises it to the scan surface.
func TestScanShapedCommands_DoNotShadowTheRootJSONFlag(t *testing.T) {
	for _, path := range scanShapedCommands {
		c := findScanShaped(t, path)
		if f := c.LocalFlags().Lookup("json"); f != nil {
			t.Errorf("%s declares a LOCAL --json.\n"+
				"useJSON/resolveFormat read the ROOT persistent --json (root.go), so a local "+
				"redeclaration makes --json and --format json two different variables on this "+
				"command. That is the mechanism named in scan_remote.go's S1 comment as the "+
				"reason a repo-wide --format json disarmed the gate. Delete the local flag; "+
				"the persistent one already provides it.", path)
		}
		if !ownsGlobalFlag(c, "json") {
			t.Errorf("%s: --json is not the root's own flag after the persistent merge", path)
		}
	}
}

// TestScanActions_DoesNotShadowTheRootFormatFlag pins the second half of (b).
// scan-actions redeclared --format with default "text" against the root's
// "table" — the only command in the tree where the global flag's documented
// default was not the one in effect. Per root.go's extraCommandFormats
// comment, a local shadow also makes ownsGlobalFlag false and opts the command
// out of ALL --format validation, so `--format bogus` was checked only by the
// command's own ad-hoc switch.
func TestScanActions_DoesNotShadowTheRootFormatFlag(t *testing.T) {
	c := findScanShaped(t, "chainsaw scan-actions")
	if f := c.LocalFlags().Lookup("format"); f != nil {
		t.Fatalf("scan-actions declares a LOCAL --format (default %q); the root's default is %q. "+
			"A local shadow exempts the command from validateOutputFlags entirely — declare the "+
			"extra vocabulary in extraCommandFormats instead.", f.DefValue, "table")
	}
	if !ownsGlobalFlag(c, "format") {
		t.Fatal("scan-actions: --format is not the root's own flag after the persistent merge")
	}
	// The vocabulary must survive the un-shadowing, or `--format sarif` (which
	// the help text promises) starts exiting 4 — the B3 regression, again.
	for _, v := range []string{"text", "sarif"} {
		if !extraCommandFormats["chainsaw scan-actions"][v] {
			t.Errorf("extraCommandFormats is missing %q for scan-actions; the help text promises it", v)
		}
	}
}

// TestScanActions_RootFormatDefaultRendersTheHumanFormat proves the reconciled
// default is a no-op for output: the root's "table" must land on the same
// renderer the local "text" default used to select.
func TestScanActions_RootFormatDefaultRendersTheHumanFormat(t *testing.T) {
	dir := t.TempDir()
	wf := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := "name: ci\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n" +
		"      - uses: actions/setup-node@main\n"
	if err := os.WriteFile(filepath.Join(wf, "ci.yml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	render := func(format string) string {
		var out strings.Builder
		cmd := &cobra.Command{Use: "scan-actions"}
		cmd.Flags().String("format", format, "")
		cmd.Flags().Bool("json", false, "")
		cmd.Flags().String("output", "", "")
		cmd.SetOut(&out)
		cmd.SetErr(io.Discard)
		if _, err := runScanActions(cmd, []string{dir}); err != nil {
			t.Fatalf("runScanActions(--format %q): %v", format, err)
		}
		return out.String()
	}
	if got, want := render("table"), render("text"); got != want {
		t.Errorf("the root default --format=table must render identically to the old local "+
			"default --format=text.\ntable:\n%s\ntext:\n%s", got, want)
	}
}

// ── (a) scan-repo now has a gate, and no format can weaken it ──────────────

// newScanRepoGateCmd mirrors the REAL command's flag set, including the gate
// flags added by addScanGateFlags, so these tests exercise the same resolution
// path a user gets.
func newScanRepoGateCmd(out, errOut *strings.Builder) *cobra.Command {
	cmd := &cobra.Command{Use: "scan-repo", RunE: runScanRepo}
	// Inherited-from-root persistent flags.
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("format", "table", "")
	cmd.Flags().String("output", "", "")
	addScanGateFlags(cmd, scanGateFlags{
		FailOnUnscanned:        true,
		FailOnUnscannedDefault: true,
		ExitZero:               true,
	})
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs(nil)
	return cmd
}

// bypassRepo writes a tree with exactly one bypass finding.
func bypassRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"),
		[]byte("registry=https://registry.npmjs.org/\n"), 0o600); err != nil {
		t.Fatalf("write .npmrc: %v", err)
	}
	return dir
}

// TestScanRepo_GateFiresOnABypassFinding is the baseline: the documented
// exit 10 is produced, and it is a typed, message-less ExitCodeError so
// Execute() still flushes telemetry and renderError prints nothing on top of
// the report.
func TestScanRepo_GateFiresOnABypassFinding(t *testing.T) {
	var out, errOut strings.Builder
	cmd := newScanRepoGateCmd(&out, &errOut)
	err := runScanRepo(cmd, []string{bypassRepo(t)})

	var coded *ExitCodeError
	if !errors.As(err, &coded) {
		t.Fatalf("a bypass file produced %v, not an ExitCodeError; CI would read the tree as clean", err)
	}
	if coded.Code != doctorExitDrift {
		t.Errorf("exit code = %d, want %d (the value documented in the help text)", coded.Code, doctorExitDrift)
	}
	if coded.Err != nil {
		t.Errorf("ExitCodeError carries a message (%v); renderError would print it on top of the report", coded.Err)
	}
}

// TestScanRepo_GateIsNotDisarmedByAnyFormat is the (b)-applied-to-(a) test.
// Every one of these is a RENDERING choice; none of them is a verdict.
//
// The mismatch rows are the ones that matter: they set the persistent --format
// and the --json flag to DISAGREEING values, which is precisely the state a
// local --json shadow used to be able to produce.
func TestScanRepo_GateIsNotDisarmedByAnyFormat(t *testing.T) {
	cases := []struct {
		name string
		set  func(*cobra.Command)
	}{
		{"default", func(*cobra.Command) {}},
		{"--json", func(c *cobra.Command) { _ = c.Flags().Set("json", "true") }},
		{"--format json", func(c *cobra.Command) { _ = c.Flags().Set("format", "json") }},
		{"--format JSON", func(c *cobra.Command) { _ = c.Flags().Set("format", "JSON") }},
		{"--json with --format table", func(c *cobra.Command) {
			_ = c.Flags().Set("json", "true")
			_ = c.Flags().Set("format", "table")
		}},
		{"--json=false with --format json", func(c *cobra.Command) {
			_ = c.Flags().Set("json", "false")
			_ = c.Flags().Set("format", "json")
		}},
	}
	dir := bypassRepo(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut strings.Builder
			cmd := newScanRepoGateCmd(&out, &errOut)
			tc.set(cmd)
			if code := scanRepoExitCode(t, runScanRepo(cmd, []string{dir})); code != doctorExitDrift {
				t.Fatalf("exit code = %d, want %d — %s weakened the verdict", code, doctorExitDrift, tc.name)
			}
			if strings.TrimSpace(out.String()) == "" {
				t.Error("the report was not rendered; the gate must fire IN ADDITION to the output, not instead of it")
			}
		})
	}
}

// TestScanRepo_ExitZeroIsTheOnlyWayToDisarmTheFindingsGate pins that monitor
// mode is EXPLICIT. The escape hatch exists (teams adopting scan-repo need to
// see findings before they break the build) but it has to be typed into the
// workflow file, where it is greppable — unlike --json, which is what
// scan-remote's accidental opt-out looked like.
func TestScanRepo_ExitZeroIsTheOnlyWayToDisarmTheFindingsGate(t *testing.T) {
	dir := bypassRepo(t)
	var out, errOut strings.Builder
	cmd := newScanRepoGateCmd(&out, &errOut)
	_ = cmd.Flags().Set("exit-zero", "true")
	if err := runScanRepo(cmd, []string{dir}); err != nil {
		t.Fatalf("--exit-zero must exit 0, got %v", err)
	}
	if !strings.Contains(out.String(), "findings:") {
		t.Errorf("--exit-zero must still REPORT; got %q", out.String())
	}
}

// TestScanRepo_FailOnUnscannedIsArmedByDefault pins the deviation from
// `chainsaw scan`'s default and the reason for it. scan-repo has exited 2 on an
// uninspectable candidate since X2, unconditionally. Registering the flag
// default-OFF (matching `scan`) would have silently disarmed a shipped
// fail-closed gate — the flag adds an escape hatch, it does not lower the
// posture.
func TestScanRepo_FailOnUnscannedIsArmedByDefault(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 000 is still readable")
	}
	newUnreadable := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		p := filepath.Join(dir, ".npmrc")
		if err := os.WriteFile(p, []byte("registry=https://registry.npmjs.org/\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := os.Chmod(p, 0o000); err != nil {
			t.Skipf("chmod 000 unsupported here: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
		return dir
	}

	t.Run("default is armed", func(t *testing.T) {
		var out, errOut strings.Builder
		cmd := newScanRepoGateCmd(&out, &errOut)
		if code := scanRepoExitCode(t, runScanRepo(cmd, []string{newUnreadable(t)})); code != ExitOpError {
			t.Fatalf("exit code = %d, want %d — the pre-flag behaviour was unconditional", code, ExitOpError)
		}
	})

	t.Run("an explicit false is the escape hatch", func(t *testing.T) {
		var out, errOut strings.Builder
		cmd := newScanRepoGateCmd(&out, &errOut)
		_ = cmd.Flags().Set("fail-on-unscanned", "false")
		if err := runScanRepo(cmd, []string{newUnreadable(t)}); err != nil {
			t.Fatalf("--fail-on-unscanned=false must exit 0 on an uninspectable candidate, got %v", err)
		}
		if !strings.Contains(errOut.String(), "not inspected") {
			t.Errorf("the coverage loss must still be LOUD on stderr when the gate is lowered; got %q", errOut.String())
		}
	})

	t.Run("the env var cannot lower an armed default", func(t *testing.T) {
		t.Setenv("CHAINSAW_SCAN_FAIL_ON_UNSCANNED", "false")
		var out, errOut strings.Builder
		cmd := newScanRepoGateCmd(&out, &errOut)
		if code := scanRepoExitCode(t, runScanRepo(cmd, []string{newUnreadable(t)})); code != ExitOpError {
			t.Fatalf("exit code = %d, want %d — an env var must never disarm a gate that ships armed. "+
				"Note the failing edit is NOT `def || envTruthy(...)` (equivalent); it is any form "+
				"that resolves the unchanged case from the environment ALONE, because envTruthy of "+
				"an UNSET var is false too", code, ExitOpError)
		}
	})

	t.Run("findings still outrank an uninspectable candidate", func(t *testing.T) {
		// 10 is the stronger signal and the one the bundled Action keys on.
		dir := newUnreadable(t)
		if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM ghcr.io/o/r:1\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		var out, errOut strings.Builder
		cmd := newScanRepoGateCmd(&out, &errOut)
		if code := scanRepoExitCode(t, runScanRepo(cmd, []string{dir})); code != doctorExitDrift {
			t.Fatalf("exit code = %d, want %d", code, doctorExitDrift)
		}
	})
}

// TestScanRepo_ExitZeroDoesNotSuppressAFailureToRun. --exit-zero suppresses a
// VERDICT. A mistyped path is not a verdict — it is the tool never having
// looked, which X1 established must not exit 0.
func TestScanRepo_ExitZeroDoesNotSuppressAFailureToRun(t *testing.T) {
	var out, errOut strings.Builder
	cmd := newScanRepoGateCmd(&out, &errOut)
	_ = cmd.Flags().Set("exit-zero", "true")
	err := runScanRepo(cmd, []string{filepath.Join(t.TempDir(), "does-not-exist")})
	if code := scanRepoExitCode(t, err); code != ExitOpError {
		t.Fatalf("exit code = %d, want %d; --exit-zero must not turn a mistyped path into a clean run", code, ExitOpError)
	}
}

// TestScanRepo_HelpDocumentsEveryCodeItCanReturn — the help text is the exit
// contract published to docs.chain305.com/cli-reference/ by cmd/gen-cli-docs.
// Adding a gate knob without saying so there is how the vendor's fabricated
// "Exit 11" went unchallenged.
func TestScanRepo_HelpDocumentsEveryCodeItCanReturn(t *testing.T) {
	c := findScanShaped(t, "chainsaw scan-repo")
	for _, want := range []string{
		"0  the tree is clean",
		"10 at least one bypass file was found",
		"2  the scan could not be completed",
		"--exit-zero",
		"--fail-on-unscanned",
	} {
		if !strings.Contains(c.Long, want) {
			t.Errorf("scan-repo help does not document %q", want)
		}
	}
}

// ── pr-scan: verify, do not assume, that its own scheme is format-blind ────

// TestPRScan_GateIsNotDisarmedByAnyFormat. pr-scan computes its 10/20/30 in
// buildPRScanReport, before any rendering branch, and the escalation and return
// sit after all of them — so it reads as format-independent. This asserts it
// rather than leaving it as a reading, because that is exactly the property
// scan-remote also appeared to have.
func TestPRScan_GateIsNotDisarmedByAnyFormat(t *testing.T) {
	dir := newGitRepoForGate(t)
	writeFileIn(t, dir, "package.json", `{"name":"x","dependencies":{"lodash":"4.17.21"}}`)
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "base")
	base := gitIn(t, dir, "rev-parse", "HEAD")
	writeFileIn(t, dir, "package.json", `{"name":"x","dependencies":{"lodash":"4.17.21","left-pad":"1.3.0"}}`)
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "head")

	newCmd := func() *cobra.Command {
		cmd := &cobra.Command{Use: "pr-scan", RunE: runPRScan}
		cmd.Flags().String("base", "", "")
		cmd.Flags().String("head", "HEAD", "")
		cmd.Flags().String("repo-path", ".", "")
		cmd.Flags().String("output-file", "", "")
		cmd.Flags().Bool("strict", false, "")
		// Inherited-from-root persistent flags. No local --json: the real
		// command no longer declares one either.
		cmd.Flags().Bool("json", false, "")
		cmd.Flags().String("format", "", "")
		cmd.Flags().String("output", "", "")
		_ = cmd.Flags().Set("base", base)
		_ = cmd.Flags().Set("repo-path", dir)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		return cmd
	}

	cases := []struct {
		name string
		set  func(*cobra.Command)
	}{
		{"default", func(*cobra.Command) {}},
		{"--json", func(c *cobra.Command) { _ = c.Flags().Set("json", "true") }},
		{"--format json", func(c *cobra.Command) { _ = c.Flags().Set("format", "json") }},
		{"--json=false with --format json", func(c *cobra.Command) {
			_ = c.Flags().Set("json", "false")
			_ = c.Flags().Set("format", "json")
		}},
		{"--format sarif", func(c *cobra.Command) { _ = c.Flags().Set("format", "sarif") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newCmd()
			tc.set(cmd)
			err := runPRScan(cmd, nil)
			var coded *ExitCodeError
			if !errors.As(err, &coded) {
				t.Fatalf("%s: got %v, want a non-zero ExitCodeError", tc.name, err)
			}
			if coded.Code != prScanExitWarning && coded.Code != prScanExitBlocking {
				t.Errorf("%s: exit code = %d, want %d or %d", tc.name, coded.Code, prScanExitWarning, prScanExitBlocking)
			}
		})
	}
}

// ── the helper is the single registration point ────────────────────────────

// TestScanGateFlags_ComeFromTheSharedHelper pins that every gate flag on the
// scan surface carries the helper's default and usage string. A command that
// re-declares one inline will drift — a different default, a different usage
// string in the published CLI reference, or a resolver that forgets the
// Changed()-gate that lets --fail-on-unscanned=false carve a job out of a
// fleet-wide env default.
func TestScanGateFlags_ComeFromTheSharedHelper(t *testing.T) {
	want := map[string]map[string]struct{ def, usage string }{
		"chainsaw scan": {
			"fail-on-unscanned": {"false", scanGateFlagUsageFailOnUnscanned},
		},
		"chainsaw scan-remote": {
			"exit-zero": {"false", scanGateFlagUsageReportOnly},
		},
		"chainsaw scan-repo": {
			// scan-repo's two overrides are DELIBERATE and documented at the
			// registration site: its "unscanned" is an uninspectable file, not
			// an unevaluated package, and its default is ON because the
			// behaviour predates the flag.
			"fail-on-unscanned": {"true", "Exit 2 when a candidate file could not be inspected (default: on; pass =false to warn only)"},
			"exit-zero":         {"false", "Always exit 0, even when bypass files are found (report-only mode)"},
		},
	}
	for path, flags := range want {
		c := findScanShaped(t, path)
		for name, spec := range flags {
			f := c.LocalFlags().Lookup(name)
			if f == nil {
				t.Errorf("%s: --%s is not registered", path, name)
				continue
			}
			if f.DefValue != spec.def {
				t.Errorf("%s --%s default = %q, want %q", path, name, f.DefValue, spec.def)
			}
			if f.Usage != spec.usage {
				t.Errorf("%s --%s usage drifted.\n got: %q\nwant: %q\n"+
					"Usage strings are published verbatim on docs.chain305.com/cli-reference/ "+
					"by cmd/gen-cli-docs — run `make gen-cli-docs` if the change is intended.",
					path, name, f.Usage, spec.usage)
			}
		}
	}
}

// TestResolveFailOnUnscanned_Precedence pins the resolver in isolation,
// including the two asymmetries that are easy to "simplify" into a bug:
// an explicit flag wins in BOTH directions, and the env var can only RAISE.
func TestResolveFailOnUnscanned_Precedence(t *testing.T) {
	newCmd := func(def bool, set string) *cobra.Command {
		c := &cobra.Command{Use: "x"}
		addScanGateFlags(c, scanGateFlags{FailOnUnscanned: true, FailOnUnscannedDefault: def})
		if set != "" {
			if err := c.Flags().Set("fail-on-unscanned", set); err != nil {
				t.Fatalf("set: %v", err)
			}
		}
		return c
	}
	cases := []struct {
		name string
		def  bool
		set  string
		env  string
		want bool
	}{
		{"default off, nothing set", false, "", "", false},
		{"default off, env on", false, "", "1", true},
		{"default off, env off", false, "", "false", false},
		{"default off, explicit true beats env off", false, "true", "false", true},
		{"default on, nothing set", true, "", "", true},
		{"default on, env off cannot lower it", true, "", "false", true},
		{"default on, env unset cannot lower it", true, "", "", true},
		{"default on, explicit false is the escape hatch", true, "false", "", false},
		{"default on, explicit false beats env on", true, "false", "1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env != "" {
				t.Setenv("CHAINSAW_SCAN_FAIL_ON_UNSCANNED", tc.env)
			} else {
				t.Setenv("CHAINSAW_SCAN_FAIL_ON_UNSCANNED", "")
			}
			if got := resolveFailOnUnscanned(newCmd(tc.def, tc.set), tc.def); got != tc.want {
				t.Errorf("resolveFailOnUnscanned = %v, want %v", got, tc.want)
			}
		})
	}

	// A command that never registered the flag must still get its documented
	// posture. A missing flag reading as "disarmed" is the failure mode this
	// signature exists to prevent.
	t.Setenv("CHAINSAW_SCAN_FAIL_ON_UNSCANNED", "")
	if !resolveFailOnUnscanned(&cobra.Command{Use: "unregistered"}, true) {
		t.Error("an unregistered --fail-on-unscanned must fall back to the caller's default, not to false")
	}
	if scanExitZero(&cobra.Command{Use: "unregistered"}) {
		t.Error("an unregistered --exit-zero must read false, i.e. the gate stays ARMED")
	}
}

// TestScanRepo_JSONEnvelopeIsUnchangedByTheGateRewrite. emitAndGateInto
// replaced an inline `if useJSON(cmd)` branch; the document on the wire must be
// byte-identical, including the empty-array `findings` and the omitted
// `unreadable` key that N1/X2 pinned.
func TestScanRepo_JSONEnvelopeIsUnchangedByTheGateRewrite(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hi\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out, errOut strings.Builder
	cmd := newScanRepoGateCmd(&out, &errOut)
	_ = cmd.Flags().Set("json", "true")
	if err := runScanRepo(cmd, []string{dir}); err != nil {
		t.Fatalf("clean tree: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal([]byte(out.String()), &generic); err != nil {
		t.Fatalf("json: %v\n%s", err, out.String())
	}
	if len(generic) != 2 {
		t.Errorf("clean-tree envelope should stay {root, findings}, got %v", generic)
	}
	arr, ok := generic["findings"].([]any)
	if !ok || len(arr) != 0 {
		t.Errorf("`findings` must be an empty ARRAY, got %#v", generic["findings"])
	}
}
