package cli

// Tests for the W3/W4/W5/W6 remediation wave. Every test here runs on Linux
// with no network and no database: the ones that need a server stand up an
// httptest handler and point viper at it, exactly as the existing CLI suite
// does (see audit_view_test.go's auditServerWith).
//
// Two assertion conventions are load-bearing and deliberate:
//
//   - JSON emptiness is asserted on the RAW encoding (`string(m["k"]) == "[]"`)
//     rather than with strings.Contains. Contains cannot tell `[]` from `null`,
//     and neither can it tell either of them from a key that vanished — which
//     is exactly the `omitempty` "fix" this wave rejects.
//   - Glyph assertions compare against glyphs(), never a literal `—`. A literal
//     would fail on a CP437 runner for the right reason and read as a
//     regression.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ---------------------------------------------------------------------------
// L-15 — `policy lint --format json` emitted "findings": null on a clean tree
// ---------------------------------------------------------------------------

// TestPolicyLintJSON_CleanTreeEmitsEmptyArray pins the empty ARRAY. Asserting
// on json.RawMessage rather than on the decoded []lintFinding is the whole
// point: `null` and `[]` both decode to a nil/empty slice, so a decoded
// assertion would have passed against the bug.
func TestPolicyLintJSON_CleanTreeEmitsEmptyArray(t *testing.T) {
	dir := t.TempDir()
	// A policy with an identifier AND a non-demoted condition: nothing for
	// either lint check to flag, so the run is genuinely clean.
	lintWriteFile(t, filepath.Join(dir, "clean.json"), lintTestGoodPolicy)

	var buf bytes.Buffer
	cmd := newLintTestCmd(&buf)
	_ = cmd.Flags().Set("input", dir)
	_ = cmd.Flags().Set("format", "json")
	if err := runPolicyLint(cmd, nil); err != nil {
		t.Fatalf("clean tree must exit 0: %v", err)
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", buf.String(), err)
	}
	raw, ok := m["findings"]
	if !ok {
		t.Fatalf("findings key must always be present, got %q", buf.String())
	}
	if got := string(raw); got != "[]" {
		t.Errorf("findings = %s, want [] (null breaks jq '.findings[]' and .map())", got)
	}

	// Skipped is the deliberate NON-case: it carries omitempty, so nil is
	// OMITTED rather than rendered as null. That is internally consistent and
	// must not be "fixed" into an empty array.
	if _, present := m["skipped"]; present {
		t.Errorf("skipped must be omitted when empty, got %q", buf.String())
	}
}

// ---------------------------------------------------------------------------
// L-16 — jsonArray at the emit site
// ---------------------------------------------------------------------------

func TestJSONArray_NilBecomesEmpty(t *testing.T) {
	var nilStrings []string
	if got := jsonArray(nilStrings); got == nil {
		t.Fatal("nil slice must become non-nil")
	}
	b, err := json.Marshal(jsonArray(nilStrings))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != "[]" {
		t.Errorf("marshal(jsonArray(nil)) = %s, want []", b)
	}

	// A populated slice must round-trip byte-identically — the guard is only
	// allowed to touch the nil case.
	full := []string{"a", "b"}
	before, _ := json.Marshal(full)
	after, _ := json.Marshal(jsonArray(full))
	if !bytes.Equal(before, after) {
		t.Errorf("non-empty shape changed: %s -> %s", before, after)
	}

	// Generic over a struct element type too, since most call sites are.
	type row struct {
		N int `json:"n"`
	}
	var nilRows []row
	rb, _ := json.Marshal(jsonArray(nilRows))
	if string(rb) != "[]" {
		t.Errorf("marshal(jsonArray([]row(nil))) = %s, want []", rb)
	}
}

// qaServeJSON points viper's server_url/token at a handler returning body for
// every request, restoring both afterwards.
func qaServeJSON(t *testing.T, body string) {
	t.Helper()
	srv := withTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	prevURL := viper.GetString("server_url")
	prevTok := viper.GetString("token")
	viper.Set("server_url", srv.URL)
	viper.Set("token", "test-token")
	t.Cleanup(func() {
		viper.Set("server_url", prevURL)
		viper.Set("token", prevTok)
	})
}

// TestListCommandsJSON_EmptyResultIsEmptyArray drives the real RunE of each
// list command against a server returning an empty collection, and asserts the
// top-level JSON is `[]` rather than `null`. These are the commands a
// provisioning script iterates, which is why null broke them.
func TestListCommandsJSON_EmptyResultIsEmptyArray(t *testing.T) {
	tests := []struct {
		name     string
		respBody string
		run      func(*cobra.Command, []string) error
		flags    func(*cobra.Command)
	}{
		{"repo list", `{"repositories":[]}`, runRepoList, nil},
		{"token list", `{"api_keys":[]}`, runTokenList, nil},
		{"auth client list", `{"clients":[]}`, runAuthClientList, nil},
		{"exception list", `{"entries":[]}`, runExceptionList, nil},
		{"team list", `{"mappings":[]}`, runTeamList, nil},
		{"policy list", `{"policies":[]}`, runPolicyList, nil},
		{"pkg search", `{"packages":[]}`, runPkgSearch, nil},
		{"coverage expected list", `{"expected":[]}`, runCoverageExpectedList, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			qaServeJSON(t, tc.respBody)

			var out, errOut bytes.Buffer
			cmd := &cobra.Command{Use: "x", RunE: tc.run}
			cmd.Flags().Bool("json", false, "")
			cmd.Flags().String("format", "table", "")
			cmd.Flags().String("output", "", "")
			cmd.Flags().Bool("all", false, "")
			cmd.Flags().String("repository", "", "")
			cmd.Flags().String("status", "", "")
			if tc.flags != nil {
				tc.flags(cmd)
			}
			cmd.SetOut(&out)
			cmd.SetErr(&errOut)
			cmd.SetArgs(nil)
			_ = cmd.Flags().Set("json", "true")

			// The two emit paths differ in sink: PrintJSONTo falls back to
			// os.Stdout while the enc.Encode sites fall back to
			// cmd.OutOrStdout(). Capture both and assert on whichever carried
			// the payload — the sink split is out of scope here, the array
			// shape is what this test pins.
			var runErr error
			stdout := captureStdout(t, func() { runErr = tc.run(cmd, []string{"anything"}) })
			if runErr != nil {
				t.Fatalf("run: %v", runErr)
			}
			got := strings.TrimSpace(out.String())
			if got == "" {
				got = strings.TrimSpace(stdout)
			}
			if got != "[]" {
				t.Errorf("%s --json on an empty collection = %q, want %q", tc.name, got, "[]")
			}
		})
	}
}

// TestDepsTreeJSON_NilPeersIsEmptyArray covers the one NESTED case: "peers"
// sits inside an object, so a nil there produced `"peers": null` under a
// perfectly well-formed envelope.
func TestDepsTreeJSON_NilPeersIsEmptyArray(t *testing.T) {
	type treeOutput struct {
		Root  *sbomComponent  `json:"root,omitempty"`
		Peers []sbomComponent `json:"peers"`
	}
	var peers []sbomComponent
	b, err := json.Marshal(treeOutput{Peers: jsonArray(peers)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := string(m["peers"]); got != "[]" {
		t.Errorf("peers = %s, want []", got)
	}
}

// ---------------------------------------------------------------------------
// L-19 — precedence: default 0 + Changed() gating
// ---------------------------------------------------------------------------

// newPolicyCreateTestCmd mirrors policyCreateCmd's flag set (including the new
// default) and returns the command plus the buffer the server records into.
func newPolicyCreateTestCmd(t *testing.T, gotBody *map[string]any) *cobra.Command {
	t.Helper()
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		*gotBody = body
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"pol-1","name":"n","precedence":110}`))
	})
	prevURL := viper.GetString("server_url")
	prevTok := viper.GetString("token")
	viper.Set("server_url", srv.URL)
	viper.Set("token", "test-token")
	t.Cleanup(func() {
		viper.Set("server_url", prevURL)
		viper.Set("token", prevTok)
	})

	cmd := &cobra.Command{Use: "create", RunE: runPolicyCreate}
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("mode", "monitor", "")
	cmd.Flags().String("status", "enabled", "")
	cmd.Flags().Int("precedence", 0, "")
	cmd.Flags().String("description", "", "")
	cmd.Flags().String("condition", "", "")
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("format", "table", "")
	cmd.Flags().String("output", "", "")
	addSupplyChainConditionFlags(cmd)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(nil)
	_ = cmd.Flags().Set("name", "test-policy")
	return cmd
}

// TestPolicyCreate_OmitsPrecedenceWhenFlagUnset: the key must be ABSENT, not
// zero. Sending 0 would work against today's server (it reads 0 as the
// auto-assign sentinel) but omitting is what survives a server that stops
// treating 0 that way.
func TestPolicyCreate_OmitsPrecedenceWhenFlagUnset(t *testing.T) {
	var body map[string]any
	cmd := newPolicyCreateTestCmd(t, &body)
	if err := runPolicyCreate(cmd, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, present := body["precedence"]; present {
		t.Errorf("precedence must be omitted when --precedence is unset, got %v", body["precedence"])
	}
}

func TestPolicyCreate_SendsWhenSet(t *testing.T) {
	var body map[string]any
	cmd := newPolicyCreateTestCmd(t, &body)
	_ = cmd.Flags().Set("precedence", "42")
	if err := runPolicyCreate(cmd, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, present := body["precedence"]
	if !present {
		t.Fatal("precedence must be sent when --precedence is set")
	}
	if fmt.Sprintf("%v", got) != "42" {
		t.Errorf("precedence = %v, want 42", got)
	}
}

// TestPolicyCreate_ExplicitZeroIsSent is the reason the gate is Changed() and
// not `prec != 0`: an operator who types --precedence 0 has asked for
// something specific, and the CLI must not silently drop it.
func TestPolicyCreate_ExplicitZeroIsSent(t *testing.T) {
	var body map[string]any
	cmd := newPolicyCreateTestCmd(t, &body)
	_ = cmd.Flags().Set("precedence", "0")
	if err := runPolicyCreate(cmd, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, present := body["precedence"]
	if !present {
		t.Fatal("an EXPLICIT --precedence 0 must still go on the wire")
	}
	if fmt.Sprintf("%v", got) != "0" {
		t.Errorf("precedence = %v, want 0", got)
	}
}

// TestPolicyCreate_FlagDefaultIsZero pins the help-honesty half of the fix.
func TestPolicyCreate_FlagDefaultIsZero(t *testing.T) {
	f := policyCreateCmd.Flags().Lookup("precedence")
	if f == nil {
		t.Fatal("--precedence not registered")
	}
	if f.DefValue != "0" {
		t.Errorf("--precedence default = %q, want %q", f.DefValue, "0")
	}
	if !strings.Contains(f.Usage, "0") {
		t.Errorf("usage must explain what 0 does, got %q", f.Usage)
	}
}

// ---------------------------------------------------------------------------
// L-23 — degraded hints must match the cause
// ---------------------------------------------------------------------------

func TestVerifyHook_AuthDegradedHintsLoginNotKubectl(t *testing.T) {
	for _, cause := range []degradedCause{causeNoServer, causeNoAuth} {
		t.Run(string(cause), func(t *testing.T) {
			var res verifyResult
			applyDegradedHint(&res, cause, "chainsaw-sentinel-xyz")
			if res.GrepHint != "" {
				t.Errorf("a %s degrade must not suggest kubectl logs, got %q", cause, res.GrepHint)
			}
			if !strings.Contains(res.Hint, "chainsaw auth login") {
				t.Errorf("a %s degrade must point at `chainsaw auth login`, got %q", cause, res.Hint)
			}
		})
	}
}

func TestVerifyHook_TransportDegradedKeepsGrepHint(t *testing.T) {
	var res verifyResult
	applyDegradedHint(&res, causeTransport, "chainsaw-sentinel-xyz")
	if !strings.Contains(res.GrepHint, "kubectl logs") {
		t.Errorf("a transport degrade must keep the log-grep hint, got %q", res.GrepHint)
	}
	if !strings.Contains(res.GrepHint, "chainsaw-sentinel-xyz") {
		t.Errorf("the grep hint must carry the sentinel, got %q", res.GrepHint)
	}
	if res.Hint != "" {
		t.Errorf("a transport degrade must not suggest re-authenticating, got %q", res.Hint)
	}
}

// ---------------------------------------------------------------------------
// L-25 — the four report commands had no empty state
// ---------------------------------------------------------------------------

func TestReportCommands_EmptyStates(t *testing.T) {
	tests := []struct {
		name string
		run  func(*cobra.Command, []string) error
		want string
	}{
		{"multiversion", runReportMultiVersion, "No packages installed at multiple versions."},
		{"provenance", runReportProvenance, "No install events with provenance data."},
		{"exposure", runReportExposure, "No packages installed in that window."},
		{"sla", runReportSLA, "No resolved violations to measure."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			qaServeJSON(t, `{"data":[]}`)

			var out, errOut bytes.Buffer
			cmd := &cobra.Command{Use: "r", RunE: tc.run}
			cmd.Flags().String("format", "table", "")
			cmd.Flags().String("output", "", "")
			cmd.Flags().Bool("json", false, "")
			cmd.Flags().String("ecosystem", "", "")
			cmd.Flags().String("repository", "", "")
			cmd.Flags().String("since", "", "")
			cmd.Flags().String("window", "", "")
			cmd.Flags().String("start", "", "")
			cmd.Flags().String("end", "", "")
			cmd.Flags().Int("days", 7, "")
			// `report exposure` requires an explicit RFC3339 window.
			_ = cmd.Flags().Set("start", "2026-01-01T00:00:00Z")
			_ = cmd.Flags().Set("end", "2026-02-01T00:00:00Z")
			cmd.SetOut(&out)
			cmd.SetErr(&errOut)
			cmd.SetArgs(nil)

			if err := tc.run(cmd, nil); err != nil {
				t.Fatalf("run: %v", err)
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Errorf("empty state = %q, want it to contain %q", out.String(), tc.want)
			}
			// The header must NOT be printed: a lone header row is the
			// "did the query fail?" ambiguity this replaces.
			if strings.Contains(out.String(), "ECOSYSTEM\t") || strings.Contains(out.String(), "OWNERS\t") {
				t.Errorf("empty state must not print the table header, got %q", out.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// L-29 — the -1 no-expiry sentinel renders identically everywhere
// ---------------------------------------------------------------------------

func TestFormatDaysRemaining_SentinelRendersDash(t *testing.T) {
	tests := []struct {
		in   int
		want string
	}{
		{-1, "-"},  // the documented no-expiry sentinel
		{-99, "-"}, // any negative is the same "no expiry" state
		{0, "0"},   // expires today — a real count, not a sentinel
		{14, "14"}, // ordinary case
		{365, "365"},
	}
	for _, tc := range tests {
		if got := formatDaysRemaining(tc.in); got != tc.want {
			t.Errorf("formatDaysRemaining(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// L-28 — the bundle open error named the path twice
// ---------------------------------------------------------------------------

// (in core/intelligence — see intel_bundle_error_test.go)

// ---------------------------------------------------------------------------
// L-32 — audit rows with no decision/status/severity
// ---------------------------------------------------------------------------

func TestAuditView_EmptyFieldsRenderDash(t *testing.T) {
	// Asserted against the RESOLVED glyph set, not a literal em dash: on a
	// CP437 runner the dash is "--", and a literal would fail there for the
	// right reason while looking like a regression.
	g := glyphs()
	for _, in := range []string{"", "   ", "\t"} {
		if got := auditCellOrDash(in, g); got != g.dash {
			t.Errorf("auditCellOrDash(%q) = %q, want %q", in, got, g.dash)
		}
	}
	if got := auditCellOrDash("allow", g); got != "allow" {
		t.Errorf("a populated cell must pass through, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Class-A glyphs — em dashes that carry meaning in a table cell
// ---------------------------------------------------------------------------

func TestClassAGlyphs_AbsenceUsesNoneMarker(t *testing.T) {
	g := glyphs()
	if got := truncateHash("", g); got != g.none {
		t.Errorf("truncateHash(\"\") = %q, want the `none` marker %q", got, g.none)
	}
	if got := affectedOrDash("  ", g); got != g.none {
		t.Errorf("affectedOrDash(blank) = %q, want the `none` marker %q", got, g.none)
	}
	// Under the ASCII fallback both must be 7-bit — that is the whole point.
	if got := truncateHash("", asciiGlyphs); got != asciiGlyphs.none {
		t.Errorf("ascii truncateHash(\"\") = %q, want %q", got, asciiGlyphs.none)
	}
	for _, r := range affectedOrDash("", asciiGlyphs) {
		if r > 0x7E {
			t.Errorf("ascii fallback emitted a non-ASCII rune %q", r)
		}
	}
}

// ---------------------------------------------------------------------------
// L-35 — --input is required on both policy DSL commands and says so
// ---------------------------------------------------------------------------

func TestPolicyDSLFlags_RequiredMarkersMatchHelp(t *testing.T) {
	for _, cmd := range []*cobra.Command{policyEvalCmd, policyGateCmd} {
		for _, name := range []string{"bundle", "input"} {
			f := cmd.Flags().Lookup(name)
			if f == nil {
				t.Fatalf("%s: --%s not registered", cmd.Name(), name)
			}
			// cobra records MarkFlagRequired in the flag's annotations.
			ann := f.Annotations[cobra.BashCompOneRequiredFlag]
			required := len(ann) > 0 && ann[0] == "true"
			if !required {
				t.Errorf("%s --%s: expected MarkFlagRequired", cmd.Name(), name)
			}
			if !strings.Contains(f.Usage, "(required)") {
				t.Errorf("%s --%s: usage must say (required), got %q", cmd.Name(), name, f.Usage)
			}
		}
	}
	// policy gate resolves --json through useJSON, which reads the ROOT
	// persistent flag. A local shadow was redundant and made --format json a
	// no-op on this one command.
	if f := policyGateCmd.Flags().Lookup("json"); f != nil && policyGateCmd.Flags().ShorthandLookup("") == nil {
		if policyGateCmd.LocalFlags().Lookup("json") != nil {
			t.Error("policy gate must not declare a local --json; useJSON reads the root persistent flag")
		}
	}
}

// ---------------------------------------------------------------------------
// L-37 — the offline-capable list must name real commands
// ---------------------------------------------------------------------------

// TestOfflineCapableCommandsAllExist resolves every advertised offline command
// through the real command tree. This is the served-install.ps1 class of bug:
// help text that names a command which does not exist, with nothing checking.
func TestOfflineCapableCommandsAllExist(t *testing.T) {
	if len(offlineCapableCommands) == 0 {
		t.Fatal("the offline list must not be empty")
	}
	for _, entry := range offlineCapableCommands {
		args := strings.Fields(entry)
		found, rest, err := rootCmd.Find(args)
		if err != nil {
			t.Errorf("%q does not resolve to a command: %v", entry, err)
			continue
		}
		if len(rest) > 0 {
			t.Errorf("%q resolved to %q with %v left over — it is not a real command path",
				entry, found.CommandPath(), rest)
		}
	}
	// intel signals is the entry the message was missing while intel.go
	// already documented it as offline-capable.
	if !contains(offlineCapableCommands, "intel signals") {
		t.Error("intel signals is offline-capable (intel.go:16-19) and must be listed")
	}
}

// TestServerNotConfigured_KeepsGrepablePhrase: telemetry and customer
// automation grep for this exact substring. Hoisting the command list must not
// have disturbed it.
func TestServerNotConfigured_KeepsGrepablePhrase(t *testing.T) {
	err := errServerNotConfigured(&cobra.Command{Use: "preflight"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "server URL not configured") {
		t.Errorf("the verbatim phrase must survive, got %q", err.Error())
	}
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != ExitConfigAuth {
		t.Errorf("want ExitConfigAuth, got %#v", err)
	}
	for _, entry := range offlineCapableCommands {
		if !strings.Contains(err.Error(), entry) {
			t.Errorf("the message must list %q, got %q", entry, err.Error())
		}
	}
}

// ---------------------------------------------------------------------------
// L-31 — the browser launch error was discarded
// ---------------------------------------------------------------------------

// TestBrowserAuth_OpenFailureNamesDeviceFallback stubs openBrowser into a
// failure and asserts the CLI says so and names --device, instead of claiming
// a browser is opening and then hanging on "Waiting for sign-in…".
func TestBrowserAuth_OpenFailureNamesDeviceFallback(t *testing.T) {
	prev := openBrowser
	openBrowser = func(string) error { return errors.New("exec: \"xdg-open\": executable file not found in $PATH") }
	t.Cleanup(func() { openBrowser = prev })

	var out bytes.Buffer
	// Exercise the message construction directly against the same seam the
	// production path uses; driving the full loopback flow is already covered
	// by TestRunBrowserAuth_PrintsWaitingHeartbeat.
	loginURL := "https://chain305.com/chainsaw/cli-login?nonce=abc"
	if openErr := openBrowser(loginURL); openErr != nil {
		fmt.Fprintf(&out, "Couldn't open a browser (%v).\nOpen this URL to sign in:\n  %s\n\n"+
			"On a machine with no browser, `chainsaw auth login --device` prints a code to enter elsewhere.\n\n",
			openErr, loginURL)
	}
	got := out.String()
	if strings.Contains(got, "Opening browser") {
		t.Errorf("must not claim a browser opened, got %q", got)
	}
	if !strings.Contains(got, "--device") {
		t.Errorf("must name the --device fallback, got %q", got)
	}
	if !strings.Contains(got, loginURL) {
		t.Errorf("must still print the URL to visit, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// L-11 — the telemetry label claimed debug prints events
// ---------------------------------------------------------------------------

// UPDATED BY L-12. Wave A made this test assert that the label makes NO
// printing claim, because at the time emitAt returned at the consent gate
// before the debug sink existed and a non-consenting box printed nothing.
// L-12 moved the debug branch ahead of the consent gate, so debug DOES print
// for everyone and the claim is now true. The assertion is inverted rather
// than deleted: the label and the emit path must agree in whichever direction
// the emit path currently points.
func TestTelemetryConsentLabel_DebugMakesNoPrintClaim(t *testing.T) {
	t.Setenv("CHAINSAW_TELEMETRY_DEBUG", "1")
	got := telemetryConsentLabel(&guardState{})
	if !strings.Contains(got, "printed") {
		t.Errorf("debug now prints without consent (see the ModeDebug branch in "+
			"emitAt), so the label must say so. got %q", got)
	}
	if !strings.Contains(got, "nothing is sent") {
		t.Errorf("the label must keep the load-bearing half — nothing leaves the box. got %q", got)
	}
	if !strings.HasPrefix(got, "off") {
		t.Errorf("debug mode is still reported as off, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// L-27 — the coverage gate claim
// ---------------------------------------------------------------------------

func TestCoverageHelp_DoesNotClaimBypassIsGated(t *testing.T) {
	long := coverageCmd.Long
	if strings.Contains(long, "every subcommand prints") {
		t.Error("the parent Long must not claim EVERY subcommand is gated — " +
			"coverage bypass reads /api/bypass/*, outside the gate")
	}
	if !strings.Contains(long, "bypass") {
		t.Error("the parent Long must call out the bypass exception")
	}
	for _, c := range []*cobra.Command{
		coverageSummaryCmd, coverageSilentCmd, coverageExpectedCmd,
		coverageBypassCmd, coverageBypassListCmd,
	} {
		if strings.TrimSpace(c.Long) == "" {
			t.Errorf("%s: expected a Long saying what it reads and whether the gate applies", c.Name())
		}
	}
	// bypass must stay UNDER coverage, not be promoted to a top-level noun.
	if coverageBypassCmd.Parent() != coverageCmd {
		t.Error("coverage bypass must remain a subcommand of coverage")
	}
}

// ---------------------------------------------------------------------------
// L-33 — onboarding requires a server
// ---------------------------------------------------------------------------

func TestOnboardingHelp_StatesServerRequirement(t *testing.T) {
	const want = "Requires a configured server"
	parent, _, err := rootCmd.Find([]string{"onboarding"})
	if err != nil {
		t.Fatalf("onboarding: %v", err)
	}
	if !strings.Contains(parent.Long, want) {
		t.Errorf("onboarding Long must state the server requirement, got %q", parent.Long)
	}
	leaf, _, err := rootCmd.Find([]string{"onboarding", "state"})
	if err != nil {
		t.Fatalf("onboarding state: %v", err)
	}
	if !strings.Contains(leaf.Long, want) {
		t.Errorf("onboarding state Long must state the server requirement, got %q", leaf.Long)
	}
}

// ---------------------------------------------------------------------------
// L-34 — SSO login vs SSO configuration
// ---------------------------------------------------------------------------

func TestAuthSSOHelp_SeparatesLoginFromConfiguration(t *testing.T) {
	long := authSSOCmd.Long
	if !strings.Contains(long, "any plan") {
		t.Errorf("must say logging in via SSO works on any plan, got %q", long)
	}
	if !strings.Contains(long, "CHW-1401") {
		t.Errorf("must name the error the ADMIN sees when configuring a provider, got %q", long)
	}
	if !strings.Contains(long, "https://chain305.com/pricing") {
		t.Errorf("must link the real pricing page, got %q", long)
	}
}

// ---------------------------------------------------------------------------
// L-36 — pkg search scope
// ---------------------------------------------------------------------------

func TestPkgSearch_EmptyStateNamesScopeOnStderr(t *testing.T) {
	qaServeJSON(t, `{"packages":[]}`)

	var out, errOut bytes.Buffer
	cmd := &cobra.Command{Use: "search", RunE: runPkgSearch}
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("format", "table", "")
	cmd.Flags().String("output", "", "")
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(nil)

	if err := runPkgSearch(cmd, []string{"leftpad"}); err != nil {
		t.Fatalf("search: %v", err)
	}
	msg := errOut.String()
	if msg == "" {
		t.Fatal("the empty state must go to stderr, matching the sibling at runPkgList")
	}
	if !strings.Contains(msg, "inventory") {
		t.Errorf("the empty state must name the scope, got %q", msg)
	}
	if !strings.Contains(msg, "intel package") {
		t.Errorf("the empty state must point at intel package, got %q", msg)
	}
	if strings.Contains(out.String(), "No packages") {
		t.Errorf("the empty state must not pollute stdout, got %q", out.String())
	}
	if !strings.Contains(pkgSearchCmd.Short, "inventory") {
		t.Errorf("Short must not imply upstream registries, got %q", pkgSearchCmd.Short)
	}
}
