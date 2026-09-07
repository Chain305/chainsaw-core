package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/policy"
)

// TestParseCSVKinds covers whitespace trimming, case folding, empty
// handling, and de-duplication of the --*-kinds flag parser.
func TestParseCSVKinds(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"  ", nil},
		{"zero_width", []string{"zero_width"}},
		{"zero_width,bidi_override", []string{"zero_width", "bidi_override"}},
		{" Zero_Width ,  BIDI_OVERRIDE ", []string{"zero_width", "bidi_override"}},
		{"tag,tag,tag", []string{"tag"}},
		{"semver_regression,,major_skip", []string{"semver_regression", "major_skip"}},
	}
	for _, tc := range tests {
		got := parseCSVKinds(tc.in)
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("parseCSVKinds(%q)=%v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestValidateKinds checks that bad kind values produce an error
// listing the offenders, and that valid kinds pass silently.
func TestValidateKinds(t *testing.T) {
	if err := validateKinds("version-anomaly-kinds", nil, validVersionAnomalyKinds); err != nil {
		t.Fatalf("empty kinds should be valid, got %v", err)
	}
	if err := validateKinds("version-anomaly-kinds", []string{"semver_regression"}, validVersionAnomalyKinds); err != nil {
		t.Fatalf("valid kind rejected: %v", err)
	}
	err := validateKinds("version-anomaly-kinds", []string{"semver_regression", "bogus"}, validVersionAnomalyKinds)
	if err == nil {
		t.Fatalf("expected error for unknown kind")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("error should mention offending value, got %v", err)
	}
	if !strings.Contains(err.Error(), "allowed:") {
		t.Fatalf("error should list allowed kinds, got %v", err)
	}

	// Hidden-unicode kinds: same shape.
	if err := validateKinds("hidden-unicode-kinds", []string{"zero_width"}, validHiddenUnicodeKinds); err != nil {
		t.Fatalf("valid hidden-unicode kind rejected: %v", err)
	}
	if err := validateKinds("hidden-unicode-kinds", []string{"not_a_kind"}, validHiddenUnicodeKinds); err == nil {
		t.Fatalf("expected error for unknown hidden-unicode kind")
	}
}

// newPolicyTestCmd returns a throwaway cobra command with the
// supply-chain convenience flags wired up, so we can exercise the flag
// parser and applySupplyChainConditionFlags without spinning up the
// full CLI.
func newPolicyTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test", RunE: func(_ *cobra.Command, _ []string) error { return nil }}
	addSupplyChainConditionFlags(cmd)
	return cmd
}

// TestApplySupplyChainConditionFlags_HappyPath drives every
// convenience flag at least once and asserts the resulting conditions
// map has the server-expected JSON key names and values.
func TestApplySupplyChainConditionFlags_HappyPath(t *testing.T) {
	cmd := newPolicyTestCmd()
	err := cmd.ParseFlags([]string{
		"--has-install-script=true",
		"--install-script-fetches-remote=true",
		"--publisher-changed=true",
		"--version-anomaly=true",
		"--version-anomaly-kinds=semver_regression,major_skip",
		"--has-hidden-unicode=true",
		"--hidden-unicode-kinds=zero_width,bidi_override",
		"--publish-velocity-anomaly=true",
		"--publish-velocity-threshold-24h=15",
	})
	if err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	conditions := map[string]any{}
	if err := applySupplyChainConditionFlags(cmd, conditions); err != nil {
		t.Fatalf("applySupplyChainConditionFlags: %v", err)
	}

	wantBool := map[string]bool{
		"hasInstallScript":           true,
		"installScriptFetchesRemote": true,
		"publisherChanged":           true,
		"versionAnomaly":             true,
		"hasHiddenUnicode":           true,
		"publishVelocityAnomaly":     true,
	}
	for k, want := range wantBool {
		if got, ok := conditions[k].(bool); !ok || got != want {
			t.Errorf("conditions[%q]=%v (type %T), want %v", k, conditions[k], conditions[k], want)
		}
	}

	if got, ok := conditions["versionAnomalyKinds"].([]string); !ok ||
		!reflect.DeepEqual(got, []string{"semver_regression", "major_skip"}) {
		t.Errorf("versionAnomalyKinds=%v, want [semver_regression major_skip]", conditions["versionAnomalyKinds"])
	}
	if got, ok := conditions["hiddenUnicodeKinds"].([]string); !ok ||
		!reflect.DeepEqual(got, []string{"zero_width", "bidi_override"}) {
		t.Errorf("hiddenUnicodeKinds=%v, want [zero_width bidi_override]", conditions["hiddenUnicodeKinds"])
	}
	if got, ok := conditions["publishVelocityThreshold24h"].(int); !ok || got != 15 {
		t.Errorf("publishVelocityThreshold24h=%v, want 15", conditions["publishVelocityThreshold24h"])
	}
}

// TestApplySupplyChainConditionFlags_Unset confirms that flags not
// provided on the command line leave the conditions map untouched.
// Matters because applySupplyChainConditionFlags composes with
// --condition JSON — an unset flag must not clobber a JSON-provided
// value.
func TestApplySupplyChainConditionFlags_Unset(t *testing.T) {
	cmd := newPolicyTestCmd()
	if err := cmd.ParseFlags([]string{}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	conditions := map[string]any{"hasInstallScript": true} // pre-set from hypothetical --condition JSON
	if err := applySupplyChainConditionFlags(cmd, conditions); err != nil {
		t.Fatalf("applySupplyChainConditionFlags: %v", err)
	}
	if got, ok := conditions["hasInstallScript"].(bool); !ok || !got {
		t.Fatalf("hasInstallScript was clobbered: %v", conditions["hasInstallScript"])
	}
	if len(conditions) != 1 {
		t.Fatalf("expected only the pre-set field, got %+v", conditions)
	}
}

// TestApplySupplyChainConditionFlags_InvalidKinds makes sure the
// validator fires before the map is mutated — a typoed kind should
// leave no trace.
func TestApplySupplyChainConditionFlags_InvalidKinds(t *testing.T) {
	cmd := newPolicyTestCmd()
	if err := cmd.ParseFlags([]string{"--version-anomaly-kinds=typo"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	conditions := map[string]any{}
	err := applySupplyChainConditionFlags(cmd, conditions)
	if err == nil {
		t.Fatalf("expected error for invalid kind")
	}
	if _, ok := conditions["versionAnomalyKinds"]; ok {
		t.Fatalf("invalid kinds should not be stored: %v", conditions)
	}
}

// TestApplySupplyChainConditionFlags_NegativeThreshold guards the
// min-value check on --publish-velocity-threshold-24h.
func TestApplySupplyChainConditionFlags_NegativeThreshold(t *testing.T) {
	cmd := newPolicyTestCmd()
	if err := cmd.ParseFlags([]string{"--publish-velocity-threshold-24h=0"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if err := applySupplyChainConditionFlags(cmd, map[string]any{}); err == nil {
		t.Fatalf("expected error for threshold 0")
	}
}

// TestSummarizeConditions_Stable verifies the condition summary is
// deterministic and only includes fields the server actually sent.
//
// Carried forward from the version that fed a hand-maintained
// policyConditionsSummary struct: same intent (stable order, set-fields
// only, exact "<key>=<value>" spelling), now driven from the wire JSON
// the renderer actually consumes. The families at the bottom —
// cooldownDays, attestation, licence, behavioural — are the ones the
// struct never carried and therefore never printed.
func TestSummarizeConditions_Stable(t *testing.T) {
	// Empty input yields an empty list, which the callers render as
	// "no runtime conditions" rather than as a rendering gap.
	if got := summarizeConditions(nil); len(got) != 0 {
		t.Fatalf("nil conditions: want empty, got %v", got)
	}
	if got := summarizeConditions(json.RawMessage(`{}`)); len(got) != 0 {
		t.Fatalf("empty object: want empty, got %v", got)
	}

	raw := json.RawMessage(`{
		"hasInstallScript": true,
		"publisherChanged": true,
		"versionAnomalyKinds": ["semver_regression"],
		"hiddenUnicodeKinds": ["zero_width","bidi_override"],
		"publishVelocityThreshold24h": 10,
		"cooldownDays": 7,
		"requireSlsaLevel": 3,
		"licenseCopyleft": true,
		"usesEval": true,
		"cvssMin": 9.1,
		"hasProvenance": false,
		"trustScoreMin": 0
	}`)
	got := summarizeConditions(raw)
	joined := strings.Join(got, "\n")
	for _, want := range []string{
		"hasInstallScript=true",
		"publisherChanged=true",
		"versionAnomalyKinds=[semver_regression]",
		"hiddenUnicodeKinds=[zero_width,bidi_override]",
		"publishVelocityThreshold24h=10",
		// The four families the old struct omitted.
		"cooldownDays=7",
		"requireSlsaLevel=3",
		"licenseCopyleft=true",
		"usesEval=true",
		// A false/zero condition is real configuration ("must NOT have
		// provenance"), not an absent one — dropping it would re-create
		// the same defect one value-shape lower down.
		"hasProvenance=false",
		"trustScoreMin=0",
		// Floats keep their literal spelling.
		"cvssMin=9.1",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("summary missing %q; got:\n%s", want, joined)
		}
	}

	// Deterministic: sorted by key, and the same input renders the same
	// way every call (map iteration order must not leak).
	if !sort.StringsAreSorted(got) {
		t.Errorf("summary is not sorted by key: %v", got)
	}
	for i := 0; i < 20; i++ {
		if again := summarizeConditions(raw); !reflect.DeepEqual(again, got) {
			t.Fatalf("summary is not deterministic:\n%v\n%v", got, again)
		}
	}
}

// TestSummarizeConditions_SkipsOnlyAbsentValues pins the skip rule:
// null / "" / [] / {} are absent, false and 0 are not.
func TestSummarizeConditions_SkipsOnlyAbsentValues(t *testing.T) {
	got := summarizeConditions(json.RawMessage(
		`{"a":null,"b":"","c":[],"d":{},"e":false,"f":0,"g":"npm"}`))
	want := []string{"e=false", "f=0", "g=npm"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestSummarizeConditions_CoversEveryConditionField is the anti-drift
// guard, and it replaces TestPolicyConditionsSummary_JSONRoundTrip —
// same intent (the CLI must not fall behind policy.Conditions), a
// structurally stronger mechanism.
//
// The old test pinned a FIELD LIST, so it could only fail for fields
// somebody had already remembered to add; policy.Conditions grew to 67
// fields while the CLI's view type stayed at 22 and the test stayed
// green throughout. This one reflects over policy.Conditions, fills
// EVERY field, marshals it the way the server does, and asserts the
// renderer emits a line for every key on the wire.
//
// A newly added condition therefore cannot silently disappear from
// `policy show` or `policy simulate`: it is picked up automatically
// (generic rendering makes omission structurally impossible — there is
// no field list to update), and if the renderer ever regresses to a
// curated list, this goes red on the first unlisted field. The
// assertion is on the BEHAVIOUR — "every key the server marshals is
// rendered" — not on any enumeration of field names.
func TestSummarizeConditions_CoversEveryConditionField(t *testing.T) {
	var c policy.Conditions
	filled := fillEveryConditionField(t, reflect.ValueOf(&c).Elem())
	if filled < 40 {
		t.Fatalf("filler only populated %d fields — policy.Conditions has changed shape "+
			"and this guard is no longer covering it", filled)
	}

	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal Conditions: %v", err)
	}
	var onWire map[string]any
	if err := json.Unmarshal(raw, &onWire); err != nil {
		t.Fatalf("unmarshal Conditions: %v", err)
	}
	if len(onWire) != filled {
		t.Fatalf("filled %d fields but %d reached the wire", filled, len(onWire))
	}

	rendered := summarizeConditions(raw)
	if len(rendered) != len(onWire) {
		t.Fatalf("rendered %d conditions for %d on the wire", len(rendered), len(onWire))
	}
	seen := make(map[string]bool, len(rendered))
	for _, line := range rendered {
		k, _, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("rendered line is not <key>=<value>: %q", line)
		}
		seen[k] = true
	}
	for k := range onWire {
		if !seen[k] {
			t.Errorf("condition %q is on the wire but was not rendered", k)
		}
	}
}

// fillEveryConditionField sets every field of a policy.Conditions to a
// non-zero value and returns how many it set. Unknown field kinds are a
// hard failure rather than a skip — a silently-skipped field is exactly
// the hole this guard exists to close.
func fillEveryConditionField(t *testing.T, v reflect.Value) int {
	t.Helper()
	n := 0
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		name := v.Type().Field(i).Name
		switch f.Type().String() {
		case "*bool":
			b := true
			f.Set(reflect.ValueOf(&b))
		case "*int":
			x := 3
			f.Set(reflect.ValueOf(&x))
		case "*float64":
			x := 1.5
			f.Set(reflect.ValueOf(&x))
		case "[]string":
			f.Set(reflect.ValueOf([]string{"x"}))
		case "*string":
			s := "x"
			f.Set(reflect.ValueOf(&s))
		default:
			t.Fatalf("policy.Conditions.%s has unhandled type %s — teach this filler "+
				"about it, do not let the field go uncovered", name, f.Type())
		}
		n++
	}
	return n
}

// ── policy show ───────────────────────────────────────────────────────────────

func newPolicyShowCmdForTest() *cobra.Command {
	c := &cobra.Command{Use: "show", RunE: runPolicyShow, Args: cobra.ExactArgs(1), SilenceUsage: true}
	c.Flags().Bool("json", false, "")
	return c
}

// singlePolicyStub answers GET /api/policies/{id} with the given policy
// body verbatim.
func singlePolicyStub(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/policies/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"policy":` + body + `}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestPolicyShow_RendersCooldownDays is the direct regression test for
// the QA rows this command exists to close. A tester created a
// cooldown-quarantine policy, saw its name in `policy list`, and wrote
// it up as "actively enforced" — because no documented command could
// print a policy's configuration. `policy show` must print the
// condition that was configured.
func TestPolicyShow_RendersCooldownDays(t *testing.T) {
	srv := singlePolicyStub(t, `{
		"id":"pol-1","name":"cooldown-quarantine","mode":"quarantine","status":"enabled",
		"conditions":{"cooldownDays":14}
	}`)
	setViperServer(t, srv.URL)

	cmd := newPolicyShowCmdForTest()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"pol-1"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "cooldownDays=14") {
		t.Fatalf("policy show must print the configured cooldown; got:\n%s", out)
	}
	if !strings.Contains(out, "Mode:") || !strings.Contains(out, "quarantine") {
		t.Errorf("policy show must print the mode; got:\n%s", out)
	}
}

// TestPolicyShow_RendersEveryOmittedFamily covers one condition from
// each family the old hand-maintained summary dropped on the floor:
// attestation, licence, behavioural (Wave-3 source scanner), plus
// ecosystems and dependency hygiene for good measure.
func TestPolicyShow_RendersEveryOmittedFamily(t *testing.T) {
	srv := singlePolicyStub(t, `{
		"id":"pol-2","name":"slsa-baseline","mode":"block","status":"enabled",
		"conditions":{
			"requireSlsaLevel":3,
			"requireTransparencyLog":true,
			"licenseCopyleft":true,
			"licenseUnidentified":false,
			"usesEval":true,
			"networkAccess":true,
			"ecosystems":["npm","pypi"],
			"gitDependency":true,
			"dangerousPickle":true
		}
	}`)
	setViperServer(t, srv.URL)

	cmd := newPolicyShowCmdForTest()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"pol-2"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"requireSlsaLevel=3",          // attestation
		"requireTransparencyLog=true", // attestation
		"licenseCopyleft=true",        // licence
		"licenseUnidentified=false",   // licence, explicitly false
		"usesEval=true",               // behavioural
		"networkAccess=true",          // behavioural
		"ecosystems=[npm,pypi]",       // scoping
		"gitDependency=true",          // dependency hygiene
		"dangerousPickle=true",        // AI artifact
	} {
		if !strings.Contains(out, want) {
			t.Errorf("policy show omitted %q; got:\n%s", want, out)
		}
	}
}

// TestPolicyShow_EmptyConditionsSaysSo: a policy with no conditions
// must say it fires on every match. A blank section reads as "the tool
// did not render it", which is the ambiguity that let an unconfigured
// policy pass for a configured one.
func TestPolicyShow_EmptyConditionsSaysSo(t *testing.T) {
	srv := singlePolicyStub(t, `{"id":"pol-3","name":"bare","mode":"monitor","status":"enabled"}`)
	setViperServer(t, srv.URL)

	cmd := newPolicyShowCmdForTest()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"pol-3"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "Conditions:") {
		t.Fatalf("expected a Conditions block; got:\n%s", out)
	}
	if !strings.Contains(out, "fires on every identifier match") {
		t.Fatalf("empty conditions must be stated, not left blank; got:\n%s", out)
	}
}

// TestPolicyShow_JSONIsVerbatim: --json hands back the server's object
// unchanged, including fields the human rendering does not know about.
// --json is the complete surface; the text view is the readable one.
func TestPolicyShow_JSONIsVerbatim(t *testing.T) {
	srv := singlePolicyStub(t, `{
		"id":"pol-4","name":"x","mode":"block","status":"enabled",
		"conditions":{"cooldownDays":9},
		"someFutureField":{"nested":true}
	}`)
	setViperServer(t, srv.URL)

	cmd := newPolicyShowCmdForTest()
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"pol-4", "--json"})
	// PrintJSONTo writes to the RESULT sink (os.Stdout unless --output),
	// not to cmd.OutOrStdout() — same path `policy list --json` takes.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := cmd.Execute()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	if err != nil {
		t.Fatalf("execute: %v\n%s", err, buf.String())
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("--json output is not JSON: %v\n%s", err, buf.String())
	}
	if _, ok := got["someFutureField"]; !ok {
		t.Errorf("--json dropped a field the CLI does not model: %v", got)
	}
	conds, _ := got["conditions"].(map[string]any)
	if conds["cooldownDays"] == nil {
		t.Errorf("--json dropped cooldownDays: %v", got)
	}
}

// ── policy simulate ───────────────────────────────────────────────────────────

// TestPolicySimulate_RendersCooldownDays: the second half of the same
// defect. summarizeConditions had exactly one caller — simulate — so
// the 45 unmodelled conditions were invisible there too. An operator
// previewing a cooldown-only rule saw an empty condition list AND an
// "identifier-only match — runtime conditions not evaluated" headline
// for a rule that has a runtime condition.
func TestPolicySimulate_RendersCooldownDays(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"policies":[{
			"id":"pol-1","name":"cooldown-quarantine","mode":"quarantine","status":"enabled",
			"identifier":{"targetPackageName":"*"},
			"conditions":{"cooldownDays":14}
		}]}`))
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := &cobra.Command{Use: "simulate", RunE: runPolicySimulate, Args: cobra.ExactArgs(1), SilenceUsage: true}
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("repository", "", "")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"lodash@4.17.21"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "cooldownDays=14") {
		t.Fatalf("simulate must list the cooldown condition; got:\n%s", out)
	}
	// And the headline must stop claiming the match was identifier-only.
	if strings.Contains(out, "identifier-only match") {
		t.Errorf("a rule with a runtime condition is not an identifier-only match; got:\n%s", out)
	}
	if !strings.Contains(out, "conditional") {
		t.Errorf("expected a conditional outcome for an unevaluable condition; got:\n%s", out)
	}
}

// ── policy list CONDITIONS column ─────────────────────────────────────────────

// TestPolicyConditionsCell_TruncatesDeterministically: the cell is
// width-bounded, always marks elision, and never renders empty for a
// policy that has conditions. PrintTable has no cap of its own, so an
// unbounded cell would destroy the table.
func TestPolicyConditionsCell_TruncatesDeterministically(t *testing.T) {
	if got := policyConditionsCell(nil); got != "-" {
		t.Errorf("no conditions should render %q, got %q", "-", got)
	}

	raw := json.RawMessage(`{
		"cooldownDays":7,"cvssMin":9,"epssMin":0.5,"gitDependency":true,
		"hasInstallScript":true,"licenseCopyleft":true,"networkAccess":true,
		"publisherChanged":true,"requireSlsaLevel":3,"shellAccess":true,
		"usesEval":true,"versionAnomaly":true
	}`)
	cell := policyConditionsCell(raw)
	if !strings.Contains(cell, "+") || !strings.HasSuffix(cell, "more") {
		t.Fatalf("elision must be visible, got %q", cell)
	}
	// Deterministic across calls.
	for i := 0; i < 20; i++ {
		if again := policyConditionsCell(raw); again != cell {
			t.Fatalf("cell is not deterministic: %q vs %q", cell, again)
		}
	}
	// The kept prefix stays inside the budget; the "+N more" marker is
	// allowed to overhang it so the elision is never itself elided.
	prefix, _, _ := strings.Cut(cell, " +")
	if displayWidth(prefix) > policyListConditionsWidth {
		t.Errorf("kept prefix %q is %d wide, budget is %d",
			prefix, displayWidth(prefix), policyListConditionsWidth)
	}
	// Sorted keys mean the first condition is stable; cooldownDays sorts
	// early, which is why the QA row's condition survives the cut.
	if !strings.HasPrefix(cell, "cooldownDays=7") {
		t.Errorf("cell should lead with the first sorted condition, got %q", cell)
	}
	// The count adds up: kept + elided == total.
	total := len(summarizeConditions(raw))
	kept := len(strings.Split(prefix, ", "))
	var n int
	if _, err := fmt.Sscanf(cell[strings.Index(cell, " +"):], " +%d more", &n); err != nil {
		t.Fatalf("could not parse the elision marker in %q: %v", cell, err)
	}
	if kept+n != total {
		t.Errorf("cell accounts for %d+%d of %d conditions: %q", kept, n, total, cell)
	}

	// A single condition longer than the budget is kept whole rather
	// than rendered as an empty cell.
	long := json.RawMessage(`{"reservedNamespaces":["` + strings.Repeat("a", 80) + `"]}`)
	if got := policyConditionsCell(long); !strings.HasPrefix(got, "reservedNamespaces=") {
		t.Errorf("an over-budget single condition must still render, got %q", got)
	}
}

// TestPolicyList_ColumnAndJSON: the table carries a CONDITIONS column
// and names the authoritative command, and --json still carries every
// condition untouched.
func TestPolicyList_ColumnAndJSON(t *testing.T) {
	body := `{"policies":[{
		"id":"pol-1","name":"cooldown-quarantine","mode":"quarantine","status":"enabled",
		"precedence":10,"conditions":{"cooldownDays":14,"licenseCopyleft":true}
	}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	run := func(asJSON bool) string {
		t.Helper()
		cmd := &cobra.Command{Use: "list", RunE: runPolicyList}
		cmd.Flags().Bool("json", asJSON, "")
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		cmd.SetOut(w)
		err := runPolicyList(cmd, nil)
		_ = w.Close()
		os.Stdout = old
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		if err != nil {
			t.Fatalf("runPolicyList: %v\n%s", err, buf.String())
		}
		return buf.String()
	}

	table := run(false)
	// Assert on the HEADER ROW, not on the whole output: the footer
	// below the table also says "CONDITIONS", so a whole-output Contains
	// would stay green with the column removed.
	var header string
	for _, line := range strings.Split(table, "\n") {
		if strings.HasPrefix(line, "ID") {
			header = line
			break
		}
	}
	if header == "" {
		t.Fatalf("could not find the table header row in:\n%s", table)
	}
	if !strings.Contains(header, "CONDITIONS") {
		t.Errorf("list table has no CONDITIONS column; header was %q", header)
	}
	if !strings.Contains(table, "cooldownDays=14") {
		t.Errorf("list table omits the configured cooldown:\n%s", table)
	}
	if !strings.Contains(table, "policy show") {
		t.Errorf("list must name the authoritative command:\n%s", table)
	}

	out := run(true)
	var got []map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("--json is not JSON: %v\n%s", err, out)
	}
	conds, _ := got[0]["conditions"].(map[string]any)
	if conds["cooldownDays"] == nil || conds["licenseCopyleft"] == nil {
		t.Errorf("--json must stay the complete surface, got %v", got[0]["conditions"])
	}
}
