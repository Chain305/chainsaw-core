package cli

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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
// deterministic and only includes set fields.
func TestSummarizeConditions_Stable(t *testing.T) {
	truePtr := func() *bool { v := true; return &v }
	intPtr := func(i int) *int { return &i }

	// Empty summary yields empty list.
	if got := summarizeConditions(policyConditionsSummary{}); len(got) != 0 {
		t.Fatalf("empty summary: want empty, got %v", got)
	}

	s := policyConditionsSummary{
		HasInstallScript:            truePtr(),
		PublisherChanged:            truePtr(),
		VersionAnomalyKinds:         []string{"semver_regression"},
		HiddenUnicodeKinds:          []string{"zero_width", "bidi_override"},
		PublishVelocityThreshold24h: intPtr(10),
	}
	got := summarizeConditions(s)
	joined := strings.Join(got, "\n")
	for _, want := range []string{
		"hasInstallScript=true",
		"publisherChanged=true",
		"versionAnomalyKinds=[semver_regression]",
		"hiddenUnicodeKinds=[zero_width,bidi_override]",
		"publishVelocityThreshold24h=10",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("summary missing %q; got:\n%s", want, joined)
		}
	}
}

// TestPolicyConditionsSummary_JSONRoundTrip verifies the summary type
// decodes the canonical server JSON (key names, types) without loss —
// catching drift between the CLI's view type and the policy.Conditions
// schema.
func TestPolicyConditionsSummary_JSONRoundTrip(t *testing.T) {
	raw := []byte(`{
		"hasInstallScript": true,
		"installScriptFetchesRemote": false,
		"publisherChanged": true,
		"versionAnomaly": true,
		"versionAnomalyKinds": ["semver_regression","major_skip"],
		"hasHiddenUnicode": true,
		"hiddenUnicodeKinds": ["zero_width"],
		"publishVelocityAnomaly": true,
		"publishVelocityThreshold24h": 25
	}`)
	var s policyConditionsSummary
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.HasInstallScript == nil || *s.HasInstallScript != true {
		t.Errorf("HasInstallScript not parsed")
	}
	if s.InstallScriptFetchesRemote == nil || *s.InstallScriptFetchesRemote != false {
		t.Errorf("InstallScriptFetchesRemote not parsed")
	}
	if s.PublisherChanged == nil || *s.PublisherChanged != true {
		t.Errorf("PublisherChanged not parsed")
	}
	if !reflect.DeepEqual(s.VersionAnomalyKinds, []string{"semver_regression", "major_skip"}) {
		t.Errorf("VersionAnomalyKinds = %v", s.VersionAnomalyKinds)
	}
	if !reflect.DeepEqual(s.HiddenUnicodeKinds, []string{"zero_width"}) {
		t.Errorf("HiddenUnicodeKinds = %v", s.HiddenUnicodeKinds)
	}
	if s.PublishVelocityThreshold24h == nil || *s.PublishVelocityThreshold24h != 25 {
		t.Errorf("PublishVelocityThreshold24h = %v", s.PublishVelocityThreshold24h)
	}
}
