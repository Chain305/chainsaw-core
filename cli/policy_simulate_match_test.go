package cli

// policy_simulate_match_test.go — regressions for the `policy simulate`
// matcher (P4/P5/P10). Every case here previously reported the WRONG
// answer in the "you are safe" direction: no_match on rules that do
// match, or a confident allow from a rule the CLI could not actually
// evaluate.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/policy"
)

// TestSimulateIdentifierMatch_WildcardName is P4. Every seeded org policy
// ("Block known malware", "Block suspected typosquats", cooldown,
// publisher-change, the system SLSA rule) uses targetPackageName:"*".
// The old CLI matcher wildcarded "*" on the VERSION leg only, so the name
// leg string-compared "*" against the package and returned false —
// `policy simulate <any-known-malicious-package>` printed "no_match" and
// exited 0 on a default org while the proxy blocked the install.
func TestSimulateIdentifierMatch_WildcardName(t *testing.T) {
	ident := policy.Identifier{
		TargetPackageName:    "*",
		TargetPackageRepo:    "*",
		TargetPackageVersion: "*",
	}
	matched, unevaluated := simulateIdentifierMatch(ident, "", "lodash", "4.17.21")
	if !matched {
		t.Fatal(`identifier {name:"*",repo:"*",version:"*"} must match every package — every seeded policy uses this shape`)
	}
	if len(unevaluated) != 0 {
		t.Errorf("an all-wildcard identifier narrows nothing, so nothing is unevaluated; got %v", unevaluated)
	}
}

// TestSimulateIdentifierMatch_SemverConstraint is P5, on the exact shape
// the evaluator was previously fixed for: the CLI compared versions with
// string equality, so `<2.15.0` never matched `2.14.1` and simulate said
// "this would not be blocked" for log4j.
func TestSimulateIdentifierMatch_SemverConstraint(t *testing.T) {
	ident := policy.Identifier{
		TargetPackageName:    "log4j-core",
		TargetPackageVersion: "<2.15.0",
	}
	if matched, _ := simulateIdentifierMatch(ident, "", "log4j-core", "2.14.1"); !matched {
		t.Error("constraint <2.15.0 must match 2.14.1 (the log4j shape)")
	}
	if matched, _ := simulateIdentifierMatch(ident, "", "log4j-core", "2.17.0"); matched {
		t.Error("constraint <2.15.0 must NOT match 2.17.0")
	}
	// Range forms an operator would plausibly write.
	for _, c := range []struct {
		constraint, version string
		want                bool
	}{
		{"^1.0.0", "1.4.2", true},
		{"^1.0.0", "2.0.0", false},
		{">=1 <2", "1.9.9", true},
		{">=1 <2", "2.0.1", false},
	} {
		id := policy.Identifier{TargetPackageName: "p", TargetPackageVersion: c.constraint}
		if got, _ := simulateIdentifierMatch(id, "", "p", c.version); got != c.want {
			t.Errorf("constraint %q vs %q: got %v want %v", c.constraint, c.version, got, c.want)
		}
	}
}

// TestSimulateIdentifierMatch_RepoScopedWithoutFlag is P10-repo. The old
// matcher PARSED targetPackageRepo and then never compared it, so a
// repo-scoped rule matched every package unconditionally. Handing the
// evaluator's matcher an empty ctx.Repository would flip that into the
// opposite error — the rule silently stops matching. Neither is an
// honest preview, so the rule still surfaces and the dimension is
// reported as unevaluated.
func TestSimulateIdentifierMatch_RepoScopedWithoutFlag(t *testing.T) {
	ident := policy.Identifier{TargetPackageRepo: "npm-internal"}

	matched, unevaluated := simulateIdentifierMatch(ident, "", "lodash", "1.0.0")
	if !matched {
		t.Fatal("a repo-scoped rule must not be silently DROPPED when --repository is absent")
	}
	if len(unevaluated) != 1 {
		t.Fatalf("expected the repository dimension reported as unevaluated, got %v", unevaluated)
	}
	if want := "npm-internal"; !strings.Contains(unevaluated[0], want) {
		t.Errorf("the unevaluated reason must name the repo the rule targets (%q), got %q", want, unevaluated[0])
	}

	// With --repository supplied there is nothing unevaluated, and the
	// rule matches or does not on its merits.
	matched, unevaluated = simulateIdentifierMatch(ident, "npm-internal", "lodash", "1.0.0")
	if !matched || len(unevaluated) != 0 {
		t.Errorf("--repository npm-internal: matched=%v unevaluated=%v; want true / none", matched, unevaluated)
	}
	matched, unevaluated = simulateIdentifierMatch(ident, "npm-public", "lodash", "1.0.0")
	if matched || len(unevaluated) != 0 {
		t.Errorf("--repository npm-public: matched=%v unevaluated=%v; want false / none", matched, unevaluated)
	}
}

// TestSimulateIdentifierMatch_VersionScopedWithoutVersion is the same
// argument one dimension over: `policy simulate lodash` supplies no
// version, so a version-constrained rule cannot be decided here.
func TestSimulateIdentifierMatch_VersionScopedWithoutVersion(t *testing.T) {
	ident := policy.Identifier{TargetPackageName: "log4j-core", TargetPackageVersion: "<2.15.0"}
	matched, unevaluated := simulateIdentifierMatch(ident, "", "log4j-core", "")
	if !matched {
		t.Fatal("a version-scoped rule must not be silently dropped when no version was supplied")
	}
	if len(unevaluated) != 1 || !strings.Contains(unevaluated[0], "<2.15.0") {
		t.Fatalf("expected the version dimension reported as unevaluated and named, got %v", unevaluated)
	}
}

// TestUnevaluatedScopeDimensions is the Scope half of P10. Scope gates on
// the REQUESTER (client id, group, source repo, country, IP) — none of
// which exist in a `policy simulate` invocation and none of which the CLI
// could obtain. The old code never looked at Scope at all, so a rule
// scoped to one CI client previewed as if it applied to everyone.
func TestUnevaluatedScopeDimensions(t *testing.T) {
	if got := unevaluatedScopeDimensions(nil); got != nil {
		t.Errorf("absent scope: got %v want nil", got)
	}
	if got := unevaluatedScopeDimensions(json.RawMessage(`{}`)); got != nil {
		t.Errorf("empty scope means applies-to-all, nothing unevaluated; got %v", got)
	}
	if got := unevaluatedScopeDimensions(json.RawMessage(`{"targetClient":["*"]}`)); got != nil {
		t.Errorf(`scope of ["*"] narrows nothing; got %v`, got)
	}
	got := unevaluatedScopeDimensions(json.RawMessage(`{"targetClient":["ci-runner"],"targetRequestingCountry":["RU"]}`))
	if len(got) != 2 {
		t.Fatalf("expected both set dimensions reported, got %v", got)
	}
	if !strings.Contains(got[0], "ci-runner") || !strings.Contains(got[1], "RU") {
		t.Errorf("each reported dimension must name its values, got %v", got)
	}
}

// TestSimulateExceptionExpired is the expiry half of P10. Exceptions are
// stored with Precedence: -UnixNano so they sort FIRST, and the simulate
// loop breaks on the first match — so a dead exception outranked every
// block rule behind it and previewed as "allow" while the proxy blocked.
func TestSimulateExceptionExpired(t *testing.T) {
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	yesterday := now.Add(-24 * time.Hour)
	tomorrow := now.Add(24 * time.Hour)
	var zero time.Time

	cases := []struct {
		name string
		item policyItem
		want bool
	}{
		{"expired exception is skipped",
			policyItem{Kind: "exception", Mode: "allow", ExpiresAt: &yesterday}, true},
		{"live exception is honoured",
			policyItem{Kind: "exception", Mode: "allow", ExpiresAt: &tomorrow}, false},
		{"legacy allow-mode exception, expired",
			policyItem{Mode: "allow", ExpiresAt: &yesterday}, true},
		{"undated exception stays live (org exceptionAge is not visible to the CLI)",
			policyItem{Kind: "exception", Mode: "allow"}, false},
		{"zero-time expiry is 'no expiry', not 'expired in year 1'",
			policyItem{Kind: "exception", Mode: "allow", ExpiresAt: &zero}, false},
		{"a BLOCK rule with a stray expiresAt must keep blocking",
			policyItem{Mode: "block", ExpiresAt: &yesterday}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := simulateExceptionExpired(c.item, now); got != c.want {
				t.Errorf("simulateExceptionExpired = %v, want %v", got, c.want)
			}
		})
	}
}

// TestSimulateNoteDisclosesExceptionAgeBlindSpot pins the honesty
// requirement: the CLI cannot read the org's exceptionAge setting, so an
// undated exception may already be dead server-side while previewing as
// live. That gap is stated in the Note rather than papered over.
func TestSimulateNoteDisclosesExceptionAgeBlindSpot(t *testing.T) {
	dated := time.Now().Add(24 * time.Hour)

	clean := simulateNote([]policyItem{
		{Status: "enabled", Mode: "block"},
		{Status: "enabled", Kind: "exception", Mode: "allow", ExpiresAt: &dated},
	})
	if strings.Contains(clean, "exceptionAge") {
		t.Errorf("no undated exception exists — the caveat is noise here:\n%s", clean)
	}

	dirty := simulateNote([]policyItem{
		{Status: "enabled", Kind: "exception", Mode: "allow"},
	})
	if !strings.Contains(dirty, "exceptionAge") {
		t.Errorf("an undated exception must disclose the org-exceptionAge blind spot, got:\n%s", dirty)
	}
}

// newSimulateTestCmdWithRepo is newSimulateTestCmd plus the --repository
// flag the real command registers.
func newSimulateTestCmdWithRepo(buf *bytes.Buffer, asJSON bool, repo string) *cobra.Command {
	cmd := newSimulateTestCmd(buf, asJSON)
	cmd.Flags().String("repository", "", "")
	if repo != "" {
		_ = cmd.Flags().Set("repository", repo)
	}
	return cmd
}

// seededPolicyHandler serves the shape a DEFAULT org actually has: a
// wildcard-name block rule (every seeded policy uses
// targetPackageName:"*"), preceded by an EXPIRED exception at negative
// precedence — exactly how internal/server/exceptions_api.go writes them,
// and exactly the ordering /api/policies returns them in.
func seededPolicyHandler(t *testing.T, exceptionExpiry string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/policies" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"policies": []map[string]any{
				{
					"id":         "exc-1",
					"name":       "temporary exception",
					"mode":       "allow",
					"kind":       "exception",
					"status":     "enabled",
					"precedence": -1,
					"expiresAt":  exceptionExpiry,
					"identifier": map[string]any{"targetPackageName": "left-pad", "targetPackageVersion": "1.3.0"},
				},
				{
					"id":         "pol-malware",
					"name":       "Block known malware",
					"mode":       "block",
					"status":     "enabled",
					"precedence": 10,
					"identifier": map[string]any{"targetPackageName": "*", "targetPackageRepo": "*", "targetPackageVersion": "*"},
				},
			},
		})
	}
}

// TestPolicySimulate_ExpiredExceptionDoesNotShadowBlock is P4 and P10
// end-to-end, on the shape that actually ships. Before the fix BOTH bugs
// pointed the same way: the wildcard block rule was invisible (name leg
// did not wildcard "*") and the expired exception was honoured, so a
// default org previewed "allow" for a package the proxy blocks.
func TestPolicySimulate_ExpiredExceptionDoesNotShadowBlock(t *testing.T) {
	yesterday := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	srv := withTestServer(t, seededPolicyHandler(t, yesterday))
	withConfiguredServer(t, srv.URL)

	var buf bytes.Buffer
	err := runPolicySimulate(newSimulateTestCmdWithRepo(&buf, true, ""), []string{"left-pad@1.3.0"})

	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != ExitBlocked {
		t.Fatalf("an expired exception must not shadow the wildcard block rule; got err=%v\nenvelope:\n%s", err, buf.String())
	}
	var got map[string]any
	if uerr := json.Unmarshal(buf.Bytes(), &got); uerr != nil {
		t.Fatalf("decode envelope: %v\n%s", uerr, buf.String())
	}
	if got["outcome"] != "block" {
		t.Errorf("outcome = %v, want block", got["outcome"])
	}
	if got["matched_id"] != "pol-malware" {
		t.Errorf("matched_id = %v, want pol-malware (the wildcard rule)", got["matched_id"])
	}
}

// TestPolicySimulate_LiveExceptionStillWins is the negative control for
// the test above: the expiry check must skip only DEAD exceptions. A live
// exception continues to outrank the block rule, as the evaluator does.
func TestPolicySimulate_LiveExceptionStillWins(t *testing.T) {
	tomorrow := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	srv := withTestServer(t, seededPolicyHandler(t, tomorrow))
	withConfiguredServer(t, srv.URL)

	var buf bytes.Buffer
	if err := runPolicySimulate(newSimulateTestCmdWithRepo(&buf, true, ""), []string{"left-pad@1.3.0"}); err != nil {
		t.Fatalf("a live exception must still produce an allow (ExitOK), got %v\n%s", err, buf.String())
	}
	var got map[string]any
	_ = json.Unmarshal(buf.Bytes(), &got)
	if got["outcome"] != "allow" || got["matched_id"] != "exc-1" {
		t.Errorf("outcome=%v matched_id=%v; want allow / exc-1", got["outcome"], got["matched_id"])
	}
}

// TestPolicySimulate_RepoScopedReportsConditional pins the repo caveat at
// the command level: with no --repository, a repo-scoped rule yields
// `conditional` plus a named unevaluated dimension — never a silent match
// (the old behaviour: the repo was parsed and never compared) and never a
// silent skip.
func TestPolicySimulate_RepoScopedReportsConditional(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"policies": []map[string]any{{
				"id":         "pol-internal",
				"name":       "internal repo only",
				"mode":       "block",
				"status":     "enabled",
				"identifier": map[string]any{"targetPackageRepo": "npm-internal"},
			}},
		})
	}
	srv := withTestServer(t, handler)
	withConfiguredServer(t, srv.URL)

	// No --repository → conditional, ExitOK, dimension named.
	var buf bytes.Buffer
	if err := runPolicySimulate(newSimulateTestCmdWithRepo(&buf, true, ""), []string{"lodash@1.0.0"}); err != nil {
		t.Fatalf("conditional is informational, must be ExitOK; got %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(buf.Bytes(), &got)
	if got["outcome"] != "conditional" {
		t.Errorf("outcome = %v, want conditional", got["outcome"])
	}
	un, _ := got["unevaluated"].([]any)
	if len(un) != 1 || !strings.Contains(un[0].(string), "npm-internal") {
		t.Errorf("unevaluated must name the repo the rule targets, got %v", got["unevaluated"])
	}

	// With --repository matching → a definitive block.
	buf.Reset()
	err := runPolicySimulate(newSimulateTestCmdWithRepo(&buf, true, "npm-internal"), []string{"lodash@1.0.0"})
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != ExitBlocked {
		t.Fatalf("--repository npm-internal must produce a definitive block, got %v\n%s", err, buf.String())
	}

	// With --repository NOT matching → no_match, and nothing unevaluated.
	buf.Reset()
	if err := runPolicySimulate(newSimulateTestCmdWithRepo(&buf, true, "npm-public"), []string{"lodash@1.0.0"}); err != nil {
		t.Fatalf("non-matching repo must be no_match/ExitOK, got %v", err)
	}
	got = nil
	_ = json.Unmarshal(buf.Bytes(), &got)
	if got["outcome"] != "no_match" {
		t.Errorf("outcome = %v, want no_match", got["outcome"])
	}
}
