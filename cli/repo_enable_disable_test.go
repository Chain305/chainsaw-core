package cli

// repo_enable_disable_test.go — retiring a mistyped repository from the CLI.
//
// `repo` shipped list / create / status and nothing else, so a repository
// created with the wrong name could only be dealt with from the dashboard.
// `repo delete` was REJECTED for sound reasons (L-18, docs/qa-remediation/
// W5-W6-server-ux.md: re-adopting a deleted name inherits index_entries,
// vulnerability_metadata and package_permissions, so a credential silently
// regains access to a repository an admin believes destroyed) — and its stated
// substitute, "make PATCH {enabled:false} discoverable", was never built.
//
// These tests pin the substitute: the wire contract, the destructive-verb
// convention on `disable`, and the absence of a `delete` verb.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

type capturedRepoPatch struct {
	method string
	path   string
	body   map[string]any
	gets   int
}

// mockRepoPatchServer answers GET /api/proxies/{name} (the confirmation
// probe) and records the PATCH the command issues.
func mockRepoPatchServer(t *testing.T, existing repoItem) (*httptest.Server, *capturedRepoPatch) {
	t.Helper()
	got := &capturedRepoPatch{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			got.gets++
			_ = json.NewEncoder(w).Encode(map[string]any{"repository": existing})
			return
		}
		got.method, got.path = r.Method, r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got.body)
		_ = json.NewEncoder(w).Encode(map[string]any{"repository": existing})
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func newRepoToggleCmd(t *testing.T, use string) (*cobra.Command, *strings.Builder) {
	t.Helper()
	out := &strings.Builder{}
	cmd := &cobra.Command{Use: use, SilenceUsage: true}
	cmd.Flags().Bool("yes", false, "")
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("output", "", "")
	cmd.SetOut(out)
	cmd.SetErr(out)
	return cmd, out
}

// TestRepoDisable_SendsEnabledFalse is the wire contract: the server's
// PATCH /api/proxies/{name} with {"enabled":false} arm (internal/server/
// proxies_api.go) is what takes a repository out of service.
func TestRepoDisable_SendsEnabledFalse(t *testing.T) {
	srv, got := mockRepoPatchServer(t, repoItem{Name: "npm-proxy", Format: "npm", Enabled: false})
	authedAgainst(t, srv)

	cmd, out := newRepoToggleCmd(t, "disable")
	if err := cmd.Flags().Set("yes", "true"); err != nil {
		t.Fatalf("set yes: %v", err)
	}
	if err := runRepoSetEnabled(false)(cmd, []string{"npm-proxy"}); err != nil {
		t.Fatalf("disable: %v", err)
	}

	if got.method != http.MethodPatch {
		t.Errorf("method = %q, want PATCH", got.method)
	}
	if got.path != "/api/proxies/npm-proxy" {
		t.Errorf("path = %q, want /api/proxies/npm-proxy", got.path)
	}
	if got.body["enabled"] != false {
		t.Errorf("body = %v, want enabled:false", got.body)
	}
	// --yes must fire no probe: a script that has already decided should not
	// pay a round trip (confirm_target.go).
	if got.gets != 0 {
		t.Errorf("--yes issued %d confirmation probe(s); it must issue none", got.gets)
	}
	if !strings.Contains(out.String(), "repo enable") {
		t.Errorf("the operator was not told how to undo it:\n%s", out.String())
	}
}

// TestRepoEnable_SendsEnabledTrue is the reverse verb, and the reason disable
// is safe to offer at all: the row is intact and the name still owned.
func TestRepoEnable_SendsEnabledTrue(t *testing.T) {
	srv, got := mockRepoPatchServer(t, repoItem{Name: "npm-proxy", Format: "npm", Enabled: true})
	authedAgainst(t, srv)

	cmd, _ := newRepoToggleCmd(t, "enable")
	if err := runRepoSetEnabled(true)(cmd, []string{"npm-proxy"}); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if got.method != http.MethodPatch || got.body["enabled"] != true {
		t.Errorf("enable sent %s %v, want PATCH enabled:true", got.method, got.body)
	}
	// enable is not gated, so it must not probe or prompt either.
	if got.gets != 0 {
		t.Errorf("enable issued %d probe(s); it is not a gated verb", got.gets)
	}
}

// TestRepoDisable_PromptNamesTheRepository: the confirmation is the operator's
// last chance to notice they typed the wrong name, so it has to say which
// repository goes dark and what breaks.
func TestRepoDisable_PromptNamesTheRepository(t *testing.T) {
	srv, got := mockRepoPatchServer(t, repoItem{Name: "npm-proxy", Format: "npm", Enabled: true})
	authedAgainst(t, srv)
	prompt := recordPrompt(t) // answers "no"

	cmd, out := newRepoToggleCmd(t, "disable")
	if err := runRepoSetEnabled(false)(cmd, []string{"npm-proxy"}); err != nil {
		t.Fatalf("declining must not error: %v", err)
	}

	if !strings.Contains(*prompt, "npm-proxy") {
		t.Errorf("prompt = %q, want the repository named", *prompt)
	}
	if !strings.Contains(*prompt, "start failing") {
		t.Errorf("prompt = %q, want the consequence spelled out", *prompt)
	}
	if got.method != "" {
		t.Errorf("declining the prompt still issued %s %s", got.method, got.path)
	}
	if !strings.Contains(out.String(), "Aborted") {
		t.Errorf("declining must say so:\n%s", out.String())
	}
}

// TestRepoDisable_RefusesWithoutYesOffATTY: off a terminal there is no prompt
// to answer, so prompting would print "Aborted." at rc=0 and hide the no-op.
// Same rule every other gated verb follows.
func TestRepoDisable_RefusesWithoutYesOffATTY(t *testing.T) {
	srv, got := mockRepoPatchServer(t, repoItem{Name: "npm-proxy", Format: "npm", Enabled: true})
	authedAgainst(t, srv)
	prevTTY := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = prevTTY })

	cmd, _ := newRepoToggleCmd(t, "disable")
	err := runRepoSetEnabled(false)(cmd, []string{"npm-proxy"})
	if err == nil {
		t.Fatal("a non-TTY disable without --yes must refuse, not silently succeed")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Errorf("error = %q, want it to name --yes", err)
	}
	if got.method != "" {
		t.Errorf("the refusal still issued %s %s", got.method, got.path)
	}
}

// TestRepoDisable_UnknownRepositoryFailsBeforeThePrompt: a typo'd name must
// produce the server's own 404 rather than a confirmation for something that
// does not exist.
func TestRepoDisable_UnknownRepositoryFailsBeforeThePrompt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"CHW-4001","message":"repository not found"}}`))
	}))
	t.Cleanup(srv.Close)
	authedAgainst(t, srv)
	forbidPrompt(t)

	cmd, _ := newRepoToggleCmd(t, "disable")
	if err := runRepoSetEnabled(false)(cmd, []string{"nmp-proxy"}); err == nil {
		t.Fatal("disabling a repository that does not exist must fail")
	}
}

// TestRepoHasNoDeleteVerb keeps L-18's rejection in force. If someone adds
// `repo delete` later, they have to come here and read why it was refused.
func TestRepoHasNoDeleteVerb(t *testing.T) {
	for _, c := range repoCmd.Commands() {
		switch c.Name() {
		case "delete", "rm", "remove", "destroy":
			t.Fatalf("`repo %s` exists. L-18 rejected deleting a repository: ten tables carry a bare "+
				"`repository TEXT` with no FK, so re-adopting the name inherits the old index entries, "+
				"cached verdicts and package permissions — a credential regains access to a repository "+
				"an admin believes was destroyed. Use `repo disable` instead.", c.Name())
		}
	}
}

// TestRepoStatusShowsTheEnabledFlag: a disable verb whose effect is invisible
// is half a feature. `list` and `status` must both be able to report it.
func TestRepoStatusShowsTheEnabledFlag(t *testing.T) {
	srv, _ := mockRepoPatchServer(t, repoItem{Name: "npm-proxy", Format: "npm", Enabled: false})
	authedAgainst(t, srv)

	cmd, out := newRepoToggleCmd(t, "status")
	if err := runRepoStatus(cmd, []string{"npm-proxy"}); err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out.String(), "disabled") {
		t.Errorf("`repo status` does not surface the disabled state:\n%s", out.String())
	}
}
