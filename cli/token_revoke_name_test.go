package cli

// token_revoke_name_test.go — `token revoke` took an id where its sibling
// takes a name.
//
// `auth client delete` resolves a label by list-and-filter (auth_client.go),
// but `token revoke` concatenated its argument straight into the DELETE path.
// So a name copied out of `chainsaw token list` came back "CHW-4925: api key
// not found" — a real token, the name the CLI itself printed, and an error
// that reads as though the token does not exist.
//
// The property that matters most here is the ambiguity refusal: CLI keys are
// named cli:<host>@<date>, so two live tokens sharing a name is an ordinary
// Tuesday, and revoking an arbitrary one of them is a mistake nobody notices
// until something stops authenticating.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

type capturedRevoke struct {
	lists   int
	deleted []string
	dryRuns []string
}

// mockTokenRevokeServer serves the listing and records DELETEs, separating
// the dry-run probe from the real revoke by the header the CLI sets.
func mockTokenRevokeServer(t *testing.T, listing []tokenItem) (*httptest.Server, *capturedRevoke) {
	t.Helper()
	got := &capturedRevoke{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/api-keys", func(w http.ResponseWriter, r *http.Request) {
		got.lists++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"api_keys": listing})
	})
	mux.HandleFunc("/api/api-keys/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/api-keys/")
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get(DryRunHeader) == "true" {
			got.dryRuns = append(got.dryRuns, id)
			var target tokenItem
			for _, k := range listing {
				if k.ID == id {
					target = k
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"dry_run": true, "would": "revoke", "target": target,
			})
			return
		}
		got.deleted = append(got.deleted, id)
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, got
}

func newTokenRevokeCmd(t *testing.T) (*cobra.Command, *strings.Builder) {
	t.Helper()
	out := &strings.Builder{}
	cmd := &cobra.Command{Use: "revoke", SilenceUsage: true}
	cmd.Flags().Bool("yes", false, "")
	cmd.Flags().Bool("dry-run", false, "")
	cmd.SetOut(out)
	cmd.SetErr(out)
	return cmd, out
}

var twoLiveCLIKeys = []tokenItem{
	{ID: "ak-morning", Name: "cli:laptop@2026-08-22", Prefix: "morning", Active: true},
	{ID: "ak-evening", Name: "cli:laptop@2026-08-22", Prefix: "evening", Active: true},
	{ID: "ak-ci", Name: "ci-deploy", Prefix: "cipfx", Active: true},
}

// TestTokenRevoke_ByIDCostsNoExtraRoundTrip is the no-regression half: an
// argument in the id shape must behave exactly as it did before name
// resolution existed, including not paying for a listing.
func TestTokenRevoke_ByIDCostsNoExtraRoundTrip(t *testing.T) {
	srv, got := mockTokenRevokeServer(t, twoLiveCLIKeys)
	authedAgainst(t, srv)

	cmd, _ := newTokenRevokeCmd(t)
	if err := cmd.Flags().Set("yes", "true"); err != nil {
		t.Fatalf("set yes: %v", err)
	}
	if err := runTokenRevoke(cmd, []string{"ak-ci"}); err != nil {
		t.Fatalf("revoke by id: %v", err)
	}
	if got.lists != 0 {
		t.Errorf("revoking by id issued %d listing(s); an id needs no resolution", got.lists)
	}
	if len(got.deleted) != 1 || got.deleted[0] != "ak-ci" {
		t.Errorf("DELETEd %v, want [ak-ci]", got.deleted)
	}
}

// TestTokenRevoke_ByNameResolvesToTheID is the defect itself.
func TestTokenRevoke_ByNameResolvesToTheID(t *testing.T) {
	srv, got := mockTokenRevokeServer(t, twoLiveCLIKeys)
	authedAgainst(t, srv)

	cmd, out := newTokenRevokeCmd(t)
	if err := cmd.Flags().Set("yes", "true"); err != nil {
		t.Fatalf("set yes: %v", err)
	}
	if err := runTokenRevoke(cmd, []string{"ci-deploy"}); err != nil {
		t.Fatalf("revoke by name: %v", err)
	}
	if len(got.deleted) != 1 || got.deleted[0] != "ak-ci" {
		t.Fatalf("DELETEd %v, want [ak-ci] — the name must resolve to its id", got.deleted)
	}
	if !strings.Contains(out.String(), "ak-ci") {
		t.Errorf("the confirmation line should name the id that was revoked:\n%s", out.String())
	}
}

// TestTokenRevoke_AmbiguousNameIsRefused: two live tokens, one name. Picking
// one is not an option — the error lists the ids so the operator can.
func TestTokenRevoke_AmbiguousNameIsRefused(t *testing.T) {
	srv, got := mockTokenRevokeServer(t, twoLiveCLIKeys)
	authedAgainst(t, srv)

	cmd, _ := newTokenRevokeCmd(t)
	if err := cmd.Flags().Set("yes", "true"); err != nil {
		t.Fatalf("set yes: %v", err)
	}
	err := runTokenRevoke(cmd, []string{"cli:laptop@2026-08-22"})
	if err == nil {
		t.Fatal("an ambiguous name must be refused, not resolved to an arbitrary token")
	}
	for _, id := range []string{"ak-morning", "ak-evening"} {
		if !strings.Contains(err.Error(), id) {
			t.Errorf("error must list %s so the operator can disambiguate: %v", id, err)
		}
	}
	if len(got.deleted) != 0 {
		t.Fatalf("an ambiguous name still revoked %v", got.deleted)
	}
}

// TestTokenRevoke_AmbiguityIgnoresRevokedNamesakes: a name reused after an
// earlier token was revoked is NOT ambiguous — there is one live token and
// exactly one thing the operator can have meant.
func TestTokenRevoke_AmbiguityIgnoresRevokedNamesakes(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	srv, got := mockTokenRevokeServer(t, []tokenItem{
		{ID: "ak-old", Name: "cli:laptop@2026-08-22", Prefix: "oldpfx", RevokedAt: &past},
		{ID: "ak-new", Name: "cli:laptop@2026-08-22", Prefix: "newpfx", Active: true},
	})
	authedAgainst(t, srv)

	cmd, _ := newTokenRevokeCmd(t)
	if err := cmd.Flags().Set("yes", "true"); err != nil {
		t.Fatalf("set yes: %v", err)
	}
	if err := runTokenRevoke(cmd, []string{"cli:laptop@2026-08-22"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(got.deleted) != 1 || got.deleted[0] != "ak-new" {
		t.Fatalf("DELETEd %v, want [ak-new] — only the live namesake counts", got.deleted)
	}
}

// TestTokenRevoke_UnknownNameFallsThroughToTheServer: an argument the listing
// cannot place is handed over unchanged, so a typo still produces the server's
// own not-found rather than a CLI-invented one — and an id from a seeded row
// that does not match the "ak-" shape is not swallowed.
func TestTokenRevoke_UnknownNameFallsThroughToTheServer(t *testing.T) {
	srv, got := mockTokenRevokeServer(t, twoLiveCLIKeys)
	authedAgainst(t, srv)

	cmd, _ := newTokenRevokeCmd(t)
	if err := cmd.Flags().Set("yes", "true"); err != nil {
		t.Fatalf("set yes: %v", err)
	}
	if err := runTokenRevoke(cmd, []string{"legacy-uuid-row"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(got.deleted) != 1 || got.deleted[0] != "legacy-uuid-row" {
		t.Fatalf("DELETEd %v, want the argument passed through verbatim", got.deleted)
	}
}

// TestTokenRevoke_NameResolvesBeforeTheConfirmationProbe pins the v0.20.9
// ordering (L-30): the dry-run probe runs BEFORE the prompt, so a typo fails
// before the y rather than after it. Name resolution must slot in ahead of the
// probe, not between the probe and the prompt.
func TestTokenRevoke_NameResolvesBeforeTheConfirmationProbe(t *testing.T) {
	srv, got := mockTokenRevokeServer(t, twoLiveCLIKeys)
	authedAgainst(t, srv)
	prompt := recordPrompt(t) // answers "no"

	cmd, _ := newTokenRevokeCmd(t)
	if err := runTokenRevoke(cmd, []string{"ci-deploy"}); err != nil {
		t.Fatalf("declining must not error: %v", err)
	}
	if len(got.dryRuns) != 1 || got.dryRuns[0] != "ak-ci" {
		t.Fatalf("dry-run probes = %v, want [ak-ci] before the prompt", got.dryRuns)
	}
	if !strings.Contains(*prompt, "ci-deploy") {
		t.Errorf("prompt = %q, want the resolved token named", *prompt)
	}
	if len(got.deleted) != 0 {
		t.Errorf("declining still revoked %v", got.deleted)
	}
}

// TestTokenRevoke_DryRunPreviewsTheResolvedToken: --dry-run must preview the
// row the real revoke would hit, which means resolving the name first.
func TestTokenRevoke_DryRunPreviewsTheResolvedToken(t *testing.T) {
	srv, got := mockTokenRevokeServer(t, twoLiveCLIKeys)
	authedAgainst(t, srv)

	cmd, out := newTokenRevokeCmd(t)
	if err := cmd.Flags().Set("dry-run", "true"); err != nil {
		t.Fatalf("set dry-run: %v", err)
	}
	if err := runTokenRevoke(cmd, []string{"ci-deploy"}); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if len(got.deleted) != 0 {
		t.Fatalf("--dry-run revoked %v", got.deleted)
	}
	if !strings.Contains(out.String(), "ak-ci") {
		t.Errorf("preview does not name the resolved token:\n%s", out.String())
	}
}
