package cli

// install_hook_credentials_test.go covers L-07: uninstall-hook must revoke
// the client_credential install-hook minted, and must NOT revoke anything
// else.
//
// The QA evidence this exists for: client_credentials went 0 → 1 on
// `install-hook`, and stayed 1 after a "clean" `uninstall-hook`. Nothing on
// disk recorded the client_id, so nothing could revoke it.
//
// Every test here is hermetic — an httptest.Server stands in for
// /api/clients, and withIsolatedConfigHome redirects the ledger into a temp
// dir. No DB, no network.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/chain305/chainsaw-core/cli/hook"
)

// clientAPIRecorder records every request the CLI makes to /api/clients so a
// test can assert on what was (or was not) revoked.
type clientAPIRecorder struct {
	deletes []string
	all     []string
}

// withRevokeServer stands up a fake /api/clients surface. status is the code
// returned for DELETE (204 = success).
func withRevokeServer(t *testing.T, status int) (*clientAPIRecorder, string) {
	t.Helper()
	rec := &clientAPIRecorder{}
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		rec.all = append(rec.all, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/clients/") {
			rec.deletes = append(rec.deletes, strings.TrimPrefix(r.URL.Path, "/api/clients/"))
			if status == http.StatusNoContent {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{"code": "CHW-TEST", "message": "nope"},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	return rec, srv.URL
}

// withLedgerEnv isolates the config home (so hook_credentials.json lands in a
// temp dir) and points the CLI at server with a token.
func withLedgerEnv(t *testing.T, server, token string) {
	t.Helper()
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	viper.Set("server_url", server)
	if token != "" {
		viper.Set("token", token)
	}
	// resolveScope prompts on a TTY; keep every test on the scripted path.
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = prev })
}

// wireManager writes a real chainsaw block for the manager, so Unwire has
// something to remove.
func wireManager(t *testing.T, name, server, creds string) hook.Manager {
	t.Helper()
	m, err := hook.ByName(name)
	if err != nil {
		t.Fatalf("ByName(%q): %v", name, err)
	}
	if err := m.Wire(hook.WireOpts{
		ChainsawBinary: "chainsaw",
		ServerURL:      server,
		Credentials:    creds,
		OrgSlug:        "acme",
		Scope:          hook.ScopeUser,
	}); err != nil {
		t.Fatalf("wire %s: %v", name, err)
	}
	return m
}

func runUninstall(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := newUninstallHookCmd()
	cmd.SetArgs(args)
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	err := cmd.Execute()
	return out.String(), errb.String(), err
}

func ledgerRecords(t *testing.T) []hookCredentialRecord {
	t.Helper()
	l, err := loadHookCredentialLedger()
	if err != nil {
		t.Fatalf("load ledger: %v", err)
	}
	return l.Records
}

// TestUninstallHookRevokesTheCredentialItMinted is the headline case: one
// manager, one minted credential, uninstall must DELETE it server-side and
// drop the ledger entry.
func TestUninstallHookRevokesTheCredentialItMinted(t *testing.T) {
	npmrc, _, _ := withHookEnv(t)
	rec, server := withRevokeServer(t, http.StatusNoContent)
	withLedgerEnv(t, server, "test-token")

	wireManager(t, "npm", server, "cli-host-abc123:s3cret")
	if err := recordMintedHookCredential("cli-host-abc123", server, "npm", hook.ScopeUser); err != nil {
		t.Fatalf("record: %v", err)
	}

	out, errb, err := runUninstall(t, "npm")
	if err != nil {
		t.Fatalf("uninstall-hook npm: %v\nstderr: %s", err, errb)
	}

	if len(rec.deletes) != 1 || rec.deletes[0] != "cli-host-abc123" {
		t.Fatalf("expected exactly one DELETE /api/clients/cli-host-abc123, got %v", rec.deletes)
	}
	if !strings.Contains(out, "revoked client_credential cli-host-abc123") {
		t.Fatalf("stdout should name the revoked credential, got: %q", out)
	}
	if recs := ledgerRecords(t); len(recs) != 0 {
		t.Fatalf("ledger should be empty after a successful revoke, got %+v", recs)
	}
	// And the unwire itself still happened.
	data, _ := os.ReadFile(npmrc)
	if strings.Contains(string(data), "chainsaw-managed") {
		t.Fatalf("npmrc still has the chainsaw block: %s", data)
	}
	// The backup left behind is disclosed, because we minted for npm.
	if !strings.Contains(errb, "plaintext client_id:client_secret") {
		t.Fatalf("stderr should disclose the plaintext backups, got: %q", errb)
	}
}

// TestUninstallHookDoesNotRevokeUserSuppliedCredentials pins the structural
// guard: a --credentials pair is never ledgered, so it can never be revoked.
// The operator may well be sharing it with CI or a teammate.
func TestUninstallHookDoesNotRevokeUserSuppliedCredentials(t *testing.T) {
	_, _, _ = withHookEnv(t)
	rec, server := withRevokeServer(t, http.StatusNoContent)
	withLedgerEnv(t, server, "test-token")

	install := newInstallHookCmd()
	install.SetArgs([]string{"npm", "--credentials", "shared-ci-client:shared-secret"})
	var iout, ierr bytes.Buffer
	install.SetOut(&iout)
	install.SetErr(&ierr)
	if err := install.Execute(); err != nil {
		t.Fatalf("install-hook: %v\nstderr: %s", err, ierr.String())
	}

	if recs := ledgerRecords(t); len(recs) != 0 {
		t.Fatalf("a --credentials pair must never be ledgered, got %+v", recs)
	}

	_, errb, err := runUninstall(t, "npm")
	if err != nil {
		t.Fatalf("uninstall-hook npm: %v\nstderr: %s", err, errb)
	}
	if len(rec.deletes) != 0 {
		t.Fatalf("expected ZERO revoke calls for a user-supplied credential, got %v", rec.deletes)
	}
	for _, call := range rec.all {
		if strings.Contains(call, "/api/clients") {
			t.Fatalf("expected ZERO /api/clients requests, saw %v", rec.all)
		}
	}
}

// TestUninstallHookHoldsTheCredentialUntilTheLastManagerIsUnwired is the
// --all hazard: ONE credential is written into EVERY manager, so
// `uninstall-hook npm` must leave it live for pip.
func TestUninstallHookHoldsTheCredentialUntilTheLastManagerIsUnwired(t *testing.T) {
	_, _, _ = withHookEnv(t)
	rec, server := withRevokeServer(t, http.StatusNoContent)
	withLedgerEnv(t, server, "test-token")

	const id = "cli-host-shared"
	wireManager(t, "npm", server, id+":s3cret")
	wireManager(t, "pip", server, id+":s3cret")
	for _, name := range []string{"npm", "pip"} {
		if err := recordMintedHookCredential(id, server, name, hook.ScopeUser); err != nil {
			t.Fatalf("record %s: %v", name, err)
		}
	}
	if recs := ledgerRecords(t); len(recs) != 1 || len(recs[0].Refs) != 2 {
		t.Fatalf("want one record with two refs, got %+v", recs)
	}

	// First removal: pip still holds it. Nothing may be revoked.
	if _, errb, err := runUninstall(t, "npm"); err != nil {
		t.Fatalf("uninstall-hook npm: %v\nstderr: %s", err, errb)
	}
	if len(rec.deletes) != 0 {
		t.Fatalf("credential revoked while pip still holds it: %v", rec.deletes)
	}
	recs := ledgerRecords(t)
	if len(recs) != 1 || len(recs[0].Refs) != 1 || recs[0].Refs[0].Manager != "pip" {
		t.Fatalf("want one record left referencing pip only, got %+v", recs)
	}

	// Second removal: last ref goes, so the credential must be revoked.
	if _, errb, err := runUninstall(t, "pip"); err != nil {
		t.Fatalf("uninstall-hook pip: %v\nstderr: %s", err, errb)
	}
	if len(rec.deletes) != 1 || rec.deletes[0] != id {
		t.Fatalf("expected the credential to be revoked once the last ref went, got %v", rec.deletes)
	}
	if recs := ledgerRecords(t); len(recs) != 0 {
		t.Fatalf("ledger should be empty, got %+v", recs)
	}
}

// TestUninstallHookWithoutAuthStillUnwiresAndNamesTheLiveCredential: unwire
// must NEVER require auth. Without a token we skip the network entirely, keep
// the ledger entry, and print the exact recovery command.
func TestUninstallHookWithoutAuthStillUnwiresAndNamesTheLiveCredential(t *testing.T) {
	npmrc, _, _ := withHookEnv(t)
	rec, server := withRevokeServer(t, http.StatusNoContent)
	withLedgerEnv(t, server, "") // no token anywhere

	wireManager(t, "npm", server, "cli-host-noauth:s3cret")
	if err := recordMintedHookCredential("cli-host-noauth", server, "npm", hook.ScopeUser); err != nil {
		t.Fatalf("record: %v", err)
	}

	_, errb, err := runUninstall(t, "npm")
	if err != nil {
		t.Fatalf("uninstall-hook must not fail without auth: %v\nstderr: %s", err, errb)
	}
	data, _ := os.ReadFile(npmrc)
	if strings.Contains(string(data), "chainsaw-managed") {
		t.Fatalf("unwire did not happen: %s", data)
	}
	if len(rec.all) != 0 {
		t.Fatalf("expected NO network calls without a token, got %v", rec.all)
	}
	if !strings.Contains(errb, "chainsaw auth client delete cli-host-noauth") {
		t.Fatalf("stderr must name the exact recovery command, got: %q", errb)
	}
	recs := ledgerRecords(t)
	if len(recs) != 1 || recs[0].ClientID != "cli-host-noauth" {
		t.Fatalf("ledger entry must survive so the id stays recoverable, got %+v", recs)
	}
}

// TestUninstallHookRevokeFailureDoesNotFailTheUnwire: the config is already
// clean, so a 500 from the revoke is a warning, not a command failure.
func TestUninstallHookRevokeFailureDoesNotFailTheUnwire(t *testing.T) {
	npmrc, _, _ := withHookEnv(t)
	rec, server := withRevokeServer(t, http.StatusInternalServerError)
	withLedgerEnv(t, server, "test-token")

	wireManager(t, "npm", server, "cli-host-flaky:s3cret")
	if err := recordMintedHookCredential("cli-host-flaky", server, "npm", hook.ScopeUser); err != nil {
		t.Fatalf("record: %v", err)
	}

	_, errb, err := runUninstall(t, "npm")
	if err != nil {
		t.Fatalf("a failed revoke must not fail the command: %v\nstderr: %s", err, errb)
	}
	if len(rec.deletes) != 1 {
		t.Fatalf("expected the revoke to be attempted, got %v", rec.deletes)
	}
	data, _ := os.ReadFile(npmrc)
	if strings.Contains(string(data), "chainsaw-managed") {
		t.Fatalf("unwire did not happen: %s", data)
	}
	if !strings.Contains(errb, "could not revoke client_credential cli-host-flaky") ||
		!strings.Contains(errb, "chainsaw auth client delete cli-host-flaky") {
		t.Fatalf("stderr must warn and name the recovery command, got: %q", errb)
	}
	if recs := ledgerRecords(t); len(recs) != 1 {
		t.Fatalf("ledger entry must survive a failed revoke, got %+v", recs)
	}
}

// A 404 means somebody already deleted it. Treat as success and drop the
// entry so we stop nagging about a credential that no longer exists.
func TestUninstallHookTreatsA404AsAlreadyRevoked(t *testing.T) {
	_, _, _ = withHookEnv(t)
	_, server := withRevokeServer(t, http.StatusNotFound)
	withLedgerEnv(t, server, "test-token")

	wireManager(t, "npm", server, "cli-host-gone:s3cret")
	if err := recordMintedHookCredential("cli-host-gone", server, "npm", hook.ScopeUser); err != nil {
		t.Fatalf("record: %v", err)
	}
	if _, errb, err := runUninstall(t, "npm"); err != nil {
		t.Fatalf("uninstall-hook: %v\nstderr: %s", err, errb)
	}
	if recs := ledgerRecords(t); len(recs) != 0 {
		t.Fatalf("a 404 should drop the entry, got %+v", recs)
	}
}

// A credential minted against a DIFFERENT server must never be deleted just
// because the CLI happens to be pointed somewhere else now.
func TestUninstallHookDoesNotRevokeAcrossServers(t *testing.T) {
	_, _, _ = withHookEnv(t)
	rec, server := withRevokeServer(t, http.StatusNoContent)
	withLedgerEnv(t, server, "test-token")

	wireManager(t, "npm", server, "cli-host-elsewhere:s3cret")
	if err := recordMintedHookCredential("cli-host-elsewhere", "https://other.example", "npm", hook.ScopeUser); err != nil {
		t.Fatalf("record: %v", err)
	}
	_, errb, err := runUninstall(t, "npm")
	if err != nil {
		t.Fatalf("uninstall-hook: %v\nstderr: %s", err, errb)
	}
	if len(rec.deletes) != 0 {
		t.Fatalf("must not revoke a credential minted against another server, got %v", rec.deletes)
	}
	if !strings.Contains(errb, "was NOT revoked") {
		t.Fatalf("the skip must be visible, got: %q", errb)
	}
	if recs := ledgerRecords(t); len(recs) != 1 {
		t.Fatalf("ledger entry must survive, got %+v", recs)
	}
}

// --keep-credentials is the documented opt-out. It must leave BOTH the
// server-side credential and the ledger ref alone, so a later plain
// uninstall can still finish the job.
func TestUninstallHookKeepCredentialsOptsOut(t *testing.T) {
	_, _, _ = withHookEnv(t)
	rec, server := withRevokeServer(t, http.StatusNoContent)
	withLedgerEnv(t, server, "test-token")

	wireManager(t, "npm", server, "cli-host-keep:s3cret")
	if err := recordMintedHookCredential("cli-host-keep", server, "npm", hook.ScopeUser); err != nil {
		t.Fatalf("record: %v", err)
	}
	if _, errb, err := runUninstall(t, "npm", "--keep-credentials"); err != nil {
		t.Fatalf("uninstall-hook: %v\nstderr: %s", err, errb)
	}
	if len(rec.deletes) != 0 {
		t.Fatalf("--keep-credentials must not revoke, got %v", rec.deletes)
	}
	recs := ledgerRecords(t)
	if len(recs) != 1 || len(recs[0].Refs) != 1 {
		t.Fatalf("--keep-credentials must leave the ref in place, got %+v", recs)
	}
}

// --purge-backups deletes the timestamped copies that still hold the
// plaintext pair. It runs AFTER the unwire so the xml restore path is safe.
func TestUninstallHookPurgeBackupsDeletesThePlaintextCopies(t *testing.T) {
	npmrc, _, _ := withHookEnv(t)
	_, server := withRevokeServer(t, http.StatusNoContent)
	withLedgerEnv(t, server, "test-token")

	// Wire twice so a backup definitely exists (the first Wire has no
	// pre-existing file to copy).
	wireManager(t, "npm", server, "cli-host-purge:s3cret")
	wireManager(t, "npm", server, "cli-host-purge:s3cret")
	if err := recordMintedHookCredential("cli-host-purge", server, "npm", hook.ScopeUser); err != nil {
		t.Fatalf("record: %v", err)
	}
	before, err := hook.BackupsFor(npmManagerForTest(t), hook.ScopeUser)
	if err != nil {
		t.Fatalf("BackupsFor: %v", err)
	}
	if len(before) == 0 {
		t.Skip("no backup was produced in this environment; nothing to purge")
	}

	if _, errb, err := runUninstall(t, "npm", "--purge-backups"); err != nil {
		t.Fatalf("uninstall-hook: %v\nstderr: %s", err, errb)
	}
	after, err := hook.BackupsFor(npmManagerForTest(t), hook.ScopeUser)
	if err != nil {
		t.Fatalf("BackupsFor: %v", err)
	}
	if len(after) != 0 {
		t.Fatalf("--purge-backups left %d backups behind: %v", len(after), after)
	}
	if _, err := os.Stat(npmrc); err != nil && !os.IsNotExist(err) {
		t.Fatalf("stat npmrc: %v", err)
	}
}

func npmManagerForTest(t *testing.T) hook.Manager {
	t.Helper()
	m, err := hook.ByName("npm")
	if err != nil {
		t.Fatalf("ByName(npm): %v", err)
	}
	return m
}

// The ledger must never contain the secret — only the id. This is the
// property that makes a leaked ledger a naming problem, not a breach.
func TestHookCredentialLedgerNeverStoresTheSecret(t *testing.T) {
	withLedgerEnv(t, "https://example.test", "test-token")
	if err := recordMintedHookCredential(
		clientIDFromCredentials("cli-host-xyz:super-secret-value"),
		"https://example.test", "npm", hook.ScopeUser); err != nil {
		t.Fatalf("record: %v", err)
	}
	raw, err := os.ReadFile(hookCredentialLedgerPath())
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if strings.Contains(string(raw), "super-secret-value") {
		t.Fatalf("the ledger leaked the client secret: %s", raw)
	}
	if !strings.Contains(string(raw), "cli-host-xyz") {
		t.Fatalf("the ledger should record the client_id: %s", raw)
	}
	info, err := os.Stat(hookCredentialLedgerPath())
	if err != nil {
		t.Fatalf("stat ledger: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("ledger mode = %o, want 0600", perm)
	}
}

// Re-running install-hook mints a fresh credential; the ref must move to the
// new record so the new id is what a later uninstall revokes.
func TestRecordMintedHookCredentialMovesTheRefOnRemint(t *testing.T) {
	withLedgerEnv(t, "https://example.test", "test-token")
	const server = "https://example.test"
	if err := recordMintedHookCredential("cli-old", server, "npm", hook.ScopeUser); err != nil {
		t.Fatalf("record old: %v", err)
	}
	if err := recordMintedHookCredential("cli-new", server, "npm", hook.ScopeUser); err != nil {
		t.Fatalf("record new: %v", err)
	}
	recs := ledgerRecords(t)
	if len(recs) != 2 {
		t.Fatalf("both credentials should stay named, got %+v", recs)
	}
	byID := map[string]hookCredentialRecord{}
	for _, r := range recs {
		byID[r.ClientID] = r
	}
	if len(byID["cli-old"].Refs) != 0 {
		t.Fatalf("the old credential should hold no refs, got %+v", byID["cli-old"])
	}
	if len(byID["cli-new"].Refs) != 1 {
		t.Fatalf("the new credential should hold the npm ref, got %+v", byID["cli-new"])
	}

	found, clientID, gotServer, err := releaseHookCredentialRef("npm", hook.ScopeUser)
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if !found || clientID != "cli-new" || gotServer != server {
		t.Fatalf("release returned (%v, %q, %q), want (true, cli-new, %q)", found, clientID, gotServer, server)
	}
}
