package cli

// Tests for `chainsaw cargo-credentials` (Cargo credential-provider).
// The protocol surface is small enough that a few hand-rolled fixtures
// give us full coverage: hello handshake, get success, get with bad
// creds, login/logout rejection, malformed JSON, EOF.
//
// We never spawn real cargo here — `cargo fetch` is exercised in the
// smoke evidence under qa/smoke-evidence/. These tests pin the protocol
// contract so a refactor that breaks cargo's parser shows up as a unit
// failure long before we discover it via 401s in the field.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// TestCargoCredentials_FastPathReadsYAMLConfig pins the Wave S fix: the
// `chainsaw --cargo-plugin` fast-path in Execute() must call initConfig()
// before runCargoCredsProtocol, otherwise viper never reads the YAML
// config file and the YAML credential-source branch in
// lookupCargoCredentials is silently dead. Before the fix, `cargo
// fetch` returned "no client_credential available" even when
// ~/.chainsaw/config.yaml contained a valid cargo_credentials key.
//
// We exercise the inner pieces — initConfig() + lookupCargoCredentials()
// — directly, because Execute() itself calls os.Exit on error. As long
// as those two are wired in the fast-path (which the code change in
// root.go now guarantees), the cargo-plugin protocol will find the
// YAML credential.
func TestCargoCredentials_FastPathReadsYAMLConfig(t *testing.T) {
	dir := withIsolatedConfigHome(t)
	withFileCredStore(t)
	// Env + keyring intentionally empty so YAML is the only source.
	t.Setenv("CHAINSAW_CARGO_CREDENTIALS", "")
	t.Setenv("CHAINSAW_CLIENT_CREDENTIALS", "")

	cfg := "cargo_credentials: yaml-id:yaml-secret\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// This is the exact pair Execute()'s fast-path now invokes.
	initConfig()
	creds, source := lookupCargoCredentials()

	if creds != "yaml-id:yaml-secret" {
		t.Fatalf("lookupCargoCredentials returned creds=%q, want yaml-id:yaml-secret (YAML branch not wired into fast-path?)", creds)
	}
	if !strings.Contains(source, "cargo_credentials") {
		t.Fatalf("source=%q does not name the YAML branch", source)
	}
}

func TestCargoCredentials_HelloHandshake(t *testing.T) {
	withFileCredStore(t)
	t.Setenv("CHAINSAW_CARGO_CREDENTIALS", "")
	t.Setenv("CHAINSAW_CLIENT_CREDENTIALS", "")
	out, _ := runProtocol(t, "")
	first := firstJSONLine(t, out)
	if v, ok := first["v"]; !ok || !equalsIntSlice(v, []any{float64(1)}) {
		t.Fatalf("expected hello {\"v\":[1]}, got %v", first)
	}
}

func TestCargoCredentials_GetWithEnvCred(t *testing.T) {
	withFileCredStore(t)
	t.Setenv("CHAINSAW_CARGO_CREDENTIALS", "alice-ci:s3cret-shh")
	t.Setenv("CHAINSAW_CLIENT_CREDENTIALS", "")
	req := `{"v":1,"kind":"get","operation":"read","registry":{"index-url":"sparse+https://example/index/"}}` + "\n"
	out, _ := runProtocol(t, req)
	lines := jsonLines(t, out)
	if len(lines) < 2 {
		t.Fatalf("expected hello + response, got %d lines: %q", len(lines), out)
	}
	resp := lines[1]
	ok, ok2 := resp["Ok"].(map[string]any)
	if !ok2 {
		t.Fatalf("expected Ok envelope, got: %v", resp)
	}
	tok, _ := ok["token"].(string)
	if !strings.HasPrefix(tok, "Basic ") {
		t.Fatalf("expected Basic token, got %q", tok)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(tok, "Basic "))
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if string(decoded) != "alice-ci:s3cret-shh" {
		t.Fatalf("expected decoded creds alice-ci:s3cret-shh, got %q", decoded)
	}
	if cache, _ := ok["cache"].(string); cache != "session" {
		t.Errorf("expected cache=session, got %q", cache)
	}
	if opind, _ := ok["operation_independent"].(bool); !opind {
		t.Error("expected operation_independent=true (publish reuses the same Basic auth)")
	}
}

func TestCargoCredentials_GetWithGenericClientCreds(t *testing.T) {
	// CHAINSAW_CARGO_CREDENTIALS takes precedence — but if absent,
	// CHAINSAW_CLIENT_CREDENTIALS (the cross-ecosystem env var) supplies
	// the secret. This is the common case in CI where one secret feeds
	// every package manager.
	withFileCredStore(t)
	t.Setenv("CHAINSAW_CARGO_CREDENTIALS", "")
	t.Setenv("CHAINSAW_CLIENT_CREDENTIALS", "shared-ci:abc-123")
	req := `{"v":1,"kind":"get","operation":"read","registry":{"index-url":"sparse+https://example/index/"}}` + "\n"
	out, _ := runProtocol(t, req)
	lines := jsonLines(t, out)
	resp := lines[1]
	envelope, ok := resp["Ok"].(map[string]any)
	if !ok {
		t.Fatalf("expected Ok envelope, got: %v (full output: %s)", resp, out)
	}
	tok, _ := envelope["token"].(string)
	dec, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(tok, "Basic "))
	if string(dec) != "shared-ci:abc-123" {
		t.Fatalf("expected decoded creds shared-ci:abc-123, got %q", dec)
	}
}

func TestCargoCredentials_GetWithKeyring(t *testing.T) {
	// Pure-keyring path: no env, no YAML, just credstore.
	withFileCredStore(t)
	t.Setenv("CHAINSAW_CARGO_CREDENTIALS", "")
	t.Setenv("CHAINSAW_CLIENT_CREDENTIALS", "")
	viper.Reset()
	viper.Set("server_url", "https://chain305.com/chainproxy")
	if err := credStore().Set(credService, cargoCredsKeyringAccount("https://chain305.com/chainproxy"), "ring-id:ring-secret"); err != nil {
		t.Fatalf("seed keyring: %v", err)
	}
	req := `{"v":1,"kind":"get","operation":"read","registry":{"index-url":"sparse+https://example/index/"}}` + "\n"
	out, _ := runProtocol(t, req)
	lines := jsonLines(t, out)
	resp := lines[1]
	envelope, ok := resp["Ok"].(map[string]any)
	if !ok {
		t.Fatalf("expected Ok envelope; got %v (output: %s)", resp, out)
	}
	tok, _ := envelope["token"].(string)
	dec, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(tok, "Basic "))
	if string(dec) != "ring-id:ring-secret" {
		t.Fatalf("expected creds from keyring, got %q", dec)
	}
}

func TestCargoCredentials_GetWithoutAnyCredentialErrors(t *testing.T) {
	// All sources empty → defensive error message naming every source
	// we tried. This message is the user's only debugging breadcrumb,
	// so we assert on its contents.
	withFileCredStore(t)
	t.Setenv("CHAINSAW_CARGO_CREDENTIALS", "")
	t.Setenv("CHAINSAW_CLIENT_CREDENTIALS", "")
	viper.Reset()
	req := `{"v":1,"kind":"get","operation":"read","registry":{"index-url":"sparse+https://example/index/"}}` + "\n"
	out, _ := runProtocol(t, req)
	lines := jsonLines(t, out)
	if len(lines) < 2 {
		t.Fatalf("expected hello + error, got %d lines", len(lines))
	}
	errResp, ok := lines[1]["Err"].(map[string]any)
	if !ok {
		t.Fatalf("expected Err envelope, got %v", lines[1])
	}
	if kind, _ := errResp["kind"].(string); kind != "other" {
		t.Errorf("expected kind=other, got %q", kind)
	}
	msg, _ := errResp["message"].(string)
	for _, want := range []string{
		"CHAINSAW_CARGO_CREDENTIALS",
		"CHAINSAW_CLIENT_CREDENTIALS",
		"OS keyring",
		"cargo-credentials store",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q: %s", want, msg)
		}
	}
}

func TestCargoCredentials_MalformedCredentialErrors(t *testing.T) {
	withFileCredStore(t)
	// No colon → not a client_id:client_secret pair.
	t.Setenv("CHAINSAW_CARGO_CREDENTIALS", "garbage-no-colon")
	t.Setenv("CHAINSAW_CLIENT_CREDENTIALS", "")
	req := `{"v":1,"kind":"get","operation":"read","registry":{"index-url":"sparse+https://example/index/"}}` + "\n"
	out, _ := runProtocol(t, req)
	lines := jsonLines(t, out)
	errResp, ok := lines[1]["Err"].(map[string]any)
	if !ok {
		t.Fatalf("expected Err envelope, got %v", lines[1])
	}
	msg, _ := errResp["message"].(string)
	if !strings.Contains(msg, "client_id:client_secret") {
		t.Errorf("expected explanation about format, got %q", msg)
	}
}

func TestCargoCredentials_LoginLogoutRejected(t *testing.T) {
	// "login" and "logout" must NOT silently succeed — we don't mint
	// tokens via cargo. operation-not-supported is the canonical kind.
	withFileCredStore(t)
	t.Setenv("CHAINSAW_CARGO_CREDENTIALS", "id:secret")
	t.Setenv("CHAINSAW_CLIENT_CREDENTIALS", "")
	for _, kind := range []string{"login", "logout"} {
		req := `{"v":1,"kind":"` + kind + `","registry":{"index-url":"sparse+https://example/index/"}}` + "\n"
		out, _ := runProtocol(t, req)
		lines := jsonLines(t, out)
		errResp, ok := lines[1]["Err"].(map[string]any)
		if !ok {
			t.Fatalf("[%s] expected Err envelope, got %v", kind, lines[1])
		}
		if k, _ := errResp["kind"].(string); k != "operation-not-supported" {
			t.Errorf("[%s] expected operation-not-supported, got %q", kind, k)
		}
	}
}

func TestCargoCredentials_MalformedJSONIsIsolated(t *testing.T) {
	// One bad line should not poison subsequent requests. Cargo can in
	// principle send multiple requests on the same stdin (the protocol
	// doesn't pin one-shot semantics) so we must keep reading.
	withFileCredStore(t)
	t.Setenv("CHAINSAW_CARGO_CREDENTIALS", "id:secret")
	t.Setenv("CHAINSAW_CLIENT_CREDENTIALS", "")
	in := "{not valid json\n" +
		`{"v":1,"kind":"get","operation":"read","registry":{"index-url":"sparse+https://example/index/"}}` + "\n"
	out, _ := runProtocol(t, in)
	lines := jsonLines(t, out)
	if len(lines) < 3 {
		t.Fatalf("expected hello + err + ok, got %d lines: %s", len(lines), out)
	}
	if _, ok := lines[1]["Err"]; !ok {
		t.Errorf("expected first response to be Err for bad JSON, got %v", lines[1])
	}
	if _, ok := lines[2]["Ok"]; !ok {
		t.Errorf("expected second response to be Ok after recovery, got %v", lines[2])
	}
}

func TestSplitCargoCreds_Parses(t *testing.T) {
	cases := []struct {
		in     string
		id     string
		secret string
		ok     bool
	}{
		{"a:b", "a", "b", true},
		{" a : b ", "a", "b", true},                           // whitespace trimmed
		{"id:sec:with:colons", "id", "sec:with:colons", true}, // secret may contain colons
		{"a:", "", "", false},
		{":b", "", "", false},
		{"no-colon", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		id, secret, ok := splitCargoCreds(c.in)
		if ok != c.ok || id != c.id || secret != c.secret {
			t.Errorf("splitCargoCreds(%q) = (%q, %q, %v); want (%q, %q, %v)",
				c.in, id, secret, ok, c.id, c.secret, c.ok)
		}
	}
}

func TestCargoCredentialsAccountIncludesServer(t *testing.T) {
	// Account naming convention pins to "cargo-credentials@<server>"
	// so multi-profile users can store distinct creds per Chainsaw.
	if got := cargoCredsKeyringAccount("https://chain305.com/chainproxy"); got != "cargo-credentials@https://chain305.com/chainproxy" {
		t.Errorf("unexpected account: %q", got)
	}
	if got := cargoCredsKeyringAccount(""); got != "cargo-credentials" {
		t.Errorf("expected bare account when no server, got %q", got)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func runProtocol(t *testing.T, stdin string) (stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	if err := runCargoCredsProtocol(cmd, strings.NewReader(stdin), &out, &errBuf); err != nil {
		t.Fatalf("protocol returned error: %v", err)
	}
	return out.String(), errBuf.String()
}

func jsonLines(t *testing.T, s string) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, raw := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatalf("decode %q: %v", raw, err)
		}
		lines = append(lines, m)
	}
	return lines
}

func firstJSONLine(t *testing.T, s string) map[string]any {
	t.Helper()
	lines := jsonLines(t, s)
	if len(lines) == 0 {
		t.Fatalf("no JSON lines in output: %q", s)
	}
	return lines[0]
}

func equalsIntSlice(got any, want []any) bool {
	gotSlice, ok := got.([]any)
	if !ok {
		return false
	}
	if len(gotSlice) != len(want) {
		return false
	}
	for i := range gotSlice {
		if gotSlice[i] != want[i] {
			return false
		}
	}
	return true
}
