package hook

// bun_test.go pins the Wave U bun wire shape. Background:
//   Wave S live-verify (qa/smoke-evidence/20260523-wave-S-deep/
//   21_bun_block.txt + 22_bun_two_field_probe.txt) proved bun 1.3.12
//   silently ignores ALL bunfig.toml [install.registry] shapes for
//   authenticated chainsaw proxies. bun's npm-compat layer DOES honor
//   .npmrc, so chainsaw install-hook bun was switched to write .npmrc
//   with the same base64(client_id:secret) :_auth shape renderNpm uses
//   on the server config-snippet path.
//
// These tests are the regression guard: if anyone reverts to bunfig.toml
// or drops the base64 _auth line, CI screams.

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func setupBun(t *testing.T) (bunManager, string) {
	t.Helper()
	dir := t.TempDir()
	// bun's config path resolution for ScopeUser uses os.UserHomeDir, which
	// is hard to override portably; use ScopeProject (which reads cwd) for
	// the unit-level tests. ScopeUser is covered by the path-shape test.
	t.Chdir(dir)
	return bunManager{}, filepath.Join(dir, ".npmrc")
}

func TestBunConfigPathIsNpmrcAcrossScopes(t *testing.T) {
	// Wave U regression: bun wires .npmrc — NEVER bunfig.toml — because
	// bun silently ignores authenticated bunfig.toml registries.
	m := bunManager{}
	for _, scope := range []Scope{ScopeUser, ScopeProject} {
		t.Run(string(scope), func(t *testing.T) {
			if scope == ScopeProject {
				t.Chdir(t.TempDir())
			}
			p, err := m.ConfigPathForScope(scope)
			if err != nil {
				t.Fatalf("ConfigPathForScope(%q): %v", scope, err)
			}
			base := filepath.Base(p)
			wantBase := ".npmrc"
			if scope == ScopeProject {
				wantBase = ".npmrc"
			}
			if base != wantBase {
				t.Errorf("scope=%q ConfigPath base=%q, want %q (regression: bun must wire .npmrc, not bunfig.toml)", scope, base, wantBase)
			}
			if strings.HasSuffix(p, "bunfig.toml") || strings.HasSuffix(p, ".bunfig.toml") {
				t.Errorf("scope=%q ConfigPath=%q — bun MUST NOT write bunfig.toml (Wave U: silently ignored by bun)", scope, p)
			}
		})
	}
	// System scope path varies across OS; spot-check Unix.
	if runtime.GOOS != "windows" {
		p, err := m.ConfigPathForScope(ScopeSystem)
		if err != nil {
			t.Fatalf("ConfigPathForScope(system): %v", err)
		}
		if p != "/etc/npmrc" {
			t.Errorf("system scope path=%q, want /etc/npmrc", p)
		}
	}
}

func TestBunWireIntoEmptyEmitsCommentedTemplate(t *testing.T) {
	// Empty ServerURL → commented-out template that explains why we use
	// .npmrc instead of bunfig.toml. The Wave U preamble MUST be present.
	m, path := setupBun(t)
	if err := m.Wire(WireOpts{Scope: ScopeProject}); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	body := string(data)
	if !hasSentinel(data) {
		t.Errorf("file missing sentinel block: %s", body)
	}
	if !strings.Contains(body, "Wave U") || !strings.Contains(body, "npm-compat") {
		t.Errorf("template missing Wave U preamble explaining the .npmrc switch: %s", body)
	}
	// MUST NOT silently emit any TOML — that's the shape bun ignores.
	if strings.Contains(body, "[install.registry]") {
		t.Errorf("template still emits [install.registry] (TOML shape bun ignores): %s", body)
	}
}

func TestBunWireWithServerEmitsNpmrcShape(t *testing.T) {
	// With a real ServerURL we emit the npm gold-standard shape:
	//   registry=<base>/<org-path>/npmjs/
	//   //host/path/npmjs/:_auth=<base64 or placeholder>
	//   //host/path/npmjs/:always-auth=true
	m, path := setupBun(t)
	opts := WireOpts{
		Scope:     ScopeProject,
		ServerURL: "https://proxy.example.com/",
		OrgSlug:   "acme",
	}
	if err := m.Wire(opts); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	body := string(data)
	wantRegistry := "registry=https://proxy.example.com/chainproxy/repository/@acme/npmjs/"
	if !strings.Contains(body, wantRegistry) {
		t.Errorf("missing registry line %q in body:\n%s", wantRegistry, body)
	}
	// :_auth line on the no-creds path is a literal placeholder; when no
	// creds passed we get "<base64(client_id:secret)>" — but the host/path
	// prefix MUST be present.
	if !strings.Contains(body, "//proxy.example.com/chainproxy/repository/@acme/npmjs/:_auth=") {
		t.Errorf("missing :_auth line (host/path prefix):\n%s", body)
	}
	if !strings.Contains(body, "//proxy.example.com/chainproxy/repository/@acme/npmjs/:always-auth=true") {
		t.Errorf("missing :always-auth=true line:\n%s", body)
	}
	// No TOML — bun ignores it.
	if strings.Contains(body, "[install.registry]") {
		t.Errorf("body still contains [install.registry] (TOML shape bun ignores):\n%s", body)
	}
}

func TestBunWireWithCredsEmitsBase64Auth(t *testing.T) {
	// When credentials are passed, :_auth must carry
	// base64(client_id:secret) — same shape as renderNpm in
	// internal/server/server_configsnippets.go. This is the on-the-wire
	// invariant that makes bun's npm-compat layer authenticate against
	// chain305 instead of falling back to registry.npmjs.org.
	m, path := setupBun(t)
	const id = "smoke-tier1a-verify"
	const secret = "tier1aSecret-z9q7"
	opts := WireOpts{
		Scope:       ScopeProject,
		ServerURL:   "https://proxy.example.com/",
		OrgSlug:     "acme",
		Credentials: id + ":" + secret,
	}
	if err := m.Wire(opts); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	wantB64 := base64.StdEncoding.EncodeToString([]byte(id + ":" + secret))
	if !strings.Contains(string(data), ":_auth="+wantB64) {
		t.Errorf("missing :_auth=%s line in body:\n%s", wantB64, data)
	}
	// Cleartext secret MUST NOT be inlined — defense in depth against
	// accidental shoulder-surfing leaks (npm spec requires base64).
	if strings.Contains(string(data), ":_auth="+id+":"+secret) {
		t.Errorf("body inlines cleartext client_id:secret in :_auth — must be base64:\n%s", data)
	}
}

func TestBunWireRejectsBadCreds(t *testing.T) {
	m, _ := setupBun(t)
	err := m.Wire(WireOpts{
		Scope:       ScopeProject,
		ServerURL:   "https://proxy.example.com/",
		OrgSlug:     "acme",
		Credentials: "no-colon-here",
	})
	if err == nil || !strings.Contains(err.Error(), "credentials") {
		t.Errorf("expected credentials error, got %v", err)
	}
}

func TestBunWireRejectsControlCharURL(t *testing.T) {
	m, path := setupBun(t)
	err := m.Wire(WireOpts{Scope: ScopeProject, ServerURL: "https://foo.example/%0Aevil"})
	if err == nil || !strings.Contains(err.Error(), "invalid server URL") {
		t.Errorf("expected invalid server URL error, got %v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("expected .npmrc to be absent after rejected Wire, stat err = %v", statErr)
	}
}

func TestBunUnwireAfterWire(t *testing.T) {
	m, path := setupBun(t)
	user := "save-exact=true\n"
	if err := os.WriteFile(path, []byte(user), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := m.Wire(WireOpts{Scope: ScopeProject}); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	if err := m.Unwire(ScopeProject); err != nil {
		t.Fatalf("Unwire: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if hasSentinel(data) {
		t.Errorf("sentinel still present after unwire: %s", data)
	}
	if !strings.Contains(string(data), "save-exact=true") {
		t.Errorf("user content lost after unwire: %s", data)
	}
}

func TestBunUnwireNoSentinelReturnsErrNotWired(t *testing.T) {
	m, _ := setupBun(t)
	if err := m.Unwire(ScopeProject); !errors.Is(err, ErrNotWired) {
		t.Errorf("empty file Unwire error = %v, want ErrNotWired", err)
	}
}
