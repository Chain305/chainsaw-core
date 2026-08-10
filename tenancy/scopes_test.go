package tenancy

import "testing"

// TestRBACScopesFlagDefaultsOff is the headline DARK guard: with the env var
// unset, the feature is OFF. Phase 1 ships in exactly this state.
func TestRBACScopesFlagDefaultsOff(t *testing.T) {
	t.Setenv(rbacScopesFlagEnv, "")
	if rbacScopesEnabled() {
		t.Fatal("CHAINSAW_RBAC_SCOPES_ENABLED must default OFF")
	}
	if RBACScopesEnabled() {
		t.Fatal("exported RBACScopesEnabled must default OFF")
	}
}

func TestRBACScopesFlagParsing(t *testing.T) {
	on := []string{"1", "true", "TRUE", "on", "On", "yes", "enable", "enabled"}
	for _, v := range on {
		t.Setenv(rbacScopesFlagEnv, v)
		if !rbacScopesEnabled() {
			t.Fatalf("value %q should enable the flag", v)
		}
	}
	off := []string{"", "0", "false", "off", "no", "disabled", "garbage", " "}
	for _, v := range off {
		t.Setenv(rbacScopesFlagEnv, v)
		if rbacScopesEnabled() {
			t.Fatalf("value %q should NOT enable the flag", v)
		}
	}
}

func TestDecodeResourceScopesSafeDefaults(t *testing.T) {
	// Empty / null / whitespace / explicit empty object → nil = UNSCOPED
	// (full org-wide access; today's behaviour). This is the compatibility
	// invariant: every existing role row (default '{}') stays unscoped.
	for _, raw := range []string{"", "   ", "{}", "  {}  "} {
		if got := DecodeResourceScopes(raw); got != nil {
			t.Fatalf("DecodeResourceScopes(%q) = %#v, want nil (unscoped)", raw, got)
		}
	}

	// A well-formed object naming only unregistered resources is unscoped:
	// unscopable resources are always org-wide.
	if got := DecodeResourceScopes(`{"policies":{"repo_ids":["r1"]}}`); got != nil {
		t.Fatalf("unregistered resource should decode to nil, got %#v", got)
	}
}

func TestDecodeResourceScopesParsesSample(t *testing.T) {
	got := DecodeResourceScopes(`{"findings":{"repo_ids":["repo-1"," repo-2 ","repo-1",""],"self":true}}`)
	if got == nil {
		t.Fatal("expected a non-nil ResourceScopes for a findings scope")
	}
	s, ok := got[ResourceFindings]
	if !ok {
		t.Fatalf("expected a findings scope, got %#v", got)
	}
	if s.IsDenyAll() {
		t.Fatal("a well-formed scope must not be deny-all")
	}
	if !s.Self {
		t.Fatal("expected self=true")
	}
	// De-duped, trimmed, empties dropped, order preserved.
	want := []string{"repo-1", "repo-2"}
	if len(s.RepoIDs) != len(want) {
		t.Fatalf("repo_ids = %#v, want %#v", s.RepoIDs, want)
	}
	for i := range want {
		if s.RepoIDs[i] != want[i] {
			t.Fatalf("repo_ids = %#v, want %#v", s.RepoIDs, want)
		}
	}
}

func TestDecodeResourceScopesUnparseableFailsClosed(t *testing.T) {
	// Present-but-malformed JSON must fail CLOSED to a deny-all sentinel for
	// every registered resource — NEVER the empty/unscoped default (which
	// would fail OPEN; plan finding 16).
	got := DecodeResourceScopes(`{"findings": this is not json`)
	if got == nil {
		t.Fatal("unparseable scopes must NOT decode to nil (that is fail-open)")
	}
	s, ok := got[ResourceFindings]
	if !ok || !s.IsDenyAll() {
		t.Fatalf("unparseable scopes must be deny-all for findings, got %#v", got)
	}
}

func TestScopableRegistry(t *testing.T) {
	if !IsScopableResource(ResourceFindings) {
		t.Fatal("findings must be a registered scopable resource")
	}
	if IsScopableResource("policies") {
		t.Fatal("policies is not scopable in Phase 1")
	}
	if len(ScopableResources()) == 0 {
		t.Fatal("expected at least one scopable resource")
	}
}

// TestFlagOffNoNewDenial is the ANTI-REGRESSION guard at the tenancy layer.
// It proves that with the feature flag OFF, the presence of a decoded
// resource scope changes NOTHING about the permission model: a permission
// that a role has today is still granted. The scope decode path can never
// strip or gate a granted permission.
//
// The identity.HasPermission counterpart (an identity carrying ResourceScopes
// still authorizes exactly as today) lives in internal/reqctx, which owns the
// Identity type; core/tenancy is the public open-core module and must not
// import the private internal packages.
func TestFlagOffNoNewDenial(t *testing.T) {
	t.Setenv(rbacScopesFlagEnv, "")
	if RBACScopesEnabled() {
		t.Fatal("precondition: flag must be off")
	}

	// A scoped role config exists in the column...
	scopes := DecodeResourceScopes(`{"findings":{"repo_ids":["only-repo-x"]}}`)
	if scopes == nil {
		t.Fatal("expected a decodable scope for the fixture")
	}

	// ...and the built-in permission model is entirely unaffected by it:
	// a member still has findings:read, exactly as today. Nothing in the
	// scope decode path can strip or gate a granted permission.
	if !RoleAllows(RoleMember, PermFindingsRead) {
		t.Fatal("member lost findings:read — scope plumbing changed permission behaviour")
	}
	perms := PermissionsForRole(RoleMember)
	if !perms[PermFindingsRead] {
		t.Fatal("PermissionsForRole changed under scope plumbing")
	}
}
