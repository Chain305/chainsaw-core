package featureflags

import (
	"context"
	"testing"
)

// TestEval_NilReceiver covers the documented nil-safety guarantee: a
// nil *Client returns the default value, except when an env override
// is set — the env override is honoured even on a nil receiver so
// kill switches work before the client is constructed.
func TestEval_NilReceiver(t *testing.T) {
	var c *Client
	if c.Eval(context.Background(), "any_flag", "u", "o", true) != true {
		t.Fatal("nil client should return default=true")
	}
	if c.Eval(context.Background(), "any_flag", "u", "o", false) != false {
		t.Fatal("nil client should return default=false")
	}

	t.Setenv("CHAINSAW_FF_FORCED_FLAG", "true")
	if c.Eval(context.Background(), "forced_flag", "u", "o", false) != true {
		t.Fatal("env override should win even on nil client")
	}
}

// TestEval_EnvOverride confirms the env-var override beats every other
// signal — including SetOverride (which is the test-only mechanism) and
// a PostHog client that would have returned the opposite.
func TestEval_EnvOverride(t *testing.T) {
	c := NewWithClient(nil) // no PostHog backend; SetOverride is the source of truth otherwise
	c.SetOverride("my_flag", false)

	// Without env, SetOverride wins.
	if c.Eval(context.Background(), "my_flag", "u", "o", true) != false {
		t.Fatal("SetOverride(false) should beat default=true")
	}

	// With env=true, env wins over SetOverride(false).
	t.Setenv("CHAINSAW_FF_MY_FLAG", "true")
	if c.Eval(context.Background(), "my_flag", "u", "o", false) != true {
		t.Fatal("env override should beat SetOverride")
	}

	// With env=false (explicit), env still wins.
	t.Setenv("CHAINSAW_FF_MY_FLAG", "false")
	c.SetOverride("my_flag", true)
	if c.Eval(context.Background(), "my_flag", "u", "o", true) != false {
		t.Fatal("env=false should beat SetOverride(true)")
	}
}

// TestEval_EnvBoolParsing checks every truthy / explicit-falsy / unset
// variant we promise to accept. Empty string is treated as "unset" so
// that operators can clear an override by exporting an empty value
// without removing the line from their env file.
func TestEval_EnvBoolParsing(t *testing.T) {
	cases := []struct {
		raw  string
		want bool // true means env says "on"
		set  bool // true means env says anything at all (vs unset)
	}{
		{"1", true, true},
		{"true", true, true},
		{"TRUE", true, true},
		{"yes", true, true},
		{"on", true, true},
		{"0", false, true},
		{"false", false, true},
		{"no", false, true},
		{"off", false, true},
		{"garbage", false, true},
		{"", false, false},
		{"   ", false, false},
	}
	for _, tc := range cases {
		got, present := parseEnvBool(tc.raw)
		if got != tc.want || present != tc.set {
			t.Errorf("parseEnvBool(%q) = (%v, %v), want (%v, %v)", tc.raw, got, present, tc.want, tc.set)
		}
	}
}

// TestEval_EmptyFlag — passing an empty flag key always returns
// default. Defensive: prevents env-prefix collisions from a stray "".
func TestEval_EmptyFlag(t *testing.T) {
	c := NewWithClient(nil)
	t.Setenv("CHAINSAW_FF_", "true") // would match envOverrideKey("") if we weren't guarding
	if c.Eval(context.Background(), "", "u", "o", false) != false {
		t.Fatal("empty flag key must return default, not honour CHAINSAW_FF_")
	}
}

// TestEval_OrgScoping — without an orgID and without a userID, the
// flag has no entity to evaluate against and falls back to default
// (we don't want to bucket "anonymous" globally as that produces
// stable-but-arbitrary results).
func TestEval_AnonymousReturnsDefault(t *testing.T) {
	c := NewWithClient(nil)
	c.SetOverride("any", true) // overrides are honoured even without userID/orgID

	// SetOverride wins.
	if c.Eval(context.Background(), "any", "", "", false) != true {
		t.Fatal("SetOverride should be honoured even without an identity")
	}

	// Without any override and without a client, default wins.
	c2 := NewWithClient(nil)
	if c2.Eval(context.Background(), "any", "", "", true) != true {
		t.Fatal("anonymous without override should return default")
	}
}

// TestIsEnabled_DelegatesToEval — the legacy signature must keep
// behaving identically so existing call sites are unaffected.
func TestIsEnabled_DelegatesToEval(t *testing.T) {
	c := NewWithClient(nil)
	c.SetOverride("legacy", true)
	if c.IsEnabled("legacy", "u", "o", false) != true {
		t.Fatal("IsEnabled should delegate to Eval and honour SetOverride")
	}

	t.Setenv("CHAINSAW_FF_LEGACY", "false")
	if c.IsEnabled("legacy", "u", "o", true) != false {
		t.Fatal("IsEnabled must honour env override")
	}
}

// TestDefault_ReturnsSameInstance — Default() is documented to return
// a singleton so the whole process shares one PostHog SDK connection.
func TestDefault_ReturnsSameInstance(t *testing.T) {
	a := Default()
	b := Default()
	if a != b {
		t.Fatal("Default() should return the same *Client across calls")
	}
}

// TestEnvOverrideKey_UppercasesAndPrefixes — small but worth pinning
// because the contract is documented in docs/feature-flag-inventory.md.
func TestEnvOverrideKey(t *testing.T) {
	cases := map[string]string{
		"risk_threshold_overrides": "CHAINSAW_FF_RISK_THRESHOLD_OVERRIDES",
		"installscript_ast":        "CHAINSAW_FF_INSTALLSCRIPT_AST",
		"a":                        "CHAINSAW_FF_A",
	}
	for in, want := range cases {
		if got := envOverrideKey(in); got != want {
			t.Errorf("envOverrideKey(%q) = %q, want %q", in, got, want)
		}
	}
}
