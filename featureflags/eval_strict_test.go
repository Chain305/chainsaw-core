package featureflags

import (
	"context"
	"errors"
	"testing"

	"github.com/posthog/posthog-go"
)

// stubClient drives EvalStrict's provider branch deterministically.
// Only IsFeatureEnabled is exercised; every other method is a stub so
// the type satisfies posthog.Client.
type stubClient struct {
	posthog.Client
	result any
	err    error
}

func (s stubClient) IsFeatureEnabled(posthog.FeatureFlagPayload) (any, error) {
	return s.result, s.err
}

func (s stubClient) Close() error { return nil }

// TestEvalStrict_ClassifiesEverySilentBranch is the core of the fix.
//
// Eval returns defaultValue from six different places and a caller could
// not tell which — so a security control gated on a flag with
// defaultValue=false silently switched itself OFF whenever the flag
// provider had a bad day, and the response looked exactly like an org
// that had never enabled it.
//
// Each case below names one branch and asserts BOTH the value and the
// classification. The classification is what callers key on.
func TestEvalStrict_ClassifiesEverySilentBranch(t *testing.T) {
	provider := NewWithClient(stubClient{result: true})

	cases := []struct {
		name      string
		client    *Client
		flag      string
		userID    string
		orgID     string
		env       [2]string
		def       bool
		wantValue bool
		wantErr   error
		// wantUnavailable is the ONLY signal a fail-closed caller acts
		// on. It must be false for every branch except a real provider
		// failure — most importantly for the no-provider branch, which
		// is every self-hosted install.
		wantUnavailable bool
	}{
		{
			name:      "empty flag key is a programmer error, not a flag state",
			client:    provider,
			flag:      "",
			userID:    "u",
			orgID:     "o",
			def:       false,
			wantValue: false,
			wantErr:   ErrFlagKeyEmpty,
		},
		{
			name:      "env override is authoritative",
			client:    provider,
			flag:      "gate",
			userID:    "u",
			orgID:     "o",
			env:       [2]string{"CHAINSAW_FF_GATE", "true"},
			def:       false,
			wantValue: true,
			wantErr:   nil,
		},
		{
			name:      "env override is authoritative on a nil receiver too",
			client:    nil,
			flag:      "gate",
			userID:    "u",
			orgID:     "o",
			env:       [2]string{"CHAINSAW_FF_GATE", "true"},
			def:       false,
			wantValue: true,
			wantErr:   nil,
		},
		{
			name:      "nil client is not-configured, NOT unreachable",
			client:    nil,
			flag:      "gate",
			userID:    "u",
			orgID:     "o",
			def:       false,
			wantValue: false,
			wantErr:   ErrProviderNotConfigured,
		},
		{
			name: "nil inner client (every self-hosted install) is not-configured, NOT unreachable",
			// This is the branch the fix most depends on getting right.
			// POSTHOG_API_KEY unset ⇒ New() hands back this sentinel. If
			// it classified as unreachable, a fail-closed caller would
			// turn its gate ON for every self-hosted install — a product
			// change, not a bug fix.
			client:    NewWithClient(nil),
			flag:      "gate",
			userID:    "u",
			orgID:     "o",
			def:       false,
			wantValue: false,
			wantErr:   ErrProviderNotConfigured,
		},
		{
			name:      "no user and no org has nothing to bucket",
			client:    provider,
			flag:      "gate",
			userID:    "",
			orgID:     "",
			def:       false,
			wantValue: false,
			wantErr:   ErrNoIdentity,
		},
		{
			name:            "provider error is unreachable",
			client:          NewWithClient(stubClient{err: errors.New("connection refused")}),
			flag:            "gate",
			userID:          "u",
			orgID:           "o",
			def:             false,
			wantValue:       false,
			wantErr:         ErrProviderUnreachable,
			wantUnavailable: true,
		},
		{
			name:            "uninterpretable provider answer is unreachable, not flag-off",
			client:          NewWithClient(stubClient{result: 42}),
			flag:            "gate",
			userID:          "u",
			orgID:           "o",
			def:             false,
			wantValue:       false,
			wantErr:         ErrProviderUnreachable,
			wantUnavailable: true,
		},
		{
			name:      "provider says false — authoritative, an outage must not look like this",
			client:    NewWithClient(stubClient{result: false}),
			flag:      "gate",
			userID:    "u",
			orgID:     "o",
			def:       true,
			wantValue: false,
			wantErr:   nil,
		},
		{
			name:      "provider says true",
			client:    provider,
			flag:      "gate",
			userID:    "u",
			orgID:     "o",
			def:       false,
			wantValue: true,
			wantErr:   nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env[0] != "" {
				t.Setenv(tc.env[0], tc.env[1])
			}
			got, err := tc.client.EvalStrict(context.Background(), tc.flag, tc.userID, tc.orgID, tc.def)
			if got != tc.wantValue {
				t.Errorf("value = %v, want %v", got, tc.wantValue)
			}
			if tc.wantErr == nil {
				if err != nil {
					t.Errorf("err = %v, want nil (answer must be authoritative)", err)
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want errors.Is(..., %v)", err, tc.wantErr)
			}
			if Unavailable(err) != tc.wantUnavailable {
				t.Errorf("Unavailable(%v) = %v, want %v", err, Unavailable(err), tc.wantUnavailable)
			}
		})
	}
}

// TestEval_MatchesEvalStrictValue — Eval is now EvalStrict with the
// reason discarded, so every existing caller must see byte-identical
// behaviour. If these ever diverge, one of the two has grown a policy
// the other does not have.
func TestEval_MatchesEvalStrictValue(t *testing.T) {
	clients := map[string]*Client{
		"nil":               nil,
		"no-inner":          NewWithClient(nil),
		"provider-true":     NewWithClient(stubClient{result: true}),
		"provider-false":    NewWithClient(stubClient{result: false}),
		"provider-erroring": NewWithClient(stubClient{err: errors.New("boom")}),
	}
	for name, c := range clients {
		for _, def := range []bool{false, true} {
			strict, _ := c.EvalStrict(context.Background(), "gate", "u", "o", def)
			if plain := c.Eval(context.Background(), "gate", "u", "o", def); plain != strict {
				t.Errorf("%s default=%v: Eval=%v EvalStrict=%v", name, def, plain, strict)
			}
		}
	}
}

// TestUnavailable_IgnoresNonProviderFailures — a fail-closed caller must
// not be tripped by a missing provider or a missing identity. Those are
// normal states, not outages.
func TestUnavailable_IgnoresNonProviderFailures(t *testing.T) {
	for _, err := range []error{nil, ErrFlagKeyEmpty, ErrProviderNotConfigured, ErrNoIdentity} {
		if Unavailable(err) {
			t.Errorf("Unavailable(%v) = true, want false", err)
		}
	}
	if !Unavailable(ErrProviderUnreachable) {
		t.Error("Unavailable(ErrProviderUnreachable) = false, want true")
	}
}

// TestEnvOverridesInEffect_SeesOverridesBeforeAnyFlagIsRead pins the defect
// production surfaced on 2026-09-06.
//
// The startup enforcement-posture line read ObservedEnvOverrides, which is
// populated on read. At boot nothing has read a flag yet, so on a pod
// carrying EIGHT CHAINSAW_FF_* overrides — including
// CHAINSAW_FF_EXCEPTION_APPROVAL_GATING, which gates the two-person
// exception approval — the line logged "no enforcement-weakening
// environment variables set". It said the opposite of the truth at exactly
// the moment an operator reads it.
func TestEnvOverridesInEffect_SeesOverridesBeforeAnyFlagIsRead(t *testing.T) {
	// The real production environment shape, verbatim.
	environ := []string{
		"PATH=/usr/bin",
		"CHAINSAW_FF_CONNECTORS_WIZARD=1",
		"CHAINSAW_FF_ARTIFACT_UPLOAD_API=1",
		"CHAINSAW_FF_POLICY_GRACE_MODE=true",
		"CHAINSAW_FF_EXCEPTION_APPROVAL_GATING=true",
		"CHAINSAW_FF_BILLY_EXECUTE=true",
		"CHAINSAW_FF_CONNECTORS_SLACK_OAUTH=0",
		"CHAINSAW_DATABASE_URL=postgres://redacted",
	}

	got := EnvOverridesInEffect(environ)

	if len(got) != 6 {
		t.Fatalf("EnvOverridesInEffect found %d overrides, want 6: %v", len(got), got)
	}
	if _, ok := got["CHAINSAW_FF_EXCEPTION_APPROVAL_GATING"]; !ok {
		t.Error("the flag gating two-person exception approval was not reported")
	}
	// An explicitly-off override still overrides, and must be reported.
	if v, ok := got["CHAINSAW_FF_CONNECTORS_SLACK_OAUTH"]; !ok || v != "0" {
		t.Errorf("an explicitly-off override was dropped: %q ok=%v", v, ok)
	}
	if _, ok := got["CHAINSAW_DATABASE_URL"]; ok {
		t.Error("a non-flag variable was reported as a flag override")
	}
}

// TestEnvOverridesInEffect_MatchesEvalSemantics is the negative control, and
// it corrected my own assumption while writing it.
//
// parseEnvBool returns (value, present), where ANY non-truthy string is
// (false, true) — "explicitly set to off". So a value Eval cannot read as
// true is not ignored by Eval, it is honoured as an override that forces
// the flag OFF. Forcing a security flag off is the case this inventory
// exists to surface, so it must be reported, not filtered.
//
// Only an EMPTY value is (false, false), i.e. not an override at all.
func TestEnvOverridesInEffect_MatchesEvalSemantics(t *testing.T) {
	got := EnvOverridesInEffect([]string{
		"CHAINSAW_FF_GARBAGE=banana", // Eval honours this as force-OFF
		"CHAINSAW_FF_REAL=true",
		"CHAINSAW_FF_EMPTY=", // not an override
	})

	if _, ok := got["CHAINSAW_FF_GARBAGE"]; !ok {
		t.Error("a force-OFF override was filtered out; forcing a security flag off " +
			"is exactly what this inventory exists to surface")
	}
	if _, ok := got["CHAINSAW_FF_REAL"]; !ok {
		t.Errorf("the truthy override was dropped: %v", got)
	}
	if _, ok := got["CHAINSAW_FF_EMPTY"]; ok {
		t.Error("an empty value is not an override and must not be reported")
	}
	if len(got) != 2 {
		t.Errorf("want exactly the two overrides, got %v", got)
	}

	// Cross-check against Eval itself, so this test cannot drift from the
	// behaviour it claims to describe.
	t.Setenv("CHAINSAW_FF_GARBAGE", "banana")
	if v := (&Client{}).Eval(context.Background(), "garbage", "u", "o", true); v {
		t.Error("Eval did not honour the non-truthy override as force-OFF; " +
			"this test's premise no longer holds")
	}
}
