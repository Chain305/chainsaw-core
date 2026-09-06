// Package featureflags is a thin wrapper around the posthog-go SDK's
// feature-flag evaluation. Exposed to the rest of the server so handlers
// can gate behavior on a flag without caring about the PostHog client's
// exact API surface.
//
// Today we use feature flags for:
//   - Experiments (onboarding_v2 — 10% rollout test)
//   - Kill-switches (proxy_sampling_aggressive — drop Tier C to 0.1%)
//   - Staged rollouts (mcp_suggestions_enabled)
//
// The primary entrypoint is Eval(ctx, flag, user, org, defaultVal). The
// resolution order (env-override → SetOverride → PostHog → default) is
// documented on Eval. IsEnabled is retained as a no-context alias that
// delegates to Eval; new call sites should prefer Eval.
package featureflags

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/posthog/posthog-go"
)

// envOverridePrefix is the unified env-var prefix for forcing any flag's
// value at the process level. Resolution order in Eval() is:
//
//  1. CHAINSAW_FF_<UPPER_FLAG_NAME>  (env override — always wins)
//  2. PostHog evaluation (per-org via the "organization" group)
//  3. defaultValue
//
// The prefix makes every flag-related env var greppable as a single set,
// replacing the previous ad-hoc CHAINSAW_<NAME>_ENABLED scheme that
// scattered toggles across the codebase. Legacy env-var names continue
// to work via per-call backwards-compat shims (see init_server.go and
// provider_installscripts.go for examples).
const envOverridePrefix = "CHAINSAW_FF_"

// envOverrideKey turns a flag key ("risk_threshold_overrides") into its
// uppercase env-var name ("CHAINSAW_FF_RISK_THRESHOLD_OVERRIDES").
func envOverrideKey(flag string) string {
	return envOverridePrefix + strings.ToUpper(flag)
}

// parseEnvBool returns (value, present). Truthy values: 1/true/yes/on
// (case-insensitive). Anything else returns (false, true) — explicitly
// set to off. Empty/unset returns (false, false).
func parseEnvBool(raw string) (bool, bool) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return false, false
	}
	switch v {
	case "1", "true", "yes", "on":
		return true, true
	default:
		return false, true
	}
}

// Client evaluates flags for identified users. Nil-safe — a nil Client
// returns the defaultValue for every call, so callers don't branch on
// "flag system not wired up yet".
type Client struct {
	client posthog.Client

	// overrides lets tests pin a flag to a fixed value without
	// reaching for a PostHog stub. Only honored when the underlying
	// client is nil OR returns an error; production flag evaluation
	// is always preferred when wired. Keys: flag name. Values: forced
	// boolean.
	overrides map[string]bool
}

// SetOverride pins the given flag to value for this Client. Intended
// for tests that need to exercise a flag-gated handler without
// standing up a full PostHog setup. Safe on a nil sentinel — calling
// SetOverride on a nil receiver is a no-op (tests should construct a
// non-nil Client via New() first).
func (c *Client) SetOverride(flag string, value bool) {
	if c == nil {
		return
	}
	if c.overrides == nil {
		c.overrides = map[string]bool{}
	}
	c.overrides[flag] = value
}

// New constructs a Client from env. Reads:
//
//	POSTHOG_API_KEY           — project ingestion key (required)
//	POSTHOG_HOST              — optional self-hosted endpoint
//	POSTHOG_PERSONAL_API_KEY  — optional. When set, the PostHog SDK
//	                            does local flag evaluation (in-memory
//	                            map polled every ~30s) instead of a
//	                            decide() HTTP call per IsEnabled. This
//	                            makes the hot path effectively free
//	                            and is the reason call sites no longer
//	                            need to use env vars to skip PostHog.
//
// Returns a nil-safe sentinel when POSTHOG_API_KEY is missing so the
// rest of the server can call Eval/IsEnabled unconditionally.
func New() *Client {
	key := strings.TrimSpace(os.Getenv("POSTHOG_API_KEY"))
	if key == "" {
		return &Client{}
	}
	cfg := posthog.Config{}
	if endpoint := strings.TrimSpace(os.Getenv("POSTHOG_HOST")); endpoint != "" {
		cfg.Endpoint = endpoint
	}
	if personal := strings.TrimSpace(os.Getenv("POSTHOG_PERSONAL_API_KEY")); personal != "" {
		cfg.PersonalApiKey = personal
	}
	c, err := posthog.NewWithConfig(key, cfg)
	if err != nil {
		return &Client{}
	}
	return &Client{client: c}
}

// Default returns the process-wide flag client, constructed lazily on
// first use from env (see New for the variables it reads). Use this
// from sites that need flag evaluation but don't already have a
// *Client wired in — e.g. providers in internal/intelligence — so that
// the whole process shares one PostHog SDK connection rather than
// spinning up a fresh one per package.
//
// Tests that need to override flag values should still construct an
// explicit *Client via NewWithClient and pass it in; Default()'s
// instance is shared and not safe to mutate from a test.
func Default() *Client {
	defaultOnce.Do(func() {
		defaultClient = New()
	})
	return defaultClient
}

var (
	defaultOnce   sync.Once
	defaultClient *Client
)

// Eval is the unified flag evaluation entrypoint. Resolution order:
//
//  1. Env-var override (CHAINSAW_FF_<UPPER_FLAG>) — always wins. Lets
//     operators force a flag on/off without PostHog (air-gapped
//     installs, kill switches, debugging) and lets tests pin
//     behaviour without standing up a PostHog stub.
//  2. SetOverride() value (test-only convenience).
//  3. PostHog evaluation, scoped to the "organization" group when
//     orgID is non-empty. With POSTHOG_PERSONAL_API_KEY set this is
//     a local in-memory lookup; without it, a decide() HTTP call.
//  4. defaultValue.
//
// Safe on a nil receiver — returns defaultValue (after honouring an
// env override if present).
//
// Prefer Eval over the older IsEnabled signature for new call sites:
// it accepts ctx (for future cancellation propagation) and gives ops
// a uniform escape hatch for any flag.
//
// Eval CANNOT tell you which of those four steps produced the answer —
// steps 1-3 and step 4 return an indistinguishable bool. Any caller
// gating a security control on a flag must use EvalStrict instead and
// decide explicitly what to do when the provider never answered.
func (c *Client) Eval(ctx context.Context, flag, userID, orgID string, defaultValue bool) bool {
	v, _ := c.EvalStrict(ctx, flag, userID, orgID, defaultValue)
	return v
}

// Sentinel errors returned by EvalStrict. Each one names exactly ONE of
// the branches on which Eval falls back to defaultValue, so a caller can
// tell "the flag provider said no" apart from "we never got an answer".
//
// Eval collapses all six into a bare defaultValue, which is fine for a
// rollout toggle and actively dangerous for a security control: a
// control that is ON only while a third-party SaaS is reachable silently
// turns itself OFF during an outage, an ad-block, or a DNS blip, with
// nothing in the response to distinguish that from normal operation.
//
// Use errors.Is against these. The three "we could not evaluate"
// branches are deliberately NOT merged:
//
//   - ErrProviderUnreachable — PostHog IS configured and we asked it,
//     and the ask failed (transport error, 5xx, malformed payload).
//     This is the only branch a security-gating caller should read as
//     "unknown, assume the strict posture". It cannot fire on an install
//     that never configured PostHog.
//   - ErrProviderNotConfigured — no PostHog client at all. This is EVERY
//     self-hosted install (POSTHOG_API_KEY unset ⇒ New() returns the
//     sentinel with a nil inner client) and every nil *Client. Nothing
//     is broken; the org simply has no flag provider, and there is
//     nothing to be unavailable. Treating it as unreachable would flip
//     every fail-closed gate ON for every self-hosted install — a
//     product change wearing a bug fix's clothes.
//   - ErrNoIdentity — neither a userID nor an orgID, so there is no
//     entity to bucket. Bucketing "anonymous" globally yields a stable
//     but arbitrary answer, which is worse than admitting we have none.
//
// ErrFlagKeyEmpty is a programmer error (empty key), surfaced rather
// than silently defaulted so it shows up in a test instead of in prod.
var (
	ErrFlagKeyEmpty          = errors.New("featureflags: empty flag key")
	ErrProviderNotConfigured = errors.New("featureflags: no flag provider configured")
	ErrNoIdentity            = errors.New("featureflags: no user or org identity to evaluate against")
	ErrProviderUnreachable   = errors.New("featureflags: flag provider unreachable")
)

// EvalStrict is Eval with the reason attached. It returns the same
// boolean Eval does — callers that want today's behaviour can ignore the
// error entirely — plus a sentinel naming which branch produced it.
//
// A nil error means the value is AUTHORITATIVE: it came from an env
// override, a SetOverride, or an actual provider answer. A non-nil error
// means the returned bool is just defaultValue and the provider never
// spoke; the sentinel says why, and only ErrProviderUnreachable means
// "something is broken right now".
//
// Resolution order is identical to Eval's, and deliberately so — this is
// the same function with its silence made legible, not a second policy:
//
//  1. CHAINSAW_FF_<UPPER_FLAG> env override        → (value, nil)
//  2. SetOverride (test-only)                      → (value, nil)
//  3. PostHog evaluation                           → (value, nil)
//  4. defaultValue                                 → (default, sentinel)
//
// Safe on a nil receiver.
func (c *Client) EvalStrict(_ context.Context, flag, userID, orgID string, defaultValue bool) (bool, error) {
	if flag == "" {
		return defaultValue, ErrFlagKeyEmpty
	}
	// Env override always wins, including on nil receivers. Authoritative:
	// an operator said so out loud, and recordEnvOverride leaves the trace.
	if raw, ok := os.LookupEnv(envOverrideKey(flag)); ok {
		if v, present := parseEnvBool(raw); present {
			recordEnvOverride(envOverrideKey(flag), raw)
			return v, nil
		}
	}
	if c == nil {
		return defaultValue, ErrProviderNotConfigured
	}
	if v, ok := c.overrides[flag]; ok {
		return v, nil
	}
	// Distinct from the unreachable branch below: there is no provider to
	// be unreachable. See the ErrProviderNotConfigured doc above.
	if c.client == nil {
		return defaultValue, ErrProviderNotConfigured
	}
	distinct := "user:" + userID
	if userID == "" {
		distinct = "org:" + orgID
	}
	if distinct == "user:" || distinct == "org:" {
		return defaultValue, ErrNoIdentity
	}
	payload := posthog.FeatureFlagPayload{
		Key:        flag,
		DistinctId: distinct,
	}
	if orgID != "" {
		payload.Groups = posthog.Groups{"organization": orgID}
	}
	result, err := c.client.IsFeatureEnabled(payload)
	if err != nil {
		return defaultValue, fmt.Errorf("%w: %v", ErrProviderUnreachable, err)
	}
	switch v := result.(type) {
	case bool:
		return v, nil
	case string:
		return strings.EqualFold(v, "true") || v == "1", nil
	default:
		// The SDK answered with something we cannot interpret. We asked a
		// configured provider and did not get a usable answer, so this is
		// an unreachable-class failure, not a flag-is-off.
		return defaultValue, fmt.Errorf("%w: unexpected value type %T", ErrProviderUnreachable, result)
	}
}

// Unavailable reports whether err means "a configured flag provider was
// asked and did not answer". It is FALSE for a missing provider, a
// missing identity, and an empty key — none of those are outages.
//
// Security-gating callers should fail closed on this and only this.
func Unavailable(err error) bool {
	return errors.Is(err, ErrProviderUnreachable)
}

// IsEnabled is the original (pre-Eval) signature retained for the
// existing call sites that don't have a ctx in scope. Delegates to
// Eval with context.Background(); behaves identically.
func (c *Client) IsEnabled(flag, userID, orgID string, defaultValue bool) bool {
	return c.Eval(context.Background(), flag, userID, orgID, defaultValue)
}

// NewWithClient wraps an arbitrary posthog.Client implementation. Used
// by tests that need to drive flag evaluation deterministically (the
// production constructor New() reads from env). Pass nil to get the
// same default-returning sentinel that New() produces when POSTHOG_API_KEY
// is unset.
func NewWithClient(client posthog.Client) *Client {
	return &Client{client: client}
}

// Close shuts down the underlying PostHog client. Safe on nil/sentinel.
func (c *Client) Close() {
	if c == nil || c.client == nil {
		return
	}
	_ = c.client.Close()
}

// observedEnvOverrides records every CHAINSAW_FF_* override this process
// has actually consulted.
//
// The override returns before every logging path in Eval and "always
// wins" over the flag provider, including on a nil receiver — so until
// this existed, a security control could be forced off process-wide with
// no trace anywhere. That is a worse property than the fail-open the
// override was added to work around.
//
// Recording on read rather than scanning the environment is deliberate:
// it captures exactly the flags that influenced a decision, and it does
// not invite a reader to assume an unread variable had an effect.
var (
	observedEnvOverridesMu sync.RWMutex
	observedEnvOverrides   = map[string]string{}
)

func recordEnvOverride(env, raw string) {
	observedEnvOverridesMu.Lock()
	defer observedEnvOverridesMu.Unlock()
	observedEnvOverrides[env] = raw
}

// ObservedEnvOverrides returns a copy of the CHAINSAW_FF_* overrides this
// process has consulted, for the startup enforcement-posture inventory.
func ObservedEnvOverrides() map[string]string {
	observedEnvOverridesMu.RLock()
	defer observedEnvOverridesMu.RUnlock()
	out := make(map[string]string, len(observedEnvOverrides))
	for k, v := range observedEnvOverrides {
		out[k] = v
	}
	return out
}
