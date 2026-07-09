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
func (c *Client) Eval(_ context.Context, flag, userID, orgID string, defaultValue bool) bool {
	if flag == "" {
		return defaultValue
	}
	// Env override always wins, including on nil receivers.
	if raw, ok := os.LookupEnv(envOverrideKey(flag)); ok {
		if v, present := parseEnvBool(raw); present {
			return v
		}
	}
	if c == nil {
		return defaultValue
	}
	if v, ok := c.overrides[flag]; ok {
		return v
	}
	if c.client == nil {
		return defaultValue
	}
	distinct := "user:" + userID
	if userID == "" {
		distinct = "org:" + orgID
	}
	if distinct == "user:" || distinct == "org:" {
		return defaultValue
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
		return defaultValue
	}
	switch v := result.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true") || v == "1"
	default:
		return defaultValue
	}
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
