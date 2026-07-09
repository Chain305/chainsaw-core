package config

// offline.go implements the CHAINSAW_OFFLINE=1 umbrella flag — a single
// on/off switch that short-circuits every "phone home" code path at the
// server entrypoint. Tutorial 44 (air-gapped deployment) is the canonical
// reference for the intended blast radius.
//
// Resolution order for IsOffline():
//  1. CHAINSAW_OFFLINE env var (values "1", "true", "yes", "on") — ALWAYS
//     wins. An operator shouldn't have to touch the YAML to enable
//     offline mode on an existing deployment.
//  2. The `runtime.offline: true` YAML field (mirrors the env var for
//     operators who prefer declarative configs).
//  3. false (the historical default).
//
// The value of IsOffline() drives gates in:
//   - internal/trivydb : skip OCI registry pulls.
//   - internal/billy (via internal/server/billy.go) : 503 on chat endpoints.
//   - internal/telemetry : ModeDisabled overrides consent.
//   - internal/datasource : startup_sync defaults to false; periodic
//     refresh loops are suppressed.
//   - internal/server/auth_cli.go : device-code OAuth returns 503 and the
//     server refuses to boot without a fallback auth mechanism.
//   - Paddle / Postmark / Turnstile / signup : the per-env-var disables
//     remain, but the server additionally treats an offline boot as "no
//     phone-home integrations active" for logging purposes.

import (
	"os"
	"strconv"
	"strings"
)

// offlineEnvVar is the canonical environment variable operators set to
// force offline mode on an existing deployment without editing YAML.
const offlineEnvVar = "CHAINSAW_OFFLINE"

// RuntimeConfig holds cross-cutting runtime knobs that don't belong in
// any one subsystem's config. Only one knob today — Offline — but the
// block is an explicit YAML surface so the next similar flag has a
// natural home.
type RuntimeConfig struct {
	// Offline mirrors CHAINSAW_OFFLINE=1. Set to true in YAML to mark a
	// deployment as air-gapped; the env var always wins when both are
	// set. See tutorial 44 for the blast radius.
	Offline bool `yaml:"offline"`
	// AllowInsecureTLS is the global opt-in gate for honoring the
	// per-remote / per-integration `TLSInsecureSkipVerify` flag set by
	// admins on webhooks, registries, and SIEM destinations. Default
	// (false) is fail-closed: skip-verify flags are IGNORED and TLS is
	// always validated. Set via the CHAINSAW_ALLOW_INSECURE_TLS env var
	// (1/true/yes/on) to honor admin-configured bypass — intended for
	// lab/staging deployments with internal-CA destinations. Unsafe in
	// production. Mirrors the CHAINSAW_OFFLINE resolution order: env
	// var wins, then this YAML field, then false.
	AllowInsecureTLS bool `yaml:"allow_insecure_tls"`
	// IntelBundlePath is the on-disk path to the signed
	// chainsaw-intel-bundle-YYYY-MM-DD.tar.gz that ships pre-mirrored
	// snapshots of every "phone-home" data source (W4). Mirrors
	// CHAINSAW_INTEL_BUNDLE_PATH; the env var wins. See
	// docs/install/AIRGAP.md.
	IntelBundlePath string `yaml:"intel_bundle_path"`
	// OfflineFailMode controls how remote-only providers behave when
	// air-gapped: "condition-default" (per-condition fall-back —
	// historical behaviour, default), "open" (allow installs through),
	// "closed" (block installs). Mirrors CHAINSAW_OFFLINE_FAIL_MODE.
	// See docs/install/AIRGAP.md for the per-provider matrix.
	OfflineFailMode string `yaml:"offline_fail_mode"`
	// WebhookLegacyPerUserRouting restores the pre-fix per-user routing
	// path for install.blocked / install.flagged webhooks (keyed off
	// client_credentials.created_by_user_id). Default false: org-wide
	// fan-out via dispatchOrgWebhooks + TopicSecurityEvents, which is
	// the safer behaviour because security signals belong to the org,
	// not to whichever CI user created the client credential. Mirrors
	// CHAINSAW_WEBHOOK_LEGACY_PERUSER_ROUTING. Operators on a staged
	// migration set this to true to preserve legacy delivery for
	// receivers wired to specific user accounts.
	WebhookLegacyPerUserRouting bool `yaml:"webhook_legacy_peruser_routing"`
	// MalwareTestOverrides is a TEST-ONLY raw comma-separated list of
	// synthetic malicious entries injected into the in-memory
	// malware.Index at boot. Format per entry:
	//   ecosystem:package:version:malware_id[:summary]
	// Real OSV malware hits take precedence over overrides; overrides
	// only fire when the real index has no match for the queried
	// (ecosystem, package, version). Mirrors
	// CHAINSAW_TEST_MALWARE_OVERRIDES — the env var always wins. Intended
	// to live-fire the malware-feed → dispatchOrgWebhooks path on a
	// reachable package when every OSV-flagged malware target has
	// already been pulled from its upstream CDN. MUST be empty in
	// production; the server logs a loud WARN at startup when
	// non-empty.
	MalwareTestOverrides string `yaml:"malware_test_overrides"`
}

// allowInsecureTLSEnvVar is the canonical environment variable operators
// set to honor admin-configured per-destination TLSInsecureSkipVerify.
// Matches the CHAINSAW_OFFLINE pattern — env var always wins over YAML.
const allowInsecureTLSEnvVar = "CHAINSAW_ALLOW_INSECURE_TLS"

// webhookLegacyPerUserRoutingEnvVar restores the pre-fix
// install.blocked / install.flagged routing path that keyed off
// client_credentials.created_by_user_id. Default behaviour (env unset
// or unparseable, YAML field false) is org-wide fan-out via
// dispatchOrgWebhooks + TopicSecurityEvents — the safer default because
// security signals belong to the org, not to whichever CI user happened
// to create the client credential. Set CHAINSAW_WEBHOOK_LEGACY_PERUSER_ROUTING=1
// for operators who depend on the legacy per-user fan-out during a
// staged migration; see docs/TELEMETRY.md and the chain305.com 2026-05-21
// smoke for the gap this flag protects against.
const webhookLegacyPerUserRoutingEnvVar = "CHAINSAW_WEBHOOK_LEGACY_PERUSER_ROUTING"

// parseWebhookLegacyPerUserRoutingEnv mirrors parseOfflineEnv: tolerant
// bool parsing with (value, set) semantics so the YAML can decide when
// the env var is unset or unparseable.
func parseWebhookLegacyPerUserRoutingEnv() (bool, bool) {
	raw := strings.TrimSpace(os.Getenv(webhookLegacyPerUserRoutingEnvVar))
	if raw == "" {
		return false, false
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	}
	if v, err := strconv.ParseBool(raw); err == nil {
		return v, true
	}
	return false, false
}

// WebhookLegacyPerUserRouting returns the effective routing-mode for
// install.blocked / install.flagged webhook fan-out. true = legacy
// per-user routing (keyed off client_credentials.created_by_user_id);
// false (the default) = org-wide fan-out via dispatchOrgWebhooks.
// CHAINSAW_WEBHOOK_LEGACY_PERUSER_ROUTING wins; otherwise the YAML
// runtime.webhook_legacy_peruser_routing field; otherwise false. Safe on
// a nil receiver.
func (c *Config) WebhookLegacyPerUserRouting() bool {
	if v, ok := parseWebhookLegacyPerUserRoutingEnv(); ok {
		return v
	}
	if c == nil {
		return false
	}
	return c.Runtime.WebhookLegacyPerUserRouting
}

// malwareTestOverridesEnvVar names the TEST-ONLY env var that injects
// synthetic known-malicious entries into the malware.Index at server
// boot. Comma-separated entries; each entry is
// `ecosystem:package:version:malware_id[:summary]`. Real OSV malware
// hits take precedence — overrides only fire when the real index
// misses. Loud WARN at startup makes shipping a prod pod with this set
// hard to do by accident. See cmd/chainsaw-proxy/init_server.go for the
// startup log and internal/malware/index.go for the lookup wiring.
const malwareTestOverridesEnvVar = "CHAINSAW_TEST_MALWARE_OVERRIDES"

// parseMalwareTestOverridesEnv returns (raw, set): the literal env-var
// value (trimmed) plus whether the env was set to a non-empty value.
// Unlike the bool helpers we don't reinterpret the contents — parsing
// the comma-separated form lives in internal/malware so config doesn't
// take a dependency on that package.
func parseMalwareTestOverridesEnv() (string, bool) {
	raw := strings.TrimSpace(os.Getenv(malwareTestOverridesEnvVar))
	if raw == "" {
		return "", false
	}
	return raw, true
}

// MalwareTestOverrides returns the effective raw test-overrides string.
// CHAINSAW_TEST_MALWARE_OVERRIDES wins; otherwise the YAML
// runtime.malware_test_overrides field; otherwise "". Safe on a nil
// receiver. Callers (cmd/chainsaw-proxy + supplychain bootstrap) parse
// the comma-separated form via malware.ParseOverrides.
func (c *Config) MalwareTestOverrides() string {
	if v, ok := parseMalwareTestOverridesEnv(); ok {
		return v
	}
	if c == nil {
		return ""
	}
	return c.Runtime.MalwareTestOverrides
}

// parseAllowInsecureTLSEnv mirrors parseOfflineEnv: tolerant bool parsing
// with (value, set) semantics so the YAML can decide when the env var is
// unset or unparseable.
func parseAllowInsecureTLSEnv() (bool, bool) {
	raw := strings.TrimSpace(os.Getenv(allowInsecureTLSEnvVar))
	if raw == "" {
		return false, false
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	}
	if v, err := strconv.ParseBool(raw); err == nil {
		return v, true
	}
	return false, false
}

// AllowInsecureTLS returns the effective allow-insecure-TLS state for
// this config. CHAINSAW_ALLOW_INSECURE_TLS wins; otherwise the YAML
// runtime.allow_insecure_tls field; otherwise false (fail-closed). Safe
// on a nil receiver.
func (c *Config) AllowInsecureTLS() bool {
	if v, ok := parseAllowInsecureTLSEnv(); ok {
		return v
	}
	if c == nil {
		return false
	}
	return c.Runtime.AllowInsecureTLS
}

// parseOfflineEnv returns (value, set) for the CHAINSAW_OFFLINE env var
// using the same tolerant parsing every other Chainsaw env-bool helper
// uses (1/true/yes/on → true; 0/false/no/off → false). An unset or
// unparseable value returns (false, false) so the YAML can decide.
func parseOfflineEnv() (bool, bool) {
	raw := strings.TrimSpace(os.Getenv(offlineEnvVar))
	if raw == "" {
		return false, false
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	}
	// Fall through to strconv.ParseBool for anything we haven't
	// explicitly whitelisted above. It accepts "True", "TRUE", etc.
	if v, err := strconv.ParseBool(raw); err == nil {
		return v, true
	}
	return false, false
}

// IsOffline returns the effective offline-mode state for this config.
// Env var CHAINSAW_OFFLINE wins; otherwise the YAML runtime.offline
// field is consulted; otherwise false. Safe on a nil receiver.
func (c *Config) IsOffline() bool {
	if v, ok := parseOfflineEnv(); ok {
		return v
	}
	if c == nil {
		return false
	}
	return c.Runtime.Offline
}

// OfflineSource returns a short human-readable token describing where
// the offline-mode value came from: "env", "yaml", or "default". Used
// in the startup "config resolved" log line so operators can answer
// "why is offline mode on?" from the log aggregator.
func (c *Config) OfflineSource() string {
	if _, ok := parseOfflineEnv(); ok {
		return "env"
	}
	if c != nil && c.Runtime.Offline {
		return "yaml"
	}
	return "default"
}
