package telemetry

// Consent resolution for the client-side telemetry SDK.
//
// The policy the product has committed to (see docs/plans/posthog-rehaul.md):
//   * Cloud deployments: opt-out. Telemetry on by default, user can
//     disable via CHAINSAW_TELEMETRY_DISABLED=1.
//   * Self-hosted deployments: opt-in. Telemetry off by default; operator
//     flips CHAINSAW_TELEMETRY_ENABLED=1 when they want to share data
//     with the upstream.
//
// Self-hosted detection is intentionally boring: any of the listed
// signals flips the mode. We do not infer from hostname or IP because
// that creates false positives in dev environments.
//
// A hard kill-switch (CHAINSAW_TELEMETRY_DISABLED=1) always wins and is
// respected regardless of cloud/self-hosted. A build-tag-based selfhosted
// flag is expected to be compiled in via a sibling file tagged
// `//go:build selfhosted`; when present the default flips without any
// env-var gymnastics.

import (
	"os"
	"strings"
)

// Mode captures the three states the SDK can be in.
type Mode int

const (
	// ModeEnabled emits events (and persists an install_id).
	ModeEnabled Mode = iota
	// ModeDisabled emits nothing; install_id is not persisted on first run.
	ModeDisabled
	// ModeDebug prints events to stdout as JSON but never sends.
	ModeDebug
)

// IsSelfHosted reports whether this binary is running in a self-hosted
// deployment. Overridable via CHAINSAW_SELF_HOSTED=1; also flipped by the
// build-tag-gated defaultSelfHosted constant (see selfhosted_on.go /
// selfhosted_off.go).
func IsSelfHosted() bool {
	if strings.EqualFold(os.Getenv("CHAINSAW_SELF_HOSTED"), "1") ||
		strings.EqualFold(os.Getenv("CHAINSAW_SELF_HOSTED"), "true") {
		return true
	}
	return defaultSelfHosted
}

// ResolveMode returns the effective telemetry mode for the current
// process. Checks, in order:
//  1. CHAINSAW_TELEMETRY_DEBUG=1 → ModeDebug (wins over everything else
//     so developers can inspect events without accidentally sending).
//  2. CHAINSAW_OFFLINE=1 → ModeDisabled. The umbrella flag disables
//     every phone-home path; telemetry would otherwise hit the
//     backend /api/telemetry/ingest endpoint that the ingest endpoint
//     forwards to PostHog.
//  3. CHAINSAW_TELEMETRY_DISABLED=1 → ModeDisabled.
//  4. Self-hosted deployments require CHAINSAW_TELEMETRY_ENABLED=1 to
//     opt in; otherwise ModeDisabled.
//  5. Otherwise ModeEnabled.
func ResolveMode() Mode {
	if envTrue("CHAINSAW_TELEMETRY_DEBUG") {
		return ModeDebug
	}
	if envTrue("CHAINSAW_OFFLINE") {
		return ModeDisabled
	}
	if envTrue("CHAINSAW_TELEMETRY_DISABLED") {
		return ModeDisabled
	}
	if IsSelfHosted() && !envTrue("CHAINSAW_TELEMETRY_ENABLED") {
		return ModeDisabled
	}
	return ModeEnabled
}

// String renders a Mode for diagnostic output (used by
// `chainsaw telemetry status`).
func (m Mode) String() string {
	switch m {
	case ModeEnabled:
		return "enabled"
	case ModeDisabled:
		return "disabled"
	case ModeDebug:
		return "debug"
	default:
		return "unknown"
	}
}

// RefusalSharingEnabled reports whether the operator has given the
// SEPARATE, explicit consent to share refused-package IDENTIFYING data
// (package name, version, malware id) off-box. Default OFF, fail-closed:
// only an explicit truthy CHAINSAW_REFUSAL_SHARING flips it on.
//
// This governs the proxy/server surfaces. The free local guard does NOT
// depend on this — it gates identifying data on its own first-run consent
// (D-NUDGE: consent-gated, see the guard path), so a local user who answers
// "yes" to the first-run prompt shares package names without needing this
// env var, and a user who never consents shares nothing regardless.
func RefusalSharingEnabled() bool {
	return envTrue("CHAINSAW_REFUSAL_SHARING")
}

// Endpoint returns the URL the SDK should POST event batches to.
// Honors CHAINSAW_TELEMETRY_ENDPOINT for self-hosters and test harnesses;
// otherwise uses the provided default (which the caller derives from the
// CLI's configured server URL).
func Endpoint(defaultURL string) string {
	if override := strings.TrimSpace(os.Getenv("CHAINSAW_TELEMETRY_ENDPOINT")); override != "" {
		return override
	}
	return defaultURL
}

func envTrue(name string) bool {
	v := strings.TrimSpace(os.Getenv(name))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}
