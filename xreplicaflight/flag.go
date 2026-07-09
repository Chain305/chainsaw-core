package xreplicaflight

import (
	"os"
	"strings"
)

// EnvFlag is the env var that turns the cross-replica coordination
// layer on. The default (unset / empty / "false" / "0") installs
// NoopFlight, preserving the pre-xreplicaflight single-instance
// behaviour exactly.
const EnvFlag = "CHAINSAW_XREPLICA_SINGLEFLIGHT"

// Enabled reports whether the feature flag is on. Recognised truthy
// values are "true", "1", "on", "yes", "enable", "enabled" —
// case-insensitive. Everything else (including empty and typos) is
// treated as OFF. This mirrors the tolerance of ResolveMode in
// internal/intelligence/bootstrap.go.
func Enabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(EnvFlag)))
	switch v {
	case "true", "1", "on", "yes", "enable", "enabled":
		return true
	default:
		return false
	}
}
