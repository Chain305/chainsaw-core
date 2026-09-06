// Package enforcementposture enumerates the environment variables that
// weaken or disable a Chainsaw enforcement control, so a deployment can
// state its actual posture instead of its intended one.
//
// It exists because a QA adjudication in September 2026 enumerated ten
// such variables and found that none of them was recorded server-side.
// Two were worse than unrecorded:
//
//   - CHAINSAW_FF_<FLAG> forces any feature flag process-wide and
//     "always wins" over the flag provider, and it returned before every
//     logging path — so a security control could be switched off with no
//     trace at all.
//   - CHAINSAW_INTEL_BUNDLE_SKIP_VERIFY disables Sigstore verification of
//     the intelligence bundle. The source comment in core/intelligence
//     is candid that the proxy startup banner it was once documented to
//     produce "does not exist; the claim was aspirational".
//
// The point is not to remove the escape hatches. Every one of them has a
// legitimate operator use, and several are load-bearing for on-prem and
// air-gapped installs. The point is that using one should be visible to
// the person who has to answer "is this control on?" — the operator, an
// auditor, or an incident responder reading a startup log.
package enforcementposture

import (
	"fmt"
	"sort"
	"strings"
)

// Getenv matches os.Getenv. Injected so callers can test without
// mutating the process environment.
type Getenv func(string) string

// Weakening describes one environment variable that reduces enforcement.
type Weakening struct {
	// Env is the variable name. For the feature-flag override this is
	// the fully-expanded name, e.g. CHAINSAW_FF_EXCEPTION_APPROVAL_GATING.
	Env string
	// Value is the observed value. Never a secret: every variable in
	// this inventory is a boolean or a short enum.
	Value string
	// Effect is a one-line statement of what stops being enforced,
	// written for an operator rather than for a developer.
	Effect string
}

// known lists the fixed-name variables. The feature-flag overrides are
// discovered dynamically because their names are open-ended.
//
// Keep this in step with the escape hatches themselves. A variable that
// weakens a control and is absent here is worse than one that was never
// added, because this inventory is what makes the others trustworthy.
var known = []struct {
	env    string
	effect string
	// weakOnlyIf, when non-nil, reports whether a given value actually
	// weakens anything. Absent means any non-empty truthy value does.
	weakOnlyIf func(string) bool
}{
	{
		env:    "CHAINSAW_COVERAGE_BREAK_GLASS",
		effect: "coverage fail-closed gate disabled (guard, proxy, publish, admission)",
	},
	{
		env:    "CHAINSAW_INTEL_BUNDLE_SKIP_VERIFY",
		effect: "Sigstore signature verification of the intelligence bundle skipped",
	},
	{
		env:    "CHAINSAW_OPA_SKIP_VERIFY",
		effect: "OPA policy-bundle signature verification skipped",
	},
	{
		env:    "CHAINSAW_OPA_BUNDLE_SKIP_VERIFY",
		effect: "OPA policy-bundle signature verification skipped",
	},
	{
		env:    "CHAINSAW_ALLOW_INSECURE_TLS",
		effect: "TLS certificate verification may be skipped for admin-flagged upstream hosts",
	},
	{
		env:    "CHAINSAW_ALLOW_PRIVATE_UPSTREAMS",
		effect: "SSRF guard permits private/loopback/link-local upstream addresses",
	},
	{
		env:    "CHAINSAW_ALLOW_CGNAT_UPSTREAMS",
		effect: "SSRF guard permits CGNAT upstream addresses",
	},
	{
		env:    "CHAINSAW_S3_INSECURE",
		effect: "blob-store transport security relaxed",
	},
	{
		env:    "CHAINSAW_GUARD_ALLOWLIST",
		effect: "local guard waiver file read from an operator-chosen path",
		// A path, not a boolean: any non-empty value is meaningful.
		weakOnlyIf: func(v string) bool { return strings.TrimSpace(v) != "" },
	},
	{
		env:    "CHAINSAW_KEV_DISABLED",
		effect: "CISA KEV enrichment provider disabled",
	},
	{
		env:        "CHAINSAW_ADMISSION_FAIL_MODE",
		effect:     "Kubernetes admission webhook fails OPEN when signals are unavailable",
		weakOnlyIf: func(v string) bool { return strings.EqualFold(strings.TrimSpace(v), "open") },
	},
}

// truthy mirrors the loose boolean parsing used across the codebase's
// env handling. Deliberately permissive: an operator who wrote "yes"
// meant yes, and this inventory reporting nothing would be the failure.
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// Scan returns every active weakening, sorted by variable name.
//
// flagOverrides carries the feature-flag overrides observed by
// core/featureflags, whose names cannot be enumerated ahead of time.
// Pass nil when the flag client is not in use.
func Scan(getenv Getenv, flagOverrides map[string]string) []Weakening {
	if getenv == nil {
		return nil
	}
	var out []Weakening
	for _, k := range known {
		v := getenv(k.env)
		if v == "" {
			continue
		}
		weak := truthy(v)
		if k.weakOnlyIf != nil {
			weak = k.weakOnlyIf(v)
		}
		if !weak {
			continue
		}
		out = append(out, Weakening{Env: k.env, Value: v, Effect: k.effect})
	}
	for env, v := range flagOverrides {
		out = append(out, Weakening{
			Env:   env,
			Value: v,
			Effect: "feature flag forced process-wide, overriding the flag provider " +
				"(a forced-off security flag disables the control it gates)",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Env < out[j].Env })
	return out
}

// Summary renders a single log-friendly line, or "" when nothing is
// weakened. Callers log it at Warn on startup.
func Summary(w []Weakening) string {
	if len(w) == 0 {
		return ""
	}
	parts := make([]string, 0, len(w))
	for _, x := range w {
		parts = append(parts, fmt.Sprintf("%s=%s (%s)", x.Env, x.Value, x.Effect))
	}
	return strings.Join(parts, "; ")
}
