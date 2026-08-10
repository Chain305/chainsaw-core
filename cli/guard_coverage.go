package cli

// guard_coverage.go — the optional fail-closed gate on the workstation guard.
//
// Off by default. When off, evaluateAll behaves exactly as it did before this
// file existed. See docs/plan_optional_fail_closed.md for the design, and for
// why the guard is defence-in-depth rather than proof: a developer can
// uninstall the shim, so the provable chokepoints are the proxy, CI, publish,
// and admission.

import (
	"fmt"
	"os"
	"time"

	"github.com/chain305/chainsaw-core/coverage"
)

const (
	coverageModeEnv       = coverage.EnvMode
	coverageRequiredEnv   = coverage.EnvRequired
	coverageGraceEnv      = coverage.EnvGrace
	coverageMaxAgeEnv     = coverage.EnvMaxAge
	coverageBreakGlassEnv = coverage.EnvBreakGlass
)

// guardPosture reads the operator's posture from the environment (MDM, a
// dotfile, or a CI runner). Local config only — there is no org distribution;
// see decision D4.
//
// Thin wrapper over coverage.PostureFromEnv: the parsing lives in the shared
// package so the guard, the proxy, the publish path, CI and admission cannot
// end up with subtly different readings of the same variables. That drift is
// the failure the single-Gate design exists to prevent.
func guardPosture() (coverage.Posture, error) {
	return coverage.PostureFromEnv(os.Getenv, func() {
		// Break-glass is loud on purpose — a silent bypass of a security
		// control is worse than no control.
		fmt.Fprintf(os.Stderr,
			"chainsaw: %s=1 — coverage fail-closed gate DISABLED for this invocation\n",
			coverage.EnvBreakGlass)
	})
}

// guardLedger reports what the offline guard could actually evaluate.
//
// The guard is not the proxy: it has no CVE feed, no registry metadata, and no
// package bytes unless the operator staged artifacts or enabled deep mode.
// Those sources are reported as UNAVAILABLE rather than omitted, so that an
// operator who requires one gets an honest refusal with a readable reason
// instead of a silently inert control.
//
// The codes here are guard-local strings written straight into Entry.Code for
// the audit trail; they never pass through StatusForWarnCode, so they do not
// belong in the classifier tables.
func guardLedger(g *localGuard, now time.Time) coverage.Ledger {
	ok := func() coverage.Entry {
		return coverage.Entry{Status: coverage.StatusOK, Producer: "guard", ObservedAt: now, LastOKAt: now}
	}
	unavailable := func(code string) coverage.Entry {
		return coverage.Entry{Status: coverage.StatusUnavailable, Producer: "guard", Code: code, ObservedAt: now}
	}

	led := coverage.Ledger{
		// Always available offline: the typosquat corpus is embedded.
		coverage.SourceTyposquat: ok(),
		// Never available on the offline guard — these need the server.
		coverage.SourceCVE:              unavailable("offline_guard_no_network"),
		coverage.SourceRegistryMetadata: unavailable("offline_guard_no_network"),
		coverage.SourceProvenance:       unavailable("offline_guard_no_network"),
	}

	// The embedded floor alone is partial coverage; an operator who required
	// `malware` asked for the full OpenSSF set, not the famous-attack subset.
	if g != nil && g.fullFeed {
		led[coverage.SourceMalware] = ok()
	} else {
		led[coverage.SourceMalware] = unavailable("feed_not_downloaded")
	}

	// Artifact-bound sources need bytes, which exist only when the operator
	// staged them or turned on deep mode.
	artifactStatus := unavailable("no_artifact_bytes")
	if os.Getenv(guardArtifactDirEnv) != "" || deepFetchEnabled() {
		artifactStatus = ok()
	}
	led[coverage.SourceChecksum] = artifactStatus
	led[coverage.SourceInstallScripts] = artifactStatus
	led[coverage.SourceHiddenUnicode] = artifactStatus

	return led
}
