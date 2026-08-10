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
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/coverage"
)

const (
	coverageModeEnv       = "CHAINSAW_COVERAGE_MODE"
	coverageRequiredEnv   = "CHAINSAW_COVERAGE_REQUIRED"
	coverageGraceEnv      = "CHAINSAW_COVERAGE_GRACE"
	coverageMaxAgeEnv     = "CHAINSAW_COVERAGE_MAX_LEDGER_AGE"
	coverageBreakGlassEnv = "CHAINSAW_COVERAGE_BREAK_GLASS"
)

// guardPosture reads the operator's posture from the environment (MDM, a
// dotfile, or a CI runner). Local config only — there is no org distribution;
// see decision D4.
//
// An explicitly-configured posture that fails validation returns an error, and
// the caller MUST surface it and refuse to run rather than continuing with the
// gate disabled. Silently degrading to off would reproduce exactly the failure
// this option exists to prevent.
func guardPosture() (coverage.Posture, error) {
	mode := strings.TrimSpace(strings.ToLower(os.Getenv(coverageModeEnv)))
	if mode == "" {
		return coverage.Posture{Version: 1, Mode: coverage.ModeOff}, nil
	}

	// Break-glass: documented escape hatch for an operator whose build is
	// wedged by an upstream outage. Loud on purpose — a silent bypass of a
	// security control is worse than no control.
	if envTruthy(os.Getenv(coverageBreakGlassEnv)) {
		fmt.Fprintf(os.Stderr,
			"chainsaw: %s=1 — coverage fail-closed gate DISABLED for this invocation\n",
			coverageBreakGlassEnv)
		return coverage.Posture{Version: 1, Mode: coverage.ModeOff}, nil
	}

	p := coverage.Posture{
		Version:      1,
		Mode:         coverage.Mode(mode),
		Grace:        coverage.DefaultGrace,
		MaxLedgerAge: coverage.DefaultMaxLedgerAge,
	}
	for _, raw := range strings.Split(os.Getenv(coverageRequiredEnv), ",") {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		src, err := coverage.ParseSource(name)
		if err != nil {
			return coverage.Posture{}, err
		}
		p.Required = append(p.Required, src)
	}
	if raw := strings.TrimSpace(os.Getenv(coverageGraceEnv)); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return coverage.Posture{}, fmt.Errorf("%s: %w", coverageGraceEnv, err)
		}
		p.Grace = d
	}
	if raw := strings.TrimSpace(os.Getenv(coverageMaxAgeEnv)); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return coverage.Posture{}, fmt.Errorf("%s: %w", coverageMaxAgeEnv, err)
		}
		p.MaxLedgerAge = d
	}
	if err := p.Validate(); err != nil {
		return coverage.Posture{}, err
	}
	return p, nil
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
