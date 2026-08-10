package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/coverage"
)

var testGuardNow = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

func TestGuardPostureDefaultsToOff(t *testing.T) {
	t.Setenv(coverageModeEnv, "")
	t.Setenv(coverageRequiredEnv, "")
	p, err := guardPosture()
	if err != nil {
		t.Fatalf("default posture errored: %v", err)
	}
	if p.Mode != coverage.ModeOff {
		t.Errorf("Mode = %q, want off", p.Mode)
	}
}

func TestGuardPostureReadsEnv(t *testing.T) {
	t.Setenv(coverageModeEnv, "closed")
	t.Setenv(coverageRequiredEnv, "malware, typosquat")
	p, err := guardPosture()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Mode != coverage.ModeClosed {
		t.Errorf("Mode = %q, want closed", p.Mode)
	}
	if len(p.Required) != 2 {
		t.Fatalf("Required = %v, want 2 entries", p.Required)
	}
	if p.Grace != coverage.DefaultGrace || p.MaxLedgerAge != coverage.DefaultMaxLedgerAge {
		t.Errorf("defaults not applied: grace=%s maxAge=%s", p.Grace, p.MaxLedgerAge)
	}
}

func TestGuardPostureOverridesDurations(t *testing.T) {
	t.Setenv(coverageModeEnv, "warn")
	t.Setenv(coverageRequiredEnv, "cve")
	t.Setenv(coverageGraceEnv, "5s")
	t.Setenv(coverageMaxAgeEnv, "2m")
	p, err := guardPosture()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Grace != 5*time.Second || p.MaxLedgerAge != 2*time.Minute {
		t.Errorf("grace=%s maxAge=%s, want 5s / 2m", p.Grace, p.MaxLedgerAge)
	}
}

// An explicitly-closed posture that cannot be honoured must be a hard error,
// never a silent downgrade to off. See decision D3.
func TestGuardPostureRejectsBadConfig(t *testing.T) {
	cases := [][2]string{
		{"closed", "not_a_source"},
		{"closed", ""},
		{"sideways", "cve"},
	}
	for _, tc := range cases {
		t.Setenv(coverageModeEnv, tc[0])
		t.Setenv(coverageRequiredEnv, tc[1])
		if _, err := guardPosture(); err == nil {
			t.Errorf("mode=%q required=%q was accepted, want error", tc[0], tc[1])
		}
	}
}

func TestGuardPostureBreakGlassForcesOff(t *testing.T) {
	t.Setenv(coverageModeEnv, "closed")
	t.Setenv(coverageRequiredEnv, "malware")
	t.Setenv(coverageBreakGlassEnv, "1")
	p, err := guardPosture()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Mode != coverage.ModeOff {
		t.Errorf("break-glass did not disable the gate: mode=%q", p.Mode)
	}
}

func TestGuardLedgerReportsMalwareAndTyposquatFromLocalState(t *testing.T) {
	g := &localGuard{fullFeed: true}
	led := guardLedger(g, testGuardNow)

	if got := led[coverage.SourceMalware].Status; got != coverage.StatusOK {
		t.Errorf("malware = %q, want ok when the full feed is loaded", got)
	}
	if got := led[coverage.SourceTyposquat].Status; got != coverage.StatusOK {
		t.Errorf("typosquat = %q, want ok (corpus is embedded)", got)
	}
}

func TestGuardLedgerMarksMalwareUnavailableOnFloorOnly(t *testing.T) {
	// Only the embedded famous-attack floor is loaded — that is partial
	// coverage, and an operator who required `malware` asked for the real set.
	g := &localGuard{fullFeed: false}
	led := guardLedger(g, testGuardNow)
	if got := led[coverage.SourceMalware].Status; got != coverage.StatusUnavailable {
		t.Errorf("malware = %q, want unavailable when only the floor is loaded", got)
	}
}

func TestGuardLedgerMarksNetworkSourcesUnavailableOffline(t *testing.T) {
	// The offline guard never reaches these. They must read as unavailable,
	// not silently absent, so requiring one is an honest refusal.
	g := &localGuard{fullFeed: true}
	led := guardLedger(g, testGuardNow)
	for _, src := range []coverage.Source{coverage.SourceCVE, coverage.SourceRegistryMetadata} {
		if got := led[src].Status; got != coverage.StatusUnavailable {
			t.Errorf("%s = %q, want unavailable on the offline guard", src, got)
		}
	}
}

func TestGuardLedgerArtifactSourcesFollowDeepMode(t *testing.T) {
	t.Setenv(guardArtifactDirEnv, "")
	t.Setenv(guardDeepFetchEnv, "")
	g := &localGuard{fullFeed: true}
	led := guardLedger(g, testGuardNow)
	for _, src := range []coverage.Source{
		coverage.SourceChecksum, coverage.SourceInstallScripts, coverage.SourceHiddenUnicode,
	} {
		if got := led[src].Status; got != coverage.StatusUnavailable {
			t.Errorf("%s = %q, want unavailable with no staged artifacts", src, got)
		}
	}

	t.Setenv(guardArtifactDirEnv, t.TempDir())
	led = guardLedger(g, testGuardNow)
	if got := led[coverage.SourceInstallScripts].Status; got != coverage.StatusOK {
		t.Errorf("install_scripts = %q, want ok with a staged artifact dir", got)
	}
}

func TestEvaluateAllUnchangedWhenCoverageOff(t *testing.T) {
	t.Setenv("CHAINSAW_GUARD_DB", filepath.Join(t.TempDir(), "none.json"))
	t.Setenv(coverageModeEnv, "")
	specs := []packageSpec{{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}}

	verdicts, blocked := newLocalGuard().evaluateAll(context.Background(), specs)
	if blocked {
		t.Error("a benign package was blocked with coverage off")
	}
	for _, v := range verdicts {
		if v.Severity == "coverage" {
			t.Error("a coverage verdict appeared with the gate off")
		}
	}
}

func TestEvaluateAllBlocksOnMissingRequiredCoverage(t *testing.T) {
	t.Setenv("CHAINSAW_GUARD_DB", filepath.Join(t.TempDir(), "none.json"))
	t.Setenv(coverageModeEnv, "closed")
	// The offline guard can never evaluate CVE data.
	t.Setenv(coverageRequiredEnv, "cve")
	specs := []packageSpec{{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}}

	verdicts, blocked := newLocalGuard().evaluateAll(context.Background(), specs)
	if !blocked {
		t.Fatal("required-but-unavailable cve did not block")
	}
	var found bool
	for _, v := range verdicts {
		if v.Severity == "coverage" && v.Block {
			found = true
			if !strings.Contains(v.Reason, "cve") {
				t.Errorf("reason %q does not name the missing source", v.Reason)
			}
		}
	}
	if !found {
		t.Errorf("no coverage verdict in %+v", verdicts)
	}
}

func TestEvaluateAllWarnModeDoesNotBlock(t *testing.T) {
	t.Setenv("CHAINSAW_GUARD_DB", filepath.Join(t.TempDir(), "none.json"))
	t.Setenv(coverageModeEnv, "warn")
	t.Setenv(coverageRequiredEnv, "cve")
	specs := []packageSpec{{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}}

	_, blocked := newLocalGuard().evaluateAll(context.Background(), specs)
	if blocked {
		t.Error("warn mode blocked the install")
	}
}

// A posture the operator configured but which we cannot honour must refuse
// every spec, not proceed with the gate quietly disabled.
func TestEvaluateAllBlocksOnInvalidPosture(t *testing.T) {
	t.Setenv("CHAINSAW_GUARD_DB", filepath.Join(t.TempDir(), "none.json"))
	t.Setenv(coverageModeEnv, "closed")
	t.Setenv(coverageRequiredEnv, "not_a_real_source")
	specs := []packageSpec{{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}}

	verdicts, blocked := newLocalGuard().evaluateAll(context.Background(), specs)
	if !blocked {
		t.Fatal("invalid coverage config did not block")
	}
	if len(verdicts) != 1 || !strings.Contains(verdicts[0].Reason, "invalid coverage configuration") {
		t.Errorf("verdicts = %+v, want one invalid-configuration refusal", verdicts)
	}
}
