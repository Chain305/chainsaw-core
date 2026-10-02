package intelligence

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// install_script_detector_test.go pins the A-2 ledger: which detector
// produced a row's install-script facts, and the recall guard that reads it.

// TestInstallScriptsProvider_StampsTheDetectorThatRan — the stamp must name
// the detector actually called, on both switchable ecosystems, and stay
// empty where there is no choice.
func TestInstallScriptsProvider_StampsTheDetectorThatRan(t *testing.T) {
	npm := buildTGZ(t, map[string]string{
		"package/package.json": `{"name":"x","version":"1.0.0","scripts":{"postinstall":"node x.js"}}`,
	})
	pip := buildTGZ(t, map[string]string{
		"x-1.0.0/setup.py": "from setuptools import setup\nsetup(name='x')\n",
	})
	gem := buildTGZ(t, map[string]string{
		"x.gemspec": "Gem::Specification.new do |s|\n  s.name = 'x'\nend\n",
	})
	cases := []struct {
		eco     string
		payload []byte
		flag    string // CHAINSAW_FF_INSTALLSCRIPT_AST
		want    string
	}{
		{"npm", npm, "false", InstallScriptDetectorRegex},
		{"npm", npm, "true", InstallScriptDetectorAST},
		{"pypi", pip, "false", InstallScriptDetectorRegex},
		{"pypi", pip, "true", InstallScriptDetectorAST},
		{"rubygems", gem, "true", ""},
	}
	for _, tc := range cases {
		t.Run(tc.eco+"/ast="+tc.flag, func(t *testing.T) {
			t.Setenv("CHAINSAW_FF_INSTALLSCRIPT_AST", tc.flag)
			partial, err := newInstallScriptsProvider().Run(context.Background(), Request{
				Key:      Key{Ecosystem: tc.eco, Package: "x", Version: "1.0.0"},
				Artifact: &ArtifactHandle{Bytes: tc.payload},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if partial.Scan == nil {
				t.Fatal("expected a Scan section")
			}
			if got := partial.Scan.InstallScriptDetector; got != tc.want {
				t.Fatalf("InstallScriptDetector = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMergeScan_KeepsInstallScriptDetector — MergeScan copies fields one by
// one, so a field it does not name is silently dropped from every report.
func TestMergeScan_KeepsInstallScriptDetector(t *testing.T) {
	var dst ArtifactScanSection
	MergeScan(&dst, ArtifactScanSection{
		Performed:             true,
		InstallScriptKind:     "present",
		HasInstallScript:      true,
		InstallScriptDetector: InstallScriptDetectorAST,
	})
	// A later provider that never touches install scripts must not clear it.
	MergeScan(&dst, ArtifactScanSection{Performed: true, UsesEval: true})
	if dst.InstallScriptDetector != InstallScriptDetectorAST {
		t.Fatalf("InstallScriptDetector = %q after merge, want %q", dst.InstallScriptDetector, InstallScriptDetectorAST)
	}
}

// TestMergeReportPayload_StampTravelsWithTheFacts — the store keeps or
// replaces the Scan section whole, so the stamp is preserved exactly when
// the facts it describes are.
func TestMergeReportPayload_StampTravelsWithTheFacts(t *testing.T) {
	prior := Report{Scan: ArtifactScanSection{
		Performed:             true,
		InstallScriptKind:     "present",
		HasInstallScript:      true,
		InstallScriptDetector: InstallScriptDetectorRegex,
	}}
	priorPayload, err := json.Marshal(&prior)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("metadata-only rescan preserves facts and stamp", func(t *testing.T) {
		out, err := mergeReportPayload(priorPayload, &Report{})
		if err != nil {
			t.Fatal(err)
		}
		var merged Report
		if err := json.Unmarshal(out, &merged); err != nil {
			t.Fatal(err)
		}
		if !merged.Scan.HasInstallScript || merged.Scan.InstallScriptDetector != InstallScriptDetectorRegex {
			t.Fatalf("preserved scan = %+v, want the prior facts with detector %q", merged.Scan, InstallScriptDetectorRegex)
		}
	})

	t.Run("fresh artifact scan replaces facts and stamp together", func(t *testing.T) {
		next := &Report{Scan: ArtifactScanSection{
			Performed:             true,
			InstallScriptKind:     "none",
			InstallScriptDetector: InstallScriptDetectorAST,
		}}
		out, err := mergeReportPayload(priorPayload, next)
		if err != nil {
			t.Fatal(err)
		}
		var merged Report
		if err := json.Unmarshal(out, &merged); err != nil {
			t.Fatal(err)
		}
		if merged.Scan.HasInstallScript || merged.Scan.InstallScriptDetector != InstallScriptDetectorAST {
			t.Fatalf("merged scan = %+v, want the new facts with detector %q", merged.Scan, InstallScriptDetectorAST)
		}
	})
}

// scanned builds a report whose installscripts provider ran.
func scanned(detector string, has, fetches bool) *Report {
	kind := "none"
	switch {
	case fetches:
		kind = "fetches_remote"
	case has:
		kind = "present"
	}
	return &Report{Scan: ArtifactScanSection{
		Performed:             true,
		InstallScriptKind:     kind,
		HasInstallScript:      has,
		InstallScriptFetches:  fetches,
		InstallScriptDetector: detector,
	}}
}

// TestDiffSupplyChain_DetectorChangeGuard — install_script_appeared is
// skipped ONLY when both stamps are set and differ. The empty cases are the
// ones that matter: treating "" as a mismatch would silence the trigger for
// every pre-ledger row on its first rescan after deploy.
func TestDiffSupplyChain_DetectorChangeGuard(t *testing.T) {
	cases := []struct {
		name         string
		prior, next  string
		wantAppeared bool
	}{
		{"regex -> ast: skipped", InstallScriptDetectorRegex, InstallScriptDetectorAST, false},
		{"pre-ledger -> regex: still compared", "", InstallScriptDetectorRegex, true},
		{"ast -> pre-ledger: still compared", InstallScriptDetectorAST, "", true},
		{"same detector: compared", InstallScriptDetectorRegex, InstallScriptDetectorRegex, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DiffSupplyChain(recallRow(), "npm",
				scanned(tc.prior, false, false),
				scanned(tc.next, true, true))
			appeared := false
			for _, e := range got {
				if e.Trigger == AlertInstallScriptAppeared {
					appeared = true
				}
			}
			if appeared != tc.wantAppeared {
				t.Fatalf("install_script_appeared fired = %v (%v), want %v", appeared, triggers(got), tc.wantAppeared)
			}
		})
	}
}

// TestDiffSupplyChain_DetectorChangeStillReportsAWorseVerdict — the skip
// must not hide a material change. A script the new detector finds was
// always there, so "appeared" is wrong; but if it makes the package worse,
// verdict_degraded has to say so. The verdicts come from the real risk
// engine, not hand-set, so this fails if install-script facts ever stop
// moving the verdict.
func TestDiffSupplyChain_DetectorChangeStillReportsAWorseVerdict(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	evaluated := func(r *Report) *Report {
		r.Identity = IdentitySection{Ecosystem: "npm", Package: "left-pad", Version: "1.3.0"}
		ComputeTrustScore(r)
		if r.Risk == nil {
			t.Fatal("risk engine produced no evaluation")
		}
		return r
	}
	prior := evaluated(scanned(InstallScriptDetectorRegex, false, false))
	next := evaluated(scanned(InstallScriptDetectorAST, true, true))
	if recallVerdictRank(next.Risk.Verdict) <= recallVerdictRank(prior.Risk.Verdict) {
		t.Fatalf("fixture does not worsen the verdict (%s -> %s); the test proves nothing",
			prior.Risk.Verdict, next.Risk.Verdict)
	}

	got := triggers(DiffSupplyChain(recallRow(), "npm", prior, next))
	if len(got) != 1 || got[0] != AlertVerdictDegraded {
		t.Fatalf("triggers = %v, want exactly [%s]", got, AlertVerdictDegraded)
	}

	// The skip is logged, with both detectors and the coordinate.
	line := logs.String()
	for _, want := range []string{"detector change", "prior_detector=regex", "next_detector=ast", "package=left-pad", "version=1.3.0"} {
		if !strings.Contains(line, want) {
			t.Errorf("skip log missing %q:\n%s", want, line)
		}
	}
}
