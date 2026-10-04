package intelligence

import (
	"context"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// TestDebugTelemetryEndToEnd runs real-world-shaped package bytes through the
// provider, the projection and the evaluator. The vm2 lines are from
// vm2 3.11.0's published lib/; the telemetry line is dagster 1.10.16's
// telemetry_upload.py. A test file carrying the same import must not count.
func TestDebugTelemetryEndToEnd(t *testing.T) {
	tgz := buildNPMTarball(t, map[string]string{
		"package/package.json":           `{"name":"vm2","version":"3.11.0"}`,
		"package/lib/script.js":          "'use strict';\n\nconst {Script} = require('vm');\n",
		"package/lib/telemetry.py":       `    return os.getenv("DAGSTER_TELEMETRY_URL", default="http://telemetry.dagster.io/actions")` + "\n",
		"package/test/sandbox.test.js":   "const v8 = require('v8');\n",
		"package/lib/helpers/inherit.js": "return Reflect.construct(Super, arguments, NewTarget);\n",
		"package/lib/plugins.js":         "var pluginFn = require(pluginPath);\n",
	})
	req := Request{Key: Key{Ecosystem: "npm", Package: "vm2", Version: "3.11.0"}, Artifact: &ArtifactHandle{Bytes: tgz}}
	pr, err := newDebugTelemetryProvider().Run(context.Background(), req, nil)
	if err != nil || pr.Scan == nil {
		t.Fatalf("Run: scan=%v err=%v", pr.Scan, err)
	}
	if !pr.Scan.DynamicRequire {
		t.Fatalf("DynamicRequire not set")
	}
	if !pr.Scan.DebugAccess || !pr.Scan.Telemetry {
		t.Fatalf("DebugAccess=%v Telemetry=%v, want both true", pr.Scan.DebugAccess, pr.Scan.Telemetry)
	}
	for _, l := range pr.Scan.DebugAccessSamples {
		if l.File == "package/test/sandbox.test.js" {
			t.Errorf("a test file lit DebugAccess: %+v", l)
		}
	}

	// Through the real projection entry point, so an unwired call site fails.
	in := ProjectToRiskInput(&Report{Identity: IdentitySection{Ecosystem: "npm", Package: "vm2", Version: "3.11.0"}, Scan: *pr.Scan})
	if !in.CapDebugAccess || !in.CapTelemetry || len(in.CapDebugAccessEvidence) == 0 {
		t.Fatalf("projection: debug=%v telemetry=%v evidence=%v", in.CapDebugAccess, in.CapTelemetry, in.CapDebugAccessEvidence)
	}

	// Weight 0 is the contract: firing must not move the score.
	base := in
	base.CapDebugAccess, base.CapTelemetry, base.CapDynamicRequire = false, false, false
	before := risk.EvaluatePackage(base, risk.Options{}).DirectScore.Overall
	ev := risk.EvaluatePackage(in, risk.Options{})
	if ev.DirectScore.Overall != before {
		t.Errorf("overall moved %d -> %d: cap.debug_access / cap.telemetry must be weight 0 until priced against the corpus",
			before, ev.DirectScore.Overall)
	}
	fired := map[string]bool{}
	for _, c := range ev.DirectScore.Categories {
		for _, f := range c.FiredSignals {
			fired[f.ID] = true
		}
	}
	for _, id := range []string{risk.SignalCapDebugAccess, risk.SignalCapTelemetry, risk.SignalCapDynamicRequire} {
		if !fired[id] {
			t.Errorf("%s did not fire", id)
		}
		if w := risk.Registry[id].Weight; w != 0 {
			t.Errorf("%s has Weight %v, want 0", id, w)
		}
	}
}

// A scan that never ran is not a scan that found nothing.
func TestDebugTelemetryProjectionRequiresAPerformedScan(t *testing.T) {
	var in risk.Input
	projectDebugTelemetry(&ArtifactScanSection{DebugAccess: true, Telemetry: true}, &in)
	if in.CapDebugAccess || in.CapTelemetry {
		t.Error("projected from a scan that never ran")
	}
}
