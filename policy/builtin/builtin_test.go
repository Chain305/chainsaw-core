package builtin

import (
	"context"
	"os"
	"testing"

	"github.com/chain305/chainsaw-core/policy"
	"github.com/chain305/chainsaw-core/policy/dsl"
)

// TestBuiltinCompiles is the tripwire that matters most: the embedded
// bundle is compiled at process start on every guard invocation, so a
// syntax error here is a startup failure for every user. It must fail
// in CI, not in the field.
func TestBuiltinCompiles(t *testing.T) {
	eng, err := Engine(context.Background(), nil)
	if err != nil {
		t.Fatalf("built-in bundle must compile: %v", err)
	}
	if eng.Empty() {
		t.Fatal("built-in bundle compiled to an empty engine — go:embed likely lost the file")
	}
}

// TestDegradedAnalysisMonitorsNotBlocks pins the default posture. A
// degraded analysis must be VISIBLE and must not hard-fail an install:
// blocking by default would break every machine whose package cache is
// large enough to exhaust the walk budget. An operator opts into
// fail-closed by shipping a stricter rule.
func TestDegradedAnalysisMonitorsNotBlocks(t *testing.T) {
	eng, err := Engine(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := eng.Decide(context.Background(), policy.Input{
		Surface:            policy.SurfaceRuntime,
		PackageName:        "some-pkg",
		PackageVersion:     "1.0.0",
		SignalsUnavailable: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != dsl.ActionMonitor {
		t.Fatalf("degraded analysis must monitor by default, got %q — blocking by default breaks installs on any large cache", dec.Action)
	}
	if len(dec.Violations) != 1 || dec.Violations[0].RuleID != "builtin/degraded-analysis" {
		t.Fatalf("expected the builtin/degraded-analysis violation, got %+v", dec.Violations)
	}
}

// TestCleanInputAllows guards the other direction: the built-in bundle
// must be silent on a normal package. A default policy that fires on
// everything is worse than no default policy — it trains users to
// ignore the guard.
func TestCleanInputAllows(t *testing.T) {
	eng, err := Engine(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := eng.Decide(context.Background(), policy.Input{
		Surface:        policy.SurfaceRuntime,
		PackageName:    "lodash",
		PackageVersion: "4.17.21",
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != dsl.ActionAllow {
		t.Fatalf("clean input must allow, got %q with %+v", dec.Action, dec.Violations)
	}
}

// TestOperatorBundleCompilesAlongside pins the ordering contract: the
// built-in bundle is compiled WITH an operator's sources, not instead
// of them, so shipping a bundle never silently drops the defaults.
func TestOperatorBundleCompilesAlongside(t *testing.T) {
	dir := t.TempDir()
	writeRego(t, dir, "op.rego", `package chainsaw.policy

decision contains {
	"action":  "block",
	"rule_id": "operator/no-lodash",
	"message": "operator rule",
} if {
	input.package == "lodash"
}
`)
	eng, err := Engine(context.Background(), []string{dir})
	if err != nil {
		t.Fatalf("operator bundle + builtin must compile together: %v", err)
	}
	// Operator rule fires.
	dec, err := eng.Decide(context.Background(), policy.Input{
		Surface: policy.SurfaceRuntime, PackageName: "lodash", PackageVersion: "4.17.21",
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != dsl.ActionBlock {
		t.Fatalf("operator rule must fire, got %q", dec.Action)
	}
	// Built-in rule still fires too — shipping a bundle does not drop defaults.
	dec, err = eng.Decide(context.Background(), policy.Input{
		Surface: policy.SurfaceRuntime, PackageName: "other", PackageVersion: "1.0.0",
		SignalsUnavailable: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != dsl.ActionMonitor {
		t.Fatalf("built-in rule must survive an operator bundle, got %q", dec.Action)
	}
}

func writeRego(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := writeFile(dir, name, body); err != nil {
		t.Fatal(err)
	}
}

func writeFile(dir, name, body string) error {
	return os.WriteFile(dir+"/"+name, []byte(body), 0o644)
}
