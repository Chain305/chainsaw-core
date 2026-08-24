package builtin

import (
	"context"
	"os"
	"strings"
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

// TestDegradedAnalysisMessageCoversBothCauses pins a property the
// message text must keep, because nothing else did and it was wrong once.
//
// input.signalsUnavailable is ONE bool set by two different facts:
// acquireIncomplete (the analyzer could not finish) and
// acquireDigestMismatch (it finished, and the bytes disagreed with the
// lockfile anchor). Rego cannot distinguish them, so any message that
// asserts which one happened is false half the time. The original text
// said "the bytes were not fully inspected" — false for a mismatch,
// where the bytes were read in full and were simply the wrong bytes.
//
// This asserts the shape, not the wording: the message must not claim
// the bytes went unread. Rewording is fine; re-narrowing is not.
func TestDegradedAnalysisMessageCoversBothCauses(t *testing.T) {
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
	if len(dec.Violations) != 1 {
		t.Fatalf("want exactly the builtin violation, got %+v", dec.Violations)
	}
	msg := strings.ToLower(dec.Violations[0].Message)

	// Phrases that assert the analyzer never read the bytes. Each is
	// false on the digest-mismatch path.
	for _, banned := range []string{
		"not fully inspected",
		"were not inspected",
		"never inspected",
		"not read",
	} {
		if strings.Contains(msg, banned) {
			t.Errorf("message claims the bytes went unread (%q), which is false for a digest mismatch: %q",
				banned, dec.Violations[0].Message)
		}
	}
	// And it must still say something actionable about installation.
	if !strings.Contains(msg, "install") {
		t.Errorf("message should tell the operator this is about what gets installed, got %q", dec.Violations[0].Message)
	}
}
