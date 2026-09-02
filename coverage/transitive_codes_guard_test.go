package coverage

import (
	"os"
	"regexp"
	"testing"
)

// cacheUnusableCodes are the transitive-dep warn codes that mean "the walk
// could not obtain a usable row for this dependency, so it skipped it" —
// whether the row was absent, retired by an epoch bump, or unreadable
// because the store itself failed. They are one family and must classify
// identically: the walk cannot tell the difference in its output, and
// neither can an operator downstream of it.
//
// The failure mode guarded here is silent and one-directional. An
// unregistered code falls through to StatusError, and StatusError never
// blocks — so splitting one of these into two, or adding a new skip reason,
// converts a blocking condition into a non-blocking one for every org
// running core/coverage in mode: closed. Nothing else notices: the warning
// still renders and the verdict still computes; only an opted-in org's gate
// quietly stops firing.
//
// Not hypothetical — transitive_dep_superseded was split out of
// transitive_dep_not_cached and would have shipped unregistered.
var cacheUnusableCodes = []string{
	"transitive_dep_not_cached",
	"transitive_dep_superseded",
	"transitive_dep_lookup_error",
}

func TestCacheUnusableTransitiveCodesBlock(t *testing.T) {
	for _, code := range cacheUnusableCodes {
		if got := StatusForWarnCode(code); got != StatusUnavailable {
			t.Errorf("warn code %q classifies as %s, want %s.\n"+
				"A dependency whose cached row could not be used means the source was\n"+
				"not reached. Unregistered makes it StatusError, which NEVER blocks, so\n"+
				"an org running core/coverage in mode: closed stops gating on it.\n"+
				"Add it to unavailableCodes in status.go.",
				code, got, StatusUnavailable)
		}
	}
}

// A new WarnTransitiveDep* constant must be consciously classified. This
// does not assert WHICH status — two of the existing four are deliberately
// not unavailable — only that someone made a decision, recorded here.
//
// Current dispositions, and why they are not all the same:
//
//   - transitive_dep_not_cached / _superseded / _lookup_error → unavailable.
//     The walk could not obtain a usable row: absent, retired by an epoch
//     bump, or unreadable because the store errored. In each case the source
//     was effectively not reached.
//   - transitive_dep_constraint_conflict → ok, deliberately. The dependency
//     resolved and the row was read; the walk excluded the node because the
//     root's own declared constraint forbids that version. The source was
//     reached and answered — this is the walk being right, not blind.
//   - transitive_dep_constraint_unparseable → NOT unavailable, deliberately.
//     A non-semver constraint is a fact about the manifest, not an outage,
//     and gating on it would refuse every package using a constraint syntax
//     the resolver does not model. This is the one member of the group that
//     is genuinely a data property rather than an availability property.
//
// Source-scanning because core/coverage deliberately does not import
// core/intelligence — the codes are compared as strings, which is exactly
// why they can drift apart.
func TestEveryTransitiveDepWarnCodeHasADisposition(t *testing.T) {
	known := map[string]Status{
		"transitive_dep_not_cached":             StatusUnavailable,
		"transitive_dep_superseded":             StatusUnavailable,
		"transitive_dep_constraint_unparseable": StatusError,
		"transitive_dep_lookup_error":           StatusUnavailable,
		// transitive_dep_constraint_conflict -> StatusOK, deliberately.
		// The store answered and the row was read; the walk then dropped
		// the node because the ROOT's own manifest forbids that version.
		// That is a correct exclusion, not a coverage gap, and calling it
		// unavailable would turn the fix for P8-08's false blame into a
		// false block for any org in mode: closed.
		"transitive_dep_constraint_conflict": StatusOK,
	}
	const reportGo = "../intelligence/report.go"
	src, err := os.ReadFile(reportGo)
	if err != nil {
		t.Fatalf("read %s: %v", reportGo, err)
	}
	re := regexp.MustCompile(`WarnTransitiveDep\w*\s*=\s*"([^"]+)"`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) == 0 {
		t.Fatalf("no WarnTransitiveDep* constants found in %s — the regex has rotted "+
			"and this guard is silently passing", reportGo)
	}
	for _, m := range matches {
		code := m[1]
		want, ok := known[code]
		if !ok {
			t.Errorf("warn code %q has no recorded disposition.\n"+
				"Decide whether it should block (unavailable) or not, add it to\n"+
				"unavailableCodes/okCodes/notApplicableCodes in status.go as\n"+
				"appropriate, and record it in this test's table. Leaving it\n"+
				"unregistered silently means NEVER BLOCKS.", code)
			continue
		}
		if got := StatusForWarnCode(code); got != want {
			t.Errorf("warn code %q classifies as %s, recorded disposition is %s — "+
				"one of the two moved; reconcile deliberately", code, got, want)
		}
	}
}

// End-to-end: a store failure while resolving a dependency must reach a
// BLOCK for an org running mode: closed. The classification table is only
// meaningful if it actually moves the gate, and this code spent its whole
// life on the non-blocking side — the classification change is the fix, so
// the gate behaviour is what the fix is FOR.
func TestStoreErrorOnADependencyBlocksAClosedGate(t *testing.T) {
	led := Ledger{SourceCVE: fresh(StatusForWarnCode("transitive_dep_lookup_error"))}
	d := Gate(closedPosture(SourceCVE), led, testNow)
	if !d.Block {
		t.Fatalf("a store failure resolving a dependency did not block a closed gate: %+v\n"+
			"transitive_dep_lookup_error means the intelligence store returned a real\n"+
			"error, so the source was not reached. Its benign sibling\n"+
			"transitive_dep_not_cached already blocks; the severe case must not be\n"+
			"the permissive one.", d)
	}
}

// The counterpart: an unparseable constraint is a fact about the manifest,
// not an outage, and must NOT block. Pins the boundary from the other side
// so a future widening of the unavailable set cannot quietly swallow it.
func TestUnparseableConstraintDoesNotBlockAClosedGate(t *testing.T) {
	led := Ledger{SourceCVE: fresh(StatusForWarnCode("transitive_dep_constraint_unparseable"))}
	if d := Gate(closedPosture(SourceCVE), led, testNow); d.Block {
		t.Errorf("an unparseable dependency constraint blocked a closed gate: %+v\n"+
			"That would refuse every package using a constraint syntax the resolver\n"+
			"does not model — a data property, not an availability one.", d)
	}
}
