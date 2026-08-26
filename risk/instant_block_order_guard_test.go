package risk

// Source-level guard for the P8-44 ORDERING INVARIANT: inside
// EvaluatePackage, the instant-block check must be reached BEFORE the
// SignalsUnavailable branch returns UnavailableEvaluation.
//
// Why this is a source assertion and not only a behavioural test. What
// broke was an ORDER, not a computation, and an order is what a refactor
// reverts silently. Every other test in this package passes with the two
// branches swapped — the malware verdict simply stops arriving, and a
// package the malware feed knows by name reports NOT EVALUATED. The
// behavioural companion (TestInstantBlockPrecedesUnavailable, in
// instant_block_unavailable_test.go) proves the outcome today; this proves
// the shape that produces it cannot be quietly rearranged.
//
// If this failed on an edit you just made: the SignalsUnavailable branch
// must consult instantBlockEvaluation before it returns
// UnavailableEvaluation. Do NOT satisfy it by setting
// SignalsUnavailable=false and letting the full signal set run — with an
// empty Report, lic.missing and license.unidentified fire on nothing and
// regenerate the fake 86/92 scores this wave removed.

import (
	"os"
	"strings"
	"testing"
)

func TestInstantBlockOrderingIsStructural(t *testing.T) {
	src, err := os.ReadFile("evaluator.go")
	if err != nil {
		t.Fatalf("read evaluator.go: %v", err)
	}
	body, ok := riskFuncBody(string(src), "func EvaluatePackage(")
	if !ok {
		t.Fatal("EvaluatePackage not found in evaluator.go — update this guard")
	}

	instantAt := strings.Index(body, "instantBlockEvaluation(")
	if instantAt < 0 {
		t.Fatal("EvaluatePackage no longer calls instantBlockEvaluation — a " +
			"known-malicious package whose version was never published is " +
			"back to NOT EVALUATED (P8-44)")
	}
	unavailAt := strings.Index(body, "return UnavailableEvaluation(")
	if unavailAt < 0 {
		t.Fatal("EvaluatePackage no longer returns UnavailableEvaluation — update this guard")
	}
	if instantAt > unavailAt {
		t.Fatal("the SignalsUnavailable return precedes the instant-block check in " +
			"EvaluatePackage — the malware verdict is computed, merged, and then " +
			"discarded (P8-44)")
	}

	// The instant-block walk must stay restricted to the instant-block
	// ids. Widening it to runPrimitiveSignals on the unavailable path is
	// the rejected fix: it scores an empty Report.
	ib, ok := riskFuncBody(string(src), "func instantBlockEvaluation(")
	if !ok {
		t.Fatal("instantBlockEvaluation not found — update this guard")
	}
	if strings.Contains(ib, "runPrimitiveSignals(") {
		t.Fatal("instantBlockEvaluation runs the FULL signal set — on an Input " +
			"whose facts were never fetched that reproduces the fake clean " +
			"scores this wave removed (P8-44)")
	}
	if !strings.Contains(ib, "runNamedPrimitiveSignals(") {
		t.Fatal("instantBlockEvaluation no longer restricts itself to the " +
			"instant-block signals — update this guard deliberately, not by reflex")
	}
}

func riskFuncBody(src, decl string) (string, bool) {
	i := strings.Index(src, decl)
	if i < 0 {
		return "", false
	}
	open := strings.Index(src[i:], "{")
	if open < 0 {
		return "", false
	}
	open += i
	depth := 0
	for j := open; j < len(src); j++ {
		switch src[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open+1 : j], true
			}
		}
	}
	return "", false
}
