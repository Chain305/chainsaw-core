package cli

import (
	"os"
	"strings"
	"testing"
)

// TestDocumentedByteScanShapesAreProducible pins core/README.md's guard
// transcripts to the strings byteScanNotice() can actually emit.
//
// This guards the exact defect that made the notice wrong in the first place
// (P8-68). The old notice was built from environment variables read once per
// process, before any package was examined, so it asserted something the code
// never checked -- and three documentation surfaces went on quoting it after the
// code changed, including a launch-proof report that scoped a published
// catch-rate figure on the strength of it.
//
// A doc that quotes a string the binary cannot produce is the same class of
// claim-without-a-check. Pinning the shapes is cheap; discovering the drift from
// a customer transcript is not.
//
// Deliberately NOT asserted here: the surrounding prose. This checks that every
// shape the doc shows is real, not that the doc's explanation of when each fires
// is correct -- that judgement does not reduce to a string compare, and a test
// pretending otherwise would be its own false assurance.
func TestDocumentedByteScanShapesAreProducible(t *testing.T) {
	readme, err := os.ReadFile("../README.md")
	if err != nil {
		// The standalone core checkout may not carry it; skip rather than fail,
		// matching findMatrixMarkdown's convention elsewhere in this repo.
		t.Skipf("core/README.md not readable: %v", err)
	}
	doc := string(readme)

	for _, tc := range []struct {
		name                string
		attempted, analyzed int
	}{
		{"all packages analyzed", 12, 12},
		{"partial coverage", 12, 5},
		{"no local bytes", 12, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &localGuard{scanAttempted: tc.attempted, scanAnalyzed: tc.analyzed}
			want := g.byteScanNotice()
			if want == "" {
				t.Fatalf("byteScanNotice() returned empty for attempted=%d analyzed=%d",
					tc.attempted, tc.analyzed)
			}
			// The README elides the long remediation tail of the third shape
			// with "(…)" so the transcript stays readable; compare up to it.
			probe := want
			if i := strings.Index(probe, "; using name/feed/typosquat checks only"); i >= 0 {
				probe = probe[:i] + "; using name/feed/typosquat checks only (…)"
			}
			if !strings.Contains(doc, probe) {
				t.Errorf("core/README.md does not quote a shape byteScanNotice() emits.\n"+
					"  emitted: %s\n"+
					"  Update the README transcript, or the docs now describe a binary that does not exist.", probe)
			}
		})
	}
}

// TestNameLaneRefusalEmitsNoByteScanNotice pins the absence documented in
// core/README.md's first transcript.
//
// A typosquat or feed refusal returns from evaluate() before guardArtifactBytes
// is reached, so scanAttempted stays 0 and the notice is empty. The README says
// that absence is meaningful -- "not reached", not "not covered" -- and a future
// refactor that moved the counter above the name lanes would silently turn that
// documented absence into a "no local bytes" claim about a package whose bytes
// were never sought.
func TestNameLaneRefusalEmitsNoByteScanNotice(t *testing.T) {
	g := &localGuard{}
	if got := g.byteScanNotice(); got != "" {
		t.Errorf("byteScanNotice() with nothing acquired = %q, want empty;\n"+
			"a run refused on the name lane must make no claim about bytes it never sought", got)
	}
}
