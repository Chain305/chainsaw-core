package risk

// input_consumed_test.go — the rail for this repo's signature defect: a
// field that is declared, populated, documented as doing a job, and read by
// nobody.
//
// ─── THE SPECIMEN ───────────────────────────────────────────────────────────
//
// Input.VersionDataAvailable was declared (input.go), projected on every
// scan (intelligence/risk_projection.go), and UNIT-TESTED FOR BEING SET
// (intelligence/risk_projection_test.go). Its doc comment named the exact
// false positive it prevented: "Prevents the `maint.very_new_package`
// false-positive that fires when the sparse proxy-driven store returns 0
// versions for a popular package."
//
// No signal in core/risk ever read it. The false positive it named was live
// in production for the entire time, and an auditor reading the field, its
// comment and its passing unit test would have concluded the opposite.
//
// That is why the existing test — "the projection sets the flag correctly" —
// is the wrong test. It certifies the half that was never broken. The two
// tests below check the half that was:
//
//	TestVeryNewPackageDormantWithoutVersionData  — behaviour: the flag CHANGES
//	                                               the verdict on the signal.
//	TestEveryInputFieldHasAConsumer              — structure: no NEW field may
//	                                               join the unconsumed set.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestVeryNewPackageDormantWithoutVersionData drives the real signal, not a
// mock, through all four corners of the (VersionDataAvailable, VersionCount)
// square. Delete the `!in.VersionDataAvailable` guard in
// registry_maintenance.go and case 2 fails.
func TestVeryNewPackageDormantWithoutVersionData(t *testing.T) {
	var sig Signal
	for _, s := range AllSignals() {
		if s.ID == SignalMaintVeryNewPackage {
			sig = s
		}
	}
	if sig.Fires == nil {
		t.Fatalf("%s is not registered", SignalMaintVeryNewPackage)
	}
	young := time.Now().Add(-24 * time.Hour)

	cases := []struct {
		name      string
		available bool
		count     int
		want      bool
		why       string
	}{
		{
			name: "no version data at all -> dormant", available: false, count: 0, want: false,
			why: "THE REGRESSION. VersionCount 0 with no timeline means \"we do not know\", " +
				"not \"this package has no history\". Asserting a −10 maintenance penalty " +
				"on an unknown is the false positive Input.VersionDataAvailable's own doc " +
				"comment promises to prevent — and which was live until the guard landed.",
		},
		{
			name: "version data present, genuinely few versions -> fires", available: true, count: 1, want: true,
			why: "The signal's real job. A one-version package published yesterday IS new; " +
				"the guard must not silence this or the fix would be a deletion.",
		},
		{
			name: "version data present, long history -> dormant", available: true, count: 200, want: false,
			why: "boto3's shape. This is the case the harness could not reach while " +
				"VersionCount was pinned at 0, which is how 41% of the top PyPI downloads " +
				"came to be reported as \"very new\".",
		},
		{
			name: "no version data but a count leaked in -> dormant", available: false, count: 200, want: false,
			why: "Belt and braces: the availability flag is checked BEFORE the count, so an " +
				"inconsistent projection cannot re-open the hole from the other side.",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := Input{
				PublishedAt:          &young,
				VersionDataAvailable: c.available,
				VersionCount:         c.count,
			}
			got, _, _ := sig.Fires(in)
			if got != c.want {
				t.Errorf("fired=%v, want %v\n  %s", got, c.want, c.why)
			}
		})
	}
}

// unconsumedInputFields is the DECLARED set of risk.Input fields that no
// signal or evaluator in core/risk reads.
//
// It is not an allowlist of things that are fine. Every entry is a field the
// pipeline pays to compute and then discards, and three of them have doc
// comments asserting a consumer that does not exist. It ships populated
// because deleting the fields is a separate decision with its own blast
// radius (they are part of a public struct, and several are persisted in
// report JSON); what this test buys is that the set cannot GROW silently,
// which is exactly how VersionDataAvailable got here.
//
// Remove an entry when you wire the field up. Adding one requires writing
// down why the field is computed at all.
var unconsumedInputFields = map[string]string{
	"HasSourceRepo": "Projected at risk_projection.go from URLs.SourceRepoURL. The legacy " +
		"core/trustscore engine reads a same-named field on a DIFFERENT struct " +
		"(trustscore.Signals), which is why this reads as wired and is not.",
	"FirstPublishedAt": "Projected from Maintenance.FirstPublishedAt, which core's " +
		"applyTimeline computes on every scan. It is the field that would let " +
		"maint.very_new_package age the PACKAGE rather than the resolved VERSION — " +
		"the mechanism the Phase 8 baseline guessed at. Nothing reads it.",
	"Stars": "COMMENT ASSERTS A CONSUMER THAT DOES NOT EXIST: input.go says Stars/Forks/" +
		"OpenIssues/Subscribers are \"Used by quality-grade signals that mirror Socket's " +
		"stargazer/fork/watcher dimensions\". No such signal is registered. Worse, these " +
		"four are populated by enrichRepoStars, which makes a live GitHub/GitLab/" +
		"Bitbucket/Codeberg API call per scan — a paid-for round trip that is discarded.",
	"Forks":       "See Stars.",
	"OpenIssues":  "See Stars.",
	"Subscribers": "See Stars.",
	"ArtifactSubtype": "Projected from Identity.ArtifactSubtype. The AI-artifact signals " +
		"discriminate on their own inputs rather than on the subtype, so the field is " +
		"carried for consumers outside core/risk.",
	"TransitiveMediumCount": "Written by provider_transitiverisk.go alongside the Critical/" +
		"High/Malware counts, which ARE read. Only the Medium/Low/Blocked tallies have no " +
		"signal — a deliberate severity floor, or three forgotten fields; the registration " +
		"comment does not say which.",
	"TransitiveLowCount":     "See TransitiveMediumCount.",
	"TransitiveBlockedCount": "See TransitiveMediumCount.",
}

// inputFieldRe matches an exported field declaration inside `type Input struct`.
var inputFieldRe = regexp.MustCompile(`(?m)^\t([A-Z][A-Za-z0-9_]*)\s+[^/\s]`)

// stripGoComments removes // and /* */ comments so that a field MENTIONED in
// prose does not read as a field CONSUMED in code.
//
// This is not defensive tidiness — it is the fix for a real hole this guard
// shipped with for about ten minutes. The very-new-package fix carries a long
// comment explaining what Input.VersionDataAvailable is for, and that comment
// contains the literal text ".VersionDataAvailable". With comments left in,
// deleting the actual `if !in.VersionDataAvailable` guard still left the
// selector "present", so the negative control passed with the guard removed:
// a rail against unconsumed fields that was itself satisfied by a sentence.
//
// Byte-level, not a real lexer, because a string literal containing "//" would
// only ever cause this to drop code and report a field as dead, which fails
// loudly, whereas the opposite direction fails silently.
func stripGoComments(src string) string {
	var out strings.Builder
	out.Grow(len(src))
	for i := 0; i < len(src); {
		switch {
		case strings.HasPrefix(src[i:], "//"):
			j := strings.IndexByte(src[i:], '\n')
			if j < 0 {
				return out.String()
			}
			i += j // leave the newline for the next iteration
		case strings.HasPrefix(src[i:], "/*"):
			j := strings.Index(src[i+2:], "*/")
			if j < 0 {
				return out.String()
			}
			i += 2 + j + 2
		default:
			out.WriteByte(src[i])
			i++
		}
	}
	return out.String()
}

// TestEveryInputFieldHasAConsumer scans core/risk's own non-test sources for
// a reader of each Input field and fails on any field that has none and is
// not declared above.
//
// A source scan rather than reflection, because "is this field read" is a
// question about code, not about values: a field can be read on some inputs
// and not others, and no amount of evaluating the engine proves the absence.
func TestEveryInputFieldHasAConsumer(t *testing.T) {
	inputSrc, err := os.ReadFile("input.go")
	if err != nil {
		t.Skipf("input.go not readable from the test's working directory: %v", err)
	}
	m := regexp.MustCompile(`(?s)type Input struct \{(.*?)\n\}`).FindStringSubmatch(string(inputSrc))
	if m == nil {
		t.Fatal("could not locate `type Input struct` in input.go — the guard went blind")
	}
	var fields []string
	for _, f := range inputFieldRe.FindAllStringSubmatch(m[1], -1) {
		fields = append(fields, f[1])
	}
	if len(fields) < 50 {
		t.Fatalf("only %d Input fields parsed; the struct has far more — inputFieldRe "+
			"stopped matching and this guard would pass vacuously", len(fields))
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var body strings.Builder
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") || name == "input.go" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		body.WriteString(stripGoComments(string(b)))
		body.WriteByte('\n')
	}
	src := body.String()

	var undeclaredDead, staleDeclarations []string
	for _, f := range fields {
		// Any selector ending in the field name counts as a read. Deliberately
		// loose: a false "it is consumed" only makes this guard quieter, while
		// a false "it is dead" would send someone deleting a live field.
		read := regexp.MustCompile(`\.` + f + `\b`).MatchString(src)
		_, declared := unconsumedInputFields[f]
		switch {
		case !read && !declared:
			undeclaredDead = append(undeclaredDead, f)
		case read && declared:
			staleDeclarations = append(staleDeclarations, f)
		}
	}

	sort.Strings(undeclaredDead)
	sort.Strings(staleDeclarations)
	if len(undeclaredDead) > 0 {
		t.Errorf("%d Input field(s) are projected on every scan and read by NOTHING in "+
			"core/risk: %s\n"+
			"This is the VersionDataAvailable shape: a field that looks wired, is unit-tested "+
			"for being set, and changes no outcome. Either wire it to a signal, delete it, or "+
			"add it to unconsumedInputFields with the reason it is computed at all.",
			len(undeclaredDead), strings.Join(undeclaredDead, ", "))
	}
	if len(staleDeclarations) > 0 {
		t.Errorf("%d field(s) in unconsumedInputFields now HAVE a reader: %s — "+
			"good news; delete the entries so the list keeps meaning what it says.",
			len(staleDeclarations), strings.Join(staleDeclarations, ", "))
	}

	// The specimen, pinned by name. If VersionDataAvailable ever loses its
	// reader again, this says so in one line rather than leaving it to the
	// set-difference above.
	if !regexp.MustCompile(`\.VersionDataAvailable\b`).MatchString(src) {
		t.Error("Input.VersionDataAvailable has no reader in core/risk again. Its doc " +
			"comment promises it prevents the maint.very_new_package false positive; " +
			"without a reader that promise is false and the FP is live. See " +
			"registry_maintenance.go's very-new-package guard.")
	}
}
