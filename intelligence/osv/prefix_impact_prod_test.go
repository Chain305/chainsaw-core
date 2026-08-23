package osv

import (
	"bufio"
	"os"
	"sort"
	"strings"
	"testing"

	mvn "github.com/masahiro331/go-mvn-version"
)

// oldCompareVersions reproduces compareVersions EXACTLY as it behaved before
// normalizeVersionPrefix / requireNumericLead were added, so the measurement
// below is a real before/after and not an assertion about one.
func oldCompareVersions(ecosystem, a, b string) (int, error) {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	switch CanonicalEcosystem(ecosystem) {
	case "maven", "packagist":
		va, err := mvn.NewVersion(a)
		if err != nil {
			return 0, err
		}
		vb, err := mvn.NewVersion(b)
		if err != nil {
			return 0, err
		}
		return va.Compare(vb), nil
	default:
		// Every other branch either already normalised the prefix
		// (default -> parseSemver) or rejects a bad lead with a real
		// error, so the new code is identical for them. Route through
		// the current implementation.
		return compareVersions(ecosystem, a, b)
	}
}

// TestPrefixImpactOnProdCoordinates measures how many REAL production
// coordinates the comparator fix changes the answer for.
//
// Corpus: every intelligence_reports row whose version does not begin with a
// digit (166 of 6,511 on 2026-08-23), as ecosystem<TAB>version. Each is
// compared against a ladder of plausible advisory bounds — the shapes OSV
// actually publishes — and old vs new answers are diffed.
//
// Opt-in via CHAINSAW_PREFIX_CORPUS so it never gates CI on a snapshot that
// is not in the repo.
func TestPrefixImpactOnProdCoordinates(t *testing.T) {
	path := os.Getenv("CHAINSAW_PREFIX_CORPUS")
	if path == "" {
		t.Skip("set CHAINSAW_PREFIX_CORPUS=<tsv> to measure against a snapshot")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()

	bounds := []string{"1.0.0", "2.0.0", "0.9.0", "1.2.3", "4.17.21", "3.2.2"}

	type stat struct{ changed, nowUndecidable, sameAnswer, bothError int }
	byEco := map[string]*stat{}
	var examples []string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), "\t", 2)
		if len(parts) != 2 {
			continue
		}
		eco, ver := parts[0], parts[1]
		st := byEco[eco]
		if st == nil {
			st = &stat{}
			byEco[eco] = st
		}
		for _, b := range bounds {
			oldV, oldErr := oldCompareVersions(eco, ver, b)
			newV, newErr := compareVersions(eco, ver, b)
			switch {
			case oldErr != nil && newErr != nil:
				st.bothError++
			case oldErr == nil && newErr != nil:
				st.nowUndecidable++
				if len(examples) < 12 {
					examples = append(examples, "UNDECIDABLE now: "+eco+" "+ver+" vs "+b+" (was "+itoa(oldV)+")")
				}
			case oldErr != nil && newErr == nil:
				st.changed++
				if len(examples) < 12 {
					examples = append(examples, "NOW ORDERABLE: "+eco+" "+ver+" vs "+b+" = "+itoa(newV))
				}
			case oldV != newV:
				st.changed++
				if len(examples) < 12 {
					examples = append(examples, "FLIPPED: "+eco+" "+ver+" vs "+b+": "+itoa(oldV)+" -> "+itoa(newV))
				}
			default:
				st.sameAnswer++
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}

	ecos := make([]string, 0, len(byEco))
	for k := range byEco {
		ecos = append(ecos, k)
	}
	sort.Strings(ecos)
	var tc, tu, ts, tb int
	for _, e := range ecos {
		s := byEco[e]
		t.Logf("%-14s changed=%-4d now-undecidable=%-4d same=%-5d both-error=%d",
			e, s.changed, s.nowUndecidable, s.sameAnswer, s.bothError)
		tc += s.changed
		tu += s.nowUndecidable
		ts += s.sameAnswer
		tb += s.bothError
	}
	t.Logf("TOTAL comparisons: changed=%d now-undecidable=%d same=%d both-error=%d", tc, tu, ts, tb)
	for _, e := range examples {
		t.Logf("  %s", e)
	}
}

func itoa(i int) string {
	switch {
	case i < 0:
		return "-1"
	case i > 0:
		return "+1"
	default:
		return "0"
	}
}
