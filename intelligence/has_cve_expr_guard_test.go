package intelligence

import (
	"os"
	"strings"
	"testing"
)

// The "has CVE" facet COUNT and the OnlyHasCVE list filter are the two halves
// of one contract: the sidebar number and the rows it filters must mean the
// same thing. They were two separate string literals, and nothing failed when
// they drifted — which is how the facet came to under-report by more than it
// reported (measured: 423 rows with a transitive CVE vs 339 with a direct one).
//
// This guard counts OCCURRENCES, not presence. A presence check passes with
// any number of hand-written copies, which is the exact failure it is meant to
// catch — the MAX(precedence) guard from the 2026-08-18 wave exists because a
// source grep found two of three call sites and the third shipped.
func TestHasCVEPredicateHasExactlyOneDefinition(t *testing.T) {
	raw, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatalf("read store.go: %v", err)
	}
	src := string(raw)

	// Vacuity: if the const were renamed away, every count below would be
	// 0 and the test would pass having checked nothing.
	if !strings.Contains(src, "const directCVEExpr") {
		t.Fatal("const directCVEExpr is gone — if it was renamed, update this guard; do not delete it")
	}

	// The bare column name appears legitimately in the upsert column list,
	// the ON CONFLICT clause, the search projection and sortToOrderBy's
	// cvss_desc. None of those is a has-CVE PREDICATE, so counting the
	// column name would just be noise.
	//
	// `max_cvss > 0` is the predicate signature, and it must exist exactly
	// once: inside the const. (`COALESCE(max_cvss, 0) DESC` in
	// sortToOrderBy does not match — deliberately, it sorts on a numeric
	// severity a transitive-only row does not have.)
	if got := strings.Count(codeOnly(src), "max_cvss > 0"); got != 1 {
		t.Errorf("store.go contains the predicate `max_cvss > 0` %d time(s) in CODE, want exactly 1 "+
			"(inside const directCVEExpr).\n"+
			"More than one is a hand-written copy of the has-CVE predicate; route it through "+
			"hasCVEExpr instead. Zero means the const stopped being the definition.\n"+
			"The facet and the filter drifting apart is the defect this const exists to prevent.", got)
	}

	// Both consumers must actually reference the const.
	if got := strings.Count(src, "hasCVEExpr"); got < 3 {
		t.Errorf("hasCVEExpr appears %d times, want >=3 (declaration + facet COUNT + OnlyHasCVE filter). "+
			"A consumer that stopped using it has gone back to a private copy.", got)
	}
}

// codeOnly strips whole-line // comments so the count above measures the
// predicate as CODE. The comments around these consts necessarily QUOTE the
// predicate to explain it — counting prose would force the explanation out of
// the file to keep the guard green, which is the wrong trade.
func codeOnly(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
