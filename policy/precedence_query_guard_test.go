package policy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryMaxPrecedenceQueryExcludesExceptionSentinels is a source-level
// guard, and it exists because the obvious approach failed in practice.
//
// Exceptions are stored as policy rows carrying `int(-time.Now().UnixNano())`
// so that List()'s `ORDER BY precedence ASC` returns them first. Any query
// that takes MAX(precedence) to pick "the next free slot" must therefore skip
// them, or it hands the next policy a NEGATIVE precedence and seats it ahead
// of every real rule.
//
// There are THREE such queries — Store.MaxPrecedence, allocateFreePrecedence
// and nextPrecedenceTx — in three files, reached through two different
// executor shapes and written with three different SQL spellings (QueryRow vs
// Query, `?` vs `$1`, COALESCE vs a NullInt64 scan). When the defect was first
// fixed, a source grep for callers of MaxPrecedence found two of the three;
// nextPrecedenceTx was missed and shipped in a build. What caught it was
// running `strings` over the compiled binary and noticing an unfiltered query
// still in the string table.
//
// A shared constant would not have prevented that — a fourth site can be
// written without reaching for it, exactly as the third one was. Only an
// assertion over the source catches a query that simply never opted in. So
// this test reads the package's own .go files and fails on any MAX(precedence)
// SELECT that does not carry the filter.
//
// If you are here because this test failed on a query you just added: the
// answer is almost certainly to add `AND precedence >= 0`. It is `>= 0` and
// not `> 0` on purpose — baseline policies seed at precedence 0
// (system_policies.go), and treating those as absent would restart the
// sequence and collide with them.
func TestEveryMaxPrecedenceQueryExcludesExceptionSentinels(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	// Matches a MAX(precedence) select up to the end of the SQL literal, so
	// the filter has to appear within the same query rather than anywhere
	// later in the file.
	queryRE := regexp.MustCompile("(?i)SELECT[^`\"]*MAX\\(precedence\\)[^`\"]*")

	var scanned, checked int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		// Test files may legitimately assert on the buggy shape (the
		// mutation-style checks in max_precedence_test.go do exactly that).
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		scanned++
		for _, q := range queryRE.FindAllString(string(src), -1) {
			checked++
			if !strings.Contains(strings.ToLower(q), "precedence >= 0") {
				t.Errorf("%s: MAX(precedence) query does not exclude the negative "+
					"exception sentinels:\n\t%s\n"+
					"Add `AND precedence >= 0`. Without it, an org whose only "+
					"policy rows are exceptions yields a negative MAX, and the "+
					"caller's MAX+N default stamps the next policy with a "+
					"negative precedence — seating it ahead of every real rule.",
					name, strings.TrimSpace(q))
			}
		}
	}

	if scanned == 0 {
		t.Fatal("scanned no source files — the guard would pass vacuously")
	}
	// Pin the count so deleting a call site is a deliberate edit here rather
	// than a silent weakening of this guard. Raise it when you add one.
	const wantQueries = 3
	if checked != wantQueries {
		t.Errorf("found %d MAX(precedence) queries, expected %d. "+
			"If you added or removed one, update this count deliberately — "+
			"the guard is only as strong as the set of queries it sees.",
			checked, wantQueries)
	}
}
