package risk

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The advertised signal count is published in four places — core/README.md
// (twice), core/docs/signals.md (a headline, a category table and one
// heading per section) and core/docs/README.md — and nothing joined any of
// them to the registry. Worse, signals.md and core/docs/README.md both
// claimed the page was "generated from risk/registry.go"; there is no
// generator anywhere in the tree, so the claim was doing the work of a
// guard without being one. Adding a real generator would mean owning the
// hand-written "What it means" column, so instead the numbers are pinned
// here and the false generation claim was removed from the prose.
//
// Modeled on core/policy.TestSupportMatrixMatchesMarkdown, including its
// t.Skipf-when-absent convention.

// docCategoryLabels maps the human labels used in the published tables to
// the registry Category constants. A label the docs use that is missing
// here fails the test rather than being silently skipped — that is how a
// renamed category would otherwise slip through.
var docCategoryLabels = map[string]Category{
	"supply chain":  CategorySupplyChain,
	"vulnerability": CategoryVulnerability,
	"licence":       CategoryLicense,
	"license":       CategoryLicense,
	"maintenance":   CategoryMaintenance,
	"quality":       CategoryQuality,
}

func signalCounts() (total int, byCategory map[Category]int) {
	byCategory = map[Category]int{}
	all := AllSignals()
	for _, s := range all {
		byCategory[s.Category]++
	}
	return len(all), byCategory
}

// findCoreDoc walks up from the test's working directory looking for a
// path relative to the core/ module root, so the test works both in the
// monorepo (core/risk) and in a standalone chainsaw-core checkout (risk/).
func findCoreDoc(t *testing.T, rel string) string {
	t.Helper()
	start, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := start
	for i := 0; i < 6; i++ {
		for _, prefix := range []string{"", "core"} {
			candidate := filepath.Join(dir, prefix, rel)
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skipf("%s not found above %s — doc-consistency check skipped", rel, start)
	return ""
}

func readCoreDoc(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(findCoreDoc(t, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// TestSignalCountMatchesMarkdown asserts every published signal count
// agrees with len(AllSignals()) and the per-category tallies.
func TestSignalCountMatchesMarkdown(t *testing.T) {
	total, byCategory := signalCounts()
	if total == 0 {
		t.Fatal("registry is empty — did the risk signal init() blocks fail to run?")
	}

	// Every "N risk signals" / "N signals are registered" / "All N with"
	// phrasing across the three published pages. The regexes are written
	// against the sentence, not the number, so a doc that rewords keeps
	// being checked and a doc that drops the sentence entirely is caught
	// by the per-file minimum below.
	headline := []struct {
		file string
		re   *regexp.Regexp
		min  int
	}{
		{"README.md", regexp.MustCompile(`\*\*(\d+) risk signals`), 1},
		{"README.md", regexp.MustCompile(`\*\*(\d+) signals are registered\*\*`), 1},
		{"README.md", regexp.MustCompile(`\*\*All (\d+) with severities`), 1},
		{"docs/signals.md", regexp.MustCompile(`registers \*\*(\d+) risk signals\*\*`), 1},
		{"docs/README.md", regexp.MustCompile(`All (\d+) risk signals`), 1},
	}
	for _, h := range headline {
		body := readCoreDoc(t, h.file)
		ms := h.re.FindAllStringSubmatch(body, -1)
		if len(ms) < h.min {
			t.Errorf("%s: no match for %v — the sentence that carries the signal count was reworded or removed, "+
				"so this guard silently stopped guarding it; re-point the regex", h.file, h.re)
			continue
		}
		for _, m := range ms {
			got, err := strconv.Atoi(m[1])
			if err != nil {
				t.Fatalf("%s: %v", h.file, err)
			}
			if got != total {
				t.Errorf("%s says %d signals (%q) but len(AllSignals())==%d", h.file, got, m[0], total)
			}
		}
	}

	// docs/signals.md carries a "| Category | Signals |" table plus a
	// "**Total**" row.
	signalsDoc := readCoreDoc(t, "docs/signals.md")
	checkCategoryTable(t, "docs/signals.md", signalsDoc,
		regexp.MustCompile(`(?m)^\|\s*([A-Za-z ]+?)\s*\|\s*(\d+)\s*\|\s*$`), byCategory)
	if m := regexp.MustCompile(`\|\s*\*\*Total\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|`).FindStringSubmatch(signalsDoc); m == nil {
		t.Error("docs/signals.md: category table has no **Total** row any more")
	} else if got, _ := strconv.Atoi(m[1]); got != total {
		t.Errorf("docs/signals.md category table Total says %d, registry has %d", got, total)
	}

	// core/README.md carries a "| Category | Count | Examples |" table.
	checkCategoryTable(t, "README.md", readCoreDoc(t, "README.md"),
		regexp.MustCompile(`(?m)^\|\s*([A-Za-z ]+?)\s*\|\s*(\d+)\s*\|`), byCategory)

	// docs/signals.md section headings, e.g. "## Supply chain (48)".
	headings := regexp.MustCompile(`(?m)^##\s+([A-Za-z ]+?)\s*\((\d+)\)\s*$`).FindAllStringSubmatch(signalsDoc, -1)
	if len(headings) == 0 {
		t.Error("docs/signals.md: no `## Category (N)` headings found — the layout changed and this guard went blind")
	}
	seen := map[Category]bool{}
	for _, m := range headings {
		cat, ok := docCategoryLabels[strings.ToLower(m[1])]
		if !ok {
			t.Errorf("docs/signals.md: heading %q names a category with no registry constant", m[1])
			continue
		}
		seen[cat] = true
		got, _ := strconv.Atoi(m[2])
		if got != byCategory[cat] {
			t.Errorf("docs/signals.md heading %q says %d, registry has %d", m[0], got, byCategory[cat])
		}
		// The heading count must also equal the rows actually printed
		// under it — a correct number above a short table is still a lie.
		if rows := rowsUnderHeading(signalsDoc, m[0]); rows != byCategory[cat] {
			t.Errorf("docs/signals.md section %q lists %d signal rows but the registry has %d in that category",
				m[0], rows, byCategory[cat])
		}
	}
	for cat := range byCategory {
		if !seen[cat] {
			t.Errorf("docs/signals.md has no section for registry category %q — a whole category is undocumented", cat)
		}
	}
}

// checkCategoryTable validates every `| Label | N |` row whose label maps
// to a registry category, and asserts each category appears exactly once.
func checkCategoryTable(t *testing.T, file, body string, re *regexp.Regexp, byCategory map[Category]int) {
	t.Helper()
	found := map[Category]bool{}
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		cat, ok := docCategoryLabels[strings.ToLower(strings.TrimSpace(m[1]))]
		if !ok {
			continue // an unrelated two-column table row
		}
		if found[cat] {
			t.Errorf("%s: category %q counted twice in a table", file, cat)
		}
		found[cat] = true
		got, _ := strconv.Atoi(m[2])
		if got != byCategory[cat] {
			t.Errorf("%s: table says %s = %d, registry has %d", file, cat, got, byCategory[cat])
		}
	}
	var missing []string
	for cat := range byCategory {
		if !found[cat] {
			missing = append(missing, string(cat))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%s: category table omits %s", file, strings.Join(missing, ", "))
	}
}

// rowsUnderHeading counts the `| `id` | ...` table rows between a heading
// and the next `## `.
func rowsUnderHeading(body, heading string) int {
	i := strings.Index(body, heading)
	if i < 0 {
		return -1
	}
	rest := body[i+len(heading):]
	if j := strings.Index(rest, "\n## "); j >= 0 {
		rest = rest[:j]
	}
	n := 0
	for _, line := range strings.Split(rest, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "| `") {
			n++
		}
	}
	return n
}

// TestSignalDocsDoNotClaimToBeGenerated is the companion negative rail.
// signals.md said "This page is generated from risk/registry.go" and
// core/docs/README.md said the same; no generator exists. A false
// generation claim is worse than no claim — it tells the next reader that
// drift is impossible, so nobody looks. If a real generator is ever added,
// delete this test along with the manual table.
func TestSignalDocsDoNotClaimToBeGenerated(t *testing.T) {
	gens := []string{"cmd/gen-signals-docs", "../cmd/gen-signals-docs", "../../cmd/gen-signals-docs"}
	for _, g := range gens {
		if _, err := os.Stat(g); err == nil {
			t.Skipf("%s exists — a real generator landed; retire this test and the manual tables", g)
		}
	}
	for _, rel := range []string{"docs/signals.md", "docs/README.md"} {
		body := readCoreDoc(t, rel)
		for _, claim := range []string{
			"is generated from",
			"generated from the registry",
			"generated from the\nGo source",
		} {
			if idx := strings.Index(body, claim); idx >= 0 {
				// Only complain when the claim is about signals.md.
				window := body[max(0, idx-160):min(len(body), idx+160)]
				if strings.Contains(window, "registry.go") || strings.Contains(window, "signals.md") {
					t.Errorf("%s claims %q near %q, but no signals generator exists in the tree; "+
						"say the numbers are drift-tested instead",
						rel, claim, strings.TrimSpace(collapse(window)))
				}
			}
		}
	}
}

func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

// signalRowRe matches one published signal row in core/docs/signals.md:
//
//	| `sc.shrinkwrap_present` | low | -10.00 | Bundled dependency lockfile |
//
// Four columns: id, severity, weight, Title.
var signalRowRe = regexp.MustCompile("(?m)^\\|\\s*`([a-z0-9_.]+)`\\s*\\|\\s*([a-z]+)\\s*\\|\\s*(-?[0-9.]+)\\s*\\|\\s*(.+?)\\s*\\|\\s*$")

// TestSignalTitlesMatchMarkdown joins every published signal ROW to the
// registry — id, severity, weight and Title.
//
// The count guards above this one check how MANY signals are documented.
// Nothing checked what the rows SAY, and that gap had a live consequence:
// `sc.shrinkwrap_present` was titled "Bundled npm-shrinkwrap.json" in both
// the registry and this page, while its producing provider
// (intelligence.ecosystemLockfiles) covers pypi, composer, cargo and
// rubygems too — so a Rust crate shipping Cargo.lock rendered to the user as
// "Bundled npm-shrinkwrap.json". A vendor QA pass read that as a
// cross-ecosystem leak and filed it as a signal defect; the signal was
// right and only the words were wrong. Wrong words cost a review cycle.
//
// Titles and weights are USER-VISIBLE — they render in the CLI explain
// output, the dashboard breakdown and the docs page — so a doc that
// disagrees with the registry is a published falsehood, not a formatting
// nit. This test makes the two sides one edit.
func TestSignalTitlesMatchMarkdown(t *testing.T) {
	body := readCoreDoc(t, "docs/signals.md")
	rows := signalRowRe.FindAllStringSubmatch(body, -1)
	if len(rows) == 0 {
		t.Fatal("docs/signals.md: no `| `id` | sev | weight | Title |` rows matched — " +
			"the table layout changed and this guard went blind; re-point signalRowRe")
	}

	byID := map[string]Signal{}
	for _, s := range AllSignals() {
		byID[s.ID] = s
	}

	documented := map[string]bool{}
	for _, m := range rows {
		id, sev, weight, title := m[1], m[2], m[3], m[4]
		sig, ok := byID[id]
		if !ok {
			t.Errorf("docs/signals.md documents %q, which is not in the registry — "+
				"the signal was renamed or removed and the page still advertises it", id)
			continue
		}
		if documented[id] {
			t.Errorf("docs/signals.md lists %q twice", id)
		}
		documented[id] = true
		if title != sig.Title {
			t.Errorf("docs/signals.md: %s title is %q, registry says %q", id, title, sig.Title)
		}
		if sev != string(sig.Severity) {
			t.Errorf("docs/signals.md: %s severity is %q, registry says %q", id, sev, sig.Severity)
		}
		if got, err := strconv.ParseFloat(weight, 64); err != nil {
			t.Errorf("docs/signals.md: %s weight %q will not parse: %v", id, weight, err)
		} else if got != sig.Weight {
			t.Errorf("docs/signals.md: %s weight is %v, registry says %v", id, got, sig.Weight)
		}
	}

	var undocumented []string
	for id := range byID {
		if !documented[id] {
			undocumented = append(undocumented, id)
		}
	}
	sort.Strings(undocumented)
	if len(undocumented) > 0 {
		t.Errorf("docs/signals.md has no row for %d registry signal(s): %s",
			len(undocumented), strings.Join(undocumented, ", "))
	}
}
