package main

// decide.go — the clear lines and the anti-poisoning rails. The clear lines
// mirror core/risk/established.go (EstablishedWeeklyDownloads = 100_000,
// Established90DayDownloads = 75_000, EstablishedMinVersions = 50,
// EstablishedMinAge = 2y) and core/intelligence/typosquat_established.go
// (typosquatLongLivedPackageAge = 5y, typosquatLongLivedVersionAge = 1y).
// If those constants move, this table must be regenerated — the table's job
// is to carry those lines' verdicts as data, not to invent new ones.

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	weeklyDownloadsLine = 100_000                  // risk.EstablishedWeeklyDownloads (npm, pypi)
	cargoDownloadsLine  = 75_000                   // risk.Established90DayDownloads; v1 applies it to crates.io TOTAL downloads as the proxy (header says so)
	minVersions         = 50                       // risk.EstablishedMinVersions
	minVersionsAge      = 2 * 365 * 24 * time.Hour // risk.EstablishedMinAge
	longLivedPackageAge = 5 * 365 * 24 * time.Hour // typosquatLongLivedPackageAge
	longLivedVersionAge = 365 * 24 * time.Hour     // typosquatLongLivedVersionAge

	// Rail 2 floor: a row that qualifies ONLY through the downloads line must
	// also be >=1y old or carry >=10 versions — one hot week is not
	// establishment, it is indistinguishable from a purchased-audience squat.
	floorAge     = 365 * 24 * time.Hour
	floorVersion = 10

	// Rail 3 ratio: a d1 lookalike of a popular seed drawing <1% of that
	// seed's weekly downloads is squat-shaped no matter how it qualified.
	d1RatioPercent = 1

	// Rail 4 churn limits against the previous table.
	churnTopLimit   = 0.10
	churnTotalLimit = 0.25
)

// row is one candidate's distilled registry truth — the unit every decision
// (clear line, rail, TSV line) works on.
type row struct {
	Name         string
	Weekly       int64 // npm: last-week; cargo: total downloads (v1 proxy); pypi: 0 = unknown
	Versions     int
	First        string // YYYY-MM-DD or ""
	Last         string // YYYY-MM-DD or ""
	HasData      bool   // false = 404/unpublished — no registry truth, never qualifies
	SecurityOnly bool   // npm "-security" holding placeholder: its age is the removal date, not survival
}

// clearLines reports which establishment lines the row meets. A row goes in
// the table iff ANY line fires. Missing data establishes nothing, mirroring
// risk.EstablishedReason: a failed fetch is below every line.
func clearLines(eco string, r row, now time.Time) []string {
	var lines []string
	if !r.HasData {
		return lines
	}
	dl := weeklyDownloadsLine
	if eco == "cargo" {
		dl = cargoDownloadsLine
	}
	if r.Weekly >= int64(dl) {
		lines = append(lines, "downloads")
	}
	first := parseDate(r.First)
	if r.SecurityOnly {
		return lines // a holding placeholder's timestamps are removal artifacts
	}
	if r.Versions >= minVersions && !first.IsZero() && now.Sub(first) >= minVersionsAge {
		lines = append(lines, "versions")
	}
	last := parseDate(r.Last)
	if !first.IsZero() && !last.IsZero() &&
		now.Sub(first) >= longLivedPackageAge && now.Sub(last) >= longLivedVersionAge {
		lines = append(lines, "long-lived")
	}
	return lines
}

func parseDate(s string) time.Time {
	if len(s) != 10 {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// verdict is the pipeline output for one row: the lines that fired and the
// rail holds that kept it out despite them.
type verdict struct {
	Row   row
	Lines []string
	Holds []string
}

// rail2Floor holds out a row that qualified ONLY through the downloads line
// but fails the multi-signal floor (neither >=1y old nor >=10 versions).
// Returns the hold reason, or "".
func rail2Floor(r row, lines []string, now time.Time) string {
	if len(lines) != 1 || lines[0] != "downloads" {
		return ""
	}
	first := parseDate(r.First)
	if (!first.IsZero() && now.Sub(first) >= floorAge) || r.Versions >= floorVersion {
		return ""
	}
	return fmt.Sprintf("multi-signal floor: downloads-only row is %s old with %d versions (needs >=1y or >=10 versions)",
		ageOrUnknown(first, now), r.Versions)
}

func ageOrUnknown(t, now time.Time) string {
	if t.IsZero() {
		return "unknown-age"
	}
	return fmt.Sprintf("%dd", int(now.Sub(t).Hours()/24))
}

// d1Within reports whether a and b are within edit distance 1 (one insert,
// delete or substitute). Equal strings are "within" (distance 0); callers
// that mean "strictly one edit" compare for equality themselves.
func d1Within(a, b string) bool {
	la, lb := len(a), len(b)
	if la-lb > 1 || lb-la > 1 {
		return false
	}
	if la == lb {
		diff := 0
		for i := 0; i < la; i++ {
			if a[i] != b[i] {
				diff++
				if diff > 1 {
					return false
				}
			}
		}
		return true
	}
	if la > lb { // make a the shorter: one insertion into a gives b
		a, b = b, a
	}
	i, j, skipped := 0, 0, false
	for i < len(a) && j < len(b) {
		if a[i] == b[j] {
			i++
			j++
			continue
		}
		if skipped {
			return false
		}
		skipped = true
		j++
	}
	return true
}

// stripScope drops an npm scope prefix ("@scope/name" -> "name"); unscoped
// names pass through. The d1 watch is scope-insensitive.
func stripScope(name string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		return name[i+1:]
	}
	return name
}

// seedEntry is one popular-seed name with the weekly downloads that give the
// ratio rail its baseline.
type seedEntry struct {
	name     string
	stripped string
	weekly   int64
}

// seedIndex buckets popular-seed names by the length of their scope-stripped
// lowercased form, so a d1 scan only touches the three relevant buckets.
type seedIndex struct {
	buckets map[int][]seedEntry
}

func buildSeedIndex(seedNames []string, weekly map[string]int64) *seedIndex {
	idx := &seedIndex{buckets: map[int][]seedEntry{}}
	for _, n := range seedNames {
		s := strings.ToLower(stripScope(n))
		idx.buckets[len(s)] = append(idx.buckets[len(s)], seedEntry{name: n, stripped: s, weekly: weekly[n]})
	}
	return idx
}

// rail3D1Watch holds out a table row whose scope-stripped name is within
// edit distance 1 of a popular-seed name while drawing <1% of that seed's
// weekly downloads. Returns hold reasons, empty when the row is clean.
func rail3D1Watch(r row, idx *seedIndex) []string {
	s := strings.ToLower(stripScope(r.Name))
	var holds []string
	for _, L := range []int{len(s) - 1, len(s), len(s) + 1} {
		for _, seed := range idx.buckets[L] {
			if !d1Within(s, seed.stripped) {
				continue
			}
			if seed.weekly <= 0 {
				continue // no baseline to judge against
			}
			if r.Weekly*100 < seed.weekly*d1RatioPercent {
				pct := float64(r.Weekly) / float64(seed.weekly) * 100
				holds = append(holds, fmt.Sprintf(
					"d1 ratio watch: %q is within edit distance 1 of popular %q with %.4f%% of its %d/wk",
					r.Name, seed.name, pct, seed.weekly))
			}
		}
	}
	return holds
}

// decideRow is the pipeline every candidate passes through: clear lines,
// then rail 2 (multi-signal floor), then rail 3 (d1-of-popular watch). The
// patient-attacker self-test reuses this exact function on synthetic rows —
// the rails under test are these, not a reimplementation.
func decideRow(eco string, r row, seeds *seedIndex, now time.Time) verdict {
	v := verdict{Row: r, Lines: clearLines(eco, r, now)}
	if len(v.Lines) == 0 {
		return v
	}
	if hold := rail2Floor(r, v.Lines, now); hold != "" {
		v.Holds = append(v.Holds, hold)
	}
	if seeds != nil {
		v.Holds = append(v.Holds, rail3D1Watch(r, seeds)...)
	}
	return v
}

// ---------------------------------------------------------------------------
// churn rail (rail 4)

// parseTable reads a previous established TSV: # header lines, then
// name<TAB>weekly<TAB>versions<TAB>first<TAB>last. Row order is downloads
// desc, so the first 100 rows are the "top 100" the churn rail compares.
func parseTable(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var names []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 5 {
			return nil, fmt.Errorf("%s: malformed row %q (want 5 tab columns)", path, line)
		}
		names = append(names, cols[0])
	}
	return names, sc.Err()
}

// churnCheck compares the new table's row names with the previous
// generation's. Top-100 turnover >10% or total churn >25% refuses the write.
// The first run has no baseline and prints so.
func churnCheck(oldNames, newNames []string) error {
	if len(oldNames) == 0 {
		fmt.Fprintln(os.Stderr, "churn rail: first-run baseline (no previous table — limits armed for the next run)")
		return nil
	}
	oldSet := map[string]bool{}
	for _, n := range oldNames {
		oldSet[n] = true
	}
	newSet := map[string]bool{}
	for _, n := range newNames {
		newSet[n] = true
	}
	oldTop, newTop := oldNames, newNames
	if len(oldTop) > 100 {
		oldTop = oldTop[:100]
	}
	if len(newTop) > 100 {
		newTop = newTop[:100]
	}
	newTopSet := map[string]bool{}
	for _, n := range newTop {
		newTopSet[n] = true
	}
	topMoved := 0
	for _, n := range oldTop {
		if !newTopSet[n] {
			topMoved++
		}
	}
	removed, added := 0, 0
	for n := range oldSet {
		if !newSet[n] {
			removed++
		}
	}
	for n := range newSet {
		if !oldSet[n] {
			added++
		}
	}
	total := len(oldSet) + len(newSet)
	churn := 0.0
	if total > 0 {
		churn = float64(removed+added) / float64(total)
	}
	topTurn := 0.0
	if len(oldTop) > 0 {
		topTurn = float64(topMoved) / float64(len(oldTop))
	}
	fmt.Fprintf(os.Stderr, "churn rail: top-100 turnover %.1f%% (limit 10%%), total churn %.1f%% (limit 25%%) vs %d previous rows\n",
		topTurn*100, churn*100, len(oldSet))
	if topTurn > churnTopLimit {
		return fmt.Errorf("churn rail: top-100 turnover %.1f%% exceeds 10%% (%d of %d moved) — re-review before writing", topTurn*100, topMoved, len(oldTop))
	}
	if churn > churnTotalLimit {
		return fmt.Errorf("churn rail: total churn %.1f%% exceeds 25%% (+%d/-%d of %d) — re-review before writing", churn*100, added, removed, len(oldSet))
	}
	return nil
}

// ---------------------------------------------------------------------------
// patient-attacker self-test (rail 5)

// selfTest injects the specified patient-attacker row into the decision
// pipeline and asserts the rails hold it. The probe as literally specified —
// name "zz-squat-probe", "d1 of lodash" — is internally inconsistent: the
// name is 13 characters and lodash 6, so no single edit connects them, and
// rail 2 deliberately passes its profile (15 months >= 1y and 55 versions
// >= 10: a patient attacker satisfies that floor exactly by waiting). The
// rail built for that attacker is the d1 ratio watch, so the test also runs
// an ARMED variant — identical stats under "lodsh", a true one-edit
// lookalike of the lodash seed — and asserts rail 3 holds it out. The
// unarmed variant must NOT be held: it is not a lookalike, and holding it
// would mean the d1 predicate is over-broad.
func selfTest(seeds *seedIndex, weekly map[string]int64, now time.Time) bool {
	first := now.AddDate(-1, -3, 0).Format("2006-01-02") // 15 months old
	last := now.AddDate(0, 0, -14).Format("2006-01-02")
	lodashWeekly := weekly["lodash"]

	fmt.Fprintf(os.Stderr, "self-test: patient attacker — 55 versions, first published %s, 120k/wk (lodash baseline: %d/wk)\n", first, lodashWeekly)
	if lodashWeekly == 0 {
		fmt.Fprintln(os.Stderr, "self-test: FAIL — lodash weekly downloads unavailable; the ratio rail has no baseline")
		return false
	}

	pass := true
	for _, probe := range []row{
		{Name: "zz-squat-probe", Weekly: 120_000, Versions: 55, First: first, Last: last, HasData: true},
		{Name: "lodsh", Weekly: 120_000, Versions: 55, First: first, Last: last, HasData: true}, // armed: true d1 of lodash
	} {
		v := decideRow("npm", probe, seeds, now)
		held := len(v.Holds) > 0
		d1 := d1Within(stripScope(probe.Name), stripScope("lodash"))
		fmt.Fprintf(os.Stderr, "self-test: %-14s lines=%v d1(lodash)=%-5v held=%-5v holds=%v\n",
			probe.Name, v.Lines, d1, held, v.Holds)
		if probe.Name == "lodsh" {
			ratioHeld := false
			for _, h := range v.Holds {
				if strings.HasPrefix(h, "d1 ratio watch") {
					ratioHeld = true
				}
			}
			if !held {
				fmt.Fprintln(os.Stderr, "self-test: FAIL — armed lookalike escaped the rails")
				pass = false
			} else if !ratioHeld {
				fmt.Fprintln(os.Stderr, "self-test: FAIL — armed lookalike held, but not by the d1 ratio watch")
				pass = false
			}
		} else if held {
			fmt.Fprintln(os.Stderr, "self-test: FAIL — non-lookalike held; d1 predicate is over-broad")
			pass = false
		}
	}
	fmt.Fprintf(os.Stderr, "self-test: %s\n", map[bool]string{true: "PASS", false: "FAIL"}[pass])
	return pass
}

// sortRows orders table rows deterministically: weekly downloads desc, then
// name — the churn rail reads the first 100 rows as "the top 100".
func sortRows(rows []row) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Weekly != rows[j].Weekly {
			return rows[i].Weekly > rows[j].Weekly
		}
		return rows[i].Name < rows[j].Name
	})
}
