package main

// run.go — per-ecosystem census: registry name list -> d=1 candidates of
// block-eligible targets -> registry metadata -> admission -> rails -> write.
// The output file is written only after every rail passes; a hard failure
// refuses the write and exits non-zero.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/typosquat"
)

type generateArgs struct {
	eco         string
	out         string
	cacheDir    string
	npmSeed     string
	pypiSeed    string
	malwareFeed string
	conc        int
	now         time.Time

	candidatesOnly bool // stop after counting candidates (no per-candidate requests)

	// feed is the known-malicious name set (ecosystem -> normalized names),
	// loaded once by generate from malwareFeed.
	feed map[string]map[string]bool
}

var ecoLabel = map[string]string{"npm": "npm", "pypi": "pypi", "cargo": "cargo", "pub": "pub"}

func generate(a generateArgs) (int, error) {
	if _, ok := ecoLabel[a.eco]; !ok {
		return 0, fmt.Errorf("unsupported ecosystem %q (npm | pypi | cargo | pub)", a.eco)
	}
	feed, err := loadFeedNames(a.malwareFeed)
	if err != nil {
		return 0, err
	}
	a.feed = feed
	if !censusSelfTest(a.now) {
		return 0, fmt.Errorf("census self-test: FAIL — refusing to run")
	}

	var seedNames []string
	switch a.eco {
	case "npm":
		seedNames, err = loadSeedNames(a.npmSeed, "npm")
	case "pypi":
		seedNames, err = loadSeedNames(a.pypiSeed, "pypi")
	}
	if err != nil {
		return 0, err
	}
	corpus, err := detectorCorpus(a.eco, seedNames)
	if err != nil {
		return 0, err
	}
	names, err := censusNames(a.eco, a.cacheDir)
	if err != nil {
		return 0, err
	}
	started := time.Now()
	cands := censusCandidates(a.eco, corpus, names)
	tiers := map[string]int{}
	for _, c := range cands {
		tiers[c.Tier]++
	}
	fmt.Fprintf(os.Stderr, "%s census: %d registry names -> %d candidates (block tier %d, warn tier %d) in %s\n",
		a.eco, len(names), len(cands), tiers["block"], tiers["warn"], time.Since(started).Round(time.Second))
	if a.candidatesOnly {
		return 0, nil
	}

	rows, err := censusRows(a, cands)
	if err != nil {
		return 0, err
	}
	// Keyed by the detector's normalization: a PyPI row carries the project's
	// canonical spelling, which may differ from the simple index's.
	norm := typosquat.NormalizerForFormat(a.eco)
	targetOf, tierOf := map[string]string{}, map[string]string{}
	for _, c := range cands {
		targetOf[norm(c.Name)], tierOf[norm(c.Name)] = c.Target, c.Tier
	}
	var verdicts []censusVerdict
	var table []row
	for _, r := range rows {
		tier := tierOf[norm(r.Name)]
		if tier == "" {
			return 0, fmt.Errorf("%s census: row %q matches no candidate — refusing", a.eco, r.Name)
		}
		ok, why := admitCensus(a.eco, r, tier == "block", a.feed, a.now)
		verdicts = append(verdicts, censusVerdict{Row: r, Target: targetOf[norm(r.Name)], Tier: tier, Admit: ok, Reason: why})
		if ok {
			table = append(table, r)
		}
	}
	censusReport(a.eco, verdicts)
	if err := dumpVerdicts(filepath.Join(a.cacheDir, a.eco+"_census_verdicts.jsonl"), verdicts); err != nil {
		return 0, err
	}
	inTable := map[string]bool{}
	for _, r := range table {
		inTable[r.Name] = true
	}
	for _, s := range censusSentinels[a.eco] {
		if !inTable[s] {
			return 0, fmt.Errorf("%s census: sentinel %q not admitted — inputs changed shape, refusing", a.eco, s)
		}
	}
	for _, c := range censusCanaries[a.eco] {
		if inTable[c] {
			return 0, fmt.Errorf("%s census: canary squat %q admitted — refusing", a.eco, c)
		}
	}
	if err := censusChurn(a.out, table); err != nil {
		return 0, err
	}
	if err := writeTable(a, table, len(names), len(cands)); err != nil {
		return 0, err
	}
	// Only this ecosystem's lists: runs for different ecosystems share the
	// cache dir and may be in flight at the same time.
	done := []string{namesCachePath(a.eco, a.cacheDir)}
	if a.eco == "cargo" {
		done = append(done, filepath.Join(a.cacheDir, "cargo_crates_census.jsonl"))
	}
	for _, p := range done {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return 0, err
		}
	}
	printRequestCounts()
	return len(table), nil
}

// censusRows fetches registry metadata for every candidate. Downloads are
// fetched only for candidates that already pass the age half — the other
// half cannot rescue them, and every skipped call is one less upstream
// request.
func censusRows(a generateArgs, cands []censusCandidate) ([]row, error) {
	names := make([]string, len(cands))
	for i, c := range cands {
		names[i] = c.Name
	}
	old := func(first string) bool {
		t := parseDate(first)
		return !t.IsZero() && a.now.Sub(t) >= censusMinAge
	}
	var rows []row
	switch a.eco {
	case "npm":
		// Unscoped names: downloads first (128 per bulk request), docs only
		// for names on the line — most of the warn tier never needs a doc.
		// Scoped names cannot be batched (one ~1/s point call each), so
		// they take the doc first and a downloads call only once aged.
		var unscoped, scoped []string
		for _, n := range names {
			if strings.HasPrefix(n, "@") {
				scoped = append(scoped, n)
			} else {
				unscoped = append(unscoped, n)
			}
		}
		weekly, err := fetchNPMWeekly(a.cacheDir, unscoped, a.conc, &progress{})
		if err != nil {
			return nil, err
		}
		need := append([]string(nil), scoped...)
		for _, n := range unscoped {
			if weekly[n] >= oldWeeklyDownloadsLine {
				need = append(need, n)
			}
		}
		docs, err := fetchNPMDocs(a.cacheDir, need, a.conc, &progress{})
		if err != nil {
			return nil, err
		}
		var agedScoped []string
		for _, n := range scoped {
			if d := docs[n]; d.OK && old(d.Created) {
				agedScoped = append(agedScoped, n)
			}
		}
		sw, err := fetchNPMWeekly(a.cacheDir, agedScoped, a.conc, &progress{})
		if err != nil {
			return nil, err
		}
		for _, n := range agedScoped {
			weekly[n] = sw[n]
		}
		for _, n := range names {
			d := docs[n]
			rows = append(rows, row{Name: n, Weekly: weekly[n], Versions: d.Versions, First: d.Created, Last: d.Last,
				HasData: d.OK, Placeholder: npmPlaceholder(d.VersionList), Releases: d.VersionList})
		}
	case "pypi":
		// pypistats is ~1 request/second and the warn tier has tens of
		// thousands of candidates. ClickHouse's public download dataset (one
		// aggregate query) decides who is worth a call: a candidate under
		// half the lower line there cannot reach it and needs neither a doc
		// nor a pypistats call. Its counts include mirrors, so they only
		// rule names out; admission reads pypistats.
		recent, err := fetchPyPIRecent(a.now, oldWeeklyDownloadsLine/2)
		if err != nil {
			return nil, err
		}
		var near []string
		for _, n := range names {
			if recent[pep503(n)] >= oldWeeklyDownloadsLine/2 {
				near = append(near, n)
			}
		}
		docs, err := fetchPyPI(a.cacheDir, near, a.conc, &progress{})
		if err != nil {
			return nil, err
		}
		var aged []string
		for _, n := range near {
			// Doubled: a name at half a line in ClickHouse still gets its
			// pypistats reading.
			if d := docs[pep503(n)]; d.OK && mayAdmit(d.First, 2*recent[pep503(n)], a.now) {
				aged = append(aged, d.Name)
			}
		}
		weekly, err := fetchPyPIWeekly(a.cacheDir, aged)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			k := pep503(n)
			d := docs[k]
			name := d.Name
			if name == "" {
				name = n
			}
			w, ok := weekly[pep503(name)]
			if !ok {
				w = recent[k]
			}
			rows = append(rows, row{Name: name, Weekly: w, Versions: d.Versions, First: d.First,
				Last: d.Last, HasData: d.OK, Releases: d.VersionList})
		}
		rows = dedupeByName(rows)
	case "cargo":
		crates, err := fetchCrates(a.cacheDir, names)
		if err != nil {
			return nil, err
		}
		var aged []string
		for _, n := range names {
			if c := crates[n]; c.OK && mayAdmit(c.Created, c.Recent*7/90, a.now) {
				aged = append(aged, n)
			}
		}
		vers, err := fetchCargoVersions(a.cacheDir, aged)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			c := crates[n]
			// crates.io publishes a 90-day figure; scaled to a week so the
			// one weekly line (and risk.EstablishedClear at runtime) decides.
			rows = append(rows, row{Name: n, Weekly: c.Recent * 7 / 90, Versions: c.Versions, First: c.Created,
				Last: c.Updated, HasData: c.OK, Releases: vers[n]})
		}
	case "pub":
		docs, err := fetchPub(a.cacheDir, names, a.conc, &progress{})
		if err != nil {
			return nil, err
		}
		var aged []string
		for _, n := range names {
			if d := docs[n]; d.OK && old(d.First) {
				aged = append(aged, n)
			}
		}
		d30, err := fetchPubDownloads(a.cacheDir, aged)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			d := docs[n]
			// pub.dev publishes a 30-day figure; scaled to a week.
			rows = append(rows, row{Name: n, Weekly: d30[n] * 7 / 30, Versions: len(d.VersionList), First: d.First,
				Last: d.Last, HasData: d.OK, Releases: d.VersionList})
		}
	}
	return rows, nil
}

// loadSeedNames reads a popular seed; a missing seed file is fatal because
// the block-eligible targets are built on it.
func loadSeedNames(path, eco string) ([]string, error) {
	names, err := readSeedList(path)
	if err != nil {
		return nil, fmt.Errorf("popular seed %s: %w", path, err)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("popular seed %s: empty", path)
	}
	return names, nil
}

// censusMarker heads every census-generated table; the churn rail compares
// only against a previous census, not against the pre-census tables.
const censusMarker = "# Census table"

// censusChurn refuses a regeneration that loses more than a quarter of the
// previous census's rows — an upstream shape change, not real churn. Rows
// leaving because a package fell under a line are expected in small numbers.
func censusChurn(path string, table []row) error {
	raw, err := os.ReadFile(path)
	if err != nil || !strings.HasPrefix(string(raw), censusMarker) {
		fmt.Fprintln(os.Stderr, "churn rail: no previous census table — first-run baseline")
		return nil
	}
	old, err := parseTable(path)
	if err != nil {
		return err
	}
	now := map[string]bool{}
	for _, r := range table {
		now[r.Name] = true
	}
	lost := 0
	for _, n := range old {
		if !now[n] {
			lost++
		}
	}
	fmt.Fprintf(os.Stderr, "churn rail: %d of %d previous rows gone\n", lost, len(old))
	if len(old) > 0 && float64(lost)/float64(len(old)) > churnTotalLimit {
		return fmt.Errorf("churn rail: %d of %d previous rows gone (>%.0f%%) — refusing", lost, len(old), churnTotalLimit*100)
	}
	return nil
}

// writeTable emits the TSV: census header, then admitted rows.
func writeTable(a generateArgs, table []row, universe, candidates int) error {
	sortRows(table)
	var b strings.Builder
	eco := ecoLabel[a.eco]
	fmt.Fprintf(&b, "%s for %s — names the guard's typosquat lane flags (block or warn tier) that the registry shows are long-standing and heavily used.\n", censusMarker, eco)
	fmt.Fprintf(&b, "# GENERATED by core/tools/established-table-gen — do not hand-edit; regenerate with:\n")
	fmt.Fprintf(&b, "#   go run ./tools/established-table-gen -ecosystem %s -cache <dir outside the repo> -out %s\n", eco, a.out)
	fmt.Fprintf(&b, "# Universe: the registry's full public name list (%d names); the guard's detector flags %d of them (medium or high). No customer data.\n", universe, candidates)
	fmt.Fprintf(&b, "# Admission (either line): first published >= 2 years before %s AND >= %d downloads/week, or >= 5 years AND >= %d downloads/week (%d for a block-tier lookalike)%s.\n",
		a.now.Format("2006-01-02"), weeklyDownloadsLine, oldWeeklyDownloadsLine, oldBlockWeeklyDownloadsLine, weeklyNote(a.eco))
	fmt.Fprintf(&b, "# Never admitted: known-malicious feed names (the `chainsaw guard update` OSV set + embedded floor), npm security placeholders, names without registry data, the reviewed keep-blocked list.\n")
	fmt.Fprintf(&b, "# Columns: name <TAB> weekly_downloads <TAB> version_count <TAB> first_published <TAB> last_published <TAB> releases (comma-separated, build-time).\n")
	fmt.Fprintf(&b, "# The guard is silent only for an exact pin in releases; any other install of a row warns. Rows: %d.\n", len(table))
	for _, r := range table {
		fmt.Fprintf(&b, "%s\t%d\t%d\t%s\t%s\t%s\n", r.Name, r.Weekly, r.Versions, r.First, r.Last, sortedReleases(r.Releases))
	}
	if b.Len() > 8<<20 {
		return fmt.Errorf("%s: output %d bytes exceeds the 8MB budget", a.eco, b.Len())
	}
	return os.WriteFile(a.out, []byte(b.String()), 0o644)
}

func weeklyNote(eco string) string {
	switch eco {
	case "pypi":
		return " (pypistats.org last_week)"
	case "cargo":
		return " (crates.io 90-day recent downloads x 7/90)"
	case "pub":
		return " (pub.dev 30-day downloads x 7/30)"
	}
	return " (api.npmjs.org last-week)"
}

func dedupeByName(rows []row) []row {
	seen := map[string]bool{}
	out := rows[:0]
	for _, r := range rows {
		if seen[r.Name] {
			continue
		}
		seen[r.Name] = true
		out = append(out, r)
	}
	return out
}

// sortRows orders table rows deterministically: weekly downloads desc, then
// name.
func sortRows(rows []row) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Weekly != rows[j].Weekly {
			return rows[i].Weekly > rows[j].Weekly
		}
		return rows[i].Name < rows[j].Name
	})
}

// dumpVerdicts writes every candidate's decision to the cache dir (outside
// the repo) for review and measurement: which names were refused, and why.
func dumpVerdicts(path string, verdicts []censusVerdict) error {
	var b strings.Builder
	for _, v := range verdicts {
		line, err := json.Marshal(map[string]any{"name": v.Row.Name, "target": v.Target, "tier": v.Tier, "admit": v.Admit,
			"reason": v.Reason, "first": v.Row.First, "weekly": v.Row.Weekly})
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
