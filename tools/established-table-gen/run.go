package main

// run.go — per-ecosystem orchestration: universe -> cached fetches ->
// decide (clear lines + rails) -> canary adjudication -> floor/sentinel
// refuse-don't-report-zero checks -> churn rail -> write. The output file is
// written only after every rail passes; any hard failure refuses the write
// and exits non-zero, after the corpus floor discipline in popular-corpus-gen.

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type generateArgs struct {
	eco         string
	out         string
	cacheDir    string
	packagesCSV string
	npmDocs     string
	npmSeed     string
	pypiSeed    string
	cargoPages  int
	conc        int
	now         time.Time
}

// floors and sentinels per ecosystem: a table below the floor or missing a
// flagship established name means an upstream change, not a real shrink —
// refuse rather than write a hollow file.
var ecoFloors = map[string]int{"npm": 1000, "pypi": 300, "cargo": 500}

var ecoSentinels = map[string][]string{
	"npm":   {"react", "lodash", "express", "typescript"},
	"pypi":  {"requests", "numpy", "boto3", "urllib3"},
	"cargo": {"serde", "tokio", "libc", "rand"},
}

// ecoLabel maps the flag value to the ecosystem word used in headers.
var ecoLabel = map[string]string{"npm": "npm", "pypi": "pypi", "cargo": "cargo"}

func generate(a generateArgs) (int, error) {
	switch a.eco {
	case "npm":
		return generateNPM(a)
	case "pypi":
		return generatePyPI(a)
	case "cargo":
		return generateCargo(a)
	default:
		return 0, fmt.Errorf("unsupported ecosystem %q (npm | pypi | cargo)", a.eco)
	}
}

// loadSeedNames reads a popular seed; a missing seed file is fatal because
// both universes and the d1 rail are built on it.
func loadSeedNames(path, eco string) ([]string, error) {
	names, err := readSeedList(path)
	if err != nil {
		return nil, fmt.Errorf("popular seed %s: %w", path, err)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("popular seed %s: empty", path)
	}
	fmt.Fprintf(os.Stderr, "%s universe: popular seed %s -> %d names\n", eco, path, len(names))
	return names, nil
}

func loadCSVNames(path, eco string) ([]string, error) {
	names, err := readPackagesCSV(path, eco)
	if err != nil {
		return nil, fmt.Errorf("packages.csv: %w", err)
	}
	fmt.Fprintf(os.Stderr, "%s universe: packages.csv -> %d names\n", eco, len(names))
	return names, nil
}

// decideAll runs every candidate row through the pipeline and partitions it:
// table rows, held-out rows (qualified but rail-blocked), and non-qualifiers.
func decideAll(eco string, rows []row, seeds *seedIndex, now time.Time) (table []row, held []verdict, nq int) {
	for _, r := range rows {
		v := decideRow(eco, r, seeds, now)
		switch {
		case len(v.Lines) == 0:
			nq++
		case len(v.Holds) > 0:
			held = append(held, v)
		default:
			table = append(table, r)
		}
	}
	return table, held, nq
}

func printHeld(eco string, held []verdict) {
	if len(held) == 0 {
		fmt.Fprintf(os.Stderr, "%s rails: no qualified row was held out\n", eco)
		return
	}
	fmt.Fprintf(os.Stderr, "%s rails: %d qualified row(s) HELD OUT:\n", eco, len(held))
	for _, v := range held {
		fmt.Fprintf(os.Stderr, "  HELD %-40q lines=%v — %s\n", v.Row.Name, v.Lines, strings.Join(v.Holds, "; "))
	}
	// A hold is the rail working; a FLOOD of holds is data trouble. More
	// than 3% of qualified rows held means the inputs changed shape —
	// refuse rather than ship a table that a broken rail quietly shrank.
}

func checkHoldFlood(eco string, tableRows int, held int) error {
	total := held + tableRows
	if total > 0 && float64(held)/float64(total) > 0.03 {
		return fmt.Errorf("%s rails: %d of %d qualified rows held out (>3%%) — inputs look wrong, refusing", eco, held, total)
	}
	return nil
}

// adjudicateCanaries prints, for every measured npm false-block, either its
// place in the table or the reason real registry data keeps it out. A canary
// without registry data is a hard failure: the table would silently lose its
// false-positive regression coverage.
func adjudicateCanaries(rows map[string]row, table map[string]bool, held map[string]verdict, now time.Time) error {
	inTable := 0
	fmt.Fprintf(os.Stderr, "canary rail: %d measured false-blocks to adjudicate\n", len(canaries))
	for _, c := range canaries {
		r, ok := rows[c]
		switch {
		case !ok || !r.HasData:
			fmt.Fprintf(os.Stderr, "  canary %-12q NO REGISTRY DATA — cannot adjudicate\n", c)
			return fmt.Errorf("canary rail: %q has no registry data; refusing", c)
		case table[c]:
			inTable++
			fmt.Fprintf(os.Stderr, "  canary %-12q IN TABLE via %v (%d/wk, %d versions, first %s, last %s)\n",
				c, clearLines("npm", r, now), r.Weekly, r.Versions, r.First, r.Last)
		case held[c].Row.Name == c:
			v := held[c]
			fmt.Fprintf(os.Stderr, "  canary %-12q QUALIFIES via %v BUT HELD by rail: %s\n", c, v.Lines, strings.Join(v.Holds, "; "))
		default:
			first := parseDate(r.First)
			age := "unknown"
			if !first.IsZero() {
				age = fmt.Sprintf("%dd", int(now.Sub(first).Hours()/24))
			}
			fmt.Fprintf(os.Stderr, "  canary %-12q does not qualify: %d/wk (<100k), %d versions (<50 or <2y), first %s (%s old) — clears only via the runtime metadata path\n",
				c, r.Weekly, r.Versions, r.First, age)
		}
	}
	fmt.Fprintf(os.Stderr, "canary rail: %d/%d canaries in table, %d adjudicated out with reasons\n",
		inTable, len(canaries), len(canaries)-inTable)
	return nil
}

// floorAndSentinels refuses a table that is too small or missing flagship
// established names.
func floorAndSentinels(eco string, table []row) error {
	if len(table) < ecoFloors[eco] {
		return fmt.Errorf("%s: %d rows is below the %d floor — upstream change, refusing", eco, len(table), ecoFloors[eco])
	}
	inTable := map[string]bool{}
	for _, r := range table {
		inTable[r.Name] = true
	}
	for _, s := range ecoSentinels[eco] {
		if !inTable[s] {
			return fmt.Errorf("%s: sentinel %q missing from the %d-row table — upstream change, refusing", eco, s, len(table))
		}
	}
	return nil
}

// writeTable emits the TSV: # header lines then qualifying rows only, name
// TAB weekly TAB versions TAB first TAB last.
func writeTable(a generateArgs, table []row, universe int, universeCounts map[string]int, held2, held3 int, canaryIn, canaryN int) error {
	sortRows(table)
	var b strings.Builder
	eco := ecoLabel[a.eco]
	fmt.Fprintf(&b, "# Established-%s table for the typosquat clear — every row meets a clear line (see core/tools/established-table-gen/README.md).\n", eco)
	fmt.Fprintf(&b, "# GENERATED by core/tools/established-table-gen — do not hand-edit; regenerate with:\n")
	fmt.Fprintf(&b, "#   go run ./tools/established-table-gen -ecosystem %s -packages-csv %q -cache <cache-dir> -out %s\n", eco, a.packagesCSV, a.out)
	if a.eco == "npm" {
		fmt.Fprintf(&b, "#   (npm also takes -npm-docs-jsonl <path>)\n")
	}
	fmt.Fprintf(&b, "# Universe: %d candidate names %s.\n", universe, universeSummary(a, universeCounts))
	switch a.eco {
	case "npm":
		fmt.Fprintf(&b, "# Sources: registry.npmjs.org full docs (created/last/version count) + api.npmjs.org last-week downloads (bulk 128/batch, scoped individually).\n")
	case "pypi":
		fmt.Fprintf(&b, "# Sources: pypi.org/pypi/<PEP503>/json (releases with files; first/last upload_time). Weekly downloads unknown -> 0.\n")
	case "cargo":
		fmt.Fprintf(&b, "# Sources: crates.io/api/v1/crates?sort=downloads top %d pages (%d crates): created_at, updated_at, num_versions, total downloads.\n", a.cargoPages, a.cargoPages*100)
		fmt.Fprintf(&b, "# cargo downloads proxy: crates.io publishes no weekly figure; the >=75k/90d clear line is applied to TOTAL downloads (>=75000), a strictly LOOSER bar for old crates — treat cargo download-line rows with that in mind.\n")
	}
	fmt.Fprintf(&b, "# Clear lines (mirror core/risk/established.go + core/intelligence/typosquat_established.go):\n")
	fmt.Fprintf(&b, "#   %s\n", clearLineSummary(a.eco))
	fmt.Fprintf(&b, "# A row qualifies on ANY line; downloads-only rows also pass the multi-signal floor (>=1y old or >=10 versions).\n")
	fmt.Fprintf(&b, "# Held out this run: %d by the multi-signal floor, %d by the d1-of-popular ratio watch (see generator output).\n", held2, held3)
	if canaryN > 0 {
		fmt.Fprintf(&b, "# Canary adjudication (npm measured false-blocks): %d/%d in table, %d adjudicated out with printed reasons.\n", canaryIn, canaryN, canaryN-canaryIn)
	}
	fmt.Fprintf(&b, "# Generated: %s | rows: %d | row order: weekly downloads desc (churn rail reads the top 100).\n", a.now.Format("2006-01-02"), len(table))
	fmt.Fprintf(&b, "# Columns: name <TAB> weekly_downloads (0=unknown) <TAB> version_count <TAB> first_published (YYYY-MM-DD|empty) <TAB> last_published (YYYY-MM-DD|empty).\n")
	fmt.Fprintf(&b, "# Names are keyed exactly as the registry spells them; the consumer normalizes. Trust channel: reviewed data PR or signed bundle — never live at install time.\n")
	for _, r := range table {
		fmt.Fprintf(&b, "%s\t%d\t%d\t%s\t%s\n", r.Name, r.Weekly, r.Versions, r.First, r.Last)
	}
	if b.Len() > 2<<20 {
		return fmt.Errorf("%s: output %d bytes exceeds the 2MB budget", a.eco, b.Len())
	}
	if err := os.WriteFile(a.out, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return nil
}

func universeSummary(a generateArgs, counts map[string]int) string {
	var parts []string
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
	}
	return "(" + strings.Join(parts, " + ") + ")"
}

func clearLineSummary(eco string) string {
	dl := "weekly downloads >= 100000"
	if eco == "cargo" {
		dl = "total downloads >= 75000 (90d-spirit proxy, see above)"
	}
	return fmt.Sprintf("%s | >=50 versions AND first published >=2y ago | first published >=5y ago AND last published >=1y ago", dl)
}

// ---------------------------------------------------------------------------
// npm

func generateNPM(a generateArgs) (int, error) {
	seedNames, err := loadSeedNames(a.npmSeed, "npm")
	if err != nil {
		return 0, err
	}
	csvNames, err := loadCSVNames(a.packagesCSV, "npm")
	if err != nil {
		return 0, err
	}
	docNames, err := readNpmDocsNames(a.npmDocs)
	if err != nil {
		return 0, fmt.Errorf("npm docs jsonl: %w", err)
	}
	fmt.Fprintf(os.Stderr, "npm universe: npm_docs.jsonl -> %d names\n", len(docNames))
	names, counts := unionNames(map[string][]string{
		"popular-seed":   seedNames,
		"packages-csv":   csvNames,
		"npm-docs-jsonl": docNames,
		"canary-pins":    canaries,
	})
	fmt.Fprintf(os.Stderr, "npm universe: %d distinct candidates\n", len(names))

	prog := &progress{}
	docs, err := fetchNPMDocs(a.cacheDir, names, a.conc, prog)
	if err != nil {
		return 0, err
	}
	weekly, err := fetchNPMWeekly(a.cacheDir, names, a.conc, &progress{})
	if err != nil {
		return 0, err
	}

	rows := make([]row, 0, len(names))
	rowByName := map[string]row{}
	for _, n := range names {
		doc := docs[n]
		r := row{
			Name:         n,
			Weekly:       weekly[n],
			Versions:     doc.Versions,
			First:        doc.Created,
			Last:         doc.Last,
			HasData:      doc.OK,
			SecurityOnly: doc.SecurityOnly,
		}
		rows = append(rows, r)
		rowByName[n] = r
	}

	seeds := buildSeedIndex(seedNames, weekly)
	table, held, nq := decideAll("npm", rows, seeds, a.now)
	sortRows(table)
	fmt.Fprintf(os.Stderr, "npm decide: %d qualify, %d held out, %d do not qualify (of %d candidates)\n",
		len(table), len(held), nq, len(rows))
	printHeld("npm", held)

	// Partition held rows by rail for the header counts.
	held2, held3 := 0, 0
	heldByName := map[string]verdict{}
	for _, v := range held {
		heldByName[v.Row.Name] = v
		floor, ratio := false, false
		for _, h := range v.Holds {
			if strings.HasPrefix(h, "multi-signal floor") {
				floor = true
			}
			if strings.HasPrefix(h, "d1 ratio watch") {
				ratio = true
			}
		}
		if floor {
			held2++
		}
		if ratio {
			held3++
		}
	}
	if err := checkHoldFlood("npm", len(table), len(held)); err != nil {
		return 0, err
	}

	tableSet := map[string]bool{}
	for _, r := range table {
		tableSet[r.Name] = true
	}
	if err := adjudicateCanaries(rowByName, tableSet, heldByName, a.now); err != nil {
		return 0, err
	}

	if err := floorAndSentinels("npm", table); err != nil {
		return 0, err
	}

	// Churn rail reads the previous file BEFORE this run overwrites it.
	oldNames, err := parseTable(a.out)
	if err != nil {
		return 0, err
	}
	newNames := make([]string, len(table))
	for i, r := range table {
		newNames[i] = r.Name
	}
	if err := churnCheck(oldNames, newNames); err != nil {
		return 0, err
	}

	if !selfTest(seeds, weekly, a.now) {
		return 0, fmt.Errorf("self-test rail: FAIL — refusing to write")
	}

	canaryIn := 0
	for _, c := range canaries {
		if tableSet[c] {
			canaryIn++
		}
	}
	if err := writeTable(a, table, len(names), counts, held2, held3, canaryIn, len(canaries)); err != nil {
		return 0, err
	}
	return len(table), nil
}

// ---------------------------------------------------------------------------
// pypi

func generatePyPI(a generateArgs) (int, error) {
	seedNames, err := loadSeedNames(a.pypiSeed, "pypi")
	if err != nil {
		return 0, err
	}
	csvNames, err := loadCSVNames(a.packagesCSV, "pypi")
	if err != nil {
		return 0, err
	}
	names, counts := unionNames(map[string][]string{
		"popular-seed": seedNames,
		"packages-csv": csvNames,
	})
	fmt.Fprintf(os.Stderr, "pypi universe: %d distinct candidates\n", len(names))

	docs, err := fetchPyPI(a.cacheDir, names, a.conc, &progress{})
	if err != nil {
		return 0, err
	}

	rows := make([]row, 0, len(names))
	for _, n := range names {
		doc := docs[pep503(n)]
		rows = append(rows, row{
			Name:     doc.Name, // registry spelling
			Weekly:   0,        // pypi download figures are not fetched in v1; 0 = unknown
			Versions: doc.Versions,
			First:    doc.First,
			Last:     doc.Last,
			HasData:  doc.OK,
		})
	}
	// Two seed spellings can normalise to one registry name; dedupe by the
	// registry spelling so the table never carries a name twice.
	rows = dedupeByName(rows)

	// No downloads data, so the downloads line and rails 2/3 are inert here;
	// decideAll still enforces the versions and long-lived lines.
	table, held, nq := decideAll("pypi", rows, nil, a.now)
	sortRows(table)
	fmt.Fprintf(os.Stderr, "pypi decide: %d qualify, %d held out, %d do not qualify (of %d candidates)\n",
		len(table), len(held), nq, len(rows))
	printHeld("pypi", held)
	if err := checkHoldFlood("pypi", len(table), len(held)); err != nil {
		return 0, err
	}
	if err := floorAndSentinels("pypi", table); err != nil {
		return 0, err
	}

	oldNames, err := parseTable(a.out)
	if err != nil {
		return 0, err
	}
	newNames := make([]string, len(table))
	for i, r := range table {
		newNames[i] = r.Name
	}
	if err := churnCheck(oldNames, newNames); err != nil {
		return 0, err
	}

	if err := writeTable(a, table, len(names), counts, len(held), 0, 0, 0); err != nil {
		return 0, err
	}
	fmt.Fprintln(os.Stderr, "self-test rail: npm-specific (patient-attacker probe against lodash) — skipped for pypi")
	return len(table), nil
}

// ---------------------------------------------------------------------------
// cargo

func generateCargo(a generateArgs) (int, error) {
	crates, err := fetchCargoListing(a.cacheDir, a.cargoPages)
	if err != nil {
		return 0, err
	}
	rows := make([]row, 0, len(crates))
	for _, c := range crates {
		rows = append(rows, row{
			Name:     c.Name,
			Weekly:   c.Downloads, // total downloads as the >=75k/90d-spirit proxy; header says so
			Versions: c.NumVersions,
			First:    c.Created,
			Last:     c.Updated,
			HasData:  true,
		})
	}
	counts := map[string]int{fmt.Sprintf("crates.io top %d by downloads", a.cargoPages*100): len(rows)}

	// No popular-seed corpus exists for cargo, so the d1 rail has no index;
	// the multi-signal floor still applies to downloads-proxy-only rows.
	table, held, nq := decideAll("cargo", rows, nil, a.now)
	sortRows(table)
	fmt.Fprintf(os.Stderr, "cargo decide: %d qualify, %d held out, %d do not qualify (of %d candidates)\n",
		len(table), len(held), nq, len(rows))
	printHeld("cargo", held)
	if err := checkHoldFlood("cargo", len(table), len(held)); err != nil {
		return 0, err
	}
	if err := floorAndSentinels("cargo", table); err != nil {
		return 0, err
	}

	oldNames, err := parseTable(a.out)
	if err != nil {
		return 0, err
	}
	newNames := make([]string, len(table))
	for i, r := range table {
		newNames[i] = r.Name
	}
	if err := churnCheck(oldNames, newNames); err != nil {
		return 0, err
	}

	if err := writeTable(a, table, len(rows), counts, len(held), 0, 0, 0); err != nil {
		return 0, err
	}
	fmt.Fprintln(os.Stderr, "self-test rail: npm-specific (patient-attacker probe against lodash) — skipped for cargo")
	return len(table), nil
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
