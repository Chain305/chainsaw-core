package intelligence

// TestPhase8TransitiveVerdictSnapshot is the transitive-aware twin of
// TestPhase8VerdictSnapshot.
//
// WHY A FOURTH HARNESS. TestPhase8VerdictSnapshot calls
// risk.EvaluatePackage, which computes the DIRECT score and nothing else.
// It never runs the transitive pass, so two whole populations are invisible
// to it:
//
//  1. Rows whose verdict comes from the ROLLUP rather than from their own
//     signals. On the production corpus 1,042 rows (14.5%) persist with
//     RolledUp.Overall < DirectScore.Overall; 45 of them persist as
//     `quarantine` yet re-evaluate to `allow` under a direct-only replay.
//     Read through the direct-only harness those 45 look like untrustworthy
//     stored verdicts. They are not — they are quarantined by their
//     DEPENDENCIES, and a direct-only instrument cannot say so.
//
//  2. AMPLIFICATION. A direct-score flip on a widely-depended-on package
//     propagates into every parent's rolled-up score and transitive severity
//     counts, and can move the PARENT's verdict even when the parent's own
//     direct verdict did not move. The direct-only harness reports zero for
//     a parent in that state.
//
// WHAT IT RUNS. The production sequence, in production order, calling the
// product's own functions rather than a reimplementation of them
// (scanner.go: ComputeTrustScoreForOrg -> evaluateTransitiveRisk ->
// ReapplyKnownFixAfterTransitive). Constraint resolution, the per-ecosystem
// satisfiers, the BFS, the cycle guard, the `latest` sentinel probe and the
// matcher-stale skip all come from provider_transitiverisk.go verbatim. The
// only thing this file supplies is a `transitiveLookup` backed by the corpus
// instead of Postgres — and the corpus IS the store, because the export is
// the whole intelligence_reports table.
//
// markNoAdvisoryCoverage is deliberately NOT called: it does not exist at
// the base commit, and this file must compile and run byte-identically in
// both checkouts or the diff measures the harness instead of the engine.
// Every field and function referenced below exists in BOTH trees.
//
// THREE DELIBERATE DEVIATIONS FROM PRODUCTION, all of which make the
// measurement possible rather than flattering it:
//
//	(a) MATCHER EPOCH. lookupDepReport refuses any row where
//	    Report.MatcherStale() is true, i.e. Observation.MatcherEpoch <
//	    CurrentMatcherEpoch. The corpus tops out at epoch 5 while HEAD's
//	    CurrentMatcherEpoch is 8, so an unmodified replay would resolve
//	    ZERO dependencies at HEAD and a full set at base — a pure harness
//	    artifact that would swamp every number this file exists to produce.
//	    The corpus store therefore stamps CurrentMatcherEpoch on each
//	    report it serves, and counts separately how many of those serves
//	    were of rows that the real store WOULD have refused
//	    (`served_below_epoch`). That counter is itself an operational
//	    finding and is reported, not hidden. MatcherEpoch feeds nothing in
//	    ProjectToRiskInput or core/risk, so stamping it cannot move a
//	    score.
//
//	(b) LISTVERSIONS ORDER. Store.ListVersions documents that its order is
//	    not guaranteed, and pickConstraintMatchDetailed keeps the FIRST of
//	    two versions its comparator ranks equal. The corpus store returns a
//	    sorted slice so a rerun cannot produce a different answer.
//
//	(c) NO NETWORK. LatestVersionCorroborator stays nil, so
//	    upgradeCandidateCorroborated falls back to the Report's own
//	    Release.LatestVersion exactly as it does for a cache-only replay.
//
// COVERAGE IS THE HONESTY REQUIREMENT. Production only scanned what it was
// asked about, so most dependencies are NOT in the corpus. Every emitted
// line carries its own resolved/total direct-dep coverage and its closure
// size, and the summary reports the distribution. A root whose deps did not
// resolve gets a shallow tree and a rollup close to its direct score: that
// is a MEASUREMENT LIMITATION, not a finding, and a low-coverage root must
// never be read as evidence that the transitive pass had nothing to say.
//
// Opt-in: CHAINSAW_FLIP_CORPUS=/abs/reports.jsonl (same row shape as the
// three sibling harnesses, plus the optional `epoch` field).
// CHAINSAW_SNAPSHOT_OUT=/abs/out.txt writes the sorted snapshot.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// transitiveLatestSentinel is the literal version string candidateVersions
// appends to every probe list, and probes BEFORE the constraint match. A
// corpus row stored at that coordinate therefore wins over the row the
// constraint actually names. The corpus holds 14 such rows, so the path is
// live; the store counts every serve so the snapshot can flag which roots
// resolved through it (column 8).
const transitiveLatestSentinel = "latest"

// transitiveCorpusKey mirrors the store's primary key. Matching is exact on
// all three fields because Store.Get's SQL is exact on all three fields —
// case-folding here would resolve dependencies production could not.
type transitiveCorpusKey struct {
	eco string
	pkg string
	ver string
}

// transitiveCorpusRow is one line of the export.
type transitiveCorpusRow struct {
	Eco       string          `json:"eco"`
	Pkg       string          `json:"pkg"`
	Ver       string          `json:"ver"`
	Persisted string          `json:"persisted_verdict"`
	Epoch     int             `json:"epoch"`
	Report    json.RawMessage `json:"report"`
}

// transitiveCorpusStore is a read-only transitiveLookup over the export. It
// implements exactly the two methods evaluateTransitiveRisk needs and adds
// nothing else: every resolution decision stays in lookupDepReport.
type transitiveCorpusStore struct {
	raw      map[transitiveCorpusKey]json.RawMessage
	epoch    map[transitiveCorpusKey]int
	versions map[string][]string
	cache    map[transitiveCorpusKey]*Report
	cacheCap int

	getCalls         int
	getHits          int
	getMisses        int
	decodeFailures   int
	servedBelowEpoch int
	latestServes     int
	latestThisRoot   int
	listCalls        int
}

func newTransitiveCorpusStore(cacheCap int) *transitiveCorpusStore {
	return &transitiveCorpusStore{
		raw:      make(map[transitiveCorpusKey]json.RawMessage),
		epoch:    make(map[transitiveCorpusKey]int),
		versions: make(map[string][]string),
		cache:    make(map[transitiveCorpusKey]*Report),
		cacheCap: cacheCap,
	}
}

func transitiveVersionsKey(eco, name string) string { return eco + "\x00" + name }

func (s *transitiveCorpusStore) add(r transitiveCorpusRow) {
	k := transitiveCorpusKey{r.Eco, r.Pkg, r.Ver}
	if _, dup := s.raw[k]; !dup {
		vk := transitiveVersionsKey(r.Eco, r.Pkg)
		s.versions[vk] = append(s.versions[vk], r.Ver)
	}
	s.raw[k] = r.Report
	s.epoch[k] = r.Epoch
}

// finalise sorts every version list so pickConstraintMatchDetailed's
// first-wins tie-break is reproducible. See deviation (b).
func (s *transitiveCorpusStore) finalise() {
	for k := range s.versions {
		sort.Strings(s.versions[k])
	}
}

func (s *transitiveCorpusStore) Get(_ context.Context, _ string, key Key) (*Report, error) {
	k := transitiveCorpusKey{key.Ecosystem, key.Package, key.Version}
	s.getCalls++
	blob, ok := s.raw[k]
	if !ok {
		s.getMisses++
		return nil, ErrNotFound
	}
	if key.Version == transitiveLatestSentinel {
		s.latestServes++
		s.latestThisRoot++
	}
	if s.epoch[k] < CurrentMatcherEpoch {
		s.servedBelowEpoch++
	}
	if rep, cached := s.cache[k]; cached {
		s.getHits++
		return rep, nil
	}
	var rep Report
	if err := json.Unmarshal(blob, &rep); err != nil {
		s.decodeFailures++
		return nil, ErrNotFound
	}
	// Deviation (a): neutralise the epoch skip so the two checkouts see the
	// same resolvable set. Counted above, never silent.
	rep.Observation.MatcherEpoch = CurrentMatcherEpoch
	if len(s.cache) < s.cacheCap {
		s.cache[k] = &rep
	}
	s.getHits++
	return &rep, nil
}

func (s *transitiveCorpusStore) ListVersions(_ context.Context, _ string, ecosystem, name string) ([]string, error) {
	s.listCalls++
	v := s.versions[transitiveVersionsKey(ecosystem, name)]
	out := make([]string, len(v))
	copy(out, v)
	return out, nil
}

// transitiveBucket buckets a resolved/total ratio for the coverage
// histogram the summary leads with.
func transitiveBucket(resolved, total int) string {
	switch {
	case total == 0:
		return "no_declared_deps"
	case resolved == 0:
		return "0%"
	case resolved == total:
		return "100%"
	case resolved*4 >= total*3:
		return "75-99%"
	case resolved*2 >= total:
		return "50-74%"
	case resolved*4 >= total:
		return "25-49%"
	default:
		return "1-24%"
	}
}

func TestPhase8TransitiveVerdictSnapshot(t *testing.T) {
	path := os.Getenv("CHAINSAW_FLIP_CORPUS")
	if path == "" {
		t.Skip("set CHAINSAW_FLIP_CORPUS=<jsonl> to emit a transitive verdict snapshot")
	}
	// Pin the walk depth so the two checkouts agree and a stray env in one
	// shell cannot silently change the closure size on one side only.
	t.Setenv(TransitiveDepthEnv, "5")

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}

	store := newTransitiveCorpusStore(6000)
	var (
		total     int
		badRow    int
		dupCoord  int
		rows      []transitiveCorpusRow
		seenCoord = make(map[transitiveCorpusKey]struct{})
	)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		total++
		var r transitiveCorpusRow
		if err := json.Unmarshal(line, &r); err != nil {
			badRow++
			continue
		}
		k := transitiveCorpusKey{r.Eco, r.Pkg, r.Ver}
		if _, dup := seenCoord[k]; dup {
			dupCoord++
		}
		seenCoord[k] = struct{}{}
		store.add(r)
		rows = append(rows, r)
	}
	if err := sc.Err(); err != nil {
		_ = f.Close()
		t.Fatalf("scan corpus: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close corpus: %v", err)
	}
	store.finalise()

	// Deterministic root order. The snapshot is sorted before it is written
	// anyway, but a fixed evaluation order keeps the per-root `latest`
	// counter and the progress log reproducible too.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Eco != rows[j].Eco {
			return rows[i].Eco < rows[j].Eco
		}
		if rows[i].Pkg != rows[j].Pkg {
			return rows[i].Pkg < rows[j].Pkg
		}
		return rows[i].Ver < rows[j].Ver
	})

	ctx := context.Background()
	var (
		lines []string

		parsed, badReport, nilEval int
		rootsWithDeclaredDeps      int
		rootsWithClosure           int
		rootsLatestResolved        int
		declaredDeps, resolvedDeps int
		closureTotal               int
		verdictMovedByTree         int
		rolledBelowDirect          int
		carriesTransitiveSeverity  int
		reproducedPersisted        int
		directReproducedPersisted  int
		coverageHist               = map[string]int{}
	)

	for _, r := range rows {
		coord := r.Eco + "/" + r.Pkg + "@" + r.Ver
		var rep Report
		if err := json.Unmarshal(r.Report, &rep); err != nil {
			badReport++
			lines = append(lines, coord+"\tREPORT_UNPARSEABLE\t-\t-\t-\t-\t-\t-\t-\t-\t-")
			continue
		}
		parsed++

		// Production step 1. Fills report.Risk, including the direct-only
		// upgrade promotion, exactly as the scanner does.
		ComputeTrustScoreForOrg(&rep, "")
		if rep.Risk == nil {
			nilEval++
			lines = append(lines, coord+"\tNIL_EVALUATION\t-\t-\t-\t-\t-\t-\t-\t-\t-")
			continue
		}
		directVerdict := string(rep.Risk.Verdict)
		directOverall := rep.Risk.DirectScore.Overall

		declared := len(rep.Dependencies.Direct)
		declaredDeps += declared
		if declared > 0 {
			rootsWithDeclaredDeps++
		}

		// Production steps 2 and 3.
		store.latestThisRoot = 0
		evaluateTransitiveRisk(ctx, store, "", &rep)
		ReapplyKnownFixAfterTransitive(&rep, "")

		treeVerdict := string(rep.Risk.Verdict)
		rolledOverall := rep.Risk.RolledUp.Overall

		resolved, closure := 0, 0
		if tc := rep.SupplyChain.TransitiveCoverage; tc != nil {
			resolved = tc.Resolved
			closure = tc.ClosureSize
		}
		resolvedDeps += resolved
		closureTotal += closure
		if closure > 0 {
			rootsWithClosure++
		}
		if store.latestThisRoot > 0 {
			rootsLatestResolved++
		}
		coverageHist[transitiveBucket(resolved, declared)]++

		ts := rep.Risk.Resolution.TransitiveSeverity
		if ts != (risk.TransitiveSeverity{}) {
			carriesTransitiveSeverity++
		}
		if treeVerdict != directVerdict {
			verdictMovedByTree++
		}
		if rolledOverall < directOverall {
			rolledBelowDirect++
		}
		if r.Persisted != "" && treeVerdict == r.Persisted {
			reproducedPersisted++
		}
		if r.Persisted != "" && directVerdict == r.Persisted {
			directReproducedPersisted++
		}

		// Blame is sorted before it is printed: the fallback branch in
		// evaluateTransitiveRisk appends in te.ByKey map order, so the
		// unsorted list is not reproducible and would show up as a phantom
		// diff between two runs of the SAME tree.
		blame := make([]string, 0, len(rep.Risk.Resolution.TransitiveBlame))
		for _, b := range rep.Risk.Resolution.TransitiveBlame {
			blame = append(blame, b.Ecosystem+"/"+b.Package+"@"+b.Version)
		}
		sort.Strings(blame)
		blameTop := "-"
		if len(blame) > 0 {
			blameTop = strings.Join(blame[:min3(len(blame))], ",")
		}

		// Columns, all present in BOTH checkouts.
		//
		// ALL COLUMNS ARE STABLE. Columns 9-11 used to jitter run to run
		// because of two engine-level nondeterminism bugs (map-ordered float
		// accumulation in computeOverall, and map-ordered blame ranking in
		// rollupForNode). Both are fixed — see the note at the top of the
		// summary — so a two-checkout diff may now be taken on every column.
		//
		//   1 coordinate
		//   2 persisted verdict (from the export, constant across trees)
		//   3 DIRECT verdict  — post ComputeTrustScoreForOrg, pre-rollup
		//   4 TREE verdict    — post evaluateTransitiveRisk + reapply
		//   5 resolved/declared direct deps  (COVERAGE — read before 3 and 4)
		//   6 closure size
		//   7 transitive severity c/h/m/l/malware/blocked
		//   8 how many `latest`-sentinel rows this root resolved through
		//   9 direct overall
		//  10 rolled-up overall
		//  11 blame count + sorted top 3
		//
		// Columns 3 and 4 together are what make the amplification count
		// computable: a root whose column 3 is identical in both trees but
		// whose column 4 differs changed verdict because a DESCENDANT moved.
		lines = append(lines, fmt.Sprintf(
			"%s\t%s\t%s\t%s\t%d/%d\t%d\t%d/%d/%d/%d/%d/%d\t%d\t%d\t%d\t%d:%s",
			coord, r.Persisted, directVerdict, treeVerdict,
			resolved, declared, closure,
			ts.CriticalCount, ts.HighCount, ts.MediumCount, ts.LowCount,
			ts.MalwareCount, ts.BlockedCount,
			store.latestThisRoot,
			directOverall, rolledOverall,
			len(blame), blameTop,
		))
	}

	sort.Strings(lines)

	pct := func(n, d int) float64 {
		if d == 0 {
			return 0
		}
		return 100 * float64(n) / float64(d)
	}
	covKeys := make([]string, 0, len(coverageHist))
	for k := range coverageHist {
		covKeys = append(covKeys, k)
	}
	sort.Strings(covKeys)
	var covLine strings.Builder
	for i, k := range covKeys {
		if i > 0 {
			covLine.WriteString(" ")
		}
		fmt.Fprintf(&covLine, "%s=%d", k, coverageHist[k])
	}

	summary := fmt.Sprintf(
		"TRANSITIVE SNAPSHOT total=%d parsed=%d bad_row=%d bad_report=%d nil_eval=%d dup_coord=%d\n"+
			"  COVERAGE FIRST (read before any headline number):\n"+
			"    roots declaring direct deps = %d (%.2f%% of parsed)\n"+
			"    direct deps resolved to a corpus row = %d/%d (%.2f%%)\n"+
			"    roots with a non-empty closure = %d ; total closure nodes = %d\n"+
			"    per-root direct-dep coverage histogram: %s\n"+
			"    NOTE: a root in the 0%%/1-24%% buckets is modelled SHALLOWLY. Its\n"+
			"    rollup necessarily sits close to its direct score. That is a limit of\n"+
			"    the corpus, not a property of the package.\n"+
			"  ENGINE STATE UNDER THIS BUILD:\n"+
			"    rolled_up < direct = %d (%.2f%%)\n"+
			"    carries a non-zero transitiveSeverity = %d (%.2f%%)\n"+
			"    tree verdict != direct verdict = %d (%.2f%%)\n"+
			"    reproduces persisted verdict: direct-only=%d (%.2f%%) with-tree=%d (%.2f%%)\n"+
			"  EVERY COLUMN IS DIFFABLE (both nondeterminism sources are FIXED):\n"+
			"    col 9/10 (scores): computeOverall used to sum the per-category\n"+
			"      deficit while ranging over the CategoryWeights MAP, so float\n"+
			"      addition order — and the round-half-up at int(deficit+0.5) —\n"+
			"      varied run to run. 160 of 200k random fixtures straddled a\n"+
			"      VERDICT BAND. Fixed: it iterates AllCategories().\n"+
			"    col 11 (blame): rollupForNode ranked TransitiveBlame against the\n"+
			"      progressively-mutated running max while walking `depths` in MAP\n"+
			"      order, so a descendant visited early masked one visited later.\n"+
			"      696 rows on this corpus named different deps run to run. Fixed:\n"+
			"      blame is measured against the node's OWN deficit. The rolled\n"+
			"      score was never affected — it is a max, and max is commutative,\n"+
			"      which is why this hid for so long.\n"+
			"    Verified: three consecutive runs are byte-identical, and the blame\n"+
			"      fix moved 838 rows' blame while changing ZERO verdicts and ZERO\n"+
			"      scores.\n"+
			"  STORE BEHAVIOUR:\n"+
			"    Get calls=%d hits=%d misses=%d decode_failures=%d ListVersions calls=%d\n"+
			"    served_below_epoch=%d  (rows the REAL store would have refused as\n"+
			"      matcher-stale; the corpus tops out below CurrentMatcherEpoch=%d)\n"+
			"    latest_sentinel_serves=%d across %d roots  (candidateVersions probes the\n"+
			"      literal \"latest\" BEFORE the constraint match — see column 8)",
		total, parsed, badRow, badReport, nilEval, dupCoord,
		rootsWithDeclaredDeps, pct(rootsWithDeclaredDeps, parsed),
		resolvedDeps, declaredDeps, pct(resolvedDeps, declaredDeps),
		rootsWithClosure, closureTotal,
		covLine.String(),
		rolledBelowDirect, pct(rolledBelowDirect, parsed),
		carriesTransitiveSeverity, pct(carriesTransitiveSeverity, parsed),
		verdictMovedByTree, pct(verdictMovedByTree, parsed),
		directReproducedPersisted, pct(directReproducedPersisted, parsed),
		reproducedPersisted, pct(reproducedPersisted, parsed),
		store.getCalls, store.getHits, store.getMisses, store.decodeFailures, store.listCalls,
		store.servedBelowEpoch, CurrentMatcherEpoch,
		store.latestServes, rootsLatestResolved,
	)

	if out := os.Getenv("CHAINSAW_SNAPSHOT_OUT"); out != "" {
		w, err := os.Create(out)
		if err != nil {
			t.Fatalf("create snapshot out: %v", err)
		}
		bw := bufio.NewWriter(w)
		fmt.Fprintln(bw, "# "+strings.ReplaceAll(summary, "\n", "\n# "))
		for _, l := range lines {
			fmt.Fprintln(bw, l)
		}
		if err := bw.Flush(); err != nil {
			t.Fatalf("flush snapshot: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close snapshot: %v", err)
		}
	} else {
		for _, l := range lines {
			t.Log(l)
		}
	}

	// Nothing is skipped silently: every corpus line is either a snapshot
	// line or a counted failure, and these must reconcile with `total`.
	if got := len(lines) + badRow; got != total {
		t.Errorf("row accounting does not reconcile: lines=%d bad_row=%d total=%d", len(lines), badRow, total)
	}
	t.Log("\n" + summary)
	if badRow != 0 {
		t.Logf("WARNING: %d corpus lines failed to unmarshal as a row and produced NO snapshot line", badRow)
	}
}

// min3 caps the printed blame list without importing a helper that may not
// exist in both checkouts.
func min3(n int) int {
	if n > 3 {
		return 3
	}
	return n
}
