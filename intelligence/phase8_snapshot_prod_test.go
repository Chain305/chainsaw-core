package intelligence

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// TestPhase8VerdictSnapshot emits ONE deterministic line per corpus row so
// two checkouts can be diffed against each other.
//
// Why a two-checkout diff and not an in-binary A/B: core/risk.Registry is a
// package global populated by init()/register() (core/risk/registry.go:37-42),
// so the pre-wave and post-wave signal tables cannot coexist in one process.
// flipcount_prod_test.go's in-binary A/B works only because it toggles a
// single pure function (promoteToUpgradeAvailable); the Phase 8 waves changed
// signal severities, MaxImpact ceilings, the licence classifier and weights,
// and the unavailability arms, none of which are togglable at runtime.
//
// This test MUST be byte-identical in both checkouts, or the diff measures
// the harness rather than the engine.
//
// Opt-in: CHAINSAW_FLIP_CORPUS=/abs/reports.jsonl (one JSON object per line:
// {eco,pkg,ver,persisted_verdict,report}) — the shape
// scripts/detection-eval/build-server-risk-corpus.sh already emits and the
// shape the production intelligence_reports export uses.
// CHAINSAW_SNAPSHOT_OUT=/abs/out.txt writes the sorted snapshot to a file;
// without it the lines go to the test log.
func TestPhase8VerdictSnapshot(t *testing.T) {
	path := os.Getenv("CHAINSAW_FLIP_CORPUS")
	if path == "" {
		t.Skip("set CHAINSAW_FLIP_CORPUS=<jsonl> to emit a verdict snapshot")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()

	// Row shape is copied verbatim from flipcount_prod_test.go: that shape is
	// already the contract between the corpus builder and this package.
	type row struct {
		Eco       string          `json:"eco"`
		Pkg       string          `json:"pkg"`
		Ver       string          `json:"ver"`
		Persisted string          `json:"persisted_verdict"`
		Report    json.RawMessage `json:"report"`
	}

	prodMode := os.Getenv("CHAINSAW_SNAPSHOT_MODE") == "production"

	var lines []string
	total, parsed := 0, 0
	var badRow, badReport, nilEval int

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		total++
		var r row
		if err := json.Unmarshal(line, &r); err != nil {
			badRow++
			continue
		}
		var rep Report
		if err := json.Unmarshal(r.Report, &rep); err != nil {
			badReport++
			lines = append(lines, r.Eco+"/"+r.Pkg+"@"+r.Ver+"\tREPORT_UNPARSEABLE\t-\t-\t-\t-")
			continue
		}
		parsed++

		in := ProjectToRiskInput(&rep)
		// CHAINSAW_SNAPSHOT_MODE=production reproduces what the server
		// actually passes: ComputeTrustScoreForOrg fills
		// risk.Options.SafeUpgradeVersion from MinimumSafeVersion, which is
		// what arms the upgrade_available promotion (epochs 2 and 5) and is
		// therefore the only mode in which an epoch-8 warn -> upgrade_available
		// flip can appear at all. The default bare-Options mode isolates the
		// signal table; run BOTH and say which number came from which.
		opts := risk.Options{}
		if prodMode {
			opts.SafeUpgradeVersion = MinimumSafeVersion(&rep)
		}
		ev := risk.EvaluatePackage(in, opts)
		if ev == nil {
			nilEval++
			lines = append(lines, r.Eco+"/"+r.Pkg+"@"+r.Ver+"\tNIL_EVALUATION\t-\t-\t-\t-")
			continue
		}
		// Columns: coordinate, verdict, overall, minCategory,
		// worstCategory, rationale. The last is diagnostic only — it names
		// the top driving signal IDs, which is what turns a flip count into
		// an attributable one. Only fields that exist in BOTH checkouts may
		// appear here: RolledUp.CeilingSignal was ADDED this session, so
		// referencing it makes the base tree fail to compile.
		lines = append(lines, fmt.Sprintf("%s/%s@%s\t%s\t%d\t%d\t%s\t%s",
			r.Eco, r.Pkg, r.Ver,
			string(ev.Verdict),
			ev.RolledUp.Overall,
			ev.RolledUp.MinCategoryScore,
			string(ev.RolledUp.WorstCategory),
			nonEmpty(strings.Join(ev.Resolution.Rationale, "|")),
		))
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan corpus: %v", err)
	}

	sort.Strings(lines)

	out := os.Getenv("CHAINSAW_SNAPSHOT_OUT")
	if out != "" {
		w, err := os.Create(out)
		if err != nil {
			t.Fatalf("create snapshot out: %v", err)
		}
		bw := bufio.NewWriter(w)
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

	// Nothing is skipped silently: every row is either a snapshot line or a
	// counted failure, and the two counts below must reconcile with `total`.
	t.Logf("SNAPSHOT mode=%v lines=%s total=%s parsed=%s bad_row=%s bad_report=%s nil_eval=%s",
		prodMode, strconv.Itoa(len(lines)), strconv.Itoa(total), strconv.Itoa(parsed),
		strconv.Itoa(badRow), strconv.Itoa(badReport), strconv.Itoa(nilEval))
	if badRow != 0 {
		t.Logf("WARNING: %d corpus lines failed to unmarshal as a row and produced NO snapshot line", badRow)
	}
}

// nonEmpty keeps every column populated so a tab-split never shifts.
func nonEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
