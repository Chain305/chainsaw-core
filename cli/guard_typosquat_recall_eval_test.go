package cli

// guard_typosquat_recall_eval_test.go — measures what the block-lane gate
// COSTS, on real attacker names, in the same units the false-block harness
// (guard_typosquat_fp_eval_test.go) reports what it SAVES.
//
// ─── WHY THIS EXISTS ───────────────────────────────────────────────────────
//
// Every demotion in guard_typosquat_gate.go is a trade: a real package stops
// being refused, and some squat stops being refused with it. The false-block
// side of that trade was measured on a held-out corpus of real names. The
// recall side was argued from a six-name regression suite — which is exactly
// the shape of measurement that hides a 7% loss, because a suite made of
// hand-picked long-target typo shapes passes by construction.
//
// This harness runs the OpenSSF malicious-packages feed — every npm and PyPI
// name Chainsaw already ships as its known-malicious floor, ~219k of them —
// through the SAME predicates the install path uses, with the malware index
// deliberately out of the picture so that only the typosquat lane can speak.
// The number it prints is the one to publish next to the false-block rate.
//
// It is a MEASUREMENT, not a gate: it never fails on a rate. The bar it does
// enforce is that the corpus is usable.
//
// ─── WHAT IT IS NOT ────────────────────────────────────────────────────────
//
// This is not "the guard's malware catch rate". The known-malicious floor
// blocks every name in this feed by coordinate, at full confidence, BEFORE
// the typosquat lane runs (see evaluate() in guard_eval.go), and the feed
// ships with the CLI. What the numbers below price is the lane that catches
// the NEXT squat — a name shaped like these but not yet in any feed. A
// demotion here means that hypothetical name warns instead of refusing.
//
// ─── RUN ───────────────────────────────────────────────────────────────────
//
//	CHAINSAW_TYPOSQUAT_RECALL_FEED=$HOME/Library/Caches/chainsaw/known_malicious.json \
//	  go test ./core/cli/ -run TestTyposquatMalwareFeedBlockRecall -v -timeout 30m
//
// Accepts either the OSV JSON array Chainsaw caches (streamed, so the 197 MB
// file never lands in memory at once) or a two-column TSV of
// "<ecosystem>\t<name>" for a trimmed corpus. Skips when the var is unset, so
// CI stays hermetic and offline — the same convention as
// CHAINSAW_TYPOSQUAT_EVAL_CORPUS and CHAINSAW_DETECTION_EVAL_CORPUS.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/intelligence"
)

// tsrcFeedEnv points at an OSV malicious-packages blob or a two-column TSV.
const tsrcFeedEnv = "CHAINSAW_TYPOSQUAT_RECALL_FEED"

// tsrcMaxNames caps the corpus for a quick run. 0 (the default) means all.
const tsrcLimitEnv = "CHAINSAW_TYPOSQUAT_RECALL_LIMIT"

// tsrcEcosystems maps the OSV ecosystem label onto the ecosystem string the
// guard is called with, for the two ecosystems whose typosquat index the CLI
// actually ships. Everything else is skipped: without a popular corpus there
// is no typosquat lane to price.
var tsrcEcosystems = map[string]string{
	"npm":  "npm",
	"pypi": "pypi",
}

// tsrcName is one malicious coordinate.
type tsrcName struct {
	Ecosystem string
	Name      string
}

// tsrcModes are the configurations to price. BASELINE is the pre-fix block
// lane (rank cutoff only); the rest isolate what each predicate gives up.
var tsrcModes = []tsfpMode{
	{"BASELINE (rank cutoff only)", "baseline", typosquatBlockGate{}},
	{"P2 (target length, by shape)", "p2", typosquatBlockGate{RequireMinTargetLen: true}},
	{"P1 (edge edits demote)", "p1", typosquatBlockGate{
		RequireTypoShape: true, PopularTargetRescueRank: guardTyposquatPopularRescueRank}},
	{"P2+P1, rescue OFF", "p2p1-norescue", typosquatBlockGate{
		RequireMinTargetLen: true, RequireTypoShape: true}},
	{"P2+P1 (production gate)", "p2p1", typosquatBlockGate{
		RequireMinTargetLen: true, RequireTypoShape: true,
		PopularTargetRescueRank: guardTyposquatPopularRescueRank}},
}

const tsrcProdMode = 4

func TestTyposquatMalwareFeedBlockRecall(t *testing.T) {
	path := strings.TrimSpace(os.Getenv(tsrcFeedEnv))
	if path == "" {
		t.Skipf("set %s=<osv-json-or-tsv> to measure the gate's cost on real malicious names", tsrcFeedEnv)
	}
	limit := 0
	if v := strings.TrimSpace(os.Getenv(tsrcLimitEnv)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("%s=%q is not a number", tsrcLimitEnv, v)
		}
		limit = n
	}

	// Hermetic: the verdict must come from the EMBEDDED popularity seed, and
	// the known-malicious floor must be OUT of the way — otherwise it claims
	// every name in this corpus before the typosquat lane is consulted and
	// the measurement reads 100% by construction.
	t.Setenv(intelligence.BundleEnvVar, "")
	t.Setenv(guardDBEnv, filepath.Join(t.TempDir(), "no-such-known-malicious.json"))
	t.Setenv(guardArtifactDirEnv, "")
	t.Setenv(guardDeepFetchEnv, "")

	names, err := tsrcLoadFeed(path, limit)
	if err != nil {
		t.Fatalf("load malicious-name corpus %s: %v", path, err)
	}
	if len(names) < 100 {
		t.Fatalf("corpus %s yielded only %d npm/PyPI names — that cannot price anything", path, len(names))
	}

	ctx := context.Background()
	guard := newLocalGuard()

	type lost struct {
		Ecosystem, Name, Target, Shape string
		TargetRank, TargetLen          int
	}
	blocks := make([]int, len(tsrcModes))
	var (
		suspected int
		d1InRank  int
		lostRows  []lost
		lostEco   = map[string]int{}
		lostShape = map[string]int{}
		perEco    = map[string]int{}
	)

	for _, n := range names {
		perEco[n.Ecosystem]++
		det := guard.detector(n.Ecosystem)
		if det == nil {
			t.Fatalf("no typosquat detector for ecosystem %q", n.Ecosystem)
		}
		res := det.Check(ctx, n.Ecosystem, n.Name)
		if !res.IsSuspected {
			continue
		}
		suspected++
		gated := res.Method == "edit-distance" && res.Distance == 1 &&
			res.TargetRank > 0 && res.TargetRank <= guardTyposquatBlockRankCutoff
		if gated {
			d1InRank++
		}
		for i, m := range tsrcModes {
			if tsfpLadder(m.Gate, n.Ecosystem, n.Name, res) == tsfpBlock {
				blocks[i]++
			}
		}
		if !gated {
			continue
		}
		base := tsrcModes[0].Gate.allowsD1Block(n.Ecosystem, n.Name, res)
		prod := tsrcModes[tsrcProdMode].Gate.allowsD1Block(n.Ecosystem, n.Name, res)
		if base && !prod {
			shape := string(classifyTyposquatEdit(n.Ecosystem, n.Name, res))
			lostRows = append(lostRows, lost{
				Ecosystem: n.Ecosystem, Name: n.Name, Target: res.SimilarTo, Shape: shape,
				TargetRank: res.TargetRank, TargetLen: len([]rune(res.SimilarTo)),
			})
			lostEco[n.Ecosystem]++
			lostShape[shape]++
		}
	}

	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("")
	w("TYPOSQUAT BLOCK RECALL ON REAL MALICIOUS NAMES")
	w("feed: %s", path)
	w("")
	ecos := make([]string, 0, len(perEco))
	for e := range perEco {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	for _, e := range ecos {
		w("  %-6s %8d names", e, perEco[e])
	}
	w("  %-6s %8d names", "TOTAL", len(names))
	w("")
	w("  detector fired on %d (%.2f%%); %d of those are d=1 against an in-cutoff target,",
		suspected, pct(suspected, len(names)), d1InRank)
	w("  which is the only population this gate can speak for.")
	w("")
	w("  %-30s %8s %10s", "configuration", "BLOCK", "of baseline")
	w("  %-30s %8s %10s", strings.Repeat("-", 30), strings.Repeat("-", 8), strings.Repeat("-", 10))
	for i, m := range tsrcModes {
		w("  %-30s %8d %9.1f%%", m.Label, blocks[i], pct(blocks[i], blocks[0]))
	}
	w("")
	w("  The production gate gives up %d of BASELINE's %d typosquat-lane blocks (%.1f%%).",
		blocks[0]-blocks[tsrcProdMode], blocks[0], pct(blocks[0]-blocks[tsrcProdMode], blocks[0]))
	w("  Every one of them still WARNS, and prints under --quiet (severity %q).", guardSeverityTyposquatDemoted)
	w("")
	w("  lost by ecosystem: %v", lostEco)
	w("  lost by edit shape: %v", lostShape)

	sort.Slice(lostRows, func(i, j int) bool {
		if lostRows[i].TargetRank != lostRows[j].TargetRank {
			return lostRows[i].TargetRank < lostRows[j].TargetRank
		}
		return lostRows[i].Name < lostRows[j].Name
	})
	w("")
	w("DEMOTED MALICIOUS NAMES (most popular target first; the full list is the deliverable)")
	for _, r := range lostRows {
		w("  %-6s %-40s → %-24q #%-5d len %d  %s",
			r.Ecosystem, r.Name, r.Target, r.TargetRank, r.TargetLen, r.Shape)
	}

	w("")
	w("CAVEAT: this is the lane's block recall on names that are ALREADY in the")
	w("shipped known-malicious floor, which refuses them by coordinate before the")
	w("typosquat lane runs. It prices the lane's value against the NEXT squat of")
	w("the same shape, not today's protection for these names.")

	t.Log(b.String())
}

// tsrcLoadFeed reads npm/PyPI names out of an OSV JSON array (streamed) or a
// two-column TSV, de-duplicated, order-stable.
func tsrcLoadFeed(path string, limit int) ([]tsrcName, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{}
	var out []tsrcName
	add := func(eco, name string) bool {
		eco = strings.ToLower(strings.TrimSpace(eco))
		guardEco, ok := tsrcEcosystems[eco]
		if !ok {
			return true
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return true
		}
		key := guardEco + "\x00" + strings.ToLower(name)
		if seen[key] {
			return true
		}
		seen[key] = true
		out = append(out, tsrcName{Ecosystem: guardEco, Name: name})
		return limit <= 0 || len(out) < limit
	}

	if strings.HasSuffix(path, ".tsv") {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Split(line, "\t")
			if len(parts) < 2 {
				continue
			}
			if !add(parts[0], parts[1]) {
				break
			}
		}
		return out, nil
	}

	// Streaming OSV: read the opening '[' then decode one entry at a time, so
	// a 197 MB feed costs one entry of memory rather than all of it.
	dec := json.NewDecoder(f)
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("read first token: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return nil, fmt.Errorf("expected a JSON array, got %v", tok)
	}
	type osvAffected struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
	}
	type osvEntry struct {
		Affected []osvAffected `json:"affected"`
	}
	for dec.More() {
		var e osvEntry
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("decode entry %d: %w", len(out), err)
		}
		for _, a := range e.Affected {
			if !add(a.Package.Ecosystem, a.Package.Name) {
				return out, nil
			}
		}
	}
	return out, nil
}
