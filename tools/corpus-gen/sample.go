package main

// The build pipeline: enumerate → resolve → verify → classify → exclude →
// deduplicate → allocate → freeze.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Row is one corpus coordinate with its ground truth.
type Row struct {
	Coord
	Stratum    string
	Truth      string
	Confidence string // A observed directly | B derived from a feed | C text-derived
	PairID     string
	Label      string // the corpus.tsv label the existing harnesses read
	Published  string
	Licenses   []string
	Behaviors  Behaviors
	Provenance string
	Notes      string
}

// Exclusion is one rejected candidate and why. Written out so the corpus can
// be audited for selection bias: "why is that package not in the corpus" has
// a mechanical answer too, not just "why is it in".
type Exclusion struct {
	Coord
	Stratum string
	Reason  string
}

// subRNG derives an independent, deterministic stream per (seed, purpose).
//
// Independent streams are the reason adding a stratum does not reshuffle the
// ones already drawn, and the reason changing --pool-multiplier for one
// ecosystem leaves the other seven byte-identical. A single shared stream
// would make every number in the corpus depend on every other, which is a
// reproducibility claim that collapses the first time anyone tunes anything.
func subRNG(seed string, parts ...string) *rand.Rand {
	h := sha256.Sum256([]byte(seed + "\x00" + strings.Join(parts, "\x00")))
	return rand.New(rand.NewPCG(
		binary.BigEndian.Uint64(h[0:8]),
		binary.BigEndian.Uint64(h[8:16]),
	))
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// sampleStrings draws want items from a SORTED pool without replacement.
// The caller is responsible for the sort; see the determinism note in main.go.
func sampleStrings(pool []string, rng *rand.Rand, want int) []string {
	if want >= len(pool) {
		out := make([]string, len(pool))
		copy(out, pool)
		return out
	}
	idx := rng.Perm(len(pool))[:want]
	sort.Ints(idx)
	out := make([]string, 0, want)
	for _, i := range idx {
		out = append(out, pool[i])
	}
	return out
}

// allocate splits target across ecos as evenly as the available supply allows.
//
// EQUAL WEIGHTING IS THE INTENT; AVAILABILITY IS THE CONSTRAINT. Benign strata
// hit the equal share every time — every registry has millions of packages.
// Malicious strata cannot: the public feed holds 2 maven records and 1
// packagist record in total. So the equal share is capped at what exists and
// the deficit is redistributed to ecosystems with surplus. The shortfall is
// RETURNED, not swallowed, because a stratum quietly filled from one
// ecosystem is how a cross-ecosystem claim gets made from an npm sample.
func allocate(target int, ecos []string, available map[string]int) (map[string]int, int) {
	alloc := map[string]int{}
	share := target / len(ecos)
	rem := target % len(ecos)
	for i, e := range ecos {
		want := share
		if i < rem {
			want++
		}
		if a := available[e]; want > a {
			want = a
		}
		alloc[e] = want
	}
	assigned := 0
	for _, n := range alloc {
		assigned += n
	}
	// Redistribute the deficit in a fixed ecosystem order so the result is
	// deterministic rather than map-iteration-dependent.
	for assigned < target {
		progressed := false
		for _, e := range ecos {
			if assigned >= target {
				break
			}
			if alloc[e] < available[e] {
				alloc[e]++
				assigned++
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	return alloc, target - assigned
}

// resolved is one verified candidate coordinate plus what the neutral sources
// said about it.
type resolved struct {
	Info *VersionInfo
	OSV  OSVResult
}

func runBuild(o buildOpts) error {
	start := time.Now()
	c := newClient()

	fmt.Fprintf(os.Stderr, "corpus-gen build  seed=%q  target=%d coordinates\n", o.seed, totalTarget())

	// ── 1. Ground truth, pinned ──────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "\n[1/6] loading OpenSSF malicious-packages from %s\n", o.ossfDir)
	mal, ossfCommit, ossfSkipped, err := loadOSSF(o.ossfDir)
	if err != nil {
		return err
	}
	byEco := map[string]int{}
	pinnedByEco := map[string]int{}
	for _, r := range mal {
		byEco[r.Eco]++
		if len(r.Versions) > 0 {
			pinnedByEco[r.Eco]++
		}
	}
	fmt.Fprintf(os.Stderr, "      %d usable records @ %s\n", len(mal), ossfCommit[:12])
	for _, e := range ecosystems {
		if byEco[e] > 0 {
			fmt.Fprintf(os.Stderr, "        %-10s %7d records, %7d version-pinned\n", e, byEco[e], pinnedByEco[e])
		}
	}

	var rows []Row
	var excl []Exclusion
	used := map[string]bool{} // coordinate dedup across every stratum

	// ── 2. Malicious strata ──────────────────────────────────────────────
	//
	// M1 / M2 / M3 / T1 all draw from the same pinned feed but ask a
	// different question of each record, so they are allocated in a fixed
	// order and a record consumed by an earlier stratum is not offered to a
	// later one. T1 and M3 come FIRST because they are the scarce ones —
	// letting M1 take 250 arbitrary records before T1 looks for typosquats
	// would starve the specific stratum to fill the general one.
	fmt.Fprintln(os.Stderr, "\n[2/6] malicious strata (OpenSSF, pinned)")
	for _, spec := range []struct {
		stratum string
		pick    func(MaliciousRecord) bool
		conf    string
		note    string
	}{
		{"T1", func(r MaliciousRecord) bool { return len(r.Classification) > 0 }, "C", "attack type derived from advisory prose; see ossf.go"},
		{"M3", func(r MaliciousRecord) bool { return r.IsBehavioral() }, "B", "origin " + BehavioralSource + ": behaviour observed executing"},
		{"M1", func(r MaliciousRecord) bool { return true }, "B", ""},
	} {
		q := quotaFor(spec.stratum)
		pools := map[string][]MaliciousRecord{}
		for _, r := range mal {
			if len(r.Versions) == 0 {
				continue // unpinned: no coordinate to scan
			}
			if !spec.pick(r) {
				continue
			}
			if used["ossf:"+r.ID] {
				continue
			}
			pools[r.Eco] = append(pools[r.Eco], r)
		}
		avail := map[string]int{}
		for e, p := range pools {
			avail[e] = len(p)
		}
		alloc, short := allocate(q.Target, ecosystems, avail)
		got := 0
		for _, e := range ecosystems {
			want := alloc[e]
			if want == 0 {
				continue
			}
			rng := subRNG(o.seed, spec.stratum, e)
			pool := pools[e]
			// Oversample so a coordinate the registry cannot confirm
			// does not cost the stratum a row.
			idx := rng.Perm(len(pool))
			for _, i := range idx {
				if alloc[e] <= 0 {
					break
				}
				r := pool[i]
				if used["ossf:"+r.ID] {
					continue
				}
				ver := r.Versions[rng.IntN(len(r.Versions))]
				co := Coord{Eco: r.Eco, Name: r.Name, Version: ver}
				if used[co.Key()] {
					continue
				}
				used["ossf:"+r.ID] = true
				used[co.Key()] = true
				alloc[e]--
				got++
				rows = append(rows, Row{
					Coord: co, Stratum: spec.stratum, Truth: q.Truth, Label: q.Label,
					Confidence: spec.conf, Published: r.Published.Format(time.RFC3339),
					Provenance: "ossf:" + r.ID + " (" + strings.Join(r.Sources, ",") + ")",
					Notes:      strings.TrimSpace(spec.note + " " + strings.Join(r.Classification, ",")),
				})
			}
		}
		fmt.Fprintf(os.Stderr, "      %s  %d/%d", spec.stratum, got, q.Target)
		if short > 0 || got < q.Target {
			fmt.Fprintf(os.Stderr, "   SHORTFALL %d (public ground truth does not contain more)", q.Target-got)
			excl = append(excl, Exclusion{Stratum: spec.stratum, Reason: fmt.Sprintf("shortfall:%d", q.Target-got)})
		}
		fmt.Fprintln(os.Stderr)
	}

	// ── 3. M2: reported malicious, registry no longer serves it ──────────
	//
	// The name is the whole point. "Registry absent" is a fact we can
	// check; "tombstoned" would assert the registry removed it FOR being
	// malicious, which nothing here establishes.
	fmt.Fprintln(os.Stderr, "\n[3/6] M2 — reported malicious, registry absent")
	{
		q := quotaFor("M2")
		pools := map[string][]MaliciousRecord{}
		for _, r := range mal {
			if len(r.Versions) == 0 || used["ossf:"+r.ID] {
				continue
			}
			pools[r.Eco] = append(pools[r.Eco], r)
		}
		avail := map[string]int{}
		for e, p := range pools {
			avail[e] = len(p)
		}
		alloc, _ := allocate(q.Target, ecosystems, avail)
		got := 0
		for _, e := range ecosystems {
			if alloc[e] == 0 {
				continue
			}
			rng := subRNG(o.seed, "M2", e)
			pool := pools[e]
			need := alloc[e]
			// Probe up to 6x the need: most reported packages are still
			// served, and "absent" is the minority case we are after.
			for _, i := range rng.Perm(len(pool)) {
				if need == 0 {
					break
				}
				r := pool[i]
				if used["ossf:"+r.ID] {
					continue
				}
				ver := r.Versions[rng.IntN(len(r.Versions))]
				co := Coord{Eco: r.Eco, Name: r.Name, Version: ver}
				if used[co.Key()] {
					continue
				}
				if _, err := c.resolveVersion(r.Eco, r.Name, subRNG(o.seed, "M2probe", r.ID)); err == nil {
					// Still served: this is an M1 shape, not M2.
					excl = append(excl, Exclusion{Coord: co, Stratum: "M2", Reason: "registry_still_serves"})
					continue
				}
				used["ossf:"+r.ID] = true
				used[co.Key()] = true
				need--
				got++
				rows = append(rows, Row{
					Coord: co, Stratum: "M2", Truth: q.Truth, Label: q.Label,
					Confidence: "B", Published: r.Published.Format(time.RFC3339),
					Provenance: "ossf:" + r.ID + "; registry lookup returned no such package",
					Notes:      "absence does not prove removal FOR maliciousness",
				})
			}
		}
		fmt.Fprintf(os.Stderr, "      M2  %d/%d\n", got, q.Target)
	}

	// ── 4. Shared benign / vulnerable candidate pool ─────────────────────
	fmt.Fprintln(os.Stderr, "\n[4/6] registry candidate pool (enumerate → resolve → verify)")
	poolNeed := 0
	for _, s := range []string{"B1", "B2", "V1", "R1", "L1"} {
		poolNeed += quotaFor(s).Target
	}
	perEco := (poolNeed*o.poolMult)/len(ecosystems) + 1
	pool := map[string][]resolved{}
	for _, e := range ecosystems {
		names, err := c.enumerate(e, subRNG(o.seed, "enumerate", e), perEco)
		if err != nil {
			fmt.Fprintf(os.Stderr, "      %-10s enumerate FAILED: %v\n", e, err)
			continue
		}
		infos := c.resolveAll(e, names, o.seed, o.concurrency)
		coords := make([]Coord, 0, len(infos))
		for _, in := range infos {
			coords = append(coords, in.Coord())
		}
		osvBy, _ := c.osvQueryBatch(coords)
		for _, in := range infos {
			r := osvBy[in.Coord().Key()]
			if !r.Queried {
				// OSV did not answer. Not "clean" — dropped, with a
				// reason. Recording silence as safety is how a fetch
				// failure becomes a false-positive denominator.
				excl = append(excl, Exclusion{Coord: in.Coord(), Reason: "osv_no_answer"})
				continue
			}
			pool[e] = append(pool[e], resolved{Info: in, OSV: r})
		}
		sort.Slice(pool[e], func(i, j int) bool {
			return pool[e][i].Info.Coord().Key() < pool[e][j].Info.Coord().Key()
		})
		vuln := 0
		for _, p := range pool[e] {
			if len(p.OSV.VulnIDs) > 0 {
				vuln++
			}
		}
		fmt.Fprintf(os.Stderr, "      %-10s %5d names → %5d verified coordinates (%d with advisories)\n",
			e, len(names), len(pool[e]), vuln)
	}

	// ── 5. Derived strata ────────────────────────────────────────────────
	fmt.Fprintln(os.Stderr, "\n[5/6] derived strata")
	rows = append(rows, c.fillVulnPairs(o, used, &excl)...)
	rows = append(rows, c.fillBehavioral(o, pool, used, &excl)...)
	rows = append(rows, fillMaintenance(o, pool, used, &excl)...)
	rows = append(rows, fillLicense(o, pool, used, &excl)...)
	rows = append(rows, fillPresumedBenign(o, pool, used, &excl)...)

	// ── 6. Freeze ────────────────────────────────────────────────────────
	fmt.Fprintln(os.Stderr, "\n[6/6] emitting")
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Stratum != rows[j].Stratum {
			return rows[i].Stratum < rows[j].Stratum
		}
		return rows[i].Coord.Key() < rows[j].Coord.Key()
	})
	man := Manifest{
		Seed:           o.seed,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		OSSFCommit:     ossfCommit,
		OSSFSkipped:    ossfSkipped,
		PoolMultiplier: o.poolMult,
		Ecosystems:     ecosystems,
		Duration:       time.Since(start).Round(time.Second).String(),
	}
	if o.dryRun {
		fmt.Fprintf(os.Stderr, "\ndry run: %d rows, not written\n", len(rows))
		return nil
	}
	return emit(o.out, rows, excl, c.evidence(), man)
}

func quotaFor(stratum string) Quota {
	for _, q := range quotas {
		if q.Stratum == stratum {
			return q
		}
	}
	panic("unknown stratum " + stratum)
}

// resolveAll resolves names to exact coordinates with bounded concurrency.
// Failures are counted, not fatal: at this scale a handful of names will be
// deleted, renamed or unindexed between enumeration and resolution.
func (c *client) resolveAll(eco string, names []string, seed string, workers int) []*VersionInfo {
	if workers < 1 {
		workers = 1
	}
	type res struct {
		i  int
		in *VersionInfo
	}
	in := make(chan int)
	out := make(chan res, len(names))
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range in {
				// Per-PACKAGE stream: which version a package
				// contributes must not depend on where it landed in the
				// pool, or resizing the pool reshuffles every row.
				info, err := c.resolveVersion(eco, names[i], subRNG(seed, "version", eco, names[i]))
				if err == nil && info != nil {
					out <- res{i, info}
				}
			}
		}()
	}
	for i := range names {
		in <- i
	}
	close(in)
	wg.Wait()
	close(out)
	got := make([]res, 0, len(names))
	for r := range out {
		got = append(got, r)
	}
	// Restore enumeration order; channel completion order is nondeterministic.
	sort.Slice(got, func(i, j int) bool { return got[i].i < got[j].i })
	infos := make([]*VersionInfo, 0, len(got))
	for _, r := range got {
		infos = append(infos, r.in)
	}
	return infos
}
