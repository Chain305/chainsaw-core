package main

// The five strata derived from the shared registry pool.
//
// Each one asks a different question of the SAME verified coordinates, and
// each consumes from `used` so no coordinate can appear twice in the corpus
// under two labels. Order matters and is fixed in runBuild: the specific
// strata (paired vulnerabilities, behavioural benign, licence families) claim
// their rows before the general presumed-benign stratum sweeps up the rest.

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─── V1 / V2 — THE PAIRED DESIGN ────────────────────────────────────────────
//
// A vulnerable coordinate on its own proves very little. A vendor that flags
// `foo@1.7.2` may be detecting CVE-2026-XXXX, or may simply be detecting
// `foo`. Pairing it with `foo@1.8.0` — the version the SAME advisory names as
// fixed — controls for the package, the maintainer, the licence, the install
// scripts and the dependency tree, leaving the vulnerability as the only
// difference. A vendor that flags both halves is scored as not having
// detected the CVE at all.
//
// The fixed version is taken from the advisory's `ranges[].events[].fixed`,
// which is why V2 needs the vuln DETAIL fetch: querybatch returns ids only.
func (c *client) fillVulnPairs(o buildOpts, used map[string]bool, excl *[]Exclusion) []Row {
	q := quotaFor("V1")
	pools := map[string][]VulnPair{}
	avail := map[string]int{}
	for _, e := range ecosystems {
		ps, err := c.osvBulkPairs(e, o.osvCache)
		if err != nil {
			fmt.Fprintf(os.Stderr, "      %-10s OSV bulk FAILED: %v\n", e, err)
			*excl = append(*excl, Exclusion{Stratum: "V1", Reason: "osv_bulk_unavailable:" + e})
			continue
		}
		pools[e] = ps
		avail[e] = len(ps)
	}
	alloc, _ := allocate(q.Target, ecosystems, avail)

	var rows []Row
	pairs := 0
	// perm is computed once per ecosystem and the cursor persists across
	// both passes, so the top-up resumes where the first pass stopped
	// instead of re-verifying candidates it already rejected.
	perms := map[string][]int{}
	cursor := map[string]int{}
	for _, e := range ecosystems {
		if len(pools[e]) > 0 {
			perms[e] = subRNG(o.seed, "V1", e).Perm(len(pools[e]))
		}
	}

	// tryPair attempts one candidate. BOTH halves must be published:
	// verifying only the vulnerable half is how a pair silently degrades
	// into a single observation while still being counted as a pair.
	tryPair := func(e string, p VulnPair) bool {
		vulnCo := Coord{Eco: e, Name: p.Name, Version: p.VulnVersion}
		fixedCo := Coord{Eco: e, Name: p.Name, Version: p.FixedVersion}
		if used[vulnCo.Key()] || used[fixedCo.Key()] {
			return false
		}
		vInfo, err := c.verifyCoord(e, p.Name, p.VulnVersion)
		if err != nil {
			*excl = append(*excl, Exclusion{Coord: vulnCo, Stratum: "V1", Reason: "vulnerable_version_not_published"})
			return false
		}
		fInfo, err := c.verifyCoord(e, p.Name, p.FixedVersion)
		if err != nil {
			*excl = append(*excl, Exclusion{Coord: fixedCo, Stratum: "V2", Reason: "fixed_version_not_published"})
			return false
		}
		pairs++
		pid := fmt.Sprintf("VULN-%04d", pairs)
		used[vulnCo.Key()] = true
		used[fixedCo.Key()] = true
		rows = append(rows,
			Row{Coord: vulnCo, Stratum: "V1", Truth: "vulnerable", Label: "vulnerable",
				Confidence: "A", PairID: pid, Published: fmtTime(vInfo.PublishedAt),
				Licenses:   vInfo.Licenses,
				Provenance: "osv:" + p.AdvisoryID + " lists this exact version as affected",
				Notes:      "paired control is " + p.FixedVersion},
			Row{Coord: fixedCo, Stratum: "V2", Truth: "patched", Label: "benign",
				Confidence: "A", PairID: pid, Published: fmtTime(fInfo.PublishedAt),
				Licenses:   fInfo.Licenses,
				Provenance: "osv:" + p.AdvisoryID + " names this version fixed",
				Notes:      "control for " + p.VulnVersion + "; same package, same maintainer, same tree"},
		)
		return true
	}

	// PASS 1 — the balanced allocation.
	for _, e := range ecosystems {
		need := alloc[e]
		for need > 0 && cursor[e] < len(perms[e]) {
			p := pools[e][perms[e][cursor[e]]]
			cursor[e]++
			if tryPair(e, p) {
				need--
			}
		}
	}

	// PASS 2 — top up from whoever still has candidates.
	//
	// allocate() caps each ecosystem at its CANDIDATE count, but a
	// candidate only becomes a row if BOTH of its versions verify against
	// the registry, and many do not: OSV records advisories for coordinates
	// that were later unpublished, and it names fixed versions that were
	// never cut for that branch. Without this pass the deficit from a
	// verification-poor ecosystem is simply lost, and the stratum comes in
	// short while eight pools still hold thousands of usable candidates.
	// Measured before this pass existed: 154 of 175 pairs.
	for pairs < q.Target {
		progressed := false
		for _, e := range ecosystems {
			if pairs >= q.Target {
				break
			}
			for cursor[e] < len(perms[e]) {
				p := pools[e][perms[e][cursor[e]]]
				cursor[e]++
				if tryPair(e, p) {
					progressed = true
					break
				}
			}
		}
		if !progressed {
			break // every pool exhausted; the shortfall is real
		}
	}

	if pairs < q.Target {
		*excl = append(*excl, Exclusion{Stratum: "V1", Reason: fmt.Sprintf("shortfall:%d pairs", q.Target-pairs)})
	}
	report("V1/V2", pairs*2, q.Target*2)
	return rows
}

// ─── B2 — HARD BENIGN ───────────────────────────────────────────────────────
//
// See the long note in metadata.go for why this stratum decides whether a
// false-positive rate means anything. Only npm and PyPI expose an objective
// behaviour fact in registry metadata, so only those two are sampled and the
// rest is reported as a shortfall rather than padded with ordinary packages.
func (c *client) fillBehavioral(o buildOpts, pool map[string][]resolved, used map[string]bool, excl *[]Exclusion) []Row {
	q := quotaFor("B2")
	probeable := []string{"npm", "pypi"}
	per := q.Target / len(probeable)
	var rows []Row
	got := 0
	for _, e := range probeable {
		var cands []resolved
		for _, p := range pool[e] {
			if len(p.OSV.VulnIDs) == 0 && !used[p.Info.Coord().Key()] {
				cands = append(cands, p)
			}
		}
		// Draw the probe ORDER first, then probe CONCURRENTLY, then select
		// in that same order. Selecting in completion order would make the
		// stratum depend on which packument happened to return first,
		// which is exactly the kind of nondeterminism the rest of this
		// tool goes to some trouble to avoid.
		order := subRNG(o.seed, "B2", e).Perm(len(cands))

		// Probing is bounded and PARALLEL. Measured serially, this stratum
		// walked ~2,300 npm and PyPI packuments one at a time -- some are
		// multi-megabyte documents -- and became the longest stage in the
		// build by a wide margin. Behaviour density runs around 10%, so the
		// budget has to be several times the quota or the stratum comes in
		// short for want of looking.
		// Probe EVERY available candidate, not a multiple of the quota.
		// Measured: behaviour density is 9.75% (117 hits from 1,200 probes),
		// so a 6x budget yields ~0.6 rows per row needed and the stratum
		// lands at 117 of 200. The pool is already bounded by
		// --pool-multiplier; bounding it a second time here only guarantees
		// a shortfall in the one stratum that cannot be padded.
		budget := len(order)
		type probed struct {
			pos int
			b   Behaviors
		}
		results := make(chan probed, budget)
		sem := make(chan struct{}, o.concurrency)
		var wg sync.WaitGroup
		for i := 0; i < budget; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				co := cands[order[i]].Info.Coord()
				var b Behaviors
				var ok bool
				if e == "npm" {
					b, ok = c.probeBehaviorsNPM(co.Name, co.Version)
				} else {
					b, ok = c.probeBehaviorsPyPI(co.Name, co.Version)
				}
				if ok && len(b) > 0 {
					results <- probed{pos: i, b: b}
				}
			}(i)
		}
		wg.Wait()
		close(results)
		hits := make([]probed, 0, budget)
		for r := range results {
			hits = append(hits, r)
		}
		sort.Slice(hits, func(i, j int) bool { return hits[i].pos < hits[j].pos })

		need := per
		for _, h := range hits {
			if need == 0 {
				break
			}
			p := cands[order[h.pos]]
			co := p.Info.Coord()
			if used[co.Key()] {
				continue
			}
			used[co.Key()] = true
			need--
			got++
			keys := make([]string, 0, len(h.b))
			for k, v := range h.b {
				if v {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			rows = append(rows, Row{
				Coord: co, Stratum: "B2", Truth: q.Truth, Label: q.Label,
				Confidence: "A", Published: fmtTime(p.Info.PublishedAt),
				Licenses: p.Info.Licenses, Behaviors: h.b,
				Provenance: "registry metadata states: " + strings.Join(keys, ","),
				Notes:      "behaviour is REAL; an alert naming it is correct, a VERDICT on it is a false positive",
			})
		}
	}
	if got < q.Target {
		*excl = append(*excl, Exclusion{Stratum: "B2",
			Reason: fmt.Sprintf("shortfall:%d (only npm and pypi expose an objective behaviour fact in registry metadata)", q.Target-got)})
	}
	report("B2", got, q.Target)
	return rows
}

// ─── R1 — MAINTENANCE ───────────────────────────────────────────────────────
//
// Two objective, deps.dev-stated facts: the registry's own deprecation flag,
// and a publication date older than staleYears. Neither is evidence of risk,
// which is why the truth stays presumed_benign while the corpus label is
// `suspicious` — the row exists to test whether a vendor reports maintenance
// state, not to assert that an old package is dangerous.
const staleYears = 4

func fillMaintenance(o buildOpts, pool map[string][]resolved, used map[string]bool, excl *[]Exclusion) []Row {
	q := quotaFor("R1")
	cutoff := time.Now().AddDate(-staleYears, 0, 0)
	cands := map[string][]resolved{}
	for _, e := range ecosystems {
		for _, p := range pool[e] {
			if used[p.Info.Coord().Key()] || len(p.OSV.VulnIDs) > 0 {
				continue
			}
			stale := !p.Info.PublishedAt.IsZero() && p.Info.PublishedAt.Before(cutoff)
			if p.Info.Deprecated || stale {
				cands[e] = append(cands[e], p)
			}
		}
	}
	avail := map[string]int{}
	for e, v := range cands {
		avail[e] = len(v)
	}
	alloc, _ := allocate(q.Target, ecosystems, avail)
	var rows []Row
	got := 0
	for _, e := range ecosystems {
		need := alloc[e]
		rng := subRNG(o.seed, "R1", e)
		for _, i := range rng.Perm(len(cands[e])) {
			if need == 0 {
				break
			}
			p := cands[e][i]
			co := p.Info.Coord()
			if used[co.Key()] {
				continue
			}
			used[co.Key()] = true
			need--
			got++
			why := fmt.Sprintf("last published %s", fmtTime(p.Info.PublishedAt))
			if p.Info.Deprecated {
				why = "registry deprecation flag set"
				if p.Info.DeprecatedReason != "" {
					why += ": " + oneLine(p.Info.DeprecatedReason)
				}
			}
			rows = append(rows, Row{
				Coord: co, Stratum: "R1", Truth: q.Truth, Label: q.Label,
				Confidence: "A", Published: fmtTime(p.Info.PublishedAt),
				Licenses: p.Info.Licenses, Provenance: "deps.dev: " + why,
				Notes: "maintenance state, NOT a risk assertion",
			})
		}
	}
	if got < q.Target {
		*excl = append(*excl, Exclusion{Stratum: "R1", Reason: fmt.Sprintf("shortfall:%d", q.Target-got)})
	}
	report("R1", got, q.Target)
	return rows
}

// ─── L1 — LICENCE FAMILIES ──────────────────────────────────────────────────
//
// Stratified by SPDX family rather than sampled at random, because the axis
// under test is whether a vendor distinguishes weak from strong from network
// copyleft. A random licence sample is ~90% MIT/Apache and measures nothing.
var licenseQuota = []struct {
	Family string
	N      int
}{
	{"permissive", 30},
	{"strong_copyleft", 20},
	{"weak_copyleft", 15},
	{"network_copyleft", 10},
	{"multiple", 15},
	{"unknown", 10},
}

func licenseFamily(ls []string) string {
	if len(ls) == 0 {
		return "unknown"
	}
	if len(ls) > 1 {
		return "multiple"
	}
	l := strings.ToUpper(ls[0])
	switch {
	case strings.HasPrefix(l, "AGPL"):
		return "network_copyleft"
	case strings.HasPrefix(l, "LGPL"), strings.HasPrefix(l, "MPL"),
		strings.HasPrefix(l, "EPL"), strings.HasPrefix(l, "CDDL"):
		return "weak_copyleft"
	case strings.HasPrefix(l, "GPL"):
		return "strong_copyleft"
	case strings.HasPrefix(l, "MIT"), strings.HasPrefix(l, "APACHE"),
		strings.HasPrefix(l, "BSD"), strings.HasPrefix(l, "ISC"),
		strings.HasPrefix(l, "ZLIB"), strings.HasPrefix(l, "UNLICENSE"):
		return "permissive"
	case l == "NON-STANDARD", l == "NOASSERTION", l == "":
		return "unknown"
	}
	return "unknown"
}

func fillLicense(o buildOpts, pool map[string][]resolved, used map[string]bool, excl *[]Exclusion) []Row {
	byFamily := map[string][]resolved{}
	for _, e := range ecosystems {
		for _, p := range pool[e] {
			if used[p.Info.Coord().Key()] || len(p.OSV.VulnIDs) > 0 {
				continue
			}
			byFamily[licenseFamily(p.Info.Licenses)] = append(byFamily[licenseFamily(p.Info.Licenses)], p)
		}
	}
	var rows []Row
	got, target := 0, 0
	for _, lq := range licenseQuota {
		target += lq.N
		need := lq.N
		rng := subRNG(o.seed, "L1", lq.Family)
		cands := byFamily[lq.Family]
		sort.Slice(cands, func(i, j int) bool {
			return cands[i].Info.Coord().Key() < cands[j].Info.Coord().Key()
		})
		for _, i := range rng.Perm(len(cands)) {
			if need == 0 {
				break
			}
			p := cands[i]
			co := p.Info.Coord()
			if used[co.Key()] {
				continue
			}
			used[co.Key()] = true
			need--
			got++
			rows = append(rows, Row{
				Coord: co, Stratum: "L1", Truth: "presumed_benign", Label: "benign",
				Confidence: "A", Published: fmtTime(p.Info.PublishedAt),
				Licenses:   p.Info.Licenses,
				Provenance: "deps.dev licences: " + strings.Join(p.Info.Licenses, ","),
				Notes:      "licence family: " + lq.Family,
			})
		}
		if need > 0 {
			*excl = append(*excl, Exclusion{Stratum: "L1",
				Reason: fmt.Sprintf("shortfall:%d family=%s", need, lq.Family)})
		}
	}
	report("L1", got, target)
	return rows
}

// ─── B1 — PRESUMED BENIGN ───────────────────────────────────────────────────
//
// The name is the finding. A package absent from OSV and from the OpenSSF feed
// is not KNOWN to be benign; it is merely unreported. OpenSSF says its own
// malicious dataset may contain false positives, and no feed claims
// completeness, so neither a positive nor a negative from upstream is
// infallible. Calling this stratum `benign` would assert a fact no source
// supports and would put that assertion straight into the denominator of
// every false-positive rate the benchmark publishes.
func fillPresumedBenign(o buildOpts, pool map[string][]resolved, used map[string]bool, excl *[]Exclusion) []Row {
	q := quotaFor("B1")
	cands := map[string][]resolved{}
	for _, e := range ecosystems {
		for _, p := range pool[e] {
			if used[p.Info.Coord().Key()] || len(p.OSV.VulnIDs) > 0 {
				continue
			}
			cands[e] = append(cands[e], p)
		}
	}
	avail := map[string]int{}
	for e, v := range cands {
		avail[e] = len(v)
	}
	alloc, _ := allocate(q.Target, ecosystems, avail)
	var rows []Row
	got := 0
	for _, e := range ecosystems {
		need := alloc[e]
		rng := subRNG(o.seed, "B1", e)
		for _, i := range rng.Perm(len(cands[e])) {
			if need == 0 {
				break
			}
			p := cands[e][i]
			co := p.Info.Coord()
			if used[co.Key()] {
				continue
			}
			used[co.Key()] = true
			need--
			got++
			rows = append(rows, Row{
				Coord: co, Stratum: "B1", Truth: q.Truth, Label: q.Label,
				Confidence: "B", Published: fmtTime(p.Info.PublishedAt),
				Licenses:   p.Info.Licenses,
				Provenance: "OSV: no advisory for this coordinate; OpenSSF: not reported",
				Notes:      "unreported, NOT proven benign",
			})
		}
	}
	if got < q.Target {
		*excl = append(*excl, Exclusion{Stratum: "B1", Reason: fmt.Sprintf("shortfall:%d", q.Target-got)})
	}
	report("B1", got, q.Target)
	return rows
}

func report(stratum string, got, target int) {
	msg := fmt.Sprintf("      %-6s %d/%d", stratum, got, target)
	if got < target {
		msg += fmt.Sprintf("   SHORTFALL %d", target-got)
	}
	fmt.Fprintln(os.Stderr, msg)
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return strings.TrimSpace(s)
}
