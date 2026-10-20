package cli

// Research lane runner: drives the REAL offline guard (the exact code a
// `chainsaw npm install` runs — known-malicious lane, typosquat ladder with
// the block gate, embedded seed corpora) over the pseudonymised research
// dataset, so published numbers are receipts from product code, not a
// re-implementation.
//
// Skipped unless RESEARCH_DIR points at the "Chain305 Research" directory:
//
//	RESEARCH_DIR=/Users/zeeshan/Desktop/Chain305 Research \
//	  go test ./core/cli/ -run TestResearchGuardOverDataset -count=1 -v -timeout 30m
//
// What it runs, deliberately split by determinism:
//   - malware lane: g.malware.Lookup over EVERY SBOM coordinate (the exact
//     first call localGuard.evaluate makes), index = embedded floor + every
//     MAL- advisory OSV reports against any queried coordinate (SBOM or
//     findings history), fetched from api.osv.dev and cached in
//     analysis/osv_mal_full.jsonl.
//   - name lanes: g.evaluate over every DISTINCT public name with no version
//     (typosquat ladder + policy; the byte-scan acquisition inside evaluate
//     finds no staged artifacts for this dataset and is not claimed).
//
// Output: analysis/guard_malware.csv, analysis/guard_names.csv, and a summary
// with the feed size n (a zero hit is only meaningful with the feed size and
// the coordinate count stated alongside).

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/typosquat"
)

// dataset ecosystem -> the ecosystem string the guard uses internally
// (malware.NormalizeEcosystem and the detector switch both see these).
var researchEcoAlias = map[string]string{
	"npm": "npm", "pypi": "pypi", "cargo": "cargo", "maven": "maven",
	"composer": "composer", "gem": "rubygems", "golang": "go", "pub": "pub",
	"cocoapods": "cocoapods", "swift": "swift", "nuget": "nuget",
}

type researchCoord struct {
	Eco, Name, Version string
}

func TestResearchGuardOverDataset(t *testing.T) {
	root := os.Getenv("RESEARCH_DIR")
	if root == "" {
		t.Skip("RESEARCH_DIR not set — research dataset not in scope")
	}
	ctx := context.Background()
	outDir := filepath.Join(root, "analysis")

	coords, names, skipped := readResearchPackages(t, filepath.Join(root, "publish", "sbom", "packages.csv"))
	t.Logf("coordinates: %d, distinct public names: %d, rows skipped (internal names): %d",
		len(coords), len(names), skipped)

	// Malware feed: floor + every MAL- id the OSV backfill saw (SBOM coords
	// and findings-history coords), full docs cached on disk.
	feed := researchMalFeed(t, filepath.Join(outDir, "osv_hits.csv"), filepath.Join(outDir, "osv_mal_full.jsonl"))
	entries := append(malware.Floor(), feed...)
	g := newLocalGuard()
	g.malware.Load(entries)
	t.Logf("malware index: %d entries (%d floor + %d MAL docs fetched)", len(entries), len(malware.Floor()), len(feed))

	malFile := researchOut(t, filepath.Join(outDir, "guard_malware.csv"), "ecosystem", "name", "version", "blocked", "advisory")
	blocked := 0
	for _, c := range coords {
		res := g.malware.Lookup(ctx, c.Eco, c.Name, c.Version)
		if !res.IsKnownMalicious {
			continue
		}
		blocked++
		researchRow(malFile, c.Eco, c.Name, c.Version, "true", res.MalwareID)
	}
	t.Logf("malware lane: %d of %d coordinates known-malicious", blocked, len(coords))

	nameFile := researchOut(t, filepath.Join(outDir, "guard_names.csv"), "ecosystem", "name", "verdict", "severity", "reason")
	verdicts := map[string]int{}
	for _, n := range names {
		v := g.evaluate(ctx, packageSpec{Ecosystem: n.eco, Name: n.name})
		// The coordinate pass above already decided the malware lane per
		// exact version; an empty-version range match here would be a
		// different question (unpinned install) than the census asks.
		if v.Severity == "malicious" {
			continue
		}
		kind := "allow"
		switch {
		case v.Block:
			kind = "block"
		case v.Severity != "":
			kind = "warn"
		}
		verdicts[kind]++
		if kind != "allow" {
			researchRow(nameFile, n.eco, n.name, kind, v.Severity, v.Reason)
		}
	}
	kinds := make([]string, 0, len(verdicts))
	for k := range verdicts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		t.Logf("name lanes: %s %d", k, verdicts[k])
	}
}

func readResearchPackages(t *testing.T, path string) (coords []researchCoord, names []ecoName, skipped int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	seenName := map[string]bool{}
	seen := map[string]bool{}
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	col := func(name string) int {
		for i, h := range header {
			if h == name {
				return i
			}
		}
		t.Fatalf("packages.csv lacks column %q", name)
		return -1
	}
	ie, in, iv := col("ecosystem"), col("name"), col("version")
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(row[in], "internal-") {
			skipped++
			continue
		}
		eco, ok := researchEcoAlias[row[ie]]
		if !ok {
			continue
		}
		c := researchCoord{Eco: eco, Name: row[in], Version: row[iv]}
		k := c.Eco + "\x00" + c.Name + "\x00" + c.Version
		if !seen[k] {
			seen[k] = true
			coords = append(coords, c)
		}
		nk := c.Eco + "\x00" + c.Name
		if !seenName[nk] {
			seenName[nk] = true
			names = append(names, ecoName{eco: c.Eco, name: c.Name})
		}
	}
	return coords, names, skipped
}

type ecoName struct{ eco, name string }

// researchMalFeed returns the full OSV docs for every MAL- id in the hits
// file, fetching from api.osv.dev with a permanent disk cache so reruns and
// published reproductions only re-fetch what changed.
func researchMalFeed(t *testing.T, hitsPath, cachePath string) []*malware.OSVEntry {
	t.Helper()
	ids := map[string]bool{}
	if f, err := os.Open(hitsPath); err == nil {
		r := csv.NewReader(f)
		r.FieldsPerRecord = -1
		for {
			row, err := r.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, cell := range row {
				if strings.HasPrefix(cell, "MAL-") {
					ids[cell] = true
				}
			}
		}
		f.Close()
	} else {
		t.Logf("no hits file at %s — malware feed is the embedded floor only", hitsPath)
	}

	cached := map[string][]byte{}
	if f, err := os.Open(cachePath); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
		for sc.Scan() {
			var row struct {
				ID  string `json:"id"`
				Raw json.RawMessage
			}
			if json.Unmarshal(sc.Bytes(), &row) == nil && row.ID != "" {
				cached[row.ID] = sc.Bytes()
			}
		}
		f.Close()
	}

	client := &http.Client{Timeout: 30 * time.Second}
	var out []*malware.OSVEntry
	var lines []string
	for id := range ids {
		raw, ok := cached[id]
		if !ok {
			resp, err := client.Get("https://api.osv.dev/v1/vulns/" + id)
			if err != nil {
				t.Fatalf("fetch %s: %v", id, err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatalf("read %s: %v", id, err)
			}
			if resp.StatusCode == 404 {
				t.Logf("%s returned 404 (withdrawn?) — skipped", id)
				continue
			}
			if resp.StatusCode != 200 {
				t.Fatalf("fetch %s: status %d", id, resp.StatusCode)
			}
			raw = body
		}
		e, err := malware.ParseOSVEntry(raw)
		if err != nil {
			t.Fatalf("parse %s: %v", id, err)
		}
		out = append(out, e)
		lines = append(lines, string(raw))
	}
	if len(lines) > 0 {
		cache, err := os.Create(cachePath)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range lines {
			fmt.Fprintln(cache, l)
		}
		cache.Close()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func researchOut(t *testing.T, path string, header ...string) *csv.Writer {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := csv.NewWriter(f)
	if err := w.Write(header); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Flush(); f.Close() })
	return w
}

func researchRow(w *csv.Writer, cells ...string) {
	if err := w.Write(cells); err != nil {
		panic(err)
	}
	w.Flush()
}

// TestResearchGateShapes replays the corpus typosquat blocks through the
// real d1 block gate and prints, per name, the target, its rank and length,
// and whether the gate still allows the block (i.e. it is a gate miss, not
// an evidence-tier miss).
func TestResearchGateShapes(t *testing.T) {
	root := os.Getenv("RESEARCH_DIR")
	if root == "" {
		t.Skip("RESEARCH_DIR not set")
	}
	f, err := os.Open(filepath.Join(root, "analysis", "guard_names.csv"))
	if err != nil {
		t.Skip("no guard_names.csv")
	}
	defer f.Close()
	re := regexp.MustCompile(`typosquat of "([^"]+)" \(distance (\d+), ([^,]+), target rank #(\d+)\)`)
	cr := csv.NewReader(f)
	n := 0
	for {
		r, err := cr.Read()
		if err != nil {
			break
		}
		if len(r) < 5 || r[2] != "block" || r[3] != "typosquat-high" {
			continue
		}
		m := re.FindStringSubmatch(r[4])
		if m == nil {
			t.Logf("%s/%s: unparsed reason %q", r[0], r[1], r[4])
			continue
		}
		rank, _ := strconv.Atoi(m[4])
		res := typosquat.DetectionResult{IsSuspected: true, Method: m[3],
			Distance: 1, SimilarTo: m[1], TargetRank: rank, Confidence: "high"}
		t.Logf("%-24s eco=%-8s target=%-24s rank=%-5d tlen=%d allowsD1Block=%v",
			r[1], r[0], m[1], rank, len(m[1]),
			guardTyposquatBlockGate.allowsD1Block(r[0], r[1], res))
		n++
	}
	t.Logf("replayed %d blocks", n)
}
