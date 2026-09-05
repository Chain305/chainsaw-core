package cli

// The corrupt-corpus regression suite (vendor row P9F-257).
//
// WHAT THE VENDOR ACTUALLY DID, AND WHY IT PROVED NOTHING. P9F-257 corrupted
// `known_malicious.json` in the guard cache, then installed a CLEAN package
// (`lodash`), saw "offline known-malicious + typosquat active", watched the
// install succeed, and recorded a pass. A clean package succeeding is the
// outcome for a guard that has been switched off entirely; it carries no
// information about whether protection survived. The question the row was
// supposed to answer is the opposite one: with the cache file corrupt, is a
// KNOWN-MALICIOUS package still refused?
//
// It must be. The floor (core/malware.Floor(), embedded via //go:embed into
// the binary) is combined with the cache file and the signal bundle in ONE
// index Load — see loadMalwareSources. A file on disk cannot delete bytes that
// are compiled in, so no corruption shape may cost the floor. These tests
// prove that rather than assuming it, across the five shapes a real cache
// actually breaks in.
//
// NOTE ON THE PLAN'S WORDING. docs/plan_qa_phase9_fresh_remediation.md §5 says
// to "re-run with `lodahs` to prove the embedded floor still blocks". `lodahs`
// is NOT a floor coordinate — the floor holds eleven famous attacks and lodahs
// is none of them (it is refused by the TYPOSQUAT lane, off the embedded
// popular corpus, which the malware cache cannot influence either). A lodahs
// re-run would therefore have re-proved the wrong subsystem. The floor
// coordinates are asserted directly below: npm event-stream@3.3.6,
// npm flatmap-stream, pip colourama.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/coverage"
	"github.com/chain305/chainsaw-core/malware"
)

// corruptCacheShape is one way a `guard update` cache file breaks.
type corruptCacheShape struct {
	name string
	// data is the file content; when nil the file is not written at all.
	data []byte
	// unreadable chmods the file to 0o000 after writing it. A dedicated
	// bool, not an os.FileMode field: 0o000 IS the zero value, so a
	// `mode != 0` guard would silently skip the chmod and the shape would
	// quietly test the readable case instead. (It did, on the first run.)
	unreadable bool
	// wantStderr is a substring the guard MUST print for this shape. Every
	// shape that costs coverage has to be visible to the operator: a cache
	// that contributes nothing must never read like a cache that was never
	// downloaded.
	wantStderr string
	// rootUnsafe marks a shape a root test runner cannot exercise (chmod is
	// advisory for uid 0).
	rootUnsafe bool
}

// goodMalwareEntries builds n syntactically valid OSV entries, none of which
// overlap the floor.
func goodMalwareEntries(n int) []malware.OSVEntry {
	out := make([]malware.OSVEntry, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, malware.OSVEntry{
			ID: fmt.Sprintf("MAL-CORRUPT-%05d", i),
			Affected: []malware.OSVAffected{{
				Package:  malware.OSVPackage{Name: fmt.Sprintf("synthetic-corrupt-%05d", i), Ecosystem: "npm"},
				Versions: []string{"1.0.0"},
			}},
		})
	}
	return out
}

// goodMalwareArray marshals n valid entries the way `guard update` writes them
// (guard_update.go: a single json.Marshal of the whole slice — one line, one
// JSON array).
func goodMalwareArray(t *testing.T, n int) []byte {
	t.Helper()
	data, err := json.Marshal(goodMalwareEntries(n))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// corruptCacheShapes enumerates the five shapes P9F-257 should have covered.
func corruptCacheShapes(t *testing.T) []corruptCacheShape {
	t.Helper()
	full := goodMalwareArray(t, guardMalwareFeedFloor)

	// (e) One malformed record among good ones, in the ARRAY format the real
	// `guard update` writes: `"modified"` is a number where a timestamp
	// belongs. encoding/json is all-or-nothing over an array, so this costs
	// the WHOLE file, not the one record — see the dedicated test below.
	oneBad := []byte(`[` +
		`{"id":"MAL-A","affected":[{"package":{"name":"corrupt-a","ecosystem":"npm"},"versions":["1.0.0"]}]},` +
		`{"id":"MAL-BAD","modified":12345},` +
		`{"id":"MAL-C","affected":[{"package":{"name":"corrupt-c","ecosystem":"npm"},"versions":["1.0.0"]}]}` +
		`]`)

	return []corruptCacheShape{
		{
			// (a) A download or write that stopped half way.
			name:       "truncated mid-JSON",
			data:       full[:len(full)*6/10],
			wantStderr: "holds no readable known-malicious entries",
		},
		{
			// (b) Valid JSON, wrong shape — the operator pointed
			// CHAINSAW_GUARD_DB at some other JSON file. It parses as ONE
			// contentless entry, so it lands in the existing sub-floor
			// PARTIAL warning rather than the unusable one. Either way the
			// operator is told, and `extra` stays 0.
			name:       "valid JSON of the wrong shape",
			data:       []byte(`{"advisories":{"count":2},"name":"not-an-osv-array"}`),
			wantStderr: "PARTIAL coverage",
		},
		{
			// (c) Zero bytes — an interrupted write, or a `> file` truncate.
			name:       "empty file",
			data:       []byte{},
			wantStderr: "is empty",
		},
		{
			// (d) Present but unreadable: root-owned cache, a hardened
			// umask, a restored CI cache with the wrong ownership.
			name:       "present but unreadable",
			data:       full,
			unreadable: true,
			wantStderr: "could not be read",
			rootUnsafe: true,
		},
		{
			// (e) The subtle one.
			name:       "one malformed entry among good ones",
			data:       oneBad,
			wantStderr: "holds no readable known-malicious entries",
		},
	}
}

// writeCorruptCache writes the shape to a temp file and points
// CHAINSAW_GUARD_DB at it. Returns the path.
func writeCorruptCache(t *testing.T, s corruptCacheShape) string {
	t.Helper()
	if s.rootUnsafe && os.Geteuid() == 0 {
		t.Skip("running as root: chmod cannot make a file unreadable")
	}
	path := filepath.Join(t.TempDir(), "known_malicious.json")
	if err := os.WriteFile(path, s.data, 0o644); err != nil {
		t.Fatal(err)
	}
	if s.unreadable {
		if err := os.Chmod(path, 0o000); err != nil {
			t.Fatal(err)
		}
		// Restore write permission so t.TempDir cleanup succeeds.
		t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
	}
	t.Setenv(guardDBEnv, path)
	return path
}

// floorCoordinates are the known-malicious blocks that must survive every
// corruption shape, and the clean sibling that must NOT start blocking.
var floorCoordinates = []struct {
	spec      packageSpec
	wantBlock bool
}{
	{packageSpec{Ecosystem: "npm", Name: "event-stream", Version: "3.3.6"}, true},
	{packageSpec{Ecosystem: "npm", Name: "flatmap-stream"}, true},
	{packageSpec{Ecosystem: "pip", Name: "colourama"}, true},
	// The floor is version-exact where a clean release exists. A corrupt
	// cache must not push the guard into blocking a clean version either —
	// fail-safe is not the same as fail-loud-at-everything.
	{packageSpec{Ecosystem: "npm", Name: "event-stream", Version: "4.0.0"}, false},
}

// TestGuardCorruptMalwareCacheKeepsEmbeddedFloor is the regression P9F-257
// never performed: for every way the `guard update` cache breaks, a
// known-malicious floor coordinate is still REFUSED.
func TestGuardCorruptMalwareCacheKeepsEmbeddedFloor(t *testing.T) {
	ctx := context.Background()
	for _, shape := range corruptCacheShapes(t) {
		t.Run(shape.name, func(t *testing.T) {
			writeCorruptCache(t, shape)

			var g *localGuard
			stderr := captureStderr(t, func() { g = newLocalGuard() })

			// 1. The floor survives, and is what actually refuses the install.
			for _, c := range floorCoordinates {
				v := g.evaluate(ctx, c.spec)
				got := v.Block && v.Severity == "malicious"
				if got != c.wantBlock {
					t.Errorf("%s: known-malicious block = %v, want %v (verdict %+v)",
						c.spec, got, c.wantBlock, v)
				}
			}

			// 2. The index knows it carries the floor. FloorLoaded is the
			// marker a loader that forgot the floor trips.
			idx := malware.NewIndex(guardLogger)
			var floor, extra int
			captureStderr(t, func() { floor, extra = loadMalwareSources(idx, nil) })
			if !idx.FloorLoaded() {
				t.Error("FloorLoaded() = false: a corrupt cache file cost the embedded floor")
			}
			if floor != len(malware.Floor()) {
				t.Errorf("floor = %d, want %d", floor, len(malware.Floor()))
			}

			// 3. And it does NOT report coverage it does not have. `extra`
			// is the evidence for the "full feed present" claim; a corrupt
			// file must contribute none of it, so the coverage ledger keeps
			// reporting `malware` UNAVAILABLE and a fail-closed operator
			// still gets a refusal.
			if extra != 0 {
				t.Errorf("extra = %d, want 0: a corrupt cache must not underwrite the full-feed claim", extra)
			}
			if g.fullFeed {
				t.Error("fullFeed = true on a corrupt cache")
			}
			led := guardLedger(g, time.Now())
			if got := led[coverage.SourceMalware].Status; got != coverage.StatusUnavailable {
				t.Errorf("ledger malware = %q, want %q", got, coverage.StatusUnavailable)
			}
			for _, n := range g.notices {
				if strings.Contains(n, "malicious packages indexed") {
					t.Errorf("notice claims an indexed full feed on a corrupt cache: %q", n)
				}
			}

			// 4. The operator is TOLD. Without this, every shape below is
			// byte-identical to a machine that never ran `guard update`.
			if !strings.Contains(stderr, "WARNING") || !strings.Contains(stderr, guardDBEnv) {
				t.Errorf("want a loud warning naming %s, got stderr:\n%s", guardDBEnv, stderr)
			}
			if !strings.Contains(stderr, shape.wantStderr) {
				t.Errorf("stderr does not say why the cache is unusable; want %q, got:\n%s",
					shape.wantStderr, stderr)
			}
		})
	}
}

// TestGuardCorruptMalwareCacheStillRefusesUnderFailClosed proves the other
// half of "does not silently report coverage it does not have": an operator
// who declared `malware` mandatory gets a REFUSAL, not a pass, when the cache
// is corrupt. The floor alone is partial coverage and must never satisfy that
// gate.
func TestGuardCorruptMalwareCacheStillRefusesUnderFailClosed(t *testing.T) {
	writeCorruptCache(t, corruptCacheShape{
		name: "truncated", data: goodMalwareArray(t, guardMalwareFeedFloor)[:200],
	})
	t.Setenv(coverageModeEnv, string(coverage.ModeClosed))
	t.Setenv(coverageRequiredEnv, string(coverage.SourceMalware))

	var g *localGuard
	captureStderr(t, func() { g = newLocalGuard() })
	verdicts, blocked := g.evaluateAll(context.Background(),
		[]packageSpec{{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}})
	if !blocked {
		t.Fatal("fail-closed run with a corrupt malware cache did not refuse")
	}
	if len(verdicts) != 1 || verdicts[0].Severity != "coverage" {
		t.Fatalf("want a coverage refusal, got %+v", verdicts)
	}
}

// TestGuardMalformedRecordDropsWholeArrayNotJustTheRecord states shape (e)
// explicitly, because "which one is it" is the whole point of the case.
//
// `guard update` writes ONE json.Marshal of the whole slice (guard_update.go:
// `data, err := json.Marshal(entries)`), so the cache is a single-line JSON
// array. encoding/json rejects an array wholesale on the first bad element,
// and ParseOSVBlob's NDJSON fallback then sees that same single line and
// rejects it too. So ONE malformed record among 237,000 good ones costs the
// ENTIRE file — the guard drops to the embedded floor.
//
// That is defensible (fail-safe: nothing is claimed that is not indexed) and
// it is NOT silently dropping the file while claiming coverage: `extra` stays
// 0, the ledger reports UNAVAILABLE, and warnGuardCacheUnusable says so out
// loud. What is NOT acceptable, and what this pins, is the third option —
// dropping the file and saying nothing.
//
// The NDJSON arm behaves differently on purpose and is asserted here so the
// difference is documented rather than discovered: line-delimited input skips
// only the bad LINE.
func TestGuardMalformedRecordDropsWholeArrayNotJustTheRecord(t *testing.T) {
	good := `{"id":"MAL-A","affected":[{"package":{"name":"corrupt-a","ecosystem":"npm"},"versions":["1.0.0"]}]}`
	bad := `{"id":"MAL-BAD","modified":12345}`
	other := `{"id":"MAL-C","affected":[{"package":{"name":"corrupt-c","ecosystem":"npm"},"versions":["1.0.0"]}]}`

	t.Run("JSON array loses every record", func(t *testing.T) {
		if n := len(malware.ParseOSVBlob([]byte("[" + good + "," + bad + "," + other + "]"))); n != 0 {
			t.Fatalf("parsed %d entries from an array with one bad record, want 0 "+
				"(if this now skips the bad record, the comment above and the shape (e) "+
				"finding in the P9F-257 write-up are both stale)", n)
		}
	})

	t.Run("NDJSON skips only the bad line", func(t *testing.T) {
		entries := malware.ParseOSVBlob([]byte(good + "\n" + bad + "\n" + other + "\n"))
		if len(entries) != 2 {
			t.Fatalf("parsed %d entries from NDJSON with one bad line, want 2", len(entries))
		}
	})

	t.Run("the array case is loud, not silent", func(t *testing.T) {
		writeCorruptCache(t, corruptCacheShape{
			name: "one bad record", data: []byte("[" + good + "," + bad + "," + other + "]"),
		})
		idx := malware.NewIndex(guardLogger)
		var extra int
		stderr := captureStderr(t, func() { _, extra = loadMalwareSources(idx, nil) })
		if extra != 0 {
			t.Errorf("extra = %d, want 0", extra)
		}
		// The good records around the bad one are gone too — that is the
		// behaviour, and the operator must be able to see it.
		if res := idx.Lookup(context.Background(), "npm", "corrupt-a", "1.0.0"); res.IsKnownMalicious {
			t.Error("a good record from the same array survived; the parser changed, update the finding")
		}
		if !strings.Contains(stderr, "WARNING") {
			t.Errorf("the whole cache was dropped in silence; stderr:\n%s", stderr)
		}
	})
}

// TestGuardCorruptCacheIsDistinguishableFromNoCache is the honesty check the
// vendor's screenshot raised: the startup line "offline known-malicious +
// typosquat active" is printed on both paths, so on its own it cannot tell an
// operator whether their downloaded feed is loaded. It stays (it is true — the
// floor and the typosquat corpus ARE active), but a cache file that exists and
// contributes nothing must produce output a machine that never ran `guard
// update` does not.
func TestGuardCorruptCacheIsDistinguishableFromNoCache(t *testing.T) {
	var absent, corrupt string

	t.Run("no cache file", func(t *testing.T) {
		t.Setenv(guardDBEnv, filepath.Join(t.TempDir(), "absent.json"))
		absent = captureStderr(t, func() { _ = newLocalGuard() })
		if strings.Contains(absent, "WARNING") {
			t.Errorf("a machine that never ran `guard update` must not warn; got:\n%s", absent)
		}
	})

	t.Run("corrupt cache file", func(t *testing.T) {
		writeCorruptCache(t, corruptCacheShape{name: "garbage", data: []byte("not json at all")})
		corrupt = captureStderr(t, func() { _ = newLocalGuard() })
	})

	if absent == corrupt {
		t.Fatalf("a corrupt cache is byte-identical to no cache on stderr:\n%s", corrupt)
	}
	if !strings.Contains(corrupt, "EMBEDDED FLOOR ONLY") {
		t.Errorf("the degraded state is not named; got:\n%s", corrupt)
	}
}
