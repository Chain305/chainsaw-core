package osv

import (
	"encoding/json"
	"testing"
)

// TestFlattenRecordDropsRustSecInformational: RustSec publishes
// "informational" advisories (unmaintained, unsound, notice) next to real
// vulnerabilities, marked at affected[].database_specific.informational.
// They are not vulnerabilities — cargo-audit reports them as warnings and
// does not fail on them — but the flattener matched them like any other
// advisory, so every affected crate stored isVulnerable=true and scored
// vuln.known_vulnerable. On feldera/feldera's Cargo.lock (2026-10-14) that
// was 16 of the 26 medium findings: paste, bincode, async-std, instant,
// proc-macro-error (unmaintained), lru, memmap2, scc, anyhow (unsound), ...
//
// Break it like this: drop the informational guard in flattenRecord, or the
// DatabaseSpecific field from osvAffected (the guard then reads "").
func TestFlattenRecordDropsRustSecInformational(t *testing.T) {
	for _, kind := range []string{"unmaintained", "unsound", "notice"} {
		rec := decodeInformationalFixture(t, `"`+kind+`"`)
		if got := flattenRecord(rec); len(got) != 0 {
			t.Errorf("%s advisory produced %d rows, want 0", kind, len(got))
		}
	}
	// Control: a real RustSec vulnerability carries informational: null and
	// must still flatten (RUSTSEC-2023-0071, rsa, the Marvin attack).
	if got := flattenRecord(decodeInformationalFixture(t, "null")); len(got) == 0 {
		t.Fatal("a non-informational RustSec advisory produced 0 rows; the filter is over-broad")
	}
}

func decodeInformationalFixture(t *testing.T, informational string) osvRecord {
	t.Helper()
	raw := `{"id":"RUSTSEC-2024-0436","affected":[{"package":{"ecosystem":"crates.io","name":"paste"},` +
		`"versions":["1.0.15"],"database_specific":{"categories":[],"cvss":null,"informational":` + informational + `}}]}`
	var rec osvRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rec
}
