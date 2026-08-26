package intelligence

// composer_minified_test.go — the Packagist `composer/2.0` minified
// metadata format, which runComposer did not implement.
//
// This was the single largest false-positive cell in the server-side risk
// corpus: 35 of the 60 most-installed Composer packages (58.3%) firing BOTH
// lic.missing and license.unidentified, at -15 each. The plan read the 1:1
// co-firing as evidence of the same Maven name-string bug. It is not — it
// is not a classifier problem at all. Both signals fire because the report
// arrives with NO FACTS.
//
// Two independent defects, both fixed by expanding before decoding:
//
//	(1) A removed field is encoded as the literal string "__unset" in a
//	    position the schema types map[string]string. encoding/json aborts,
//	    runComposer takes its warning branch, and the ENTIRE report comes
//	    back empty — no licence, no release date, no maintainers, no deps,
//	    no source repo — which the scorer reads as a clean package.
//	    psr/log 1.0.0 carries "require":"__unset"; guzzlehttp/guzzle
//	    carries "suggest":"__unset".
//
//	(2) Entries after the first are DELTAS: only fields that CHANGED from
//	    the previous entry appear. 99.4% of version entries across those 60
//	    packages carry no `license` key at all. So even where the decode
//	    succeeded, every non-latest coordinate silently lost its licence.
//
// The fixtures below are the real shapes, hand-trimmed, so this test needs
// no network and cannot go stale when Packagist republishes.

import (
	"encoding/json"
	"testing"
)

func parseComposerDoc(t *testing.T, name, body string) ([]map[string]json.RawMessage, bool) {
	t.Helper()
	var doc struct {
		Minified string                                  `json:"minified"`
		Packages map[string][]map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("fixture itself does not parse: %v", err)
	}
	return doc.Packages[name], doc.Minified == composerMinifiedFormat
}

// psrLogShape reproduces psr/log: three versions, the OLDEST of which
// unsets `require`. Only the newest entry carries `license`.
const psrLogShape = `{
  "minified": "composer/2.0",
  "packages": {
    "psr/log": [
      {"name":"psr/log","version":"3.0.2","time":"2024-09-11T13:17:53+00:00",
       "license":["MIT"],"description":"Common interface for logging libraries",
       "require":{"php":">=8.0.0"},
       "source":{"url":"https://github.com/php-fig/log.git","type":"git"},
       "dist":{"url":"https://api.github.com/repos/php-fig/log/zipball/abc","type":"zip","shasum":"deadbeef"}},
      {"version":"3.0.1","time":"2024-08-21T13:31:24+00:00",
       "dist":{"url":"https://api.github.com/repos/php-fig/log/zipball/def","type":"zip","shasum":"cafe"}},
      {"version":"1.0.0","time":"2012-12-21T11:40:51+00:00","extra":"__unset","require":"__unset",
       "dist":{"url":"https://api.github.com/repos/php-fig/log/zipball/ghi","type":"zip","shasum":"f00d"}}
    ]
  }
}`

// TestComposerUnsetSentinelDoesNotKillTheDocument is defect (1). Before the
// fix this fixture produced `json: cannot unmarshal string into Go struct
// field .packages.require of type map[string]string` and ZERO usable
// entries.
func TestComposerUnsetSentinelDoesNotKillTheDocument(t *testing.T) {
	raw, minified := parseComposerDoc(t, "psr/log", psrLogShape)
	if !minified {
		t.Fatal(`fixture must declare "minified":"composer/2.0"`)
	}
	entries := decodeComposerEntries(expandComposerMinified(raw, minified))
	if len(entries) != 3 {
		t.Fatalf("decoded %d entries, want 3 — one \"__unset\" field must not "+
			"destroy the whole document", len(entries))
	}

	// The unset field is GONE on the entry that unset it, not inherited.
	oldest := entries[2]
	if oldest.Version != "1.0.0" {
		t.Fatalf("entry order changed: oldest is %q", oldest.Version)
	}
	if len(oldest.Require) != 0 {
		t.Errorf(`1.0.0 unset "require" but it decoded as %v — "__unset" means `+
			`delete, not inherit`, oldest.Require)
	}
	// And the entry BEFORE it still has it, so the delete is scoped.
	if len(entries[1].Require) == 0 {
		t.Error("3.0.1 lost its inherited require — the unset leaked backwards")
	}
}

// TestComposerDeltaEntriesInheritLicence is defect (2), and it is the one
// that produced the licence false positives directly. Every entry must end
// up carrying the licence, not just the newest.
func TestComposerDeltaEntriesInheritLicence(t *testing.T) {
	raw, minified := parseComposerDoc(t, "psr/log", psrLogShape)
	entries := decodeComposerEntries(expandComposerMinified(raw, minified))
	for _, e := range entries {
		lics, ok := e.License.([]any)
		if !ok || len(lics) == 0 {
			t.Errorf("version %s decoded with license=%v — a delta entry inherits "+
				"the licence from the entry before it, and losing it is what made "+
				"58.3%% of top Composer packages report \"no license declared\"",
				e.Version, e.License)
			continue
		}
		if s, _ := lics[0].(string); s != "MIT" {
			t.Errorf("version %s license = %v, want MIT", e.Version, lics[0])
		}
	}
	// The same inheritance must reach the other fields the report needs.
	if entries[2].Name != "psr/log" {
		t.Errorf("oldest entry lost the package name (%q) — `name` is a delta "+
			"field too", entries[2].Name)
	}
	if entries[2].Source.URL == "" {
		t.Error("oldest entry lost source.url, so ProvenanceSection.SourceRepo " +
			"would be empty for every non-latest coordinate")
	}
}

// TestComposerNonMinifiedDocumentIsNotBackfilled is the guard on the
// carry-forward. Inheritance is only correct BECAUSE the document declares
// itself a delta chain. On a document that does not, an absent field means
// absent, and inheriting one would invent a fact.
func TestComposerNonMinifiedDocumentIsNotBackfilled(t *testing.T) {
	const plain = `{
  "packages": {
    "acme/thing": [
      {"name":"acme/thing","version":"2.0.0","license":["MIT"]},
      {"name":"acme/thing","version":"1.0.0"}
    ]
  }
}`
	raw, minified := parseComposerDoc(t, "acme/thing", plain)
	if minified {
		t.Fatal("fixture must NOT declare itself minified")
	}
	entries := decodeComposerEntries(expandComposerMinified(raw, minified))
	if len(entries) != 2 {
		t.Fatalf("decoded %d entries, want 2", len(entries))
	}
	if entries[1].License != nil {
		t.Errorf("1.0.0 was given license=%v on a document that never claimed to "+
			"be a delta chain — that is a fabricated fact", entries[1].License)
	}
}

// TestComposerUnsetIsStrippedEvenWhenNotMinified — the sentinel is a
// decode-killer regardless of provenance, so the strip is unconditional
// while the inheritance is not.
func TestComposerUnsetIsStrippedEvenWhenNotMinified(t *testing.T) {
	const doc = `{
  "packages": {"acme/thing": [{"name":"acme/thing","version":"1.0.0","require":"__unset"}]}
}`
	raw, minified := parseComposerDoc(t, "acme/thing", doc)
	entries := decodeComposerEntries(expandComposerMinified(raw, minified))
	if len(entries) != 1 {
		t.Fatalf("decoded %d entries, want 1 — the sentinel still killed the document", len(entries))
	}
	if entries[0].Version != "1.0.0" {
		t.Errorf("version = %q, want 1.0.0", entries[0].Version)
	}
}

// TestComposerUnsetAcrossEveryMapTypedField — `require`, `require-dev`,
// `suggest` and `support` are all map[string]string and all four are
// unsettable. A fix that only handled the one field the first reproduction
// happened to hit would leave the others live.
func TestComposerUnsetAcrossEveryMapTypedField(t *testing.T) {
	for _, field := range []string{"require", "require-dev", "suggest", "support"} {
		doc := `{"minified":"composer/2.0","packages":{"acme/thing":[
      {"name":"acme/thing","version":"2.0.0","license":["MIT"],"` + field + `":{"php":">=8"}},
      {"version":"1.0.0","` + field + `":"__unset"}]}}`
		raw, minified := parseComposerDoc(t, "acme/thing", doc)
		entries := decodeComposerEntries(expandComposerMinified(raw, minified))
		if len(entries) != 2 {
			t.Errorf("%s: decoded %d entries, want 2", field, len(entries))
			continue
		}
		if lics, ok := entries[1].License.([]any); !ok || len(lics) == 0 {
			t.Errorf("%s: older entry lost its inherited licence", field)
		}
	}
}
