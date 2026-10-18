package cli

import "testing"

// Since v0.22.113 a PR that adds an action imitating a known-good one under
// another owner blocks. Both refs are SHA-pinned, so the unpinned rule is not
// what decides.
func TestPRScanActionTyposquatBlocks(t *testing.T) {
	wf := func(uses string) []byte {
		return []byte("name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + uses + "\n")
	}
	added, _, err := diffWorkflow(".github/workflows/ci.yml", nil, wf("actoins/checkout@0123456789abcdef0123456789abcdef01234567"))
	if err != nil || len(added) != 1 || !hasPRSignal(added[0].Signals, "action.typosquat") || added[0].Verdict != "block" {
		t.Fatalf("actoins/checkout: want a block row with action.typosquat, got %+v %v", added, err)
	}
	// A sibling repository of the same publisher is not a squat (every
	// typosquat hit on 940 real workflows was anchore/sbom-action).
	added, _, err = diffWorkflow(".github/workflows/sbom.yml", nil, wf("anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610"))
	if err != nil || len(added) != 1 || hasPRSignal(added[0].Signals, "action.typosquat") || added[0].Verdict == "block" {
		t.Fatalf("anchore/sbom-action: want no typosquat and no block, got %+v %v", added, err)
	}
}
