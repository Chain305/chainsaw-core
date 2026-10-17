package installscripts

import (
	"fmt"
	"strings"
	"testing"
)

// Replay of the referenced-script path against the loader shape
// MAL-2026-11524 documents for keyv@6.0.0, for
// docs/DESIGNS.md#designs-cacheable-campaign-signal-replay §3.
//
// The real setup.mjs is gone (npm 404, deps.dev 404, no cached copy), so
// the bodies below are built ONLY from behaviours the advisory states in
// prose. This measures the DETECTOR, not the artifact.
//
// What it establishes:
//  1. ReferencedScripts resolves "node setup.mjs" — the follower added
//     2026-06-27, five weeks before the campaign, does its job.
//  2. fetch-to-disk + run-binary does NOT escalate. That is deliberate
//     (see ScanReferencedBody's header).
//  3. This campaign's shape — download a legitimate signed Bun runtime,
//     exec a LOCAL FILE with it — escalates since v0.22.106 (F11): the
//     runtime is not the node running the hook and its argument is a
//     bundled script. Before that, escalation rested entirely on the
//     obfuscation arm (>24 javascript-obfuscator identifiers), an
//     unknowable byte-level property of a file that no longer exists.
func TestCacheableCampaignReferencedScript(t *testing.T) {
	manifest := []byte(`{"name":"keyv","version":"6.0.0","license":"MIT",` +
		`"scripts":{"preinstall":"node setup.mjs","test":"vitest run"}}`)

	if got := NPM(manifest).Kind; got != KindPresent {
		t.Errorf("manifest-only kind = %q, want %q — the payload is not in "+
			"the hook string, so the manifest alone can only say 'present'",
			got, KindPresent)
	}

	refs := ReferencedScripts("node setup.mjs")
	if len(refs) != 1 || refs[0] != "setup.mjs" {
		t.Fatalf("ReferencedScripts = %v, want [setup.mjs]; the follower "+
			"must resolve the loader or nothing downstream can run", refs)
	}

	// Download a signed upstream runtime, unpack it, exec a local file with
	// it. No eval, no decode. Exactly what the advisory describes.
	fetchExec := `
const r = await fetch(u); fs.writeFileSync("bun.zip", Buffer.from(await r.arrayBuffer()));
execSync("unzip -o bun.zip"); execSync("chmod +x ./bun");
execFileSync("./bun", ["Math_Symbol.js"]);
`
	if got := ScanReferencedBody(fetchExec); got != KindFetchesRemote {
		t.Errorf("fetch runtime + run bundled script = %q, want %q (F11)", got, KindFetchesRemote)
	}
	// The benign half of the trade-off is unchanged: fetch a binary and run
	// IT (a version check), not a bundled script, stays present.
	fetchBinary := strings.Replace(fetchExec, `["Math_Symbol.js"]`, `["--version"]`, 1)
	if got := ScanReferencedBody(fetchBinary); got != KindPresent {
		t.Errorf("fetch+run-binary body = %q, want %q — the FP trade-off in "+
			"ScanReferencedBody changed", got, KindPresent)
	}

	// The obfuscation arm is the only route to escalation for this shape.
	var obf strings.Builder
	for i := 0; i < 30; i++ { // looksObfuscatedJS threshold is >24
		fmt.Fprintf(&obf, "var _0x%04x=_0x%04x[%d];\n", 0x1000+i, 0x4f2a, i)
	}
	if got := ScanReferencedBody(obf.String() + fetchExec); got != KindFetchesRemote {
		t.Errorf("obfuscated loader = %q, want %q", got, KindFetchesRemote)
	}
}
