package cli

// Attack 2026-53: @7nohe/openapi-react-query-codegen (2026-08-28). release.yml
// ran on issue_comment, held id-token: write for npm trusted publishing, and
// published when any PR comment read "npm publish" — no author_association
// check. Attacker PRs #215/#216 added preinstall hooks that ran during
// `pnpm install` in the runner and published ten malicious versions with
// valid provenance (MAL-2026-15494): 0.5.4 1.6.3 2.2.1 3.0.3 (wave 1,
// binding.gyp only) and 3.0.4 1.6.4 2.2.2 0.5.5 (wave 2, binding.gyp plus
// "preinstall": "node 3FWCvzduYZg.js", a 4-6 MB XOR loader).
//
// Workflow half: scan-actions reports action.comment_trigger_unguarded
// (high), default exit 1; the author_association-guarded twin does not fire.
// Package half (install guard, analyzeArtifact): wave 2 is refused on the
// bytes (looksXorLoader behind the preinstall hook). Wave 1 is refused on the
// bytes since v0.22.106 (F13): binding.gyp makes it an install script, and
// its payload — a gyp `conditions` Python expression escaping eval()'s empty
// builtins — is read as eval_encoded. Nothing references 3FWCvzduYZg.js.
// Both waves are refused once MAL-2026-15494 is in the feed (core/malware).

import (
	"strings"
	"testing"
)

func TestAttack2026_53_7noheCommentTrigger(t *testing.T) {
	wf := func(guard string) string {
		return `name: Release
on:
  issue_comment:
    types: [created]
permissions:
  contents: write
  id-token: write
  issues: write
jobs:
  publish:
    if: github.event.issue.pull_request && contains(github.event.comment.body, 'npm publish')` + guard + `
    runs-on: ubuntu-latest
    steps:
      - uses: ` + atk26PinnedCheckout + `
        with:
          ref: refs/pull/${{ github.event.issue.number }}/head
      - run: pnpm install
      - run: pnpm build
      - run: npm publish --provenance --tag next
`
	}
	code, r, err := runScanActionsJSON(t, atk26WriteWF(t, "release.yml", wf("")), "")
	if err != nil {
		t.Fatal(err)
	}
	if atk26Sigs(r)["action.comment_trigger_unguarded"] != "high" || code != 1 {
		t.Fatalf("unguarded issue_comment publish: want high comment_trigger_unguarded, exit 1; got exit %d %+v", code, r.Findings)
	}
	guarded := wf(" && contains(fromJSON('[\"OWNER\",\"MEMBER\"]'), github.event.comment.author_association)")
	code, r, err = runScanActionsJSON(t, atk26WriteWF(t, "release.yml", guarded), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := atk26Sigs(r)["action.comment_trigger_unguarded"]; ok || code != 0 {
		t.Fatalf("author_association-guarded twin: want no finding, exit 0; got exit %d %+v", code, r.Findings)
	}
}

// atk53Loader is a defanged 3FWCvzduYZg.js: one >1 MiB XOR-encoded string
// decoded with fromCharCode and handed to the Function constructor.
func atk53Loader() string {
	return `var k=229;var d="` + strings.Repeat("Q", 1200*1024) +
		`";var o="";for(var i=0;i<d.length;i++){o+=String.fromCharCode(d.charCodeAt(i)^k)}Function(o)();`
}

// atk53Gyp hides the call in a `conditions` Python expression, the shape of
// the real 828-byte binding.gyp (defanged: it runs `true`).
const atk53Gyp = `{"targets":[{"target_name":"codegen","conditions":[["'\U0000006f'.__class__.__mro__[1].__subclasses__() and 1==1",{"defines":["X"]}]]}]}`

func TestAttack2026_53_7noheNpmPayload(t *testing.T) {
	wave2 := makeTGZ(t, map[string]string{
		"package/package.json":   `{"name":"@7nohe/openapi-react-query-codegen","version":"3.0.4","scripts":{"preinstall":"node 3FWCvzduYZg.js"}}`,
		"package/binding.gyp":    atk53Gyp,
		"package/3FWCvzduYZg.js": atk53Loader(),
	})
	if v := analyzeArtifact("npm", wave2); !v.Block {
		t.Fatalf("wave 2 (preinstall -> XOR loader) must be refused on the bytes, got %+v", v)
	}

	wave1 := makeTGZ(t, map[string]string{
		"package/package.json":   `{"name":"@7nohe/openapi-react-query-codegen","version":"3.0.3"}`,
		"package/binding.gyp":    atk53Gyp,
		"package/3FWCvzduYZg.js": atk53Loader(),
	})
	if v := analyzeArtifact("npm", wave1); !v.Block {
		t.Fatalf("wave 1 (binding.gyp condition escape) must be refused since v0.22.106 (F13), got %+v", v)
	}

	// Negative control: the last good release, no gyp file, no hook.
	clean := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"@7nohe/openapi-react-query-codegen","version":"3.0.2","bin":{"openapi-rq":"dist/cli.mjs"}}`,
		"package/dist/cli.mjs": "export const run = () => 0;\n",
	})
	if v := analyzeArtifact("npm", clean); v.Block || v.Severity != "" {
		t.Fatalf("clean 3.0.2 must not be flagged, got %+v", v)
	}
}
