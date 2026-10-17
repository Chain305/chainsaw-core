package cli

import "testing"

// Tensorlake (row 58): obfuscated lib/setup.mjs behind "preinstall": "node
// lib/setup.mjs" is refused by the guard on the first hop.
func TestAttack2026_58_Tensorlake_Guard(t *testing.T) {
	v := analyzeArtifact("npm", atkBTgz(t, map[string]string{
		"package.json":  `{"name":"tensorlake","version":"0.5.144","scripts":{"preinstall":"node lib/setup.mjs"}}`,
		"lib/setup.mjs": atkBObf("require('node:child_process').execFileSync('bun',[__dirname+'/Math_Symbol.js']);\n"),
	}))
	if !v.Block {
		t.Fatalf("guard did not refuse tensorlake@0.5.144: %+v", v)
	}
	clean := analyzeArtifact("npm", atkBTgz(t, map[string]string{
		"package.json": `{"name":"tensorlake","version":"0.5.143","main":"lib/index.js"}`,
		"lib/index.js": "module.exports={};\n",
	}))
	if clean.Block {
		t.Fatalf("tensorlake@0.5.143 refused: %+v", clean)
	}
}
