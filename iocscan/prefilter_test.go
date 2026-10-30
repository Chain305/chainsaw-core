package iocscan

import (
	"strings"
	"testing"
)

// refFindExfilHost is findExfilHost as it was before the prefilter: every
// regex match, no literal gate.
func refFindExfilHost(body string) string {
	for _, loc := range exfilHostRE.FindAllStringIndex(body, -1) {
		m := body[loc[0]:loc[1]]
		if hostBoundaryOK(body, loc[0], m) {
			return m
		}
	}
	return ""
}

func refStealer(body string) bool {
	return credStoreRE.MatchString(body) || tokenGrabRE.MatchString(body) ||
		walletRE.MatchString(body) || keyloggerRE.MatchString(body)
}

var prefilterSeeds = []string{
	"",
	"const x = 1;",
	"https://discord.com/api/webhooks/1/abc",
	"HTTPS://DISCORDAPP.COM/API/WEBHOOKS/1",
	"x=https://ptb.discord.com/api/webhooks/9",
	"api.telegram.org/bot123:abc",
	"foo.NGROK-FREE.APP/x",
	"http://pastebin.com/raw/abc",
	"tdtqy-aaaaa-bbbbb-ccccc-cai.raw.icp0.io/drop",
	"abcde-fghij-klmno-pqrst-uvw.RAW.IC0.APP",
	"BracketedPaste.ee/ and paste.ee/",
	"oast.fun oast.online dpaste.org",
	"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
	`"~/Library/Application Support/Google/Chrome/Local State"`,
	"the local state of the context",
	`AppData\\Local\\x`,
	`C:\\Users\\a\\AppData\\\\Roaming\\\\x`,
	"cookies.sqlite KEY4.DB Logins.Json .Mozilla/Firefox",
	"wallet.dat .electrum exodus\\\\exodus atomic\\\\Local MetaMask",
	"from pynput.keyboard import Listener; GetAsyncKeyState; keylogger",
	// Token-shaped, split so no literal token sits in the file (push protection).
	"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAx" + "." + "abcdef" + "." + "ghijklmnopqrstuvwxyz0123456",
	"NTIzNDU2Nzg5MDEyMzQ1Njc4OTAx" + "." + "AbC-_f" + "." + "0123456789abcdefghijklmnopqrstu",
	"discord user token here; token stealer grab; steal the cookie",
	"requests.post (url); httpx.stream; aiohttp.ClientSession; urllib.request.urlopen(u)",
	".sendall (b); http.client; fetch (u); axios.get; new XMLHttpRequest()",
	// Non-ASCII folds Go's (?i) accepts: long s and the Kelvin sign.
	"cookie\u017f.sqlite",
	"\u212aey4.db",
	"pyn\u017fput.\u212aeyboard",
	"https://di\u017fcord.com/api/webhooks/1",
}

// The prefilter must never change what the IOC regexes find: each gated
// predicate equals the raw regex it gates, on every input.
func FuzzPrefilterMatchesRegexes(f *testing.F) {
	for _, s := range prefilterSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if got, want := findExfilHost(body), refFindExfilHost(body); got != want {
			t.Fatalf("findExfilHost(%q) = %q, regex %q", body, got, want)
		}
		if got, want := stealerMatch(fold(body)), refStealer(body); got != want {
			t.Fatalf("stealerMatch(%q) = %v, regex %v", body, got, want)
		}
		if got, want := netSendMatch(body), netSendRE.MatchString(body); got != want {
			t.Fatalf("netSendMatch(%q) = %v, regex %v", body, got, want)
		}
		if got, want := tokenGrabMatch(body), tokenGrabRE.MatchString(body); got != want {
			t.Fatalf("tokenGrabMatch(%q) = %v, regex %v", body, got, want)
		}
	})
}

// The seeds alone, so the equivalence runs in every `go test`, not only
// under -fuzz.
func TestPrefilterSeedsMatchRegexes(t *testing.T) {
	for _, s := range prefilterSeeds {
		for _, v := range []string{s, strings.ToUpper(s), "pad " + s + " pad\n" + s} {
			if findExfilHost(v) != refFindExfilHost(v) || stealerMatch(fold(v)) != refStealer(v) ||
				netSendMatch(v) != netSendRE.MatchString(v) || tokenGrabMatch(v) != tokenGrabRE.MatchString(v) {
				t.Errorf("prefilter disagrees with the regexes on %q", v)
			}
		}
	}
}

func BenchmarkScanLargeCleanSource(b *testing.B) {
	line := "function f(a, b) { return a.map((x) => x * b).filter(Boolean); } // ordinary code\n"
	files := map[string][]byte{"lib/index.js": []byte(strings.Repeat(line, 25000))}
	b.SetBytes(int64(len(files["lib/index.js"])))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Scan(files)
	}
}
