// Package iocscan detects high-confidence malicious INDICATORS embedded in a
// package's source — the host/string IOCs that reveal intent even when the
// code shape itself looks ordinary. It complements the structural signals
// (install-scripts, pysource import-time) by catching what the package TALKS
// TO and CONTAINS rather than how its code is shaped.
//
// Two tiers, tuned for near-zero false positives:
//
//   - exfil_host (dispositive alone): a Discord/Telegram/Slack webhook, a
//     paste/anon-file drop, an ngrok/interactsh tunnel, or an OOB-interaction
//     host. A published package embedding one of these is almost never
//     legitimate — these are exfil sinks, not dependencies.
//
//   - stealer_string (gated): a browser-credential-store path, a token-grab
//     regex, a wallet file, or a keylogger primitive — but ONLY when COUPLED
//     with an exfil sink or a network send in the same package. A legit
//     browser-cookie / forensics library reads `cookies.sqlite` but does not
//     also POST it to a webhook; the coupling is what separates the stealer
//     from the legitimate reader (the FP that a bare cred-path match would
//     cause).
package iocscan

import (
	"regexp"
	"strings"
)

type Result struct {
	Detected bool
	Kind     string // "exfil_host" | "stealer_string" | "reputation_host"
	Detail   string // indicator + file

	// Weak marks a hit whose ONLY evidence sits in content the package ships
	// but does not run — its own tests, docs examples, or a vendored
	// third-party tree. The indicator is real and worth surfacing; it is not
	// strong enough on its own to refuse a developer's install.
	//
	// Callers must branch on this. The workstation guard downgrades a weak hit
	// to a warning; the server-side intelligence provider skips it, because
	// its report field is named MaliciousIOC and a URL inside an SSRF-
	// protection test is not that. Ignoring Weak reinstates the false-block.
	Weak bool
}

const maxFileSize = 2 << 20 // 2 MiB per file

var (
	// exfilHostRE: dedicated exfil/OOB sinks — near-zero legitimate use inside
	// a published package. Webhooks, paste/anon-file drops, tunnels, OOB hosts.
	exfilHostRE = regexp.MustCompile(`(?i)discord(?:app)?\.com/api/webhooks/|ptb\.discord\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|webhook\.site/|requestbin\.(?:net|com)|pipedream\.net|\.ngrok(?:-free)?\.(?:io|app)|pastebin\.com/raw/|paste\.ee/|hastebin\.com|ghostbin\.|transfer\.sh|anonfiles\.com|gofile\.io|file\.io/|0x0\.st|oshi\.at|burpcollaborator\.net|\.interactsh\.com|oast\.(?:fun|site|pro|live|online)|dpaste\.`)

	// credStoreRE / tokenGrabRE / walletRE / keyloggerRE: stealer building
	// blocks. High-signal but legitimately present in browser/forensics tools,
	// so they only fire when coupled (see Scan).
	// NOTE ON CASING: `Local State` and `Login Data` are literal Chrome/Chromium
	// FILENAMES, not English. Matching them case-insensitively made the pattern
	// fire on ordinary prose — "local state" appears in comments in
	// opentelemetry-api's context module and in oauthlib's OAuth grant types,
	// and both were hard-BLOCKED at install time as a result. Measured on 860
	// real top packages, this single alternative drove a large share of a 2.09%
	// false-block rate on PyPI.
	//
	// They are therefore matched case-SENSITIVELY and only in a filename-ish
	// context (adjacent to a path separator or a quote), which is how a real
	// credential-store path appears:
	//   "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"
	//   "~/Library/Application Support/Google/Chrome/Local State"
	// No detection is lost: a stealer references the file, it does not discuss
	// the concept. The remaining alternatives stay case-insensitive because
	// they are already unambiguous tokens.
	credStoreRE = regexp.MustCompile(
		`(?i)cookies\.sqlite|\bkey4\.db\b|logins\.json|AppData\\\\.*\\\\(?:Local|Roaming)|\.mozilla/firefox|Google/Chrome/User Data` +
			// (?-i) is load-bearing: in Go a (?i) flag persists to the end of the
			// pattern, so without turning it back off these two alternatives
			// would stay case-insensitive and the prose match would survive.
			`|` + `(?-i)[/\\"'](?:Local State|Login Data)(?:["'/\\]|$)`)
	tokenGrabRE = regexp.MustCompile(`[MNO][\w-]{23}\.[\w-]{6}\.[\w-]{27,38}|discord[^\n]{0,30}token|token[^\n]{0,20}grab|steal[^\n]{0,12}(?:token|cookie|password)`)
	walletRE    = regexp.MustCompile(`(?i)wallet\.dat|\.electrum|exodus\\\\exodus|atomic\\\\Local|metamask`)
	keyloggerRE = regexp.MustCompile(`(?i)pynput\.keyboard|GetAsyncKeyState|\bkeylogg`)

	// netSendRE: an actual outbound call, used only to COUPLE a stealer string
	// (so a stealer-shaped package that also sends is caught even if its sink
	// host is not on the exfil list).
	netSendRE = regexp.MustCompile(`requests\.(?:post|put|get)\s*\(|httpx\.(?:post|get|put|stream)|aiohttp\.|urllib\.request\.urlopen\s*\(|\.send(?:all)?\s*\(|http\.client|fetch\s*\(|axios\.|XMLHttpRequest`)

	// nonShippingPathRE marks files that ship inside a package but are not part
	// of what the package DOES: its own test suite, its documentation examples,
	// and third-party code it vendors.
	//
	// The exfil_host tier was written as "dispositive alone" on the premise
	// that "a published package embedding one of these is almost never
	// legitimate". Measured against 860 real top packages, that premise does
	// not hold: the hits were langchain-core's test FOR SSRF protection,
	// huggingface-hub's API tests, rapidfuzz's vendored bootstrap.js, and
	// textual's docs example for key handling. A test that asserts a URL is
	// blocked necessarily contains that URL.
	//
	// A hit in one of these paths is downgraded to a WARNING rather than
	// dropped. This is a deliberate, bounded loss: a payload hidden under
	// `tests/` still warns, still appears in the report, and is still caught by
	// the name/feed floor and the server-side signals — it just does not
	// hard-refuse a developer's install on evidence this weak. A hit anywhere
	// the package actually executes stays dispositive.
	nonShippingPathRE = regexp.MustCompile(`(?i)(?:^|/)(?:tests?|testing|__tests__|spec|specs|e2e|fixtures?|testdata|examples?|docs?|doc|samples?|benchmarks?)/|(?:^|/)(?:extern|external|third_party|thirdparty|vendor|vendored|node_modules|site-packages)/|(?:^|/)[^/]*_test\.[a-z]+$|(?:^|/)test_[^/]*\.[a-z]+$|\.min\.js$`)
)

// isNonShippingPath reports whether a path inside a package archive is test,
// documentation, or vendored third-party content rather than the package's own
// shipping code. See nonShippingPathRE for why this distinction exists.
func isNonShippingPath(name string) bool { return nonShippingPathRE.MatchString(name) }

// Scan reports the strongest IOC across a package's source files.
func Scan(files map[string][]byte) Result {
	stealerHit, stealerFile := false, ""
	sinkOrSend := false

	// weakExfil records an exfil-host hit seen ONLY in test / docs / vendored
	// content, so it can be reported as a warning if no shipping-code hit turns
	// up. Deliberately not returned early: a real hit elsewhere in the same
	// package must still win and still block.
	var weakExfil *Result

	for name, b := range files {
		body := string(b)
		if len(body) > maxFileSize {
			body = body[:maxFileSize]
		}
		// Tier 1: an exfil sink host is dispositive when it appears in code the
		// package actually ships and runs. In its own tests, docs examples, or
		// vendored third-party trees it is downgraded to a warning — see
		// nonShippingPathRE.
		if m := exfilHostRE.FindString(body); m != "" {
			hit := Result{Detected: true, Kind: "exfil_host", Detail: name + ": " + strings.TrimSpace(m)}
			if !isNonShippingPath(name) {
				return hit
			}
			if weakExfil == nil {
				hit.Weak = true
				hit.Detail += " (test/docs/vendored path — not shipping code)"
				weakExfil = &hit
			}
		}
		if netSendRE.MatchString(body) {
			sinkOrSend = true
		}
		if credStoreRE.MatchString(body) || tokenGrabRE.MatchString(body) ||
			walletRE.MatchString(body) || keyloggerRE.MatchString(body) {
			stealerHit, stealerFile = true, name
		}
	}

	// Tier 2: a stealer string only counts when the package also has a sink or
	// makes a network call — the coupling that separates a stealer from a
	// legitimate browser/forensics reader.
	if stealerHit && sinkOrSend {
		return Result{Detected: true, Kind: "stealer_string", Detail: stealerFile}
	}

	// Tier 3: reputation feed. A host on the offline known-bad feed, referenced
	// in source COUPLED with an outbound send (and not an allowlisted CDN), is a
	// strong signal. Runs last so the more specific exfil_host / stealer_string
	// kinds take precedence. A bare reference (no send) stays advisory and does
	// not fire (detection-roadmap item 4).
	if hit, detail := defaultReputationMatcher.match(files, true); hit {
		return Result{Detected: true, Kind: "reputation_host", Detail: detail}
	}

	// Weakest tier last: an exfil host seen only in test/docs/vendored content.
	// Reported so it is never silently dropped, flagged Weak so no caller
	// mistakes it for shipping-code evidence.
	if weakExfil != nil {
		return *weakExfil
	}
	return Result{}
}
