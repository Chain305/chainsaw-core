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
}

const maxFileSize = 2 << 20 // 2 MiB per file

var (
	// exfilHostRE: dedicated exfil/OOB sinks — near-zero legitimate use inside
	// a published package. Webhooks, paste/anon-file drops, tunnels, OOB hosts.
	exfilHostRE = regexp.MustCompile(`(?i)discord(?:app)?\.com/api/webhooks/|ptb\.discord\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|webhook\.site/|requestbin\.(?:net|com)|pipedream\.net|\.ngrok(?:-free)?\.(?:io|app)|pastebin\.com/raw/|paste\.ee/|hastebin\.com|ghostbin\.|transfer\.sh|anonfiles\.com|gofile\.io|file\.io/|0x0\.st|oshi\.at|burpcollaborator\.net|\.interactsh\.com|oast\.(?:fun|site|pro|live|online)|dpaste\.`)

	// credStoreRE / tokenGrabRE / walletRE / keyloggerRE: stealer building
	// blocks. High-signal but legitimately present in browser/forensics tools,
	// so they only fire when coupled (see Scan).
	credStoreRE = regexp.MustCompile(`(?i)cookies\.sqlite|\bLogin Data\b|\bkey4\.db\b|logins\.json|\bLocal State\b|AppData\\\\.*\\\\(?:Local|Roaming)|\.mozilla/firefox|Google/Chrome/User Data`)
	tokenGrabRE = regexp.MustCompile(`[MNO][\w-]{23}\.[\w-]{6}\.[\w-]{27,38}|discord[^\n]{0,30}token|token[^\n]{0,20}grab|steal[^\n]{0,12}(?:token|cookie|password)`)
	walletRE    = regexp.MustCompile(`(?i)wallet\.dat|\.electrum|exodus\\\\exodus|atomic\\\\Local|metamask`)
	keyloggerRE = regexp.MustCompile(`(?i)pynput\.keyboard|GetAsyncKeyState|\bkeylogg`)

	// netSendRE: an actual outbound call, used only to COUPLE a stealer string
	// (so a stealer-shaped package that also sends is caught even if its sink
	// host is not on the exfil list).
	netSendRE = regexp.MustCompile(`requests\.(?:post|put|get)\s*\(|httpx\.(?:post|get|put|stream)|aiohttp\.|urllib\.request\.urlopen\s*\(|\.send(?:all)?\s*\(|http\.client|fetch\s*\(|axios\.|XMLHttpRequest`)
)

// Scan reports the strongest IOC across a package's source files.
func Scan(files map[string][]byte) Result {
	stealerHit, stealerFile := false, ""
	sinkOrSend := false

	for name, b := range files {
		body := string(b)
		if len(body) > maxFileSize {
			body = body[:maxFileSize]
		}
		// Tier 1: an exfil sink host is dispositive on its own.
		if m := exfilHostRE.FindString(body); m != "" {
			return Result{Detected: true, Kind: "exfil_host", Detail: name + ": " + strings.TrimSpace(m)}
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
	return Result{}
}
