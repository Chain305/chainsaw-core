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
	"encoding/base64"
	"net/netip"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
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

	// Coupled marks an exfil_host hit whose file also makes an outbound call:
	// the sink is used, not merely named. A downloader that lists gofile.io
	// among unsupported sites, or a type declaration naming .ngrok.io, names
	// the host and sends nothing. The guard ignores this field; the risk
	// engine requires it before an exfil host alone moves a verdict.
	Coupled bool
}

const maxFileSize = 2 << 20 // 2 MiB per file

var (
	// exfilHostRE: dedicated exfil/OOB sinks — near-zero legitimate use inside
	// a published package. Webhooks, paste/anon-file drops, tunnels, OOB hosts.
	//
	// MATCHES ARE NOT DISPOSITIVE ON THEIR OWN — every hit must pass
	// hostBoundaryOK. Several alternatives here are bare hostnames with no
	// scheme or path to anchor them (`dpaste\.`, `ghostbin\.`, `transfer\.sh`,
	// `file\.io/`, `gofile\.io`, `oshi\.at`, `oast\.(fun|site|...)`), and under
	// (?i) with no leading boundary they match INSIDE ordinary identifiers:
	//
	//   Keys.BracketedPaste.   -> dPaste.      (prompt_toolkit, a real block)
	//   ./profile.io/index     -> file.io/
	//   fileTransfer.sh        -> Transfer.sh
	//   toast.live             -> oast.live
	//   roast.pro              -> oast.pro
	//   logofile.io            -> gofile.io
	//   yoshi.at               -> oshi.at
	//   myGhostbin.render()    -> Ghostbin.
	//
	// This is the same defect class as the `Local State` prose match documented
	// on credStoreRE below, and the same fix: require the indicator to appear in
	// the context a real one appears in. Go's regexp is RE2 and has no
	// lookbehind, so the boundary is enforced in code rather than in the pattern
	// — see findExfilHost.
	exfilHostRE = regexp.MustCompile(`(?i)discord(?:app)?\.com/api/webhooks/|ptb\.discord\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|webhook\.site/|requestbin\.(?:net|com)|pipedream\.net|\.ngrok(?:-free)?\.(?:io|app)|pastebin\.com/raw/|paste\.ee/|hastebin\.com|ghostbin\.|transfer\.sh|anonfiles\.com|gofile\.io|file\.io/|0x0\.st|oshi\.at|burpcollaborator\.net|\.interactsh\.com|oast\.(?:fun|site|pro|live|online)|dpaste\.` +
		// An Internet Computer canister served RAW (uncertified) answers any
		// HTTP request with whatever the canister owner deploys — a C2 and drop
		// with no domain to seize: CanisterWorm (2026-03) polled
		// tdtqy-...-cai.raw.icp0.io, pgserve (2026-04) POSTed to
		// cjn37-...-cai.raw.icp0.io/drop. Only the canister-id form is
		// matched, so ICP SDK prose ("<canister>.raw.icp0.io") and the
		// certified boundary hosts (ic0.app, icp0.io, icp-api.io) are not.
		`|[a-z0-9]{5}(?:-[a-z0-9]{5}){3}-[a-z0-9]{3}\.raw\.(?:icp0\.io|ic0\.app)`)

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

	// nodeSendRE adds Node's own request primitives for the exfil_host
	// coupling. Kept out of netSendRE so the stealer tier, which the guard
	// enforces, is unchanged.
	nodeSendRE = regexp.MustCompile(`\bhttps?\.(?:request|get)\s*\(|\bdns\.(?:lookup|resolve\w*)\s*\(|\bnet\.(?:connect|createConnection)\s*\(`)

	// beaconSendRE is the browser send that is not a call: assigning a URL to
	// an Image (or script/iframe) .src makes the request. helpersutils-dev-tools
	// (2026-09, MAL-2026-16465) beaconed document.domain with
	// `new Image().src='http://5.189.173.113:8899/csp-edu?d='+...`. Like
	// nodeSendRE it only couples the exfil_host tier and the IP rule; a bare
	// `.src =` never fires anything on its own.
	beaconSendRE = regexp.MustCompile(`\bnew\s+Image\b|\.src\s*=[^=]`)

	// scriptSendRE is PHP's and Ruby's own send primitives, for the files
	// WantsScriptSource admits: laravel-lang (2026-05) posted from an
	// autoloaded helpers.php with curl_exec; a Ruby payload uses Net::HTTP,
	// open-uri, a raw socket or a client gem. file_get_contents and fopen
	// count only on a literal http(s) URL — on a path they read a file.
	// Read only for .php/.rb files (fileSends).
	scriptSendRE = regexp.MustCompile(`\bcurl_exec\s*\(|\b(?:file_get_contents|fopen)\s*\(\s*['"]https?://|\bfsockopen\s*\(|\bstream_socket_client\s*\(|\bwp_remote_(?:post|get|request)\s*\(|\bNet::HTTP\b|\bURI\.open\b|\bTCPSocket\.(?:new|open)\b|\b(?:Faraday|HTTParty|RestClient)\.`)

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
	// The same premise fails for stealer_string, and the test path was the only
	// one guarded until 2026-08-24. textual@8.2.8 hard-blocked on a docs
	// example that defines a RichLog subclass named KeyLogger — `\bkeylogg` in
	// a file the package documents with, never runs. Both tiers now consult
	// this predicate.
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

// IsNonShippingPath is isNonShippingPath for the other byte detectors
// (core/scriptsource), so they downgrade the same paths iocscan does.
func IsNonShippingPath(name string) bool { return isNonShippingPath(name) }

// hostBoundaryOK reports whether an exfilHostRE match starting at `start`
// begins where a hostname can actually begin, rather than in the middle of a
// longer word. See exfilHostRE for the false blocks this prevents.
//
// A real exfil host is always preceded by something that ends the previous
// token — a scheme's "//", a quote, whitespace, "=", "@", "(" — or by "." when
// it carries a subdomain. It is never preceded by a letter, digit, "-" or "_",
// because that would make it a DIFFERENT host: xdpaste.com is not dpaste.com.
//
// Two carve-outs, both load-bearing:
//
//   - A match that starts with "." anchors its own boundary (`\.ngrok\.io`,
//     `\.interactsh\.com`). Those are written to consume the separating dot
//     precisely so they attach to any subdomain, so the character before them
//     is EXPECTED to be alphanumeric — "foo.ngrok.io". Rejecting those would
//     delete a real detection.
//   - A match at offset 0 has nothing before it and is accepted.
func hostBoundaryOK(body string, start int, match string) bool {
	if start == 0 || strings.HasPrefix(match, ".") {
		return true
	}
	switch c := body[start-1]; {
	case c >= 'a' && c <= 'z',
		c >= 'A' && c <= 'Z',
		c >= '0' && c <= '9',
		c == '-', c == '_':
		return false
	}
	return true
}

// findExfilHost returns the first exfilHostRE match in body that begins at a
// real host boundary, or "" when none does.
//
// It scans ALL matches rather than testing only the first: a file can mention
// "BracketedPaste." near the top and embed a genuine sink lower down, and
// rejecting the first match must not blind the scan to the second.
func findExfilHost(body string) string {
	for _, loc := range exfilHostRE.FindAllStringIndex(body, -1) {
		m := body[loc[0]:loc[1]]
		if hostBoundaryOK(body, loc[0], m) {
			return m
		}
	}
	return ""
}

// ipURLRE is http:// followed by a dotted-quad and then something that ends a
// host, so 1.2.3.4.nip.io (a hostname) is not read as an address.
var ipURLRE = regexp.MustCompile(`http://(\d{1,3}(?:\.\d{1,3}){3})(?:[:/?#"'\x60\s)]|$)`)

// notC2Prefixes are addresses a package talks to for ordinary reasons: the
// shared-address, benchmarking and documentation ranges, plus 0/8 and 240/4.
// Private, loopback, link-local and multicast are checked by netip.
var notC2Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// wellKnownResolvers are public DNS services connectivity checks hit.
var wellKnownResolvers = map[string]bool{"8.8.8.8": true, "1.1.1.1": true, "9.9.9.9": true}

// findPublicIPURL returns the first "http://<public IPv4>" in body, or "".
// helpersutils-dev-tools (2026-09) beaconed to http://5.189.173.113:8899 on
// require; a hard-coded public address is a C2 the hostname list cannot name.
func findPublicIPURL(body string) string {
	for _, m := range ipURLRE.FindAllStringSubmatch(body, -1) {
		a, err := netip.ParseAddr(m[1])
		if err != nil || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
			a.IsMulticast() || wellKnownResolvers[m[1]] {
			continue
		}
		reserved := false
		for _, p := range notC2Prefixes {
			reserved = reserved || p.Contains(a)
		}
		if !reserved {
			return "http://" + m[1]
		}
	}
	return ""
}

// exfilSend reports whether body makes an outbound request of any shape the
// exfil_host tier and the public-IP rule accept as coupling.
func exfilSend(body string) bool {
	return netSendRE.MatchString(body) || nodeSendRE.MatchString(body) || beaconSendRE.MatchString(body)
}

// fileSends is exfilSend for JS/Python, scriptSendRE for PHP and Ruby.
func fileSends(name, text string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".php", ".rb":
		return scriptSendRE.MatchString(text)
	}
	return exfilSend(text)
}

// WantsScriptSource selects the PHP, Ruby and Python .pth files Scan reads
// on top of the caller's source set. A Composer autoload.files entry, a
// gem's lib/ and a .pth line all run without the user calling anything.
// Only the IOC scanner reads them; other detectors keep their file set.
func WantsScriptSource(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".php", ".rb", ".pth":
		return true
	}
	return false
}

// base64LiteralRE is a quoted string literal of base64 alphabet long enough
// to carry a URL. A data: URI ("data:image/png;base64,...") does not start at
// the quote, so inlined images, fonts and sourcemaps are not matched.
var base64LiteralRE = regexp.MustCompile(`['"\x60]([A-Za-z0-9+/]{40,}={0,2})['"\x60]`)

// Per-file bounds on base64 decoding: literals examined, the size of one
// literal, and the decoded text kept.
const (
	maxBase64Literals = 256
	maxBase64Literal  = 64 << 10
	maxBase64Decoded  = 256 << 10
)

// decodedBase64Text returns the file's base64 string literals that decode to
// printable text, newline-joined, or "". Binary (images, fonts, wasm, hashes)
// is dropped, so only decoded source or URLs reach the host rules.
// ponytail: one level, quoted literals only; a split or nested encoding is
// missed. Add concatenation/nesting when a sample needs it.
func decodedBase64Text(body string) string {
	var sb strings.Builder
	for _, m := range base64LiteralRE.FindAllStringSubmatch(body, maxBase64Literals) {
		lit := m[1]
		if len(lit) > maxBase64Literal {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(lit)
		if err != nil {
			if raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(lit, "=")); err != nil {
				continue
			}
		}
		if !printableText(raw) {
			continue
		}
		if sb.Len()+len(raw) > maxBase64Decoded {
			break
		}
		sb.Write(raw)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// printableText reports whether b is UTF-8 text with no control characters
// other than tab, newline and carriage return.
func printableText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}

// viaBase64 marks a Detail whose indicator appears only in decoded base64.
func viaBase64(body, indicator string) string {
	if strings.Contains(body, indicator) {
		return ""
	}
	return " (in base64)"
}

// Scan reports the strongest IOC across a package's source files.
func Scan(files map[string][]byte) Result {
	// Stealer evidence is tracked in two buckets, shipping and non-shipping,
	// for the same reason weakExfil exists below: a stealer string inside the
	// package's own tests, its docs examples, or a vendored tree is not
	// evidence that the package steals anything. textual@8.2.8 hard-blocked
	// because docs/examples/guide/input/key03.py defines a RichLog subclass
	// named KeyLogger, which hits keyloggerRE's `\bkeylogg`; textual has no
	// stealer match anywhere in its shipping code.
	//
	// The shipping bucket always wins — see the tier-2 branch below.
	stealerHit, stealerFile := false, ""
	weakStealerHit, weakStealerFile := false, ""
	sinkOrSend := false

	// weakExfil records an exfil-host hit seen ONLY in test / docs / vendored
	// content, so it can be reported as a warning if no shipping-code hit turns
	// up. Deliberately not returned early: a real hit elsewhere in the same
	// package must still win and still block.
	var weakExfil *Result
	// exfil is the first shipping exfil_host hit; a coupled one replaces it.
	var exfil *Result

	for name, b := range files {
		body := string(b)
		if len(body) > maxFileSize {
			body = body[:maxFileSize]
		}
		// The host and IP rules also read the file's base64 string literals,
		// decoded: CanisterWorm (2026-03) kept its canister C2 inside a
		// base64 Python payload. A send in the file OR in the decoded text
		// couples. The stealer tier and the reputation feed read body only.
		hostText := body
		if dec := decodedBase64Text(body); dec != "" {
			hostText = body + "\n" + dec
		}
		// Tier 1: an exfil sink host is dispositive when it appears in code the
		// package actually ships and runs. In its own tests, docs examples, or
		// vendored third-party trees it is downgraded to a warning — see
		// nonShippingPathRE.
		//
		// PHP, Ruby and .pth files (WantsScriptSource) count only a COUPLED
		// exfil_host or IP hit, with their own send primitives: Ruby's
		// ubiquitous obj.send(:m) is not a request, and named-only hits there
		// were the false blocks measured — domain_name's public-suffix data
		// names .ngrok.io, metasm's Windows export table matches the stealer
		// strings. The stealer tier and the feed's coupling read JS/Python.
		script := WantsScriptSource(name)
		if m := findExfilHost(hostText); m != "" {
			hit := Result{Detected: true, Kind: "exfil_host", Detail: name + ": " + strings.TrimSpace(m) + viaBase64(body, m)}
			if !isNonShippingPath(name) {
				hit.Coupled = fileSends(name, hostText)
				if hit.Coupled {
					return hit
				}
				if script {
					continue
				}
				if exfil == nil {
					exfil = &hit
				}
				continue
			}
			if weakExfil == nil && !script {
				hit.Weak = true
				hit.Detail += " (test/docs/vendored path — not shipping code)"
				weakExfil = &hit
			}
		} else if !isNonShippingPath(name) && fileSends(name, hostText) {
			// A public IP literal counts only coupled: addresses are named in
			// configs and comments far more often than hostnames on the list.
			if ip := findPublicIPURL(hostText); ip != "" {
				return Result{Detected: true, Kind: "exfil_host", Detail: name + ": " + ip + viaBase64(body, ip), Coupled: true}
			}
		}
		if script {
			continue
		}
		if netSendRE.MatchString(body) {
			sinkOrSend = true
		}
		if credStoreRE.MatchString(body) || tokenGrabRE.MatchString(body) ||
			walletRE.MatchString(body) || keyloggerRE.MatchString(body) {
			if isNonShippingPath(name) {
				if !weakStealerHit {
					weakStealerHit, weakStealerFile = true, name
				}
			} else {
				stealerHit, stealerFile = true, name
			}
		}
	}

	if exfil != nil {
		return *exfil
	}

	// Tier 2: a stealer string only counts when the package also has a sink or
	// makes a network call — the coupling that separates a stealer from a
	// legitimate browser/forensics reader.
	//
	// Shipping code first, so a genuine hit is never masked by a test/docs one
	// found earlier in the (randomised) map walk. Only when the stealer
	// evidence is EXCLUSIVELY non-shipping does the hit degrade to a warning,
	// mirroring the exfil tier's weakExfil.
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

	// Weakest tier last: an indicator seen only in test/docs/vendored content.
	// Reported so it is never silently dropped, flagged Weak so no caller
	// mistakes it for shipping-code evidence. Both weak kinds sit BELOW the
	// reputation tier deliberately — a shipping-code reputation hit is stronger
	// evidence than an indicator in a docs example, whatever its kind.
	if weakExfil != nil {
		return *weakExfil
	}
	if weakStealerHit && sinkOrSend {
		return Result{
			Detected: true,
			Kind:     "stealer_string",
			Detail:   weakStealerFile + " (test/docs/vendored path — not shipping code)",
			Weak:     true,
		}
	}
	return Result{}
}
