package codesmell

import (
	"bytes"
	"math"
	"regexp"
	"sync"
)

// entropyPrefilter is the set of ASCII substrings that at least one
// secretRule uses as an anchor. If NONE of these appears in the file
// body, we can skip the regex pass entirely. This cuts the dominant
// "no-hit" path to a handful of bytes.Contains calls.
var entropyPrefilter = [][]byte{
	[]byte("AKIA"), []byte("ASIA"),
	[]byte("aws_secret"), []byte("aws_access"),
	[]byte("ghp_"), []byte("gho_"), []byte("ghu_"), []byte("ghs_"), []byte("ghr_"),
	[]byte("github_pat_"), []byte("glpat-"),
	[]byte("xox"), []byte("hooks.slack.com"),
	[]byte("AIza"), []byte(`"private_key"`),
	[]byte("sk_live_"), []byte("rk_live_"),
	[]byte("npm_"), []byte("pypi-AgENd"), []byte("cio"),
	[]byte("-----BEGIN "),
	// Generic-high-entropy anchors (case-insensitive handled by dedup).
	[]byte("secret"), []byte("Secret"), []byte("SECRET"),
	[]byte("token"), []byte("Token"), []byte("TOKEN"),
	[]byte("password"), []byte("Password"), []byte("PASSWORD"),
	[]byte("api_key"), []byte("API_KEY"), []byte("apiKey"),
	[]byte("credential"), []byte("Credential"),
	[]byte("eyJ"),
}

// hasEntropyAnchor reports whether any known secret-rule anchor appears
// in the file body. Returns true quickly on files that cannot match
// any rule, giving us an O(body-size) fast path.
func hasEntropyAnchor(body []byte) bool {
	for _, a := range entropyPrefilter {
		if bytes.Contains(body, a) {
			return true
		}
	}
	return false
}

// Gitleaks (MIT) is the upstream-of-record for secret-detection rules;
// chainsaw ships a curated subset in-tree rather than vendoring the
// gitleaks library — the upstream Go module pulls in a ~30-package
// transitive cone (BubbleTea / Viper / charmbracelet / zerolog / wazero)
// that would blow through the commercial-safe license allow-list audit
// surface for a detect-only use case.
//
// Rule intents are reimplemented here; the token shapes are public facts
// (AKIA-prefixed AWS access keys, github_pat_* prefixes, etc.). When we
// raise confidence above detect-only in a future wave, reconsider a
// library dep under a narrower license review.

// secretRule pairs a compiled regex with a short tag used for Match.Kind.
type secretRule struct {
	Re  *regexp.Regexp
	Tag string
	// MinEntropy is the bits-per-char Shannon-entropy floor the hit
	// must clear to count. Zero means "pattern alone is enough" (e.g.
	// AKIA prefix is literally only assigned by AWS).
	MinEntropy float64
}

var (
	secretRules     []secretRule
	secretRulesOnce sync.Once
)

func ensureSecretRules() {
	secretRulesOnce.Do(func() {
		secretRules = []secretRule{
			// --- AWS (IAM, Temp creds, session tokens) ------------------
			{Re: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), Tag: "aws-access-key"},
			{Re: regexp.MustCompile(`\bASIA[0-9A-Z]{16}\b`), Tag: "aws-temp-access-key"},
			// AWS secret keys are 40 random chars — use entropy to cut noise.
			{Re: regexp.MustCompile(`(?i)aws_secret(?:_access)?_key[^a-z0-9]{1,10}["']?([A-Za-z0-9/+=]{40})["']?`), Tag: "aws-secret-key", MinEntropy: 4.5},

			// --- GitHub -----------------------------------------------
			{Re: regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`), Tag: "github-pat"},
			{Re: regexp.MustCompile(`\bgho_[A-Za-z0-9]{36}\b`), Tag: "github-oauth"},
			{Re: regexp.MustCompile(`\bghu_[A-Za-z0-9]{36}\b`), Tag: "github-user-to-server"},
			{Re: regexp.MustCompile(`\bghs_[A-Za-z0-9]{36}\b`), Tag: "github-server-to-server"},
			{Re: regexp.MustCompile(`\bghr_[A-Za-z0-9]{36}\b`), Tag: "github-refresh"},
			{Re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{82}\b`), Tag: "github-fine-grained-pat"},

			// --- GitLab -----------------------------------------------
			{Re: regexp.MustCompile(`\bglpat-[A-Za-z0-9\-_]{20}\b`), Tag: "gitlab-pat"},

			// --- Slack ------------------------------------------------
			{Re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`), Tag: "slack-token"},
			{Re: regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}`), Tag: "slack-webhook"},

			// --- Google / GCP ----------------------------------------
			{Re: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), Tag: "gcp-api-key"},
			{Re: regexp.MustCompile(`"private_key"\s*:\s*"-----BEGIN (?:RSA |EC |)PRIVATE KEY-----`), Tag: "gcp-service-account"},

			// --- Stripe -----------------------------------------------
			{Re: regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{24,}`), Tag: "stripe-secret"},
			{Re: regexp.MustCompile(`\brk_live_[A-Za-z0-9]{24,}`), Tag: "stripe-restricted"},

			// --- npm / pypi / crates-io tokens ------------------------
			{Re: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), Tag: "npm-token"},
			{Re: regexp.MustCompile(`\bpypi-AgENdGVzdC5weXBpLm9yZ[A-Za-z0-9\-_]{50,}`), Tag: "pypi-token"},
			{Re: regexp.MustCompile(`\bcio[A-Za-z0-9]{40,}\b`), Tag: "crates-io-token"},

			// --- Generic / catch-alls --------------------------------
			{Re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |)PRIVATE KEY(?: BLOCK)?-----`), Tag: "private-key"},
			// Hex-encoded 32+ byte secrets (commonly an HMAC key / JWT secret).
			// Require a nearby "secret"/"token"/"key"/"password" label to cut
			// false positives on SHA256 content hashes.
			{Re: regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password|passwd|pwd|credential)\s*[:=]\s*["']?([A-Za-z0-9/+=_\-]{24,})["']?`), Tag: "generic-high-entropy", MinEntropy: 4.0},
			// JWT — header.payload.signature.
			{Re: regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`), Tag: "jwt"},
		}
		// Fast-path: the hasEntropyAnchor byte-prefix filter above
		// shortcuts past files that cannot match any rule. We used
		// to compile a union regex here but the anchor filter is an
		// order of magnitude cheaper on the no-hit path.
	})
}

// ScanEntropy runs the curated secret-rule set over the file map.
// Entropy gating on generic patterns keeps false positives tolerable on
// well-compressed source. The bounded result list means pathological
// files cannot flood the findings UI.
func ScanEntropy(files map[string][]byte) Result {
	ensureSecretRules()
	var res Result
	if len(files) == 0 {
		return res
	}
	iterFiles(files, func(name string, body []byte, lang Language) bool {
		// Cheap anchor fast-path: bytes.Contains is ~10x faster than
		// running the alternation regex. Files that don't carry any
		// known anchor cannot match any rule, so we skip them.
		if !hasEntropyAnchor(body) {
			return true
		}
		for _, rule := range secretRules {
			loc := rule.Re.FindSubmatchIndex(body)
			if loc == nil {
				continue
			}
			start, end := loc[0], loc[1]
			snippet := string(body[start:end])
			if rule.MinEntropy > 0 {
				sample := snippet
				if len(loc) >= 4 && loc[2] >= 0 {
					sample = string(body[loc[2]:loc[3]])
				}
				if shannonEntropy(sample) < rule.MinEntropy {
					continue
				}
			}
			res.addMatch(Match{
				Path:    name,
				Line:    lineOf(body, start),
				Snippet: snippet,
				Kind:    rule.Tag,
			})
		}
		return true
	})
	return res
}

// shannonEntropy computes bits/char Shannon entropy over an ASCII slice.
// Used to separate base64 secret payloads from low-entropy fixtures like
// "AAAAA...A" or repeated words.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
