package iocscan

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Two narrow indicators found by reading the bytes of malicious packages
// that every other detector here allowed (2026-10-04). Each answers with a
// detail string, empty for "no hit", and each skips test, docs and vendored
// paths like the exfil tier does.

// credentialTokenRE matches registry and forge credentials by their
// documented prefixes. userinfoURLRE matches user:password@ in a URL.
var (
	credentialTokenRE = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b|\bglpat-[A-Za-z0-9_-]{20,}\b|\bnpm_[A-Za-z0-9]{36}\b`)
	userinfoURLRE     = regexp.MustCompile(`(?:git\+)?(?:https?|ssh)://[^/\s:@"']+:[^/\s@"']+@`)
)

// dependencySpecFiles are where a dependency can be pinned to a URL.
var dependencySpecFiles = map[string]bool{
	"package.json": true, "package-lock.json": true, "npm-shrinkwrap.json": true,
	"yarn.lock": true, "requirements.txt": true, "setup.py": true, "pyproject.toml": true,
	"pipfile.lock": true, "poetry.lock": true,
}

// WantsDependencySpec selects the files DependencyCredential reads.
func WantsDependencySpec(name string) bool {
	return dependencySpecFiles[strings.ToLower(path.Base(name))]
}

// DependencyCredential returns "file: <redacted>" when a dependency spec
// carries a live credential: a forge or registry token, or user:password in
// a git/http URL. For package.json only the dependency maps are read, so a
// token in a README-like field is not a dependency. The token itself is never
// returned: only its prefix and length.
func DependencyCredential(files map[string][]byte) string {
	for _, name := range sortedNames(files) {
		if !WantsDependencySpec(name) || isNonShippingPath(name) {
			continue
		}
		texts := []string{string(files[name])}
		if strings.EqualFold(path.Base(name), "package.json") {
			texts = packageJSONDependencySpecs(files[name])
		}
		for _, t := range texts {
			if m := credentialTokenRE.FindString(t); m != "" {
				return name + ": " + redact(m)
			}
			if userinfoURLRE.MatchString(t) {
				return name + ": user:password@ in a URL"
			}
		}
	}
	return ""
}

func packageJSONDependencySpecs(b []byte) []string {
	var pj map[string]json.RawMessage
	if json.Unmarshal(b, &pj) != nil {
		return nil
	}
	var out []string
	for _, k := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		var deps map[string]string
		if json.Unmarshal(pj[k], &deps) == nil {
			for _, v := range deps {
				out = append(out, v)
			}
		}
	}
	return out
}

// redact keeps the token's prefix (up to the first '_' or '-') and length.
func redact(tok string) string {
	p := tok
	if i := strings.IndexAny(tok, "_-"); i >= 0 {
		p = tok[:i+1]
	}
	return p + "…(" + strconv.Itoa(len(tok)) + " chars)"
}

// appCredentialRE is a NARROW, reviewed list of credential stores that only
// the owning application has reason to read: AI coding assistants' transcripts
// and auth files, the Lark CLI keychain, the GitHub CLI's token file and git's
// plaintext credential store. Generic paths (.npmrc, .netrc, ~/.ssh, AWS
// credentials) are deliberately absent: SDKs read them and send by design,
// and a vendored copy of requests reads .netrc.
var appCredentialRE = regexp.MustCompile(`\.claude/projects|\.claude/\.credentials\.json|\.codex/auth\.json|lark-cli/[^\s"'\x60]*\.enc|Cursor/User/globalStorage|\.config/gh/hosts\.yml|\.git-credentials`)

// credSendRE is an outbound write: a POST/PUT, a raw request or a socket.
var credSendRE = regexp.MustCompile(`requests\.(?:post|put)\s*\(|httpx\.(?:post|put)|urlopen\s*\(|\bfetch\s*\(|axios\.(?:post|put)|\bhttps?\.request\s*\(|XMLHttpRequest|new WebSocket\s*\(|\.send\s*\(`)

// AppCredentialSend returns "path (file)" when a shipping source file both
// names an application's private credential store and sends.
func AppCredentialSend(files map[string][]byte) string {
	for _, name := range sortedNames(files) {
		if isNonShippingPath(name) {
			continue
		}
		body := capped(files[name])
		if m := appCredentialRE.FindString(body); m != "" && credSendRE.MatchString(body) {
			return m + " (" + name + ")"
		}
	}
	return ""
}

// defenderTamperRE is PowerShell turning a Microsoft Defender protection off
// or carving an exclusion out of it. Get-MpPreference (a read) and any
// Set-MpPreference that does not disable something are not matched.
var defenderTamperRE = regexp.MustCompile(`(?i)\bSet-MpPreference\s+-Disable\w+|\bAdd-MpPreference\s+-Exclusion\w+`)

// smartAppControlWriteRE is a registry WRITE of Smart App Control's state
// value (HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy), which turns SAC
// off: @apexacc/cli (2026-09) set it to 0 before running a downloaded binary.
// The value name is specific to SAC; reading it (Get-ItemProperty) is not
// matched.
var smartAppControlWriteRE = regexp.MustCompile(`(?i)\b(?:Set-ItemProperty|New-ItemProperty|reg(?:\.exe)?\s+add)\b[^\n;|]{0,300}?\bVerifiedAndReputablePolicyState\b`)

// encodedCommandRE is PowerShell's -EncodedCommand (any prefix PowerShell
// accepts: -e, -ec, -enc, ...) and its base64 argument. @apexacc/cli 1.5.122
// shipped the same Defender and SAC commands as 1.5.121, base64-encoded and
// launched elevated, so the plaintext regexes saw nothing.
var encodedCommandRE = regexp.MustCompile(`(?i)(?:^|[^\w-])-e(?:c|n[a-z]*)?['"\x60]?[\s,]+['"\x60]?([A-Za-z0-9+/]{16,}={0,2})`)

// maxEncodedCommand bounds the base64 decoded per match. A real command is a
// few hundred bytes; this keeps a large base64 blob (an inlined wasm or font)
// that happens to follow "-e" from being decoded.
const maxEncodedCommand = 64 << 10

// decodeEncodedCommand decodes an -EncodedCommand argument: base64 of
// UTF-16LE. Returns "" when it is not that.
func decodeEncodedCommand(b64 string) string {
	if len(b64) > maxEncodedCommand {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(b64, "=")); err != nil {
			return ""
		}
	}
	if len(raw) < 2 || len(raw)%2 != 0 {
		return ""
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	return string(utf16.Decode(u))
}

// tamperIn returns the normalised tamper command found in s, or "".
func tamperIn(s string) string {
	if m := defenderTamperRE.FindString(s); m != "" {
		return strings.Join(strings.Fields(m), " ")
	}
	if smartAppControlWriteRE.MatchString(s) {
		return "Smart App Control policy write (VerifiedAndReputablePolicyState)"
	}
	return ""
}

// WantsWindowsScript selects the PowerShell and batch files DefenderTamper
// reads on top of the caller's source set: NuGet runs tools/install.ps1 on
// install, and a .cmd/.bat wrapper calls powershell or reg add the same way.
// Only this indicator reads them; the other detectors keep their file set.
func WantsWindowsScript(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".ps1", ".psm1", ".cmd", ".bat":
		return true
	}
	return false
}

// DefenderTamper returns "command (file)" when a shipping file disables
// Defender, adds an exclusion to it, or turns Smart App Control off — in
// plain text or inside a PowerShell -EncodedCommand.
func DefenderTamper(files map[string][]byte) string {
	for _, name := range sortedNames(files) {
		if isNonShippingPath(name) {
			continue
		}
		body := capped(files[name])
		if m := tamperIn(body); m != "" {
			return m + " (" + name + ")"
		}
		for _, sm := range encodedCommandRE.FindAllStringSubmatch(body, 32) {
			if m := tamperIn(decodeEncodedCommand(sm[1])); m != "" {
				return m + " (" + name + ", -EncodedCommand)"
			}
		}
	}
	return ""
}

func capped(b []byte) string {
	if len(b) > maxFileSize {
		b = b[:maxFileSize]
	}
	return string(b)
}

func sortedNames(files map[string][]byte) []string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
