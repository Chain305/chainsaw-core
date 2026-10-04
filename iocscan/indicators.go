package iocscan

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
