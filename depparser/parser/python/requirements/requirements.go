// Package requirements parses pip's requirements.txt.
//
// Manifest, not a lock file. Only pinned entries (== or === operator)
// produce a Package — anything else (ranges, tildes, star specifiers) is
// skipped since the vuln-scan pipeline wants an exact version.
//
// Ported from internal/cli/scan.go:parseRequirementsTxt. The behaviour
// differences vs Trivy's pkg/dependency/parser/python/packaging are
// intentional — Trivy additionally parses `-r`/`-c` includes and PEP 440
// pre-release versions; chainsaw keeps a strict "pinned == only" policy so
// a scan result is always a set of fully-resolved packages.
package requirements

import (
	"io"
	"regexp"
	"strings"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

func Parse(r io.Reader) ([]ftypes.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var out []ftypes.Package
	for _, req := range Requirements(string(data)) {
		if name, ver, ok := Pin(req); ok {
			out = append(out, ftypes.Package{Name: name, Version: ver})
		}
	}
	return out, nil
}

// commentRE is pip's COMMENT_RE (pip/_internal/req/req_file.py): a "#" at
// the start of a line or after whitespace. A URL's "#egg=" has none.
var commentRE = regexp.MustCompile(`(^|\s+)#.*$`)

// Requirements returns the requirement part of every logical line of a
// requirements file, following pip's own reader: "\" continuations are
// joined, comments dropped, and per-requirement options (pip-compile's
// `--hash=sha256:…`) cut off at the first token starting with "-" (pip's
// break_args_options). Option-only lines (-r, --index-url, -e) yield nothing.
//
// 2026-10-14: before this, every `pip-compile --generate-hashes` line came
// back as `certifi==2024.2.2 \` and an inline `# via` comment stayed in the
// version.
func Requirements(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(text, "\n") {
		isComment := strings.HasPrefix(strings.TrimSpace(line), "#")
		if strings.HasSuffix(line, `\`) && !isComment {
			cur.WriteString(strings.Trim(line, `\`)) // pip: line.strip("\\"), no separator
			continue
		}
		if isComment {
			line = " " + line // pip: so the comment still matches after a join
		}
		cur.WriteString(line)
		logical := strings.TrimSpace(commentRE.ReplaceAllString(cur.String(), ""))
		cur.Reset()
		var args []string
		for _, tok := range strings.Fields(logical) {
			if strings.HasPrefix(tok, "-") {
				break
			}
			args = append(args, tok)
		}
		if len(args) > 0 {
			out = append(out, strings.Join(args, " "))
		}
	}
	return out
}

var pep508Name = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// Pin returns the name and exact version of a requirement pinned with `==`
// or `===`; ok is false for anything else (ranges, wildcards, URLs). The
// environment marker and extras are dropped and whitespace is allowed
// around the operator: `uvicorn[standard] == 0.29.0 ; python_version<"3.12"`
// is ("uvicorn", "0.29.0").
func Pin(req string) (name, version string, ok bool) {
	req, _, _ = strings.Cut(req, ";")
	req = strings.Join(strings.Fields(req), "")
	if strings.Contains(req, "@") {
		return "", "", false // `name @ url` direct reference
	}
	name, version, found := strings.Cut(req, "==")
	if !found {
		return "", "", false
	}
	version = strings.TrimPrefix(version, "=") // `===` arbitrary equality
	if b := strings.IndexByte(name, '['); b >= 0 && strings.HasSuffix(name, "]") {
		name = name[:b]
	}
	if !pep508Name.MatchString(name) || version == "" || strings.ContainsAny(version, "*,=<>!~") {
		return "", "", false
	}
	return name, version, true
}
