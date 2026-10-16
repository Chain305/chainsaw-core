// Package requirements parses pip's requirements.txt.
//
// Manifest, not a lock file. Only pinned entries (== or === operator)
// produce a registry Package — anything else (ranges, tildes, star
// specifiers) is skipped since the vuln-scan pipeline wants an exact version.
// A requirement on a SOURCE instead of the index (`name @ git+…`, a bare VCS
// or archive URL, `-e <path or VCS URL>`) is returned with its Origin and
// whatever version the source names (an archive file name), often none.
//
// Ported from internal/cli/scan.go:parseRequirementsTxt. The behaviour
// differences vs Trivy's pkg/dependency/parser/python/packaging are
// intentional — Trivy additionally parses `-r`/`-c` includes and PEP 440
// pre-release versions; chainsaw keeps a strict "pinned == only" policy so
// a scan result is always a set of fully-resolved packages. Included files
// are not read: the server sees one uploaded file.
package requirements

import (
	"io"
	"regexp"
	"strings"

	"github.com/chain305/chainsaw-core/depparser/origin"
	"github.com/chain305/chainsaw-core/depparser/parser/python"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

func Parse(r io.Reader) ([]ftypes.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return Packages(string(data)), nil
}

// Packages returns every package a requirements file installs that can be
// named: pinned index requirements, and source requirements with their
// Origin. File-wide options decide where the index requirements come from,
// wherever in the file they appear (pip applies them to the whole run):
//
//   - `-i` / `--index-url` (`--pypi-url`) on a host other than PyPI gives
//     every index requirement the Origin "registry+<url>": a mirror or a
//     private index, decided by content hash on the server.
//   - `--extra-index-url` does NOT: pip still consults the primary index,
//     and marking everything would call PyPI's packages unassessable.
//   - `--no-index` with `-f` / `--find-links`: the packages come from the
//     first find-links location, nothing from an index.
//
// `--hash` options become the package's Hash (origin.JoinHashes); one pip
// accepts but we cannot compare (md5:…) stays in it as
// origin.UnreadableHash (python.FileHash).
func Packages(text string) []ftypes.Package {
	pkgs, fromIndex := scan(text)
	indexOrigin := IndexSource(text)
	for i := range pkgs {
		if fromIndex[i] {
			pkgs[i].Origin = indexOrigin
		}
	}
	return pkgs
}

// IndexSource is the Origin every index requirement of the file takes (see
// Packages): "" for PyPI.
func IndexSource(text string) string {
	var index, findLinks string
	var noIndex bool
	for _, line := range logicalLines(text) {
		for _, o := range options(lineOptions(strings.Fields(line))) {
			switch o.name {
			case "--index-url":
				index = o.value
			case "--no-index":
				noIndex = true
			case "--find-links":
				if findLinks == "" {
					findLinks = o.value
				}
			}
		}
	}
	if noIndex && findLinks != "" {
		if o := python.FileOrigin(findLinks); o != "" {
			return o
		}
		return origin.Sanitize(findLinks) // a page on PyPI's host: still not an index install
	}
	return python.IndexOrigin(index)
}

// lineOptions is the option part of a logical line's tokens: everything from
// the first token starting with "-" (pip's break_args_options).
func lineOptions(toks []string) []string {
	for i, tok := range toks {
		if strings.HasPrefix(tok, "-") {
			return toks[i:]
		}
	}
	return nil
}

// scan returns every nameable package of the file, in order; fromIndex[i]
// says pkgs[i] is resolved from the file's index.
func scan(text string) (pkgs []ftypes.Package, fromIndex []bool) {
	for _, line := range logicalLines(text) {
		toks := strings.Fields(line)
		opts := lineOptions(toks)
		req := toks[:len(toks)-len(opts)]
		var hashes []string
		for _, o := range options(opts) {
			switch o.name {
			case "--hash":
				hashes = append(hashes, python.FileHash(o.value))
			case "--editable":
				if p, ok := sourcePackage("", o.value); ok {
					pkgs, fromIndex = append(pkgs, p), append(fromIndex, false)
				}
			}
		}
		if len(req) == 0 {
			continue
		}
		p, isIndex, ok := requirement(strings.Join(req, " "))
		if !ok {
			continue
		}
		p.Hash = origin.JoinHashes(hashes...)
		pkgs, fromIndex = append(pkgs, p), append(fromIndex, isIndex)
	}
	return pkgs, fromIndex
}

// requirement parses one requirement (options already cut off). isIndex:
// it is resolved from the file's index; a source requirement carries its
// own Origin instead.
func requirement(req string) (p ftypes.Package, isIndex, ok bool) {
	if name, src, ok := directReference(req); ok {
		p, ok = sourcePackage(name, src)
		return p, false, ok
	}
	if tok, _, _ := strings.Cut(strings.TrimSpace(strings.SplitN(req, ";", 2)[0]), " "); isSource(tok) {
		p, ok = sourcePackage("", tok)
		return p, false, ok
	}
	name, ver, ok := Pin(req)
	return ftypes.Package{Name: name, Version: ver}, true, ok
}

// pipReqName is a PEP 508 name with optional extras, the left side of a
// direct reference.
var pipReqName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\s*(\[[^\]]*\])?$`)

// directReference splits a PEP 508 direct reference, `name[extras] @ url ;
// marker`, into the name and the URL.
func directReference(req string) (name, src string, ok bool) {
	req, _, _ = strings.Cut(req, ";")
	at := strings.Index(req, "@")
	if at <= 0 || !pipReqName.MatchString(strings.TrimSpace(req[:at])) {
		return "", "", false
	}
	name = strings.TrimSpace(req[:at])
	if b := strings.Index(name, "["); b >= 0 {
		name = strings.TrimSpace(name[:b])
	}
	src = strings.TrimSpace(req[at+1:])
	if i := strings.IndexAny(src, " \t"); i >= 0 {
		src = src[:i]
	}
	return name, src, src != ""
}

// isSource reports whether a requirement token is a URL, VCS source, path
// or archive rather than a project name.
func isSource(tok string) bool {
	if strings.Contains(tok, "://") || strings.ContainsAny(tok, `/\`) ||
		strings.HasPrefix(tok, ".") || strings.HasPrefix(tok, "~") {
		return true
	}
	n, _ := python.DistFilename(tok)
	return n != ""
}

// sourcePackage is a requirement on a source. The name is the requirement's
// own, else `#egg=`, else the archive file name's; a version only ever comes
// from an archive file name of the same project. A file on PyPI's own hosts
// is the registry package (no Origin) only when it is that project's file
// of that version (python.ProjectFileOrigin). A source
// that names no project (`-e .`, the project itself) is skipped.
func sourcePackage(name, src string) (ftypes.Package, bool) {
	src = strings.TrimSpace(src)
	if i := strings.Index(src, "#"); i >= 0 {
		for _, kv := range strings.Split(src[i+1:], "&") {
			if egg, ok := strings.CutPrefix(kv, "egg="); ok && name == "" {
				if j := strings.IndexAny(egg, "<>=!~["); j >= 0 {
					egg = egg[:j]
				}
				name = strings.TrimSpace(egg)
			}
		}
		if strings.Contains(src[i:], "egg=") || strings.Contains(src[i:], "subdirectory=") {
			src = src[:i] // pip metadata, not a VCS revision
		}
	}
	var version string
	if fn, fv := python.DistFilename(src); fn != "" {
		if name == "" {
			name = fn
		}
		if python.SameProject(name, fn) {
			version = fv
		}
	}
	if name == "" {
		return ftypes.Package{}, false
	}
	return ftypes.Package{Name: name, Version: version, Origin: python.ProjectFileOrigin(name, version, src)}, true
}

// option is one parsed option of a requirements line.
type option struct{ name, value string }

// reqFileOptions is the long options pip's requirements-file parser knows
// (pip/_internal/req/req_file.py), for resolving abbreviations the way
// optparse does: `--ind URL` is --index-url. valueOptions take a value.
var (
	reqFileOptions = strings.Fields("--all-releases --config-settings --constraint --editable " +
		"--extra-index-url --find-links --hash --index-url --no-binary --no-index --only-binary " +
		"--only-final --pre --prefer-binary --pypi-url --require-hashes --requirement --trusted-host " +
		"--use-feature --global-option")
	valueOptions = map[string]bool{"--all-releases": true, "--config-settings": true, "--constraint": true,
		"--editable": true, "--extra-index-url": true, "--find-links": true, "--hash": true, "--index-url": true,
		"--no-binary": true, "--only-binary": true, "--only-final": true, "--pypi-url": true,
		"--requirement": true, "--trusted-host": true, "--use-feature": true, "--global-option": true}
	shortOptions = map[string]string{"-i": "--index-url", "-f": "--find-links", "-e": "--editable",
		"-r": "--requirement", "-c": "--constraint", "-C": "--config-settings"}
)

// canonicalOption expands a unique prefix of a long option; anything else is
// returned unchanged.
func canonicalOption(name string) string {
	match := ""
	for _, l := range reqFileOptions {
		if l == name {
			return name
		}
		if strings.HasPrefix(l, name) {
			if match != "" {
				return name
			}
			match = l
		}
	}
	if match == "" {
		return name
	}
	return match
}

// options parses option tokens (`--opt=v`, `--opt v`, `-iv`, `-i v`).
// --pypi-url is folded onto --index-url, which it is an alias of.
func options(toks []string) []option {
	var out []option
	for i := 0; i < len(toks); i++ {
		tok := toks[i]
		var name, value string
		hasValue := false
		switch {
		case strings.HasPrefix(tok, "--"):
			name, value, hasValue = strings.Cut(tok, "=")
			name = canonicalOption(name)
		case len(tok) >= 2 && tok[0] == '-':
			long, known := shortOptions[tok[:2]]
			if !known {
				continue
			}
			name = long
			if len(tok) > 2 {
				value, hasValue = strings.TrimPrefix(tok[2:], "="), true
			}
		default:
			continue
		}
		if name == "--pypi-url" {
			name = "--index-url"
		}
		if !hasValue && valueOptions[name] && i+1 < len(toks) {
			i++
			value = toks[i]
		}
		out = append(out, option{name, value})
	}
	return out
}

// commentRE is pip's COMMENT_RE (pip/_internal/req/req_file.py): a "#" at
// the start of a line or after whitespace. A URL's "#egg=" has none.
var commentRE = regexp.MustCompile(`(^|\s+)#.*$`)

// logicalLines follows pip's own reader: "\" continuations are joined and
// comments dropped. Blank lines are skipped.
func logicalLines(text string) []string {
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
		if logical := strings.TrimSpace(commentRE.ReplaceAllString(cur.String(), "")); logical != "" {
			out = append(out, logical)
		}
		cur.Reset()
	}
	return out
}

// Requirements returns the requirement part of every logical line of a
// requirements file: per-requirement options (pip-compile's `--hash=sha256:…`)
// cut off at the first token starting with "-" (pip's break_args_options).
// Option-only lines (-r, --index-url, -e) yield nothing.
//
// 2026-10-14: before this, every `pip-compile --generate-hashes` line came
// back as `certifi==2024.2.2 \` and an inline `# via` comment stayed in the
// version.
func Requirements(text string) []string {
	var out []string
	for _, logical := range logicalLines(text) {
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
