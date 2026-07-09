// Package bun parses bun.lock (text format).
//
// Format: a JSON-ish trailing-comma-tolerant syntax Bun calls "jsonc".
// Top-level has:
//
//	{
//	  "lockfileVersion": 1,
//	  "workspaces": { ... },
//	  "packages": {
//	    "foo": ["foo@1.2.3", "...integrity..."],
//	    "@scope/foo": ["@scope/foo@1.2.3", "...integrity..."],
//	  }
//	}
//
// Each packages-map entry's first array element is
// "{name}@{resolved-version}", which is what we extract.
//
// We deliberately do a lenient parse: strip `//` line comments and
// trailing commas, then hand to encoding/json. This matches Bun's actual
// tolerance in practice; Bun's binary v0 lockfile is a separate format
// (bun.lockb) and is not a text artifact so we don't attempt to parse it.
//
// Trivy reference: pkg/dependency/parser/nodejs/bun/parse.go.
package bun

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type lockfile struct {
	LockfileVersion int              `json:"lockfileVersion"`
	Packages        map[string][]any `json:"packages"`
}

var trailingCommaRe = regexp.MustCompile(`,(\s*[}\]])`)

func Parse(r io.Reader) ([]ftypes.Package, error) {
	// Drop // line comments and trailing commas so stdlib json accepts it.
	buf := &bytes.Buffer{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	cleaned := trailingCommaRe.ReplaceAllString(buf.String(), "$1")

	var lf lockfile
	if err := json.Unmarshal([]byte(cleaned), &lf); err != nil {
		return nil, err
	}

	var out []ftypes.Package
	seen := map[string]bool{}
	for _, arr := range lf.Packages {
		if len(arr) == 0 {
			continue
		}
		spec, ok := arr[0].(string)
		if !ok {
			continue
		}
		name, ver := splitAtLastAt(spec)
		if name == "" || ver == "" {
			continue
		}
		k := name + "@" + ver
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, ftypes.Package{Name: name, Version: ver})
	}
	return out, nil
}

// splitAtLastAt: "@scope/foo@1.2.3" → ("@scope/foo", "1.2.3").
func splitAtLastAt(s string) (string, string) {
	idx := strings.LastIndex(s, "@")
	if idx <= 0 {
		return "", ""
	}
	return s[:idx], s[idx+1:]
}
