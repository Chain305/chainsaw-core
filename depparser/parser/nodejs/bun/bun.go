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
	"encoding/json"
	"io"
	"strings"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type lockfile struct {
	LockfileVersion int              `json:"lockfileVersion"`
	Packages        map[string][]any `json:"packages"`
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var lf lockfile
	if err := json.Unmarshal(stripJSONC(raw), &lf); err != nil {
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
		if name == "" || ver == "" || localProtocol(ver) {
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

// localProtocol reports a version that points into the repository itself —
// a workspace member or a local path — rather than at a registry. Those are
// first-party code with no registry coordinate to score; the npm parser drops
// the same entries (`link: true`). git/github/tarball sources are NOT local:
// they are third-party code and stay in, to be reported as unknown rather
// than silently omitted.
func localProtocol(ver string) bool {
	for _, p := range []string{"workspace:", "link:", "file:", "portal:"} {
		if strings.HasPrefix(ver, p) {
			return true
		}
	}
	return false
}

// splitAtLastAt: "@scope/foo@1.2.3" → ("@scope/foo", "1.2.3").
func splitAtLastAt(s string) (string, string) {
	idx := strings.LastIndex(s, "@")
	if idx <= 0 {
		return "", ""
	}
	return s[:idx], s[idx+1:]
}

// stripJSONC drops `//` line comments and trailing commas so stdlib json
// accepts a bun.lock — but only OUTSIDE string literals. Integrity hashes are
// base64 and routinely contain "//" (feldera/feldera's bun.lock has 14); the
// previous line-based strip cut those strings in half and the whole lockfile
// failed with "invalid character '\n' in string literal".
func stripJSONC(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inString, escaped := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			if i < len(b) {
				out = append(out, '\n')
			}
			continue
		case c == ',':
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}
