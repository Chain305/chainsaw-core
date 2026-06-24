// Package mix parses mix.lock (Elixir).
//
// Format: a single Elixir map literal `%{ "name": {tuple}, ... }` where
// each tuple's structure is `:hex, :pkg_atom, "version", "hash", [:mix],
// [deps], "hexpm", ...`. The third element is the resolved version.
//
// We parse line-by-line with a regex rather than pulling in an Elixir
// term parser; this matches how Trivy handles it too.
//
// Trivy reference: pkg/dependency/parser/hex/mix/parse.go.
package mix

import (
	"bufio"
	"io"
	"regexp"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

// Line example:
//
//	"plug": {:hex, :plug, "1.14.2", "<hash>", [:mix], [...], "hexpm", "<...>"},
//
// We capture (name)=group 1 and (version)=group 2. Non-hex sources
// (git/path) have a different tuple shape starting with :git or :path;
// they don't carry a pinned version and are skipped.
var hexLineRe = regexp.MustCompile(`"([^"]+)":\s*\{:hex,\s*:[^,]+,\s*"([^"]+)"`)

func Parse(r io.Reader) ([]ftypes.Package, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var out []ftypes.Package
	for sc.Scan() {
		m := hexLineRe.FindStringSubmatch(sc.Text())
		if len(m) != 3 {
			continue
		}
		name, ver := m[1], m[2]
		if name == "" || ver == "" {
			continue
		}
		out = append(out, ftypes.Package{Name: name, Version: ver})
	}
	return out, sc.Err()
}
