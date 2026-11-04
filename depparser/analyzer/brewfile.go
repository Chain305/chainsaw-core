package analyzer

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/chain305/chainsaw-core/depparser/parser/homebrew/brewfile"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

// brewfileAnalyzer is not a shim: shim.Parse drops a package with no version
// and no Origin, and every Brewfile formula is exactly that (a Brewfile names
// packages, never versions). Its packages carry Version "" = current recipe.
type brewfileAnalyzer struct{}

func (brewfileAnalyzer) Type() ftypes.LangType { return ftypes.Homebrew }

// Required matches `Brewfile` and `<name>.Brewfile` (brew bundle --file).
func (brewfileAnalyzer) Required(path string) bool {
	base := filepath.Base(path)
	return base == "Brewfile" || (strings.HasSuffix(base, ".Brewfile") && len(base) > len(".Brewfile"))
}

func (brewfileAnalyzer) Parse(_ context.Context, path string) ([]Package, error) {
	f, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	fpkgs, err := brewfile.Parse(f)
	if err != nil {
		return nil, err
	}
	out := make([]Package, 0, len(fpkgs))
	for _, fp := range fpkgs {
		out = append(out, Package{Name: fp.Name, Lang: ftypes.Homebrew, Source: path, Origin: fp.Origin})
	}
	return out, nil
}

func init() { Register(brewfileAnalyzer{}) }
