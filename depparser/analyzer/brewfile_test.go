package analyzer

import (
	"context"
	"testing"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

func TestBrewfileAnalyzer(t *testing.T) {
	a := brewfileAnalyzer{}
	for path, want := range map[string]bool{
		"/x/Brewfile": true, "/x/work.Brewfile": true, "/x/.Brewfile": false,
		"/x/Brewfile.lock.json": false, "/x/Gemfile": false,
	} {
		if got := a.Required(path); got != want {
			t.Errorf("Required(%q) = %v, want %v", path, got, want)
		}
	}
	pkgs, err := ParseBytes(context.Background(), "Brewfile", []byte("tap \"a/b\"\nbrew \"jq\"\ncask \"firefox\"\nbrew \"a/b/c\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 || pkgs[0].Name != "jq" || pkgs[0].Version != "" || pkgs[0].Lang != ftypes.Homebrew ||
		pkgs[1].Name != "a/b/c" || pkgs[1].Origin == "" {
		t.Fatalf("got %+v", pkgs)
	}
}
