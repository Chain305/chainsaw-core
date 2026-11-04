package brewfile

import (
	"reflect"
	"strings"
	"testing"
)

const sample = `# dev box
tap "homebrew/bundle"
tap "acme/tools", "https://user:tok@git.acme.example/acme/homebrew-tools.git"
tap 'other/thing'
brew "jq"
brew 'GIT'
brew "homebrew/core/wget"
brew "acme/tools/deployer", args: ["HEAD"]
brew "other/thing/x" if OS.mac?
brew("ripgrep")
cask "firefox"
cask "homebrew/cask/iterm2", greedy: true
mas "Xcode", id: 497799835
vscode "golang.go"
whalebrew "whalebrew/wget"
cask_args appdir: "~/Applications"
  brew "jq"   # duplicate
#brew "commented"
`

func TestParseEntries(t *testing.T) {
	got, err := ParseEntries(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, e := range got {
		kinds = append(kinds, e.Kind+":"+e.Name)
	}
	want := []string{
		"tap:homebrew/bundle", "tap:acme/tools", "tap:other/thing",
		"brew:jq", "brew:git", "brew:wget", "brew:acme/tools/deployer", "brew:other/thing/x", "brew:ripgrep",
		"cask:firefox", "cask:iterm2", "brew:jq",
	}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("entries\n got %v\nwant %v", kinds, want)
	}
	if got[1].URL != "https://git.acme.example/acme/homebrew-tools.git" {
		t.Errorf("tap URL not sanitised: %q", got[1].URL)
	}
}

func TestParse(t *testing.T) {
	pkgs, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		if p.Version != "" {
			t.Errorf("%s: version %q, want empty (current recipe)", p.Name, p.Version)
		}
		got[p.Name] = p.Origin
	}
	want := map[string]string{
		"jq": "", "git": "", "wget": "", "ripgrep": "",
		"acme/tools/deployer": "https://git.acme.example/acme/homebrew-tools.git",
		"other/thing/x":       "git+https://github.com/other/homebrew-thing",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packages\n got %v\nwant %v", got, want)
	}
}

func TestParseEmpty(t *testing.T) {
	pkgs, err := Parse(strings.NewReader("# nothing\n\n"))
	if err != nil || len(pkgs) != 0 {
		t.Fatalf("got %v, %v", pkgs, err)
	}
}
