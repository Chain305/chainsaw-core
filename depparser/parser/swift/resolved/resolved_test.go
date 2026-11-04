package resolved

import (
	"strings"
	"testing"
)

func TestParseRekeysGitHubPinsToOwnerRepo(t *testing.T) {
	const v2 = `{"pins":[
	 {"identity":"alamofire","kind":"remoteSourceControl","location":"https://github.com/Alamofire/Alamofire.git","state":{"version":"5.8.0"}},
	 {"identity":"swift-log","kind":"remoteSourceControl","location":"git@github.com:apple/swift-log.git","state":{"version":"1.5.3"}},
	 {"identity":"internal","kind":"remoteSourceControl","location":"https://git.corp.example/team/internal.git","state":{"version":"2.0.0"}},
	 {"identity":"local","kind":"localSourceControl","location":"/Users/me/src/local","state":{"version":"0.1.0"}},
	 {"identity":"mona.linkedlist","kind":"registry","location":"","state":{"version":"1.1.0"}},
	 {"identity":"branchy","kind":"remoteSourceControl","location":"https://github.com/x/branchy","state":{"revision":"abc"}}
	],"version":2}`
	pkgs, err := Parse(strings.NewReader(v2))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name+"@"+p.Version] = p.Origin
	}
	want := map[string]string{
		"alamofire.alamofire@5.8.0": "",
		"apple.swift-log@1.5.3":     "",
		"internal@2.0.0":            "https://git.corp.example/team/internal.git",
		"local@0.1.0":               "/Users/me/src/local",
		"mona.linkedlist@1.1.0":     "",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, o := range want {
		if g, ok := got[k]; !ok || g != o {
			t.Errorf("%s: got origin %q (present %v), want %q", k, g, ok, o)
		}
	}
}

func TestParseV1RepositoryURL(t *testing.T) {
	const v1 = `{"object":{"pins":[{"package":"SnapKit","repositoryURL":"https://github.com/SnapKit/SnapKit","state":{"version":"5.6.0"}}]},"version":1}`
	pkgs, err := Parse(strings.NewReader(v1))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "snapkit.snapkit" || pkgs[0].Origin != "" {
		t.Fatalf("got %+v", pkgs)
	}
}

func TestGitHubIdentityRejectsNonRepoShapes(t *testing.T) {
	for _, loc := range []string{
		"https://github.com/apple",
		"https://github.com/apple/swift-nio/tree/main",
		"https://gitlab.com/apple/swift-nio.git",
		"https://user:tok@github.com.evil.example/apple/swift-nio",
		"../relative/path",
		"",
	} {
		if id, ok := GitHubIdentity(loc); ok {
			t.Errorf("%q: got %q, want rejection", loc, id)
		}
	}
	if id, ok := GitHubIdentity("https://token@github.com/Apple/Swift-NIO.git/"); !ok || id != "apple.swift-nio" {
		t.Errorf("got %q %v", id, ok)
	}
}
