package cli

import "testing"

func TestFindLocalBlock(t *testing.T) {
	blocks := []guardBlockRecord{
		{Ecosystem: "npm", Name: "loadsh", Reason: "typosquat of lodash", AtUnix: 100},
		{Ecosystem: "pip", Name: "reqeusts", Reason: "typosquat of requests", AtUnix: 200},
		{Ecosystem: "npm", Name: "flatmap-stream", Reason: "known-malicious", AtUnix: 300},
		{Ecosystem: "npm", Name: "flatmap-stream", Version: "0.1.1", Reason: "known-malicious", AtUnix: 400},
	}

	cases := []struct {
		name        string
		eco, pkg    string
		ver         string
		wantReason  string // "" => expect nil
		wantVersion string
	}{
		{"newest npm match wins", "npm", "flatmap-stream", "", "known-malicious", "0.1.1"},
		{"case-insensitive ecosystem+name", "NPM", "FlatMap-Stream", "", "known-malicious", "0.1.1"},
		{"pinned version matches pinned record", "npm", "flatmap-stream", "0.1.1", "known-malicious", "0.1.1"},
		{"pinned version skips mismatched, falls to unpinned", "npm", "flatmap-stream", "9.9.9", "known-malicious", ""},
		{"pip match", "pip", "reqeusts", "", "typosquat of requests", ""},
		{"no match", "npm", "left-pad", "", "", ""},
		{"wrong ecosystem", "cargo", "loadsh", "", "", ""},
	}
	for _, c := range cases {
		got := findLocalBlock(blocks, c.eco, c.pkg, c.ver)
		if c.wantReason == "" {
			if got != nil {
				t.Errorf("%s: expected nil, got %+v", c.name, got)
			}
			continue
		}
		if got == nil {
			t.Errorf("%s: expected a match, got nil", c.name)
			continue
		}
		if got.Reason != c.wantReason || got.Version != c.wantVersion {
			t.Errorf("%s: got {reason=%q version=%q}, want {reason=%q version=%q}",
				c.name, got.Reason, got.Version, c.wantReason, c.wantVersion)
		}
	}
}
