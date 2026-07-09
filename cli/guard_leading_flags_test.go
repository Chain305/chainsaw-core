package cli

import (
	"reflect"
	"testing"
)

// A leading flag — whether one of chainsaw's own globals eaten off the front
// (`chainsaw --json npm install evil`) or a package-manager flag
// (`chainsaw npm -q install evil`) — must not hide the install verb. Before the
// fix, the parsers required args[0] to be the verb, so any leading flag made the
// guard report "not an install" and pass the package through UNSCANNED.
func TestStripLeadingFlagsForParse_recoversInstallVerb(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"no flags", []string{"install", "evil"}, []string{"install", "evil"}},
		{"chainsaw json", []string{"--json", "install", "evil"}, []string{"install", "evil"}},
		{"chainsaw no-color", []string{"--no-color", "install", "evil"}, []string{"install", "evil"}},
		{"tool quiet short", []string{"-q", "install", "evil"}, []string{"install", "evil"}},
		{"tool quiet long", []string{"--quiet", "install", "evil"}, []string{"install", "evil"}},
		{"stacked globals + tool flag", []string{"--json", "--no-color", "-q", "install", "evil"}, []string{"install", "evil"}},
		{"chainsaw value flag separate", []string{"--org", "acme", "install", "evil"}, []string{"install", "evil"}},
		{"chainsaw value flag eq", []string{"--org=acme", "install", "evil"}, []string{"install", "evil"}},
		{"verb already first, trailing flag untouched", []string{"install", "evil", "--json"}, []string{"install", "evil", "--json"}},
	}
	for _, c := range cases {
		if got := stripLeadingFlagsForParse(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: stripLeadingFlagsForParse(%v) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}

// The real package manager keeps its own flags; only chainsaw's leading globals
// are removed so they don't leak to the tool.
func TestStripLeadingChainsawGlobals(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"drop leading json", []string{"--json", "install", "lodash"}, []string{"install", "lodash"}},
		{"keep tool quiet flag", []string{"-q", "install", "lodash"}, []string{"-q", "install", "lodash"}},
		{"drop chainsaw, keep tool", []string{"--json", "-q", "install", "lodash"}, []string{"-q", "install", "lodash"}},
		{"preserve tool trailing json", []string{"install", "lodash", "--json"}, []string{"install", "lodash", "--json"}},
		{"value flag separate", []string{"--org", "acme", "install", "lodash"}, []string{"install", "lodash"}},
		{"value flag eq", []string{"--server=https://x", "install", "lodash"}, []string{"install", "lodash"}},
	}
	for _, c := range cases {
		if got := stripLeadingChainsawGlobals(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: stripLeadingChainsawGlobals(%v) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}

// End-to-end at the parser layer: the install verb is recognized and the
// malicious spec extracted regardless of leading flags.
func TestParsersRecognizeInstallBehindLeadingFlags(t *testing.T) {
	npmVariants := [][]string{
		{"install", "flatmap-stream"},
		{"--json", "install", "flatmap-stream"},
		{"--no-color", "install", "flatmap-stream"},
		{"-q", "install", "flatmap-stream"},
	}
	for _, v := range npmVariants {
		specs, recognized := parseNpmInstall(stripLeadingFlagsForParse(v))
		if !recognized {
			t.Errorf("npm %v: not recognized as install (guard would bypass)", v)
			continue
		}
		if len(specs) != 1 || specs[0].Name != "flatmap-stream" {
			t.Errorf("npm %v: specs = %v, want one flatmap-stream", v, specs)
		}
	}

	pipVariants := [][]string{
		{"install", "reqeusts"},
		{"--quiet", "install", "reqeusts"},
		{"-q", "install", "reqeusts"},
	}
	for _, v := range pipVariants {
		specs, recognized := parsePipInstall(stripLeadingFlagsForParse(v))
		if !recognized || len(specs) != 1 || specs[0].Name != "reqeusts" {
			t.Errorf("pip %v: recognized=%v specs=%v, want one reqeusts", v, recognized, specs)
		}
	}
}
