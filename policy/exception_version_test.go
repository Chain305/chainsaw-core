package policy

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// H5: an "exact-version" exception was read as a semver constraint, so a
// reviewer approving Django@4.2 approved every later 4.2.x.
func TestException_PartialVersionDoesNotCoverItsLine(t *testing.T) {
	isVuln := true
	blockAll := Policy{ID: "blk", Name: "block all", Mode: ModeBlock, Status: StatusEnabled, Precedence: 10,
		Identifier: Identifier{TargetPackageName: "*"}}
	exc := func(format, name, version string) []Policy {
		return []Policy{{ID: "exc-" + name, Mode: ModeAllow, Status: StatusEnabled, Kind: KindException, Precedence: -1,
			Identifier: Identifier{TargetPackageRepo: "r", TargetPackageName: name, TargetPackageVersion: version}}, blockAll}
	}
	cases := []struct {
		format, name, excepted, requested string
		allowed                           bool
	}{
		{"pip", "Django", "4.2", "4.2.7", false},
		{"pip", "Django", "4.2", "4.2", true},
		{"pip", "Django", "4.2", "4.2.0", true}, // PEP 440: same release
		{"pip", "Django", "1.0RC1", "1.0rc1", true},
		{"pip", "Django", "2024.1", "2024.1.1", false},
		{"npm", "lodash", "4.17", "4.17.22", false},
		{"npm", "lodash", "1", "1.5.0", false},
		{"npm", "lodash", "1.x", "1.2.0", false},
		{"npm", "lodash", "1.2.X", "1.2.9", false},
		{"npm", "lodash", "4.17.21", "4.17.21", true},
		{"npm", "lodash", "4.17.21", "4.17.22", false},
		{"go", "golang.org/x/net", "0.17.0", "v0.17.0", true},
		{"nuget", "Newtonsoft.Json", "13.0.1-Beta", "13.0.1-beta", true},
		{"docker", "library/nginx", "v1", "1", false},
	}
	e := NewEvaluator(nil)
	for _, c := range cases {
		ctx := EvaluationContext{Repository: "r", RepositoryFormat: c.format, PackageName: c.name, PackageVersion: c.requested}
		got := e.EvaluateWithPolicies(ctx, exc(c.format, c.name, c.excepted), 0).Action != ModeBlock
		if got != c.allowed {
			t.Errorf("%s %s exception %q, request %q: allowed=%v, want %v", c.format, c.name, c.excepted, c.requested, got, c.allowed)
		}
	}

	// The legacy exception shape (allow + isVulnerable) is an exception too.
	legacy := []Policy{{ID: "legacy", Mode: ModeAllow, Status: StatusEnabled, Precedence: -1,
		Identifier: Identifier{TargetPackageName: "Django", TargetPackageVersion: "4.2"},
		Conditions: Conditions{IsVulnerable: &isVuln}}, blockAll}
	ctx := EvaluationContext{Repository: "r", RepositoryFormat: "pip", PackageName: "Django", PackageVersion: "4.2.7", IsVulnerable: true}
	if e.EvaluateWithPolicies(ctx, legacy, 0).Action != ModeBlock {
		t.Error("legacy allow+isVulnerable exception for 4.2 covered 4.2.7")
	}
}

// Policies keep constraint semantics: a block rule on "4.2" still blocks 4.2.7.
func TestPolicy_VersionLegStaysAConstraint(t *testing.T) {
	block := []Policy{{ID: "b", Mode: ModeBlock, Status: StatusEnabled,
		Identifier: Identifier{TargetPackageName: "lodash", TargetPackageVersion: "<4.17.21"}}}
	ctx := EvaluationContext{RepositoryFormat: "npm", PackageName: "lodash", PackageVersion: "4.17.20"}
	if NewEvaluator(nil).EvaluateWithPolicies(ctx, block, 0).Action != ModeBlock {
		t.Fatal("block rule <4.17.21 stopped matching 4.17.20")
	}
	if !MatchesPolicyIdentifier(ctx, Policy{Mode: ModeBlock, Identifier: Identifier{TargetPackageName: "lodash", TargetPackageVersion: "4.17"}}) {
		t.Fatal("block rule version 4.17 stopped matching 4.17.20")
	}
}

// A stored partial-version exception that narrows is logged once, not silently.
func TestException_NarrowedIsLoggedOnce(t *testing.T) {
	var buf bytes.Buffer
	e := NewEvaluator(nil)
	e.logger = slog.New(slog.NewTextHandler(&buf, nil))
	pols := []Policy{{ID: "exc-1", Mode: ModeAllow, Status: StatusEnabled, Kind: KindException,
		Identifier: Identifier{TargetPackageName: "lodash", TargetPackageVersion: "4.17"}}}
	for _, v := range []string{"4.17.20", "4.17.21"} {
		e.EvaluateWithPolicies(EvaluationContext{RepositoryFormat: "npm", PackageName: "lodash", PackageVersion: v}, pols, 0)
	}
	if n := strings.Count(buf.String(), "exception.version_narrowed"); n != 1 {
		t.Fatalf("narrowed warnings = %d, want 1:\n%s", n, buf.String())
	}
}

func TestPartialOrWildcardVersion(t *testing.T) {
	refuse := [][2]string{{"npm", "4.2"}, {"npm", "1"}, {"go", "v1.2"}, {"cargo", "1.0"}, {"nuget", "13.0"},
		{"pip", "1.x"}, {"pip", "1.2.X"}, {"maven", "1.*"}, {"npm", "^1.2.3"}, {"npm", ">=1.0.0"}, {"pip", ""}}
	for _, c := range refuse {
		if PartialOrWildcardVersion(c[0], c[1]) == "" {
			t.Errorf("%s %q accepted, want refused", c[0], c[1])
		}
	}
	accept := [][2]string{{"pip", "4.2"}, {"pip", "2024.1"}, {"maven", "1.0"}, {"npm", "1.2.3-rc.1"}, {"go", "v0.17.0"},
		{"nuget", "1.2.3.4"}, {"npm", "1.2.3+build.5"}}
	for _, c := range accept {
		if why := PartialOrWildcardVersion(c[0], c[1]); why != "" {
			t.Errorf("%s %q refused: %s", c[0], c[1], why)
		}
	}
}
