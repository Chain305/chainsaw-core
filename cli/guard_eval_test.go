package cli

import (
	"context"
	"testing"

	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/typosquat"
)

func TestParseNpmSpec(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantVer  string
	}{
		{"lodash", "lodash", ""},
		{"lodash@4.17.21", "lodash", "4.17.21"},
		{"@babel/core@7.24.0", "@babel/core", "7.24.0"},
		{"@babel/core", "@babel/core", ""},
	}
	for _, c := range cases {
		got := parseNpmSpec(c.in)
		if got.Name != c.wantName || got.Version != c.wantVer {
			t.Errorf("parseNpmSpec(%q) = {%q,%q}, want {%q,%q}", c.in, got.Name, got.Version, c.wantName, c.wantVer)
		}
		if got.Ecosystem != "npm" {
			t.Errorf("parseNpmSpec(%q) ecosystem = %q, want npm", c.in, got.Ecosystem)
		}
	}
}

func TestParseNpmInstall(t *testing.T) {
	if specs, ok := parseNpmInstall([]string{"run", "build"}); ok || specs != nil {
		t.Errorf("`npm run build` should not be recognized as install; got ok=%v specs=%v", ok, specs)
	}
	specs, ok := parseNpmInstall([]string{"i", "-D", "react@18", "lodash"})
	if !ok {
		t.Fatal("`npm i ...` should be recognized as install")
	}
	if len(specs) != 2 {
		t.Fatalf("want 2 specs (flag skipped), got %d: %v", len(specs), specs)
	}
	if specs[0].Name != "react" || specs[0].Version != "18" || specs[1].Name != "lodash" {
		t.Errorf("unexpected specs: %v", specs)
	}
	// install from lockfile (no named packages) is recognized but yields no specs.
	if specs, ok := parseNpmInstall([]string{"install"}); !ok || len(specs) != 0 {
		t.Errorf("`npm install` (lockfile) want recognized+empty, got ok=%v specs=%v", ok, specs)
	}
}

func TestParsePipInstall(t *testing.T) {
	if _, ok := parsePipInstall([]string{"freeze"}); ok {
		t.Error("`pip freeze` should not be recognized as install")
	}
	specs, ok := parsePipInstall([]string{"install", "-r", "requirements.txt", "requests==2.31.0", "flask[async]>=2"})
	if !ok {
		t.Fatal("`pip install ...` should be recognized")
	}
	// -r + its value skipped; two real specs remain.
	if len(specs) != 2 {
		t.Fatalf("want 2 specs (-r value skipped), got %d: %v", len(specs), specs)
	}
	if specs[0].Name != "requests" || specs[0].Version != "2.31.0" {
		t.Errorf("requests==2.31.0 parsed wrong: %+v", specs[0])
	}
	if specs[1].Name != "flask" || specs[1].Version != "" {
		t.Errorf("flask[async]>=2 should drop extras + leave version empty: %+v", specs[1])
	}
}

func TestParseGoGet(t *testing.T) {
	if _, ok := parseGoGet([]string{"build", "./..."}); ok {
		t.Error("`go build` should not be recognized as get")
	}
	specs, ok := parseGoGet([]string{"get", "-u", "github.com/x/y@v1.2.3"})
	if !ok || len(specs) != 1 {
		t.Fatalf("`go get ...` want recognized+1 spec, got ok=%v specs=%v", ok, specs)
	}
	if specs[0].Name != "github.com/x/y" || specs[0].Version != "v1.2.3" || specs[0].Ecosystem != "go" {
		t.Errorf("unexpected go spec: %v", specs[0])
	}
}

// The offline corpus must load with no network so the wrapper works on the
// install hot path. npm uses the static seed; go uses the embedded seed.
func TestLocalGuardOfflineCorpus(t *testing.T) {
	g := newLocalGuard()
	if d := g.detector("npm"); d == nil {
		t.Error("npm typosquat corpus failed to load offline (detector nil)")
	}
	if d := g.detector("go"); d == nil {
		t.Error("go typosquat corpus failed to load offline (detector nil)")
	}
}

// The offline known-malicious floor must block the famous attacks at the exact
// compromised versions, and must NOT block clean versions of the same package.
func TestKnownMaliciousFloor(t *testing.T) {
	ctx := context.Background()
	g := newLocalGuard()
	cases := []struct {
		spec      packageSpec
		wantBlock bool
	}{
		{packageSpec{Ecosystem: "npm", Name: "event-stream", Version: "3.3.6"}, true},
		{packageSpec{Ecosystem: "npm", Name: "event-stream", Version: "4.0.0"}, false}, // clean version
		{packageSpec{Ecosystem: "npm", Name: "ua-parser-js", Version: "0.7.29"}, true},
		{packageSpec{Ecosystem: "npm", Name: "flatmap-stream", Version: ""}, true}, // all-versions malware
		{packageSpec{Ecosystem: "pip", Name: "colourama", Version: ""}, true},      // all-versions malware
		{packageSpec{Ecosystem: "pip", Name: "python3-dateutil", Version: ""}, true},
	}
	for _, c := range cases {
		v := g.evaluate(ctx, c.spec)
		gotMalBlock := v.Block && v.Severity == "malicious"
		if c.wantBlock && !gotMalBlock {
			t.Errorf("%s: want known-malicious BLOCK, got %+v", c.spec, v)
		}
		if !c.wantBlock && gotMalBlock {
			t.Errorf("%s: false known-malicious block: %+v", c.spec, v)
		}
	}
}

// evaluate() must mirror the detector's verdict and apply the block policy:
// high → block, medium → warn (allow), clean → allow.
func TestEvaluatePolicyMirrorsDetector(t *testing.T) {
	ctx := context.Background()
	g := &localGuard{detectors: map[string]*typosquat.Detector{}, malware: malware.NewIndex(nil)}
	d := typosquat.NewDetector(nil)
	d.LoadEcosystem("npm", []typosquat.PopularPackage{
		{Name: "lodash", Rank: 1}, {Name: "react", Rank: 2}, {Name: "express", Rank: 3},
	})
	g.detectors["npm"] = d

	// Exact popular name: never blocked, no typosquat severity.
	clean := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "lodash"})
	if clean.Block || clean.Severity != "" {
		t.Errorf("exact popular package flagged: %+v", clean)
	}

	// A near-miss: evaluate must mirror whatever the detector decides.
	typo := "lodahs"
	res := d.Check(ctx, "npm", typo)
	v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: typo})
	switch {
	case res.IsSuspected && res.Confidence == "high":
		if !v.Block || v.Severity != "typosquat-high" {
			t.Errorf("high-confidence typo should BLOCK: detector=%+v verdict=%+v", res, v)
		}
	case res.IsSuspected && res.Confidence == "medium":
		if v.Block || v.Severity != "typosquat-medium" {
			t.Errorf("medium-confidence typo should WARN not block: detector=%+v verdict=%+v", res, v)
		}
	default:
		if v.Block {
			t.Errorf("unsuspected name must not block: detector=%+v verdict=%+v", res, v)
		}
	}
}
