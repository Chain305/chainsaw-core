package cli

// guard_established_fixtures_test.go — the measured names, against the REAL
// embedded tables and corpora (no injected rows). The 13 false blocks come
// from a real 10,428-name inventory (2026-10-21); the canary squats are the
// recall floor every change to this lane must keep.

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestEstablishedCanarySquatsStillBlock: the recall floor. None of these is
// established, so no table row can touch them.
func TestEstablishedCanarySquatsStillBlock(t *testing.T) {
	g := newSeedOnlyGuard(t)
	for _, s := range []packageSpec{
		{Ecosystem: "npm", Name: "lodahs"}, {Ecosystem: "npm", Name: "loadash"},
		{Ecosystem: "npm", Name: "crossenv"}, {Ecosystem: "npm", Name: "expres"},
		{Ecosystem: "npm", Name: "chalkk"}, {Ecosystem: "pip", Name: "reqeusts"},
		{Ecosystem: "pip", Name: "beautifulsoup5"}, {Ecosystem: "cargo", Name: "proc-macro1"},
	} {
		v := g.evaluate(context.Background(), s)
		if !v.Block || v.Severity != guardSeverityTyposquatHigh {
			t.Errorf("%s:%s must keep BLOCKING as a typosquat, got %+v", s.Ecosystem, s.Name, v)
		}
	}
}

// TestGoMajorVersionIsNotALookalike: gopsutil/v4 was blocked as a typosquat
// of gopsutil/v3 (same module), and helm.sh/helm/v4 of helm/v3. A squat
// behind a major suffix, and a cross-owner copy, are still compared.
func TestGoMajorVersionIsNotALookalike(t *testing.T) {
	g := newSeedOnlyGuard(t)
	ctx := context.Background()
	for _, name := range []string{"github.com/shirou/gopsutil/v4", "helm.sh/helm/v4", "gopkg.in/yaml.v3", "github.com/labstack/echo/v4"} {
		if v := g.evaluate(ctx, packageSpec{Ecosystem: "go", Name: name}); v.Block || v.Severity != "" {
			t.Errorf("go:%s is a major version of a popular module, not a lookalike: %+v", name, v)
		}
	}
	for _, c := range []struct{ name, target string }{
		{"github.com/sirupsem/logrus/v2", "sirupsen/logrus"},
		{"github.com/1abstack/echo/v4", "labstack/echo"},
		{"github.com/shirou/gopsutii/v3", "shirou/gopsutil"},
	} {
		v := g.evaluate(ctx, packageSpec{Ecosystem: "go", Name: c.name})
		if v.Severity == "" || !strings.Contains(v.Reason, c.target) {
			t.Errorf("go:%s must still be flagged as a lookalike of %s, got %+v", c.name, c.target, v)
		}
	}
}

// TestPubEstablishedTableClearsDartx: dartx (d=1 of dartz, on pub.dev since
// 2014) blocked because pub had no established table. It now warns on an
// unpinned install and clears silently on a pinned build-time release.
func TestPubEstablishedTableClearsDartx(t *testing.T) {
	g := newSeedOnlyGuard(t)
	ctx := context.Background()
	v := g.evaluate(ctx, packageSpec{Ecosystem: "pub", Name: "dartx"})
	if v.Block || v.Severity != guardSeverityTyposquatDemoted || !strings.Contains(v.Reason, "dartz") ||
		!strings.Contains(v.Reason, "dartx is established") {
		t.Fatalf("pub:dartx unpinned must WARN naming dartz and the establishment, got %+v", v)
	}
	_, row, ok := establishedClears("pub", "dartx", time.Now())
	if !ok {
		t.Fatal("pub:dartx has no clearing row in the embedded pub table")
	}
	if _, has := row.Releases["1.2.0"]; !has {
		t.Fatalf("pub:dartx row lacks its 1.2.0 release: %v", row.Releases)
	}
	v = g.evaluate(ctx, packageSpec{Ecosystem: "pub", Name: "dartx", Version: "1.2.0"})
	if v.Block || v.Severity != "" || v.ClearedReason == "" {
		t.Fatalf("pub:dartx@1.2.0 must clear silently, got %+v", v)
	}
}

// TestNPMSecurityPlaceholderNotEstablished: npm:http is npm's
// "0.0.1-security" holding package; its installs are typos of the builtin.
func TestNPMSecurityPlaceholderNotEstablished(t *testing.T) {
	table, ok := establishedTableFor("npm")
	if !ok {
		t.Fatal("no embedded npm table")
	}
	if _, present := table["http"]; present {
		t.Fatal("npm:http (a -security placeholder) is in the established table")
	}
}

// TestEstablishedNoBareInstallIsSilent: across every embedded row that
// carries a release set — the rows the detector can flag — an unpinned
// install is never a silent clear and never a typosquat block.
func TestEstablishedNoBareInstallIsSilent(t *testing.T) {
	g := newSeedOnlyGuard(t)
	ctx := context.Background()
	checked := 0
	for _, eco := range []string{"npm", "pip", "cargo", "pub"} {
		table, ok := establishedTableFor(eco)
		if !ok {
			t.Fatalf("no embedded %s table", eco)
		}
		for _, row := range table {
			if len(row.Releases) == 0 {
				continue
			}
			checked++
			v := g.evaluate(ctx, packageSpec{Ecosystem: eco, Name: row.Name})
			if v.ClearedReason != "" {
				t.Errorf("%s:%s unpinned was cleared SILENTLY: %q", eco, row.Name, v.ClearedReason)
			}
			if v.Block && strings.HasPrefix(v.Severity, guardSeverityTyposquatPrefix) {
				t.Errorf("%s:%s is established yet blocked as a typosquat: %+v", eco, row.Name, v)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no embedded row carries a release set — the tables were not regenerated")
	}
	t.Logf("%d lookalike rows checked", checked)
}

// TestEstablishedInventoryFalseBlocks pins the 13 inventory false blocks
// against the census tables (built from public registry name lists only, so
// this inventory is out of sample). None may clear silently on an unpinned
// install. Ten no longer block: gopsutil/v4 (Go suffix), dartx (pub census),
// and jsonp, pegjs, is-blob, js-logger, has-own (npm census: on the registry
// 7+ years with >= 100k downloads a week). The rest stay blocked because the
// registry does not show them established by the census lines — under 100k
// downloads a week: as-number, clui, crypto-es, crypto-ts, hable; faiss-gpu
// likewise on PyPI. Changing that is a decision about the lines, not a table
// edit.
func TestEstablishedInventoryFalseBlocks(t *testing.T) {
	g := newSeedOnlyGuard(t)
	ctx := context.Background()
	for _, c := range []struct {
		s     packageSpec
		block bool
	}{
		{packageSpec{Ecosystem: "go", Name: "github.com/shirou/gopsutil/v4"}, false},
		{packageSpec{Ecosystem: "pub", Name: "dartx"}, false},
		{packageSpec{Ecosystem: "npm", Name: "jsonp"}, false},
		{packageSpec{Ecosystem: "npm", Name: "pegjs"}, false},
		{packageSpec{Ecosystem: "npm", Name: "is-blob"}, false},
		{packageSpec{Ecosystem: "npm", Name: "js-logger"}, false},
		{packageSpec{Ecosystem: "npm", Name: "has-own"}, false},
		{packageSpec{Ecosystem: "npm", Name: "as-number"}, true},
		{packageSpec{Ecosystem: "npm", Name: "clui"}, true},
		{packageSpec{Ecosystem: "npm", Name: "crypto-es"}, true},
		{packageSpec{Ecosystem: "npm", Name: "crypto-ts"}, true},
		{packageSpec{Ecosystem: "npm", Name: "hable"}, true},
		{packageSpec{Ecosystem: "pip", Name: "faiss-gpu"}, true},
	} {
		v := g.evaluate(ctx, c.s)
		if v.ClearedReason != "" {
			t.Errorf("%s:%s unpinned was cleared silently: %q", c.s.Ecosystem, c.s.Name, v.ClearedReason)
		}
		if v.Block != c.block {
			t.Errorf("%s:%s block=%v, want %v: %+v", c.s.Ecosystem, c.s.Name, v.Block, c.block, v)
		}
	}
	// An exact pin of a release the census recorded is the one silent case.
	if v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "jsonp", Version: "0.2.1"}); v.Block || v.Severity != "" || v.ClearedReason == "" {
		t.Errorf("npm:jsonp@0.2.1 (a build-time release) must clear silently: %+v", v)
	}
}

// TestGoShortSegmentGate: the short-target rule measures a Go module by the
// path segment the edit lands in, the way an npm name is measured by its own
// length. gopkg.in/inf.v0 and gopkg.in/ini.v1 are two real modules whose
// major digits used to keep them two edits apart; with the suffix stripped,
// inf/ini is one substitution against a 3-rune name, which the rule demotes.
// An edit in a long owner segment keeps the block.
func TestGoShortSegmentGate(t *testing.T) {
	g := newSeedOnlyGuard(t)
	ctx := context.Background()
	if v := g.evaluate(ctx, packageSpec{Ecosystem: "go", Name: "gopkg.in/inf.v0"}); v.Block {
		t.Errorf("go:gopkg.in/inf.v0 must not block as a lookalike of gopkg.in/ini.v1: %+v", v)
	}
	for _, name := range []string{"github.com/gin-gonlc/gin", "github.com/sirupsem/logrus/v2", "github.com/stretchr/testifi"} {
		if v := g.evaluate(ctx, packageSpec{Ecosystem: "go", Name: name}); !v.Block {
			t.Errorf("go:%s (edit in a long segment) must keep BLOCKING: %+v", name, v)
		}
	}
}
