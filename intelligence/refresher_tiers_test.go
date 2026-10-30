package intelligence

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/metadata"
	"github.com/chain305/chainsaw-core/risk"
)

// J.4 I13-3: the scheduled walk's window depends on what a stale answer
// could cost. Unknown or non-allow verdicts and fresh releases stay at
// MaxStaleness; an allow on a release over a year old waits ~7x; the rest
// ~3x. Every tiered window is within +-10% of its target.
func TestRefreshWindowTiers(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	r := &Refresher{cfg: RefresherConfig{MaxStaleness: 24 * time.Hour}, now: func() time.Time { return now }}
	row := metadata.PackageMetadataRow{OrgID: "o"}
	row.Repository, row.Package, row.Version = "npmjs", "left-pad", "1.3.0"
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	report := func(v risk.Verdict, released *time.Time) *Report {
		rep := &Report{Risk: &risk.Evaluation{Verdict: v}}
		rep.Release.PublishedAt = released
		return rep
	}
	within := func(got, target time.Duration) bool {
		return got >= target*9/10 && got <= target*11/10
	}
	day := 24 * time.Hour

	for name, tc := range map[string]struct {
		rep    *Report
		target time.Duration
		exact  bool
	}{
		"no report":         {nil, day, true},
		"no verdict":        {&Report{}, day, true},
		"warn verdict":      {report(risk.VerdictWarn, ago(400*day)), day, true},
		"allow, fresh":      {report(risk.VerdictAllow, ago(10*day)), day, true},
		"allow, mid-age":    {report(risk.VerdictAllow, ago(100*day)), 3 * day, false},
		"allow, no release": {report(risk.VerdictAllow, nil), 3 * day, false},
		"allow, old":        {report(risk.VerdictAllow, ago(400*day)), 7 * day, false},
	} {
		got := r.refreshWindow(row, tc.rep)
		if tc.exact && got != tc.target || !tc.exact && !within(got, tc.target) {
			t.Errorf("%s: window %v, want %v (exact=%v)", name, got, tc.target, tc.exact)
		}
	}

	r.cfg.TieredRefreshDisabled = true
	if got := r.refreshWindow(row, report(risk.VerdictAllow, ago(400*day))); got != day {
		t.Fatalf("tiering disabled: window %v, want MaxStaleness", got)
	}
}

// The jitter differs by coordinate, so rows written together do not come
// due together.
func TestRefreshWindowJitterSpreads(t *testing.T) {
	seen := map[time.Duration]bool{}
	for _, v := range []string{"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"} {
		row := metadata.PackageMetadataRow{OrgID: "o"}
		row.Package, row.Version = "p", v
		seen[jitter(72*time.Hour, row)] = true
	}
	if len(seen) < 4 {
		t.Fatalf("five coordinates got %d distinct windows; the jitter is not spreading them", len(seen))
	}
}

// Source guard: the walk's skip decision uses the tier. refreshWindow is
// pure and covered above, but the branch that reads it needs a stored
// report, i.e. a live database (see TestRefreshRowUsesTheReportStalenessGate).
func TestRefreshRowUsesTheTierWindow(t *testing.T) {
	src, err := os.ReadFile("refresher.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"window := r.refreshWindow(row, priorReport)",
		"reportIsFresh(priorReport, r.cfg.Store != nil, row.UpdatedAt, r.now().Add(-window))",
		"priorReport.freshFor(window)",
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("refresher.go no longer contains %q", want)
		}
	}
}
