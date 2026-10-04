package intelligence

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/risk"
)

// A report whose download count was still queued behind the registry rate
// limit is provisional: fresh for provisionalBackoff[0], not for the 24h
// staleness window, so the next scan fills the count from the process cache
// instead of serving -1 for a day.
func TestReportFreshForProvisional(t *testing.T) {
	plain := &Report{}
	if got := plain.freshFor(DefaultMaxStaleness); got != DefaultMaxStaleness {
		t.Fatalf("plain report: %v, want %v", got, DefaultMaxStaleness)
	}
	queued := &Report{}
	queued.Observation.Warnings = []Warning{{Provider: "weekly_downloads", Code: WarnDownloadsQueued}}
	if !queued.Provisional() {
		t.Fatal("a queued download count is provisional")
	}
	if got := queued.freshFor(DefaultMaxStaleness); got != provisionalBackoff[0] {
		t.Fatalf("provisional report: %v, want %v", got, provisionalBackoff[0])
	}
	if got := queued.freshFor(time.Minute); got != time.Minute {
		t.Fatalf("a shorter caller window still wins: %v", got)
	}
	other := &Report{}
	other.Observation.Warnings = []Warning{{Code: "timeline_fetch_failed"}}
	if other.Provisional() {
		t.Fatal("only an in-flight fact is provisional")
	}
}

// A registry fetch cut off at the deadline left the whole verdict Unknown
// (36 of 1003 benign rows in the fd81f358 corpus run). That row is
// provisional too, unless the scan decided anyway: a malware short-circuit
// cancels the fetch on a row that is not Unknown.
func TestReportProvisionalRegistryCancelled(t *testing.T) {
	cancelled := Warning{Provider: "registrymetadata", Code: WarnRegistryCancelled, Message: "context deadline exceeded"}
	unknown := &Report{Risk: &risk.Evaluation{Verdict: risk.VerdictUnknown}}
	unknown.Observation.Warnings = []Warning{cancelled}
	if !unknown.Provisional() || unknown.freshFor(DefaultMaxStaleness) != provisionalBackoff[0] {
		t.Fatal("an Unknown verdict from a cancelled registry fetch must be rechecked soon, not served for 24h")
	}
	decided := &Report{Risk: &risk.Evaluation{Verdict: risk.VerdictQuarantine}}
	decided.Observation.Warnings = []Warning{cancelled}
	if decided.Provisional() {
		t.Fatal("a decided row (malware short-circuit) is not provisional")
	}
	other := &Report{Risk: &risk.Evaluation{Verdict: risk.VerdictUnknown}}
	other.Observation.Warnings = []Warning{{Provider: "osv", Code: WarnRegistryCancelled}}
	if other.Provisional() {
		t.Fatal("only the registry fetch is in scope")
	}
}

// Both freshness gates must ask the report: Scan's cache-first read and the
// refresher's skip rule. They run against the concrete DB store, so this
// reads the source; it catches a deleted call, not a disabled one.
func TestProvisionalFreshnessIsReadAtBothGates(t *testing.T) {
	for file, want := range map[string]string{
		"scanner.go":   "age < cached.freshFor(maxStale)",
		"refresher.go": "priorReport.freshFor(r.cfg.MaxStaleness)",
	} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), want) {
			t.Errorf("%s no longer contains %q: a provisional report would be served as fresh for 24h", file, want)
		}
	}
}

// The recheck backs off per coordinate: 15m, 1h, 4h, then the normal window.
// A coordinate cut off on every try costs three extra scans, not one every 15
// minutes for ever, and the streak resets the moment a scan is not
// provisional. Both provisional kinds back off the same way.
func TestProvisionalRecheckBacksOff(t *testing.T) {
	kinds := map[string]func() *Report{
		"downloads queued": func() *Report {
			r := &Report{}
			r.Observation.Warnings = []Warning{{Provider: "weekly_downloads", Code: WarnDownloadsQueued}}
			return r
		},
		"registry cancelled": func() *Report {
			r := &Report{Risk: &risk.Evaluation{Verdict: risk.VerdictUnknown}}
			r.Observation.Warnings = []Warning{{Provider: "registrymetadata", Code: WarnRegistryCancelled}}
			return r
		},
	}
	want := []time.Duration{15 * time.Minute, time.Hour, 4 * time.Hour, DefaultMaxStaleness, DefaultMaxStaleness}
	for name, mk := range kinds {
		t.Run(name, func(t *testing.T) {
			streak := 0
			for i, w := range want {
				r := mk()
				streak = nextProvisionalStreak(r, streak)
				r.Observation.ProvisionalStreak = streak
				if got := r.freshFor(DefaultMaxStaleness); got != w {
					t.Fatalf("scan %d (streak %d): fresh for %v, want %v", i+1, streak, got, w)
				}
			}
			if s := nextProvisionalStreak(&Report{}, streak); s != 0 {
				t.Fatalf("a scan that is not provisional must reset the streak, got %d", s)
			}
			legacy := mk() // written before the streak existed
			if got := legacy.freshFor(DefaultMaxStaleness); got != 15*time.Minute {
				t.Fatalf("a streak of 0 is the first step, got %v", got)
			}
		})
	}
}

// The streak must be carried from the stored row into the new report, or
// every scan restarts the backoff at 15 minutes. runFanout needs the DB store
// to reach this, so it reads the source.
func TestProvisionalStreakIsCarriedFromThePriorRow(t *testing.T) {
	b, err := os.ReadFile("scanner.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"priorProvisionalStreak = prior.Observation.ProvisionalStreak",
		"report.Observation.ProvisionalStreak = nextProvisionalStreak(report, priorProvisionalStreak)",
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("scanner.go no longer contains %q", want)
		}
	}
}
