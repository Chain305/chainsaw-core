package risk

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// clearNow is the fixed clock for the EstablishedClear boundary table: every
// date below is chosen relative to it so "exactly at the line" and "one day
// short" are literal.
var clearNow = time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)

func clearDay(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

// TestEstablishedClearBoundaries walks every line at its threshold, one below
// it, and one above it. The at-the-line rows are the contract: a package at
// exactly 100k/week, exactly 50 versions over exactly two years, or exactly
// 5y+1d old with a release exactly 1y+1d old, CLEARS — the thresholds are
// inclusive and the ages are >=, matching EstablishedReason's server-side
// behaviour, which these boundaries mirror.
func TestEstablishedClearBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		row     EstablishedRow
		want    bool
		wantSub string // substring of the reason when cleared
	}{
		// ── the downloads line ───────────────────────────────────────────
		{"weekly at the line", EstablishedRow{WeeklyDownloads: EstablishedWeeklyDownloads}, true, "downloads per week"},
		{"weekly one above the line", EstablishedRow{WeeklyDownloads: EstablishedWeeklyDownloads + 1}, true, "downloads per week"},
		{"weekly one below the line", EstablishedRow{WeeklyDownloads: EstablishedWeeklyDownloads - 1}, false, ""},
		{"weekly zero (unknown)", EstablishedRow{WeeklyDownloads: 0}, false, ""},
		{"weekly negative (failed fetch)", EstablishedRow{WeeklyDownloads: -1}, false, ""},
		// Downloads clear alone: no dates needed.
		{"weekly clears with unknown dates", EstablishedRow{WeeklyDownloads: 1277456}, true, "1277456"},

		// ── the release-history line ─────────────────────────────────────
		{"versions at both lines", EstablishedRow{
			VersionCount: EstablishedMinVersions, FirstPublished: clearDay("2024-10-19"),
		}, true, "versions since 2024-10-19"},
		{"versions one short", EstablishedRow{
			VersionCount: EstablishedMinVersions - 1, FirstPublished: clearDay("2023-01-01"),
		}, false, ""},
		{"versions at count but one day young", EstablishedRow{
			VersionCount: EstablishedMinVersions, FirstPublished: clearDay("2024-10-20"),
		}, false, ""},
		{"versions old enough but no first publish", EstablishedRow{
			VersionCount: EstablishedMinVersions * 3,
		}, false, ""},

		// ── the long-lived line ──────────────────────────────────────────
		// (The ages are day-counts — 5*365d and 365d — not calendar years,
		// so the at-the-line dates below are the exact 1825/365-day backs of
		// clearNow; the 2024 leap day would otherwise shift them by one.)
		{"long-lived at both lines", EstablishedRow{
			FirstPublished: clearDay("2021-10-20"), LastPublished: clearDay("2025-10-19"),
		}, true, "published since 2021-10-20, last released 2025-10-19"},
		{"long-lived, package one day short", EstablishedRow{
			FirstPublished: clearDay("2021-10-21"), LastPublished: clearDay("2020-01-01"),
		}, false, ""},
		{"long-lived, last release one day short", EstablishedRow{
			FirstPublished: clearDay("2015-01-01"), LastPublished: clearDay("2025-10-20"),
		}, false, ""},
		// THE rule the adversarial review asked to pin: an unknown
		// last-published must FAIL the long-lived line, not pass it — a
		// sleeper whose last release nobody recorded must not inherit the
		// name's survival evidence.
		{"long-lived with UNKNOWN last-published fails", EstablishedRow{
			FirstPublished: clearDay("2010-01-01"),
		}, false, ""},
		{"long-lived with unknown first-published fails", EstablishedRow{
			LastPublished: clearDay("2010-01-01"),
		}, false, ""},
		{"long-lived with a fresh sleeper release fails", EstablishedRow{
			FirstPublished: clearDay("2015-01-01"), LastPublished: clearDay("2026-06-01"),
		}, false, ""},

		// ── the empty row clears nothing ─────────────────────────────────
		{"no data at all", EstablishedRow{}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason, cleared := EstablishedClear(tc.row, clearNow)
			if cleared != tc.want {
				t.Fatalf("EstablishedClear(%+v) cleared=%v (reason %q), want %v",
					tc.row, cleared, reason, tc.want)
			}
			if !cleared {
				if reason != "" {
					t.Errorf("not cleared but reason %q is non-empty", reason)
				}
				return
			}
			if !strings.Contains(reason, tc.wantSub) {
				t.Errorf("reason %q lacks %q", reason, tc.wantSub)
			}
		})
	}
}

// TestEstablishedClearPrecedence: when several lines could fire, the
// downloads line wins — it is the strongest evidence and the one whose reason
// an operator can verify fastest.
func TestEstablishedClearPrecedence(t *testing.T) {
	row := EstablishedRow{
		WeeklyDownloads: EstablishedWeeklyDownloads * 10,
		VersionCount:    EstablishedMinVersions,
		FirstPublished:  clearDay("2000-01-01"),
		LastPublished:   clearDay("2000-01-01"),
	}
	reason, cleared := EstablishedClear(row, clearNow)
	if !cleared || !strings.Contains(reason, "downloads per week") {
		t.Fatalf("downloads line should win, got %q (cleared=%v)", reason, cleared)
	}
}

// TestEstablishedClearMirrorsEstablishedReason pins the refactor: for the
// inputs both functions can take, they must agree. EstablishedReason keeps
// the windowed plumbing (90d, "week") but its weekly and release-history
// lines are EstablishedClear's — one definition, two entry points, so the
// guard and the server cannot diverge again.
func TestEstablishedClearMirrorsEstablishedReason(t *testing.T) {
	weeklys := []int{-1, 0, 8_167, 99_999, 100_000, 1_277_456, 130_138_095}
	for _, w := range weeklys {
		w := w
		t.Run("weekly="+strconv.Itoa(w), func(t *testing.T) {
			want, _ := EstablishedClear(EstablishedRow{WeeklyDownloads: int64(w)}, clearNow)
			got := EstablishedReason(nil, "", &w, 0, nil, clearNow)
			if (want != "") != (got != "") {
				t.Errorf("weekly %d: EstablishedClear=%q EstablishedReason=%q — the two definitions disagree", w, want, got)
			}
		})
	}

	versions := []int{0, 28, 49, 50, 299}
	firsts := []*time.Time{nil, tp(clearDay("2026-01-09")), tp(clearDay("2024-10-20")), tp(clearDay("2024-10-19")), tp(clearDay("2023-08-23"))}
	for _, v := range versions {
		for _, f := range firsts {
			want, _ := EstablishedClear(EstablishedRow{VersionCount: v, FirstPublished: derefTime(f)}, clearNow)
			got := EstablishedReason(nil, "", nil, v, f, clearNow)
			if (want != "") != (got != "") {
				t.Errorf("versions=%d first=%v: EstablishedClear=%q EstablishedReason=%q — the two definitions disagree", v, f, want, got)
			}
		}
	}
}

func tp(t time.Time) *time.Time { return &t }

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
