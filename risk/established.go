package risk

import (
	"fmt"
	"time"
)

// established.go — the established-package damper.
//
// Socket softens every penalty on big and popular packages (an exponent on
// lines of code and popularity, docs.socket.dev/docs/package-scores). This
// engine deliberately does NOT: on production packages with >=1M weekly
// downloads the non-allow verdicts are mostly vulnerabilities, transitive
// risk and publisher changes, and a publisher change is how popular packages
// get compromised (event-stream, ua-parser-js, coa, chalk/debug, nx). A
// global softener would soften exactly those.
//
// Instead a signal opts in (Signal.DampEstablished). On an established
// package a fired dampable signal loses its ceiling (MaxImpact, which is what
// moves verdicts) and half its weight, and its finding carries the reason.
// Damping is suspended for the whole evaluation when any signal marked
// TakeoverIndicator fires: an established package showing a takeover tell
// gets every hygiene signal in full. Design and measurement:
// docs/PLANS_INTELLIGENCE.md#plan-established-damper.

// The establishment lines. A squat's traffic is the typo traffic it steals
// from its target, a small fraction of the target's.
//
// EstablishedWeeklyDownloads: across every typosquat-flagged production row
// (2026-10-06, 85 rows) the busiest real squat was `expres` at 8,167/week;
// the false positives start at `csrf` 1.28M.
//
// Established90DayDownloads is the crates.io line (it publishes only a
// 90-day count). faster_log, the busiest crates.io squat on record, drew
// 7,181 downloads in its whole ~4-month life; the lowest production false
// positive is termbg at 94,361.
//
// EstablishedMinVersions / EstablishedMinAge: registries delete squats
// within weeks to months, and every real or suspected squat in production
// (2026-10-07) carried at most 28 versions; dbsp, the false positive this
// line exists for, has 299 since 2023-08. The age half stops a burst of
// publishes in one week from qualifying.
//
// Packagist's month and the RubyGems/NuGet all-time totals have no measured
// line, so those packages can only qualify through release history.
const (
	EstablishedWeeklyDownloads = 100_000
	Established90DayDownloads  = 75_000
	EstablishedMinVersions     = 50
	EstablishedMinAge          = 2 * 365 * 24 * time.Hour
)

// EstablishedReason reports why a package counts as established, or "" when
// it does not. Missing data establishes nothing; a failed fetch (-1) is
// below every line.
func EstablishedReason(downloads *int, window string, weekly *int, versions int, first *time.Time, now time.Time) string {
	switch {
	case window == "90d" && downloads != nil:
		if *downloads >= Established90DayDownloads {
			return fmt.Sprintf("%d downloads per 90d", *downloads)
		}
	case weekly != nil:
		if *weekly >= EstablishedWeeklyDownloads {
			return fmt.Sprintf("%d downloads per week", *weekly)
		}
	case window == "week" && downloads != nil:
		if *downloads >= EstablishedWeeklyDownloads {
			return fmt.Sprintf("%d downloads per week", *downloads)
		}
	}
	if first != nil && versions >= EstablishedMinVersions && now.Sub(*first) >= EstablishedMinAge {
		return fmt.Sprintf("%d versions since %s", versions, first.Format("2006-01-02"))
	}
	return ""
}

// establishedInputReason is EstablishedReason over a risk Input.
func establishedInputReason(in Input, now time.Time) string {
	return EstablishedReason(in.Downloads, in.DownloadsWindow, in.WeeklyDownloads, in.VersionCount, in.FirstPublishedAt, now)
}

// dampEstablished applies the damper to the fired primitive set in place and
// returns the IDs whose ceiling no longer applies. It does nothing unless the
// package is established, no TakeoverIndicator fired and no compound rule
// fired: every compound rule (takeover signature, install-time env+network,
// install-time network+shell, exfil sink at install) is compromise-shaped.
func dampEstablished(in Input, fired, compound map[string]FiredSignal, now time.Time) map[string]bool {
	reason := establishedInputReason(in, now)
	if reason == "" || len(compound) > 0 {
		return nil
	}
	for id := range fired {
		if sig, ok := Registry[id]; ok && sig.TakeoverIndicator {
			return nil
		}
	}
	var damped map[string]bool
	for id, f := range fired {
		sig, ok := Registry[id]
		if !ok || !sig.DampEstablished {
			continue
		}
		if damped == nil {
			damped = make(map[string]bool)
		}
		damped[id] = true
		f.Weight /= 2
		ev := make(map[string]any, len(f.Evidence)+2)
		for k, v := range f.Evidence {
			ev[k] = v
		}
		ev["damped"] = true
		ev["damped_reason"] = "established package: " + reason
		f.Evidence = ev
		fired[id] = f
	}
	return damped
}
