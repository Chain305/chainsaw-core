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

// The long-lived lines, shared by the server's clear
// (core/intelligence/typosquat_established.go) and the guard's table clear
// (core/cli/guard_established.go). Registries delete a squat once it is
// reported, and squats are reported in days to months; jeIlyfish (PyPI,
// 2018-12 to 2019-12) is the famous outlier at about a year. Rev6 stratum E
// (2026-10-10) quarantined 11 benign packages one edit from a popular name,
// every one on its registry since 2010-2018, none popular enough for the
// download lines, and only one with a long release history.
//
// Both halves are required. The package age is the survival evidence; the
// release age stops a sleeper — a lookalike name registered years ago that
// ships its payload in a fresh release — from inheriting that evidence.
// Unknown dates (zero time.Time) prove nothing and fail the line.
const (
	EstablishedLongLivedPackageAge = 5 * 365 * 24 * time.Hour
	EstablishedLongLivedVersionAge = 365 * 24 * time.Hour
)

// EstablishedRow is the registry-wide qualification data for one package:
// what the typosquat clear decides on. It is NOT a popularity corpus — it is
// the evidence that a name the typosquat lane suspects is itself a
// long-standing registry resident, which makes the similarity claim wrong
// rather than weak.
//
// The zero value of each field means UNKNOWN. Unknown data establishes
// nothing; a negative count (a failed fetch) is below every line, same as in
// EstablishedReason.
type EstablishedRow struct {
	Name string
	// WeeklyDownloads is the registry's weekly download count. The crates.io
	// 90-day count has no field here: the guard table stores a normalized
	// weekly figure per ecosystem, and the 90-day reading stays a server-side
	// shape (EstablishedReason's window plumbing below).
	WeeklyDownloads int64
	VersionCount    int
	// FirstPublished / LastPublished are the first and most recent release
	// dates. Zero = unknown; unknown dates fail every line that needs them —
	// in particular an unknown LastPublished FAILS the long-lived line (a
	// sleeper whose last release nobody recorded must not inherit survival
	// evidence).
	FirstPublished time.Time
	LastPublished  time.Time
}

// EstablishedClear is THE definition of when a package's qualification data
// clears a typosquat claim: one of
//
//   - the downloads line:  >= EstablishedWeeklyDownloads weekly downloads;
//   - the release-history line: >= EstablishedMinVersions versions AND
//     first published >= EstablishedMinAge ago;
//   - the long-lived line: first published >= EstablishedLongLivedPackageAge
//     ago AND last released >= EstablishedLongLivedVersionAge ago.
//
// The server path (core/intelligence, clearEstablishedTyposquat) and the
// offline guard (core/cli, establishedClears) both route their line decisions
// through this function so the two can never disagree about which packages
// are established — the guard blocked 28 established packages (pug, jsdoc,
// uglify-es, …) on a real 10,428-name inventory precisely because its copy of
// these rules had never been written.
//
// Returns the line that cleared (human-readable, carried on verdicts and
// warnings as the explanation), or "" when nothing cleared.
func EstablishedClear(row EstablishedRow, now time.Time) (reason string, cleared bool) {
	if row.WeeklyDownloads >= EstablishedWeeklyDownloads {
		return fmt.Sprintf("%d downloads per week", row.WeeklyDownloads), true
	}
	if row.FirstPublished.IsZero() {
		return "", false
	}
	if row.VersionCount >= EstablishedMinVersions && now.Sub(row.FirstPublished) >= EstablishedMinAge {
		return fmt.Sprintf("%d versions since %s", row.VersionCount, row.FirstPublished.Format("2006-01-02")), true
	}
	if !row.LastPublished.IsZero() &&
		now.Sub(row.FirstPublished) >= EstablishedLongLivedPackageAge &&
		now.Sub(row.LastPublished) >= EstablishedLongLivedVersionAge {
		return fmt.Sprintf("published since %s, last released %s",
			row.FirstPublished.Format("2006-01-02"), row.LastPublished.Format("2006-01-02")), true
	}
	return "", false
}

// EstablishedReason reports why a package counts as established, or "" when
// it does not. Missing data establishes nothing; a failed fetch (-1) is
// below every line.
//
// The weekly and release-history lines are decided by EstablishedClear — the
// same function the guard's table clear calls — by building a row that can
// only clear through the line being asked about. What stays here is the
// window plumbing the row shape has no field for: crates.io's 90-day count
// (Established90DayDownloads) and the "week"-window downloads spelling.
func EstablishedReason(downloads *int, window string, weekly *int, versions int, first *time.Time, now time.Time) string {
	switch {
	case window == "90d" && downloads != nil:
		if *downloads >= Established90DayDownloads {
			return fmt.Sprintf("%d downloads per 90d", *downloads)
		}
	case weekly != nil:
		if reason, ok := EstablishedClear(EstablishedRow{WeeklyDownloads: int64(*weekly)}, now); ok {
			return reason
		}
	case window == "week" && downloads != nil:
		if *downloads >= EstablishedWeeklyDownloads {
			return fmt.Sprintf("%d downloads per week", *downloads)
		}
	}
	row := EstablishedRow{VersionCount: versions}
	if first != nil {
		row.FirstPublished = *first
	}
	reason, _ := EstablishedClear(row, now)
	return reason
}

// establishedInputReason is EstablishedReason over a risk Input.
func establishedInputReason(in Input, now time.Time) string {
	return EstablishedReason(in.Downloads, in.DownloadsWindow, in.WeeklyDownloads, in.VersionCount, in.FirstPublishedAt, now)
}

// dampEstablished applies the damper to the fired primitive set in place and
// returns the IDs whose ceiling no longer applies. It does nothing unless the
// package is established, no TakeoverIndicator fired and no compromise-shaped
// compound fired (takeover signature, exfil sink at install, obfuscated exec,
// trivial dynamic code). A compound marked DampEstablished does not suspend
// the damper. Its ceiling is lifted, weight kept, only when the package
// clears a DOWNLOAD line: release history alone does not exempt it, because
// pxnpm (168 versions since 2019, 1,640 a week) shipped install-hook malware
// in October 2026 with no publisher change, and the history line would have
// waved it through. Every measured benign hit of those rules is popular.
func dampEstablished(in Input, fired, compound map[string]FiredSignal, now time.Time) map[string]bool {
	reason := establishedInputReason(in, now)
	if reason == "" {
		return nil
	}
	popular := EstablishedReason(in.Downloads, in.DownloadsWindow, in.WeeklyDownloads, 0, nil, now)
	var dampableCompounds []string
	for _, rule := range CompoundRules {
		if _, ok := compound[rule.ID]; !ok {
			continue
		}
		if !rule.DampEstablished {
			return nil
		}
		if popular != "" {
			dampableCompounds = append(dampableCompounds, rule.ID)
		}
	}
	for id := range fired {
		if sig, ok := Registry[id]; ok && sig.TakeoverIndicator {
			return nil
		}
	}
	var damped map[string]bool
	mark := func(set map[string]FiredSignal, id string, halve bool, reason string) {
		if damped == nil {
			damped = make(map[string]bool)
		}
		damped[id] = true
		f := set[id]
		if halve {
			f.Weight /= 2
		}
		ev := make(map[string]any, len(f.Evidence)+2)
		for k, v := range f.Evidence {
			ev[k] = v
		}
		ev["damped"] = true
		ev["damped_reason"] = "established package: " + reason
		f.Evidence = ev
		set[id] = f
	}
	for id := range fired {
		if sig, ok := Registry[id]; ok && sig.DampEstablished {
			mark(fired, id, true, reason)
		}
	}
	for _, id := range dampableCompounds {
		mark(compound, id, false, popular)
	}
	return damped
}
