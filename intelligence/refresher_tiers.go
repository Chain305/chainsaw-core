package intelligence

import (
	"hash/fnv"
	"time"

	"github.com/chain305/chainsaw-core/metadata"
	"github.com/chain305/chainsaw-core/risk"
)

// Tiered refresh (docs/REPORTS.md#backend-perf-load-test-2026-10-29 J.4
// I13-3). Every row used to be rescanned once per MaxStaleness (24h), and a
// rescan is ~10 upstream requests: 852k fetches a week for a fleet with
// almost no installs. Most rows do not change that fast, so the window now
// depends on how much a stale answer could cost:
//
//   - hot, MaxStaleness: no report yet, a verdict other than allow, or a
//     release under 30 days old (new releases are when a package is taken
//     over and when advisories land);
//   - cold, 7 x MaxStaleness: an allow verdict on a release over a year old;
//   - warm, 3 x MaxStaleness: everything else.
//
// Each window is jittered by up to +-10% per coordinate, so rows written in
// one burst do not come due in one burst.
//
// What does not wait for the tier: a newly published advisory (freshFor and
// the advisory gate force the rescan), a new upstream version (the
// latest-version probe keeps its 24h window), and serving — an install
// reads with its own staleness bound and refreshes in the background.
const (
	hotReleaseAge  = 30 * 24 * time.Hour
	coldReleaseAge = 365 * 24 * time.Hour
	warmFactor     = 3
	coldFactor     = 7
)

// refreshWindow is how long the scheduled walk leaves row's report alone.
func (r *Refresher) refreshWindow(row metadata.PackageMetadataRow, report *Report) time.Duration {
	base := r.cfg.MaxStaleness
	if r.cfg.TieredRefreshDisabled || report == nil || report.Risk == nil || report.Risk.Verdict != risk.VerdictAllow {
		return base
	}
	released := report.Release.PublishedAt
	if released == nil {
		released = row.VersionReleaseDate
	}
	factor := time.Duration(warmFactor)
	switch {
	case released == nil:
	case r.now().Sub(*released) < hotReleaseAge:
		return base
	case r.now().Sub(*released) > coldReleaseAge:
		factor = coldFactor
	}
	return jitter(base*factor, row)
}

// jitter spreads d by up to +-10%, deterministically per coordinate.
func jitter(d time.Duration, row metadata.PackageMetadataRow) time.Duration {
	h := fnv.New32a()
	_, _ = h.Write([]byte(row.OrgID + "\x00" + row.Repository + "\x00" + row.Package + "\x00" + row.Version))
	frac := float64(h.Sum32()%2001)/10000 - 0.1 // -0.1 .. +0.1
	return d + time.Duration(float64(d)*frac)
}
