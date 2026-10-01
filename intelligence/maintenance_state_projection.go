package intelligence

import (
	"regexp"
	"strings"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// versionPublishedAt is THIS version's publish date for maint.outdated_version:
// the registry's own per-version date, else the version's timeline entry, else
// the secondary Release.VersionDate (Maven POM Last-Modified, NuGet leaf).
func versionPublishedAt(r *Report) *time.Time {
	if r.Release.PublishedAt != nil {
		return r.Release.PublishedAt
	}
	for _, v := range r.Maintenance.VersionTimeline {
		if !v.PublishedAt.IsZero() && strings.EqualFold(v.Version, r.Identity.Version) {
			t := v.PublishedAt
			return &t
		}
	}
	return r.Release.VersionDate
}

// newerStableVersion returns the newest non-prerelease version published after
// `at`, or "" when none is known. A dated timeline is authoritative: when it
// has dates and none is newer, there is no newer version. Only an undated one
// (Go @v/list, Maven maven-metadata.xml, a paged NuGet index) falls back to
// the registry's latest label and its date.
func newerStableVersion(r *Report, at *time.Time) (string, *time.Time) {
	if at == nil {
		return "", nil
	}
	eco, cur := r.Identity.Ecosystem, r.Identity.Version
	var best string
	var bestAt time.Time
	dated := false
	for _, v := range r.Maintenance.VersionTimeline {
		if v.PublishedAt.IsZero() {
			continue
		}
		dated = true
		if !v.PublishedAt.After(*at) || strings.EqualFold(v.Version, cur) || isPrereleaseVersion(eco, v.Version) {
			continue
		}
		if v.PublishedAt.After(bestAt) {
			best, bestAt = v.Version, v.PublishedAt
		}
	}
	if dated {
		if best == "" {
			return "", nil
		}
		return best, &bestAt
	}
	latest, latestAt := r.Release.LatestVersion, r.Maintenance.LatestReleaseAt
	if latest == "" || latestAt == nil || !latestAt.After(*at) ||
		strings.EqualFold(latest, cur) || isPrereleaseVersion(eco, latest) {
		return "", nil
	}
	return latest, latestAt
}

// prereleaseToken matches the pre-release spellings of the ecosystems that do
// not use SemVer's "-": PEP 440 (1.0a1, 1.0rc1, 1.0.dev3), Maven (2.24.0.M2,
// -SNAPSHOT, .rc2), RubyGems (1.0.pre), Composer (-beta, -RC). A Maven
// classifier like guava's "-jre" is not a pre-release and does not match.
var prereleaseToken = regexp.MustCompile(`(?i)(alpha|beta|preview|pre|rc|cr|dev|snapshot|nightly|canary|milestone)|[\d._-](a|b|m)\d+`)

// isPrereleaseVersion reports whether v is a pre-release in eco's own scheme.
// A Go pseudo-version is NOT: on an untagged module it is the release stream.
func isPrereleaseVersion(eco, v string) bool {
	v = strings.TrimSpace(v)
	switch strings.ToLower(strings.TrimSpace(eco)) {
	case "go", "golang", "gomod":
		gv := v
		if !strings.HasPrefix(gv, "v") {
			gv = "v" + gv
		}
		return semver.Prerelease(gv) != "" && !module.IsPseudoVersion(gv)
	case "npm", "yarn", "pnpm", "bun", "cargo", "nuget":
		if i := strings.IndexByte(v, '+'); i >= 0 {
			v = v[:i]
		}
		return strings.Contains(v, "-")
	}
	return prereleaseToken.MatchString(v)
}
