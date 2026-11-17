package policy

// exception_version.go — an exception names ONE version.
//
// The identifier matcher reads a rule's version leg as a Masterminds semver
// constraint, which is right for a block rule ("<2.15.0" must match 2.14.1)
// and wrong for an exception. As a constraint "4.2" matches every 4.2.x,
// "1" matches 1.5.0, "1.x" matches the whole 1 line, and "2024.1" matches
// 2024.1.1. So an exception a reviewer approved as `Django@4.2` let every
// later 4.2.x through — including a release cut after a maintainer takeover.
//
// Exceptions therefore compare versions as exact strings, normalised only
// where the ecosystem itself says two spellings are the same release: PEP
// 440 for PyPI ("4.2" and "4.2.0", "1.0RC1" and "1.0rc1"), a leading "v"
// (Go, Composer and npm-family tags carry it; it is not a different
// release), and case for NuGet only. Block and allow POLICIES keep constraint semantics.
//
// Stored exceptions whose version is partial are not migrated: they now
// cover exactly the version they name. When one would have matched under
// the old semantics the evaluator logs exception.version_narrowed once per
// exception, so the change is visible rather than silent.

import (
	"errors"
	"strings"

	pep440 "github.com/aquasecurity/go-pep440-version"
)

// IsException reports whether p is an exception row: Kind=KindException, or
// the pre-Wave-C legacy shape Mode=Allow + Conditions.IsVulnerable=true. The
// same envelope IsExpiredException and the server's matchActiveException use.
func IsException(p Policy) bool {
	if p.Kind == KindException {
		return true
	}
	return p.Mode == ModeAllow && p.Conditions.IsVulnerable != nil && *p.Conditions.IsVulnerable
}

// MatchesPolicyIdentifier is MatchesIdentifier with the rule's kind taken
// into account: an exception's version leg is an exact version, never a
// constraint. Every caller deciding whether a POLICY ROW covers a coordinate
// should use this rather than MatchesIdentifier.
func MatchesPolicyIdentifier(ctx EvaluationContext, p Policy) bool {
	return matchesPolicyIdentifier(ctx, p)
}

func matchesPolicyIdentifier(ctx EvaluationContext, p Policy) bool {
	if !IsException(p) {
		return matchesIdentifier(ctx, p.Identifier)
	}
	id := p.Identifier
	want := strings.TrimSpace(id.TargetPackageVersion)
	if want == "" || want == "*" {
		return matchesIdentifier(ctx, id)
	}
	id.TargetPackageVersion = ""
	return matchesIdentifier(ctx, id) && ExceptionVersionEqual(ctx.RepositoryFormat, want, ctx.PackageVersion)
}

// ExceptionVersionEqual reports whether two version strings name the same
// release of a package in the given repository format. It never treats
// either side as a range.
func ExceptionVersionEqual(format, a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	// Case is folded only where the ecosystem says case does not name a
	// different release: NuGet (case-insensitive versions) and PyPI (PEP 440
	// normalises case). Elsewhere 1.0.0-rc1 and 1.0.0-RC1 are two releases
	// (npm, Go, Cargo, RubyGems, Maven paths), and a Docker tag is case
	// sensitive, so an exception for one must not cover the other (R2-E6).
	switch EcosystemForFormat(strings.ToLower(strings.TrimSpace(format))) {
	case EcoPyPI:
		va, errA := pep440.Parse(a)
		vb, errB := pep440.Parse(b)
		if errA == nil && errB == nil {
			return va.Equal(vb)
		}
		return strings.EqualFold(a, b)
	case EcoNuGet:
		return strings.EqualFold(trimVersionV(a), trimVersionV(b))
	case EcoDocker, EcoAPT, EcoYum, EcoDNF, EcoHomebrew, EcoMaven:
		// Tags and distro versions are opaque strings: "v1" and "1" are two
		// different tags.
		return a == b
	}
	return trimVersionV(a) == trimVersionV(b)
}

// ExceptionPinned reports whether p names one exact package AND one exact
// version: a non-empty name with no wildcard, and a version
// PartialOrWildcardVersion accepts. Only a pinned exception may override a
// known-malicious verdict (R2-E3); an exception with an empty or "*" name
// or version would otherwise clear the malware feed for every coordinate
// it covers.
func ExceptionPinned(format string, p Policy) bool {
	name := strings.TrimSpace(p.Identifier.TargetPackageName)
	if name == "" || strings.Contains(name, "*") {
		return false
	}
	return PartialOrWildcardVersion(format, p.Identifier.TargetPackageVersion) == ""
}

// ErrLegacyExceptionShape refuses a NEW allow-mode policy with
// isVulnerable:true and no exception kind. That is the pre-Wave-C exception
// shape; exceptions are created through /api/exceptions, which enforces the
// approval gate, the exact version and the expiry. A row already stored in
// that shape may still be updated (disable, rollback) as long as the update
// does not introduce it.
var ErrLegacyExceptionShape = errors.New("an allow policy with isVulnerable:true is the retired exception shape; create an exception through /api/exceptions instead")

// IsLegacyExceptionShape reports whether p is the pre-Wave-C exception shape:
// Mode=Allow + Conditions.IsVulnerable=true without Kind=KindException.
func IsLegacyExceptionShape(p Policy) bool {
	return p.Kind != KindException && IsException(p)
}

func trimVersionV(v string) string {
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}
	return v
}

// PartialOrWildcardVersion explains why version cannot name an exact
// release in format, or returns "" when it can. Wildcard segments (x, X, *)
// are refused everywhere. A version with fewer than three numeric segments
// is refused only where every published version has at least three (npm,
// Cargo, Go, NuGet), because elsewhere "4.2" is a real release: Django 4.2,
// a Maven "1.0", a calendar-versioned "2024.1".
func PartialOrWildcardVersion(format, version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		return "a version is required"
	}
	if strings.ContainsAny(v, "*<>=~^,| ") {
		return "an exception names one exact version, not a range or wildcard"
	}
	core := trimVersionV(v)
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	segs := strings.Split(core, ".")
	for _, s := range segs {
		if s == "x" || s == "X" {
			return "an exception names one exact version; \"x\" segments are wildcards"
		}
	}
	switch EcosystemForFormat(strings.ToLower(strings.TrimSpace(format))) {
	case EcoNPM, EcoCargo, EcoGo, EcoNuGet:
		if len(segs) < 3 {
			return "an exception names one exact version; give all three parts (for example 4.2.0, not 4.2)"
		}
	}
	return ""
}

// warnNarrowedException logs once per exception when it no longer covers a
// coordinate that the old constraint reading of its version would have
// covered — a stored "Django@4.2" seeing 4.2.7. Record only: the verdict is
// already decided.
func (e *Evaluator) warnNarrowedException(ctx EvaluationContext, p Policy) {
	if e == nil || e.logger == nil || !IsException(p) {
		return
	}
	v := strings.TrimSpace(p.Identifier.TargetPackageVersion)
	if v == "" || v == "*" || !matchesIdentifier(ctx, p.Identifier) {
		return
	}
	if _, seen := e.narrowedWarned.LoadOrStore(p.ID, struct{}{}); seen {
		return
	}
	e.logger.Warn("exception.version_narrowed: exception names an exact version and no longer covers other versions on its line",
		"policy_id", p.ID, "org_id", ctx.OrgID, "package", ctx.PackageName,
		"exception_version", v, "requested_version", ctx.PackageVersion)
}
