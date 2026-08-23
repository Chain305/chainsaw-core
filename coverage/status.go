// Package coverage decides whether a package may proceed when a data source
// the operator declared mandatory could not be evaluated.
//
// The package is deliberately dependency-free (stdlib only). It knows nothing
// about intelligence providers, risk scoring, or policy — callers translate
// their own world into a Ledger and read back a Decision. That is what makes
// the decision identical on every surface and testable without a fixture.
//
// Design, rejected alternatives, and accepted risks:
// docs/plan_optional_fail_closed.md.
package coverage

import "strings"

// Status is what we know about one data source for one package.
type Status string

const (
	// StatusOK — the source was consulted and gave an answer. A "no such
	// package" 404 is an answer, not an outage.
	StatusOK Status = "ok"
	// StatusUnavailable — the source was not reached. The ONLY status that
	// can cause a block.
	StatusUnavailable Status = "unavailable"
	// StatusNotApplicable — the source does not cover this ecosystem or this
	// surface. Never blocks.
	StatusNotApplicable Status = "not_applicable"
	// StatusError — our bug, or a warn code we do not recognise. Never
	// blocks, per the rule-bug-fails-open doctrine: a malformed rule or a
	// panicking provider must not be able to wedge production.
	StatusError Status = "error"
)

// unavailableCodes are the raw warn codes that mean "we did not reach the
// source". Kept as an explicit set rather than a heuristic so that adding a
// blocking code is always a deliberate, reviewable act.
//
// The strings here are the codes providers ACTUALLY emit, which is not the
// same as the WarnXxx constants declared in intelligence/report.go — several
// of those (WarnUpstream5xx, WarnUpstream4xx, WarnBreakerOpen,
// WarnRateLimited, WarnUnsupported) have zero emission sites in the tree. See
// the P0 section of docs/plan_optional_fail_closed.md.
var unavailableCodes = map[string]bool{
	"timeout":                          true,
	"context_cancelled":                true,
	"transport":                        true,
	"breaker_open":                     true,
	"rate_limited":                     true,
	"registry_fetch_exhausted_retries": true,
	"mod_fetch_failed":                 true,
	"github_meta_fetch_failed":         true,
	"gitlab_meta_fetch_failed":         true,
	"codeberg_meta_fetch_failed":       true,
	"bitbucket_meta_fetch_failed":      true,
	"timeline_fetch_failed":            true,
	"repolink_probe_error":             true,
	"transitive_dep_not_cached":        true,
}

// okCodes are raw codes that represent a genuine answer from the source.
var okCodes = map[string]bool{
	"":          true,
	"not_found": true,
	"http_404":  true,
	// version_not_found: the registry answered, enumerated its published
	// versions, and the requested one was not among them. Same rationale
	// as not_found — a real answer from the source, not an outage. It
	// MUST be classified here: an unregistered code falls through to
	// StatusError, the opt-in fail-closed gate would read the source as
	// FAILED, and an org that opted in would start refusing installs
	// over a typo'd version pin. The refusal that IS warranted comes
	// from the unknown verdict, not from the coverage gate.
	"version_not_found": true,
}

// notApplicableCodes are raw codes meaning the source does not apply here.
var notApplicableCodes = map[string]bool{
	"ecosystem_unsupported": true,
	"needs_artifact":        true,
	// version_not_evaluable: the coordinate's version component is not a
	// version at all — an uninterpolated `${…}` build property, our
	// synthetic maven-metadata marker, a Maven meta-version. No advisory
	// source APPLIES to it, which is what not_applicable means; it is not
	// an outage (unavailable) and it is not our bug (error).
	//
	// Classified deliberately rather than left to the StatusError default,
	// because "the source failed" is the one thing that did not happen
	// here. It never blocks either way — the refusal that IS warranted
	// comes from the marked, unevaluated report, not from the coverage
	// gate. See core/intelligence/version_evaluable.go.
	"version_not_evaluable": true,
}

// StatusForWarnCode normalizes a raw provider warn code into a Status.
//
// SAFETY: any code not explicitly classified returns StatusError, which never
// blocks. A provider added in future that emits a novel string therefore
// cannot cause a spurious org-wide refusal. The failure mode of ignorance is
// fail-open, deliberately — this is the one place where that is the safe
// direction. TestUnknownWarnCodeNeverBlocks pins it, and the drift test in
// core/intelligence fails CI when an emitted code lands here unclassified.
func StatusForWarnCode(raw string) Status {
	switch {
	case okCodes[raw]:
		return StatusOK
	case unavailableCodes[raw]:
		return StatusUnavailable
	case notApplicableCodes[raw]:
		return StatusNotApplicable
	}
	// Providers emit HTTP failures as fmt.Sprintf("http_%d"). 404 is handled
	// above as a real answer; every other 4xx/5xx is an access or upstream
	// failure. Require a full three-digit code so a truncated string falls
	// through to StatusError rather than silently blocking.
	if rest, ok := strings.CutPrefix(raw, "http_"); ok && len(rest) == 3 {
		switch rest[0] {
		case '4', '5':
			return StatusUnavailable
		}
	}
	return StatusError
}
