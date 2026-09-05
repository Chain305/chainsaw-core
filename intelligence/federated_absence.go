package intelligence

// Honest rendering when a FEDERATED registry says "not found" (Phase 9
// Fresh, A7).
//
// P8-04 taught the registry-metadata lane to distinguish "this package does
// not exist" from "this package is not in the registry we happened to ask",
// and restricted the strong reading to the ecosystems that have one
// canonical registry. The Maven family and Go keep the weak reading: a
// repo1 / proxy.golang.org 404 is not evidence about the package, because
// 1,405 of 1,699 production `not_found` rows were real `androidx.*`
// coordinates that live on maven.google.com.
//
// That is the right VERDICT call and this file does not touch it. What it
// fixes is what the reader is shown. Nothing downstream consumes the weak
// `not_found`, so those coordinates come back fully scored: every category
// at its 100 base and a composite in the nineties, held off 100 only by the
// license pair. `maven invalid:coord:format` rendered as
//
//	Verdict: ALLOW    Overall: 96 (A)
//	Vulnerability 100 A   (0 findings)
//
// where the four zeroes are not measurements — no metadata was retrieved at
// all. A grade painted on an empty fact set is the one thing an operator
// cannot tell from a real one, and the QA vendor filed it as a critical
// firewall bypass precisely because the screen says the package was checked
// and cleared.
//
// So: the stored verdict, the proxy hot path and the coverage
// classification are all unchanged (`not_found` stays an okCode, nothing
// flips under a closed gate). Only the summary sentence and the human
// verdict word change, on the surfaces where a person reads the result.
//
// Whether a federated 404 should ALSO set SignalsUnavailable and move the
// verdict is the open half of the P8-04 tier-2 decision. It moves 1,405
// known-good Android coordinates to `unknown`, so it needs its own flip
// count and its own approval, and it is deliberately not taken here.

import "strings"

// federatedRegistryName is the registry the provider actually asked, per
// ecosystem, so the sentence can name it rather than gesturing at "a"
// registry. Ecosystems absent from this map get the generic phrasing.
var federatedRegistryName = map[string]string{
	"maven":  "repo1.maven.org",
	"gradle": "repo1.maven.org",
	"go":     "proxy.golang.org",
	"gomod":  "proxy.golang.org",
}

// FederatedRegistryAbsence reports whether this report's registry-metadata
// lane came back "not found" on an ecosystem served by MORE THAN ONE
// registry, and returns the sentence to show when it did.
//
// The predicate is deliberately the generic `not_found` code, which for a
// federated ecosystem is the honest one the provider documents as "not
// found in the registry we checked" — it covers both a package the probe
// confirmed absent from repo1 and one whose probe went unanswered. The
// returned sentence is true of both, and claims nothing beyond what that
// code already records. A federated package that WAS found carries no such
// warning, which is what keeps a scored coordinate scored.
func FederatedRegistryAbsence(r *Report) (string, bool) {
	if r == nil {
		return "", false
	}
	eco := r.Identity.Ecosystem
	if ecosystemHasSingleCanonicalRegistry(eco) {
		// npm, PyPI, crates.io and the rest already get the strong
		// package_not_found marker and an unknown verdict from P8-04.
		return "", false
	}
	found := false
	for _, w := range r.Observation.Warnings {
		if w.Provider == "registrymetadata" && w.Code == WarnRegistryNotFound {
			found = true
			break
		}
	}
	if !found {
		return "", false
	}
	registry := federatedRegistryName[normalizeEcosystemKey(eco)]
	if registry == "" {
		return "not evaluated: the coordinate was not found in the registry " +
			"we checked, and this ecosystem is served by more than one — it " +
			"may exist in a private mirror or another repository", true
	}
	return "not evaluated: the coordinate was not found in " + registry +
		", and this ecosystem is served by more than one registry — it may " +
		"exist in a private mirror or another repository", true
}

// AnnotateFederatedAbsence writes the sentence above into the report's
// resolution summary so every API consumer sees WHY the categories are
// empty. The verdict is left exactly as evaluated: this is the display
// half of the P8-04 tier-2 decision, not the verdict half.
//
// An existing summary is never overwritten — a real finding outranks a
// note about coverage.
func AnnotateFederatedAbsence(r *Report) {
	if r == nil || r.Risk == nil {
		return
	}
	if strings.TrimSpace(r.Risk.Resolution.Summary) != "" {
		return
	}
	if summary, ok := FederatedRegistryAbsence(r); ok {
		r.Risk.Resolution.Summary = summary
	}
}
