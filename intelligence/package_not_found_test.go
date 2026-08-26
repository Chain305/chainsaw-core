package intelligence

// P8-04 — a package that does not exist upstream must not be graded clean.
//
// Verified against live registries on 2026-08-25, before the fix:
//
//	rubygems colourama            "could not be found"  -> ALLOW 96 (A)
//	nuget    Newtonsoft.Json.net  BlobNotFound          -> ALLOW 86 (B)
//	pypi     requests-python      HTTP 404              -> ALLOW 92 (A)
//
// `requests-python` is a textbook slopsquat of `requests`. The mechanism:
// every probe reduced its outcome to a bare bool, so a package-level 404
// and a registry outage were indistinguishable and both kept the generic
// `not_found` code — which risk_projection.go never consumes and
// core/coverage classifies as an OK answer. Nothing routed the coordinate
// into the unavailability machinery, every category started at
// categoryBase = 100, and no signal could fire on an empty Report.
//
// The table below is parameterised over EVERY ecosystem with a
// registry-metadata runner, so a new ecosystem cannot be added without an
// answer to "what happens when the package does not exist".

import (
	"context"
	"net/http"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// absentPackageEcosystems is every ecosystem registryMetadataProvider
// runs, split by whether a total upstream 404 is expected to mint the
// package-absent marker.
//
// The two exclusions are documented refusals, not oversights:
//
//	huggingface — a "version" is a git revision: a branch, a tag, or an
//	  arbitrary commit SHA, all equally valid pins. /api/models/{id}/refs
//	  can enumerate branches and tags but never commits, so a 404 cannot be
//	  told apart from "we pinned a SHA this replica has not fetched". No
//	  honest discriminator exists.
//	docker — runDocker already fetches the repository object and the
//	  per-tag object, and handles the pair inline; its absence evidence
//	  goes through versionNotFoundByProbeWarning, not through this path.
//	maven / gradle / go — FEDERATED. A 404 from the one registry this
//	  provider asks is not evidence that the package does not exist,
//	  because these ecosystems have no single canonical registry. See
//	  ecosystemHasSingleCanonicalRegistry and, for the production
//	  measurement that forced this, TestFederatedEcosystemsKeepNotFound.
var absentPackageEcosystems = []struct {
	eco       string
	pkg       string
	ver       string
	wantMoved bool
	why       string
}{
	// Group A — per-version endpoint plus a package-level probe.
	{"pypi", "requests-python", "1.0.0", true, "the vendor's ALLOW 92 (A) row"},
	{"rubygems", "colourama", "0.4.6", true, "the vendor's ALLOW 96 (A) row"},
	{"nuget", "Newtonsoft.Json.net", "13.0.3", true, "the vendor's ALLOW 86 (B) row"},
	{"cargo", "no-such-crate-xyz", "1.0.0", true, ""},
	// Federated ecosystems — see the single-canonical-registry rule.
	{"maven", "com.nope:nope", "1.0.0", false,
		"repo1 is one of several homes for a groupId, so its 404 is a statement about repo1"},
	{"go", "example.com/nope", "v1.0.0", false,
		"the module path is the identity; proxy.golang.org 404s private and vanity modules that exist"},
	// Group B — the packument IS the package object, so its 404 is
	// definitionally package-absence and needs no second request.
	{"npm", "no-such-package-xyz", "1.0.0", true, ""},
	{"composer", "nope/nope", "1.0.0", true, ""},
	{"cocoapods", "NoSuchPod", "1.0.0", true, ""},
	{"pub", "no_such_pub_pkg", "1.0.0", true, ""},
	// Documented refusals.
	{"huggingface", "nope/nope", "main", false,
		"a revision 404 cannot be told apart from an unfetched commit SHA"},
}

func TestAbsentPackageIsNotGradedClean(t *testing.T) {
	for _, tc := range absentPackageEcosystems {
		t.Run(tc.eco, func(t *testing.T) {
			// Nothing registered: every path 404s, which is what a
			// package nobody ever published looks like.
			p, _ := newStubProvider(t, http.NewServeMux())

			pr, err := p.Run(context.Background(), Request{Key: Key{
				Ecosystem: tc.eco, Package: tc.pkg, Version: tc.ver,
			}}, nil)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}

			got := hasWarningCode(pr, WarnPackageNotFound)
			if got != tc.wantMoved {
				t.Fatalf("package_not_found = %v, want %v (%s)\nwarnings: %+v",
					got, tc.wantMoved, tc.why, pr.Warnings)
			}
			if !tc.wantMoved {
				return
			}

			// End to end: the verdict a user actually sees. This is the
			// assertion the original TestVersionNotFoundNotEmittedOnPackage404
			// was missing — it said what must NOT happen and left the
			// ALLOW unstated.
			r := &Report{}
			r.Identity.Ecosystem = tc.eco
			r.Identity.Package = tc.pkg
			r.Identity.Version = tc.ver
			r.Observation.Warnings = pr.Warnings

			in := ProjectToRiskInput(r)
			if !in.SignalsUnavailable {
				t.Fatalf("SignalsUnavailable = false — a package that does not " +
					"exist would be scored off an empty Report")
			}
			ev := risk.EvaluatePackage(in, risk.Options{})
			if ev.Verdict != risk.VerdictUnknown {
				t.Fatalf("verdict = %q (overall %d), want unknown",
					ev.Verdict, ev.RolledUp.Overall)
			}
			// The secondary defect in the same run: every category
			// rendered as scanned. UnavailableEvaluation marks them all
			// DataAvailable=false, so list surfaces stop counting these
			// as covered.
			for cat, cs := range ev.RolledUp.Categories {
				if cs.DataAvailable {
					t.Errorf("category %s reports DataAvailable on a package "+
						"with zero upstream metadata", cat)
				}
			}
		})
	}
}

// An OUTAGE must keep today's behaviour on every one of those ecosystems.
// This is the false-positive rail: promoting an unanswered probe would
// convert every registry hiccup, private mirror and replication lag into
// an unknown verdict and a failed build.
func TestRegistryOutageDoesNotMintPackageNotFound(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusForbidden,
		http.StatusTooManyRequests, http.StatusBadGateway} {
		for _, tc := range absentPackageEcosystems {
			if !tc.wantMoved {
				continue
			}
			t.Run(tc.eco+"/"+http.StatusText(status), func(t *testing.T) {
				mux := http.NewServeMux()
				mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(status)
				})
				p, _ := newStubProvider(t, mux)
				pr, err := p.Run(context.Background(), Request{Key: Key{
					Ecosystem: tc.eco, Package: tc.pkg, Version: tc.ver,
				}}, nil)
				if err != nil {
					t.Fatalf("Run: %v", err)
				}
				if hasWarningCode(pr, WarnPackageNotFound) {
					t.Fatalf("a %d minted package_not_found — absence of evidence "+
						"is not evidence of absence: %+v", status, pr.Warnings)
				}
			})
		}
	}
}

// isDefiniteAbsence is the single allowlist both halves of the fix key on.
// It must stay an allowlist: a denylist would make any code added later
// default to "the package does not exist", which is the build-breaking
// direction.
func TestIsDefiniteAbsenceIsAnAllowlist(t *testing.T) {
	absent := []string{"not_found", "http_404"}
	present := []string{
		"", "http_500", "http_502", "http_503", "http_403", "http_429",
		"transport", "decode", "context_cancelled", "request_build",
		"registry_fetch_exhausted_retries", "timeline_fetch_failed",
		"timeout", "breaker_open", "rate_limited",
		"some_code_a_future_provider_invents",
	}
	for _, c := range absent {
		if !isDefiniteAbsence(&Warning{Code: c}) {
			t.Errorf("isDefiniteAbsence(%q) = false, want true", c)
		}
	}
	for _, c := range present {
		if isDefiniteAbsence(&Warning{Code: c}) {
			t.Errorf("isDefiniteAbsence(%q) = true — that code says nothing "+
				"about whether the package exists", c)
		}
	}
	if isDefiniteAbsence(nil) {
		t.Error("isDefiniteAbsence(nil) = true — nil means the registry answered 200")
	}
}
