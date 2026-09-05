package intelligence

// The single-canonical-registry rule (the P8-04 correction).
//
// P8-04 shipped `package_not_found` — operator text "no package by this
// name was found in the registry; check the spelling, or whether the name
// was invented by a model rather than published" — on ANY definite
// package-level 404. That premise only holds for an ecosystem with one
// canonical registry.
//
// Measured against the 2026-08-25 production export (7,099 rows): 1,699
// carry a registrymetadata `not_found` and grade allow, and 1,405 of those
// are real Android/AndroidX coordinates published to Google's Maven
// repository, which this provider never queries. Verified by hand:
//
//	repo1.maven.org   androidx/work/work-runtime/maven-metadata.xml -> 404
//	maven.google.com  androidx/work/work-runtime/maven-metadata.xml -> 301
//
// So under the unrestricted rule `androidx.work:work-runtime` — a
// dependency of a large fraction of all Android apps — was told its name
// may have been invented by a model. These tests pin both halves: the
// federated ecosystems keep the honest `not_found`, and the four genuine
// slopsquat coordinates from the same export still reach Unknown.

import (
	"context"
	"github.com/chain305/chainsaw-core/coverage"
	"net/http"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// registryEcosystemRule enumerates EVERY ecosystem registryMetadataProvider
// dispatches to, with the side of the rule it falls on and why. A new
// ecosystem cannot be added to the provider without answering "does a 404
// from the one registry we ask prove the package does not exist?".
var registryEcosystemRule = []struct {
	eco    string
	single bool
	why    string
}{
	{"npm", true, "registry.npmjs.org owns the whole bare-name namespace"},
	{"yarn", true, "yarn resolves against the npm registry"},
	{"bun", true, "bun resolves against the npm registry"},
	{"pypi", true, "pypi.org owns the whole project-name namespace"},
	{"pip", true, "alias of pypi"},
	{"cargo", true, "crates.io owns the whole crate-name namespace"},
	{"rubygems", true, "rubygems.org owns the whole gem-name namespace"},
	{"nuget", true, "nuget.org owns the whole package-id namespace"},
	{"composer", true, "packagist.org owns the whole vendor/package namespace"},
	{"cocoapods", true, "the CocoaPods trunk owns the whole pod-name namespace"},
	{"pub", true, "pub.dev owns the whole package-name namespace"},
	{"maven", false, "a groupId is a namespace, not a registry pointer: Central, maven.google.com, JitPack, corporate mirrors"},
	{"gradle", false, "same coordinates, same federation as maven"},
	{"go", false, "the module path is the identity; proxy.golang.org is a cache of public VCS, and GOPRIVATE/direct are first-class"},
	{"docker", false, "a coordinate names its own registry; Docker Hub is one of many"},
	{"huggingface", false, "a revision 404 cannot be told apart from an unfetched commit SHA"},
}

func TestSingleCanonicalRegistryRuleCoversEveryDispatchedEcosystem(t *testing.T) {
	classified := make(map[string]bool, len(registryEcosystemRule))
	for _, tc := range registryEcosystemRule {
		if got := ecosystemHasSingleCanonicalRegistry(tc.eco); got != tc.single {
			t.Errorf("ecosystemHasSingleCanonicalRegistry(%q) = %v, want %v (%s)",
				tc.eco, got, tc.single, tc.why)
		}
		classified[tc.eco] = true
	}
	// Every ecosystem the provider claims to support must appear above,
	// so the rule cannot silently default a new one to either side.
	for eco := range supportedRegistryEcosystems {
		if !classified[eco] {
			t.Errorf("%q is in supportedRegistryEcosystems but the "+
				"single-canonical-registry rule does not classify it — decide "+
				"whether a 404 from its one registry proves the package absent",
				eco)
		}
	}
	// And the allowlist may not name an ecosystem the provider never runs.
	for eco := range singleCanonicalRegistryEcosystems {
		if _, ok := supportedRegistryEcosystems[eco]; !ok {
			t.Errorf("singleCanonicalRegistryEcosystems lists %q, which the "+
				"provider does not dispatch", eco)
		}
	}
	if ecosystemHasSingleCanonicalRegistry("some-ecosystem-invented-later") {
		t.Error("the rule is not an allowlist — an unknown ecosystem must " +
			"default to the pre-P8-04 not_found, never to a claim of absence")
	}
}

// federatedAbsences are coordinates that 404 in the ONE registry this
// provider asks and are nonetheless real. androidx.work:work-runtime is
// the production case: 1,405 of the 1,699 `not_found` rows in the export
// are this shape.
var federatedAbsences = []struct {
	eco, pkg, ver string
}{
	{"gradle", "androidx.work:work-runtime", "2.11.2"},
	{"gradle", "com.android.tools.build:gradle", "8.5.0"},
	{"maven", "androidx.compose.ui:ui", "1.6.0"},
	{"go", "corp.example.com/internal/svc", "v1.2.3"},
}

// A federated ecosystem's total 404 keeps the pre-P8-04 `not_found`. That
// code says the true thing — "not found in the registry we checked" — and
// core/coverage classifies it as an OK answer.
//
// CHANGED DELIBERATELY IN PHASE 9 A8. Until then this test also asserted
// that the VERDICT was untouched, which is how `maven invalid:coord:format`
// came back ALLOW 96 (A) with four categories at their 100 base and no
// metadata behind any of them. The code is still the honest `not_found`
// and coverage still reads it as an answer — both asserted below, and both
// are what keep an opt-in fail-closed gate from refusing these installs —
// but the coordinate is now projected as an unavailable evaluation, so the
// verdict is NOT EVALUATED rather than a grade painted on nothing.
//
// The androidx population that motivated P8-04's restriction is answered
// upstream now: fetchMavenTimelineDoc falls back to maven.google.com for
// the namespaces Google hosts (TestGoogleMavenFallbackAnswersAndroidX).
// What still reaches this arm has been missed by BOTH repositories that
// serve the ecosystem — or is a private module, which the product has
// genuinely never evaluated and must not report as clean.
func TestFederatedEcosystemsKeepNotFound(t *testing.T) {
	for _, tc := range federatedAbsences {
		t.Run(tc.eco+"/"+tc.pkg, func(t *testing.T) {
			p, _ := newStubProvider(t, http.NewServeMux())
			pr, err := p.Run(context.Background(), Request{Key: Key{
				Ecosystem: tc.eco, Package: tc.pkg, Version: tc.ver,
			}}, nil)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if hasWarningCode(pr, WarnPackageNotFound) {
				t.Fatalf("%s/%s@%s was told its name may have been invented by "+
					"a model, but this registry is one of several homes for the "+
					"coordinate: %+v", tc.eco, tc.pkg, tc.ver, pr.Warnings)
			}
			if !hasWarningCode(pr, "not_found") {
				t.Fatalf("expected the honest not_found to survive, got %+v", pr.Warnings)
			}

			// The coverage gate must still read this as an ANSWER, not
			// an outage: that is what stops an org running the opt-in
			// fail-closed gate from refusing these installs.
			if coverage.StatusForWarnCode("not_found") != coverage.StatusOK {
				t.Fatal("not_found stopped being an OK coverage code — an org " +
					"with mode: closed would start refusing these installs")
			}

			// And the verdict IS now unavailable (A8). Nothing was
			// measured, so a grade here would be a default rather than a
			// finding.
			r := &Report{}
			r.Identity.Ecosystem = tc.eco
			r.Identity.Package = tc.pkg
			r.Identity.Version = tc.ver
			r.Observation.Warnings = pr.Warnings
			in := ProjectToRiskInput(r)
			if !in.SignalsUnavailable {
				t.Fatalf("%s/%s was scored off an empty fact set — no registry "+
					"metadata was retrieved, so the categories are 100 bases, "+
					"not measurements", tc.eco, tc.pkg)
			}
			if in.UnavailableReason == "" {
				t.Error("unavailable with no reason — the operator cannot act on that")
			}
		})
	}
}

// slopsquatCoordinates are the genuine article, taken verbatim from the
// same production export. Every one is inside the single-canonical set,
// which is the point: restricting the rule removes the false claim without
// touching the detection P8-04 exists for.
var slopsquatCoordinates = []struct {
	eco, pkg, ver string
}{
	{"npm", "leftpadd", "latest"},
	{"pip", "colourama", "latest"},
	{"pub", "htttp", "1.0.0"},
	{"pub", "flutter_secure_strorage", "1.0.0"},
}

func TestSlopsquatCoordinatesStillReachUnknown(t *testing.T) {
	for _, tc := range slopsquatCoordinates {
		t.Run(tc.eco+"/"+tc.pkg, func(t *testing.T) {
			p, _ := newStubProvider(t, http.NewServeMux())
			pr, err := p.Run(context.Background(), Request{Key: Key{
				Ecosystem: tc.eco, Package: tc.pkg, Version: tc.ver,
			}}, nil)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if !hasWarningCode(pr, WarnPackageNotFound) {
				t.Fatalf("%s/%s@%s lost package_not_found — this is the "+
					"slopsquat surface P8-04 exists for: %+v",
					tc.eco, tc.pkg, tc.ver, pr.Warnings)
			}
			r := &Report{}
			r.Identity.Ecosystem = tc.eco
			r.Identity.Package = tc.pkg
			r.Identity.Version = tc.ver
			r.Observation.Warnings = pr.Warnings
			in := ProjectToRiskInput(r)
			if !in.SignalsUnavailable {
				t.Fatalf("%s/%s would be scored off an empty Report", tc.eco, tc.pkg)
			}
			ev := risk.EvaluatePackage(in, risk.Options{})
			if ev.Verdict != risk.VerdictUnknown {
				t.Fatalf("verdict = %q (overall %d), want unknown",
					ev.Verdict, ev.RolledUp.Overall)
			}
		})
	}
}

// The restriction applies ONLY to the total-absence arm. A federated
// registry that DOES carry the package and enumerates its versions still
// answers the narrower question honestly, so a version genuinely absent
// from Maven Central keeps minting version_not_found.
func TestFederatedEcosystemStillReportsAnAbsentVersion(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/com/example/widget/maven-metadata.xml",
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<metadata><groupId>com.example</groupId>` +
				`<artifactId>widget</artifactId><versioning><versions>` +
				`<version>1.0.0</version><version>1.1.0</version>` +
				`</versions></versioning></metadata>`))
		})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{
		Ecosystem: "maven", Package: "com.example:widget", Version: "9.9.9",
	}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasVersionNotFound(pr) {
		t.Fatalf("the artifact exists and 9.9.9 is not among its published "+
			"versions, so version_not_found is still warranted: %+v", pr.Warnings)
	}
	if hasWarningCode(pr, WarnPackageNotFound) {
		t.Fatalf("the package-level document answered 200; nothing is absent "+
			"but the version: %+v", pr.Warnings)
	}
}
