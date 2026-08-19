package intelligence

// Tests for L-01: a version that does not exist upstream must come back
// as NOT EVALUATED, never as a scored report.
//
// The load-bearing test in this file is the EMPTY-versions one. Emitting
// the marker is easy; NOT emitting it when the registry gave us a
// partial document is the whole reason the fix is safe to ship. Private
// mirrors, lagging replicas, and registries that prune yanked versions
// all serve documents with an empty or absent version list, and every
// one of them would become a build-breaking false positive if that guard
// regressed.

import (
	"context"
	"net/http"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// hasVersionNotFound reports whether the marker is present on a partial
// report.
func hasVersionNotFound(pr PartialReport) bool {
	for _, w := range pr.Warnings {
		if w.Code == WarnVersionNotFound {
			return true
		}
	}
	return false
}

// TestVersionNotFoundMarker walks all four Group-B (packument-style)
// runners. Group A (pypi/maven/cargo/rubygems/nuget/go/huggingface/
// docker) hits a per-version endpoint and is covered by the fetch
// layer's not_found warning instead — see the note on
// versionNotFoundWarning for why the two are deliberately distinct.
func TestVersionNotFoundMarker(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		body      string
		ecosystem string
		pkg       string
		version   string
		want      bool
		why       string
	}{
		{
			name:      "npm/absent version",
			path:      "/left-pad",
			body:      `{"name":"left-pad","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}}}`,
			ecosystem: "npm",
			pkg:       "left-pad",
			version:   "9.9.9",
			want:      true,
			why:       "packument listed 1.0.0 and nothing else",
		},
		{
			name:      "npm/empty versions map",
			path:      "/mirrored",
			body:      `{"name":"mirrored","dist-tags":{"latest":"1.0.0"},"versions":{}}`,
			ecosystem: "npm",
			pkg:       "mirrored",
			version:   "9.9.9",
			want:      false,
			why:       "an empty versions map is a partial document, not evidence of absence",
		},
		{
			name:      "npm/absent versions key",
			path:      "/keyless",
			body:      `{"name":"keyless","dist-tags":{"latest":"1.0.0"}}`,
			ecosystem: "npm",
			pkg:       "keyless",
			version:   "9.9.9",
			want:      false,
			why:       "no versions key at all is the same partial-document case",
		},
		{
			name:      "npm/present version",
			path:      "/present",
			body:      `{"name":"present","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}}}`,
			ecosystem: "npm",
			pkg:       "present",
			version:   "1.0.0",
			want:      false,
			why:       "the requested version is published",
		},
		{
			name:      "npm/v-prefixed pin against unprefixed publish",
			path:      "/vprefix",
			body:      `{"name":"vprefix","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}}}`,
			ecosystem: "npm",
			pkg:       "vprefix",
			version:   "v1.0.0",
			want:      false,
			why:       "a formatting difference is not a hallucinated version",
		},
		{
			name:      "composer/absent version",
			path:      "/p2/monolog/monolog.json",
			body:      `{"packages":{"monolog/monolog":[{"name":"monolog/monolog","version":"3.5.0"}]}}`,
			ecosystem: "composer",
			pkg:       "monolog/monolog",
			version:   "9.9.9",
			want:      true,
			why:       "packagist listed 3.5.0; the old code returned an empty report in silence",
		},
		{
			name:      "composer/empty release list",
			path:      "/p2/vendor/empty.json",
			body:      `{"packages":{"vendor/empty":[]}}`,
			ecosystem: "composer",
			pkg:       "vendor/empty",
			version:   "9.9.9",
			want:      false,
			why:       "no releases listed is a partial document",
		},
		{
			name:      "cocoapods/absent version",
			path:      "/api/v1/pods/AFNetworking",
			body:      `{"name":"AFNetworking","versions":[{"name":"4.0.0","created_at":"2020-01-01T00:00:00Z"}]}`,
			ecosystem: "cocoapods",
			pkg:       "AFNetworking",
			version:   "9.9.9",
			want:      true,
			why:       "trunk listed 4.0.0 and the runner had no match flag at all",
		},
		{
			name:      "cocoapods/empty version list",
			path:      "/api/v1/pods/Quiet",
			body:      `{"name":"Quiet","versions":[]}`,
			ecosystem: "cocoapods",
			pkg:       "Quiet",
			version:   "9.9.9",
			want:      false,
			why:       "no versions listed is a partial document",
		},
		{
			name: "pub/absent version",
			path: "/api/packages/http",
			body: `{"name":"http","latest":{"version":"1.2.0","published":"2024-01-01T00:00:00Z"},
				"versions":[{"version":"1.2.0","published":"2024-01-01T00:00:00Z","pubspec":{}}]}`,
			ecosystem: "pub",
			pkg:       "http",
			version:   "9.9.9",
			want:      true,
			why:       "pub computed `matched` already and used it only to pick a fallback date",
		},
		{
			name: "pub/absent from versions but named as latest",
			path: "/api/packages/skewed",
			body: `{"name":"skewed","latest":{"version":"2.0.0","published":"2024-01-01T00:00:00Z"},
				"versions":[{"version":"1.0.0","published":"2023-01-01T00:00:00Z","pubspec":{}}]}`,
			ecosystem: "pub",
			pkg:       "skewed",
			version:   "2.0.0",
			want:      false,
			why:       "`latest` naming the version is positive evidence of PRESENCE and outranks the miss",
		},
		{
			name:      "pub/empty version list",
			path:      "/api/packages/hollow",
			body:      `{"name":"hollow","latest":{"version":"1.0.0","published":"2024-01-01T00:00:00Z"},"versions":[]}`,
			ecosystem: "pub",
			pkg:       "hollow",
			version:   "9.9.9",
			want:      false,
			why:       "no versions listed is a partial document",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			body := tc.body
			mux.HandleFunc(tc.path, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			})
			p, _ := newStubProvider(t, mux)

			pr, err := p.Run(context.Background(), Request{Key: Key{
				Ecosystem: tc.ecosystem,
				Package:   tc.pkg,
				Version:   tc.version,
			}}, nil)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if got := hasVersionNotFound(pr); got != tc.want {
				t.Fatalf("version_not_found marker = %v, want %v (%s)\nwarnings: %+v",
					got, tc.want, tc.why, pr.Warnings)
			}
		})
	}
}

// TestVersionNotFoundNotEmittedOnFetchFailure pins the other half of the
// discriminator: an upstream that never answered is absence of evidence,
// and must keep whatever warning the fetch layer produced rather than
// being upgraded into a claim that the version does not exist.
func TestVersionNotFoundNotEmittedOnFetchFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/gone", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	p, _ := newStubProvider(t, mux)

	pr, err := p.Run(context.Background(), Request{Key: Key{
		Ecosystem: "npm", Package: "gone", Version: "9.9.9",
	}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasVersionNotFound(pr) {
		t.Fatalf("a 5xx must never produce version_not_found: %+v", pr.Warnings)
	}
}

// TestVersionNotFoundNotEmittedOnPackage404 pins the package-level 404,
// which the fetch layer already reports as not_found. Promoting it here
// would claim a version does not exist on the strength of a response
// that said nothing about versions at all.
func TestVersionNotFoundNotEmittedOnPackage404(t *testing.T) {
	// Nothing registered — every path 404s.
	p, _ := newStubProvider(t, http.NewServeMux())

	pr, err := p.Run(context.Background(), Request{Key: Key{
		Ecosystem: "npm", Package: "no-such-package", Version: "9.9.9",
	}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasVersionNotFound(pr) {
		t.Fatalf("a package-level 404 must never produce version_not_found: %+v", pr.Warnings)
	}
}

// TestProjectToRiskInputVersionNotFoundIsUnavailable asserts the
// projection refuses to hand the scorer packument-level facts about a
// version that does not exist. The Report below is deliberately loaded
// with plausible-looking data — a CVE-free vuln section, a maintainer
// count, a publish date — because that is exactly what the silent
// fallback produced, and every one of those fields belongs to a
// different version.
func TestProjectToRiskInputVersionNotFoundIsUnavailable(t *testing.T) {
	r := &Report{}
	r.Identity.Ecosystem = "npm"
	r.Identity.Package = "left-pad"
	r.Identity.Version = "9.9.9"
	r.Maintenance.MaintainerCount = 4
	r.Maintenance.Stars = 1200
	r.Vulnerabilities.CVEs = []string{"CVE-2024-0001"}
	r.Vulnerabilities.IsVulnerable = true
	r.Observation.Warnings = []Warning{{
		Provider: "registrymetadata",
		Code:     WarnVersionNotFound,
	}}

	in := ProjectToRiskInput(r)

	if !in.SignalsUnavailable {
		t.Fatalf("SignalsUnavailable = false; a non-existent version is NOT EVALUATED")
	}
	if in.UnavailableReason == "" {
		t.Fatalf("UnavailableReason must explain the miss to the operator")
	}
	// Identity survives so the evaluation can still be keyed and blamed.
	if in.Package != "left-pad" || in.Version != "9.9.9" || in.Ecosystem != "npm" {
		t.Fatalf("identity dropped: %+v", risk.Key{
			Ecosystem: in.Ecosystem, Package: in.Package, Version: in.Version,
		})
	}
	// Facts about the wrong version must not travel.
	if in.IsVulnerable || len(in.CVEs) != 0 {
		t.Fatalf("vulnerability facts carried through: IsVulnerable=%v CVEs=%v",
			in.IsVulnerable, in.CVEs)
	}
	if in.MaintainerCount != 0 || in.Stars != 0 {
		t.Fatalf("maintenance facts carried through: MaintainerCount=%d Stars=%d",
			in.MaintainerCount, in.Stars)
	}
}

// TestProjectToRiskInputUnrelatedWarningStillScores guards the blast
// radius: only the marker triggers the short-circuit. An unrelated
// provider warning must leave a normal, fully-populated projection.
func TestProjectToRiskInputUnrelatedWarningStillScores(t *testing.T) {
	r := &Report{}
	r.Identity.Ecosystem = "npm"
	r.Identity.Package = "left-pad"
	r.Identity.Version = "1.0.0"
	r.Maintenance.MaintainerCount = 4
	r.Observation.Warnings = []Warning{{
		Provider: "registrymetadata",
		Code:     "timeline_fetch_failed",
	}}

	in := ProjectToRiskInput(r)

	if in.SignalsUnavailable {
		t.Fatalf("an unrelated warning must not mark the coordinate unavailable")
	}
	if in.MaintainerCount != 4 {
		t.Fatalf("MaintainerCount = %d, want 4 (facts must still project)", in.MaintainerCount)
	}
}

// TestEvaluateVersionNotFoundIsUnknownVerdict is the end-to-end
// assertion the whole change exists for: the marker reaches the risk
// engine as an unknown verdict, which is what the CLI renders as
// "NOT EVALUATED" and what makes `intel scan` count the package toward
// INCOMPLETE and exit 2.
func TestEvaluateVersionNotFoundIsUnknownVerdict(t *testing.T) {
	r := &Report{}
	r.Identity.Ecosystem = "npm"
	r.Identity.Package = "left-pad"
	r.Identity.Version = "9.9.9"
	r.Observation.Warnings = []Warning{{
		Provider: "registrymetadata",
		Code:     WarnVersionNotFound,
	}}

	ev := risk.EvaluatePackage(ProjectToRiskInput(r), risk.Options{})

	if ev.Verdict != risk.VerdictUnknown {
		t.Fatalf("Verdict = %q, want %q", ev.Verdict, risk.VerdictUnknown)
	}
	// A fact-free report used to score 100/allow. Confirm it no longer
	// reads as a clean bill of health on any axis a consumer might use.
	if ev.RolledUp.Overall != 0 {
		t.Fatalf("Overall = %d, want 0 (read as \"no score\", not \"worst score\")",
			ev.RolledUp.Overall)
	}
	for cat, cs := range ev.RolledUp.Categories {
		if cs.DataAvailable {
			t.Fatalf("category %q reports DataAvailable=true for an unevaluated package", cat)
		}
	}
	if ev.Resolution.Summary == "" {
		t.Fatalf("Resolution.Summary must carry the operator-facing explanation")
	}
}
