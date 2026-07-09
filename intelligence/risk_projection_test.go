package intelligence

import (
	"testing"
	"time"
)

func TestProjectToRiskInput_NilReport(t *testing.T) {
	// Must not panic; must return the zero Input so the evaluator is
	// safe to call unconditionally.
	in := ProjectToRiskInput(nil)
	if in.Ecosystem != "" || in.Package != "" || in.Version != "" {
		t.Fatalf("nil report should yield zero identity, got %+v", in)
	}
	if in.IsKnownMalicious || in.IsVulnerable || in.HasInstallScript {
		t.Fatalf("nil report should yield all-false bits, got %+v", in)
	}
}

func TestProjectToRiskInput_Malicious(t *testing.T) {
	r := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "evilpkg", Version: "1.0.0"},
		SupplyChain: SupplyChainSection{
			MalwareStatus:  "malicious",
			MalwareID:      "MAL-2025-0001",
			MalwareSummary: "cred stealer",
		},
	}
	in := ProjectToRiskInput(r)
	if !in.IsKnownMalicious {
		t.Fatalf("expected IsKnownMalicious=true")
	}
	if in.MalwareID != "MAL-2025-0001" {
		t.Fatalf("expected MalwareID propagated, got %q", in.MalwareID)
	}
	if in.MalwareSummary != "cred stealer" {
		t.Fatalf("expected MalwareSummary propagated, got %q", in.MalwareSummary)
	}
	if in.Ecosystem != "npm" || in.Package != "evilpkg" || in.Version != "1.0.0" {
		t.Fatalf("identity not propagated, got %+v", in)
	}
}

func TestProjectToRiskInput_CVE(t *testing.T) {
	r := &Report{
		Vulnerabilities: VulnSection{
			IsVulnerable: true,
			CVSSScore:    9.8,
			EPSSScore:    0.82,
			CVEs:         []string{"CVE-2025-1234", "CVE-2025-1235"},
		},
	}
	in := ProjectToRiskInput(r)
	if !in.IsVulnerable {
		t.Fatalf("IsVulnerable not propagated")
	}
	if in.MaxCVSS != 9.8 {
		t.Fatalf("MaxCVSS got %v, want 9.8", in.MaxCVSS)
	}
	if in.EPSSScore != 0.82 {
		t.Fatalf("EPSSScore got %v, want 0.82", in.EPSSScore)
	}
	if len(in.CVEs) != 2 || in.CVEs[0] != "CVE-2025-1234" {
		t.Fatalf("CVEs not propagated, got %v", in.CVEs)
	}
	// KEV is a known Phase-2 gap — must be false until a follow-up adds
	// the ingestion path.
	if in.KnownExploited {
		t.Fatalf("KnownExploited should default false in Phase 2")
	}
}

func TestProjectToRiskInput_FixAvailable(t *testing.T) {
	cases := []struct {
		name      string
		details   []CVEDetail
		wantFix   bool
		wantFixed []string
	}{
		{
			name:    "no details — no signal",
			details: nil,
			wantFix: false,
		},
		{
			name: "all unfixed",
			details: []CVEDetail{
				{CVE: "CVE-2025-1"},
				{CVE: "CVE-2025-2"},
			},
			wantFix: false,
		},
		{
			name: "single fixed CVE — fires",
			details: []CVEDetail{
				{CVE: "CVE-2025-1", FixedVersion: "1.2.3", FixAvailable: true},
			},
			wantFix:   true,
			wantFixed: []string{"CVE-2025-1"},
		},
		{
			name: "mixed (one fixed, one not) — fires",
			details: []CVEDetail{
				{CVE: "CVE-2025-1", FixedVersion: "1.2.3", FixAvailable: true},
				{CVE: "CVE-2025-2"},
			},
			wantFix:   true,
			wantFixed: []string{"CVE-2025-1"},
		},
		{
			name: "FixedVersion set without FixAvailable bool still fires",
			details: []CVEDetail{
				{CVE: "CVE-2025-1", FixedVersion: "2.0.0"},
			},
			wantFix:   true,
			wantFixed: []string{"CVE-2025-1"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &Report{
				Vulnerabilities: VulnSection{
					IsVulnerable: true,
					CVEDetails:   c.details,
				},
			}
			in := ProjectToRiskInput(r)
			if in.FixAvailable != c.wantFix {
				t.Fatalf("FixAvailable got %v want %v", in.FixAvailable, c.wantFix)
			}
			if len(in.FixedCVEs) != len(c.wantFixed) {
				t.Fatalf("FixedCVEs got %v want %v", in.FixedCVEs, c.wantFixed)
			}
			for i, cve := range c.wantFixed {
				if in.FixedCVEs[i] != cve {
					t.Fatalf("FixedCVEs[%d] got %q want %q", i, in.FixedCVEs[i], cve)
				}
			}
		})
	}
}

func TestProjectToRiskInput_PublisherChangedPointerDeref(t *testing.T) {
	changed := true
	r := &Report{
		SupplyChain: SupplyChainSection{PublisherChanged: &changed},
	}
	if !ProjectToRiskInput(r).PublisherChanged {
		t.Fatalf("PublisherChanged pointer=true should produce true")
	}

	unchanged := false
	r2 := &Report{
		SupplyChain: SupplyChainSection{PublisherChanged: &unchanged},
	}
	if ProjectToRiskInput(r2).PublisherChanged {
		t.Fatalf("PublisherChanged pointer=false should produce false")
	}

	// nil pointer must not panic and must produce false.
	r3 := &Report{SupplyChain: SupplyChainSection{PublisherChanged: nil}}
	if ProjectToRiskInput(r3).PublisherChanged {
		t.Fatalf("nil PublisherChanged pointer should yield false")
	}
}

func TestProjectToRiskInput_PublishVelocityFallback(t *testing.T) {
	// No explicit bool → fall back to the counter vs threshold (20).
	r := &Report{
		SupplyChain: SupplyChainSection{PublishVelocity24h: 25},
	}
	if !ProjectToRiskInput(r).PublishVelocityAnomaly {
		t.Fatalf("24h count above threshold should set PublishVelocityAnomaly")
	}

	// Counter at-or-below threshold → no anomaly.
	r2 := &Report{
		SupplyChain: SupplyChainSection{PublishVelocity24h: 15},
	}
	if ProjectToRiskInput(r2).PublishVelocityAnomaly {
		t.Fatalf("counter below threshold must NOT set anomaly")
	}

	// Explicit pointer overrides the counter either way.
	no := false
	r3 := &Report{
		SupplyChain: SupplyChainSection{
			PublishVelocity24h:     1000,
			PublishVelocityAnomaly: &no,
		},
	}
	if ProjectToRiskInput(r3).PublishVelocityAnomaly {
		t.Fatalf("explicit false pointer must override counter")
	}
}

func TestProjectToRiskInput_Typosquat(t *testing.T) {
	r := &Report{
		SupplyChain: SupplyChainSection{
			TyposquatStatus:     "suspected",
			TyposquatConfidence: "high",
			TyposquatSimilarTo:  "lodash",
		},
	}
	in := ProjectToRiskInput(r)
	if !in.IsSuspectedTyposquat {
		t.Fatalf("suspected typosquat should set IsSuspectedTyposquat")
	}
	if in.TyposquatConfidence != "high" {
		t.Fatalf("confidence got %q want high", in.TyposquatConfidence)
	}
	if in.TyposquatSimilarTo != "lodash" {
		t.Fatalf("similarTo got %q want lodash", in.TyposquatSimilarTo)
	}

	// "confirmed_safe" / "clean" must not set the bit.
	r2 := &Report{SupplyChain: SupplyChainSection{TyposquatStatus: "confirmed_safe"}}
	if ProjectToRiskInput(r2).IsSuspectedTyposquat {
		t.Fatalf("confirmed_safe must not set IsSuspectedTyposquat")
	}
}

func TestProjectToRiskInput_ProvenanceVerifiedEitherShape(t *testing.T) {
	// Path 1: Verified bool.
	r := &Report{Provenance: ProvenanceSection{Verified: true, Status: "unverified"}}
	if !ProjectToRiskInput(r).HasProvenance {
		t.Fatalf("Verified=true should set HasProvenance")
	}

	// Path 2: Status string.
	r2 := &Report{Provenance: ProvenanceSection{Verified: false, Status: "verified"}}
	if !ProjectToRiskInput(r2).HasProvenance {
		t.Fatalf(`Status="verified" should set HasProvenance`)
	}

	// Neither: must stay false.
	r3 := &Report{Provenance: ProvenanceSection{Status: "unverified"}}
	if ProjectToRiskInput(r3).HasProvenance {
		t.Fatalf("no verified signal should yield HasProvenance=false")
	}
}

func TestProjectToRiskInput_ChecksumMismatchInferred(t *testing.T) {
	// Declared != Actual, not verified → mismatch.
	r := &Report{Artifact: ArtifactSection{Digests: ArtifactDigest{
		Declared: "abc", Actual: "def", Verified: false,
	}}}
	if !ProjectToRiskInput(r).ChecksumMismatch {
		t.Fatalf("declared!=actual should flag mismatch")
	}

	// Verified overrides — never report mismatch on a verified digest.
	r2 := &Report{Artifact: ArtifactSection{Digests: ArtifactDigest{
		Declared: "abc", Actual: "def", Verified: true,
	}}}
	if ProjectToRiskInput(r2).ChecksumMismatch {
		t.Fatalf("Verified=true must suppress mismatch even with differing hashes")
	}

	// One side missing → ambiguous, not a mismatch.
	r3 := &Report{Artifact: ArtifactSection{Digests: ArtifactDigest{Declared: "abc"}}}
	if ProjectToRiskInput(r3).ChecksumMismatch {
		t.Fatalf("missing Actual must not count as mismatch")
	}
}

func TestProjectToRiskInput_PublishedAtPropagates(t *testing.T) {
	at := time.Now().Add(-24 * time.Hour)
	r := &Report{Release: ReleaseSection{PublishedAt: &at}}
	in := ProjectToRiskInput(r)
	if in.PublishedAt == nil || !in.PublishedAt.Equal(at) {
		t.Fatalf("PublishedAt not propagated: %+v", in.PublishedAt)
	}
}

// TestProjectToRiskInput_ActionsSection_Absent confirms the absence of
// an ActionsSection leaves every ActionRef* field at its zero value —
// the existing Wave 4 signals stay dormant for non-Action reports.
func TestProjectToRiskInput_ActionsSection_Absent(t *testing.T) {
	r := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
	}
	in := ProjectToRiskInput(r)
	if in.ActionRefUnpinned || in.ActionRefTyposquat || in.ActionRefUnknownPublisher || in.ActionRefMalicious {
		t.Fatalf("nil ActionsSection should leave ActionRef* booleans false, got %+v", in)
	}
	if len(in.ActionRefUnpinnedRefs) != 0 ||
		len(in.ActionRefTyposquats) != 0 ||
		len(in.ActionRefUnknownPublishers) != 0 ||
		len(in.ActionRefMaliciousRefs) != 0 {
		t.Fatalf("nil ActionsSection should leave ActionRef* slices empty, got %+v", in)
	}
}

// TestProjectToRiskInput_ActionsSection_Unpinned covers the simplest
// single-finding projection.
func TestProjectToRiskInput_ActionsSection_Unpinned(t *testing.T) {
	r := &Report{
		Actions: &ActionsSection{
			Findings: []ActionFinding{
				{Signal: "action.unpinned_ref", Severity: "medium", Ref: "actions/checkout@v4"},
			},
		},
	}
	in := ProjectToRiskInput(r)
	if !in.ActionRefUnpinned {
		t.Fatalf("expected ActionRefUnpinned=true")
	}
	if len(in.ActionRefUnpinnedRefs) != 1 || in.ActionRefUnpinnedRefs[0] != "actions/checkout@v4" {
		t.Fatalf("expected unpinned refs to contain checkout@v4, got %v", in.ActionRefUnpinnedRefs)
	}
	// Other Action signals must stay dormant.
	if in.ActionRefTyposquat || in.ActionRefUnknownPublisher {
		t.Fatalf("unrelated Action signals should not fire, got %+v", in)
	}
}

// TestProjectToRiskInput_ActionsSection_Mixed confirms each signal is
// projected independently and refs accumulate into their own slice.
func TestProjectToRiskInput_ActionsSection_Mixed(t *testing.T) {
	r := &Report{
		Actions: &ActionsSection{
			Findings: []ActionFinding{
				{Signal: "action.unpinned_ref", Ref: "actions/checkout@v4"},
				{Signal: "action.typosquat", Ref: "actoins/checkout@v4", Detail: "actions/checkout"},
				{Signal: "action.unknown_publisher", Ref: "randoorg/whatever@v1"},
				{Signal: "action.malicious", Ref: "evil/runner@v1", Detail: "cred stealer"},
			},
		},
	}
	in := ProjectToRiskInput(r)
	if !in.ActionRefUnpinned || !in.ActionRefTyposquat || !in.ActionRefUnknownPublisher || !in.ActionRefMalicious {
		t.Fatalf("expected all four Action booleans true, got %+v", in)
	}
	if len(in.ActionRefUnpinnedRefs) != 1 || in.ActionRefUnpinnedRefs[0] != "actions/checkout@v4" {
		t.Fatalf("unpinned refs wrong: %v", in.ActionRefUnpinnedRefs)
	}
	if len(in.ActionRefTyposquats) != 1 || in.ActionRefTyposquats[0] != "actoins/checkout@v4" {
		t.Fatalf("typosquat refs wrong: %v", in.ActionRefTyposquats)
	}
	if len(in.ActionRefUnknownPublishers) != 1 || in.ActionRefUnknownPublishers[0] != "randoorg/whatever@v1" {
		t.Fatalf("unknown-publisher refs wrong: %v", in.ActionRefUnknownPublishers)
	}
	if len(in.ActionRefMaliciousRefs) != 1 || in.ActionRefMaliciousRefs[0] != "evil/runner@v1" {
		t.Fatalf("malicious refs wrong: %v", in.ActionRefMaliciousRefs)
	}
	// IsKnownMalicious must NOT flip from a malicious Action finding —
	// it's only sourced from SupplyChainSection.MalwareStatus (a
	// package-level field). The Action-level boolean is the new
	// ActionRefMalicious pair, which is independent.
	if in.IsKnownMalicious {
		t.Fatalf("action.malicious finding should not flip IsKnownMalicious in projection")
	}
}

// TestProjectToRiskInput_ActionsSection_Malicious covers the
// single-finding malicious projection: only the ActionRefMalicious pair
// flips, and the other three Action signals stay dormant.
func TestProjectToRiskInput_ActionsSection_Malicious(t *testing.T) {
	r := &Report{
		Actions: &ActionsSection{
			Findings: []ActionFinding{
				{Signal: "action.malicious", Severity: "high", Ref: "evil/runner@v1", Detail: "cred stealer"},
			},
		},
	}
	in := ProjectToRiskInput(r)
	if !in.ActionRefMalicious {
		t.Fatalf("expected ActionRefMalicious=true")
	}
	if len(in.ActionRefMaliciousRefs) != 1 || in.ActionRefMaliciousRefs[0] != "evil/runner@v1" {
		t.Fatalf("expected malicious refs to contain evil/runner@v1, got %v", in.ActionRefMaliciousRefs)
	}
	if in.ActionRefUnpinned || in.ActionRefTyposquat || in.ActionRefUnknownPublisher {
		t.Fatalf("unrelated Action signals should not fire, got %+v", in)
	}
	if len(in.ActionRefUnpinnedRefs) != 0 ||
		len(in.ActionRefTyposquats) != 0 ||
		len(in.ActionRefUnknownPublishers) != 0 {
		t.Fatalf("unrelated Action ref slices should stay empty, got %+v", in)
	}
	// Package-level malware bool is independent — must stay false.
	if in.IsKnownMalicious {
		t.Fatalf("action.malicious must not flip package-level IsKnownMalicious")
	}
}

// TestProjectToRiskInput_ActionsSection_Dedupe confirms a ref appearing
// twice in findings is recorded once in the corresponding slice.
func TestProjectToRiskInput_ActionsSection_Dedupe(t *testing.T) {
	r := &Report{
		Actions: &ActionsSection{
			Findings: []ActionFinding{
				{Signal: "action.unpinned_ref", Ref: "actions/checkout@v4"},
				{Signal: "action.unpinned_ref", Ref: "actions/checkout@v4"},
				{Signal: "action.unpinned_ref", Ref: "actions/setup-node@v3"},
				{Signal: "action.unknown_publisher", Ref: "weirdorg/x@v1"},
				{Signal: "action.unknown_publisher", Ref: "weirdorg/x@v1"},
			},
		},
	}
	in := ProjectToRiskInput(r)
	if len(in.ActionRefUnpinnedRefs) != 2 {
		t.Fatalf("expected 2 unique unpinned refs, got %v", in.ActionRefUnpinnedRefs)
	}
	if len(in.ActionRefUnknownPublishers) != 1 {
		t.Fatalf("expected 1 unique unknown-publisher ref, got %v", in.ActionRefUnknownPublishers)
	}
}

// TestProjectToRiskInput_RepoArchivedThreeState pins down that the
// projection preserves the *bool tri-state instead of collapsing
// nil → false. A probe-failed Report (e.g. Bitbucket / private repo /
// rate-limit) must reach the risk engine as nil so the abandoned-repo
// signal can still fire on commit-staleness alone.
func TestProjectToRiskInput_RepoArchivedThreeState(t *testing.T) {
	tru := true
	fls := false

	cases := []struct {
		name string
		src  *bool
	}{
		{"nil stays nil", nil},
		{"true stays &true", &tru},
		{"false stays &false", &fls},
	}
	for _, tc := range cases {
		r := &Report{
			Maintenance: MaintenanceSection{RepoArchived: tc.src},
		}
		in := ProjectToRiskInput(r)
		if (in.RepoArchived == nil) != (tc.src == nil) {
			t.Errorf("%s: nil-ness changed (got %v, want %v)", tc.name, in.RepoArchived, tc.src)
			continue
		}
		if tc.src != nil && *in.RepoArchived != *tc.src {
			t.Errorf("%s: value changed (got %v, want %v)", tc.name, *in.RepoArchived, *tc.src)
		}
	}
}

// TestProjectToRiskInput_VulnDataAvailable exercises the data-available
// projection for CVE scans. Report.Vulnerabilities is a value type, so
// "scanner produced data" is signalled by VulnSection.ScannedAt being
// non-nil — provider_cve.go stamps that whenever vulnerability_metadata
// returned a row (including empty-CVE clean rows).
func TestProjectToRiskInput_VulnDataAvailable(t *testing.T) {
	t.Run("no scan — false", func(t *testing.T) {
		// Default zero VulnSection — no ScannedAt, no CVEs. Mirrors
		// the "CVE provider never produced a partial" state.
		in := ProjectToRiskInput(&Report{})
		if in.VulnDataAvailable {
			t.Fatalf("VulnDataAvailable must default false when no scan ran")
		}
	})
	t.Run("scanned but clean — true", func(t *testing.T) {
		// ScannedAt non-nil with empty CVE list — the CVE provider ran
		// and found nothing. Mirrors the "&VulnSection{} non-nil"
		// case the engine must treat as data-available.
		scanned := time.Date(2026, 5, 19, 0, 0, 0, 0, time.UTC)
		r := &Report{Vulnerabilities: VulnSection{ScannedAt: &scanned}}
		in := ProjectToRiskInput(r)
		if !in.VulnDataAvailable {
			t.Fatalf("VulnDataAvailable must be true when ScannedAt is set, even with no CVEs")
		}
	})
	t.Run("scanned with CVEs — true", func(t *testing.T) {
		scanned := time.Date(2026, 5, 19, 0, 0, 0, 0, time.UTC)
		r := &Report{Vulnerabilities: VulnSection{
			IsVulnerable: true,
			CVEs:         []string{"CVE-2026-1234"},
			ScannedAt:    &scanned,
		}}
		in := ProjectToRiskInput(r)
		if !in.VulnDataAvailable {
			t.Fatalf("VulnDataAvailable must be true when ScannedAt is set with CVEs")
		}
	})
}

// TestProjectToRiskInput_VersionDataAvailable covers the version
// timeline data-available bit. The intent: distinguish "we fetched the
// timeline and the package has N versions" from "we never fetched, so
// VersionCount=0 means unknown not zero".
func TestProjectToRiskInput_VersionDataAvailable(t *testing.T) {
	t.Run("no timeline — false", func(t *testing.T) {
		in := ProjectToRiskInput(&Report{})
		if in.VersionDataAvailable {
			t.Fatalf("VersionDataAvailable must default false with no timeline")
		}
	})
	t.Run("populated timeline — true", func(t *testing.T) {
		r := &Report{
			Maintenance: MaintenanceSection{
				VersionTimeline: []VersionRelease{
					{Version: "1.0.0"},
					{Version: "1.0.1"},
				},
			},
		}
		in := ProjectToRiskInput(r)
		if !in.VersionDataAvailable {
			t.Fatalf("VersionDataAvailable must be true when timeline is non-empty")
		}
	})
}

// TestProjectToRiskInput_RepoActivityPropagates covers the four GitHub
// repo-activity counts and FirstPublishedAt. The maintenance-grade
// signals consume these directly; the projection is a plain pass-through.
func TestProjectToRiskInput_RepoActivityPropagates(t *testing.T) {
	first := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	r := &Report{
		Maintenance: MaintenanceSection{
			Stars:            42,
			Forks:            7,
			OpenIssues:       3,
			Subscribers:      5,
			FirstPublishedAt: &first,
		},
	}
	in := ProjectToRiskInput(r)
	if in.Stars != 42 {
		t.Errorf("Stars got %d want 42", in.Stars)
	}
	if in.Forks != 7 {
		t.Errorf("Forks got %d want 7", in.Forks)
	}
	if in.OpenIssues != 3 {
		t.Errorf("OpenIssues got %d want 3", in.OpenIssues)
	}
	if in.Subscribers != 5 {
		t.Errorf("Subscribers got %d want 5", in.Subscribers)
	}
	if in.FirstPublishedAt == nil || !in.FirstPublishedAt.Equal(first) {
		t.Errorf("FirstPublishedAt got %v want %v", in.FirstPublishedAt, first)
	}
}
