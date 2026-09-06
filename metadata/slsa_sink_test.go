package metadata

import (
	"os"
	"strings"
	"testing"
)

// verifiedReport is a report from a coordinate whose Sigstore bundle actually
// verified. Nothing here may change.
func verifiedReport() SLSAReport {
	return SLSAReport{
		Ecosystem:                  "npm",
		Package:                    "good-pkg",
		Version:                    "1.0.0",
		ProvenanceStatus:           "verified",
		SLSALevel:                  3,
		AttestationBuilderID:       "https://github.com/slsa-framework/slsa-github-generator/...",
		AttestationIssuer:          "https://token.actions.githubusercontent.com",
		AttestationSourceRepo:      "https://github.com/acme/widgets",
		AttestationTransparencyLog: "https://search.sigstore.dev/?logIndex=1",
	}
}

func TestWithoutUnverifiedIdentityKeepsVerified(t *testing.T) {
	in := verifiedReport()
	got := in.WithoutUnverifiedIdentity()
	if got != in {
		t.Fatalf("verified report was modified.\n got: %+v\nwant: %+v", got, in)
	}
}

// TestWithoutUnverifiedIdentityStripsEveryNonVerifiedStatus is the write half
// of the fix. Each of these statuses reaches the sink carrying identity that
// no signature check validated — noteUnverifiedBundle's best-effort cert
// extraction, a gem-bundled x509 Subject CN, unauthenticated Swift registry
// JSON, or (the empty-status case) provider_registrymetadata writing the
// publisher's own repository.url purely so the UI can render it.
func TestWithoutUnverifiedIdentityStripsEveryNonVerifiedStatus(t *testing.T) {
	for _, status := range []string{"unverified", "failed", "missing", "unavailable", "", "  "} {
		in := verifiedReport()
		in.ProvenanceStatus = status
		got := in.WithoutUnverifiedIdentity()

		if got.AttestationBuilderID != "" {
			t.Errorf("status=%q: BuilderID survived as %q", status, got.AttestationBuilderID)
		}
		if got.AttestationIssuer != "" {
			t.Errorf("status=%q: Issuer survived as %q", status, got.AttestationIssuer)
		}
		if got.AttestationSourceRepo != "" {
			t.Errorf("status=%q: SourceRepo survived as %q", status, got.AttestationSourceRepo)
		}
		if got.AttestationTransparencyLog != "" {
			t.Errorf("status=%q: TransparencyLog survived as %q", status, got.AttestationTransparencyLog)
		}
		// The verdict itself is NOT rewritten — only identity is stripped.
		if got.ProvenanceStatus != status {
			t.Errorf("status=%q: status was rewritten to %q", status, got.ProvenanceStatus)
		}
		if got.SLSALevel != in.SLSALevel {
			t.Errorf("status=%q: SLSALevel changed %d -> %d", status, in.SLSALevel, got.SLSALevel)
		}
	}
}

// TestRegistryMetadataShapeProjectsNothing covers the widest poison source by
// row count: provider_registrymetadata.go builds a ProvenanceSection holding
// ONLY the publisher's repository.url, with no status at all. After stripping,
// the report has nothing left to say, so Project must short-circuit at
// HasAnyAttestationFields rather than write a policy-gated column.
func TestRegistryMetadataShapeProjectsNothing(t *testing.T) {
	r := SLSAReport{
		Ecosystem:             "npm",
		Package:               "lodash",
		Version:               "4.17.21",
		AttestationSourceRepo: "https://github.com/lodash/lodash",
	}
	if !r.HasAnyAttestationFields() {
		t.Fatal("precondition: the raw registry-metadata shape should look projectable")
	}
	if r.WithoutUnverifiedIdentity().HasAnyAttestationFields() {
		t.Error("registry-metadata report still projectable after stripping — " +
			"a display-only repository.url would reach attestation_source_repo")
	}
}

// TestProvenanceAuthoritativeGatesTheClear pins the one licence to write an
// EMPTY value over a stored one.
//
// ProjectSLSAFields is non-empty-wins everywhere else, which is why a single
// poisoned write used to be permanent. Identity columns are now cleared when
// the report is AUTHORITATIVE — it ran a provenance check and is stating the
// outcome. A report with an empty status has no opinion (an ecosystem with no
// checker, a registry-metadata provider) and must NOT be able to erase a
// genuine verified identity, so it keeps non-empty-wins.
func TestProvenanceAuthoritativeGatesTheClear(t *testing.T) {
	authoritative := []string{"verified", "unverified", "failed", "missing", "unavailable"}
	for _, s := range authoritative {
		if !(SLSAReport{ProvenanceStatus: s}).ProvenanceAuthoritative() {
			t.Errorf("status=%q: want authoritative", s)
		}
	}
	for _, s := range []string{"", "   "} {
		if (SLSAReport{ProvenanceStatus: s}).ProvenanceAuthoritative() {
			t.Errorf("status=%q: want NOT authoritative — a report with no opinion "+
				"must not clear a stored verified identity", s)
		}
	}

	// ProjectSLSAFields clears on (authoritative AND NOT verified) — the
	// two-term form matters. A VERIFIED report that simply carries no
	// identity (apt/yum are gpg-only; AttestationIssuer has no producer at
	// all today) is authoritative, and clearing on it would let two
	// providers for one coordinate flap the columns against each other.
	clears := func(status string) bool {
		r := SLSAReport{ProvenanceStatus: status}
		return r.ProvenanceAuthoritative() && !r.ProvenanceVerified()
	}
	for _, s := range []string{"unverified", "failed", "missing", "unavailable"} {
		if !clears(s) {
			t.Errorf("status=%q: must clear — this is the poison-retraction lane", s)
		}
	}
	for _, s := range []string{"verified", "", "   "} {
		if clears(s) {
			t.Errorf("status=%q: must NOT clear a stored identity", s)
		}
	}
}

// TestSLSAReportVerifiedLiteralMatchesProvenance pins the duplicated literal.
// core/metadata does not import core/provenance (the sink is deliberately
// dependency-light), so "verified" is spelled out in ProvenanceVerified. If
// the wire value is ever renamed, this gate would silently strip identity from
// EVERY report, including genuinely verified ones.
func TestSLSAReportVerifiedLiteralMatchesProvenance(t *testing.T) {
	const src = "../provenance/provenance.go"
	b, err := os.ReadFile(src)
	if err != nil {
		t.Skipf("cannot read %s: %v", src, err)
	}
	const want = `StatusVerified Status = "verified"`
	if !strings.Contains(string(b), want) {
		t.Fatalf("%s no longer declares %s — update SLSAReport.ProvenanceVerified too", src, want)
	}
}
