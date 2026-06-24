package intelligence

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCursorRoundTrip(t *testing.T) {
	want := searchCursor{
		CollectedAt: time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
		Ecosystem:   "npm",
		Package:     "@scope/pkg",
		Version:     "1.2.3-alpha+build.4",
	}
	enc := encodeCursor(want)
	if enc == "" {
		t.Fatalf("encodeCursor produced empty string")
	}
	got, err := decodeCursor(enc)
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}
	if !got.CollectedAt.Equal(want.CollectedAt) {
		t.Fatalf("CollectedAt: got %v, want %v", got.CollectedAt, want.CollectedAt)
	}
	if got.Ecosystem != want.Ecosystem || got.Package != want.Package || got.Version != want.Version {
		t.Fatalf("cursor roundtrip mismatch: got %+v, want %+v", got, want)
	}
}

func TestDecodeCursor_RejectsInvalid(t *testing.T) {
	if _, err := decodeCursor("not-valid-base64!!!"); err == nil {
		t.Fatalf("expected error on invalid base64")
	}
	if _, err := decodeCursor("bm90LWpzb24"); err == nil {
		// "not-json" base64-encoded
		t.Fatalf("expected error on invalid JSON")
	}
}

func TestNewStore_NilSafe(t *testing.T) {
	var s *Store = NewStore(nil)
	if s == nil {
		t.Fatalf("NewStore(nil) returned nil — should return a non-nil store")
	}
	// All operations on a nil-underlying store should noop or return ErrNotFound.
	if _, err := s.Get(nil, "o", Key{Ecosystem: "npm", Package: "p", Version: "1"}); err != ErrNotFound {
		t.Fatalf("Get on empty store: got %v, want ErrNotFound", err)
	}
	if err := s.Upsert(nil, "o", &Report{}); err != nil {
		t.Fatalf("Upsert on empty store: got %v, want nil", err)
	}
	if r, err := s.Search(nil, SearchQuery{OrgID: "o"}); err != nil || r == nil {
		t.Fatalf("Search on empty store: got (%v, %v), want (non-nil, nil)", r, err)
	}
}

// TestMergeReportPayload_PreservesTier2 covers the Tier-2 preservation
// contract: when a Tier-1-only refresher tick is upserted over an existing
// Tier-2-rich proxy record, the prior row's Scan / Vulns / Maintenance
// timeline + repo-activity subtrees survive the merge.
//
// We exercise mergeReportPayload directly because the DB-backed Upsert
// requires a live Postgres handle. The merge function is the pure piece
// of the upsert path; the SQL wiring around it is a thin transaction
// wrapper that calls the same function with the prior row's JSONB.
func TestMergeReportPayload_PreservesTier2(t *testing.T) {
	scannedAt := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	firstPub := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Step 1: simulate a Tier-2-rich prior row — the proxy hot-path
	// produced a full ArtifactScanSection, a populated VulnSection with
	// CVE + KEV data, a multi-entry version timeline, and GitHub repo
	// activity counts.
	prior := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "left-pad", Version: "1.3.0"},
		Scan: ArtifactScanSection{
			Performed:            true,
			InstallScriptKind:    "preinstall-network",
			HasInstallScript:     true,
			InstallScriptFetches: true,
			HiddenUnicodeHits:    3,
			ScannedArtifactSHA:   "sha256:deadbeef",
		},
		Vulnerabilities: VulnSection{
			IsVulnerable:   true,
			CVSSScore:      9.8,
			CVEs:           []string{"CVE-2024-3651"},
			ScannedAt:      &scannedAt,
			KnownExploited: true,
			KEVEntries:     []KEVEntry{{CVE: "CVE-2024-3651", DateAdded: "2024-08-01"}},
		},
		Maintenance: MaintenanceSection{
			FirstPublishedAt: &firstPub,
			Stars:            42,
			Forks:            7,
			OpenIssues:       3,
			Subscribers:      5,
			VersionTimeline: []VersionRelease{
				{Version: "1.0.0"},
				{Version: "1.2.0"},
				{Version: "1.3.0"},
			},
		},
	}
	priorPayload, err := json.Marshal(prior)
	if err != nil {
		t.Fatalf("marshal prior: %v", err)
	}

	// Step 2: simulate a Tier-1-only refresher — the new report has
	// fresh identity / observation / metadata but explicitly does NOT
	// re-run the artifact scan or CVE provider. Without merging, this
	// would clobber every Tier-2 field above with a zero value.
	next := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "left-pad", Version: "1.3.0"},
		Metadata: MetadataSection{LicenseExpression: "MIT"},
		// Scan, Vulnerabilities, Maintenance timeline + repo activity
		// all intentionally left zero.
	}
	merged, err := mergeReportPayload(priorPayload, next)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}

	// Step 3: decode the merged payload and verify each preserved field.
	var got Report
	if err := json.Unmarshal(merged, &got); err != nil {
		t.Fatalf("unmarshal merged: %v", err)
	}

	// Scan subtree preserved.
	if got.Scan.InstallScriptKind != "preinstall-network" {
		t.Fatalf("Scan.InstallScriptKind clobbered: got %q want %q",
			got.Scan.InstallScriptKind, "preinstall-network")
	}
	if !got.Scan.Performed || !got.Scan.HasInstallScript ||
		!got.Scan.InstallScriptFetches || got.Scan.HiddenUnicodeHits != 3 {
		t.Fatalf("Scan subtree partially clobbered: got %+v", got.Scan)
	}
	if got.Scan.ScannedArtifactSHA != "sha256:deadbeef" {
		t.Fatalf("Scan.ScannedArtifactSHA lost, got %q", got.Scan.ScannedArtifactSHA)
	}

	// Vulnerabilities subtree preserved.
	if len(got.Vulnerabilities.CVEs) != 1 || got.Vulnerabilities.CVEs[0] != "CVE-2024-3651" {
		t.Fatalf("CVEs not preserved: got %+v", got.Vulnerabilities.CVEs)
	}
	if !got.Vulnerabilities.KnownExploited || got.Vulnerabilities.CVSSScore != 9.8 {
		t.Fatalf("Vuln scalar fields lost: got %+v", got.Vulnerabilities)
	}
	if len(got.Vulnerabilities.KEVEntries) != 1 ||
		got.Vulnerabilities.KEVEntries[0].CVE != "CVE-2024-3651" {
		t.Fatalf("KEVEntries lost: got %+v", got.Vulnerabilities.KEVEntries)
	}

	// Maintenance timeline + activity counts preserved.
	if len(got.Maintenance.VersionTimeline) != 3 {
		t.Fatalf("VersionTimeline preserved length: got %d want 3",
			len(got.Maintenance.VersionTimeline))
	}
	if got.Maintenance.FirstPublishedAt == nil ||
		!got.Maintenance.FirstPublishedAt.Equal(firstPub) {
		t.Fatalf("FirstPublishedAt lost: got %v", got.Maintenance.FirstPublishedAt)
	}
	if got.Maintenance.Stars != 42 || got.Maintenance.Forks != 7 ||
		got.Maintenance.OpenIssues != 3 || got.Maintenance.Subscribers != 5 {
		t.Fatalf("Maintenance activity lost: got %+v", got.Maintenance)
	}

	// Tier-1 fields from the new report survive unchanged (the merge
	// preserves Tier-2, not Tier-1).
	if got.Metadata.LicenseExpression != "MIT" {
		t.Fatalf("Tier-1 Metadata lost: got %+v", got.Metadata)
	}
}

// TestMergeReportPayload_NewReportWins is the counter-test: when the new
// report carries a populated Tier-2 subtree, the merge prefers the new
// value rather than holding the stale prior value. A freshly observed
// install-script kind must overwrite an older one.
func TestMergeReportPayload_NewReportWins(t *testing.T) {
	priorScan := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	prior := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "left-pad", Version: "1.3.0"},
		Scan: ArtifactScanSection{
			Performed:         true,
			InstallScriptKind: "preinstall-network",
		},
		Vulnerabilities: VulnSection{
			CVEs:      []string{"CVE-2024-3651"},
			ScannedAt: &priorScan,
		},
		Maintenance: MaintenanceSection{
			Stars: 42,
			VersionTimeline: []VersionRelease{
				{Version: "1.0.0"},
			},
		},
	}
	priorPayload, err := json.Marshal(prior)
	if err != nil {
		t.Fatalf("marshal prior: %v", err)
	}

	freshScan := time.Date(2026, 5, 19, 0, 0, 0, 0, time.UTC)
	next := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "left-pad", Version: "1.3.0"},
		Scan: ArtifactScanSection{
			Performed:         true,
			InstallScriptKind: "different-value",
		},
		Vulnerabilities: VulnSection{
			CVEs:      []string{"CVE-2026-0001"},
			ScannedAt: &freshScan,
		},
		Maintenance: MaintenanceSection{
			Stars: 100,
			VersionTimeline: []VersionRelease{
				{Version: "2.0.0"},
				{Version: "2.0.1"},
			},
		},
	}
	merged, err := mergeReportPayload(priorPayload, next)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	var got Report
	if err := json.Unmarshal(merged, &got); err != nil {
		t.Fatalf("unmarshal merged: %v", err)
	}

	if got.Scan.InstallScriptKind != "different-value" {
		t.Fatalf("merge held stale Scan: got %q want %q",
			got.Scan.InstallScriptKind, "different-value")
	}
	if len(got.Vulnerabilities.CVEs) != 1 || got.Vulnerabilities.CVEs[0] != "CVE-2026-0001" {
		t.Fatalf("merge held stale CVEs: got %+v", got.Vulnerabilities.CVEs)
	}
	if got.Maintenance.Stars != 100 {
		t.Fatalf("merge held stale Stars: got %d want 100", got.Maintenance.Stars)
	}
	if len(got.Maintenance.VersionTimeline) != 2 ||
		got.Maintenance.VersionTimeline[0].Version != "2.0.0" {
		t.Fatalf("merge held stale VersionTimeline: got %+v",
			got.Maintenance.VersionTimeline)
	}
}

// TestMergeReportPayload_FreshInsertPath ensures the merge is a no-op
// when there is no prior row — the payload is exactly the marshal of
// the new report, preserving the fresh-insert behaviour callers rely on.
func TestMergeReportPayload_FreshInsertPath(t *testing.T) {
	next := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "left-pad", Version: "1.3.0"},
		Metadata: MetadataSection{LicenseExpression: "MIT"},
	}
	want, err := json.Marshal(next)
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	got, err := mergeReportPayload(nil, next)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("fresh-insert path diverged:\n got=%s\nwant=%s", got, want)
	}
	// Empty (non-nil) prior payload should also fall through.
	got, err = mergeReportPayload([]byte{}, next)
	if err != nil {
		t.Fatalf("merge empty prior: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("empty-prior path diverged:\n got=%s\nwant=%s", got, want)
	}
}

// TestMergeReportPayload_EmptyButScannedVulnsWins covers the subtle
// case where a fresh scan ran and found NO CVEs (ScannedAt non-nil,
// CVEs empty). That section is authoritative — the prior section's
// CVEs must NOT be merged in, because doing so would resurrect CVEs
// the new scan implicitly cleared.
func TestMergeReportPayload_EmptyButScannedVulnsWins(t *testing.T) {
	priorScan := time.Date(2026, 5, 18, 0, 0, 0, 0, time.UTC)
	prior := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "p", Version: "1"},
		Vulnerabilities: VulnSection{
			IsVulnerable: true,
			CVEs:         []string{"CVE-2024-9999"},
			ScannedAt:    &priorScan,
		},
	}
	priorPayload, err := json.Marshal(prior)
	if err != nil {
		t.Fatalf("marshal prior: %v", err)
	}
	freshScan := time.Date(2026, 5, 19, 0, 0, 0, 0, time.UTC)
	next := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "p", Version: "1"},
		Vulnerabilities: VulnSection{
			// IsVulnerable defaults false, CVEs nil — but ScannedAt
			// is set, marking this as an authoritative clean scan.
			ScannedAt: &freshScan,
		},
	}
	merged, err := mergeReportPayload(priorPayload, next)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	var got Report
	if err := json.Unmarshal(merged, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Vulnerabilities.CVEs) != 0 {
		t.Fatalf("authoritative clean scan was overridden by stale CVEs: got %+v",
			got.Vulnerabilities.CVEs)
	}
	if got.Vulnerabilities.IsVulnerable {
		t.Fatalf("stale IsVulnerable resurrected by merge")
	}
	if got.Vulnerabilities.ScannedAt == nil || !got.Vulnerabilities.ScannedAt.Equal(freshScan) {
		t.Fatalf("fresh ScannedAt lost: got %v want %v",
			got.Vulnerabilities.ScannedAt, freshScan)
	}
}

// TestMergeReportPayload_PreservesArtifactSection covers the Tier-2/3
// preservation contract for the Artifact section: a Tier-1-only refresher
// must not blank out the Tier-2 checksum (Digests.Actual / Verified) or
// the Tier-3 signature verification result (SignatureVerified).
func TestMergeReportPayload_PreservesArtifactSection(t *testing.T) {
	tru := true
	prior := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "p", Version: "1"},
		Artifact: ArtifactSection{
			Filename: "p-1.tgz",
			Size:     1024,
			Digests: ArtifactDigest{
				Declared: "sha256:declared",
				Actual:   "sha256:abc",
				Verified: true,
			},
			SignatureVerified: &tru,
			SignatureKind:     "sigstore",
			SignatureKeyID:    "https://github.com/login/oauth",
		},
	}
	priorPayload, err := json.Marshal(prior)
	if err != nil {
		t.Fatalf("marshal prior: %v", err)
	}
	// Tier-1-only refresher: re-emits the registry-authoritative fields
	// (filename, size, declared digest) but the checksum provider +
	// signature verifier did not run.
	next := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "p", Version: "1"},
		Artifact: ArtifactSection{
			Filename: "p-1.tgz",
			Size:     1024,
			Digests:  ArtifactDigest{Declared: "sha256:declared"},
		},
	}
	merged, err := mergeReportPayload(priorPayload, next)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	var got Report
	if err := json.Unmarshal(merged, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Artifact.Digests.Actual != "sha256:abc" {
		t.Fatalf("Digests.Actual lost: got %q", got.Artifact.Digests.Actual)
	}
	if !got.Artifact.Digests.Verified {
		t.Fatalf("Digests.Verified lost")
	}
	if got.Artifact.SignatureVerified == nil || !*got.Artifact.SignatureVerified {
		t.Fatalf("SignatureVerified lost: got %v", got.Artifact.SignatureVerified)
	}
	if got.Artifact.SignatureKind != "sigstore" {
		t.Fatalf("SignatureKind lost: got %q", got.Artifact.SignatureKind)
	}
	if got.Artifact.SignatureKeyID != "https://github.com/login/oauth" {
		t.Fatalf("SignatureKeyID lost: got %q", got.Artifact.SignatureKeyID)
	}
	// Tier-1 authoritative fields must pass through from `next` unchanged
	// (this also exercises that the merge doesn't accidentally clobber
	// them with prior values).
	if got.Artifact.Filename != "p-1.tgz" || got.Artifact.Size != 1024 ||
		got.Artifact.Digests.Declared != "sha256:declared" {
		t.Fatalf("Tier-1 fields disturbed: got %+v", got.Artifact)
	}
}

// TestMergeReportPayload_PreservesSupplyChainTier3 covers the Tier-3
// enricher preservation: RepoLinkStatus (repo-link probe), PublisherChanged
// (metadiff), and the sticky-true semantics that keep "observed once"
// signals from being silently withdrawn by a Tier-1-only refresher.
func TestMergeReportPayload_PreservesSupplyChainTier3(t *testing.T) {
	tru := true
	lastCommit := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	prior := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "p", Version: "1"},
		SupplyChain: SupplyChainSection{
			MalwareStatus:    "clean",
			TyposquatStatus:  "clean",
			RepoLinkStatus:   "ok",
			RepoLastCommitAt: &lastCommit,
			PublisherChanged: &tru,
			VersionAnomaly:   &tru,
			TrustScore:       72,
		},
	}
	priorPayload, err := json.Marshal(prior)
	if err != nil {
		t.Fatalf("marshal prior: %v", err)
	}
	// Tier-1-only refresher emits a fresh TrustScore (always recomputed)
	// but every Tier-3 field is left empty.
	next := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "p", Version: "1"},
		SupplyChain: SupplyChainSection{
			TrustScore: 84,
		},
	}
	merged, err := mergeReportPayload(priorPayload, next)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	var got Report
	if err := json.Unmarshal(merged, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SupplyChain.RepoLinkStatus != "ok" {
		t.Fatalf("RepoLinkStatus lost: got %q", got.SupplyChain.RepoLinkStatus)
	}
	if got.SupplyChain.RepoLastCommitAt == nil || !got.SupplyChain.RepoLastCommitAt.Equal(lastCommit) {
		t.Fatalf("RepoLastCommitAt lost: got %v", got.SupplyChain.RepoLastCommitAt)
	}
	if got.SupplyChain.PublisherChanged == nil || !*got.SupplyChain.PublisherChanged {
		t.Fatalf("PublisherChanged not sticky-true: got %v", got.SupplyChain.PublisherChanged)
	}
	if got.SupplyChain.VersionAnomaly == nil || !*got.SupplyChain.VersionAnomaly {
		t.Fatalf("VersionAnomaly not sticky-true: got %v", got.SupplyChain.VersionAnomaly)
	}
	if got.SupplyChain.MalwareStatus != "clean" || got.SupplyChain.TyposquatStatus != "clean" {
		t.Fatalf("Malware/Typosquat status lost: got %+v", got.SupplyChain)
	}
	// TrustScore is recomputed every scan — must reflect the incoming value.
	if got.SupplyChain.TrustScore != 84 {
		t.Fatalf("TrustScore should pass through new (not preserved): got %d want 84",
			got.SupplyChain.TrustScore)
	}
}

// TestMergeReportPayload_PreservesPeople covers preservation of the
// publisher-set fields. The Tier-3 FirstTimeCollaborator path diffs
// prior.People against next.People, so a Tier-1 refresher whose registry
// call failed must not silently empty these lists.
func TestMergeReportPayload_PreservesPeople(t *testing.T) {
	tru := true
	prior := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "p", Version: "1"},
		People: PeopleSection{
			Authors:          []string{"alice"},
			Maintainers:      []string{"a", "b", "c"},
			PublisherIDs:     []string{"npm:alice"},
			TrustedPublisher: &tru,
		},
	}
	priorPayload, err := json.Marshal(prior)
	if err != nil {
		t.Fatalf("marshal prior: %v", err)
	}
	next := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "p", Version: "1"},
		People:   PeopleSection{},
	}
	merged, err := mergeReportPayload(priorPayload, next)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	var got Report
	if err := json.Unmarshal(merged, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.People.Maintainers) != 3 {
		t.Fatalf("Maintainers lost: got %+v", got.People.Maintainers)
	}
	if len(got.People.Authors) != 1 || got.People.Authors[0] != "alice" {
		t.Fatalf("Authors lost: got %+v", got.People.Authors)
	}
	if len(got.People.PublisherIDs) != 1 {
		t.Fatalf("PublisherIDs lost: got %+v", got.People.PublisherIDs)
	}
	if got.People.TrustedPublisher == nil || !*got.People.TrustedPublisher {
		t.Fatalf("TrustedPublisher lost: got %v", got.People.TrustedPublisher)
	}
}

// TestMergeReportPayload_PreservesProvenance covers the sigstore + Tier-3
// signature-verify enricher preservation. An empty Provenance section in
// `next` must not blank out the prior verified attestation.
func TestMergeReportPayload_PreservesProvenance(t *testing.T) {
	prior := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "p", Version: "1"},
		Provenance: ProvenanceSection{
			Kind:       "sigstore",
			Verified:   true,
			SourceRepo: "github.com/foo/bar",
			BundleURL:  "https://example.test/bundle.json",
			SLSALevel:  3,
		},
	}
	priorPayload, err := json.Marshal(prior)
	if err != nil {
		t.Fatalf("marshal prior: %v", err)
	}
	next := &Report{
		Identity:   IdentitySection{Ecosystem: "npm", Package: "p", Version: "1"},
		Provenance: ProvenanceSection{},
	}
	merged, err := mergeReportPayload(priorPayload, next)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	var got Report
	if err := json.Unmarshal(merged, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Provenance.Kind != "sigstore" {
		t.Fatalf("Provenance.Kind lost: got %q", got.Provenance.Kind)
	}
	if !got.Provenance.Verified {
		t.Fatalf("Provenance.Verified not sticky-true")
	}
	if got.Provenance.SourceRepo != "github.com/foo/bar" {
		t.Fatalf("Provenance.SourceRepo lost: got %q", got.Provenance.SourceRepo)
	}
	if got.Provenance.BundleURL != "https://example.test/bundle.json" {
		t.Fatalf("Provenance.BundleURL lost: got %q", got.Provenance.BundleURL)
	}
	if got.Provenance.SLSALevel != 3 {
		t.Fatalf("Provenance.SLSALevel lost: got %d", got.Provenance.SLSALevel)
	}
}

// TestMergeReportPayload_NewProvenanceWins is the counter-test for the
// Provenance preservation rules: when the incoming report carries a
// populated Provenance.Kind, the new value must win — preservation only
// kicks in when the new section is empty.
func TestMergeReportPayload_NewProvenanceWins(t *testing.T) {
	prior := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "p", Version: "1"},
		Provenance: ProvenanceSection{
			Kind:       "sigstore",
			Verified:   true,
			SourceRepo: "github.com/foo/old",
			SLSALevel:  3,
		},
	}
	priorPayload, err := json.Marshal(prior)
	if err != nil {
		t.Fatalf("marshal prior: %v", err)
	}
	next := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "p", Version: "1"},
		Provenance: ProvenanceSection{
			Kind:       "x509",
			SourceRepo: "github.com/foo/new",
			SLSALevel:  2,
			// Verified intentionally false — but Kind is non-empty so
			// preservation does NOT kick in here; the new section is
			// authoritative.
		},
	}
	merged, err := mergeReportPayload(priorPayload, next)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	var got Report
	if err := json.Unmarshal(merged, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Provenance.Kind != "x509" {
		t.Fatalf("merge held stale Provenance.Kind: got %q want %q",
			got.Provenance.Kind, "x509")
	}
	if got.Provenance.SourceRepo != "github.com/foo/new" {
		t.Fatalf("merge held stale Provenance.SourceRepo: got %q",
			got.Provenance.SourceRepo)
	}
	if got.Provenance.SLSALevel != 2 {
		t.Fatalf("merge held stale Provenance.SLSALevel: got %d", got.Provenance.SLSALevel)
	}
	// Verified is sticky-true: prior was true, incoming false, so the
	// merged blob preserves true. This is the documented semantic — a
	// fresh observation that clears verification must be expressed via
	// an explicit empty-section refresh, not by re-emitting the section
	// with Verified=false alongside other populated fields.
	if !got.Provenance.Verified {
		t.Fatalf("Provenance.Verified should be sticky-true through field-level merge")
	}
}
