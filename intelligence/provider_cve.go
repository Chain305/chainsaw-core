package intelligence

// cveProvider reads the cached `vulnerability_metadata` row keyed by
// (orgID, repository, package, version). Trivy + EPSS write those rows
// out-of-band; this provider is a pure reader so the Scan fan-out never
// blocks on an upstream scanner.
//
// CVE/EPSS are format-agnostic: every chainsaw-supported ecosystem gets
// a row if the scanner has covered it. The ecosystem whitelist here
// mirrors malware's list so matrix cells stay aligned.

import (
	"context"
	"errors"

	"github.com/chain305/chainsaw-core/metadata"
)

// cveProvider surfaces vulnerability metadata into VulnSection.
type cveProvider struct {
	store *metadata.Store
}

func newCVEProvider(store *metadata.Store) *cveProvider {
	return &cveProvider{store: store}
}

func (p *cveProvider) Name() string { return "cve" }

func (p *cveProvider) Signal() SignalMask { return SignalCVE }

func (p *cveProvider) Tier() int { return 1 }

// NeedsArtifact is false — this is a DB read on metadata the async
// Trivy/EPSS scanners populate elsewhere.
func (p *cveProvider) NeedsArtifact() bool { return false }

// supportedCVEEcosystems mirrors malware's coverage list. Kept in-file
// so the matrix can evolve independently of the malware provider.
var supportedCVEEcosystems = map[string]struct{}{
	"npm": {}, "pip": {}, "pypi": {}, "rubygems": {}, "cargo": {},
	"composer": {}, "nuget": {}, "maven": {}, "gradle": {},
	"go": {}, "gomod": {}, "cocoapods": {}, "swift": {},
	"docker": {}, "huggingface": {}, "apt": {}, "yum": {}, "dnf": {},
	"yarn": {}, "bun": {}, "pub": {},
}

// Supports returns true for ecosystems the vulnerability scanners cover.
// Nil store → always false (disabled).
func (p *cveProvider) Supports(ecosystem string) bool {
	if p.store == nil {
		return false
	}
	_, ok := supportedCVEEcosystems[ecosystem]
	return ok
}

// Run reads vulnerability_metadata keyed by (RepoName, package, version).
// A missing row (ErrNotFound) means "not yet scanned" — normal startup
// state, not an error — so we return an empty PartialReport with no
// warning. A store that was constructed but has no live DB handle is
// treated the same as nil store (the metadata package guards this by
// returning metadata.ErrUnavailable). Other errors surface
// as a PartialReport warning so the Scanner picks them up.
func (p *cveProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if p.store == nil {
		return PartialReport{}, nil
	}
	orgStore := p.store.ForOrg(req.OrgID)
	if orgStore == nil {
		return PartialReport{}, nil
	}
	row, err := orgStore.GetVulnerabilityMetadata(req.RepoName, req.Key.Package, req.Key.Version)
	if err != nil {
		if errors.Is(err, metadata.ErrNotFound) {
			// No row yet — that's "not scanned", surface nothing.
			return PartialReport{}, nil
		}
		if errors.Is(err, metadata.ErrUnavailable) {
			// Nil-DB store → treat as "no data" rather than an error
			// warning. Happens during startup races and in unit tests
			// that wire a zero-value *metadata.Store.
			return PartialReport{}, nil
		}
		return PartialReport{}, err
	}
	vuln := &VulnSection{
		IsVulnerable:    row.IsVulnerable,
		CVSSScore:       row.CVSSScore,
		EPSSScore:       row.EPSSScore,
		CVEs:            row.CVEs,
		ScannerDBDigest: row.ScannerDBDigest,
		// CVEDetails carries per-CVE FixedVersion/FixAvailable. Trivy
		// ingestion now persists fix-version data into
		// vulnerability_metadata.cve_details — prefer that when present
		// and fall back to a per-CVE stub for legacy rows whose JSONB
		// column is still NULL.
		CVEDetails: cveDetailsFromRow(row),
	}
	if !row.ScannedAt.IsZero() {
		t := row.ScannedAt
		vuln.ScannedAt = &t
	}
	return PartialReport{Vulns: vuln}, nil
}

// cveDetailsFromRow projects the per-CVE detail slice the risk projector
// consumes. When the Trivy ingestion path persisted fix-version data into
// vulnerability_metadata.cve_details, that slice is the source of truth.
// Otherwise (legacy rows pre-dating PR 35dce29's wiring) we fall back to a
// stub-per-CVE so the slice keys 1:1 with CVEs and the fix-available risk
// signal stays dormant rather than panicking on nil.
func cveDetailsFromRow(row metadata.VulnerabilityMetadata) []CVEDetail {
	if len(row.CVEDetails) > 0 {
		out := make([]CVEDetail, len(row.CVEDetails))
		for i, d := range row.CVEDetails {
			out[i] = CVEDetail{
				CVE:          d.CVE,
				FixedVersion: d.FixedVersion,
				FixAvailable: d.FixAvailable,
			}
		}
		return out
	}
	return detailsFromCVEs(row.CVEs)
}

// detailsFromCVEs is the legacy-row fallback: a per-CVE stub keyed against
// the flat CVE ID list when no JSONB cve_details payload exists yet.
func detailsFromCVEs(cves []string) []CVEDetail {
	if len(cves) == 0 {
		return nil
	}
	out := make([]CVEDetail, len(cves))
	for i, id := range cves {
		out[i] = CVEDetail{CVE: id}
	}
	return out
}

var _ Provider = (*cveProvider)(nil)
