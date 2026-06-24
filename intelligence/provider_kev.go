package intelligence

// kevProvider cross-references the merged CVE list against CISA's
// Known Exploited Vulnerabilities catalog. A match means the CVE is
// actively exploited in the wild and should dominate the vuln signal
// weight in the risk engine (vuln-kev).
//
// This is a Tier-3 provider: it needs the CVE provider's merged output
// on the prior Report, so it runs after the Tier-1/2 fan-out converges.
// The brief initially labelled it Tier-1, but Tier-1 workers receive
// nil as `prior`, which would prevent any lookup. Tier-3 is the only
// placement where Run can read r.Vulnerabilities.CVEs.
//
// The KEV index is lazy-loaded on first use; a fetch failure keeps the
// last-known snapshot (or serves empty) so startup never blocks and
// transient network trouble never fails a scan.

import (
	"context"

	"github.com/chain305/chainsaw-core/kev"
)

type kevProvider struct {
	idx *kev.Index
}

func newKEVProvider(idx *kev.Index) *kevProvider {
	return &kevProvider{idx: idx}
}

func (p *kevProvider) Name() string { return "kev" }

func (p *kevProvider) Signal() SignalMask { return SignalKEV }

// Tier 3: needs the merged CVE list from prior.Vulnerabilities.CVEs.
func (p *kevProvider) Tier() int { return 3 }

// NeedsArtifact is false — pure index lookup on CVE IDs.
func (p *kevProvider) NeedsArtifact() bool { return false }

// Supports returns true for every ecosystem — CVE identifiers are
// format-agnostic. The provider no-ops when the prior CVE list is
// empty, so ecosystems without any CVE coverage pay nothing.
func (p *kevProvider) Supports(ecosystem string) bool {
	return p.idx != nil
}

// Run scans prior.Vulnerabilities.CVEs against the KEV index. Every
// match appends a KEVEntry and flips KnownExploited on the returned
// VulnSection patch. Non-matches are silent — a clean CVE list is the
// common case and shouldn't noise the merge path.
func (p *kevProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if p.idx == nil || prior == nil {
		return PartialReport{}, nil
	}
	// Offline-first refresh: when running air-gapped, load the KEV
	// snapshot from the active intelligence bundle (W4) rather than
	// hitting cisa.gov. The bundle ships the same JSON shape, so the
	// kev.Index.LoadFromJSON path handles parsing.
	if IsOffline() {
		if b := ActiveBundle(); b != nil {
			if data := b.File("kev"); len(data) > 0 {
				_ = p.idx.LoadFromJSON(data)
			}
		}
		// No fail-closed escalation here: kev is layered on top of CVE
		// matches that themselves degrade to SevUnknown when no bundle
		// data is present, so an empty index is the right zero state.
	} else if err := p.idx.EnsureFresh(ctx); err != nil {
		// Best-effort lazy refresh; never fail the scan on a fetch
		// error. Degrade silently with the in-memory snapshot.
		_ = err
	}

	cves := prior.Vulnerabilities.CVEs
	if len(cves) == 0 {
		return PartialReport{}, nil
	}

	var matched []KEVEntry
	for _, cve := range cves {
		if entry, ok := p.idx.Lookup(cve); ok {
			matched = append(matched, KEVEntry{
				CVE:                        entry.CVE,
				DateAdded:                  entry.DateAdded,
				KnownRansomwareCampaignUse: entry.KnownRansomwareCampaignUse,
			})
		}
	}
	if len(matched) == 0 {
		return PartialReport{}, nil
	}

	// Emit a VulnSection patch that preserves every field the CVE
	// provider populated and layers the KEV verdict on top. The merge
	// helper for Vulns is a wholesale replacement today, so we copy
	// the prior slice forward rather than dropping it.
	vuln := prior.Vulnerabilities
	vuln.KnownExploited = true
	vuln.KEVEntries = matched
	return PartialReport{Vulns: &vuln}, nil
}

var _ Provider = (*kevProvider)(nil)
