package intelligence

// typosquatProvider wraps *typosquat.Detector. Supported ecosystems are
// the ones typosquat.EcosystemsWithTyposquatRisk() returns — the formats
// where similar-name attacks are meaningful. Apt / yum / dnf are
// explicitly omitted because their curated repositories make typosquat
// very unlikely (typosquat.IsLowRiskEcosystem).

import (
	"context"

	"github.com/chain305/chainsaw-core/typosquat"
)

// typosquatProvider contributes the SupplyChain.Typosquat* fields.
type typosquatProvider struct {
	detector *typosquat.Detector
}

func newTyposquatProvider(detector *typosquat.Detector) *typosquatProvider {
	return &typosquatProvider{detector: detector}
}

func (p *typosquatProvider) Name() string { return "typosquat" }

func (p *typosquatProvider) Signal() SignalMask { return SignalTyposquat }

// Tier: metadata-only, fans out in parallel with the other Tier-1 providers.
func (p *typosquatProvider) Tier() int { return 1 }

// NeedsArtifact is false — the check is name-only.
func (p *typosquatProvider) NeedsArtifact() bool { return false }

// supportedTyposquatEcosystems is the whitelist surfaced by
// typosquat.EcosystemsWithTyposquatRisk, precomputed as a set for O(1)
// Supports(). Kept package-level so a test can sanity-check shape.
var supportedTyposquatEcosystems = buildTyposquatEcosystemSet()

func buildTyposquatEcosystemSet() map[string]struct{} {
	ecos := typosquat.EcosystemsWithTyposquatRisk()
	m := make(map[string]struct{}, len(ecos))
	for _, e := range ecos {
		m[e] = struct{}{}
	}
	return m
}

// Supports returns true only for ecosystems in the detector's coverage
// list. Nil detector → always false.
func (p *typosquatProvider) Supports(ecosystem string) bool {
	if p.detector == nil {
		return false
	}
	if _, ok := supportedTyposquatEcosystems[ecosystem]; !ok {
		return false
	}
	return true
}

// Run runs Detector.Check and writes only SupplyChain.Typosquat* fields.
// Clean packages emit TyposquatStatus = "clean" so the UI can tell
// "scanned + cleared" from "never scanned".
func (p *typosquatProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if p.detector == nil {
		return PartialReport{}, nil
	}
	result := p.detector.Check(ctx, req.Key.Ecosystem, req.Key.Package)
	sc := &SupplyChainSection{}
	if result.IsSuspected {
		sc.TyposquatStatus = "suspected"
		sc.TyposquatConfidence = result.Confidence
		sc.TyposquatSimilarTo = result.SimilarTo
	} else {
		sc.TyposquatStatus = "clean"
	}
	return PartialReport{SupplyChain: sc}, nil
}

var _ Provider = (*typosquatProvider)(nil)
