package intelligence

import "testing"

// TestPublisherChangedRequiresEvidence pins the rule qual.version_anomaly
// already follows: a supply-chain fact fires on its evidence, not on a
// bare bool.
//
// Measured in production on 2026-09-05: 30 of the 66 rows carrying
// publisherChanged=true had BOTH publisherAdded and publisherRemoved
// empty, `requests 2.31.0` among them — the most-downloaded package on
// PyPI, capped at WARN 40 on a maintainer change nobody can name.
// provider_metadiff computes `changed := len(added) > 0 || len(removed) > 0`
// and always assigns it, so it cannot mint that shape; every one of those
// rows came from the sticky carry reviving the bool without its evidence.
func TestPublisherChangedRequiresEvidence(t *testing.T) {
	t.Parallel()

	withEvidence := &Report{}
	withEvidence.SupplyChain.PublisherChanged = boolp(true)
	withEvidence.SupplyChain.PublisherAdded = []string{"new-maintainer"}
	if !ProjectToRiskInput(withEvidence).PublisherChanged {
		t.Error("a publisher change WITH evidence stopped firing — this is the real signal")
	}

	removedOnly := &Report{}
	removedOnly.SupplyChain.PublisherChanged = boolp(true)
	removedOnly.SupplyChain.PublisherRemoved = []string{"old-maintainer"}
	if !ProjectToRiskInput(removedOnly).PublisherChanged {
		t.Error("a removal is evidence too")
	}

	evidenceless := &Report{}
	evidenceless.SupplyChain.PublisherChanged = boolp(true)
	if ProjectToRiskInput(evidenceless).PublisherChanged {
		t.Error("publisherChanged fired with no added and no removed maintainer — " +
			"that is a fact whose evidence was dropped, and it cannot bind a verdict")
	}

	clean := &Report{}
	clean.SupplyChain.PublisherChanged = boolp(false)
	clean.SupplyChain.PublisherAdded = []string{"stale"}
	if ProjectToRiskInput(clean).PublisherChanged {
		t.Error("an explicit false is an observation and must clear the signal")
	}
}

// The sticky carry must move the evidence with the bool, so a Tier-1-only
// refresh cannot mint the evidence-less shape the projection now rejects.
func TestStickyPublisherChangedCarriesItsEvidence(t *testing.T) {
	t.Parallel()

	prior := &Report{}
	prior.SupplyChain.PublisherChanged = boolp(true)
	prior.SupplyChain.PublisherAdded = []string{"new-maintainer"}
	prior.SupplyChain.PublisherRemoved = []string{"old-maintainer"}

	next := &Report{} // a refresh that never ran the metadiff provider
	applyStickySupplyChain(next, prior)

	if next.SupplyChain.PublisherChanged == nil || !*next.SupplyChain.PublisherChanged {
		t.Fatal("the bool was not carried")
	}
	if len(next.SupplyChain.PublisherAdded) != 1 || len(next.SupplyChain.PublisherRemoved) != 1 {
		t.Fatalf("evidence was dropped in transit: added=%v removed=%v",
			next.SupplyChain.PublisherAdded, next.SupplyChain.PublisherRemoved)
	}
	// And the carried fact must survive the projection it now has to satisfy.
	if !ProjectToRiskInput(next).PublisherChanged {
		t.Error("carried fact does not fire — the carry and the projection disagree")
	}
}
