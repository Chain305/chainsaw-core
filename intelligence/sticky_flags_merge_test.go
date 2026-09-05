package intelligence

import (
	"encoding/json"
	"testing"
)

// The sticky-true merge rules for *bool supply-chain flags.
//
// "Sticky-true" here means sticky ON SILENCE, not sticky forever. A
// Tier-1-only refresh that never ran the metadiff provider leaves the
// pointer nil and must not flip a prior observation off. An explicit
// incoming false is a real observation and must clear it.
//
// The distinction is the whole of P8-35. That item was filed claiming
// sc.publisher_changed is "sticky-true forever", so a legitimate one-time
// maintainer handover pins a package at WARN indefinitely. It does not:
// provider_metadiff.go computes `changed := len(added) > 0 || len(removed)
// > 0` and ALWAYS assigns it, so the next scan that sees an unchanged
// publisher set returns the package to clean. The claim came from the
// merge function's own comment, which described a stronger rule than the
// code implemented.
//
// These tests exist so nobody closes that gap in the wrong direction.
// Making the comment true would create the bug it describes.
func mergeSticky(t *testing.T, prior, next *Report) Report {
	t.Helper()
	priorBytes, err := json.Marshal(prior)
	if err != nil {
		t.Fatal(err)
	}
	out, err := mergeReportPayload(priorBytes, next)
	if err != nil {
		t.Fatal(err)
	}
	var got Report
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func boolp(b bool) *bool { return &b }

func TestPublisherChangedClearsOnExplicitFalse(t *testing.T) {
	got := mergeSticky(t,
		&Report{SupplyChain: SupplyChainSection{PublisherChanged: boolp(true)}},
		&Report{SupplyChain: SupplyChainSection{PublisherChanged: boolp(false)}},
	)
	if got.SupplyChain.PublisherChanged == nil {
		t.Fatal("PublisherChanged became nil; an explicit observation must survive the merge")
	}
	if *got.SupplyChain.PublisherChanged {
		t.Error("an explicit incoming false did not clear a prior true.\n" +
			"That is the P8-35 bug: a package that had ONE legitimate maintainer " +
			"handover would stay flagged forever with no path back to clean.")
	}
}

func TestPublisherChangedSurvivesSilence(t *testing.T) {
	// With its evidence, as provider_metadiff always emits it: `changed`
	// is derived from these lists, so a true without them is a shape the
	// provider cannot produce and the sticky rule declines to revive.
	got := mergeSticky(t,
		&Report{SupplyChain: SupplyChainSection{
			PublisherChanged: boolp(true),
			PublisherAdded:   []string{"new-maintainer"},
		}},
		&Report{SupplyChain: SupplyChainSection{PublisherChanged: nil}},
	)
	if got.SupplyChain.PublisherChanged == nil || !*got.SupplyChain.PublisherChanged {
		t.Error("a Tier-1-only refresh (nil, i.e. no observation) withdrew a prior true.\n" +
			"Silence from one tier is not evidence the observation was retracted.")
	}
}

// VersionAnomaly is the other *bool on this rule and must behave identically.
func TestVersionAnomalyFollowsTheSameStickyRule(t *testing.T) {
	cleared := mergeSticky(t,
		&Report{SupplyChain: SupplyChainSection{VersionAnomaly: boolp(true)}},
		&Report{SupplyChain: SupplyChainSection{VersionAnomaly: boolp(false)}},
	)
	if cleared.SupplyChain.VersionAnomaly == nil || *cleared.SupplyChain.VersionAnomaly {
		t.Error("explicit false did not clear VersionAnomaly")
	}
	// With its flags, as the provider always emits it: the signal fires on
	// `len(flags) > 0`, so a flagless true is inert for enforcement, and
	// the sticky rule declines to revive an anomaly it cannot name.
	kept := mergeSticky(t,
		&Report{SupplyChain: SupplyChainSection{
			VersionAnomaly:      boolp(true),
			VersionAnomalyFlags: []string{"version_gap"},
		}},
		&Report{SupplyChain: SupplyChainSection{VersionAnomaly: nil}},
	)
	if kept.SupplyChain.VersionAnomaly == nil || !*kept.SupplyChain.VersionAnomaly {
		t.Error("silence withdrew a prior VersionAnomaly observation")
	}
}

// The flagless half, which is what 117 of the 1,157 flagged production
// rows looked like: the bool alone is not an observation, and reviving it
// would leave the row claiming an anomaly its own verdict never saw.
func TestVersionAnomalyWithoutFlagsIsNotRevived(t *testing.T) {
	got := mergeSticky(t,
		&Report{SupplyChain: SupplyChainSection{VersionAnomaly: boolp(true)}},
		&Report{SupplyChain: SupplyChainSection{VersionAnomaly: nil}},
	)
	if got.SupplyChain.VersionAnomaly != nil && *got.SupplyChain.VersionAnomaly {
		t.Error("a flagless versionAnomaly=true was revived; the stored row would " +
			"claim an anomaly the evaluation could not see")
	}
}
