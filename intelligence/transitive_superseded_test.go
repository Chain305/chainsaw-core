package intelligence

import (
	"context"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// supersededStore holds one dep row at a caller-chosen matcher epoch.
type supersededStore struct {
	key   Key
	epoch int
	// absent makes Get miss entirely, for the cold-cache control.
	absent bool
}

func (s *supersededStore) Get(_ context.Context, _ string, k Key) (*Report, error) {
	if s.absent || k != s.key {
		return nil, ErrNotFound
	}
	r := newReport(k.Ecosystem, k.Package, k.Version)
	r.Observation.MatcherEpoch = s.epoch
	ComputeTrustScore(r)
	return r, nil
}

func (s *supersededStore) ListVersions(_ context.Context, _, eco, name string) ([]string, error) {
	if s.absent || eco != s.key.Ecosystem || name != s.key.Package {
		return nil, nil
	}
	return []string{s.key.Version}, nil
}

func supersededRootWithDep(eco, depName, constraint string) *Report {
	root := newReport(eco, "app", "0.0.1")
	root.Metadata.LicenseExpression = "MIT"
	root.Dependencies.Direct = []DependencyRef{{Ecosystem: eco, Name: depName, Constraint: constraint}}
	ComputeTrustScore(root)
	return root
}

func warningCodes(r *Report) []string {
	out := make([]string, 0, len(r.Observation.Warnings))
	for _, w := range r.Observation.Warnings {
		out = append(out, w.Code)
	}
	return out
}

func warningWithCode(r *Report, code string) (string, bool) {
	for _, w := range r.Observation.Warnings {
		if w.Code == code {
			return w.Message, true
		}
	}
	return "", false
}

// A dep that IS cached but sits below the serve floor must report as
// superseded, not as absent. Before this split it reported "not in
// cache", which sent operators looking for a scan that had happened.
func TestTransitiveSupersededDepIsNotReportedAsUncached(t *testing.T) {
	store := &supersededStore{
		key:   Key{Ecosystem: "npm", Package: "left-pad", Version: "1.3.0"},
		epoch: CurrentMatcherEpoch - 1,
	}
	root := supersededRootWithDep("npm", "left-pad", "1.3.0")
	evaluateTransitiveRisk(context.Background(), store, "org", root)

	if _, ok := warningWithCode(root, WarnTransitiveDepNotCached); ok {
		t.Errorf("superseded dep reported as not-cached; warnings=%v", warningCodes(root))
	}
	msg, ok := warningWithCode(root, WarnTransitiveDepSuperseded)
	if !ok {
		t.Fatalf("no superseded warning emitted; warnings=%v", warningCodes(root))
	}
	// The message must name the epoch it found, or it is no more
	// diagnostic than the string it replaced.
	if !strings.Contains(msg, "left-pad") {
		t.Errorf("warning does not name the dep: %q", msg)
	}
	if !strings.Contains(msg, "epoch") {
		t.Errorf("warning does not report the row's epoch: %q", msg)
	}
}

// The cold-cache case must keep its original code — the split must not
// relabel genuine misses.
func TestTransitiveColdMissStillReportsNotCached(t *testing.T) {
	store := &supersededStore{absent: true}
	root := supersededRootWithDep("npm", "left-pad", "1.3.0")
	evaluateTransitiveRisk(context.Background(), store, "org", root)

	if _, ok := warningWithCode(root, WarnTransitiveDepSuperseded); ok {
		t.Errorf("cold miss mislabelled as superseded; warnings=%v", warningCodes(root))
	}
	if _, ok := warningWithCode(root, WarnTransitiveDepNotCached); !ok {
		t.Errorf("cold miss lost its not-cached warning; warnings=%v", warningCodes(root))
	}
}

// A current row must resolve normally and emit neither warning — proves
// the tests above are detecting the skip, not just any warning.
func TestTransitiveCurrentDepEmitsNeitherWarning(t *testing.T) {
	store := &supersededStore{
		key:   Key{Ecosystem: "npm", Package: "left-pad", Version: "1.3.0"},
		epoch: CurrentMatcherEpoch,
	}
	root := supersededRootWithDep("npm", "left-pad", "1.3.0")
	evaluateTransitiveRisk(context.Background(), store, "org", root)

	for _, code := range []string{WarnTransitiveDepSuperseded, WarnTransitiveDepNotCached} {
		if _, ok := warningWithCode(root, code); ok {
			t.Errorf("current dep emitted %s; warnings=%v", code, warningCodes(root))
		}
	}
}

// lookupDepReport's contract directly: supersession is reported only for
// an otherwise-clean miss, and a current row still wins.
func TestLookupDepReportOutcomes(t *testing.T) {
	ctx := context.Background()
	key := Key{Ecosystem: "npm", Package: "left-pad", Version: "1.3.0"}

	stale := &supersededStore{key: key, epoch: CurrentMatcherEpoch - 1}
	if _, _, outcome, _ := lookupDepReport(ctx, stale, "org", "npm", "left-pad", "1.3.0"); outcome != lookupSuperseded {
		t.Errorf("stale row: outcome = %v, want lookupSuperseded", outcome)
	}
	current := &supersededStore{key: key, epoch: CurrentMatcherEpoch}
	if _, r, outcome, _ := lookupDepReport(ctx, current, "org", "npm", "left-pad", "1.3.0"); outcome != lookupResolved || r == nil {
		t.Errorf("current row: outcome = %v (report nil: %v), want lookupResolved", outcome, r == nil)
	}
	cold := &supersededStore{absent: true}
	if _, _, outcome, _ := lookupDepReport(ctx, cold, "org", "npm", "left-pad", "1.3.0"); outcome != lookupNotCached {
		t.Errorf("cold cache: outcome = %v, want lookupNotCached", outcome)
	}
}

// A superseded dep must not be counted as resolved, and must not
// silently contribute a node to the graph. It is excluded, and the
// warning says so — the rollup being partial is the honest outcome
// while the recompute sweep drains.
func TestSupersededDepIsExcludedFromTheTree(t *testing.T) {
	store := &supersededStore{
		key:   Key{Ecosystem: "npm", Package: "left-pad", Version: "1.3.0"},
		epoch: CurrentMatcherEpoch - 1,
	}
	root := supersededRootWithDep("npm", "left-pad", "1.3.0")
	evaluateTransitiveRisk(context.Background(), store, "org", root)

	if n := len(root.Risk.Resolution.TransitiveBlame); n > 0 {
		t.Errorf("superseded dep contributed %d blame entries; it must be excluded from the tree", n)
	}
	if ts := root.Risk.Resolution.TransitiveSeverity; ts != (risk.TransitiveSeverity{}) {
		t.Errorf("superseded dep set TransitiveSeverity = %+v; it must be excluded from the tree", ts)
	}
}
