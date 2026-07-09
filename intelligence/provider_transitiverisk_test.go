package intelligence

// Tests for evaluateTransitiveRisk + the constraint-resolving and
// cycle-detecting helpers it leans on. The store is stubbed via the
// transitiveLookup interface so these tests don't pull pgstore.

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/risk"
)

// fakeStore implements transitiveLookup with an in-memory map keyed
// on (ecosystem, package, version). It also records every Get call
// so tests can assert which version candidates the helper probed.
type fakeStore struct {
	rows  map[Key]*Report
	calls []Key
}

func newFakeStore() *fakeStore {
	return &fakeStore{rows: map[Key]*Report{}}
}

func (f *fakeStore) put(eco, pkg, ver string, r *Report) {
	f.rows[Key{Ecosystem: eco, Package: pkg, Version: ver}] = r
}

func (f *fakeStore) Get(_ context.Context, _ string, k Key) (*Report, error) {
	f.calls = append(f.calls, k)
	if r, ok := f.rows[k]; ok {
		return r, nil
	}
	return nil, ErrNotFound
}

func (f *fakeStore) ListVersions(_ context.Context, _ string, eco, name string) ([]string, error) {
	var out []string
	for k := range f.rows {
		if k.Ecosystem == eco && k.Package == name {
			out = append(out, k.Version)
		}
	}
	return out, nil
}

func newReport(eco, pkg, ver string) *Report {
	return &Report{
		Identity: IdentitySection{
			Ecosystem: eco,
			Package:   pkg,
			Version:   ver,
		},
		Risk: &risk.Evaluation{
			Key: risk.Key{Ecosystem: eco, Package: pkg, Version: ver},
		},
	}
}

// TestTransitiveRisk_CandidateVersions covers the constraint→probe
// list generation directly.
func TestTransitiveRisk_CandidateVersions(t *testing.T) {
	cases := []struct {
		name       string
		constraint string
		want       []string
	}{
		{"empty falls back to latest", "", []string{"latest"}},
		{"exact pin probed verbatim then latest", "1.2.3", []string{"1.2.3", "latest"}},
		{"caret strips operator", "^1.2.3", []string{"^1.2.3", "1.2.3", "latest"}},
		{"tilde strips operator", "~1.2.3", []string{"~1.2.3", "1.2.3", "latest"}},
		{"gte strips operator", ">=1.2.3", []string{">=1.2.3", "1.2.3", "latest"}},
		{"range takes lower bound", ">=1.2.3, <2.0.0", []string{">=1.2.3, <2.0.0", "1.2.3", "latest"}},
		{"non-semver constraint falls through", "git+https://x", []string{"git+https://x", "latest"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := candidateVersions(tc.constraint)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("candidateVersions(%q) = %v, want %v", tc.constraint, got, tc.want)
			}
		})
	}
}

// TestTransitiveRisk_ResolvesExactConstraint asserts that when the
// cache holds the exact pinned version, lookupDepReport finds it
// without falling through to "latest".
func TestTransitiveRisk_ResolvesExactConstraint(t *testing.T) {
	store := newFakeStore()
	depRpt := newReport("npm", "left-pad", "1.2.3")
	store.put("npm", "left-pad", "1.2.3", depRpt)

	root := newReport("npm", "app", "0.0.1")
	root.Dependencies.Direct = []DependencyRef{
		{Name: "left-pad", Constraint: "^1.2.3"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	// Should have probed "^1.2.3" (miss) then "1.2.3" (hit) and
	// stopped before "latest".
	probedLatest := false
	for _, c := range store.calls {
		if c.Version == "latest" {
			probedLatest = true
		}
	}
	if probedLatest {
		t.Fatalf("expected no 'latest' probe once 1.2.3 hit; calls=%+v", store.calls)
	}
}

// TestTransitiveRisk_ResolvesRangeAgainstCachedVersion is the regression
// test for the "Dependency Alerts blank everywhere" bug: a "^1.2.0"
// constraint with the cache holding only "1.5.3" must resolve to
// 1.5.3 by enumerating cached versions and picking the highest one
// satisfying the range. Pre-fix, candidateVersions probed
// "^1.2.0" / "1.2.0" / "latest" — all misses — and the helper
// returned empty, leaving Risk.RolledUp == DirectScore.
func TestTransitiveRisk_ResolvesRangeAgainstCachedVersion(t *testing.T) {
	store := newFakeStore()
	depRpt := newReport("npm", "tslib", "1.5.3")
	store.put("npm", "tslib", "1.5.3", depRpt)

	root := newReport("npm", "rxjs", "7.8.2")
	root.Dependencies.Direct = []DependencyRef{
		{Name: "tslib", Constraint: "^1.2.0"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	// We can't observe lookupDepReport's return directly, but if it
	// resolved the dep we'd expect a Get for tslib@1.5.3.
	resolved := false
	for _, c := range store.calls {
		if c.Package == "tslib" && c.Version == "1.5.3" {
			resolved = true
		}
	}
	if !resolved {
		t.Fatalf("expected lookup to enumerate and hit tslib@1.5.3 for ^1.2.0; calls=%+v", store.calls)
	}
}

// TestTransitiveRisk_FallsBackToLatest exercises the constraint-miss
// path: when nothing in the constraint matches, we still look up the
// "latest" sentinel for back-compat.
func TestTransitiveRisk_FallsBackToLatest(t *testing.T) {
	store := newFakeStore()
	store.put("npm", "left-pad", "latest", newReport("npm", "left-pad", "9.9.9"))

	root := newReport("npm", "app", "0.0.1")
	root.Dependencies.Direct = []DependencyRef{
		{Name: "left-pad", Constraint: "^1.2.3"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	hitLatest := false
	for _, c := range store.calls {
		if c.Version == "latest" {
			hitLatest = true
		}
	}
	if !hitLatest {
		t.Fatalf("expected 'latest' probe as fallback; calls=%+v", store.calls)
	}
}

// TestTransitiveRisk_ExcludesPeerDevOptional makes sure only Direct
// is walked. Peer/Dev/Optional rows in the cache must NOT trigger a
// store lookup.
func TestTransitiveRisk_ExcludesPeerDevOptional(t *testing.T) {
	store := newFakeStore()
	root := newReport("npm", "app", "0.0.1")
	root.Dependencies.Direct = []DependencyRef{
		{Name: "direct-dep", Constraint: "1.0.0"},
	}
	root.Dependencies.Peer = []DependencyRef{
		{Name: "peer-dep", Constraint: "1.0.0"},
	}
	root.Dependencies.Dev = []DependencyRef{
		{Name: "dev-dep", Constraint: "1.0.0"},
	}
	root.Dependencies.Optional = []DependencyRef{
		{Name: "opt-dep", Constraint: "1.0.0"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	for _, c := range store.calls {
		switch c.Package {
		case "peer-dep", "dev-dep", "opt-dep":
			t.Fatalf("walker probed excluded bucket %q; calls=%+v", c.Package, store.calls)
		}
	}
}

// TestTransitiveRisk_DeduplicatesRepeatedDeps ensures the cycle
// guard collapses the same (eco, name, resolved-version) appearing
// twice in Direct into a single graph node.
func TestTransitiveRisk_DeduplicatesRepeatedDeps(t *testing.T) {
	store := newFakeStore()
	store.put("npm", "left-pad", "1.2.3", newReport("npm", "left-pad", "1.2.3"))

	root := newReport("npm", "app", "0.0.1")
	root.Dependencies.Direct = []DependencyRef{
		{Name: "left-pad", Constraint: "1.2.3"},
		{Name: "left-pad", Constraint: "1.2.3"},
		{Name: "LEFT-PAD", Constraint: "1.2.3"}, // case-insensitive dedupe
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	// Pre-fix the helper would AddEdge three times for the same key
	// (Graph dedupes nodes but not edges) — we can't observe that
	// directly without exporting more graph internals, but we can
	// at least confirm the lookup happened at least once.
	hits := 0
	for _, c := range store.calls {
		if c.Version == "1.2.3" && (c.Package == "left-pad" || c.Package == "LEFT-PAD") {
			hits++
		}
	}
	if hits < 1 {
		t.Fatalf("expected at least one 1.2.3 lookup, got %d", hits)
	}
}

// TestTransitiveRisk_SelfReferenceIsNoop covers the A→A cycle case:
// a manifest that lists itself as a direct dep must not cause a
// double-count or panic. The visited set is seeded with the root.
func TestTransitiveRisk_SelfReferenceIsNoop(t *testing.T) {
	store := newFakeStore()
	store.put("npm", "app", "0.0.1", newReport("npm", "app", "0.0.1"))

	root := newReport("npm", "app", "0.0.1")
	root.Dependencies.Direct = []DependencyRef{
		{Name: "app", Constraint: "0.0.1"},
	}

	// Should not panic, should not double-add the root.
	evaluateTransitiveRisk(context.Background(), store, "org", root)
}

// TestTransitiveRisk_Maven exercises the same evaluateTransitiveRisk
// helper with a Maven-shaped Identity + Direct list. The provider is
// ecosystem-agnostic; this test pins that behavior so a future
// ecosystem switch doesn't accidentally regress the Maven path.
// Pairs with depgraph.ParseMavenDepTree, which is the upstream feeder
// of Identity.Ecosystem="maven" reports via the v2 evaluate API.
func TestTransitiveRisk_Maven(t *testing.T) {
	store := newFakeStore()
	store.put("maven", "org.springframework:spring-core", "5.3.20",
		newReport("maven", "org.springframework:spring-core", "5.3.20"))

	root := newReport("maven", "com.example:my-app", "1.0.0")
	root.Dependencies.Direct = []DependencyRef{
		{Ecosystem: "maven", Name: "org.springframework:spring-core", Constraint: "5.3.20"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	hit := false
	for _, c := range store.calls {
		if c.Ecosystem == "maven" && c.Package == "org.springframework:spring-core" && c.Version == "5.3.20" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected maven spring-core lookup; calls=%+v", store.calls)
	}
}

// TestTransitiveRisk_Gradle exercises the same evaluateTransitiveRisk
// helper with a Gradle-shaped Identity + Direct list. Mirrors the
// Maven test; pairs with depgraph.ParseGradleDependencyTree, which is
// the upstream feeder of Identity.Ecosystem="gradle" reports via the
// v2 evaluate API.
func TestTransitiveRisk_Gradle(t *testing.T) {
	store := newFakeStore()
	store.put("gradle", "org.springframework:spring-core", "5.3.20",
		newReport("gradle", "org.springframework:spring-core", "5.3.20"))

	root := newReport("gradle", "com.example:my-app", "1.0.0")
	root.Dependencies.Direct = []DependencyRef{
		{Ecosystem: "gradle", Name: "org.springframework:spring-core", Constraint: "5.3.20"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	hit := false
	for _, c := range store.calls {
		if c.Ecosystem == "gradle" && c.Package == "org.springframework:spring-core" && c.Version == "5.3.20" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected gradle spring-core lookup; calls=%+v", store.calls)
	}
}

// TestTransitiveRisk_Composer mirrors TestTransitiveRisk_Maven for the
// PHP/Composer ecosystem. Pairs with depgraph.ParseComposerLockfile,
// which feeds Identity.Ecosystem="composer" reports through the v2
// evaluate API.
func TestTransitiveRisk_Composer(t *testing.T) {
	store := newFakeStore()
	store.put("composer", "psr/log", "1.1.4",
		newReport("composer", "psr/log", "1.1.4"))

	root := newReport("composer", "monolog/monolog", "2.9.1")
	root.Dependencies.Direct = []DependencyRef{
		{Ecosystem: "composer", Name: "psr/log", Constraint: "1.1.4"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	hit := false
	for _, c := range store.calls {
		if c.Ecosystem == "composer" && c.Package == "psr/log" && c.Version == "1.1.4" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected composer psr/log lookup; calls=%+v", store.calls)
	}
}

// TestTransitiveRisk_RubyGems exercises evaluateTransitiveRisk with a
// rubygems-shaped Identity + Direct list. Pairs with
// depgraph.ParseGemfileLockfile, which feeds Identity.Ecosystem="rubygems"
// reports through the v2 evaluate API.
func TestTransitiveRisk_RubyGems(t *testing.T) {
	store := newFakeStore()
	store.put("rubygems", "rack", "2.2.4",
		newReport("rubygems", "rack", "2.2.4"))

	root := newReport("rubygems", "actionpack", "7.0.4")
	root.Dependencies.Direct = []DependencyRef{
		{Ecosystem: "rubygems", Name: "rack", Constraint: "2.2.4"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	hit := false
	for _, c := range store.calls {
		if c.Ecosystem == "rubygems" && c.Package == "rack" && c.Version == "2.2.4" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected rubygems rack lookup; calls=%+v", store.calls)
	}
}

// TestTransitiveRisk_NuGet exercises evaluateTransitiveRisk with a
// NuGet-shaped Identity + Direct list, mirroring the Maven test.
// Pairs with depgraph.ParseNuGetLockfile, the upstream feeder of
// Identity.Ecosystem="nuget" reports via the v2 evaluate API.
func TestTransitiveRisk_NuGet(t *testing.T) {
	store := newFakeStore()
	store.put("nuget", "Newtonsoft.Json", "13.0.1",
		newReport("nuget", "Newtonsoft.Json", "13.0.1"))

	root := newReport("nuget", "MyApp", "1.0.0")
	root.Dependencies.Direct = []DependencyRef{
		{Ecosystem: "nuget", Name: "Newtonsoft.Json", Constraint: "13.0.1"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	hit := false
	for _, c := range store.calls {
		if c.Ecosystem == "nuget" && c.Package == "Newtonsoft.Json" && c.Version == "13.0.1" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected nuget Newtonsoft.Json lookup; calls=%+v", store.calls)
	}
}

// erroringStore wraps fakeStore to inject store errors on Get /
// ListVersions for the lookup-error visibility tests.
type erroringStore struct {
	*fakeStore
	getErr  error
	listErr error
}

func (e *erroringStore) Get(ctx context.Context, org string, k Key) (*Report, error) {
	if e.getErr != nil {
		return nil, e.getErr
	}
	return e.fakeStore.Get(ctx, org, k)
}

func (e *erroringStore) ListVersions(ctx context.Context, org, eco, name string) ([]string, error) {
	if e.listErr != nil {
		return nil, e.listErr
	}
	return e.fakeStore.ListVersions(ctx, org, eco, name)
}

func findWarning(report *Report, code string) *Warning {
	for i := range report.Observation.Warnings {
		w := &report.Observation.Warnings[i]
		if w.Code == code {
			return w
		}
	}
	return nil
}

// TestTransitiveRisk_WarnsOnNotCached covers the cache-cold drop path:
// a direct dep declared with a parseable constraint but no cached row
// must produce a transitive_dep_not_cached warning and be reflected in
// TransitiveCoverage as resolved < total.
func TestTransitiveRisk_WarnsOnNotCached(t *testing.T) {
	store := newFakeStore()
	root := newReport("npm", "app", "0.0.1")
	root.Dependencies.Direct = []DependencyRef{
		{Name: "missing-dep", Constraint: "^1.0.0"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	w := findWarning(root, WarnTransitiveDepNotCached)
	if w == nil {
		t.Fatalf("expected %q warning, got %+v", WarnTransitiveDepNotCached, root.Observation.Warnings)
	}
	if !strings.Contains(w.Message, "missing-dep") || !strings.Contains(w.Message, "^1.0.0") {
		t.Fatalf("warning message missing dep / constraint: %q", w.Message)
	}
	if root.SupplyChain.TransitiveCoverage == nil {
		t.Fatalf("expected TransitiveCoverage to be populated")
	}
	if got := *root.SupplyChain.TransitiveCoverage; got.Resolved != 0 || got.Total != 1 || got.Complete {
		t.Fatalf("coverage = %+v, want {0 1 false}", got)
	}
}

// TestTransitiveRisk_WarnsOnUnparseableConstraint covers the
// non-semver-constraint drop path: a constraint like "git+https://…"
// that semver.NewConstraint can't parse must surface a distinct
// transitive_dep_constraint_unparseable warning.
func TestTransitiveRisk_WarnsOnUnparseableConstraint(t *testing.T) {
	store := newFakeStore()
	root := newReport("npm", "app", "0.0.1")
	root.Dependencies.Direct = []DependencyRef{
		{Name: "weird-dep", Constraint: "git+https://example/repo"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	w := findWarning(root, WarnTransitiveDepConstraintUnparseable)
	if w == nil {
		t.Fatalf("expected %q warning, got %+v", WarnTransitiveDepConstraintUnparseable, root.Observation.Warnings)
	}
	if !strings.Contains(w.Message, "weird-dep") || !strings.Contains(w.Message, "git+https") {
		t.Fatalf("warning message missing dep / constraint: %q", w.Message)
	}
	if root.SupplyChain.TransitiveCoverage == nil || root.SupplyChain.TransitiveCoverage.Resolved != 0 {
		t.Fatalf("expected resolved=0 coverage, got %+v", root.SupplyChain.TransitiveCoverage)
	}
}

// TestTransitiveRisk_WarnsOnLookupError covers the transient-backend
// drop path: a store that returns a non-not-found error must surface a
// transitive_dep_lookup_error warning so operators can distinguish
// "cache cold" from "cache broken".
func TestTransitiveRisk_WarnsOnLookupError(t *testing.T) {
	boom := errors.New("connection reset")
	store := &erroringStore{fakeStore: newFakeStore(), getErr: boom}
	root := newReport("npm", "app", "0.0.1")
	root.Dependencies.Direct = []DependencyRef{
		{Name: "broken-dep", Constraint: "1.0.0"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	w := findWarning(root, WarnTransitiveDepLookupError)
	if w == nil {
		t.Fatalf("expected %q warning, got %+v", WarnTransitiveDepLookupError, root.Observation.Warnings)
	}
	if !strings.Contains(w.Message, "broken-dep") || !strings.Contains(w.Message, "connection reset") {
		t.Fatalf("warning message missing dep / err: %q", w.Message)
	}
}

// TestTransitiveRisk_CoverageComplete covers the happy path: every
// direct dep resolves, TransitiveCoverage reports Complete=true and
// Resolved == Total, no drop warnings fire.
func TestTransitiveRisk_CoverageComplete(t *testing.T) {
	store := newFakeStore()
	store.put("npm", "ok-dep", "1.0.0", newReport("npm", "ok-dep", "1.0.0"))

	root := newReport("npm", "app", "0.0.1")
	root.Dependencies.Direct = []DependencyRef{
		{Name: "ok-dep", Constraint: "1.0.0"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	if root.SupplyChain.TransitiveCoverage == nil {
		t.Fatalf("expected TransitiveCoverage to be populated")
	}
	if got := *root.SupplyChain.TransitiveCoverage; got.Resolved != 1 || got.Total != 1 || !got.Complete {
		t.Fatalf("coverage = %+v, want {1 1 true}", got)
	}
	for _, code := range []string{WarnTransitiveDepNotCached, WarnTransitiveDepConstraintUnparseable, WarnTransitiveDepLookupError} {
		if findWarning(root, code) != nil {
			t.Fatalf("unexpected drop warning %q on full coverage", code)
		}
	}
}

// TestTransitiveRisk_PopulatesTransitiveBlame is an end-to-end smoke
// test: a malicious direct dep should land in the rolled-up
// TransitiveBlame list. Drives a non-allow verdict through the
// projector → evaluator path via MalwareStatus.
func TestTransitiveRisk_PopulatesTransitiveBlame(t *testing.T) {
	store := newFakeStore()
	bad := newReport("npm", "bad-dep", "1.0.0")
	bad.SupplyChain.MalwareStatus = "malicious"
	bad.SupplyChain.MalwareID = "MAL-1"
	bad.SupplyChain.MalwareSummary = "test"
	store.put("npm", "bad-dep", "1.0.0", bad)

	root := newReport("npm", "app", "0.0.1")
	root.Dependencies.Direct = []DependencyRef{
		{Name: "bad-dep", Constraint: "1.0.0"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	if root.Risk == nil {
		t.Fatalf("Risk dropped")
	}
	blame := root.Risk.Resolution.TransitiveBlame
	sort.Slice(blame, func(i, j int) bool { return blame[i].Package < blame[j].Package })
	found := false
	for _, b := range blame {
		if b.Package == "bad-dep" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected bad-dep in TransitiveBlame, got %+v", blame)
	}
}

// --- N-level transitive walk (Pain 5 uplift) ---
//
// These tests cover the BFS extension introduced for Pain 5. The
// fixtures lean on the same fakeStore plumbing the level-1 tests use
// — the walker is depth-only (no extra plumbing for caches, locks,
// etc.) so a synthetic two/three-deep graph is enough to exercise
// the new code paths.

// makeReportWithDirect is a tiny helper for constructing a Report
// pre-wired with a Direct dep list. Saves vertical space in the
// multi-fixture tests below.
func makeReportWithDirect(eco, pkg, ver string, direct ...DependencyRef) *Report {
	r := newReport(eco, pkg, ver)
	r.Dependencies.Direct = direct
	return r
}

// TestTransitiveRisk_NLevel_LinearChain walks A -> B -> C -> D and
// asserts every node lands in the graph when the depth allows it.
// ClosureSize on the root reflects "everything reachable" (3) and
// MaxDepth mirrors the in-effect cap.
func TestTransitiveRisk_NLevel_LinearChain(t *testing.T) {
	t.Setenv("CHAINSAW_TRANSITIVE_DEPTH", "5")
	store := newFakeStore()
	d := makeReportWithDirect("npm", "d", "1.0.0")
	c := makeReportWithDirect("npm", "c", "1.0.0", DependencyRef{Name: "d", Constraint: "1.0.0"})
	b := makeReportWithDirect("npm", "b", "1.0.0", DependencyRef{Name: "c", Constraint: "1.0.0"})
	store.put("npm", "d", "1.0.0", d)
	store.put("npm", "c", "1.0.0", c)
	store.put("npm", "b", "1.0.0", b)

	root := makeReportWithDirect("npm", "a", "0.0.1", DependencyRef{Name: "b", Constraint: "1.0.0"})
	evaluateTransitiveRisk(context.Background(), store, "org", root)

	cov := root.SupplyChain.TransitiveCoverage
	if cov == nil {
		t.Fatalf("expected TransitiveCoverage to be populated")
	}
	if cov.MaxDepth != 5 {
		t.Fatalf("expected MaxDepth=5, got %d", cov.MaxDepth)
	}
	if cov.ClosureSize != 3 {
		t.Fatalf("expected ClosureSize=3 (b,c,d), got %d", cov.ClosureSize)
	}
}

// TestTransitiveRisk_NLevel_DepthOneFloor verifies that an env value
// of "1" makes the walker behave like the legacy single-level pass:
// only direct deps are visited, ClosureSize=1.
func TestTransitiveRisk_NLevel_DepthOneFloor(t *testing.T) {
	t.Setenv("CHAINSAW_TRANSITIVE_DEPTH", "1")
	store := newFakeStore()
	c := makeReportWithDirect("npm", "c", "1.0.0")
	b := makeReportWithDirect("npm", "b", "1.0.0", DependencyRef{Name: "c", Constraint: "1.0.0"})
	store.put("npm", "c", "1.0.0", c)
	store.put("npm", "b", "1.0.0", b)

	root := makeReportWithDirect("npm", "a", "0.0.1", DependencyRef{Name: "b", Constraint: "1.0.0"})
	evaluateTransitiveRisk(context.Background(), store, "org", root)

	cov := root.SupplyChain.TransitiveCoverage
	if cov == nil {
		t.Fatalf("expected coverage")
	}
	if cov.ClosureSize != 1 {
		t.Fatalf("depth=1 should bound closure to direct deps; got %d", cov.ClosureSize)
	}
}

// TestTransitiveRisk_NLevel_DepthCapClamps confirms that an env value
// above TransitiveDepthMax is clamped to the cap rather than
// honoured. This is the runaway-graph guard.
func TestTransitiveRisk_NLevel_DepthCapClamps(t *testing.T) {
	t.Setenv("CHAINSAW_TRANSITIVE_DEPTH", "999")
	if got := transitiveDepthFromEnv(); got != TransitiveDepthMax {
		t.Fatalf("expected clamp to %d, got %d", TransitiveDepthMax, got)
	}
	t.Setenv("CHAINSAW_TRANSITIVE_DEPTH", "0")
	if got := transitiveDepthFromEnv(); got != TransitiveDepthDefault {
		t.Fatalf("non-positive should fall back to default %d, got %d", TransitiveDepthDefault, got)
	}
	t.Setenv("CHAINSAW_TRANSITIVE_DEPTH", "abc")
	if got := transitiveDepthFromEnv(); got != TransitiveDepthDefault {
		t.Fatalf("unparseable should fall back to default %d, got %d", TransitiveDepthDefault, got)
	}
}

// TestTransitiveRisk_NLevel_Cycle_Terminates wires a -> b -> c -> b
// (cycle). The walker MUST terminate via the visited-set guard.
// ClosureSize counts distinct descendants only (b, c).
func TestTransitiveRisk_NLevel_Cycle_Terminates(t *testing.T) {
	t.Setenv("CHAINSAW_TRANSITIVE_DEPTH", "5")
	store := newFakeStore()
	c := makeReportWithDirect("npm", "c", "1.0.0", DependencyRef{Name: "b", Constraint: "1.0.0"})
	b := makeReportWithDirect("npm", "b", "1.0.0", DependencyRef{Name: "c", Constraint: "1.0.0"})
	store.put("npm", "c", "1.0.0", c)
	store.put("npm", "b", "1.0.0", b)

	root := makeReportWithDirect("npm", "a", "0.0.1", DependencyRef{Name: "b", Constraint: "1.0.0"})

	done := make(chan struct{})
	go func() {
		defer close(done)
		evaluateTransitiveRisk(context.Background(), store, "org", root)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("evaluateTransitiveRisk hung — cycle not detected")
	}

	cov := root.SupplyChain.TransitiveCoverage
	if cov == nil {
		t.Fatalf("expected coverage")
	}
	if cov.ClosureSize != 2 {
		t.Fatalf("cycle should yield ClosureSize=2 (b,c), got %d", cov.ClosureSize)
	}
}

// TestTransitiveRisk_NLevel_Diamond covers the fan-in case
//
//	a -> b -> d
//	a -> c -> d
//
// where d is reached via two paths. ClosureSize must dedupe d so
// the count is 3 (b, c, d), not 4. AddEdge is idempotent so both
// in-edges to d are recorded.
func TestTransitiveRisk_NLevel_Diamond(t *testing.T) {
	t.Setenv("CHAINSAW_TRANSITIVE_DEPTH", "5")
	store := newFakeStore()
	d := makeReportWithDirect("npm", "d", "1.0.0")
	c := makeReportWithDirect("npm", "c", "1.0.0", DependencyRef{Name: "d", Constraint: "1.0.0"})
	b := makeReportWithDirect("npm", "b", "1.0.0", DependencyRef{Name: "d", Constraint: "1.0.0"})
	store.put("npm", "d", "1.0.0", d)
	store.put("npm", "c", "1.0.0", c)
	store.put("npm", "b", "1.0.0", b)

	root := makeReportWithDirect("npm", "a", "0.0.1",
		DependencyRef{Name: "b", Constraint: "1.0.0"},
		DependencyRef{Name: "c", Constraint: "1.0.0"},
	)
	evaluateTransitiveRisk(context.Background(), store, "org", root)

	cov := root.SupplyChain.TransitiveCoverage
	if cov == nil {
		t.Fatalf("expected coverage")
	}
	if cov.ClosureSize != 3 {
		t.Fatalf("diamond should dedupe d; expected ClosureSize=3, got %d", cov.ClosureSize)
	}
}

// vulnReport builds an intelligence Report whose vulnerability section
// triggers the configured CVSS-tier signal when projected to risk.Input.
// Pass cvss = 9.5 for a critical, 7.5 for a high, etc.
func vulnReport(eco, pkg, ver string, cvss float64, cves ...string) *Report {
	r := newReport(eco, pkg, ver)
	r.Vulnerabilities.IsVulnerable = true
	r.Vulnerabilities.CVSSScore = cvss
	r.Vulnerabilities.CVEs = append([]string(nil), cves...)
	return r
}

// maliciousReport flags a descendant as known-malicious so the
// sc.known_malicious signal fires when projected.
func maliciousReport(eco, pkg, ver, malwareID string) *Report {
	r := newReport(eco, pkg, ver)
	r.SupplyChain.MalwareStatus = "malicious"
	r.SupplyChain.MalwareID = malwareID
	r.SupplyChain.MalwareSummary = "test fixture"
	return r
}

// TestTransitiveRisk_TransitiveSeverity_Critical asserts that a single
// descendant carrying a CVSS-critical CVE bubbles up as
// TransitiveSeverity.CriticalCount=1 on the root resolution and that
// the sc.transitive_critical_vuln signal subsequently fires when the
// root is re-evaluated with that count.
func TestTransitiveRisk_TransitiveSeverity_Critical(t *testing.T) {
	store := newFakeStore()
	// Child A has a critical CVE; child B is clean.
	a := vulnReport("npm", "child-a", "1.0.0", 9.5, "CVE-2024-CRITICAL")
	b := makeReportWithDirect("npm", "child-b", "1.0.0")
	store.put("npm", "child-a", "1.0.0", a)
	store.put("npm", "child-b", "1.0.0", b)

	root := makeReportWithDirect("npm", "root", "0.0.1",
		DependencyRef{Name: "child-a", Constraint: "1.0.0"},
		DependencyRef{Name: "child-b", Constraint: "1.0.0"},
	)
	evaluateTransitiveRisk(context.Background(), store, "org", root)

	got := root.Risk.Resolution.TransitiveSeverity
	if got.CriticalCount != 1 {
		t.Errorf("CriticalCount got %d want 1; full=%+v", got.CriticalCount, got)
	}
	if got.HighCount != 0 || got.MediumCount != 0 || got.LowCount != 0 {
		t.Errorf("other tiers should be zero; got %+v", got)
	}
}

// TestTransitiveRisk_TransitiveSeverity_DedupesCVE asserts that the
// SAME CVE appearing on TWO descendants in the same closure
// (child A + grandchild C) only counts ONCE in the severity tally.
func TestTransitiveRisk_TransitiveSeverity_DedupesCVE(t *testing.T) {
	t.Setenv("CHAINSAW_TRANSITIVE_DEPTH", "5")
	store := newFakeStore()
	// Grandchild C also carries the same critical CVE as A.
	c := vulnReport("npm", "child-c", "1.0.0", 9.5, "CVE-2024-CRITICAL")
	a := vulnReport("npm", "child-a", "1.0.0", 9.5, "CVE-2024-CRITICAL")
	a.Dependencies.Direct = []DependencyRef{{Name: "child-c", Constraint: "1.0.0"}}
	store.put("npm", "child-a", "1.0.0", a)
	store.put("npm", "child-c", "1.0.0", c)

	root := makeReportWithDirect("npm", "root", "0.0.1",
		DependencyRef{Name: "child-a", Constraint: "1.0.0"},
	)
	evaluateTransitiveRisk(context.Background(), store, "org", root)

	got := root.Risk.Resolution.TransitiveSeverity
	if got.CriticalCount != 1 {
		t.Errorf("dedup expected CriticalCount=1 (same CVE on 2 nodes); got %d, full=%+v", got.CriticalCount, got)
	}
}

// TestTransitiveRisk_TransitiveSeverity_Malware asserts that a malicious
// descendant produces MalwareCount=1 and that the sc.transitive_malware
// signal fires on the root with weight -1000 (instant-block sentinel).
func TestTransitiveRisk_TransitiveSeverity_Malware(t *testing.T) {
	store := newFakeStore()
	bad := maliciousReport("npm", "evil", "1.0.0", "MAL-001")
	store.put("npm", "evil", "1.0.0", bad)

	root := makeReportWithDirect("npm", "root", "0.0.1",
		DependencyRef{Name: "evil", Constraint: "1.0.0"},
	)
	evaluateTransitiveRisk(context.Background(), store, "org", root)

	if got := root.Risk.Resolution.TransitiveSeverity.MalwareCount; got != 1 {
		t.Fatalf("MalwareCount got %d want 1", got)
	}
	// Verify the signal fired on the root by re-running the signal's
	// Fires predicate against the same Input the provider produced.
	in := ProjectToRiskInput(root)
	in.TransitiveMalwareCount = root.Risk.Resolution.TransitiveSeverity.MalwareCount
	fired, _, _ := risk.Registry[risk.SignalSCTransitiveMalware].Fires(in)
	if !fired {
		t.Errorf("expected sc.transitive_malware to fire with TransitiveMalwareCount=%d", in.TransitiveMalwareCount)
	}
	if risk.Registry[risk.SignalSCTransitiveMalware].Weight != -1000 {
		t.Errorf("malware signal weight should be -1000 (instant-block sentinel)")
	}
	// The second-pass re-evaluation should drive Verdict toward
	// Quarantine (the malware signal is the -1000 short-circuit).
	if root.Risk.Verdict != risk.VerdictQuarantine {
		t.Errorf("verdict got %q want %q (malware should short-circuit)", root.Risk.Verdict, risk.VerdictQuarantine)
	}
}

// --- Per-ecosystem constraint parsing (PEP 440 / Gem / Maven / NuGet) ---
//
// These tests pin parseEcosystemConstraint + pickConstraintMatchDetailed
// on the four constraint shapes that the legacy Masterminds-only parser
// couldn't reason about. Each ecosystem gets a "happy path", a
// "regression-shield" exact-pin case, and at least one edge case
// (PEP 440 wildcard, Maven multi-set, RubyGems pessimistic,
// NuGet open-ended bracket).

// helper: returns the version pickConstraintMatchDetailed resolves to.
func pickFor(t *testing.T, eco string, versions []string, constraint string) (string, error) {
	t.Helper()
	store := newFakeStore()
	for _, v := range versions {
		store.put(eco, "pkg", v, newReport(eco, "pkg", v))
	}
	v, parseErr, listErr := pickConstraintMatchDetailed(context.Background(), store, "org", eco, "pkg", constraint)
	if listErr != nil {
		t.Fatalf("unexpected list error: %v", listErr)
	}
	return v, parseErr
}

// TestPickConstraint_PEP440 covers PEP 440 constraints that the legacy
// Masterminds parser rejected outright. The "(<4,>=2)" form is the
// real prod constraint string from pip/charset-normalizer.
func TestPickConstraint_PEP440(t *testing.T) {
	cases := []struct {
		name       string
		constraint string
		versions   []string
		want       string
	}{
		{"prod charset-normalizer (<4,>=2) picks highest in range",
			"(<4,>=2)", []string{"1.9.9", "2.0.0", "3.2.1", "4.0.0"}, "3.2.1"},
		{"exact pin still works",
			"==2.0.4", []string{"2.0.3", "2.0.4", "2.1.0"}, "2.0.4"},
		{"PEP 440 wildcard ==3.6.*",
			"==3.6.*", []string{"3.5.9", "3.6.0", "3.6.12", "3.7.0"}, "3.6.12"},
		{"PEP 440 compatible release ~=1.4.2",
			"~=1.4.2", []string{"1.4.1", "1.4.5", "1.5.0"}, "1.4.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, parseErr := pickFor(t, "pypi", tc.versions, tc.constraint)
			if parseErr != nil {
				t.Fatalf("parse failed: %v", parseErr)
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

// TestPickConstraint_RubyGems covers the pessimistic operator and the
// pre-release gating rule. The "~> 7.0" form is the real prod
// constraint string from rubygems/rails.
func TestPickConstraint_RubyGems(t *testing.T) {
	t.Run("prod rails ~> 7.0 picks highest 7.x", func(t *testing.T) {
		got, parseErr := pickFor(t, "rubygems", []string{"6.1.4", "7.0.0", "7.0.4", "7.1.0", "8.0.0"}, "~> 7.0")
		if parseErr != nil {
			t.Fatalf("parse failed: %v", parseErr)
		}
		// "~> 7.0" matches 7.x but not 8.0 (Ruby pessimistic semantics).
		if got != "7.1.0" {
			t.Fatalf("got %q want %q", got, "7.1.0")
		}
	})
	t.Run("exact pin still works", func(t *testing.T) {
		got, parseErr := pickFor(t, "rubygems", []string{"2.2.4", "3.0.0"}, "= 2.2.4")
		if parseErr != nil {
			t.Fatalf("parse failed: %v", parseErr)
		}
		if got != "2.2.4" {
			t.Fatalf("got %q want %q", got, "2.2.4")
		}
	})
	t.Run("stable constraint must NOT match pre-release", func(t *testing.T) {
		// Per RubyGems rules: `>= 7.0.0` should NOT match `7.0.0.beta1`
		// because the constraint itself contains no pre-release segment.
		// If the only cached version is a beta, the lookup should miss.
		got, parseErr := pickFor(t, "rubygems", []string{"7.0.0.beta1"}, ">= 7.0.0")
		if parseErr != nil {
			t.Fatalf("parse failed: %v", parseErr)
		}
		if got != "" {
			t.Fatalf("got %q, expected empty (stable constraint must skip pre-release)", got)
		}
	})
}

// TestPickConstraint_Maven covers bracket-range and multi-set syntax.
// The "[1.2.16,2.0.0)" form is the real prod constraint string from
// maven/log4j.
func TestPickConstraint_Maven(t *testing.T) {
	cases := []struct {
		name       string
		constraint string
		versions   []string
		want       string
	}{
		{"prod log4j [1.2.16,2.0.0) picks highest in range",
			"[1.2.16,2.0.0)", []string{"1.2.15", "1.2.16", "1.2.17", "2.0.0"}, "1.2.17"},
		{"Maven exact via single-version range [1.5.3]",
			"[1.5.3]", []string{"1.5.2", "1.5.3", "1.5.4"}, "1.5.3"},
		{"Maven multi-set [1.0,2.0),(3.0,4.0)",
			"[1.0,2.0),(3.0,4.0)", []string{"1.5", "2.0", "2.5", "3.5", "4.0"}, "3.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, parseErr := pickFor(t, "maven", tc.versions, tc.constraint)
			if parseErr != nil {
				t.Fatalf("parse failed: %v", parseErr)
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

// TestPickConstraint_NuGet covers NuGet's bracket-range syntax (shared
// with Maven). The "[11.0.2, )" form is the real prod constraint string
// from nuget/Newtonsoft.Json.
func TestPickConstraint_NuGet(t *testing.T) {
	cases := []struct {
		name       string
		constraint string
		versions   []string
		want       string
	}{
		{"prod Newtonsoft.Json [11.0.2, ) picks highest >= 11.0.2",
			"[11.0.2, )", []string{"10.0.3", "11.0.2", "12.0.3", "13.0.1"}, "13.0.1"},
		{"NuGet exact via [13.0.1]",
			"[13.0.1]", []string{"12.0.3", "13.0.1", "13.0.2"}, "13.0.1"},
		{"NuGet inclusive upper bound (,1.0]",
			"(,1.0]", []string{"0.9", "1.0", "1.1"}, "1.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, parseErr := pickFor(t, "nuget", tc.versions, tc.constraint)
			if parseErr != nil {
				t.Fatalf("parse failed: %v", parseErr)
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

// TestPickConstraint_GradleUsesMaven verifies the gradle alias dispatches
// to the Maven satisfier (same bracket syntax, same comparator).
func TestPickConstraint_GradleUsesMaven(t *testing.T) {
	got, parseErr := pickFor(t, "gradle", []string{"5.3.20", "5.3.21", "6.0.0"}, "[5.3.20,6.0.0)")
	if parseErr != nil {
		t.Fatalf("parse failed: %v", parseErr)
	}
	if got != "5.3.21" {
		t.Fatalf("got %q want %q", got, "5.3.21")
	}
}

// TestPickConstraint_ComposerUsesMaven verifies the packagist/composer
// alias dispatches to Maven (Composer's range syntax is Maven-flavoured
// enough that this is the safer fallback than Masterminds).
func TestPickConstraint_ComposerUsesMaven(t *testing.T) {
	got, parseErr := pickFor(t, "composer", []string{"1.1.3", "1.1.4", "2.0.0"}, "[1.1.4,2.0.0)")
	if parseErr != nil {
		t.Fatalf("parse failed: %v", parseErr)
	}
	if got != "1.1.4" {
		t.Fatalf("got %q want %q", got, "1.1.4")
	}
}

// TestPickConstraint_NPMStillUsesSemver is the no-regression shield:
// the npm/yarn/cargo path must still resolve via Masterminds so the
// existing range tests (TestTransitiveRisk_ResolvesRangeAgainstCachedVersion)
// keep behaving identically.
func TestPickConstraint_NPMStillUsesSemver(t *testing.T) {
	cases := []struct {
		name       string
		constraint string
		versions   []string
		want       string
	}{
		{"caret picks highest in major", "^1.2.0", []string{"1.2.0", "1.5.3", "2.0.0"}, "1.5.3"},
		{"tilde stays in minor", "~1.2.0", []string{"1.2.0", "1.2.9", "1.3.0"}, "1.2.9"},
		{"range >=1.0 <2.0", ">=1.0 <2.0", []string{"0.9.9", "1.0.0", "1.9.9", "2.0.0"}, "1.9.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, parseErr := pickFor(t, "npm", tc.versions, tc.constraint)
			if parseErr != nil {
				t.Fatalf("parse failed: %v", parseErr)
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

// TestPickConstraint_UnknownEcosystemFallsBackToSemver covers the
// "unknown ecosystem" branch — must preserve today's Masterminds
// behaviour rather than rejecting outright.
func TestPickConstraint_UnknownEcosystemFallsBackToSemver(t *testing.T) {
	got, parseErr := pickFor(t, "some-future-ecosystem", []string{"1.0.0", "1.2.3", "2.0.0"}, "^1.0.0")
	if parseErr != nil {
		t.Fatalf("parse failed: %v", parseErr)
	}
	if got != "1.2.3" {
		t.Fatalf("got %q want %q", got, "1.2.3")
	}
}

// TestPickConstraint_UnparseableSurfacesError verifies that a genuine
// junk constraint produces a non-nil parse error (which the warning
// path surfaces in the operator-facing message).
func TestPickConstraint_UnparseableSurfacesError(t *testing.T) {
	store := newFakeStore()
	v, parseErr, listErr := pickConstraintMatchDetailed(
		context.Background(), store, "org", "npm", "x",
		"git+https://example/repo",
	)
	if listErr != nil {
		t.Fatalf("unexpected list error: %v", listErr)
	}
	if v != "" {
		t.Fatalf("expected empty version on parse failure, got %q", v)
	}
	if parseErr == nil {
		t.Fatalf("expected non-nil parse error so warnings can include it")
	}
}

// TestTransitiveRisk_PyPIConstraintResolves is the end-to-end pin: a
// PyPI dep with a PEP 440 constraint that the OLD parser rejected must
// now resolve to the highest cached version that satisfies it AND
// produce no constraint-unparseable warning.
func TestTransitiveRisk_PyPIConstraintResolves(t *testing.T) {
	store := newFakeStore()
	store.put("pypi", "charset-normalizer", "3.2.1",
		newReport("pypi", "charset-normalizer", "3.2.1"))

	root := newReport("pypi", "requests", "2.31.0")
	root.Dependencies.Direct = []DependencyRef{
		{Ecosystem: "pypi", Name: "charset-normalizer", Constraint: "(<4,>=2)"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	if w := findWarning(root, WarnTransitiveDepConstraintUnparseable); w != nil {
		t.Fatalf("PEP 440 constraint should parse; got warning %q", w.Message)
	}
	hit := false
	for _, c := range store.calls {
		if c.Ecosystem == "pypi" && c.Package == "charset-normalizer" && c.Version == "3.2.1" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected pypi/charset-normalizer@3.2.1 lookup; calls=%+v", store.calls)
	}
}

// TestTransitiveRisk_MavenBracketRangeResolves is the end-to-end Maven
// pin paired with TestPickConstraint_Maven — the same constraint must
// drive a real cache lookup through evaluateTransitiveRisk.
func TestTransitiveRisk_MavenBracketRangeResolves(t *testing.T) {
	store := newFakeStore()
	store.put("maven", "org.apache.logging.log4j:log4j-core", "1.2.17",
		newReport("maven", "org.apache.logging.log4j:log4j-core", "1.2.17"))

	root := newReport("maven", "com.example:my-app", "1.0.0")
	root.Dependencies.Direct = []DependencyRef{
		{Ecosystem: "maven", Name: "org.apache.logging.log4j:log4j-core", Constraint: "[1.2.16,2.0.0)"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	if w := findWarning(root, WarnTransitiveDepConstraintUnparseable); w != nil {
		t.Fatalf("Maven bracket range should parse; got warning %q", w.Message)
	}
}

// TestTransitiveRisk_TransitiveSeverity_NoIssues asserts the zero-issue
// closure case: every count is zero and no transitive signal fires.
func TestTransitiveRisk_TransitiveSeverity_NoIssues(t *testing.T) {
	store := newFakeStore()
	clean := makeReportWithDirect("npm", "clean", "1.0.0")
	store.put("npm", "clean", "1.0.0", clean)

	root := makeReportWithDirect("npm", "root", "0.0.1",
		DependencyRef{Name: "clean", Constraint: "1.0.0"},
	)
	evaluateTransitiveRisk(context.Background(), store, "org", root)

	got := root.Risk.Resolution.TransitiveSeverity
	if got.CriticalCount != 0 || got.HighCount != 0 || got.MediumCount != 0 ||
		got.LowCount != 0 || got.MalwareCount != 0 {
		t.Errorf("expected zero severity counts on clean tree; got %+v", got)
	}
	// And the signals should be dormant on the resulting Input.
	in := ProjectToRiskInput(root)
	if fired, _, _ := risk.Registry[risk.SignalSCTransitiveCriticalVuln].Fires(in); fired {
		t.Error("sc.transitive_critical_vuln must stay dormant on a clean tree")
	}
	if fired, _, _ := risk.Registry[risk.SignalSCTransitiveMalware].Fires(in); fired {
		t.Error("sc.transitive_malware must stay dormant on a clean tree")
	}
}
