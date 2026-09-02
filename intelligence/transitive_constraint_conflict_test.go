package intelligence

// J-1 / P8-08. Tests for the constraint-reconciliation pass that refuses
// a closure node whose version violates a constraint the ROOT package
// declares on that same dependency name.
//
// The fixture in TestTransitiveConstraintConflict_RefusesAnachronisticNode
// is not invented: it is the exact production shape the finding was filed
// against, taken from the live `rubygems actionpack 5.2.0` row.
// actionpack 5.2.0 declares `rack ~> 2.0`; no rack 2.x is cached; and
// rack@3.2.7 still enters the closure through
// `rack-test >= 0.6.3` → rack-test 2.2.0 → its own `rack >= 1.3`, where
// it is then blamed on a package that forbids it in the same report.
//
// The negative cases matter as much as the positive one. Every one of
// them is a way this rule could delete a dependency that really is
// installed, which would turn a reporting defect into a hidden
// vulnerability:
//
//   - a constraint the node actually satisfies (no conflict at all)
//   - a BARE version constraint, which in Maven/Gradle/Go/NuGet is a soft
//     requirement or a minimum, not a pin
//   - a multi-version ecosystem, where nested resolution legitimately
//     installs two versions of one name
//   - a constraint declared by a non-root parent, whose own position in
//     the tree is only as sound as the max-satisfying chain that put it
//     there
//   - an unparseable constraint and the `latest` sentinel, neither of
//     which is evidence about anything

import (
	"context"
	"strings"
	"testing"
)

// closureHas reports whether the resolved closure of `root` contains the
// coordinate, judged through the two surfaces a consumer actually sees:
// the blame list and the closure size. Blame is checked directly;
// closure membership is inferred from ClosureSize by the callers that
// need it.
func blameHas(root *Report, eco, pkg, ver string) bool {
	if root.Risk == nil {
		return false
	}
	for _, b := range root.Risk.Resolution.TransitiveBlame {
		if b.Ecosystem == eco && b.Package == pkg && b.Version == ver {
			return true
		}
	}
	return false
}

func closureSize(root *Report) int {
	if root.SupplyChain.TransitiveCoverage == nil {
		return 0
	}
	return root.SupplyChain.TransitiveCoverage.ClosureSize
}

// buildRackTree wires the production shape: a root gem that declares
// `rack <rackConstraint>` and `rack-test >= 0.6.3`, a cache holding only
// rack 3.2.7 (malicious, so it is guaranteed to be blamed if it is
// admitted), and rack-test 2.2.0 declaring `rack >= 1.3` so the modern
// rack has a path into the closure that does not go through the root's
// own edge.
func buildRackTree(rackConstraint string) (*fakeStore, *Report) {
	store := newFakeStore()

	rack327 := newReport("rubygems", "rack", "3.2.7")
	rack327.SupplyChain.MalwareStatus = "malicious"
	rack327.SupplyChain.MalwareID = "MAL-RACK"
	rack327.SupplyChain.MalwareSummary = "fixture"
	store.put("rubygems", "rack", "3.2.7", rack327)

	rackTest := newReport("rubygems", "rack-test", "2.2.0")
	rackTest.Dependencies.Direct = []DependencyRef{
		{Name: "rack", Constraint: ">= 1.3"},
	}
	store.put("rubygems", "rack-test", "2.2.0", rackTest)

	root := newReport("rubygems", "actionpack", "5.2.0")
	root.Dependencies.Direct = []DependencyRef{
		{Name: "rack", Constraint: rackConstraint},
		{Name: "rack-test", Constraint: ">= 0.6.3"},
	}
	return store, root
}

func TestTransitiveConstraintConflict_RefusesAnachronisticNode(t *testing.T) {
	store, root := buildRackTree("~> 2.0")

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	if blameHas(root, "rubygems", "rack", "3.2.7") {
		t.Fatalf("rack@3.2.7 was blamed on actionpack 5.2.0, which declares `rack ~> 2.0`; blame=%+v",
			root.Risk.Resolution.TransitiveBlame)
	}
	// Refusing the node must also keep it OUT of the graph, not merely
	// out of the blame list — otherwise the score is still depressed by a
	// dependency the package cannot install, with the explanation deleted.
	// rack-test 2.2.0 is the only legitimate node, so the closure is 1.
	if got := closureSize(root); got != 1 {
		t.Fatalf("closure size = %d, want 1 (rack-test only; rack@3.2.7 must not be in the graph)", got)
	}
	w := findWarning(root, WarnTransitiveDepConstraintConflict)
	if w == nil {
		t.Fatalf("no %s warning: a refused node must never be silent", WarnTransitiveDepConstraintConflict)
	}
	if !strings.Contains(w.Message, "rack") || !strings.Contains(w.Message, "~> 2.0") {
		t.Fatalf("warning does not name the dep and the violated constraint: %q", w.Message)
	}
}

// The same tree with a constraint rack@3.2.7 SATISFIES. Nothing may be
// refused: this is the shape of actionpack 7.1.3 / 8.1.3, which really do
// resolve to a modern rack.
func TestTransitiveConstraintConflict_KeepsSatisfyingNode(t *testing.T) {
	store, root := buildRackTree(">= 2.0")

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	if !blameHas(root, "rubygems", "rack", "3.2.7") {
		t.Fatalf("rack@3.2.7 satisfies `>= 2.0` and is malicious; it must still be blamed. blame=%+v",
			root.Risk.Resolution.TransitiveBlame)
	}
	if findWarning(root, WarnTransitiveDepConstraintConflict) != nil {
		t.Fatalf("conflict warning fired on a satisfying version")
	}
}

// A BARE version is not a pin in Maven, Gradle, Go or NuGet — it is a
// soft requirement or a minimum, and the real resolver routinely selects
// a higher version. Acting on it would delete exactly the newer, often
// more vulnerable, node the build really gets. Measured consequence: on
// the 7,756-row prod corpus an unguarded rule flipped 10 go/maven rows,
// including a quarantine -> allow that discarded four transitive
// criticals.
func TestTransitiveConstraintConflict_IgnoresBareVersionConstraint(t *testing.T) {
	store := newFakeStore()

	newer := newReport("maven", "commons-io:commons-io", "2.20.0")
	newer.SupplyChain.MalwareStatus = "malicious"
	newer.SupplyChain.MalwareID = "MAL-IO"
	newer.SupplyChain.MalwareSummary = "fixture"
	store.put("maven", "commons-io:commons-io", "2.20.0", newer)

	mediator := newReport("maven", "org.example:mediator", "1.0.0")
	mediator.Dependencies.Direct = []DependencyRef{
		{Name: "commons-io:commons-io", Constraint: "[2.15.1,)"},
	}
	store.put("maven", "org.example:mediator", "1.0.0", mediator)

	root := newReport("maven", "org.example:app", "1.0.0")
	root.Dependencies.Direct = []DependencyRef{
		// Bare — Maven's soft requirement. Mediation may resolve 2.20.0.
		{Name: "commons-io:commons-io", Constraint: "2.15.1"},
		{Name: "org.example:mediator", Constraint: "[1.0.0]"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	if !blameHas(root, "maven", "commons-io:commons-io", "2.20.0") {
		t.Fatalf("a bare Maven version is a SOFT requirement; commons-io 2.20.0 must survive. blame=%+v",
			root.Risk.Resolution.TransitiveBlame)
	}
	if findWarning(root, WarnTransitiveDepConstraintConflict) != nil {
		t.Fatalf("conflict warning fired on a bare (soft) Maven version")
	}
}

// npm nests, so a root pinned to `^1.0.0` can legitimately have foo@2.0.0
// on disk under a transitive dep. Refusing it would hide a real node —
// the exact failure this rule exists to prevent, pointed the other way.
func TestTransitiveConstraintConflict_IgnoresMultiVersionEcosystem(t *testing.T) {
	store := newFakeStore()

	foo2 := newReport("npm", "foo", "2.0.0")
	foo2.SupplyChain.MalwareStatus = "malicious"
	foo2.SupplyChain.MalwareID = "MAL-FOO"
	foo2.SupplyChain.MalwareSummary = "fixture"
	store.put("npm", "foo", "2.0.0", foo2)

	mid := newReport("npm", "mid", "1.0.0")
	mid.Dependencies.Direct = []DependencyRef{{Name: "foo", Constraint: ">=2.0.0"}}
	store.put("npm", "mid", "1.0.0", mid)

	root := newReport("npm", "app", "0.0.1")
	root.Dependencies.Direct = []DependencyRef{
		{Name: "foo", Constraint: "^1.0.0"},
		{Name: "mid", Constraint: "1.0.0"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	if !blameHas(root, "npm", "foo", "2.0.0") {
		t.Fatalf("npm nests: foo@2.0.0 is really installed under mid and must not be refused. blame=%+v",
			root.Risk.Resolution.TransitiveBlame)
	}
	if findWarning(root, WarnTransitiveDepConstraintConflict) != nil {
		t.Fatalf("conflict warning fired in a multi-version ecosystem")
	}
}

// Only the ROOT's own manifest is trusted. A constraint declared by a
// NON-root parent is only as sound as the max-satisfying chain that put
// that parent in the tree, so it may itself be the anachronism; refusing
// a node on it could erase a legitimate subtree.
func TestTransitiveConstraintConflict_IgnoresNonRootConstraint(t *testing.T) {
	store := newFakeStore()

	rack327 := newReport("rubygems", "rack", "3.2.7")
	rack327.SupplyChain.MalwareStatus = "malicious"
	rack327.SupplyChain.MalwareID = "MAL-RACK"
	rack327.SupplyChain.MalwareSummary = "fixture"
	store.put("rubygems", "rack", "3.2.7", rack327)

	// A mid-tree parent that forbids rack 3.x…
	old := newReport("rubygems", "legacy", "1.0.0")
	old.Dependencies.Direct = []DependencyRef{{Name: "rack", Constraint: "~> 2.0"}}
	store.put("rubygems", "legacy", "1.0.0", old)

	// …and a sibling that admits it.
	modern := newReport("rubygems", "rack-test", "2.2.0")
	modern.Dependencies.Direct = []DependencyRef{{Name: "rack", Constraint: ">= 1.3"}}
	store.put("rubygems", "rack-test", "2.2.0", modern)

	// The root itself says nothing about rack.
	root := newReport("rubygems", "app", "1.0.0")
	root.Dependencies.Direct = []DependencyRef{
		{Name: "legacy", Constraint: "= 1.0.0"},
		{Name: "rack-test", Constraint: ">= 0.6.3"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	if !blameHas(root, "rubygems", "rack", "3.2.7") {
		t.Fatalf("only ROOT-declared constraints may refuse a node; a deeper conflict must be left alone. blame=%+v",
			root.Risk.Resolution.TransitiveBlame)
	}
	if findWarning(root, WarnTransitiveDepConstraintConflict) != nil {
		t.Fatalf("conflict warning fired on a non-root constraint")
	}
}

// Every uncertain input answers "no conflict", because the action taken
// is deletion and a wrong deletion is a hidden dependency.
func TestTransitiveConstraintConflict_UncertainInputsNeverRefuse(t *testing.T) {
	idx := map[string][]string{
		"rubygems|rack": {"~> 2.0"},
		"rubygems|junk": {">= not-a-version"},
		"npm|foo":       {"^1.0.0"},
	}
	cases := []struct {
		name             string
		eco, pkg, ver    string
		wantConflict     bool
		conflictExplains string
	}{
		{"genuine violation", "rubygems", "rack", "3.2.7", true, "3.2.7 is outside ~> 2.0"},
		{"satisfying version", "rubygems", "rack", "2.2.6", false, ""},
		{"latest sentinel is not a version", "rubygems", "rack", "latest", false, ""},
		{"empty version", "rubygems", "rack", "", false, ""},
		{"unparseable cached version", "rubygems", "rack", "git-abcdef", false, ""},
		{"unparseable constraint", "rubygems", "junk", "1.0.0", false, ""},
		{"multi-version ecosystem", "npm", "foo", "2.0.0", false, ""},
		{"name not declared by root", "rubygems", "nokogiri", "1.16.0", false, ""},
		{"case-drifted name still matches", "RubyGems", "RACK", "3.2.7", true, "normalisation must not lose the conflict"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := violatesDeclaredRootConstraint(idx, tc.eco, tc.pkg, tc.ver)
			if got != tc.wantConflict {
				t.Fatalf("violatesDeclaredRootConstraint(%s/%s@%s) = %v, want %v (%s)",
					tc.eco, tc.pkg, tc.ver, got, tc.wantConflict, tc.conflictExplains)
			}
		})
	}
}

func TestTransitiveConstraintConflict_ActionableConstraints(t *testing.T) {
	actionable := []string{"~> 2.0", ">= 1.3", "= 5.2.0", "<4,>=2", "[1.0,2.0)", "(,1.0]", "^1.2.3", "!=1.0.0", ">=1.0.2, ~> 1.0"}
	bare := []string{"", "1.2.3", "v3.0.1", "1.27", "1.5.7-4", "0.0.20221115062448", "latest", "master"}
	for _, c := range actionable {
		if !constraintIsActionable(c) {
			t.Errorf("constraint %q carries an operator and must be actionable", c)
		}
	}
	for _, c := range bare {
		if constraintIsActionable(c) {
			t.Errorf("constraint %q is bare and must NOT be acted on (soft requirement / minimum)", c)
		}
	}
}

// The allowlist is the safety property: an ecosystem nobody has reasoned
// about must fall through to the historical behaviour, never inherit a
// rule that only holds for flat resolvers.
func TestTransitiveConstraintConflict_SingleVersionAllowlist(t *testing.T) {
	single := []string{"rubygems", "RubyGems", "pypi", "pip", "maven", "gradle", "nuget", "composer", "packagist", "go", "pub", "cocoapods", "swift", "hex"}
	multi := []string{"npm", "yarn", "pnpm", "bun", "cargo", "crates", "docker", "apt", "yum", "dnf", "huggingface", "maven-hosted", "rubygems-hosted", "npmjs-hosted", "crates-hosted", "", "something-new"}
	for _, e := range single {
		if !resolvesSingleVersion(e) {
			t.Errorf("%q resolves one version per name and belongs in the allowlist", e)
		}
	}
	for _, e := range multi {
		if resolvesSingleVersion(e) {
			t.Errorf("%q must NOT be treated as single-version: either it nests, or nobody has reasoned about it", e)
		}
	}
}
