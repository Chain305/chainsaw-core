package typosquat

// enrolled_corpus_test.go — the caller guard for typosquat enrolment.
//
// ─── THE DEFECT THIS PINS ──────────────────────────────────────────────────
//
// EcosystemsWithTyposquatRisk() is the enrolment list: every ecosystem it
// names gets typosquatProvider.Supports() == true, so the intelligence
// pipeline runs the detector and stamps SupplyChain.TyposquatStatus. But the
// corpus arrives through a completely different function —
// FetchPopularPackages — whose switch ends in `default: return nil, nil`.
//
// The single production loader (core/supplychain/bootstrap.go) skips on
// `len(pkgs) == 0`, Detector.Check returns a zero DetectionResult on an
// unloaded tree, and provider_typosquat.Run stamps "clean". An enrolled
// ecosystem with no corpus branch is therefore not "degraded" — it is a
// detector that reports every package as clean, forever, with no log line
// and no metric. docker, swift and github_actions shipped in exactly that
// state.
//
// This is the repo's recurring correct-function-no-caller shape
// (SafeUpgradeVersion, backfillRepositoryGuides, ReapplyKnownFixAfterTransitive):
// PopularGitHubActions() is a real, tested, ~80-entry corpus that NOTHING
// loaded. Its own doc comment claimed it was wired "typically at startup".
// A test that only checks "the corpus function returns entries" would have
// passed the whole time. So these tests assert the ENROLMENT PATH, from the
// list to a loaded BK-tree, not the existence of a corpus function.
//
// ─── WHY (nil, nil) IS THE TRIPWIRE ────────────────────────────────────────
//
// The tests below drive FetchPopularPackages with an HTTP client that always
// fails, so nothing here touches the network and the result is hermetic:
//
//	live-fetch ecosystem, no seed  → (nil, non-nil error)   — has a branch
//	seed-backed ecosystem          → (non-empty, nil)        — has a branch
//	NOT IN THE SWITCH              → (nil, nil)              — the defect
//
// (nil, nil) is unreachable for any ecosystem the switch names, and is the
// exact and only signature of an enrolled-but-unsourced ecosystem. That makes
// it a total assertion over the enrolment list rather than a hand-maintained
// per-ecosystem table that the next enrolment would forget to update.

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// errNoNetworkInTest is returned by every request the hermetic client sees.
var errNoNetworkInTest = errors.New("network disabled in test")

type failingRoundTripper struct{}

func (failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errNoNetworkInTest
}

// offlineFetcher returns a Fetcher whose every HTTP call fails immediately.
// Seed-backed branches still produce their embedded corpus; live branches
// surface an error. Both prove the ecosystem has a branch at all.
func offlineFetcher() *Fetcher {
	return NewFetcher(slog.New(slog.DiscardHandler),
		WithHTTPClient(&http.Client{Transport: failingRoundTripper{}}))
}

// TestEveryEnrolledTyposquatEcosystemHasACorpus asserts that no ecosystem in
// EcosystemsWithTyposquatRisk() falls through FetchPopularPackages' default
// branch.
//
// NEGATIVE CONTROL. Before the docker/swift/github_actions seeds landed this
// test failed with exactly three names. If it ever reports a count again,
// something was added to the enrolment list without a corpus and is silently
// reporting every package clean.
func TestEveryEnrolledTyposquatEcosystemHasACorpus(t *testing.T) {
	f := offlineFetcher()
	ctx := context.Background()

	var unsourced []string
	for _, eco := range EcosystemsWithTyposquatRisk() {
		// A limit below minPlausiblePopularPackages would skip the sanity
		// floor; use a production-shaped limit so seed branches are held to
		// the same bar bootstrap holds them to.
		pkgs, err := f.FetchPopularPackages(ctx, eco, 5000)
		if err == nil && len(pkgs) == 0 {
			unsourced = append(unsourced, eco)
		}
	}

	if len(unsourced) > 0 {
		t.Fatalf("%d enrolled ecosystem(s) hit FetchPopularPackages' default branch and get a permanently empty "+
			"BK-tree — Detector.Check returns a zero result and provider_typosquat stamps every package "+
			"\"clean\": %v", len(unsourced), unsourced)
	}
}

// TestEnrolledSeedEcosystemsLoadIntoTheDetectorTree closes the second half of
// the caller gap: a corpus that FetchPopularPackages returns is not the same
// thing as a corpus the detector was BOOTSTRAPPED with. This walks the exact
// production sequence — the enrolment list, the fetcher, the len(pkgs)>0 skip,
// LoadEcosystem — and asserts the tree is non-empty afterwards, i.e. that
// detector.go's `if !ok || tree == nil || tree.Size() == 0 { return
// DetectionResult{} }` branch is unreachable for these ecosystems.
//
// Scoped to the offline seed-backed ecosystems because those are the ones that
// can be proven without a network. The live-fetch ecosystems are covered by the
// (nil, nil) assertion above.
func TestEnrolledSeedEcosystemsLoadIntoTheDetectorTree(t *testing.T) {
	seedBacked := []string{"go", "cocoapods", "pub", "cargo", "rubygems", "docker", "swift", "github_actions"}

	// Every name here must actually be enrolled — otherwise this test could
	// keep passing for an ecosystem that was dropped from the risk list.
	enrolled := map[string]bool{}
	for _, e := range EcosystemsWithTyposquatRisk() {
		enrolled[e] = true
	}

	f := offlineFetcher()
	ctx := context.Background()
	det := NewDetector(slog.New(slog.DiscardHandler))

	for _, eco := range seedBacked {
		if !enrolled[eco] {
			t.Fatalf("%q is in this test's seed-backed list but not in EcosystemsWithTyposquatRisk()", eco)
		}
		pkgs, err := f.FetchPopularPackages(ctx, eco, 5000)
		if err != nil {
			t.Fatalf("%s: offline FetchPopularPackages returned an error; a seed-backed ecosystem must not "+
				"need the network: %v", eco, err)
		}
		// Mirror bootstrap.go's skip so a regression that empties a seed
		// reproduces here as the same silent no-load it causes in prod.
		if len(pkgs) > 0 {
			det.LoadEcosystem(eco, pkgs)
		}
		if !det.HasIndex(eco) {
			t.Errorf("%s: enrolled and seed-backed, but the detector has no loaded index after the production "+
				"bootstrap sequence — Check would return a zero result for every package (%d fetched)",
				eco, len(pkgs))
		}
	}
}

// ─── what the new corpora do and do not fire on ────────────────────────────
//
// The rates live in TestHeldOutFalsePositiveRateByEcosystem, which needs a
// downloaded corpus and is therefore env-gated. These two tests pin the
// specific names behind those rates so a regression is caught hermetically,
// in CI, without a network. Every entry below was produced by an actual
// measurement run over the held-out corpora — none is hypothetical.

// loadEnrolled builds a detector for one ecosystem through the production
// sequence, with the network down.
func loadEnrolled(t *testing.T, eco string) *Detector {
	t.Helper()
	det := NewDetector(slog.New(slog.DiscardHandler))
	pkgs, err := offlineFetcher().FetchPopularPackages(context.Background(), eco, 5000)
	if err != nil {
		t.Fatalf("%s: offline fetch: %v", eco, err)
	}
	det.LoadEcosystem(eco, pkgs)
	if !det.HasIndex(eco) {
		t.Fatalf("%s: no index loaded", eco)
	}
	return det
}

// TestNewCorporaDoNotFireOnRealBenignNames pins the false positives the
// held-out measurement found, and the sibling exemption that closed them.
//
// The swift and github_actions entries are ALL THREE of the high-confidence
// false positives those two ecosystems produced across 13,574 held-out real
// package names — every one a same-owner sibling. If any of them rises above
// advisory again, sameOwnerSibling has been narrowed or bypassed and both
// ecosystems are quarantining first-party releases.
//
// "does not fire" here means "does not reach high or medium confidence". A
// same-owner sibling is DEMOTED to low (sc.typosquat_low, -8, advisory), not
// silenced — see the Check comment for why the finding is kept.
func TestNewCorporaDoNotFireOnRealBenignNames(t *testing.T) {
	cases := []struct{ eco, name, why string }{
		// swift — same scope, published by the same GitHub owner.
		{"swift", "grpc.grpc-swift-2", "grpc's own v2 release line, d=1 from grpc.grpc-swift"},
		{"swift", "typelift.swiftx", "typelift's own sibling of typelift.swiftz"},
		{"swift", "apple.swift-nio-ssl", "apple's own NIO family member"},
		{"swift", "apple.swift-nio-http2", "apple's own NIO family member"},
		{"swift", "hummingbird-project.hummingbird-auth", "hummingbird's own module"},
		// github_actions — same owner.
		{"github_actions", "reviewdog/action-eclint", "reviewdog publishes both eclint and eslint actions"},
		{"github_actions", "actions/cache/save", "composite subpath of actions/cache, same owner"},
		// docker — org-scoped rebuilds must not read as squats of the
		// official image they are a rebuild OF, above advisory confidence.
		{"docker", "bitnami/redis", "a legitimate org rebuild of the official redis"},
		{"docker", "cimg/postgres", "CircleCI's convenience image"},
	}

	for _, tc := range cases {
		det := loadEnrolled(t, tc.eco)
		res := det.Check(context.Background(), tc.eco, tc.name)
		if res.Confidence == "high" || res.Confidence == "medium" {
			t.Errorf("%s %q fired %s confidence (→ %q, d=%d, %s) — %s",
				tc.eco, tc.name, res.Confidence, res.SimilarTo, res.Distance, res.Method, tc.why)
		}
	}
}

// TestNewCorporaStillCatchRealSquats is the recall half. A corpus that fires
// on nothing is indistinguishable from the empty tree this whole change
// exists to fix, so the FP test above is meaningless without this one.
//
// Every case crosses an OWNER boundary where the ecosystem has one — which is
// what makes it a squat rather than a sibling, and what proves the exemption
// did not swallow the detector.
func TestNewCorporaStillCatchRealSquats(t *testing.T) {
	cases := []struct{ eco, name, wantConf string }{
		// docker: the classic bare-official-image squat shapes.
		{"docker", "ngnix", "high"},
		{"docker", "pyhton", "high"},
		{"docker", "pstgres", "high"},
		{"docker", "ubunut", "high"},
		// github_actions: a DIFFERENT owner wearing a popular Action's name.
		{"github_actions", "actons/checkout", "high"},
		{"github_actions", "aws-action/configure-aws-credentials", "high"},
		// swift: a different scope one edit from a popular package.
		{"swift", "aple.swift-nio", "high"},
		{"swift", "alamofir.alamofire", "high"},
		// Same owner, typo-shaped name: DEMOTED to advisory, not silenced.
		// The finding is still reported; it just cannot quarantine.
		{"github_actions", "actions/chekout", "low"},
		{"swift", "alamofire.alamofira", "low"},
	}

	for _, tc := range cases {
		det := loadEnrolled(t, tc.eco)
		res := det.Check(context.Background(), tc.eco, tc.name)
		if !res.IsSuspected {
			t.Errorf("%s %q: not flagged at all — the corpus is not catching the shape it exists for", tc.eco, tc.name)
			continue
		}
		if res.Confidence != tc.wantConf {
			t.Errorf("%s %q: confidence = %q (→ %q d=%d %s), want %q",
				tc.eco, tc.name, res.Confidence, res.SimilarTo, res.Distance, res.Method, tc.wantConf)
		}
	}
}

// TestSameOwnerSiblingIsScopedToTheTwoNewEcosystems is the blast-radius
// guard. The exemption is deliberately NOT applied to npm, composer, maven,
// huggingface or docker even though their coordinates have the same shape:
// those corpora have been firing in production for a long time and their
// false-positive and recall numbers are published against current behaviour.
// Widening it silently would move both halves of that published trade.
func TestSameOwnerSiblingIsScopedToTheTwoNewEcosystems(t *testing.T) {
	exempt := map[string]bool{"swift": true, "github_actions": true}
	for _, eco := range EcosystemsWithTyposquatRisk() {
		_, got := ownerScopeSeparator(eco)
		if got != exempt[eco] {
			t.Errorf("ownerScopeSeparator(%q) = %v, want %v — changing this set moves published "+
				"FP/recall numbers for an ecosystem that already ships; re-measure both halves first", eco, got, exempt[eco])
		}
	}
	// A homoglyph in the SCOPE is a different account wearing the same face,
	// and must never be exempted. Byte equality, not visual equality.
	if sameOwnerSibling("swift", "аpple.swift-nio", "apple.swift-nio") {
		t.Error("a Cyrillic-а scope was treated as the same owner as the Latin one")
	}
	// An unscoped name must not match another unscoped name on "".
	if sameOwnerSibling("swift", "nio", "nio2") {
		t.Error("two unscoped names were treated as same-owner siblings")
	}
}

// TestOwnerShadowIsOutOfScopeForThisDetector documents a REAL residual gap,
// asserted so nobody reads the docker/swift/actions corpora as covering it
// and so a future change that closes it is a deliberate, measured decision.
//
// An owner-shadow attack keeps the popular name and swaps the owner:
// `attacker/checkout` against `actions/checkout`. It is invisible to this
// detector by construction — the names differ by the owner token, which is
// far past any edit-distance threshold, and the combosquat lane cannot see it
// either (the popular NAME is `actions-checkout`, not `checkout`). This is
// not a regression from the sibling exemption: it never fired, before or
// after, and TestNewCorporaStillCatchRealSquats would have masked it if the
// case had been asserted as a positive.
//
// Closing it means flagging every fork and every same-named repo under a
// different owner, which is a publisher-reputation question, not a
// name-similarity one. It belongs to the known-publisher lane
// (githubactions.DefaultKnownPublishers), not here.
func TestOwnerShadowIsOutOfScopeForThisDetector(t *testing.T) {
	det := loadEnrolled(t, "github_actions")
	res := det.Check(context.Background(), "github_actions", "attacker/checkout")
	if res.IsSuspected {
		t.Logf("owner-shadow is now detected (%q d=%d %s) — the gap documented here has closed; "+
			"re-measure the false-positive rate on forks before relying on it",
			res.SimilarTo, res.Distance, res.Method)
	}
}

// TestNoCallerBuildsAnEmptyGitHubActionsDetector is a SOURCE-LEVEL caller
// guard. It exists because supplying a corpus to FetchPopularPackages fixes
// the ecosystem for callers that go through supplychain.Bootstrap — and only
// for those.
//
// githubactions.NewTyposquatAdapter takes a *Detector directly. Both
// production call sites handed it `typosquat.NewDetector(nil)`: a detector
// with no ecosystem loaded at all, on which Check returns a zero result for
// every Action and the scan reports clean. A behavioural test cannot see it
// (the adapter is a pure pass-through and the detector is a valid object), so
// the assertion has to be on the source.
//
// This is the third form of the same repo-wide defect class in one change:
// PopularGitHubActions() with no caller, EcosystemsWithTyposquatRisk() with
// no corpus, and here a corpus with no detector.
func TestNoCallerBuildsAnEmptyGitHubActionsDetector(t *testing.T) {
	// Known-outstanding sites, by repo-relative path. Each entry is a
	// promise to fix, not a permanent exemption — the staleness check below
	// fails the test once a listed site is fixed, so the list cannot rot.
	//
	// EMPTY, and that is the point: both production call sites now use
	// NewGitHubActionsDetector. core/cli/scan_actions.go was fixed with the
	// corpus work; internal/server/api_v1_intel.go (the POST scan-actions
	// handler) followed in the Wave C coverage-honesty pass, which owned
	// that file at the time and carried the epoch bump the change rides.
	//
	// Leave the map in place rather than deleting it. Its value is the
	// staleness check below — a future edit that has to defer one site can
	// list it here and be forced to come back, which is exactly how this
	// entry got retired instead of rotting.
	outstanding := map[string]bool{}

	root := repoRoot(t)
	const badPattern = "NewTyposquatAdapter(typosquat.NewDetector("

	found := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable trees are not this test's business
		}
		if e.IsDir() {
			switch e.Name() {
			case ".git", "node_modules", "vendor", "dist", ".claude":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		if strings.Contains(string(b), badPattern) {
			rel, _ := filepath.Rel(root, path)
			found[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	for site := range found {
		if !outstanding[site] {
			t.Errorf("%s builds an Actions typosquat adapter on a detector with no loaded ecosystem — "+
				"Check returns a zero result for every Action and the scan reports clean. "+
				"Use typosquat.NewGitHubActionsDetector instead.", site)
		}
	}
	for site := range outstanding {
		if !found[site] {
			t.Errorf("%s is listed as an outstanding empty-detector site but no longer matches %q — "+
				"remove it from the list in this test", site, badPattern)
		}
	}
}

// repoRoot walks up from the working directory to the module root, so the
// scan covers internal/ and cmd/ as well as core/.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		// The repo root is the directory holding BOTH core/ and internal/;
		// core/ has its own go.mod, so go.mod alone stops one level short.
		if st, err := os.Stat(filepath.Join(dir, "internal")); err == nil && st.IsDir() {
			if st, err := os.Stat(filepath.Join(dir, "core")); err == nil && st.IsDir() {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("repo root (a directory holding both core/ and internal/) not found; " +
		"this guard only runs inside a full checkout")
	return ""
}
