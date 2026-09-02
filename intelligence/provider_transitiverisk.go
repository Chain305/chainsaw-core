package intelligence

// evaluateTransitiveRisk overlays transitive-dependency risk onto the
// freshly-computed Report.Risk. The single-package risk evaluator
// (called by ComputeTrustScore) only sees the package itself; this
// helper extends the picture with an N-level depgraph built from
// Report.Dependencies.Direct (and the recursive Direct lists of each
// resolved descendant) plus the cached intelligence rows for each
// resolved dep. The output is a reshaped Report.Risk whose RolledUp
// score reflects descendant deficits, with Resolution.TransitiveBlame
// listing dependencies whose direct verdict was anything other than
// "allow".
//
// Only the Direct bucket of each visited node is walked. Peer, Dev,
// and Optional buckets are deliberately excluded: peer deps are
// caller-supplied so the security signal belongs to the caller's
// manifest, dev deps don't ship to production runtimes, and optional
// deps may simply be absent at install time. Including them would
// over-attribute risk to the host package and noise up the Dependency
// Alerts UI tab.
//
// Walk depth is configurable via env CHAINSAW_TRANSITIVE_DEPTH
// (default 5, hard-capped at TransitiveDepthMax = 10 to prevent
// runaway expansion through pathological dep graphs). Depth 1
// preserves the historical "direct-only" behaviour. The walker
// remains cycle-safe: a `visited` set keyed on
// (ecosystem|name@version) collapses self-references and case-drifted
// duplicates so a -> b -> a -> ... terminates immediately, and the
// closure-size accounting uses the existing depgraph.Descendants()
// BFS (already cycle-safe — see graph.go) rather than a parallel
// traversal, so one cycle-correctness invariant covers both surfaces.
//
// ---------------------------------------------------------------------
// WHAT THIS CLOSURE MEANS — J-2, ruled 2026-09-02. Read before changing
// anything about resolution.
// ---------------------------------------------------------------------
//
// The tree this builds is **what a fresh install would resolve to
// TODAY**, not what the pinned release resolved to at the moment it was
// published. Every open-ended edge is matched against THE CACHE AS IT
// STANDS NOW (pickConstraintMatchDetailed takes the highest cached
// version that satisfies the constraint); nothing here consults registry
// publish dates, and nothing tries to reconstruct the dependency set that
// existed on the parent's release day.
//
// THAT IS A DELIBERATE PRODUCT DECISION, NOT AN ACCIDENT. Publish-time
// resolution would need per-version publish timestamps for every
// dependency in every ecosystem plus a point-in-time resolver — a much
// larger build — and the "install it today" reading is the one that
// matches what the user's `bundle install` / `pip install` / `mvn` will
// actually place on disk. An enforcement product is being asked about the
// install that is about to happen.
//
// THE CONSEQUENCE, STATED PLAINLY: re-scanning an UNCHANGED coordinate
// can produce a DIFFERENT closure over time, because the cache moved, not
// because the package did. A closure is a statement about today's
// registry, not a property of the pinned release. Do not read a closure
// diff between two scans of the same version as package drift.
//
// It also has a bias, which is recorded and NOT fixed — see J-3 below.
//
// ---------------------------------------------------------------------
// J-3: TRANSITIVE SEVERITY IS A FLOOR, NOT AN ESTIMATE. Recorded
// 2026-09-02. Known limit, deliberately unfixed.
// ---------------------------------------------------------------------
//
// Because every open-ended edge resolves to the MAXIMUM cached satisfying
// version, and the newest version of a package is usually the LEAST
// vulnerable one, this walk is systematically biased toward
// under-reporting. The vulnerable older version can be sitting in the
// same cache and be excluded purely by the take-the-max rule. Worked
// example: cached rubygems/rack is 1.6.5, 3.2.6, 3.2.7 with max_cvss 10,
// null, null — the CVSS-10 row IS cached and is excluded precisely
// because `>= 1.3` takes the max.
//
// Measured 2026-09-02 on the full production export (7,756 rows), ordered
// with the same per-ecosystem satisfiers this file uses rather than
// lexically: 57 of 1,142 package names with more than one cached version
// (5.0%) have a newest cached version that is safer than an older cached
// version carrying CVSS >= 7. A further 52 groups could not be ordered
// under their own ecosystem's grammar, so 57 is itself a floor.
//
// READ EVERY TransitiveSeverity COUNT AS A LOWER BOUND. The direction of
// the error is under-statement, not over-blocking, so it is an internal
// correctness limit rather than a truthfulness problem. Fixing it means
// evaluating every cached satisfying version instead of the max, which
// changes the cost model of the walk; that is not scheduled. Details in
// docs/POLICY_PROXY_MATRIX.md, "Transitive closure semantics".

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	gem "github.com/aquasecurity/go-gem-version"
	pep440 "github.com/aquasecurity/go-pep440-version"
	mvn "github.com/masahiro331/go-mvn-version"

	"github.com/chain305/chainsaw-core/depgraph"
	"github.com/chain305/chainsaw-core/risk"
)

// TransitiveDepthDefault is the depth used when
// CHAINSAW_TRANSITIVE_DEPTH is unset or invalid. 5 levels covers the
// vast majority of real-world parent→child→grandchild blame chains
// without hitting the cache-miss tail that exponentially grows past
// depth 5 in npm/pypi corpora.
const TransitiveDepthDefault = 5

// TransitiveDepthMax is the hard cap. A pathological graph (or a
// mis-set env var) cannot cause the walker to blow through more than
// 10 levels of cached deps. The cap is enforced AFTER reading the
// env, so misconfiguration silently clamps to the safe ceiling rather
// than failing startup.
const TransitiveDepthMax = 10

// TransitiveDepthEnv is the env-var name that overrides the default
// walk depth. Read once per evaluateTransitiveRisk invocation; the
// cost (one os.Getenv per scan) is below noise on the proxy hot path.
const TransitiveDepthEnv = "CHAINSAW_TRANSITIVE_DEPTH"

// transitiveDepthFromEnv resolves the configured walk depth from the
// process environment, falling back to TransitiveDepthDefault on any
// parse failure or out-of-range value. A returned value is always in
// [1, TransitiveDepthMax].
func transitiveDepthFromEnv() int {
	v := strings.TrimSpace(os.Getenv(TransitiveDepthEnv))
	if v == "" {
		return TransitiveDepthDefault
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return TransitiveDepthDefault
	}
	if n > TransitiveDepthMax {
		return TransitiveDepthMax
	}
	return n
}

// lookupOutcome explains why a single direct-dep lookup did or didn't
// produce a graph node. evaluateTransitiveRisk uses it to emit a
// distinct Observation Warning per failure mode so operators can tell
// a cache-cold miss from a transient store error from a non-semver
// constraint the resolver couldn't reason about.
type lookupOutcome int

const (
	lookupResolved              lookupOutcome = iota // dep found in cache
	lookupNotCached                                  // dep absent — cache cold
	lookupConstraintUnparseable                      // constraint not semver, no probe matched
	lookupStoreError                                 // store returned a non-not-found error
	// lookupSuperseded: a row for this dep IS cached, but it was
	// produced by a retired matcher generation, so it is skipped for the
	// same reason a stale row is skipped everywhere else. Split out from
	// lookupNotCached because the two need opposite responses from an
	// operator — a cold miss means the dep has never been scanned, a
	// superseded row means it has and is queued for recompute — and
	// because after an epoch bump this is the overwhelmingly common
	// case. Reporting it as "not in cache" sent operators looking for a
	// scan that had already happened.
	lookupSuperseded
)

// transitiveLookup is the read-only cache slice the helper needs.
// Defined as an interface so unit tests can stub a tiny in-memory
// map without pulling pgstore. ListVersions returns every cached
// version of (eco, name) so lookupDepReport can pick a row that
// satisfies a range constraint when no candidate probe matches.
type transitiveLookup interface {
	Get(ctx context.Context, orgID string, key Key) (*Report, error)
	ListVersions(ctx context.Context, orgID, ecosystem, name string) ([]string, error)
}

func evaluateTransitiveRisk(ctx context.Context, store transitiveLookup, orgID string, report *Report) {
	if store == nil || report == nil || report.Risk == nil {
		return
	}
	deps := report.Dependencies.Direct
	if len(deps) == 0 {
		return
	}

	rootKey := depgraph.Key{
		Ecosystem: report.Identity.Ecosystem,
		Name:      report.Identity.Package,
		Version:   report.Identity.Version,
	}
	graph := depgraph.NewGraph()
	graph.AddNode(rootKey, true, true)
	graph.Roots = append(graph.Roots, rootKey)

	inputs := map[depgraph.Key]risk.Input{
		rootKey: ProjectToRiskInput(report),
	}

	// nodeSafe is the per-descendant upgrade evidence the tree pass needs
	// so a dependency that legitimately earned upgrade_available in its
	// OWN scan is not re-derived as bare quarantine inside somebody
	// else's tree — which would leave it in blockedNodes and inflate the
	// parent's "N blocked dependencies" count with a dependency that has
	// a published fix.
	//
	// The evidence is per-node and comes from the descendant's OWN
	// cached Report, which the BFS below already holds: lookupDepReport
	// returns the very *Report the risk.Input was projected from, so
	// MinimumSafeVersion and upgradeCandidateCorroborated can be asked
	// about that node exactly as ComputeTrustScoreForOrg asks them about
	// the root. Nothing is invented and nothing is borrowed from the
	// parent.
	//
	// The ROOT is deliberately absent from this map.
	// ReapplyKnownFixAfterTransitive owns the root's promotion, and it
	// re-runs the gates against the OVERLAID evaluation (i.e. after the
	// more-conservative secondEval has been folded in), which is
	// strictly more conservative than promoting the root inside the tree
	// pass would be.
	nodeSafe := make(map[depgraph.Key]string)

	// visited collapses self-references and case-drifted duplicates so
	// the same (eco, name, resolved-version) triple yields exactly one
	// node and one edge in the graph. Seeded with the root so an A→A
	// listing is a no-op. Used across every level of the BFS — once a
	// node is visited at level k, a deeper rediscovery of the same
	// (eco, name, version) at level k+1 is a no-op, which both
	// guarantees cycle termination and avoids double-counting fan-in.
	visited := map[string]bool{
		visitedKey(rootKey.Ecosystem, rootKey.Name, rootKey.Version): true,
	}

	// Level-0 frontier is the package's own Direct list. Each
	// subsequent level walks the resolved nodes' Direct buckets,
	// re-using the same lookup/cache/warning machinery as the
	// historical one-level pass. Only "true" direct-dep failures (the
	// root's own Direct entries) emit warnings; level >= 2 cache
	// misses are the common case (transitive grandchildren that
	// haven't been scanned yet) and would flood Observation.Warnings
	// without giving operators actionable signal.
	maxDepth := transitiveDepthFromEnv()

	// J-1 (P8-08). Every constraint the ROOT declares on a dependency
	// name, indexed so the BFS can refuse a resolved node the root's own
	// manifest forbids. Empty for every ecosystem outside
	// singleVersionEcosystems, which makes the check free for npm roots.
	// See the J-1 block above violatesDeclaredRootConstraint.
	rootConstraints := buildRootConstraintIndex(deps, report.Identity.Ecosystem)
	conflictsRefused := 0
	conflictWarnings := 0

	type frontierEntry struct {
		parent      depgraph.Key
		ref         DependencyRef
		fallbackEco string
		emitWarn    bool
	}
	frontier := make([]frontierEntry, 0, len(deps))
	for _, ref := range deps {
		frontier = append(frontier, frontierEntry{
			parent:      rootKey,
			ref:         ref,
			fallbackEco: report.Identity.Ecosystem,
			emitWarn:    true,
		})
	}

	resolvedDirect := 0
	for level := 1; level <= maxDepth; level++ {
		next := make([]frontierEntry, 0)
		for _, entry := range frontier {
			ref := entry.ref
			eco := strings.TrimSpace(ref.Ecosystem)
			if eco == "" {
				eco = entry.fallbackEco
			}
			depKey, depReport, outcome, lookupErr := lookupDepReport(ctx, store, orgID, eco, ref.Name, ref.Constraint)
			switch outcome {
			case lookupNotCached:
				if entry.emitWarn {
					emitTransitiveWarning(report, WarnTransitiveDepNotCached,
						fmt.Sprintf("direct dep %s/%s@%s not in cache", eco, ref.Name, displayConstraint(ref.Constraint)))
				}
				continue
			case lookupSuperseded:
				// Deliberately NOT enqueuing a rescan here. Two
				// mechanisms already cover this row: the matcher-epoch
				// recompute sweep targets every row below
				// CurrentMatcherEpoch by construction, and
				// enqueueDependencyScans — which the scanner runs a few
				// statements after this walk (scanner.go) — lets a stale
				// cache entry fall through to a real Scan. Adding a third
				// enqueue inside the BFS would fan out one scan per node
				// per level on a cold tree, from inside a scan that is
				// already holding a deadline.
				//
				// The cost of that choice is honest and bounded: this
				// walk sees the cache as it was BEFORE the enqueuer runs,
				// so the rollup persisted by THIS scan is missing the
				// dep, and it corrects on the next scan of this root. The
				// warning below says so rather than leaving the tree
				// silently short a node.
				if entry.emitWarn {
					msg := fmt.Sprintf("direct dep %s/%s@%s is cached but was produced by a retired matcher generation (serve floor %d); it is queued for recompute and is excluded from this tree until then",
						eco, ref.Name, displayConstraint(ref.Constraint), MinServeableEpoch)
					if e := supersededDepEpoch(ctx, store, orgID, eco, ref.Name, ref.Constraint); e > 0 {
						msg = fmt.Sprintf("direct dep %s/%s@%s is cached at matcher epoch %d, below the serve floor %d; it is queued for recompute and is excluded from this tree until then",
							eco, ref.Name, displayConstraint(ref.Constraint), e, MinServeableEpoch)
					}
					emitTransitiveWarning(report, WarnTransitiveDepSuperseded, msg)
				}
				continue
			case lookupConstraintUnparseable:
				if entry.emitWarn {
					msg := fmt.Sprintf("direct dep %s/%s constraint %q not parseable as semver", eco, ref.Name, ref.Constraint)
					if lookupErr != nil {
						msg = msg + ": " + lookupErr.Error()
					}
					emitTransitiveWarning(report, WarnTransitiveDepConstraintUnparseable, msg)
				}
				continue
			case lookupStoreError:
				if entry.emitWarn {
					msg := fmt.Sprintf("direct dep %s/%s@%s store lookup failed", eco, ref.Name, displayConstraint(ref.Constraint))
					if lookupErr != nil {
						msg = msg + ": " + lookupErr.Error()
					}
					emitTransitiveWarning(report, WarnTransitiveDepLookupError, msg)
				}
				continue
			}
			if depKey == (depgraph.Key{}) {
				continue
			}
			// J-1 (P8-08). The dependency resolved, but to a version the
			// ROOT's own manifest forbids — so it is not in this package's
			// install and must not be scored, counted or blamed as if it
			// were. Refusing here rather than after the BFS also prunes the
			// subtree for free: `continue` skips the enqueue below, so the
			// grandchildren read off the anachronism never enter the graph
			// either. The check is a pure function of (eco, name, version)
			// and the root's constraints, so it gives the same answer no
			// matter which edge discovers the node — it cannot depend on
			// walk order, and it is placed BEFORE the `visited` branch so
			// that stays true.
			if depKey != rootKey {
				if badConstraint, conflict := violatesDeclaredRootConstraint(
					rootConstraints, depKey.Ecosystem, depKey.Name, depKey.Version); conflict {
					conflictsRefused++
					if conflictWarnings < transitiveConflictWarnCap {
						conflictWarnings++
						emitTransitiveWarning(report, WarnTransitiveDepConstraintConflict,
							fmt.Sprintf("closure dep %s/%s@%s resolved via %s/%s but violates this package's own declared constraint %q on %s; excluded from the dependency tree",
								depKey.Ecosystem, depKey.Name, depKey.Version,
								entry.parent.Name, entry.parent.Version,
								badConstraint, depKey.Name))
					}
					continue
				}
			}
			vk := visitedKey(depKey.Ecosystem, depKey.Name, depKey.Version)
			if visited[vk] {
				if entry.emitWarn {
					resolvedDirect++
				}
				// Already in graph: still attach an edge from this
				// parent so multi-parent fan-in is preserved. AddEdge
				// is idempotent on (parent, child) pairs.
				graph.AddEdge(entry.parent, depKey)
				continue
			}
			visited[vk] = true
			if _, exists := graph.Nodes[depKey]; !exists {
				graph.AddNode(depKey, false, true)
			}
			graph.AddEdge(entry.parent, depKey)
			if depReport != nil {
				inputs[depKey] = ProjectToRiskInput(depReport)
				// This descendant's own evidence, on this descendant's
				// own coordinate. Empty (the common case) means "no
				// version of this package is provably clear of every
				// advisory that still affects it" and the node keeps
				// whatever verdict the engine gives it.
				if sv := MinimumSafeVersion(depReport); sv != "" &&
					upgradeCandidateCorroborated(depReport, sv) {
					nodeSafe[depKey] = sv
				}
				// Enqueue this node's own Direct deps for the next
				// BFS level — but only if we haven't reached the
				// configured max depth. A nil/empty Direct list
				// short-circuits the next level naturally.
				if level < maxDepth {
					for _, child := range depReport.Dependencies.Direct {
						next = append(next, frontierEntry{
							parent:      depKey,
							ref:         child,
							fallbackEco: depKey.Ecosystem,
							emitWarn:    false,
						})
					}
				}
			}
			if entry.emitWarn {
				resolvedDirect++
			}
		}
		frontier = next
		if len(frontier) == 0 {
			break
		}
	}

	if conflictsRefused > conflictWarnings {
		emitTransitiveWarning(report, WarnTransitiveDepConstraintConflict,
			fmt.Sprintf("%d closure dependencies in total were excluded for violating this package's own declared constraints; %d are itemised above",
				conflictsRefused, conflictWarnings))
	}

	// Always record coverage when at least one direct dep was declared,
	// even if the rolled-up evaluation short-circuits below — a 0/N
	// reading is the most actionable case for a policy evaluator.
	// Resolved/Total still count direct deps only so the gauge stays
	// comparable to the historical one-level numbers; closure size
	// (set below) carries the multi-level signal.
	report.SupplyChain.TransitiveCoverage = &TransitiveCoverage{
		Resolved:    resolvedDirect,
		Total:       len(deps),
		Complete:    resolvedDirect == len(deps) && len(deps) > 0,
		MaxDepth:    maxDepth,
		ClosureSize: len(graph.Descendants(rootKey)),
	}

	if len(graph.Nodes) <= 1 {
		return
	}

	te := risk.EvaluateTree(graph, inputs, risk.Options{PerNodeSafeUpgrade: nodeSafe})
	rootEval := te.ByKey[rootKey]
	if rootEval == nil {
		return
	}

	// Tally severity-bucketed transitive findings across descendants.
	// Walks every node in te.ByKey except the root, sums fired
	// vulnerability signals per CVSS tier, and counts malware /
	// blocked-verdict descendants. CVEs are deduped across descendants
	// so the same advisory pulled in via two grandparents only counts
	// once per severity.
	ts := computeTransitiveSeverity(te, rootKey)
	rootEval.Resolution.TransitiveSeverity = ts

	// Fold the populated severity counts back into the root's risk
	// Input so a second EvaluatePackage call fires the new
	// sc.transitive_* signals. The first evaluation (inside
	// EvaluateTree) ran with zero counts; this second pass is the
	// natural place to re-score with transitive context. The original
	// te.RolledUp (descendant-deficit decay) and TransitiveBlame are
	// preserved below — the second pass only changes the root's own
	// direct-signal set.
	rootInput := inputs[rootKey]
	rootInput.TransitiveCriticalCount = ts.CriticalCount
	rootInput.TransitiveHighCount = ts.HighCount
	rootInput.TransitiveMediumCount = ts.MediumCount
	rootInput.TransitiveLowCount = ts.LowCount
	rootInput.TransitiveMalwareCount = ts.MalwareCount
	rootInput.TransitiveBlockedCount = ts.BlockedCount

	var secondEval *risk.Evaluation
	if hasTransitiveSignal(ts) {
		secondEval = risk.EvaluatePackage(rootInput, risk.Options{})
	}

	// Overlay rolled-up score, verdict, and blame onto the existing
	// Risk evaluation. DirectScore stays as the single-package eval.
	report.Risk.RolledUp = rootEval.RolledUp
	report.Risk.Verdict = rootEval.Verdict
	report.Risk.Resolution = rootEval.Resolution

	// If the second evaluation produced a more conservative verdict
	// (because a transitive critical / malware signal fired), let it
	// win. Critical-class signals must drive the root's verdict even
	// when the rolled-up category-decay numbers stayed above the
	// threshold. Preserve TransitiveBlame from the tree pass — it
	// carries the per-descendant attribution the UI renders.
	if secondEval != nil && verdictRank(secondEval.Verdict) > verdictRank(rootEval.Verdict) {
		preservedBlame := report.Risk.Resolution.TransitiveBlame
		report.Risk.Verdict = secondEval.Verdict
		report.Risk.Resolution = secondEval.Resolution
		report.Risk.Resolution.TransitiveBlame = preservedBlame
		// Push the worse-of-two onto RolledUp so the score consumers
		// see the transitive penalty too.
		if secondEval.DirectScore.Overall < report.Risk.RolledUp.Overall {
			report.Risk.RolledUp = secondEval.DirectScore
		}
	}
	// Always carry the severity counts on Resolution so UI/API
	// consumers can render the Socket-style transitive_vulnerabilities
	// summary line regardless of whether a signal fired.
	report.Risk.Resolution.TransitiveSeverity = ts

	// If the rolled-up score wasn't dragged below the direct score
	// far enough to populate TransitiveBlame, but at least one direct
	// dep has a non-allow verdict, surface those deps anyway so the
	// UI Dependency Alerts tab has data. Without this users see an
	// empty tab even when their direct deps have known issues.
	if len(report.Risk.Resolution.TransitiveBlame) == 0 {
		// te.ByKey is a map, so collect first and sort before appending.
		// This list is rendered in order in the Dependency Alerts tab;
		// appending straight out of map iteration meant the same tree
		// listed the same deps in a different order on every evaluation,
		// which reads to a user as the data changing under them.
		fallback := make([]depgraph.Key, 0, len(te.ByKey))
		for k, ev := range te.ByKey {
			if k == rootKey || ev == nil {
				continue
			}
			if ev.Verdict != "" && ev.Verdict != risk.VerdictAllow {
				fallback = append(fallback, k)
			}
		}
		sort.Slice(fallback, func(i, j int) bool {
			return depgraph.KeyLess(fallback[i], fallback[j])
		})
		for _, k := range fallback {
			report.Risk.Resolution.TransitiveBlame = append(report.Risk.Resolution.TransitiveBlame, risk.Key{
				Ecosystem: k.Ecosystem,
				Package:   k.Name,
				Version:   k.Version,
			})
		}
	}

	// Mirror the rolled-up score into the legacy supply-chain bucket —
	// v2 is unconditionally authoritative for the score field after the
	// cutover (see ComputeTrustScore).
	report.SupplyChain.TrustScore = rootEval.RolledUp.Overall
}

// ---------------------------------------------------------------------
// J-1: constraint reconciliation (P8-08)
// ---------------------------------------------------------------------
//
// THE DEFECT. Every edge in the BFS above is resolved INDEPENDENTLY, to
// the maximum cached version that satisfies that one edge's constraint
// (pickConstraintMatchDetailed). Nothing unifies the constraints that
// several parents declare on the same package name, and visitedKey is
// keyed on name+version, so two versions of one package are unrelated
// nodes. A 2018 parent therefore walks forward into the 2026 tree:
// rubygems/actionpack@5.2.0 declares `rack ~> 2.0`, that edge finds no
// satisfier in cache, and rack@3.2.7 still enters the closure via
// rack-test@2.2.0's `rack >= 1.3` — where it is then BLAMED on a package
// whose own manifest, in the same report, forbids it.
//
// THE RULE. After a dependency resolves, test the resolved version
// against every constraint the ROOT declares on that same package name.
// A version that violates one is refused: it is not added to the graph,
// no edge is drawn to it, and its own Direct list is never enqueued, so
// the subtree that hangs off the anachronism goes with it.
//
// WHY REFUSE THE NODE RATHER THAN JUST SUPPRESS ITS BLAME LINE. Blame is
// downstream of the score, not the other way round: a node kept in the
// graph still contributes its deficit to RolledUp and still increments
// the sc.transitive_* severity counts that can drive the root's verdict.
// Suppressing only the blame line would leave the package's score
// depressed by a dependency it cannot install AND remove the one field
// that says which one — a wrong number with its explanation deleted,
// which is strictly worse to operate than a wrong number you can see.
// Refusing the node keeps score, counts and explanation consistent with
// each other.
//
// THE TWO LIMITS, both deliberate, both chosen against over-reach.
//
//  1. ROOT-DECLARED CONSTRAINTS ONLY. The root's Direct list is
//     first-party data about the coordinate under evaluation. A
//     constraint declared by a NON-root parent is only as trustworthy as
//     the max-satisfying chain that put that parent in the tree — it may
//     itself be the anachronism. Refusing a node on that evidence would
//     let one wrongly-resolved parent erase a legitimate subtree, which
//     is exactly the failure this fix exists to prevent, pointed the
//     other way. Deeper conflicts are therefore left alone.
//
//  2. SINGLE-VERSION ECOSYSTEMS ONLY. The rule is only sound where a
//     violated constraint PROVES the version is absent. In npm, yarn,
//     pnpm, bun and cargo it proves nothing: nested resolution installs
//     several versions of one package at once, so a root pinned to
//     `foo ^1` can legitimately have a vulnerable `foo@2` on disk
//     underneath a transitive dep. Refusing it there would hide a real
//     node. resolvesSingleVersion is an explicit ALLOWLIST for that
//     reason: an unrecognised ecosystem keeps the historical behaviour.
//
// WHAT THIS IS NOT. It is not a resolver and it does not re-pick a
// version. It only deletes closure members that the root's own manifest
// contradicts. The residual bias — every open-ended edge still resolving
// to the maximum cached version, and so to the LEAST vulnerable one — is
// J-3 and is unfixed; see the doc block on evaluateTransitiveRisk.

// transitiveConflictWarnCap bounds how many distinct constraint-conflict
// warnings one report can carry. Unlike the cache-miss warnings, these
// are emitted at EVERY depth (a refused node is a fact about this tree,
// not about the corpus), so a pathological graph needs a ceiling. The
// count of refusals is reported in full even when the per-node detail is
// truncated.
const transitiveConflictWarnCap = 10

// singleVersionEcosystems lists the ecosystems whose installer resolves
// exactly ONE version per package name per build, so that a constraint
// violated anywhere in the manifest is proof the version is not present.
//
// ALLOWLIST, NOT DENYLIST, on purpose: an ecosystem nobody has reasoned
// about must fall through to the historical behaviour rather than
// inherit a rule that only holds for flat resolvers. npm/yarn/pnpm/bun
// (nested node_modules) and cargo (one copy per semver-major) are the
// known-unsound cases and are absent by design, as are the `*-hosted`
// pseudo-ecosystems (their constraint grammar falls through to the
// npm-flavoured default in parseEcosystemConstraint, so their
// constraints are not reliably parsed under their real syntax) and the
// OS/image ecosystems, which are not package-resolution problems at all.
var singleVersionEcosystems = map[string]bool{
	"rubygems":  true, // Gemfile.lock: one version per gem
	"gem":       true,
	"pypi":      true, // site-packages: one distribution per name
	"pip":       true,
	"maven":     true, // nearest-wins conflict resolution: one per groupId:artifactId
	"gradle":    true,
	"nuget":     true, // one package version per project
	"composer":  true, // composer.lock: one version per package
	"packagist": true,
	"go":        true, // MVS: one version per module path (a new major is a new path)
	"gomod":     true,
	"golang":    true,
	"pub":       true, // pubspec.lock: one version per package
	"hex":       true,
	"cocoapods": true,
	"swift":     true,
}

// resolvesSingleVersion reports whether the ecosystem's installer picks
// exactly one version per package name. Only these ecosystems are
// eligible for constraint reconciliation — see limit (2) above.
func resolvesSingleVersion(ecosystem string) bool {
	return singleVersionEcosystems[strings.ToLower(strings.TrimSpace(ecosystem))]
}

// rootConstraintIndex maps a dependency coordinate to every constraint
// the ROOT declares on it. Keyed with visitedKey's normalisation minus
// the version, i.e. lowercased ecosystem and name, so a case-drifted
// manifest entry still matches the resolved node.
//
// Entries whose constraint is empty are skipped: "no constraint" cannot
// be violated. Entries in an ecosystem that is not single-version are
// skipped too, so the map is empty for npm roots and the whole check
// costs one map lookup that always misses.
func buildRootConstraintIndex(deps []DependencyRef, fallbackEco string) map[string][]string {
	idx := make(map[string][]string, len(deps))
	for _, ref := range deps {
		eco := strings.TrimSpace(ref.Ecosystem)
		if eco == "" {
			eco = fallbackEco
		}
		if !resolvesSingleVersion(eco) {
			continue
		}
		c := strings.TrimSpace(ref.Constraint)
		if c == "" || !constraintIsActionable(c) {
			continue
		}
		name := strings.TrimSpace(ref.Name)
		if name == "" {
			continue
		}
		k := strings.ToLower(eco) + "|" + strings.ToLower(name)
		idx[k] = append(idx[k], c)
	}
	return idx
}

// constraintIsActionable reports whether a declared constraint is
// strong enough to DELETE a node on. It requires an explicit relational
// operator, range or bracket — `~> 2.0`, `>= 1.0.2, ~> 1.0`, `= 5.2.0`,
// `<4,>=2`, `[1.0,2.0)`. A BARE version string is refused.
//
// THIS IS THE LOAD-BEARING GUARD, and it was added after measurement,
// not before. A bare version does not mean the same thing across
// ecosystems, and in the three that dominate this corpus it does NOT
// mean "pinned":
//
//   - Maven / Gradle: `<version>1.27</version>` is a SOFT requirement.
//     Dependency mediation (nearest-wins, or Gradle's highest-wins) can
//     and constantly does resolve a different version.
//   - Go: `require gopkg.in/yaml.v3 v3.0.1` is a MINIMUM. MVS selects
//     the highest version required anywhere in the build.
//   - NuGet: a bare `Version="1.2.3"` is the lower bound of `[1.2.3, )`.
//
// translateBracketConstraint deliberately reads a bare Maven version as
// `=1.0` because an exact read is the SAFER default for advisory
// matching. It is the more DANGEROUS default here: this rule deletes
// nodes, so reading a minimum as a pin would delete precisely the
// higher, newer, and often more-vulnerable version the real resolver
// selects. Measured on the 7,756-row prod corpus: without this guard the
// change flipped 11 verdicts, and 10 of them — every go and maven row —
// were driven by bare constraints read as pins, including a
// `quarantine -> allow` on maven/org.apache.maven.shared:maven-filtering
// that dropped 4 transitive criticals on that false premise. With the
// guard, only the constraint classes that really are enforced by their
// installer act.
//
// The cost is honest and stated: Maven, Gradle, NuGet and Go declare
// their dependencies almost entirely as bare versions, so in practice
// this rule reaches RubyGems, PyPI, Composer and the operator-bearing
// tail. Reconciling a soft requirement needs a mediation algorithm, not
// a satisfier, and that is not built.
func constraintIsActionable(c string) bool {
	c = strings.TrimSpace(c)
	if c == "" {
		return false
	}
	switch c[0] {
	case '<', '>', '=', '~', '^', '!', '[', '(':
		return true
	}
	return false
}

// violatesDeclaredRootConstraint reports whether `version` of (eco,
// name) contradicts a constraint the root declares on that same name,
// returning the offending constraint for the warning message.
//
// Every uncertain path answers "no". A constraint that will not parse, a
// version that will not parse, the `latest` sentinel, and an ecosystem
// outside the allowlist all fall through to false, because this function
// DELETES a node and the cost of a wrong deletion is a hidden dependency.
// The only true is a version that parsed, under a constraint that
// parsed, and failed it.
func violatesDeclaredRootConstraint(idx map[string][]string, eco, name, version string) (string, bool) {
	if len(idx) == 0 || !resolvesSingleVersion(eco) {
		return "", false
	}
	v := strings.TrimSpace(version)
	if v == "" || v == transitiveLatestVersionSentinel {
		return "", false
	}
	constraints := idx[strings.ToLower(strings.TrimSpace(eco))+"|"+strings.ToLower(strings.TrimSpace(name))]
	for _, c := range constraints {
		sat, err := parseEcosystemConstraint(eco, c)
		if err != nil || sat == nil {
			// Unparseable constraint: lookupDepReport already reports it
			// as WarnTransitiveDepConstraintUnparseable. It is not
			// evidence about this node.
			continue
		}
		if !sat.Valid(v) {
			// Not a version under this ecosystem's grammar (git ref,
			// distro tag, Maven build property). Check would return false
			// for it and that false would mean nothing.
			continue
		}
		if !sat.Check(v) {
			return c, true
		}
	}
	return "", false
}

// transitiveLatestVersionSentinel is the literal version string
// candidateVersions probes as a back-compat fallback. A row stored at
// that coordinate has no orderable version, so it is exempt from the
// conflict check rather than being deleted for failing to satisfy
// anything.
const transitiveLatestVersionSentinel = "latest"

// visitedKey is the canonical dedupe key for the cycle / repeat guard.
// Lowercased so case-drifted manifest entries (e.g. "LEFT-PAD" vs
// "left-pad") collapse to one node.
func visitedKey(eco, name, version string) string {
	return strings.ToLower(eco) + "|" + strings.ToLower(name) + "@" + version
}

// lookupDepReport tries to resolve a dependency name to a cached
// intelligence Report. The store is keyed on (ecosystem, package,
// version) but we only have a constraint string for the dep — so we
// probe the constraint verbatim, then the operator-stripped lower
// bound (when it parses as semver), then fall back to enumerating
// every cached version of (eco, name) and picking the highest one
// that satisfies the constraint, then finally the "latest" sentinel
// for back-compat.
//
// The enumerate-and-match step is what fixes the most common cause
// of empty Dependency Alerts: a dep declared as "^1.2.0" with the
// cache holding "1.5.3". Probing "^1.2.0" / "1.2.0" / "latest" all
// miss; iterating cached versions and parsing the constraint via
// Masterminds/semver finds 1.5.3.
func lookupDepReport(ctx context.Context, store transitiveLookup, orgID, eco, name, constraint string) (depgraph.Key, *Report, lookupOutcome, error) {
	var firstStoreErr error
	// Epoch of the first superseded row we saw, 0 if none. Recorded so
	// the caller can say WHY the dep was skipped rather than reporting a
	// cached-but-retired row as an absent one. Does not change which
	// rows are usable — a retired verdict is still not served.
	supersededEpoch := 0
	noteSuperseded := func(r *Report) {
		if r != nil && supersededEpoch == 0 {
			supersededEpoch = r.Observation.MatcherEpoch
		}
	}
	for _, candidate := range candidateVersions(constraint) {
		k := Key{Ecosystem: eco, Package: name, Version: candidate}
		r, err := store.Get(ctx, orgID, k)
		// A superseded-matcher row is skipped like a miss so the next
		// candidate version gets a chance; a transitive alert built on a
		// retracted verdict is worse than no alert.
		if err == nil && !r.MatcherStale() {
			return depgraph.Key{Ecosystem: eco, Name: name, Version: candidate}, r, lookupResolved, nil
		}
		if err == nil {
			noteSuperseded(r)
		}
		if err != nil && !errors.Is(err, ErrNotFound) && firstStoreErr == nil {
			firstStoreErr = err
		}
	}
	v, parseErr, listErr := pickConstraintMatchDetailed(ctx, store, orgID, eco, name, constraint)
	if listErr != nil && firstStoreErr == nil {
		firstStoreErr = listErr
	}
	if v != "" {
		k := Key{Ecosystem: eco, Package: name, Version: v}
		r, err := store.Get(ctx, orgID, k)
		if err == nil && !r.MatcherStale() {
			return depgraph.Key{Ecosystem: eco, Name: name, Version: v}, r, lookupResolved, nil
		}
		if err == nil {
			noteSuperseded(r)
		}
		if err != nil && !errors.Is(err, ErrNotFound) && firstStoreErr == nil {
			firstStoreErr = err
		}
	}
	if firstStoreErr != nil {
		return depgraph.Key{}, nil, lookupStoreError, firstStoreErr
	}
	if parseErr != nil {
		// Surface the actual parser error so the warning is diagnostic
		// (e.g. "expected version number" vs "improper constraint").
		return depgraph.Key{}, nil, lookupConstraintUnparseable, parseErr
	}
	// Ordered after the error cases on purpose: a store error or an
	// unparseable constraint is a different problem and stays the
	// headline. Supersession only explains an otherwise-clean miss.
	if supersededEpoch > 0 {
		return depgraph.Key{}, nil, lookupSuperseded, nil
	}
	return depgraph.Key{}, nil, lookupNotCached, nil
}

// supersededDepEpoch re-runs the cheap half of lookupDepReport to recover
// the epoch of a superseded row for the warning text. Split out rather
// than widened into lookupDepReport's return signature because every
// other caller of that function wants the report, not the epoch, and
// this path runs at most once per direct dep on a cold tree.
func supersededDepEpoch(ctx context.Context, store transitiveLookup, orgID, eco, name, constraint string) int {
	for _, candidate := range candidateVersions(constraint) {
		// matcher-epoch-exempt: this read exists BECAUSE the row is
		// superseded — lookupDepReport has already refused it, and the
		// only thing taken from it is Observation.MatcherEpoch, an
		// integer used in a diagnostic warning string. No verdict,
		// score, or report field reaches a consumer, so checking
		// MatcherStale() here would reject the exact rows this function
		// is asked about and always return 0.
		if r, err := store.Get(ctx, orgID, Key{Ecosystem: eco, Package: name, Version: candidate}); err == nil && r != nil {
			return r.Observation.MatcherEpoch
		}
	}
	if v := pickConstraintMatch(ctx, store, orgID, eco, name, constraint); v != "" {
		// matcher-epoch-exempt: same as above — epoch only, no verdict.
		if r, err := store.Get(ctx, orgID, Key{Ecosystem: eco, Package: name, Version: v}); err == nil && r != nil {
			return r.Observation.MatcherEpoch
		}
	}
	return 0
}

// pickConstraintMatch enumerates cached versions for (eco, name) and
// returns the highest one that satisfies the constraint, or "" if
// the constraint can't be parsed, no versions are cached, or none
// satisfy it. Non-parseable versions in the cache (git refs, "latest"
// sentinels, distro-style tags) are skipped — they can't be ranked.
func pickConstraintMatch(ctx context.Context, store transitiveLookup, orgID, eco, name, constraint string) string {
	v, _, _ := pickConstraintMatchDetailed(ctx, store, orgID, eco, name, constraint)
	return v
}

// pickConstraintMatchDetailed is the variant the warning-aware caller
// uses: it returns the actual library parse error (so an "unparseable
// constraint" warning fires only on real parse failures, not on
// cache-empty misses, and includes the diagnostic library error) and
// surfaces the ListVersions store error so a transient backend failure
// can be flagged distinctly from a cold cache.
//
// Constraint parsing dispatches per-ecosystem to match the same
// per-ecosystem comparator used in osv.compareVersions (PEP 440 for
// PyPI, Gem for RubyGems, Maven for Maven/Gradle/NuGet/Composer,
// Masterminds/semver for everything else). The version-iteration loop
// reuses the same satisfier so the comparator used to rank
// "best (highest) match" comes from the same library that parsed the
// constraint — never mixing ecosystems' ordering rules.
func pickConstraintMatchDetailed(ctx context.Context, store transitiveLookup, orgID, eco, name, constraint string) (string, error, error) {
	sat, parseErr := parseEcosystemConstraint(eco, constraint)
	if parseErr != nil {
		return "", parseErr, nil
	}
	versions, err := store.ListVersions(ctx, orgID, eco, name)
	if err != nil {
		return "", nil, err
	}
	if len(versions) == 0 {
		return "", nil, nil
	}
	// Per-ecosystem max: each satisfier exposes a "better" comparator so
	// the highest qualifying version (ecosystem-correct ordering) wins.
	// Non-parseable cache entries are skipped — the satisfier's Check
	// returns false on them and the comparator-bearing Better path is
	// only consulted on entries that passed Check.
	var bestRaw string
	for _, v := range versions {
		if !sat.Check(v) {
			continue
		}
		if bestRaw == "" || sat.Greater(v, bestRaw) {
			bestRaw = v
		}
	}
	return bestRaw, nil, nil
}

// versionSatisfier abstracts an ecosystem-specific constraint matcher
// and the matching version comparator. Check reports whether a raw
// version string satisfies the parsed constraint; Greater reports
// whether `a` is a higher (later) version than `b` under the same
// ecosystem's ordering. Both inputs are raw strings — the satisfier
// re-parses them internally so callers don't need to know which
// library is in play.
//
// Valid reports whether a raw version string parses at all under this
// ecosystem's grammar. It exists because Check collapses two very
// different answers into one `false`: "this version is outside the
// range" and "this string is not a version". The max-satisfying picker
// is happy with that collapse — an unparseable cache entry simply
// cannot be the best match. The constraint-conflict check is NOT: it
// takes action on a false, so it must be able to tell an unparseable
// coordinate (git ref, `latest` sentinel, distro tag) from a genuine
// violation, and refuse to act on the former.
type versionSatisfier interface {
	Check(version string) bool
	Greater(a, b string) bool
	Valid(version string) bool
}

// parseEcosystemConstraint dispatches a constraint string to the
// per-ecosystem parser. Returns (nil, parseErr) when the constraint
// cannot be parsed under the chosen grammar so the caller can emit a
// diagnostic warning. The dispatch mirrors osv.compareVersions:
//
//	pypi              → PEP 440 (NewSpecifiers)
//	rubygems          → Gem (NewConstraints)
//	maven / gradle    → Maven (NewConstraints)
//	nuget             → Maven (bracket syntax is shared)
//	packagist         → Maven (Composer is Maven-flavoured)
//	default / unknown → Masterminds (npm/cargo/etc.)
func parseEcosystemConstraint(ecosystem, raw string) (versionSatisfier, error) {
	c := strings.TrimSpace(raw)
	switch normalizeEcosystem(ecosystem) {
	case "pypi":
		// pip writes PEP 440 specifiers in a wrapped form in some
		// metadata fields, e.g. "(<4,>=2)". Strip a single outer paren
		// layer so the library accepts the inner specifier list. Inner
		// parens are not legal in PEP 440 and would still fail.
		normalized := stripOuterParens(c)
		spec, err := pep440.NewSpecifiers(normalized)
		if err != nil {
			return nil, err
		}
		return pep440Satisfier{spec: spec}, nil
	case "rubygems":
		// Validate the constraint once so unparseable input surfaces
		// the library error to the warning path. The satisfier stores
		// the raw string and reparses per Check call (see the type
		// doc for why).
		if _, err := gem.NewConstraints(c); err != nil {
			return nil, err
		}
		return gemSatisfier{raw: c}, nil
	case "maven", "nuget", "packagist":
		// Maven, NuGet, and Composer all use bracket-range syntax
		// ([1.0,2.0), (,1.0], [1.5.3], etc.) which the underlying mvn
		// library doesn't parse natively — it accepts only
		// operator-prefixed comma-separated constraints. Translate to
		// the library's expected shape before parsing.
		translated, err := translateBracketConstraint(c)
		if err != nil {
			return nil, err
		}
		cs, err := mvn.NewConstraints(translated)
		if err != nil {
			return nil, err
		}
		return mvnSatisfier{cs: cs}, nil
	default:
		// npm / yarn / bun / cargo / go / unknown → Masterminds semver.
		// Preserves the historical behaviour for ecosystems whose
		// constraint syntax is already npm-flavoured.
		semC, err := semver.NewConstraint(c)
		if err != nil {
			return nil, err
		}
		return semverSatisfier{c: semC}, nil
	}
}

// normalizeEcosystem maps the caller-facing ecosystem name to the
// dispatch bucket. Kept local (rather than depending on
// osv.CanonicalEcosystem) so this package stays decoupled from osv —
// the two tables happen to agree but evolve under different
// constraints (this one cares about constraint *grammar*, not advisory
// feed routing).
func normalizeEcosystem(ecosystem string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "pip", "pypi":
		return "pypi"
	case "rubygems", "gem":
		return "rubygems"
	case "maven", "gradle":
		return "maven"
	case "nuget":
		return "nuget"
	case "composer", "packagist":
		return "packagist"
	default:
		return "default"
	}
}

// semverSatisfier wraps Masterminds/semver. Used for npm-family and
// any ecosystem without an explicit dispatch entry. Greater falls back
// to "no parse" → false so the iteration just keeps the first match
// when versions can't be ranked.
type semverSatisfier struct {
	c *semver.Constraints
}

func (s semverSatisfier) Check(version string) bool {
	v, err := semver.NewVersion(version)
	if err != nil {
		return false
	}
	return s.c.Check(v)
}

func (s semverSatisfier) Valid(version string) bool {
	_, err := semver.NewVersion(version)
	return err == nil
}

func (s semverSatisfier) Greater(a, b string) bool {
	va, err := semver.NewVersion(a)
	if err != nil {
		return false
	}
	vb, err := semver.NewVersion(b)
	if err != nil {
		return false
	}
	return va.GreaterThan(vb)
}

// pep440Satisfier wraps go-pep440-version. PEP 440 handles wildcards
// (==3.6.*), compatible release (~=1.4.2), and pre/post/dev release
// segments natively.
type pep440Satisfier struct {
	spec pep440.Specifiers
}

func (p pep440Satisfier) Check(version string) bool {
	v, err := pep440.Parse(version)
	if err != nil {
		return false
	}
	return p.spec.Check(v)
}

func (p pep440Satisfier) Valid(version string) bool {
	_, err := pep440.Parse(version)
	return err == nil
}

func (p pep440Satisfier) Greater(a, b string) bool {
	va, err := pep440.Parse(a)
	if err != nil {
		return false
	}
	vb, err := pep440.Parse(b)
	if err != nil {
		return false
	}
	return va.Compare(vb) > 0
}

// gemSatisfier wraps go-gem-version. RubyGems uses the pessimistic
// "~>" operator and treats pre-release versions specially: a stable
// constraint like ">= 7.0.0" does NOT match "7.0.0.beta1" unless the
// constraint itself contains a pre-release segment. The library
// implements that rule directly.
//
// Implementation note: the upstream library's pessimistic operator
// implementation mutates the constraint version's segment slice during
// Bump(), which leaves the Constraints value in a "consumed" state
// after the first Check call. The satisfier therefore stores the raw
// constraint string and reparses on every Check so each comparison
// starts from a pristine constraint. The cost is one regex parse per
// cached version per name, which is bounded and far cheaper than a
// silently-wrong match.
type gemSatisfier struct {
	raw string
}

func (g gemSatisfier) Check(version string) bool {
	cs, err := gem.NewConstraints(g.raw)
	if err != nil {
		return false
	}
	v, err := gem.NewVersion(version)
	if err != nil {
		return false
	}
	return cs.Check(v)
}

func (g gemSatisfier) Valid(version string) bool {
	_, err := gem.NewVersion(version)
	return err == nil
}

func (g gemSatisfier) Greater(a, b string) bool {
	va, err := gem.NewVersion(a)
	if err != nil {
		return false
	}
	vb, err := gem.NewVersion(b)
	if err != nil {
		return false
	}
	return va.Compare(vb) > 0
}

// mvnSatisfier wraps go-mvn-version. Used for Maven, Gradle, NuGet,
// and Composer/Packagist (all of which share bracket-range syntax with
// Maven's set-notation: [1.0,2.0), (3.0,4.0], [1.0,] etc.). A bare
// Maven version (no brackets, e.g. "1.0") is a "soft requirement" and
// the library treats it as an exact pin — safer than guessing
// "compatible" because Maven 3 itself is ambiguous about the semantics.
type mvnSatisfier struct {
	cs mvn.Constraints
}

func (m mvnSatisfier) Check(version string) bool {
	v, err := mvn.NewVersion(version)
	if err != nil {
		return false
	}
	return m.cs.Check(v)
}

// Valid is deliberately stricter than mvn.NewVersion alone. The Maven
// version grammar accepts almost any string — it treats an unknown token
// as a qualifier and orders it — so "latest", "master" and "${project.version}"
// all "parse". Requiring a leading digit keeps the conflict check from
// acting on a coordinate that is not a version at all.
func (m mvnSatisfier) Valid(version string) bool {
	v := strings.TrimSpace(version)
	if v == "" || v[0] < '0' || v[0] > '9' {
		return false
	}
	_, err := mvn.NewVersion(v)
	return err == nil
}

func (m mvnSatisfier) Greater(a, b string) bool {
	va, err := mvn.NewVersion(a)
	if err != nil {
		return false
	}
	vb, err := mvn.NewVersion(b)
	if err != nil {
		return false
	}
	return va.Compare(vb) > 0
}

// stripOuterParens removes a single layer of surrounding parentheses
// from a constraint expression so wrapped pip/PEP 440 forms like
// "(<4,>=2)" become "<4,>=2" before being handed to the parser. Only a
// single outer pair is stripped — multi-layered or unbalanced
// expressions fall through unchanged so the library can report the
// real parse error.
func stripOuterParens(c string) string {
	c = strings.TrimSpace(c)
	if len(c) < 2 || c[0] != '(' || c[len(c)-1] != ')' {
		return c
	}
	// Confirm the parens are actually a matched outer pair (not e.g.
	// "(a)+(b)" which would otherwise be incorrectly stripped to
	// "a)+(b"). Count depth across the string; the outer pair matches
	// only if depth never returns to zero before the final char.
	depth := 0
	for i, ch := range c {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		}
		if depth == 0 && i < len(c)-1 {
			return c
		}
	}
	if depth != 0 {
		return c
	}
	return strings.TrimSpace(c[1 : len(c)-1])
}

// translateBracketConstraint translates Maven/NuGet/Composer bracket
// range syntax into the operator-prefixed form go-mvn-version's
// constraint parser understands. Examples:
//
//	[1.2.16,2.0.0)         → >=1.2.16,<2.0.0
//	(1.0,2.0]              → >1.0,<=2.0
//	[1.5.3]                → =1.5.3
//	(,1.0]                 → <=1.0
//	[11.0.2,)              → >=11.0.2
//	[1.0,2.0),(3.0,4.0)    → >=1.0,<2.0||>3.0,<4.0
//
// Strings that don't contain bracket syntax pass through unchanged so
// "operator-style" inputs (">=1.2.16,<2.0.0", "= 1.2.3") still parse
// correctly. A bare Maven version with no brackets (e.g. "1.0") is a
// soft requirement — Maven 3 doesn't actually pin it, but the safer
// default for advisory matching is exact pin (treating "1.0" as
// "=1.0") rather than guessing the looser "compatible" semantics.
//
// Returns the same string unchanged when no brackets are present so
// the parser sees operator constraints verbatim.
func translateBracketConstraint(raw string) (string, error) {
	c := strings.TrimSpace(raw)
	if c == "" {
		return c, nil
	}
	// Fast path: no bracket characters → pass through. A bare version
	// with no operator and no brackets is also passed through; the mvn
	// library treats that as exact equality.
	if !strings.ContainsAny(c, "[](") || !strings.ContainsAny(c, "])") {
		return c, nil
	}
	// Split into bracket sets (top-level commas are inside one set).
	// Scan and emit one group per matched bracket pair. A "set" starts
	// with `[` or `(` and ends with `]` or `)`.
	var groups []string
	for len(c) > 0 {
		c = strings.TrimLeft(c, ", \t")
		if len(c) == 0 {
			break
		}
		if c[0] != '[' && c[0] != '(' {
			// Operator-style fragment mixed in with bracket groups —
			// unsupported, let the caller see a clean parse error.
			return "", fmt.Errorf("unexpected token in bracket constraint: %q", c)
		}
		// Find matching closer.
		end := -1
		for i := 0; i < len(c); i++ {
			if c[i] == ']' || c[i] == ')' {
				end = i
				break
			}
		}
		if end < 0 {
			return "", fmt.Errorf("unterminated bracket in constraint: %q", raw)
		}
		groups = append(groups, c[:end+1])
		c = c[end+1:]
	}
	if len(groups) == 0 {
		return raw, nil
	}
	ors := make([]string, 0, len(groups))
	for _, g := range groups {
		op, err := bracketGroupToOperators(g)
		if err != nil {
			return "", err
		}
		ors = append(ors, op)
	}
	return strings.Join(ors, "||"), nil
}

// bracketGroupToOperators converts a single Maven bracket group
// (e.g. "[1.0,2.0)") into the operator form (">=1.0,<2.0"). Single
// version groups like "[1.5.3]" become "=1.5.3". Open lower / upper
// bounds — "(,1.0]" / "[11.0.2,)" — collapse to a single operator.
func bracketGroupToOperators(g string) (string, error) {
	if len(g) < 2 {
		return "", fmt.Errorf("bracket group too short: %q", g)
	}
	openCh := g[0]
	closeCh := g[len(g)-1]
	if (openCh != '[' && openCh != '(') || (closeCh != ']' && closeCh != ')') {
		return "", fmt.Errorf("malformed bracket group: %q", g)
	}
	inner := strings.TrimSpace(g[1 : len(g)-1])
	if inner == "" {
		return "", fmt.Errorf("empty bracket group: %q", g)
	}
	if !strings.Contains(inner, ",") {
		// Single-version group — treat as exact equality. Maven uses
		// "[1.5.3]" for hard pins.
		if openCh != '[' || closeCh != ']' {
			return "", fmt.Errorf("single-version bracket must use [v]: %q", g)
		}
		v := strings.TrimSpace(inner)
		if v == "" {
			return "", fmt.Errorf("empty version in bracket: %q", g)
		}
		return "=" + v, nil
	}
	parts := strings.SplitN(inner, ",", 2)
	low := strings.TrimSpace(parts[0])
	high := strings.TrimSpace(parts[1])
	var ops []string
	if low != "" {
		if openCh == '[' {
			ops = append(ops, ">="+low)
		} else {
			ops = append(ops, ">"+low)
		}
	}
	if high != "" {
		if closeCh == ']' {
			ops = append(ops, "<="+high)
		} else {
			ops = append(ops, "<"+high)
		}
	}
	if len(ops) == 0 {
		return "", fmt.Errorf("bracket group has no bounds: %q", g)
	}
	return strings.Join(ops, ","), nil
}

// emitTransitiveWarning appends a structured Warning to the report's
// Observation section. Each drop path uses a distinct Code so operators
// can filter on it.
func emitTransitiveWarning(report *Report, code, message string) {
	report.Observation.Warnings = append(report.Observation.Warnings, Warning{
		Provider: "transitiveRisk",
		Code:     code,
		Message:  message,
		At:       time.Now().UTC(),
	})
}

// displayConstraint renders a constraint string for human-facing
// warning messages, substituting "<unspecified>" for the empty case so
// the operator can tell "no constraint declared" from "constraint
// happened to be empty after trim".
func displayConstraint(c string) string {
	c = strings.TrimSpace(c)
	if c == "" {
		return "<unspecified>"
	}
	return c
}

// candidateVersions builds the small ordered probe list a constraint
// string maps to:
//  1. The constraint verbatim — handles exact pins like "1.2.3" or
//     "==1.2.3" already keyed by version in the cache.
//  2. The operator-stripped lower bound — handles "^1.2.3", "~1.2.3",
//     ">=1.2.3", or range tails like ">=1.2.3, <2.0.0" → "1.2.3".
//     Validated via Masterminds/semver so non-semver junk like
//     "git+https://…" doesn't generate a noisy probe.
//  3. The "latest" sentinel as a back-compat fallback.
//
// The verbatim form is always emitted first (even for non-semver
// constraints) because cache writers may have stored a row under
// exactly that string.
func candidateVersions(constraint string) []string {
	c := strings.TrimSpace(constraint)
	if c == "" {
		return []string{"latest"}
	}
	out := []string{c}
	if lb := stripLowerBound(c); lb != "" && lb != c {
		if _, err := semver.NewVersion(lb); err == nil {
			out = append(out, lb)
		}
	}
	out = append(out, "latest")
	return out
}

// computeTransitiveSeverity walks every non-root node in the
// TreeEvaluation and tallies severity-bucketed CVE counts plus malware
// / blocked-verdict descendant counts. CVEs are deduplicated per
// severity tier across descendants using the fired signal's evidence
// map (`cves` slice or `cve` singular). When neither evidence key is
// present we fall back to a stable composite of (signal ID + node key)
// so two unrelated fires aren't accidentally merged.
//
// MalwareCount and BlockedCount track distinct descendants, not signal
// fire counts, so a single malicious package pulled in via two parents
// still counts once.
//
// BlockedCount reads the verdict the tree pass FINISHED with, which
// includes each descendant's own upgrade promotion (see nodeSafe in
// evaluateTransitiveRisk). A dependency with a published fix for every
// advisory affecting it resolves to upgrade_available and is therefore
// not counted as blocked — the count means "dependencies with no way
// out", not "dependencies with a CVE". The severity tiers above are
// unchanged by promotion on purpose: a transitive critical CVE is still
// a transitive critical CVE, fix or no fix, and it must keep driving the
// root's verdict through the sc.transitive_* signals.
func computeTransitiveSeverity(te *risk.TreeEvaluation, rootKey depgraph.Key) risk.TransitiveSeverity {
	if te == nil {
		return risk.TransitiveSeverity{}
	}
	critical := make(map[string]struct{})
	high := make(map[string]struct{})
	medium := make(map[string]struct{})
	low := make(map[string]struct{})
	malwareNodes := make(map[depgraph.Key]struct{})
	blockedNodes := make(map[depgraph.Key]struct{})

	for k, ev := range te.ByKey {
		if k == rootKey || ev == nil {
			continue
		}
		// Blocked-verdict descendants: quarantine or replace verdicts.
		if ev.Verdict == risk.VerdictQuarantine || ev.Verdict == risk.VerdictReplace {
			blockedNodes[k] = struct{}{}
		}
		// Vulnerability category — bucket each fired CVE signal by tier.
		vulnCat, ok := ev.DirectScore.Categories[risk.CategoryVulnerability]
		if ok {
			for _, fs := range vulnCat.FiredSignals {
				var bucket map[string]struct{}
				switch fs.ID {
				case risk.SignalVulnCVSSCritical:
					bucket = critical
				case risk.SignalVulnCVSSHigh:
					bucket = high
				case risk.SignalVulnCVSSMedium:
					bucket = medium
				case risk.SignalVulnCVSSLow:
					bucket = low
				default:
					// vuln.kev / vuln.epss_high / vuln.fix_available are
					// surfaced separately — do not double-count into
					// severity tallies.
					continue
				}
				for _, cveID := range extractCVEIdentifiers(fs, k) {
					bucket[cveID] = struct{}{}
				}
			}
		}
		// Supply-chain category — check for known-malicious fires.
		scCat, ok := ev.DirectScore.Categories[risk.CategorySupplyChain]
		if ok {
			for _, fs := range scCat.FiredSignals {
				if fs.ID == risk.SignalSCKnownMalicious {
					malwareNodes[k] = struct{}{}
					break
				}
			}
		}
	}

	return risk.TransitiveSeverity{
		CriticalCount: len(critical),
		HighCount:     len(high),
		MediumCount:   len(medium),
		LowCount:      len(low),
		MalwareCount:  len(malwareNodes),
		BlockedCount:  len(blockedNodes),
	}
}

// extractCVEIdentifiers pulls a list of dedupe keys from a fired
// signal. Preference order:
//  1. evidence["cves"] []string (provider_cve.go's canonical shape)
//  2. evidence["cve"]  string  (singular fallback, allowed per the
//     ReasoningBank pattern for transitive severity)
//  3. composite signal-ID + descendant-key fallback so unrelated fires
//     stay distinct.
//
// CVE IDs are upper-cased so the same advisory pulled in via two
// providers de-dupes regardless of case-drift between "CVE-2024-1234"
// and "cve-2024-1234".
func extractCVEIdentifiers(fs risk.FiredSignal, k depgraph.Key) []string {
	if fs.Evidence != nil {
		if raw, ok := fs.Evidence["cves"]; ok {
			if list, ok := raw.([]string); ok && len(list) > 0 {
				out := make([]string, 0, len(list))
				for _, c := range list {
					c = strings.TrimSpace(c)
					if c == "" {
						continue
					}
					out = append(out, strings.ToUpper(c))
				}
				if len(out) > 0 {
					return out
				}
			}
		}
		if raw, ok := fs.Evidence["cve"]; ok {
			if s, ok := raw.(string); ok && strings.TrimSpace(s) != "" {
				return []string{strings.ToUpper(strings.TrimSpace(s))}
			}
		}
	}
	// Fallback: signal-ID + descendant-key composite. Stays stable
	// across runs so two evaluations of the same tree dedupe identically.
	return []string{fmt.Sprintf("%s|%s|%s|%s", fs.ID, k.Ecosystem, k.Name, k.Version)}
}

// hasTransitiveSignal reports whether the populated severity counts
// would cause any sc.transitive_* signal to fire. Used to skip the
// second EvaluatePackage call when the tree is clean — the original
// rootEval is already authoritative in that case.
func hasTransitiveSignal(ts risk.TransitiveSeverity) bool {
	return ts.CriticalCount > 0 || ts.HighCount > 0 || ts.MalwareCount > 0
}

// verdictRank maps a Verdict to an ordinal where higher = more
// restrictive. Used to pick the worse of (tree-evaluator verdict,
// second-pass verdict) when the second pass fires a transitive
// critical / malware signal that the tree-decay rollup couldn't surface.
func verdictRank(v risk.Verdict) int {
	switch v {
	case risk.VerdictAllow:
		return 0
	case risk.VerdictWarn:
		return 1
	case risk.VerdictUpgradeAvailable:
		return 2
	case risk.VerdictReplace:
		return 3
	case risk.VerdictQuarantine:
		return 4
	}
	return 0
}

// stripLowerBound takes a constraint string and returns the lower-bound
// version with operator characters removed. For ranges like
// ">=1.2.3, <2.0.0" it splits on comma/space and uses the first token.
// Returns "" if no plausible version remains.
func stripLowerBound(c string) string {
	// Take the first comma-separated clause for ranges.
	first := c
	if idx := strings.Index(first, ","); idx >= 0 {
		first = first[:idx]
	}
	first = strings.TrimSpace(first)
	// Strip a leading operator. Order matters: longer operators first.
	for _, op := range []string{">=", "<=", "==", "!=", "~>", ">", "<", "=", "^", "~"} {
		if strings.HasPrefix(first, op) {
			first = strings.TrimSpace(first[len(op):])
			break
		}
	}
	return first
}
