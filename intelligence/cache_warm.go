package intelligence

// Cache-warming pass for direct dependencies.
//
// Background: when a package is scanned for the first time the Tier-3
// transitive risk overlay walks Report.Dependencies.Direct and looks up
// each dep's intelligence_reports row. On a cold cache every direct dep
// is a miss and emits a `transitive_dep_not_cached` warning (we observed
// 10 such warnings for rails 7.0.0). The fix isn't to suppress the
// warning — it's to populate the cache so the NEXT scan of the parent
// has full transitive coverage.
//
// WarmDirectDeps is the fire-and-forget pass that does exactly that:
// for every direct dep with a CONCRETE (pinned) version it schedules
// a background Scan via the same DefaultService. Already-cached deps
// hit the fast path and no-op; cold deps populate their row. We do NOT
// warm range constraints (^1.2.3, >=2.0) because we'd be guessing which
// version to pre-populate, and we do NOT recurse beyond one level — the
// next Scan of the parent triggers the next layer naturally.
//
// THAT LAST CLAUSE WAS A COMMENT, NOT CODE, UNTIL 2026-09-14.
//
// A warm target is a full Scan, and scanner.go schedules WarmDirectDeps
// at the end of every fresh fan-out — so each warmed dependency warmed
// its own dependencies, and so on down the tree. Nothing bounded it:
// there was no depth parameter, and cacheWarmConcurrency is a per-CALL
// semaphore, which makes the process-wide ceiling 4^depth rather than 4.
// Recursion stopped only where a dependency was a cache HIT, so the blast
// radius was proportional to cache coldness — invisible in steady state,
// unbounded on a cold cache.
//
// Fifty on-demand scans issued ~8s apart drove the writable pool to
// exhaustion and shed 503s onto the unauthenticated public read path,
// which performs no writes at all. It did not recover at zero load,
// because the recursion was still expanding. See
// docs/PLANS_INTELLIGENCE.md#plan-scan-backpressure.
//
// Two bounds now hold, and both are enforced by tests:
//
//  1. maxWarmDepth — the documented one level, carried on
//     Options.WarmDepth and checked before anything is scheduled.
//  2. globalWarmBudget — a PROCESS-WIDE ceiling on concurrent warm
//     Scans, acquired non-blockingly. Warming is best-effort by design
//     (the next Scan of the parent warms the layer anyway), so the
//     correct behaviour under pressure is to skip, never to queue up
//     goroutines or block a caller.

import (
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// cacheWarmConcurrency caps how many concurrent background warm Scans
// can be in flight per WarmDirectDeps call. 4 is conservative: enough
// to amortise wall-clock latency, low enough to avoid overwhelming the
// upstream proxy or saturating the singleflight group with one parent's
// fan-out.
const cacheWarmConcurrency = 4

// maxWarmDepth is how many cache-warm hops from a caller-originated Scan
// the warmer will go. 1 == "warm my direct dependencies, and stop" — the
// bound this file has always documented. Raising it re-opens an
// exponential fan-out: see the header.
const maxWarmDepth = 1

// globalCacheWarmConcurrency is the PROCESS-WIDE ceiling on concurrent
// cache-warm Scans, across every parent.
//
// cacheWarmConcurrency alone is not a ceiling: its semaphore is
// constructed inside each WarmDirectDeps call, so N concurrent parents
// give 4N concurrent warm scans and a recursive warm gave 4^depth. This
// is the one number that bounds what a burst of scan requests can cost,
// and it must stay comfortably under the database pool
// (CHAINSAW_DB_MAX_OPEN_CONNS, 60 in production) because a scan in its
// fan-out holds a pooled connection for the duration
// (core/xreplicaflight/pg.go).
const globalCacheWarmConcurrency = 16

// globalWarmBudget is the semaphore behind globalCacheWarmConcurrency.
// Package-level: one budget for the process, deliberately NOT per
// service or per call.
var globalWarmBudget = make(chan struct{}, globalCacheWarmConcurrency)

// warmSkippedBudget counts warm scans declined because the global budget
// was full. Exported through WarmSkippedForBudget so the absence of
// warming under load is observable rather than silent — the incident
// above left no trace in production logs at all.
var warmSkippedBudget atomic.Uint64

// WarmSkippedForBudget returns the cumulative number of cache-warm scans
// skipped because globalCacheWarmConcurrency was saturated.
func WarmSkippedForBudget() uint64 { return warmSkippedBudget.Load() }

// cacheWarmEnvDisabled is the kill-switch env var. Set to "1" to skip
// the warm-up pass entirely (recovery valve if a freshly-deployed pod
// would otherwise fan out across hundreds of packages at boot).
const cacheWarmEnvDisabled = "CHAINSAW_CACHE_WARM_DISABLED"

// inFlightWarms dedupes warm-up Scans by (ecosystem|name|version) across
// all goroutines on this process. Without this, two concurrent parent
// scans that share a direct dep would each enqueue the same warm-up.
// Entries are deleted once the Scan returns so a later refresh after
// the inner Scan completes can still warm. sync.Map is used because the
// expected hot path is "key is absent, store, delete" with very low
// contention; a plain mutex+map would be equivalent in correctness.
var inFlightWarms sync.Map

// WarmDirectDeps schedules background Scans for the parent report's
// direct dependencies. It is safe to call from any goroutine — all work
// runs in detached goroutines on svc.bg (the service-scoped context) so
// the originating request's deadline does not cut the warm-up short.
//
// Behaviour:
//   - No-op when parent or svc is nil, parent has no Direct deps, or
//     CHAINSAW_CACHE_WARM_DISABLED=1.
//   - Skips entries with a non-pinned (range) constraint — we don't
//     guess which version to warm.
//   - Skips entries whose (ecosystem, name, version) is already being
//     warmed by another goroutine on this process.
//   - Concurrency-capped at cacheWarmConcurrency via a semaphore.
//   - Errors from inner Scans are logged at DEBUG and discarded.
func WarmDirectDeps(ctx context.Context, parent *Report, svc *DefaultService) {
	warmDirectDepsAtDepth(ctx, parent, svc, 0)
}

// warmDirectDepsAtDepth is WarmDirectDeps with the parent's cache-warm
// depth. parentDepth is Options.WarmDepth of the Scan that produced
// `parent`; the children it schedules run at parentDepth+1.
func warmDirectDepsAtDepth(ctx context.Context, parent *Report, svc *DefaultService, parentDepth int) {
	if svc == nil || parent == nil {
		return
	}
	childDepth := parentDepth + 1
	if childDepth > maxWarmDepth {
		// The recursion stops here. This is the bound the file header
		// describes; before it existed, this branch was the missing
		// base case of an unbounded tree walk.
		return
	}
	if os.Getenv(cacheWarmEnvDisabled) == "1" {
		return
	}
	direct := parent.Dependencies.Direct
	if len(direct) == 0 {
		return
	}

	parentEco := parent.Identity.Ecosystem

	// Always use the service's background context so warm-up survives the
	// originating request's deadline. The caller may cancel `ctx` the
	// instant their HTTP response writes — we want the warm-up to keep
	// running anyway. The `ctx` parameter is accepted for API symmetry
	// (callers may want to log against the originating trace) but is not
	// propagated into the inner Scans.
	_ = ctx
	bg := svc.bg
	if bg == nil {
		bg = context.Background()
	}

	// Collect the (eco, name, version) triples we'll actually warm so the
	// semaphore-bounded goroutine pool is sized to exactly the work that
	// needs to happen — not the raw len(Direct).
	type warmTarget struct {
		ecosystem string
		name      string
		version   string
	}
	targets := make([]warmTarget, 0, len(direct))
	for _, dep := range direct {
		eco := strings.TrimSpace(dep.Ecosystem)
		if eco == "" {
			eco = parentEco
		}
		name := strings.TrimSpace(dep.Name)
		if name == "" {
			continue
		}
		version := pinnedVersion(dep.Constraint)
		if version == "" {
			continue
		}
		targets = append(targets, warmTarget{ecosystem: eco, name: name, version: version})
	}
	if len(targets) == 0 {
		return
	}

	sem := make(chan struct{}, cacheWarmConcurrency)
	for _, t := range targets {
		dedupKey := strings.ToLower(t.ecosystem) + "|" + t.name + "|" + t.version
		if _, loaded := inFlightWarms.LoadOrStore(dedupKey, struct{}{}); loaded {
			// Another goroutine is already warming this exact key.
			continue
		}
		// Process-wide budget FIRST, and non-blocking: if the machine is
		// already warming as much as it should, drop this target rather
		// than parking a goroutine on it. Order matters — acquiring the
		// per-call semaphore first would let N parents each park a
		// goroutine waiting for a global budget that is already full.
		select {
		case globalWarmBudget <- struct{}{}:
		default:
			warmSkippedBudget.Add(1)
			inFlightWarms.Delete(dedupKey)
			continue
		}
		sem <- struct{}{}
		go func(eco, name, version, key string) {
			defer func() {
				<-sem
				<-globalWarmBudget
				inFlightWarms.Delete(key)
				// Recover from any panic in Scan so the warm-up goroutine
				// can never crash the process.
				if r := recover(); r != nil && svc.logger != nil {
					svc.logger.Debug("cache-warm scan panicked",
						"ecosystem", eco, "package", name, "version", version, "recover", r)
				}
			}()
			req := Request{
				Key:   Key{Ecosystem: eco, Package: name, Version: version},
				OrgID: "",
				Options: Options{
					RefreshReason: "cache_warm",
					AllowStale:    false,
					WarmDepth:     childDepth,
				},
			}
			if _, err := svc.Scan(bg, req); err != nil && svc.logger != nil {
				svc.logger.Debug("cache-warm scan failed",
					"ecosystem", eco, "package", name, "version", version, "err", err)
			}
		}(t.ecosystem, t.name, t.version, dedupKey)
	}
}

// pinnedVersion returns the concrete version represented by `constraint`
// if (and only if) `constraint` pins a single version exactly. Returns
// the empty string for range constraints, wildcards, the empty string,
// or anything else we can't be sure refers to one specific release.
//
// We're deliberately conservative: false negatives (returning "" for a
// version we could have warmed) just delay coverage by one parent scan,
// whereas false positives (warming the wrong version) waste an upstream
// proxy round-trip per parent scan. Examples:
//
//	"1.2.3"        → "1.2.3"     (npm, pip, cargo bare semver)
//	"==1.2.3"      → "1.2.3"     (PyPI exact pin)
//	"= 1.2.3"      → "1.2.3"     (RubyGems exact pin)
//	"=1.2.3"       → "1.2.3"     (Cargo exact pin)
//	"v1.2.3"       → "1.2.3"     (some manifests prefix v)
//	"^1.2.3"       → ""          (caret range)
//	"~1.2.3"       → ""          (tilde range)
//	">=1.0.0"      → ""          (lower bound)
//	"1.2.3 - 2.0"  → ""          (hyphen range)
//	"1.x"          → ""          (wildcard)
//	"*"            → ""          (any)
//	"1.2.3 || 2.0" → ""          (alternation)
//	""             → ""          (no signal)
func pinnedVersion(constraint string) string {
	v := strings.TrimSpace(constraint)
	if v == "" {
		return ""
	}
	// Unwrap ONE enclosing bracket pair. NuGet writes an exact pin as
	// "[2.8.0]" and PEP 345 requires_dist as "(==2.14.3)"; neither carries a
	// range operator, so both used to pass through verbatim and were warmed
	// into intelligence_reports as the literal version "[2.8.0]" — a
	// coordinate no registry serves and no advisory range matches. A real
	// interval ("[1.0,2.0)", "(,1.0]") still fails on its comma below.
	if n := len(v); n >= 2 && ((v[0] == '[' && v[n-1] == ']') || (v[0] == '(' && v[n-1] == ')')) {
		v = strings.TrimSpace(v[1 : n-1])
	}
	// Strip exact-pin prefixes from PyPI/Cargo/RubyGems. Order matters:
	// "==" must be checked before "=".
	switch {
	case strings.HasPrefix(v, "=="):
		v = strings.TrimSpace(v[2:])
	case strings.HasPrefix(v, "="):
		v = strings.TrimSpace(v[1:])
	}
	if v == "" {
		return ""
	}
	// Reject any constraint operator or whitespace that signals a range,
	// wildcard, or alternation. Whitespace inside the post-strip string
	// is always a range marker ("1.2.3 - 2.0", "1.2 || 1.3").
	for _, r := range v {
		switch r {
		case '^', '~', '>', '<', '*', ',', '|', ' ', '\t', '[', ']', '(', ')':
			return ""
		}
	}
	// Reject wildcard segments ("1.x", "1.X", "1.2.x").
	if hasWildcardSegment(v) {
		return ""
	}
	// Reject an unresolved manifest property. Maven and Gradle POMs
	// routinely declare a dependency as <version>${slf4jVersion}</version>.
	// provider_registrymetadata used to take that constraint verbatim from
	// the raw POM without interpolating it. The operator loop above does not
	// list '$', '{' or '}', and hasDigit below passes anything containing a
	// digit — so "${jsr305.version}" and "${commons.lang3.version}" both
	// survived and were warmed into intelligence_reports as though they
	// were pinned versions.
	//
	// The producer now interpolates: resolveMavenVersion
	// (provider_registrymetadata.go) substitutes properties the POM declares
	// itself, so the common shape arrives here already concrete and IS
	// warmed. What still reaches this branch is the genuinely unresolvable
	// remainder — a property inherited from a parent POM or a profile, which
	// resolving would need the whole POM hierarchy for and which
	// resolveMavenVersion deliberately leaves alone.
	//
	// This guard therefore stays as the BACKSTOP rather than becoming dead
	// code. It is the last thing between an un-interpolated string and a
	// cache row, and it must hold even if a future caller — a new lockfile
	// parser, an SBOM import — forgets to interpolate. Unresolved is
	// unresolved, wherever it came from.
	//
	// That is a SILENT BLIND SPOT: no advisory range can ever match such a
	// coordinate, so it sat in the inventory reading as scanned-and-clean.
	// Three such rows were live in production on 2026-08-23. The fingerprint
	// that identified this function as the producer is that
	// "${project.version}" contains NO digit, so hasDigit already rejected
	// it — and it is correspondingly absent from that table, while the
	// digit-bearing placeholders are present.
	//
	// intelligence.UnevaluableVersionReason is the shared definition of
	// "cannot be matched"; this is the same rule applied early, so the
	// warmer never creates the row in the first place.
	if strings.Contains(v, unresolvedPropertyMarker) {
		return ""
	}
	// Optional leading 'v' — some manifests carry it on pinned versions.
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') {
		v = v[1:]
	}
	// At this point the string should look like a semver-ish token:
	// digits + dots + optional prerelease/build (-, +, alnum). Require
	// at least one digit so we don't accept tags like "latest" or names.
	if !hasDigit(v) {
		return ""
	}
	return v
}

// hasWildcardSegment reports whether `v` contains a dot-separated segment
// equal to "x" or "X" (case-insensitive). "1.x", "1.2.X" → true.
// "1x" → false because the "x" is not its own segment.
func hasWildcardSegment(v string) bool {
	for _, seg := range strings.Split(v, ".") {
		if seg == "x" || seg == "X" {
			return true
		}
	}
	return false
}

func hasDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}
