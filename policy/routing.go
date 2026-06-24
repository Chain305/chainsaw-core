package policy

// Wave-1 Agent B — ownership-routing policy rule kind.
//
// A routing rule is a Policy with Kind=KindRouting. It carries a
// RoutingRule body (path glob and/or package pattern, plus a notify
// channel) and runs in a separate evaluation pass from enforcement
// rules: routing matches NEVER block an install — they just resolve
// owners (today, exclusively via CODEOWNERS) and dispatch a webhook
// notification.
//
// This file is the matcher + dispatch glue. The hot-path enforcement
// pipeline (internal/server/server_repo_pipeline.go) calls
// EvaluateRouting after the enforcement decision has been made; routing
// fan-out is fire-and-forget and adds zero latency to the cache-hot
// path because the dispatcher is already async.
//
// SECURITY: routing pulls owners out of the parsed CODEOWNERS file —
// never from the request body. The webhook URL routing eventually
// uses comes from the per-team destination table (managed by
// internal/ownership), which is itself SSRF-validated on write. No
// user-supplied URL ever flows through this evaluator.

import (
	"context"
	"path"
	"strings"

	"github.com/chain305/chainsaw-core/codeowners"
)

// RoutingViolation is the minimal context the routing evaluator needs
// to decide whether a rule fires. It is deliberately decoupled from the
// proxy's repoRequestCtx / event row shapes — the server bridges the
// two. PackageName / Repository are required; LogicalPath is the
// CODEOWNERS-style repo-relative path of the offending artifact when
// available (e.g. for SBOM-scoped exception flows). Empty LogicalPath
// is legal — only PackagePattern matches will fire.
type RoutingViolation struct {
	OrgID          string
	Repository     string
	PackageName    string
	PackageVersion string
	LogicalPath    string
	PolicyID       string // the enforcement policy that produced the violation
	Reason         string
}

// RoutingMatch is the resolved owner set after a successful match. It
// carries the matched policy ID so the dispatcher can correlate the
// outbound webhook with the routing rule that fired it.
type RoutingMatch struct {
	PolicyID string
	Rule     RoutingRule
	Owners   []string
}

// CodeownersIndex is the read-side surface the evaluator depends on.
// Implementations cache the parsed CODEOWNERS file per (orgID, repo)
// — see internal/ownership/store.go for the production cache.
type CodeownersIndex interface {
	// LookupOwners returns the owner handles ([@user, @org/team, email])
	// for repoPath inside repo, or nil when no pattern matches. Empty
	// repoPath returns nil unless an unanchored pattern matches the
	// empty string (rare; we treat it as no-match for safety).
	LookupOwners(ctx context.Context, orgID, repo, repoPath string) ([]string, error)
}

// MappingsIndex is a thin in-memory CodeownersIndex backed by a parsed
// []codeowners.Mapping per (orgID, repo). Useful for tests and for the
// post-enforcement hook when the production ownership store is not
// wired (e.g. OSS install). Keys are case-sensitive on orgID, lower-
// cased on repo to match the proxy's repository naming convention.
type MappingsIndex struct {
	byKey map[string][]codeowners.Mapping
}

// NewMappingsIndex constructs an empty in-memory index. Callers Set()
// per-repo mappings as they parse CODEOWNERS files.
func NewMappingsIndex() *MappingsIndex {
	return &MappingsIndex{byKey: make(map[string][]codeowners.Mapping)}
}

// Set installs the parsed CODEOWNERS mappings for (orgID, repo). The
// mappings slice is stored verbatim; the caller must not mutate it
// afterwards.
func (m *MappingsIndex) Set(orgID, repo string, mappings []codeowners.Mapping) {
	if m == nil || m.byKey == nil {
		return
	}
	m.byKey[mappingsKey(orgID, repo)] = mappings
}

// LookupOwners satisfies CodeownersIndex.
func (m *MappingsIndex) LookupOwners(_ context.Context, orgID, repo, repoPath string) ([]string, error) {
	if m == nil {
		return nil, nil
	}
	mappings, ok := m.byKey[mappingsKey(orgID, repo)]
	if !ok || len(mappings) == 0 {
		return nil, nil
	}
	return codeowners.Lookup(mappings, repoPath), nil
}

func mappingsKey(orgID, repo string) string {
	return strings.ToLower(strings.TrimSpace(orgID)) + "\x00" + strings.ToLower(strings.TrimSpace(repo))
}

// RoutingDispatcher delivers a routing match. The signature is
// deliberately narrow so callers can wire it to whichever transport
// they like — the production wiring uses the existing webhook
// dispatcher (see internal/server/server_ownership_routing.go).
//
// Implementations MUST NOT block — the routing fan-out runs on the
// caller's goroutine inside EvaluateRouting today. If a real network
// call is needed, the dispatcher should enqueue and return immediately.
type RoutingDispatcher interface {
	DispatchRouting(ctx context.Context, violation RoutingViolation, match RoutingMatch) error
}

// EvaluateRouting runs every enabled routing rule for the org against
// the violation, resolves owners via the CODEOWNERS index for matches
// against PathGlob, and fans out to the dispatcher. Returns the slice
// of matches it dispatched so callers can audit / test.
//
// Routing rules with Status != StatusEnabled are skipped. Rules with
// Kind != KindRouting are also skipped — this is the gate that keeps
// enforcement rules out of the routing path.
//
// Errors from the dispatcher are swallowed (logging is the dispatcher's
// responsibility) — routing must not break the request pipeline.
func EvaluateRouting(
	ctx context.Context,
	policies []Policy,
	violation RoutingViolation,
	index CodeownersIndex,
	dispatcher RoutingDispatcher,
) []RoutingMatch {
	if len(policies) == 0 {
		return nil
	}
	var matches []RoutingMatch
	for _, pol := range policies {
		if pol.Kind != KindRouting || pol.Routing == nil {
			continue
		}
		if pol.Status != StatusEnabled {
			continue
		}
		if !routingRuleMatches(pol.Routing, violation) {
			continue
		}
		var owners []string
		if index != nil && violation.LogicalPath != "" && violation.Repository != "" {
			o, err := index.LookupOwners(ctx, violation.OrgID, violation.Repository, violation.LogicalPath)
			if err == nil {
				owners = o
			}
		}
		match := RoutingMatch{
			PolicyID: pol.ID,
			Rule:     *pol.Routing,
			Owners:   owners,
		}
		matches = append(matches, match)
		if dispatcher != nil {
			_ = dispatcher.DispatchRouting(ctx, violation, match)
		}
	}
	return matches
}

// routingRuleMatches evaluates the rule body against the violation. A
// rule with both PathGlob and PackagePattern fires when EITHER matches
// (OR semantics — operators set the matcher they need; AND would
// require fields to coincide which is rarely useful for routing).
//
// PathGlob uses the gitignore/CODEOWNERS-flavoured matcher in the
// codeowners package so operators don't need to learn a second
// glob syntax. PackagePattern uses path.Match — the standard library's
// glob matcher — because package names are flat namespaces and the
// CODEOWNERS-style "match anywhere" semantics are wrong for them.
func routingRuleMatches(rule *RoutingRule, v RoutingViolation) bool {
	if rule == nil {
		return false
	}
	pathGlob := strings.TrimSpace(rule.PathGlob)
	pkgPattern := strings.TrimSpace(rule.PackagePattern)
	if pathGlob == "" && pkgPattern == "" {
		return false
	}
	if pathGlob != "" && v.LogicalPath != "" {
		if matchPathGlob(pathGlob, v.LogicalPath) {
			return true
		}
	}
	if pkgPattern != "" && v.PackageName != "" {
		if ok, err := path.Match(pkgPattern, v.PackageName); err == nil && ok {
			return true
		}
		// Also try an exact-equality fallback so operators can use
		// pattern="lodash" without thinking about glob syntax.
		if pkgPattern == v.PackageName {
			return true
		}
	}
	return false
}

// matchPathGlob runs the violation path through the same matcher
// CODEOWNERS uses so a rule with `pathGlob: "/services/payments/**"`
// behaves identically to a CODEOWNERS line with the same pattern. We
// route through codeowners.Lookup with a synthetic single-mapping
// slice; this keeps the matcher logic centralised in one place.
func matchPathGlob(glob, target string) bool {
	target = strings.TrimPrefix(strings.TrimSpace(target), "/")
	if target == "" {
		return false
	}
	owners := codeowners.Lookup([]codeowners.Mapping{{
		Pattern: glob,
		Owners:  []string{"@routing-probe"},
		LineNo:  1,
	}}, target)
	return len(owners) > 0
}
