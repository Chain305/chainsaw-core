package tenancy

import (
	"encoding/json"
	"os"
	"strings"
)

// rbacScopesFlagEnv is the environment variable that gates the entire
// resource/feature-scoped RBAC feature (see docs/plan_rbac_scoped_roles.md).
// Phase 1 ships DARK: the flag defaults OFF and nothing in the request path
// consumes a resource scope while it is off, so behaviour is byte-for-byte
// identical to a build without this plumbing. Flip to a truthy value only on
// a deployment that has completed the Phase 2 enforcement wiring.
const rbacScopesFlagEnv = "CHAINSAW_RBAC_SCOPES_ENABLED"

// rbacScopesEnabled reports whether the resource-scoped RBAC feature is
// enabled for this process. It DEFAULTS FALSE: only an explicit truthy value
// turns it on. This mirrors the other CHAINSAW_* boolean gates in the
// codebase (e.g. NewVulnAlertsEnabled) but inverts the default — scoping is
// off until an operator opts in.
//
// Unexported so the canonical reader stays inside package tenancy; callers in
// other packages use the exported RBACScopesEnabled wrapper.
func rbacScopesEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(rbacScopesFlagEnv))) {
	case "1", "true", "on", "yes", "enable", "enabled":
		return true
	default:
		return false
	}
}

// RBACScopesEnabled is the exported flag reader for callers outside package
// tenancy (the auth paths in internal/server/authcore). It defaults false;
// see rbacScopesEnabled for the parsing rules.
func RBACScopesEnabled() bool {
	return rbacScopesEnabled()
}

// scopableResources is the CLOSED registry of resources that support
// resource-scoping. A resource that is not in this set is UNSCOPABLE: it is
// always evaluated org-wide (today's behaviour), and any scope predicate
// naming it is dropped at decode time. Phase 1 registers `findings` only;
// `policies`/`repos` are deferred to Phase 3.
var scopableResources = map[string]bool{
	ResourceFindings: true,
}

// Registered scopable-resource names. Keep these as constants so the
// registry, the decoder, and any future enforcement wiring reference one
// symbol rather than a bare string.
const (
	ResourceFindings = "findings"
)

// IsScopableResource reports whether the named resource participates in
// resource-scoping. Unknown / unregistered resources are always org-wide.
func IsScopableResource(resource string) bool {
	return scopableResources[strings.TrimSpace(resource)]
}

// ScopableResources returns the registered scopable-resource names. Returned
// as a fresh slice so callers cannot mutate the registry.
func ScopableResources() []string {
	out := make([]string, 0, len(scopableResources))
	for name := range scopableResources {
		out = append(out, name)
	}
	return out
}

// Scope is the resource-subset predicate attached to a granted permission for
// one scopable resource. The predicate vocabulary is deliberately small and
// closed (Phase 1/2): `repo_ids` narrows to a set of repositories and `self`
// narrows to resources belonging to the caller. Anything outside this
// vocabulary is dropped at decode time.
//
// The zero value (empty RepoIDs, Self=false, not deny-all) means "no
// narrowing" — i.e. unscoped / full access — but a Scope value only ever
// exists inside a ResourceScopes map for a resource that WAS configured, so
// in practice an unconfigured resource is represented by ABSENCE from the map
// (see DecodeResourceScopes), not by a zero Scope.
type Scope struct {
	RepoIDs []string `json:"repo_ids,omitempty"`
	Self    bool     `json:"self,omitempty"`

	// denyAll is the fail-closed sentinel. It is set ONLY by the decoder
	// when a stored scopes value is present but unparseable. It is
	// unexported so it can never be produced by JSON unmarshalling of an
	// attacker/operator-controlled column value — it is a purely internal
	// "match nothing" marker. IsDenyAll reads it back.
	//
	// INERT in Phase 1: no enforcement path consults it while the flag is
	// off. Its semantics are defined here so Phase 2 wiring has a single,
	// unambiguous source of truth: a deny-all Scope must translate to a
	// `WHERE 1=0`-equivalent (match nothing), NOT to the empty/unscoped
	// default. This is the inverse of decodePermissions' safe-empty rule
	// (finding 16 in the plan): for permissions, empty = deny (safe); for
	// scopes, empty = ALLOW-ALL, so a naive empty-on-error would fail OPEN.
	denyAll bool
}

// IsDenyAll reports whether this Scope is the fail-closed deny-all sentinel
// (produced by the decoder on an unparseable stored value). A deny-all scope
// must match nothing when enforcement is live.
func (s Scope) IsDenyAll() bool {
	return s.denyAll
}

// denyAllScope constructs the fail-closed sentinel.
func denyAllScope() Scope {
	return Scope{denyAll: true}
}

// ResourceScopes maps a scopable-resource name to its Scope. A nil / empty
// map means UNSCOPED (full org-wide access — exactly today's behaviour).
// Absence of a key means that resource is unscoped. Presence with a deny-all
// Scope means that resource is fail-closed.
type ResourceScopes map[string]Scope

// scopePredicate is the on-the-wire shape of a single resource's predicate in
// the stored JSON column. Decoding into a struct silently drops unknown keys,
// which enforces the closed predicate vocabulary for free.
type scopePredicate struct {
	RepoIDs []string `json:"repo_ids"`
	Self    bool     `json:"self"`
}

// DecodeResourceScopes parses the value stored in custom_roles.scopes.
//
// Decoding rules (Phase 1):
//   - ""/whitespace/"{}"  → nil (UNSCOPED = full org-wide access; today's
//     behaviour; preserves backward compatibility by construction).
//   - a JSON object       → a ResourceScopes filtered to the registry:
//     unregistered resources are dropped (always org-wide), and each
//     predicate keeps only the closed `repo_ids`/`self` vocabulary.
//   - unparseable JSON    → a fail-closed deny-all map covering every
//     scopable resource (finding 16). Never the empty/unscoped default,
//     which would fail OPEN.
//
// This function is PURE and side-effect free; it does no flag check. It is
// safe to call regardless of the feature flag — its output is simply not
// consumed by any enforcement path while the flag is off.
func DecodeResourceScopes(raw string) ResourceScopes {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "{}" {
		return nil
	}
	var parsed map[string]scopePredicate
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		// Present-but-unparseable: fail closed. Return a deny-all sentinel
		// for every registered scopable resource so a future enforcement
		// path matches nothing rather than defaulting to unscoped/allow-all.
		return denyAllResourceScopes()
	}
	out := make(ResourceScopes)
	for resource, pred := range parsed {
		resource = strings.TrimSpace(resource)
		if !scopableResources[resource] {
			// Unregistered / unscopable resource: drop it. It stays org-wide.
			continue
		}
		out[resource] = Scope{
			RepoIDs: cleanScopeStrings(pred.RepoIDs),
			Self:    pred.Self,
		}
	}
	if len(out) == 0 {
		// A well-formed object that named no registered resources is
		// equivalent to unscoped.
		return nil
	}
	return out
}

// denyAllResourceScopes builds a ResourceScopes that fail-closes every
// registered scopable resource. Used only on a decode error.
func denyAllResourceScopes() ResourceScopes {
	out := make(ResourceScopes, len(scopableResources))
	for resource := range scopableResources {
		out[resource] = denyAllScope()
	}
	return out
}

// cleanScopeStrings trims, de-dupes, and drops empties from a predicate's
// string list while preserving first-seen order.
func cleanScopeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
