// Package builtin carries the Chainsaw default policy bundle, compiled
// into the binary.
//
// It exists because of the 2026-08-24 ruling recorded in
// docs/plan_competitive_depth.md: warn-vs-block on a degraded analysis
// is a policy question, and the offline guard falls back to defaults
// when no signed bundle is present. Those two together force the shape
// here — if "defaults" meant hardcoded Go, the ruling would be violated
// under a different name. Compiling a real policy object into the
// binary means "no bundle on disk" resolves to BUILT-IN POLICY rather
// than NO policy, and one decision path serves both cases.
//
// Ordering contract: the built-in bundle is compiled ALONGSIDE an
// operator's bundle, never instead of it, and policy verdicts fold with
// dsl.Stricter. A rule can therefore raise a verdict and can never
// clear one — including a built-in rule an operator disagrees with,
// which they override by shipping a stricter rule, not a looser one.
package builtin

import (
	"context"
	_ "embed"

	"github.com/chain305/chainsaw-core/policy/dsl"
)

//go:embed builtin.rego
var bundleRego string

// ModuleName is the compile-time name the embedded bundle registers
// under. Namespaced with a "chainsaw:builtin/" prefix that no
// filesystem path can produce, so an operator's on-disk bundle can
// never collide with it — a collision would be a rego compile error,
// not a silent override.
const ModuleName = "chainsaw:builtin/builtin.rego"

// Modules returns the embedded bundle in the shape dsl.Options.Modules
// accepts. Callers merge it with any operator bundle rather than
// choosing between them.
func Modules() map[string]string {
	return map[string]string{ModuleName: bundleRego}
}

// Engine compiles the built-in bundle together with the operator
// sources (which may be empty). A nil source list yields an engine
// carrying the built-in rules alone — the no-bundle-present case.
func Engine(ctx context.Context, sources []string) (*dsl.Engine, error) {
	return dsl.New(ctx, dsl.Options{Sources: sources, Modules: Modules()})
}
