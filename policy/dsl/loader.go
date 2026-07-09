package dsl

import "context"

// Loader is the FREE-side seam between "I have a bundle path" and "I
// have a compiled, ready-to-Decide Engine". The free policy engine
// (internal/policyengine) and the CLI (internal/cli) depend on this
// interface — NOT on any signing/verification concrete type — so the
// enterprise signing path can later move to a private package without
// touching a single free caller.
//
// The contract is deliberately narrow: given a set of sources (the same
// directory/file list dsl.New accepts), return a compiled Engine or an
// error. Implementations decide whether to perform any trust check
// before compiling:
//
//   - DefaultLoader (this package, FREE) compiles unconditionally —
//     "the bundle on disk is the policy". Suitable for the dev loop
//     (chainsaw policy eval/gate) and any deployment that pins the
//     bundle by other means.
//   - A VerifyingLoader (enterprise, internal/policy/dsl/signing)
//     wraps a Loader and gates compilation on a Sigstore signature
//     check. It satisfies this same interface, so callers swap
//     implementations without code changes.
type Loader interface {
	// Load compiles the bundle at the given sources and returns a
	// prepared Engine. An empty/absent source set yields an empty
	// Engine (Engine.Empty()==true), never an error — callers wire the
	// loader unconditionally and treat "no rules" as a no-op.
	Load(ctx context.Context, sources []string) (*Engine, error)
}

// DefaultLoader is the FREE implementation of Loader. It compiles the
// bundle unconditionally via New — no signature verification. This is
// the loader the open-core free path uses everywhere the bundle's
// provenance is established out of band (the rule-author CLI, tests,
// and deployments that don't opt into signed bundles).
//
// The enterprise signed path does NOT replace this type; it WRAPS it
// (see internal/policy/dsl/signing.VerifyingLoader), delegating the
// actual compile to DefaultLoader after the signature check passes.
type DefaultLoader struct{}

// Load implements Loader by delegating straight to New. The Query
// override is intentionally not exposed here — callers that need it
// (essentially none) can call New directly.
func (DefaultLoader) Load(ctx context.Context, sources []string) (*Engine, error) {
	return New(ctx, Options{Sources: sources})
}

// Ensure DefaultLoader satisfies the interface at compile time.
var _ Loader = DefaultLoader{}
