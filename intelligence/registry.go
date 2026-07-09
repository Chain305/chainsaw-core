package intelligence

import "sort"

// Provider registry — the seam for the open-core split.
//
// Historically buildProviders() hardcoded an inline append() for every
// provider. That made it impossible to relocate the premium providers to
// a separate (private) package without editing the one shared function.
//
// This file replaces those inline appends with a registration-based seam:
// every provider declares itself via RegisterProvider, carrying a tier tag
// (CORE vs PREMIUM) and a factory closure. buildProviders then walks the
// ordered registry and materialises the provider list.
//
// The contract that makes this a PURE refactor:
//
//   - Registration order == the historical append order. The registry is an
//     ordered slice, never a map, so iteration is deterministic and matches
//     the previous hand-written sequence one-to-one.
//   - A factory returning nil means "skip" — this reproduces the old
//     nil-dependency guards (e.g. `if cfg.MalwareIndex != nil`). The skip
//     is order-preserving: a nil factory result simply contributes nothing,
//     exactly as the old `if` block did.
//   - No provider is added or removed, no Run logic changes, no env gating
//     moves. Tiers are pure metadata today; they gate nothing at runtime.
//
// The future split: PREMIUM factories move to a private package whose
// init() calls RegisterProvider. Because registration order is preserved
// per-file via Go's deterministic init ordering within a package and the
// linker's package-init ordering across packages, the eventual move keeps
// the slice identical AS LONG AS the premium package's relative position is
// pinned (see docs in the final report).

// ProviderTier classifies a registered provider for the open-core split.
// It is metadata only — it does not influence scan behaviour, ordering, or
// verdicts. Today every tier runs identically; the tag exists so the build
// can later compile CORE-only or CORE+PREMIUM variants.
type ProviderTier int

const (
	// TierCore marks a provider that ships in the public free-core build.
	TierCore ProviderTier = iota
	// TierPremium marks a provider destined for the private enterprise
	// package. Tagging it here (rather than moving the file) lets the
	// classification land first and the physical move follow as a
	// mechanical, reviewable second step.
	TierPremium
)

// String renders the tier for logs / diagnostics.
func (t ProviderTier) String() string {
	switch t {
	case TierCore:
		return "core"
	case TierPremium:
		return "premium"
	default:
		return "unknown"
	}
}

// ProviderFactory builds a Provider from the wired BootstrapConfig.
//
// Returning nil is a first-class outcome: it means "this provider's
// dependencies are not present, skip it". buildProviders drops nil results
// without disturbing the order of the survivors — this is how the registry
// reproduces the old `if cfg.X != nil { append(...) }` guards.
type ProviderFactory func(cfg BootstrapConfig) Provider

// ProviderRegistration is one ordered entry in the registry.
type ProviderRegistration struct {
	// Name is a human-readable label for the registration. It is NOT the
	// provider's runtime Name() (that still comes from the Provider
	// itself); it exists for the classification table, logs, and to make
	// the registry self-documenting. Multiple constructors that the
	// open-core split treats as one logical unit may share a Name.
	Name string

	// Tier classifies the registration for the open-core split. Metadata
	// only — see ProviderTier.
	Tier ProviderTier

	// Order pins the position of this registration in the final provider
	// slice, INDEPENDENT of when RegisterProvider was called. This is what
	// lets CORE registrations (this package's init) and PREMIUM
	// registrations (the internal/intelligence/premium package's init)
	// interleave correctly even though their init() functions run in
	// separate, linker-determined order. buildRegisteredProviders sorts by
	// Order (stable) before materialising, so the historical interleaved
	// sequence (e.g. metadiff sitting between cve and reservedns) is
	// reproduced regardless of cross-package init timing.
	Order int

	// Factory constructs the provider, or returns nil to skip it.
	Factory ProviderFactory
}

// providerRegistry is the ordered list of registrations. Order is
// load-bearing: buildProviders consumes it head-to-tail, so the sequence
// here defines provider execution order within each Tier bucket exactly as
// the old hardcoded appends did.
//
// It is populated by RegisterProvider, called from registry_core.go's and
// registry_premium.go's init() functions. Keeping registration in init()
// (rather than a single build function) is what lets the premium block move
// to a separate package later without touching this file.
var providerRegistry []ProviderRegistration

// RegisterProvider appends a registration to the ordered registry. Call it
// from an init() function. Registration order across init() calls within a
// single package follows source-file name order, then declaration order
// within a file — both deterministic — which is why the core/premium
// registration files are split and named to preserve the historical
// sequence.
func RegisterProvider(reg ProviderRegistration) {
	providerRegistry = append(providerRegistry, reg)
}

// RegisteredProviders returns a snapshot of the registry sorted by Order.
// Exposed for tests and tooling (e.g. asserting the tier classification
// table). Sorting here (rather than relying on append order) decouples the
// final sequence from cross-package init() timing: CORE registrations
// (this package) and PREMIUM registrations (internal/intelligence/premium)
// each carry their historical Order, and the stable sort interleaves them
// back into the canonical sequence.
//
// Exported so the premium package's full-registry order test can observe
// both packages' registrations (a core-package test cannot import premium
// without an import cycle).
func RegisteredProviders() []ProviderRegistration {
	out := make([]ProviderRegistration, len(providerRegistry))
	copy(out, providerRegistry)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Order < out[j].Order })
	return out
}

// buildRegisteredProviders materialises the provider list from the registry,
// sorted by Order, applying each factory against cfg and dropping nil
// results. This is the registry-backed replacement for the old hand-written
// buildProviders body; the public buildProviders now simply delegates here.
//
// Order — not append order — defines the sequence, so a PREMIUM provider
// registered from a separate package's init() lands in its historical slot
// regardless of when the linker ran that init().
func buildRegisteredProviders(cfg BootstrapConfig) []Provider {
	regs := RegisteredProviders()
	providers := make([]Provider, 0, len(regs))
	for _, reg := range regs {
		if reg.Factory == nil {
			continue
		}
		if p := reg.Factory(cfg); p != nil {
			providers = append(providers, p)
		}
	}
	return providers
}
