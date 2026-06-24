package intelligence

// reservedNamespacesProvider is a pure-policy provider: it extracts the
// namespace prefix of the package name so the downstream policy
// evaluator (and the Shodan UI) can group / match by namespace without
// re-parsing the name. It performs no I/O and holds no state.
//
// Namespace extraction rules (covering every ecosystem that has one):
//
//	npm   @babel/core             → @babel
//	maven org.apache.commons:commons-lang3
//	                              → org.apache.commons
//	go    golang.org/x/mod        → golang.org/x
//	composer symfony/http-kernel  → symfony
//	rubygems/cargo/pip            (no namespace convention) → ""
//
// The actual reserved-namespace matching (against policy Conditions
// and the depconfusion default packs) is done by the evaluator — the
// provider's job is just to surface Identity.Namespace.

import (
	"context"
	"strings"
)

type reservedNamespacesProvider struct{}

func newReservedNamespacesProvider() *reservedNamespacesProvider {
	return &reservedNamespacesProvider{}
}

func (p *reservedNamespacesProvider) Name() string { return "reservednamespaces" }

func (p *reservedNamespacesProvider) Signal() SignalMask { return SignalReservedNamespaces }

func (p *reservedNamespacesProvider) Tier() int { return 1 }

// NeedsArtifact is false — name-only extraction.
func (p *reservedNamespacesProvider) NeedsArtifact() bool { return false }

// Supports returns true for every ecosystem. Formats without a
// namespace convention (cargo, rubygems) still route through here; the
// extractor simply returns "" and the evaluator treats them as
// unnamespaced. No harm, no panic.
func (p *reservedNamespacesProvider) Supports(ecosystem string) bool {
	return true
}

// Run writes Identity.Namespace only when the package name carries one
// on its face. Returns an empty PartialReport when no namespace is
// detectable — leaving any upstream-provided namespace untouched.
func (p *reservedNamespacesProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	ns := extractNamespace(req.Key.Ecosystem, req.Key.Package)
	if ns == "" {
		return PartialReport{}, nil
	}
	// We write the namespace via the top-level Identity — there's no
	// separate "Identity" slot on PartialReport, so the Scanner's merge
	// path doesn't surface this directly. The intelligence Report's
	// Identity section is populated by runFanout at assembly time from
	// req.Key; providers that want to contribute identity hints emit
	// a SupplyChain section with a hint. For now we only populate what
	// the merge pipeline actually ships: namespace-derived signals go
	// on SupplyChain, but SupplyChain has no Namespace field, so the
	// safe place is no-op until the namespace lands as a first-class
	// PartialReport field. Keeping the extraction here documents the
	// provider's intent and lets future wiring land without touching
	// Supports / Run again.
	//
	// To avoid returning a dead PartialReport, surface namespace as a
	// low-severity warning tag so operators can see the extracted value
	// while the Report schema catches up. This keeps the signal visible
	// and makes the provider observable during bootstrap.
	return PartialReport{
		Warnings: []Warning{{
			Provider: p.Name(),
			Code:     "namespace_extracted",
			Message:  ns,
		}},
	}, nil
}

// extractNamespace parses the conventional namespace prefix off a
// package name. Returns "" for ecosystems / names without a convention.
func extractNamespace(ecosystem, pkg string) string {
	pkg = strings.TrimSpace(pkg)
	if pkg == "" {
		return ""
	}
	switch strings.ToLower(ecosystem) {
	case "npm", "yarn", "bun":
		// npm scope: @scope/name (modern scoped packages win first).
		if strings.HasPrefix(pkg, "@") {
			if slash := strings.Index(pkg, "/"); slash > 0 {
				return pkg[:slash]
			}
			return ""
		}
		// Legacy org-style: myorg/internal-utils — some private
		// registries still publish unscoped paths with a slash. Treat
		// the prefix as a namespace so reserved-namespace policy can
		// catch typo-squats against internal orgs.
		if slash := strings.Index(pkg, "/"); slash > 0 {
			return pkg[:slash]
		}
		return ""
	case "maven", "gradle":
		// group:artifact — take everything before the colon.
		if colon := strings.Index(pkg, ":"); colon > 0 {
			return pkg[:colon]
		}
		// Also accept dotted group names without an explicit artifact
		// when the caller used org.apache.commons.commons-lang3.
		if dot := strings.LastIndex(pkg, "."); dot > 0 {
			return pkg[:dot]
		}
		return ""
	case "go", "gomod":
		// Go import paths: domain/owner/repo/.../subpkg.
		// Namespace is everything except the final path element.
		// NOTE: this is purely lexical — we do NOT resolve vanity
		// domains (e.g. git.company.com may redirect to GitHub via
		// <meta name="go-import">). Two visually-similar domains
		// (git.company.com vs git.xompany.com) therefore yield
		// distinct namespace prefixes here, which is what the
		// reserved-namespace policy wants for typo detection.
		if slash := strings.LastIndex(pkg, "/"); slash > 0 {
			return pkg[:slash]
		}
		return ""
	case "composer":
		// vendor/package
		if slash := strings.Index(pkg, "/"); slash > 0 {
			return pkg[:slash]
		}
		return ""
	case "nuget":
		// Dotted PackageName; namespace is everything before the final
		// segment when a dot is present.
		if dot := strings.LastIndex(pkg, "."); dot > 0 {
			return pkg[:dot]
		}
		return ""
	case "docker":
		// [registry/]namespace/image[:tag]. Bare names with no slash
		// (e.g. "alpine", "alpine:3.19") refer to Docker Hub's
		// implicit "library/" namespace — surface that explicitly so
		// reserved-namespace policy can match official images.
		name := pkg
		if colon := strings.Index(name, ":"); colon > 0 {
			name = name[:colon]
		}
		if slash := strings.Index(name, "/"); slash > 0 {
			return name[:slash]
		}
		return "library"
	case "huggingface":
		// owner/model
		if slash := strings.Index(pkg, "/"); slash > 0 {
			return pkg[:slash]
		}
		return ""
	case "pypi", "pip":
		// PyPI has no namespace convention. PEP 503 normalization
		// (lowercase + collapse runs of [-_.]) applies to the *name*,
		// not a namespace — and would be the wrong layer here since
		// this function only returns the namespace string.
		// TODO: PEP 503 normalization belongs at the Identity layer
		// where the package name itself is canonicalized.
		return ""
	case "rubygems", "gem":
		// RubyGems has no namespace convention; gems are flat.
		return ""
	case "cargo":
		// Cargo has no namespace convention; crates are flat.
		return ""
	default:
		return ""
	}
}

var _ Provider = (*reservedNamespacesProvider)(nil)
