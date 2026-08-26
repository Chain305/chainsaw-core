package intelligence

import (
	"fmt"
	"sort"
	"testing"

	"github.com/chain305/chainsaw-core/policy"
)

// P8-39 rail, half one of two (the other lives in
// internal/intelligence/premium, which holds the Wave-4/metadiff whitelists).
//
// Nothing in the tree joined core/policy.SupportMatrix to the intelligence
// providers' Supports() whitelists, and BOTH directions of that gap are
// production bugs:
//
//   - matrix says SupportNone + the provider DOES cover the ecosystem →
//     detectUnsupported fires and core/policy/evaluator.go:868-871 `continue`s
//     past the ENTIRE policy, BLOCK rules included. A rule an operator wrote,
//     against a signal that is genuinely hydrated, silently stops enforcing.
//     This is a LIVE FAIL-OPEN. (P8-58, P8-59 were two instances.)
//
//   - matrix says full/partial + NO producer covers the ecosystem → the UI,
//     the support-matrix API and `chainsaw policy preflight` all advertise a
//     condition that can never fire. ADVERTISED-AND-DEAD.
//
// The join is by policy.EcosystemForFormat, so registry aliases (yarn/bun →
// npm, pypi → pip, gradle → maven, gomod → go) are handled the same way the
// evaluator handles them.

// allProxyFormatStrings is every format string the proxy can present to a
// provider. Grouped through policy.EcosystemForFormat, these are the aliases
// that make up one matrix row.
var allProxyFormatStrings = []string{
	"npm", "yarn", "bun",
	"pip", "pypi",
	"maven", "gradle",
	"cargo", "composer", "rubygems", "nuget",
	"go", "gomod",
	"huggingface", "cocoapods", "swift", "pub",
	"docker", "oci",
	"apt", "yum", "dnf",
}

// conditionProducer binds one matrix column to the whitelist that decides
// whether the signal behind it is ever produced.
type conditionProducer struct {
	condition policy.ConditionType
	// producer names the whitelist site, so a failure message points at the
	// file to edit rather than at an abstraction.
	producer string
	covers   func(format string) bool
}

// matrixProducers are the core/intelligence whitelists with a static,
// dependency-free coverage decision.
//
// Deliberately NOT joined here: providers whose Supports() answer depends on
// an injected collaborator rather than on data — malwareProvider (needs an
// Index and a coverage registry), provenanceProvider (needs a Checker),
// reservedNamespacesProvider (returns true unconditionally). Their coverage is
// a runtime property, so a static join would assert something the code does
// not actually promise. typosquatProvider IS joined because its whitelist
// (typosquat.EcosystemsWithTyposquatRisk) is static data; the nil-Detector
// branch only ever narrows it.
func matrixProducers() []conditionProducer {
	inSet := func(m map[string]struct{}) func(string) bool {
		return func(f string) bool { _, ok := m[f]; return ok }
	}
	installScripts := inSet(supportedInstallScriptEcosystems)
	registryMetadata := inSet(supportedRegistryEcosystems)
	return []conditionProducer{
		{policy.ConditionHasInstallScript, "supportedInstallScriptEcosystems (provider_installscripts.go)", installScripts},
		{policy.ConditionInstallScriptFetchesRemote, "supportedInstallScriptEcosystems (provider_installscripts.go)", installScripts},
		{policy.ConditionHasHiddenUnicode, "supportedHiddenUnicodeEcosystems (provider_hiddenunicode.go)", inSet(supportedHiddenUnicodeEcosystems)},
		{policy.ConditionPackageAge, "supportedRegistryEcosystems (provider_registrymetadata.go)", registryMetadata},
		{policy.ConditionCooldown, "supportedRegistryEcosystems (provider_registrymetadata.go)", registryMetadata},
		{policy.ConditionShrinkwrapPresent, "ecosystemLockfiles (provider_shrinkwrap.go)", inSet(shrinkwrapLockfileEcosystems())},
		{policy.ConditionTyposquat, "typosquat.EcosystemsWithTyposquatRisk (provider_typosquat.go)", inSet(supportedTyposquatEcosystems)},
	}
}

func shrinkwrapLockfileEcosystems() map[string]struct{} {
	out := make(map[string]struct{}, len(ecosystemLockfiles))
	for k := range ecosystemLockfiles {
		out[k] = struct{}{}
	}
	return out
}

// matrixCell identifies one (condition, ecosystem) cell.
type matrixCell struct {
	condition policy.ConditionType
	ecosystem policy.Ecosystem
}

// advertisedElsewhere records cells the matrix advertises that NO whitelist in
// this package covers, because a SECOND producer outside core/intelligence
// hydrates the signal. Each entry MUST carry a non-empty reason naming that
// producer — an empty reason fails the test, so this is not a mute button.
//
// These are the two Phase-8 findings (P8-60, P8-61) that turned out to be
// FALSE on investigation. Both were filed as "advertised with no producer" on
// the assumption that the core provider was the only hydration path. It is
// not: internal/server has its own, independently tested path. Marking these
// cells SupportNone as the findings proposed would have been a real fail-open
// on working signals.
var advertisedElsewhere = map[matrixCell]string{
	{policy.ConditionHasHiddenUnicode, policy.EcoPub}: "" +
		"P8-61 is a false finding. supportsHiddenUnicodeInspection " +
		"(internal/server/artifact_inspection.go:108-134) includes " +
		"repository.FormatPub with an explicit rationale, and the path is " +
		"covered end-to-end by " +
		"TestInspectArtifactSignalsPubHiddenUnicode. pub .tar.gz archives " +
		"route through Tier-2 inspection and .dart is in both the " +
		"inspection and hiddenunicode source-extension allowlists.",
	{policy.ConditionPackageAge, policy.EcoSwift}: reasonReleaseDateFetcher("FormatSwift", "fetchSwiftReleaseDate (internal/server/package_metadata_swift.go:90)"),
	{policy.ConditionCooldown, policy.EcoSwift}:   reasonReleaseDateFetcher("FormatSwift", "fetchSwiftReleaseDate (internal/server/package_metadata_swift.go:90)"),
	{policy.ConditionPackageAge, policy.EcoYum}:   reasonReleaseDateFetcher("FormatYum", "fetchRPMReleaseDate (internal/server/package_metadata.go:1050)"),
	{policy.ConditionCooldown, policy.EcoYum}:     reasonReleaseDateFetcher("FormatYum", "fetchRPMReleaseDate (internal/server/package_metadata.go:1050)"),
	{policy.ConditionPackageAge, policy.EcoDNF}:   reasonReleaseDateFetcher("FormatDNF", "fetchRPMReleaseDate (internal/server/package_metadata.go:1050)"),
	{policy.ConditionCooldown, policy.EcoDNF}:     reasonReleaseDateFetcher("FormatDNF", "fetchRPMReleaseDate (internal/server/package_metadata.go:1050)"),
}

func reasonReleaseDateFetcher(format, fn string) string {
	return fmt.Sprintf(""+
		"P8-60 is a false finding. registryMetadataProvider is NOT the only "+
		"producer of VersionReleaseDate: fetchReleaseDate "+
		"(internal/server/package_metadata.go:274-316) dispatches %s to %s, "+
		"and applyFetchedMetadataFields writes both PackageReleaseDate and "+
		"VersionReleaseDate from it. APT is correctly SupportNone because it "+
		"is the one OS-package format with no case in that switch — the "+
		"matrix is not self-inconsistent, it mirrors the switch exactly.",
		format, fn)
}

// deadButNotAdvertised records cells where a whitelist here DOES cover the
// ecosystem but the matrix says SupportNone on purpose. Reason required.
// Empty today; kept so a deliberate future hold-out has a documented home
// instead of being silently reintroduced as a fail-open.
var deadButNotAdvertised = map[matrixCell]string{}

// TestSupportMatrixMatchesProviderCoverage is the both-directions join.
func TestSupportMatrixMatchesProviderCoverage(t *testing.T) {
	for _, p := range matrixProducers() {
		covered := coverageByEcosystem(t, p.covers)
		for _, eco := range policy.AllEcosystems() {
			cell := matrixCell{p.condition, eco}
			level := policy.Support(eco, p.condition)
			isCovered := covered[eco]

			switch {
			case level == policy.SupportNone && isCovered:
				if reason, ok := deadButNotAdvertised[cell]; ok {
					if reason == "" {
						t.Errorf("%s/%s: hold-out carries no reason", eco, p.condition)
					}
					continue
				}
				t.Errorf("LIVE FAIL-OPEN %s/%s: SupportMatrix says none but %s covers it. "+
					"detectUnsupported fires and core/policy/evaluator.go:868-871 continues past "+
					"the WHOLE policy, so an operator's rule against a hydrated signal stops "+
					"enforcing. Raise the cell, or document it in deadButNotAdvertised with a reason.",
					eco, p.condition, p.producer)

			case level != policy.SupportNone && !isCovered:
				if reason, ok := advertisedElsewhere[cell]; ok {
					if reason == "" {
						t.Errorf("%s/%s: exception carries no reason", eco, p.condition)
					}
					continue
				}
				t.Errorf("ADVERTISED-AND-DEAD %s/%s: SupportMatrix says %s but %s does not cover it, "+
					"so the signal can never fire. Either name the other producer in "+
					"advertisedElsewhere with a reason, or lower the cell — but read "+
					"evaluator.go:868-871 first: lowering makes the whole policy skip.",
					eco, p.condition, level, p.producer)
			}
		}
	}
}

// TestProviderCoverageExceptionsAreHonest keeps the two exception maps from
// rotting: an entry that no longer describes a real disagreement is removed,
// not left behind weakening the join.
func TestProviderCoverageExceptionsAreHonest(t *testing.T) {
	live := make(map[matrixCell]string)
	dead := make(map[matrixCell]string)
	for _, p := range matrixProducers() {
		covered := coverageByEcosystem(t, p.covers)
		for _, eco := range policy.AllEcosystems() {
			cell := matrixCell{p.condition, eco}
			level := policy.Support(eco, p.condition)
			if level == policy.SupportNone && covered[eco] {
				dead[cell] = ""
			}
			if level != policy.SupportNone && !covered[eco] {
				live[cell] = ""
			}
		}
	}
	for cell, reason := range advertisedElsewhere {
		if reason == "" {
			t.Errorf("advertisedElsewhere[%s/%s] carries no reason", cell.ecosystem, cell.condition)
		}
		if _, ok := live[cell]; !ok {
			t.Errorf("advertisedElsewhere[%s/%s] is stale — the matrix and the whitelists now agree; remove it",
				cell.ecosystem, cell.condition)
		}
	}
	for cell, reason := range deadButNotAdvertised {
		if reason == "" {
			t.Errorf("deadButNotAdvertised[%s/%s] carries no reason", cell.ecosystem, cell.condition)
		}
		if _, ok := dead[cell]; !ok {
			t.Errorf("deadButNotAdvertised[%s/%s] is stale; remove it", cell.ecosystem, cell.condition)
		}
	}
}

// TestEveryProxyFormatStringMapsToAMatrixRow guards the join itself: if a new
// proxy format appears and nobody adds it to allProxyFormatStrings (or to
// EcosystemForFormat), the join above would silently stop covering it.
func TestEveryProxyFormatStringMapsToAMatrixRow(t *testing.T) {
	seen := make(map[policy.Ecosystem]struct{})
	for _, f := range allProxyFormatStrings {
		eco := policy.EcosystemForFormat(f)
		if eco == "" {
			t.Errorf("format %q does not map to any matrix ecosystem", f)
			continue
		}
		seen[eco] = struct{}{}
	}
	var missing []string
	for _, eco := range policy.AllEcosystems() {
		if _, ok := seen[eco]; !ok {
			missing = append(missing, string(eco))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("matrix rows with no format string in allProxyFormatStrings: %v", missing)
	}
}

// coverageByEcosystem collapses per-format coverage onto matrix rows: a row is
// covered when ANY of its aliases is.
func coverageByEcosystem(t *testing.T, covers func(string) bool) map[policy.Ecosystem]bool {
	t.Helper()
	out := make(map[policy.Ecosystem]bool, len(policy.AllEcosystems()))
	for _, f := range allProxyFormatStrings {
		eco := policy.EcosystemForFormat(f)
		if eco == "" {
			continue
		}
		if covers(f) {
			out[eco] = true
		}
	}
	return out
}
