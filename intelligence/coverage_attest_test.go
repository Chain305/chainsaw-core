package intelligence

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/coverage"
)

// TestAttestationPartitionMatchesProviderTiers pins coverage's metadata-only /
// artifact-bound split against the providers' real Tier() values.
//
// coverage is a stdlib-only leaf package, so it cannot see the providers and
// has to hard-code the split. That is fine right up until someone promotes the
// checksum provider to Tier 1, or adds a byte-reading step to a Tier-1
// provider — at which point the metadata-only surfaces would be validating
// against a fiction. Either the operator gets refused a source the surface
// could actually have attested, or (worse) allowed to require one it cannot.
//
// Tier 1 providers run on a coordinate alone; Tier >= 2 providers need the
// artifact bytes and emit "needs_artifact" without them.
func TestAttestationPartitionMatchesProviderTiers(t *testing.T) {
	tiers := providerTiersByName(t)

	check := func(srcs []coverage.Source, wantTier1 bool, label string) {
		t.Helper()
		for _, src := range srcs {
			name := providerNameForSource(t, src)
			tier, ok := tiers[name]
			if !ok {
				t.Errorf("%s source %q maps to provider %q, which declares no Tier()", label, src, name)
				continue
			}
			if wantTier1 && tier != 1 {
				t.Errorf("source %q is classified metadata-only but provider %q is Tier %d "+
					"(Tier >= 2 needs artifact bytes, so a metadata-only surface cannot attest it)",
					src, name, tier)
			}
			if !wantTier1 && tier < 2 {
				t.Errorf("source %q is classified artifact-bound but provider %q is Tier %d "+
					"— a metadata-only surface could attest it, so requiring it there should be allowed",
					src, name, tier)
			}
		}
	}

	check(coverage.MetadataOnlySources(), true, "metadata-only")
	check(coverage.ArtifactBoundSources(), false, "artifact-bound")
}

func providerNameForSource(t *testing.T, src coverage.Source) string {
	t.Helper()
	for name, s := range providerToSource {
		if s == src {
			return name
		}
	}
	t.Fatalf("source %q has no entry in providerToSource", src)
	return ""
}

// providerTiersByName links each provider's Name() literal to its Tier()
// literal via the receiver type. Source scanning (rather than constructing the
// registry) is the same dead end coverage_sourcemap_test.go documents:
// buildProviders silently omits every provider whose factory needs real
// config, which is most of the ones we care about here.
func providerTiersByName(t *testing.T) map[string]int {
	t.Helper()

	nameRe := regexp.MustCompile(`func \(\w+ \*(\w+)\) Name\(\) string\s*\{\s*return "([a-z_]+)"`)
	tierRe := regexp.MustCompile(`func \(\w+ \*(\w+)\) Tier\(\) int\s*\{\s*return (\d+)`)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	nameByType := map[string]string{}
	tierByType := map[string]int{}
	for _, e := range entries {
		fn := e.Name()
		if !strings.HasSuffix(fn, ".go") || strings.HasSuffix(fn, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(fn))
		if err != nil {
			t.Fatal(err)
		}
		text := string(src)
		for _, m := range nameRe.FindAllStringSubmatch(text, -1) {
			nameByType[m[1]] = m[2]
		}
		for _, m := range tierRe.FindAllStringSubmatch(text, -1) {
			tierByType[m[1]] = int(m[2][0] - '0')
		}
	}
	if len(nameByType) == 0 || len(tierByType) == 0 {
		t.Fatal("scanned no provider Name()/Tier() literals — the regex or the package layout changed")
	}

	out := map[string]int{}
	for typ, name := range nameByType {
		if tier, ok := tierByType[typ]; ok {
			out[name] = tier
		}
	}
	return out
}
