package intelligence

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/coverage"
)

// TestProviderToSourceCoversV1Allowlist fails when a v1 source has no provider
// backing it — otherwise an operator could require a source that can never be
// reported OK, and every install would refuse.
func TestProviderToSourceCoversV1Allowlist(t *testing.T) {
	mapped := map[coverage.Source]bool{}
	for _, src := range providerToSource {
		mapped[src] = true
	}
	for _, src := range coverage.AllSources() {
		if !mapped[src] {
			t.Errorf("v1 source %q has no provider in providerToSource; an operator "+
				"requiring it would block every install", src)
		}
	}
}

// TestProviderToSourceKeysAreRealProviders pins the map keys against the
// registered providers' Name() values. A provider rename would otherwise
// silently turn its source into "never ran" — which Gate reads as unavailable,
// so a rename could start refusing every install.
func TestProviderToSourceKeysAreRealProviders(t *testing.T) {
	// Two dead ends make source-scanning the right tool here:
	// ProviderRegistration.Name is explicitly NOT the runtime Name(), and
	// buildProviders(BootstrapConfig{}) silently omits every provider whose
	// factory needs real config (cve, malware, typosquat, provenance among
	// them). Scanning for the literal return pins the exact strings that end
	// up in Report.Observation.
	nameLiteral := regexp.MustCompile(`Name\(\) string\s*\{\s*return "([a-z_]+)"`)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	registered := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range nameLiteral.FindAllStringSubmatch(string(src), -1) {
			registered[m[1]] = true
		}
	}
	if len(registered) == 0 {
		t.Fatal("scanned no provider names — the regex or the package layout changed")
	}
	for name := range providerToSource {
		if !registered[name] {
			t.Errorf("providerToSource key %q is not a registered provider name", name)
		}
	}
}
