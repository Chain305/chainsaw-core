package intelligence

// analyzer_config_guard.go — the shared half of the "a cacheable analyzer must
// account for its non-byte configuration" guard (A-3).
//
// WHY THIS IS NOT PURELY A TEST. The scan has to run over BOTH packages'
// provider sources — core/intelligence and internal/intelligence/premium — and
// core cannot import premium. So the rule lives here, exported to tests, and
// each package's own test points it at its own directory. One definition of
// the rule, two call sites, no second copy to drift.
//
// WHAT IT CATCHES. The cache key is (digest, ecosystem, analyzer, version,
// config). A cacheable analyzer that reads configuration the key does not
// carry will have the answer computed under the OLD configuration served
// indefinitely, because nothing evicts this table. Four analyzers already did
// this: two env thresholds, one lane flag read inside Run, and the ecosystem
// itself. The guard exists so the fifth is caught by the build.
//
// WHAT IT CANNOT CATCH. Configuration reached through a helper in another
// package, where this file's own source scan sees no token. That residual is
// stated rather than papered over: the scan is a tripwire on the obvious
// spelling, not a proof.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// analyzerConfigTokens are the spellings that mean "this source reads
// configuration from outside the artifact bytes".
//
// Deliberately broad and deliberately cheap. A false positive costs one line
// in a package's allowlist with a reason; a false negative costs a silently
// permanent wrong answer.
var analyzerConfigTokens = []string{
	"os.Getenv",
	"featureflags.",
	"resolveIntEnv",
	"envBool",
	"envInt",
}

var providerNameRe = regexp.MustCompile(`Name\(\) string\s*{\s*return\s+"([^"]+)"`)

// ConfigReadingProviderFiles scans dir's provider_*.go files and returns, for
// each provider name defined in a file that reads configuration, the file that
// defines it.
//
// FILE GRANULARITY, NOT FUNCTION GRANULARITY, ON PURPOSE. provider_codesmell.go
// defines nine providers over one shared extraction pass and
// provider_wave4_artifact.go defines two over one shared env helper, so a
// config read anywhere in a file plausibly reaches every analyzer in it.
// Narrowing to the exact method that reads the token would be more precise and
// would miss the construction-time case entirely — resolveIntEnv is called from
// a CONSTRUCTOR, not from Run, which is exactly how the two threshold defects
// got in.
func ConfigReadingProviderFiles(dir string) (map[string]string, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "provider_*.go"))
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	scanned := 0
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		scanned++
		src := string(body)
		if !readsConfig(src) {
			continue
		}
		for _, m := range providerNameRe.FindAllStringSubmatch(src, -1) {
			out[m[1]] = filepath.Base(path)
		}
	}
	if scanned == 0 {
		return nil, fmt.Errorf("intelligence: no provider_*.go files under %q — "+
			"the config guard scanned nothing, so a green result means the path is "+
			"wrong, not that the tree is clean", dir)
	}
	return out, nil
}

// readsConfig reports whether src contains a configuration-reading token
// outside of a comment line. Comments matter: several providers DISCUSS env
// vars in their doc comments, and treating those as reads would put most of
// the registry on the allowlist and make it meaningless.
func readsConfig(src string) bool {
	for _, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") {
			continue
		}
		for _, tok := range analyzerConfigTokens {
			if strings.Contains(t, tok) {
				return true
			}
		}
	}
	return false
}

// ConfigAccounting names how an analyzer accounts for its configuration.
type ConfigAccounting string

const (
	// AccountedByVersion means the configuration selects between fixed
	// generations, folded into AnalyzerVersion. installscripts does this: the
	// regex and AST detectors are versions 1 and 2.
	AccountedByVersion ConfigAccounting = "version"
	// AccountedByFingerprint means the configuration is a key component via
	// ConfiguredAnalyzer, because it is unordered — a threshold, a flag.
	AccountedByFingerprint ConfigAccounting = "fingerprint"
)

// AuditCacheableAnalyzerConfig checks every cacheable analyzer in providers
// against the config-reading files in dir and the package's allowlist.
//
// Returns one message per problem, empty when clean. Callers fail the test on
// any message; the messages carry their own remediation.
func AuditCacheableAnalyzerConfig(
	providers []Provider, dir string, allow map[string]ConfigAccounting,
) ([]string, error) {
	readers, err := ConfigReadingProviderFiles(dir)
	if err != nil {
		return nil, err
	}

	var problems []string
	cacheable := map[string]Provider{}
	for _, p := range providers {
		if p == nil {
			continue
		}
		if _, ok := analyzerVersionOf(p); ok {
			cacheable[p.Name()] = p
		}
	}

	for name, p := range cacheable {
		file, reads := readers[name]
		how, listed := allow[name]

		if reads && !listed {
			problems = append(problems, fmt.Sprintf(
				"%s is a CACHEABLE analyzer defined in %s, which reads configuration "+
					"(%v) that the cache key does not carry. Its output would be computed "+
					"once under one configuration and served forever, and nothing evicts "+
					"the table. Either implement ConfiguredAnalyzer so the configuration "+
					"becomes a key component, or fold it into AnalyzerVersion if it selects "+
					"between fixed generations — then add it to this package's allowlist "+
					"saying which.", name, file, analyzerConfigTokens))
			continue
		}
		if !listed {
			continue
		}

		_, hasFingerprint := p.(ConfiguredAnalyzer)
		switch how {
		case AccountedByFingerprint:
			if !hasFingerprint {
				problems = append(problems, fmt.Sprintf(
					"%s is allowlisted as accounting for configuration by FINGERPRINT but "+
						"does not implement ConfiguredAnalyzer, so its configuration is not "+
						"in the cache key at all.", name))
				continue
			}
			if analyzerConfigOf(p) == "" {
				problems = append(problems, fmt.Sprintf(
					"%s returns an EMPTY config fingerprint. Empty means 'reads no "+
						"configuration', so every configuration collapses to one key and the "+
						"first answer written wins permanently.", name))
			}
		case AccountedByVersion:
			if hasFingerprint {
				problems = append(problems, fmt.Sprintf(
					"%s is allowlisted as accounting for configuration by VERSION but also "+
						"implements ConfiguredAnalyzer. Pick one: two mechanisms for the same "+
						"input is how they drift.", name))
			}
		default:
			problems = append(problems, fmt.Sprintf(
				"%s has an unrecognised accounting %q in the allowlist", name, how))
		}
	}

	// A stale allowlist entry is a silent hole: a renamed or retired analyzer
	// leaves a line that matches nothing, and the next analyzer to read config
	// is compared against a list that looks maintained.
	for name := range allow {
		if _, ok := cacheable[name]; !ok {
			problems = append(problems, fmt.Sprintf(
				"allowlist names %q, which is not a cacheable analyzer in this registry. "+
					"It was renamed, retired, or made non-cacheable — delete or update the "+
					"line, because a stale entry makes the list look maintained when it is "+
					"not.", name))
		}
	}

	sort.Strings(problems)
	return problems, nil
}
