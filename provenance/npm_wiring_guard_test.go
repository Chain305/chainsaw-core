package provenance

import (
	"regexp"
	"strings"
	"testing"
)

// npm_wiring_guard_test.go is the npm half of the defect class that
// swift_wiring_guard_test.go documents: a correct function whose
// dependency nobody supplies.
//
// WithNPMRegistryURL shipped fully unit-tested and with ZERO callers, so
// every deployment — mirrored, self-hosted, air-gapped — still probed
// registry.npmjs.org, and a verdict about "this package's attestation"
// was really a verdict about a registry the bytes never came from. Unit
// tests of the option can never catch that; only the composition roots
// can. There are two inside this module (the third, the proxy, lives in
// cmd/chainsaw-proxy and is guarded there, because core/ is exported
// standalone as chainsaw-core and cannot reference cmd/).

var (
	reBootstrapNewCheckerNPM = regexp.MustCompile(`provChecker\s*:=\s*provenance\.NewChecker\(`)
	reBootstrapNPMURL        = regexp.MustCompile(`provChecker\.WithNPMRegistryURL\(cfg\.NPMRegistryURL\)`)
)

// TestSupplyChainBootstrapWiresNPMRegistryURL is the composition-root
// guard for the server path. It fails if someone deletes the call,
// reorders it before construction, or renames the config field without
// rewiring.
func TestSupplyChainBootstrapWiresNPMRegistryURL(t *testing.T) {
	const rel = "../supplychain/bootstrap.go"
	src := readSourceFile(t, rel)

	newIdx := reBootstrapNewCheckerNPM.FindStringIndex(src)
	if newIdx == nil {
		t.Fatalf("%s: provenance.NewChecker(...) assignment to provChecker not found — "+
			"the guard can no longer see the composition root; update this test deliberately", rel)
	}
	urlIdx := reBootstrapNPMURL.FindStringIndex(src)
	if urlIdx == nil {
		t.Fatalf("%s: nothing calls provChecker.WithNPMRegistryURL(cfg.NPMRegistryURL). "+
			"The npm checker is registered and correct but closes over an empty URL, so "+
			"every npm coordinate is probed against registry.npmjs.org regardless of the "+
			"registry this deployment actually resolves from.", rel)
	}
	if urlIdx[0] < newIdx[0] {
		t.Fatalf("%s: WithNPMRegistryURL is called before the Checker is constructed", rel)
	}
	if !strings.Contains(src, "NPMRegistryURL string") {
		t.Errorf("%s: BootstrapConfig no longer carries NPMRegistryURL — "+
			"the proxy has nothing to thread its configured npm upstream through", rel)
	}
}

// TestCLIVerifyWiresNPMRegistryURL — the CLI is the second composition
// root and has no config file to read an npm upstream from. Without
// --source-url threaded into WithNPMRegistryURL, `chainsaw verify npm
// ...` on a mirrored or air-gapped network reports on a registry the
// operator cannot even reach.
func TestCLIVerifyWiresNPMRegistryURL(t *testing.T) {
	const rel = "../cli/verify.go"
	src := readSourceFile(t, rel)
	if !strings.Contains(src, "checker.WithNPMRegistryURL(sourceURL)") {
		t.Fatalf("%s: the CLI never configures the npm registry, so "+
			"`chainsaw verify npm <pkg> <ver> --source-url <mirror>` silently "+
			"ignores --source-url and asks the public registry instead", rel)
	}
	if !strings.Contains(src, "isNPMEcosystem(ecosystem)") {
		t.Fatalf("%s: the npm wiring is no longer gated on the ecosystem — "+
			"a --source-url meant for apt/yum/dnf would be applied as an npm "+
			"registry base", rel)
	}
}

// TestNPMCheckerHonoursConfiguredRegistry is the behavioural half: it
// pins that WithNPMRegistryURL still feeds the checker's closure, so the
// source guards above cannot pass against an option that sets a field
// nothing reads any more.
func TestNPMCheckerHonoursConfiguredRegistry(t *testing.T) {
	c := NewChecker(nil)
	npmc, ok := c.checkers["npm"].(*npmChecker)
	if !ok {
		t.Fatalf("npm checker is not an *npmChecker (%T)", c.checkers["npm"])
	}

	// Unconfigured: the explicit, documented public-registry fallback.
	if got := npmc.registryBase(); got != defaultNPMRegistryURL {
		t.Fatalf("unconfigured registryBase() = %q, want the explicit fallback %q",
			got, defaultNPMRegistryURL)
	}

	// Configured after construction, the way both composition roots do it.
	c.WithNPMRegistryURL("https://npm.mirror.internal.example/")
	if got, want := npmc.registryBase(), "https://npm.mirror.internal.example"; got != want {
		t.Fatalf("configured registryBase() = %q, want %q — WithNPMRegistryURL "+
			"no longer feeds the npm checker's closure", got, want)
	}

	// Empty resolves back to the fallback rather than to an empty base
	// URL that would compose "/-/npm/v1/attestations/..." as a relative
	// request. Both composition roots guard on != "" anyway, so this is
	// only reachable deliberately.
	c.WithNPMRegistryURL("")
	if got := npmc.registryBase(); got != defaultNPMRegistryURL {
		t.Fatalf("registryBase() after WithNPMRegistryURL(\"\") = %q, want the fallback %q",
			got, defaultNPMRegistryURL)
	}
}
