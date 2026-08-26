package provenance

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"
)

// deadNetwork fails every outbound request, so these tests exercise the
// dispatcher and the no-network guard clauses without touching a
// registry. Any result that still comes back StatusUnavailable did so
// because of a decision this package made, not because a fetch failed.
type deadNetwork struct{}

func (deadNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network disabled in test")
}

func newOfflineTestChecker(t *testing.T, opts ...CheckerOption) *Checker {
	t.Helper()
	opts = append([]CheckerOption{WithHTTPClient(&http.Client{Transport: deadNetwork{}})}, opts...)
	return NewChecker(nil, opts...)
}

// registeredAliases returns the dispatch table's keys, sorted, so
// failures name a stable subject.
func registeredAliases(c *Checker) []string {
	out := make([]string, 0, len(c.checkers))
	for k := range c.checkers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestEveryUnavailableCarriesAReason is the P8-48 structural guard.
//
// StatusUnavailable conflates three unrelated outcomes:
//
//	"this ecosystem publishes no attestations"   (cargo, composer, cocoapods)
//	"chainsaw never wrote a checker"             (pub — hit the bare return at the dispatcher)
//	"you did not give us enough to try"          (apt/yum/dnf without --source-url; swift without a registry)
//
// The CLI printed all three as "ecosystem does not expose attestations".
// absent.go exists to prevent exactly this confusion; this test extends
// the same requirement to every path that can produce UNAVAILABLE,
// including the fall-through the plan found empty.
func TestEveryUnavailableCarriesAReason(t *testing.T) {
	c := newOfflineTestChecker(t)

	// Ecosystems chainsaw has never written a checker for. pub is the
	// one Phase 8 caught in the wild; the rest guard the shape.
	unregistered := []string{"pub", "hex", "conan", "swiftpm", "bogus", ""}

	subjects := append(registeredAliases(c), unregistered...)

	for _, eco := range subjects {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		got := c.Check(ctx, eco, "some-package", "1.0.0")
		cancel()

		if got.Status != StatusUnavailable {
			continue
		}
		if strings.TrimSpace(got.Reason) == "" {
			t.Errorf("%q: StatusUnavailable with an EMPTY Reason — "+
				"'we have not written a checker' is indistinguishable from "+
				"'this ecosystem has no standard' (%+v)", eco, got)
		}
		if strings.TrimSpace(got.Error) == "" {
			t.Errorf("%q: StatusUnavailable with an EMPTY Error (%+v)", eco, got)
		}
	}
}

// TestUnregisteredEcosystemBlamesChainsawNotTheEcosystem pins the
// specific pub defect: the fall-through must not imply anything about
// the ecosystem's attestation story.
func TestUnregisteredEcosystemBlamesChainsawNotTheEcosystem(t *testing.T) {
	c := newOfflineTestChecker(t)

	got := c.Check(context.Background(), "pub", "http", "1.2.0")
	if got.Status != StatusUnavailable {
		t.Fatalf("Status = %q, want %q", got.Status, StatusUnavailable)
	}
	if got.Reason != ReasonNoCheckerRegistered {
		t.Fatalf("Reason = %q, want %q", got.Reason, ReasonNoCheckerRegistered)
	}
	if !strings.Contains(got.Error, "gap in chainsaw") {
		t.Errorf("Error must name chainsaw as the gap, got %q", got.Error)
	}
	if got.Ecosystem != "pub" {
		t.Errorf("Ecosystem = %q, want %q", got.Ecosystem, "pub")
	}
}

// TestOfflineAndDisabledAreDistinguishableFromMissingCoverage keeps the
// three causes apart. Deleting a key from the dispatch table destroys
// the distinction unless the Checker remembers why it deleted it.
func TestOfflineAndDisabledAreDistinguishableFromMissingCoverage(t *testing.T) {
	offline := newOfflineTestChecker(t, WithOfflineMode())
	got := offline.Check(context.Background(), "npm", "left-pad", "1.3.0")
	if got.Reason != ReasonOfflineMode {
		t.Errorf("offline npm: Reason = %q, want %q (%+v)", got.Reason, ReasonOfflineMode, got)
	}

	disabled := newOfflineTestChecker(t, WithDisabledEcosystems("maven"))
	got = disabled.Check(context.Background(), "maven", "org.ex:foo", "1.0.0")
	if got.Reason != ReasonEcosystemDisabled {
		t.Errorf("disabled maven: Reason = %q, want %q (%+v)", got.Reason, ReasonEcosystemDisabled, got)
	}
	// An ecosystem that was never registered must NOT claim to be disabled.
	got = disabled.Check(context.Background(), "pub", "http", "1.2.0")
	if got.Reason != ReasonNoCheckerRegistered {
		t.Errorf("pub on a checker with an unrelated disable: Reason = %q, want %q",
			got.Reason, ReasonNoCheckerRegistered)
	}
}

// TestAbsentEcosystemsSayItIsTheEcosystem is the other half: cargo,
// composer and cocoapods genuinely have no standard, and that must stay
// distinguishable from a chainsaw gap.
func TestAbsentEcosystemsSayItIsTheEcosystem(t *testing.T) {
	c := newOfflineTestChecker(t)
	for _, eco := range []string{"cargo", "composer", "cocoapods"} {
		got := c.Check(context.Background(), eco, "pkg", "1.0.0")
		if got.Status != StatusUnavailable {
			t.Errorf("%s: Status = %q, want %q", eco, got.Status, StatusUnavailable)
			continue
		}
		if got.Reason != ReasonEcosystemNoStandard {
			t.Errorf("%s: Reason = %q, want %q", eco, got.Reason, ReasonEcosystemNoStandard)
		}
	}
}

// TestSwiftWithoutRegistryURLNamesTheConfig — P8-48's swift half. The
// checker is registered and correct; its dependency is unset. The result
// must say so, and must not be mistaken for "Swift has no attestations"
// while claim C-073 advertises "Swift PM CMS".
func TestSwiftWithoutRegistryURLNamesTheConfig(t *testing.T) {
	c := newOfflineTestChecker(t)

	got := c.Check(context.Background(), "swift", "apple.swift-argument-parser", "1.3.0")
	if got.Status != StatusUnavailable {
		t.Fatalf("Status = %q, want %q", got.Status, StatusUnavailable)
	}
	if got.Reason != ReasonNotConfigured {
		t.Fatalf("Reason = %q, want %q (%+v)", got.Reason, ReasonNotConfigured, got)
	}
	if !strings.Contains(got.Error, "swift_registry_url") {
		t.Errorf("Error must name the config knob, got %q", got.Error)
	}
	if !strings.Contains(got.Error, "--source-url") {
		t.Errorf("Error must name the CLI flag, got %q", got.Error)
	}
}

// TestOSPackageVerifyWithoutSourceURLIsInvocationError — P8-47.
//
// The status must not be an unqualified UNAVAILABLE, the message must
// name --source-url, and it must NOT name CheckWithSource: an internal Go
// API leaked into an end-user error line.
func TestOSPackageVerifyWithoutSourceURLIsInvocationError(t *testing.T) {
	c := newOfflineTestChecker(t)

	for _, eco := range []string{"apt", "yum", "dnf"} {
		got := c.Check(context.Background(), eco, "openssl", "3.0.2")
		if got.Reason != ReasonSourceURLRequired {
			t.Errorf("%s: Reason = %q, want %q (%+v)", eco, got.Reason, ReasonSourceURLRequired, got)
		}
		if !strings.Contains(got.Error, "--source-url") {
			t.Errorf("%s: Error must name --source-url, got %q", eco, got.Error)
		}
		if strings.Contains(got.Error, "CheckWithSource") {
			t.Errorf("%s: Error still leaks the internal API name: %q", eco, got.Error)
		}
		if !strings.Contains(got.Error, "DOES publish signed repository metadata") {
			t.Errorf("%s: Error must not imply the ecosystem lacks attestations, got %q", eco, got.Error)
		}
	}
}

// TestOSPackageSourceURLIsNeverDefaulted is the anti-regression for the
// refuted fix. Defaulting a mirror can return VERIFIED for bytes the user
// never installed (openssl 3.0.2 exists in both jammy and Debian), and in
// the common miss returns FAILED — the status a tampered package gets.
//
// Asserted at source level because the hazard is a future edit adding a
// default, which a behavioural test on the current code cannot see.
func TestOSPackageSourceURLIsNeverDefaulted(t *testing.T) {
	for _, f := range []string{"apt.go", "yum_dnf.go"} {
		src := readSourceFile(t, f)
		if !strings.Contains(src, `if sourceURL == "" {`) {
			t.Errorf("%s: the empty-sourceURL guard is gone. It is the only thing "+
				"stopping the server dialling a guessed mirror on every Tier-1 scan "+
				"(provider_provenance.go calls CheckWithSource unconditionally).", f)
		}
		if !strings.Contains(src, "sourceURLRequired(") {
			t.Errorf("%s: the guard no longer returns sourceURLRequired()", f)
		}
	}
	src := readSourceFile(t, "apt.go")
	if !strings.Contains(src, "ReasonSourceURLRequired") {
		t.Error("apt.go: sourceURLRequired no longer sets ReasonSourceURLRequired")
	}
}
