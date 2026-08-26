package cli

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/provenance"
)

// TestVerifyWithoutSourceURLExitsFour — P8-47.
//
// `chainsaw verify apt openssl 3.0.2` used to print
//
//	Status:  UNAVAILABLE (ecosystem does not expose attestations)
//	Error:   OS package provenance requires the source repository URL; call CheckWithSource
//
// and exit 1. Three things wrong: APT emphatically does expose
// attestations (chainsaw walks the whole InRelease → Packages → .deb
// sha256 chain, and claim C-021 advertises it); the exit code said
// "blocked" when nothing was evaluated; and the error named an internal
// Go API at an end user.
//
// Exit 4 is ExitUsage — bad invocation. It is deliberately NOT exit 1.
func TestVerifyWithoutSourceURLExitsFour(t *testing.T) {
	for _, eco := range []string{"apt", "yum", "dnf", "swift", "APT", "  Dnf  "} {
		err := requireSourceURL(eco, "")
		if err == nil {
			t.Errorf("%q: want a usage error, got nil", eco)
			continue
		}
		var ec *ExitCodeError
		if !errors.As(err, &ec) {
			t.Errorf("%q: error is %T, want *ExitCodeError", eco, err)
			continue
		}
		if ec.Code != ExitUsage {
			t.Errorf("%q: exit code = %d, want %d (ExitUsage)", eco, ec.Code, ExitUsage)
		}
		msg := ec.Err.Error()
		if !strings.Contains(msg, "--source-url") {
			t.Errorf("%q: message must name --source-url, got %q", eco, msg)
		}
		if !strings.Contains(msg, "Try: chainsaw verify") {
			t.Errorf("%q: message must carry a worked example, got %q", eco, msg)
		}
		if strings.Contains(msg, "CheckWithSource") {
			t.Errorf("%q: message leaks the internal API name: %q", eco, msg)
		}
		if !strings.Contains(msg, "does publish verifiable provenance") {
			t.Errorf("%q: message must not imply the ecosystem lacks provenance, got %q", eco, msg)
		}
	}
}

// TestVerifyWorkedExampleIsPerDistro — a bare "pass --source-url" is not
// actionable if the operator does not know what an APT distribution root
// looks like.
func TestVerifyWorkedExampleIsPerDistro(t *testing.T) {
	cases := map[string]string{
		"apt":   "deb.debian.org",
		"yum":   "fedoraproject.org",
		"dnf":   "fedoraproject.org",
		"swift": "swift-registry",
	}
	for eco, want := range cases {
		err := requireSourceURL(eco, "")
		if err == nil {
			t.Fatalf("%s: expected an error", eco)
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: worked example missing %q, got %q", eco, want, err.Error())
		}
	}
}

// TestVerifySourceURLSuppliedIsAccepted — the gate must not fire when
// the flag IS present, and must not fire for ecosystems that do not need
// it.
func TestVerifySourceURLSuppliedIsAccepted(t *testing.T) {
	if err := requireSourceURL("apt", "https://deb.debian.org/debian/dists/bookworm"); err != nil {
		t.Errorf("apt with --source-url: %v", err)
	}
	for _, eco := range []string{"npm", "pypi", "maven", "go", "docker", "nuget", "rubygems", "cargo", "pub"} {
		if err := requireSourceURL(eco, ""); err != nil {
			t.Errorf("%s must not require --source-url: %v", eco, err)
		}
	}
}

// TestUnavailableGlossNeverClaimsTheEcosystemHasNothing — P8-48's
// user-facing half. Only ReasonEcosystemNoStandard may make a claim
// about the ecosystem.
func TestUnavailableGlossNeverClaimsTheEcosystemHasNothing(t *testing.T) {
	ecosystemBlaming := []string{
		provenance.ReasonNoCheckerRegistered,
		provenance.ReasonNotConfigured,
		provenance.ReasonSourceURLRequired,
		provenance.ReasonKeyringUnavailable,
		provenance.ReasonInconclusive,
		provenance.ReasonOfflineMode,
		provenance.ReasonEcosystemDisabled,
		provenance.ReasonArtifactTooLarge,
		provenance.ReasonUpstreamError,
		"",
	}
	for _, reason := range ecosystemBlaming {
		gloss := unavailableGloss(reason)
		if strings.Contains(gloss, "ecosystem publishes no") ||
			strings.Contains(gloss, "does not expose attestations") {
			t.Errorf("reason %q renders as a claim about the ecosystem: %q", reason, gloss)
		}
		if strings.TrimSpace(gloss) == "" {
			t.Errorf("reason %q renders as an empty gloss", reason)
		}
	}
	if got := unavailableGloss(provenance.ReasonEcosystemNoStandard); !strings.Contains(got, "publishes no") {
		t.Errorf("ReasonEcosystemNoStandard gloss = %q; this is the ONE case where "+
			"blaming the ecosystem is correct", got)
	}
}

// TestPrintVerifyHumanSurfacesReason — the reason has to reach the
// operator, not just the JSON.
func TestPrintVerifyHumanSurfacesReason(t *testing.T) {
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	printVerifyHuman("pub", "http", "1.2.0", provenance.Result{
		Status:    provenance.StatusUnavailable,
		Ecosystem: "pub",
		Reason:    provenance.ReasonNoCheckerRegistered,
		Error:     "chainsaw has no provenance checker for \"pub\"",
	})

	_ = w.Close()
	os.Stdout = orig
	out := <-done

	if !strings.Contains(out, provenance.ReasonNoCheckerRegistered) {
		t.Errorf("stdout missing the reason code, got:\n%s", out)
	}
	if strings.Contains(out, "ecosystem does not expose attestations") {
		t.Errorf("stdout still asserts the ecosystem has nothing, got:\n%s", out)
	}
	if !strings.Contains(out, "coverage gap") {
		t.Errorf("stdout must attribute the gap to chainsaw, got:\n%s", out)
	}
}

// TestVerifyJSONCarriesReason — dashboards and CI branch on the JSON, so
// the reason must be a first-class field there too.
func TestVerifyJSONCarriesReason(t *testing.T) {
	out := verifyJSON("apt", "openssl", "3.0.2", provenance.Result{
		Status:    provenance.StatusUnavailable,
		Ecosystem: "apt",
		Reason:    provenance.ReasonSourceURLRequired,
	})
	if got, _ := out["reason"].(string); got != provenance.ReasonSourceURLRequired {
		t.Errorf("json reason = %q, want %q", got, provenance.ReasonSourceURLRequired)
	}
	if got, _ := out["verified"].(bool); got {
		t.Error("verified must stay false")
	}
}
