package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// gateFixture writes the minimal input document `policy gate` needs, so the
// test fails on the bundle check rather than on a missing --input.
func gateFixture(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(p, []byte(`{"surface":"proxy"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func runGate(t *testing.T, bundle, input string) error {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().String("bundle", bundle, "")
	cmd.Flags().String("input", input, "")
	cmd.Flags().Bool("json", false, "")
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	return runPolicyGate(cmd, []string{"proxy"})
}

// THE regression test. `chainsaw policy gate` is the one verb shaped like a
// CI gate, and pointing it at a path that does not exist printed
// "action=allow violations=0" and exited 0 — a typo'd --bundle, a deleted
// .rego, or a job started in the wrong working directory silently passed
// every check. The output was sitting in our own bug register as incidental
// evidence for a different finding and nobody read it as one.
func TestPolicyGateRefusesANonexistentBundle(t *testing.T) {
	err := runGate(t, "/nonexistent/bundle/path", gateFixture(t))
	if err == nil {
		t.Fatal("gate exited 0 on a bundle path that does not exist — this is the rubber stamp")
	}
	if got := exitCode(err); got != ExitOpError {
		t.Errorf("exit code = %d, want %d (ExitOpError)", got, ExitOpError)
	}
	// The absolute path is the point: a wrong working directory is the
	// likeliest cause and the typed relative string will not reveal it.
	if !strings.Contains(err.Error(), "/nonexistent/bundle/path") {
		t.Errorf("error does not name the offending path: %v", err)
	}
}

// An empty-but-real directory is the other half: discovery succeeds, finds
// nothing, and Decide short-circuits to allow.
func TestPolicyGateRefusesAnEmptyBundle(t *testing.T) {
	err := runGate(t, t.TempDir(), gateFixture(t))
	if err == nil {
		t.Fatal("gate exited 0 on a bundle directory containing no rego sources")
	}
	if got := exitCode(err); got != ExitOpError {
		t.Errorf("exit code = %d, want %d", got, ExitOpError)
	}
	if !strings.Contains(err.Error(), "no rego sources") {
		t.Errorf("error does not explain the cause: %v", err)
	}
}

// Control: a bundle with a real rule must NOT be refused by either check.
// Without this, "always refuse" passes both tests above.
func TestPolicyGateAcceptsAPopulatedBundle(t *testing.T) {
	dir := t.TempDir()
	rule := "package chainsaw.policy\n\ndefault action := \"allow\"\n"
	if err := os.WriteFile(filepath.Join(dir, "p.rego"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runGate(t, dir, gateFixture(t))
	if err != nil {
		if strings.Contains(err.Error(), "no rego sources") ||
			strings.Contains(err.Error(), "was not fully read") {
			t.Fatalf("a populated bundle was refused by the emptiness/skip check: %v", err)
		}
		// Any other error (a policy decision, an input-shape complaint) is
		// outside what these two checks govern.
		t.Logf("gate returned a non-bundle error, which is fine here: %v", err)
	}
}
