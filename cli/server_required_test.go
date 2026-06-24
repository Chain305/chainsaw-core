package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// BUG-CLI-1 regression: the standardised "server URL not configured"
// error must (a) keep the historical phrase verbatim so telemetry
// classifiers still tag it as `auth`/`other` correctly, (b) name the
// invoking command, (c) point at the two recovery paths, and (d)
// mention --help. A nil cmd is allowed (used by newV1Client) and must
// still produce a usable message.
func TestErrServerNotConfigured_MessageShape(t *testing.T) {
	parent := &cobra.Command{Use: "chainsaw"}
	sub := &cobra.Command{Use: "preflight"}
	policy := &cobra.Command{Use: "policy"}
	parent.AddCommand(policy)
	policy.AddCommand(sub)

	got := errServerNotConfigured(sub).Error()
	mustContain := []string{
		"server URL not configured",                // historical phrase
		"chainsaw policy preflight",                // names the command
		"chainsaw auth login --device",             // recovery #1
		"chainsaw setup",                           // recovery #2
		"chainsaw --server <url> policy preflight", // one-shot form
		"--help",                   // help reference
		"Offline-capable commands", // category clarifier
	}
	for _, s := range mustContain {
		if !strings.Contains(got, s) {
			t.Errorf("error message missing %q\nfull message:\n%s", s, got)
		}
	}
}

func TestErrServerNotConfigured_NilCmd(t *testing.T) {
	got := errServerNotConfigured(nil).Error()
	if !strings.Contains(got, "server URL not configured") {
		t.Fatalf("nil-cmd path lost the historical phrase: %s", got)
	}
	if !strings.Contains(got, "chainsaw") {
		t.Fatalf("nil-cmd path must still mention the binary name: %s", got)
	}
}
