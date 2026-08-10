package cli

// setup_test.go covers the additive pieces around `chainsaw setup`: the
// closing next-step printer (B.4.4 contract: every persona variant must
// surface an explicit ecosystem block command) and the --skip-persona
// flag wiring on the cobra command. The full wizard flow stays under
// the existing manual / smoke harness — these tests only pin the
// pieces a future refactor is most likely to break by accident.

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/agenticux"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// what was written. printSetupNextStep uses fmt.Println directly (not
// a cobra writer), so we intercept at the os.Stdout level.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()

	fn()
	_ = w.Close()
	<-done
	return buf.String()
}

func TestPrintSetupNextStep_AppSecGetsTyposquatDemo(t *testing.T) {
	out := captureStdout(t, func() {
		printSetupNextStep(agenticux.PersonaAppSec)
	})
	if !strings.Contains(out, "npm install lodahs") {
		t.Errorf("appsec output missing typosquat demo command:\n%s", out)
	}
	// C1: the closing message must surface the WIRING prerequisite as an actual
	// command (not a URL), and it must come BEFORE the demo — otherwise the demo
	// `npm install lodahs` does nothing because nothing is routed yet.
	if !strings.Contains(out, "chainsaw install-hook") {
		t.Errorf("output missing the install-hook wiring step:\n%s", out)
	}
	if wire, demo := strings.Index(out, "chainsaw install-hook"), strings.Index(out, "npm install lodahs"); wire < 0 || demo < 0 || wire > demo {
		t.Errorf("install-hook wiring step must appear before the demo command:\n%s", out)
	}
}

func TestPrintSetupNextStep_DevSecOpsGetsCIHint(t *testing.T) {
	out := captureStdout(t, func() {
		printSetupNextStep(agenticux.PersonaDevSecOps)
	})
	if !strings.Contains(out, "npm install lodahs") {
		t.Errorf("devsecops output missing typosquat demo command:\n%s", out)
	}
	// The CI hint must be a REAL command. `chainsaw run` does not exist; the
	// guard-init-in-CI form uses only real, auth-free commands.
	if !strings.Contains(out, "chainsaw guard init bash") {
		t.Errorf("devsecops output missing CI hint:\n%s", out)
	}
	if strings.Contains(out, "chainsaw run") {
		t.Errorf("devsecops CI hint references nonexistent `chainsaw run`:\n%s", out)
	}
}

func TestPrintSetupNextStep_EnterpriseITGetsAuditCommand(t *testing.T) {
	out := captureStdout(t, func() {
		printSetupNextStep(agenticux.PersonaEnterpriseIT)
	})
	// Must be the REAL subcommand: `audit view` (not `audit logs`, which errors).
	if !strings.Contains(out, "chainsaw audit view --since 24h") {
		t.Errorf("enterprise_it output missing audit command:\n%s", out)
	}
	if strings.Contains(out, "audit logs") {
		t.Errorf("enterprise_it references nonexistent `audit logs` subcommand:\n%s", out)
	}
}

func TestPrintSetupNextStep_EndUserDevAndSkippedFallback(t *testing.T) {
	// end_user_dev, "" (skipped), and any unknown persona ID should all
	// fall through to the typosquat demo — B.4.4 looks for the lodahs
	// string regardless of persona path.
	for _, persona := range []string{agenticux.PersonaEndUserDev, "", "totally-unknown"} {
		out := captureStdout(t, func() {
			printSetupNextStep(persona)
		})
		if !strings.Contains(out, "npm install lodahs") {
			t.Errorf("persona %q: output missing typosquat demo:\n%s", persona, out)
		}
	}
}

func TestSetupCmd_SkipPersonaFlagRegistered(t *testing.T) {
	// We don't run the wizard end-to-end here — just pin that
	// --skip-persona is a documented flag so future help-text edits or
	// flag rewrites don't quietly drop it.
	f := setupCmd.Flags().Lookup("skip-persona")
	if f == nil {
		t.Fatal("setup command is missing --skip-persona flag")
	}
	if f.DefValue != "false" {
		t.Errorf("--skip-persona default = %q, want false", f.DefValue)
	}
}
