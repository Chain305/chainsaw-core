package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/provenance"
)

// TestPrintVerifyHumanWritesToStdout confirms the human "Verifying …"
// header is emitted on stdout. The pre-call progress line added in
// runVerify goes to stderr precisely so it does not duplicate this one on
// the same stream and keeps stdout/JSON clean.
//
// Uses an inline os.Stdout redirect rather than a shared helper so this
// file stays independent of test helpers owned by other files.
func TestPrintVerifyHumanWritesToStdout(t *testing.T) {
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

	printVerifyHuman("npm", "left-pad", "1.3.0", provenance.Result{
		Status: provenance.StatusVerified,
	})

	_ = w.Close()
	os.Stdout = orig
	out := <-done

	if !strings.Contains(out, "Verifying npm/left-pad@1.3.0") {
		t.Errorf("stdout missing verify header, got:\n%s", out)
	}
	if !strings.Contains(out, "VERIFIED") {
		t.Errorf("stdout missing VERIFIED status, got:\n%s", out)
	}
}

func TestVerifyJSONShape(t *testing.T) {
	r := provenance.Result{
		Status:          provenance.StatusVerified,
		Ecosystem:       "npm",
		AttestationType: "sigstore",
		SLSALevel:       3,
		BuilderID:       "https://github.com/slsa-framework/slsa-github-generator",
		SourceRepo:      "https://github.com/foo/bar",
		SourceCommit:    "abc123",
		SubjectDigest:   "sha256:def456",
	}
	out := verifyJSON("npm", "leftpad", "1.0.0", r)
	for _, key := range []string{
		"ecosystem", "package", "version", "status", "verified",
		"attestationType", "slsaLevel", "builderId", "sourceRepo",
		"sourceCommit", "subjectDigest", "bundleFormat",
		"transparencyLog", "cacheStale", "warnings", "verifiedAt",
	} {
		if _, ok := out[key]; !ok {
			t.Errorf("verifyJSON missing key %q", key)
		}
	}
	if v, _ := out["verified"].(bool); !v {
		t.Error("verified=true not propagated")
	}
	if v, _ := out["slsaLevel"].(int); v != 3 {
		t.Errorf("slsaLevel = %v, want 3", out["slsaLevel"])
	}
}

func TestVerifyJSONIncludesError(t *testing.T) {
	r := provenance.Result{
		Status:    provenance.StatusFailed,
		Ecosystem: "npm",
		Error:     "boom",
	}
	out := verifyJSON("npm", "p", "1", r)
	got, ok := out["error"].(string)
	if !ok || !strings.Contains(got, "boom") {
		t.Errorf("error key missing or wrong: %v", out["error"])
	}
}

func TestVerifyCmdHasRequiredArgs(t *testing.T) {
	// Cobra Args: ExactArgs(3) — too few or too many should fail
	// validation. Smoke check that we registered the right number.
	cmd := verifyCmd
	if cmd.Args == nil {
		t.Fatal("verifyCmd has no Args validator")
	}
	if err := cmd.Args(cmd, []string{}); err == nil {
		t.Error("expected error for zero args")
	}
	if err := cmd.Args(cmd, []string{"npm", "leftpad"}); err == nil {
		t.Error("expected error for two args")
	}
	if err := cmd.Args(cmd, []string{"npm", "leftpad", "1.0.0"}); err != nil {
		t.Errorf("expected success for 3 args, got %v", err)
	}
}

// TestVerifyExitError pins the gate predicate: only a fully-VERIFIED
// chain is exit 0. Everything else — MISSING (the common case; most
// packages publish no attestation), UNVERIFIED, FAILED, UNAVAILABLE — is
// ExitBlocked(1), which is what the command's help has always promised.
//
// Before the fix this contract held only on the human path: runVerify's
// `if asJSON { return PrintJSONTo(...) }` returned BEFORE the status
// switch, so `verify --json` (and any run under a global `--format json`)
// exited 0 on every one of these statuses.
func TestVerifyExitError(t *testing.T) {
	cases := []struct {
		status   provenance.Status
		wantExit int // 0 == nil error
	}{
		{provenance.StatusVerified, 0},
		{provenance.StatusMissing, ExitBlocked},
		{provenance.StatusUnverified, ExitBlocked},
		{provenance.StatusFailed, ExitBlocked},
		{provenance.StatusUnavailable, ExitBlocked},
		{provenance.Status("something-a-future-server-invents"), ExitBlocked},
	}
	for _, c := range cases {
		t.Run(string(c.status), func(t *testing.T) {
			err := verifyExitError(c.status)
			if c.wantExit == 0 {
				if err != nil {
					t.Fatalf("status %q: want nil, got %v", c.status, err)
				}
				return
			}
			var coded *ExitCodeError
			if !errors.As(err, &coded) {
				t.Fatalf("status %q: want *ExitCodeError, got %T (%v)", c.status, err, err)
			}
			if coded.Code != c.wantExit {
				t.Fatalf("status %q: exit code = %d, want %d", c.status, coded.Code, c.wantExit)
			}
		})
	}
}

// TestVerifyJSONNeverWeakensExitCode is the structural regression test:
// the SAME verification result must produce the SAME non-zero exit in
// every rendering. Rendering is a display choice; it is not a verdict.
//
// runVerify itself needs a live Sigstore/registry call, so the test
// drives renderAndGateVerify — literally the tail of runVerify, extracted
// for exactly this reason — across bare / --json / --format json.
func TestVerifyJSONNeverWeakensExitCode(t *testing.T) {
	result := provenance.Result{Status: provenance.StatusMissing, Ecosystem: "npm"}

	for _, mode := range []string{"bare", "--json", "--format json"} {
		t.Run(mode, func(t *testing.T) {
			cmd := &cobra.Command{Use: "verify"}
			cmd.Flags().Bool("json", false, "")
			cmd.Flags().String("format", "table", "")
			cmd.Flags().String("output", "", "")
			switch mode {
			case "--json":
				_ = cmd.Flags().Set("json", "true")
			case "--format json":
				_ = cmd.Flags().Set("format", "json")
			}
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			// PrintJSONTo writes through outWriter (os.Stdout, or the
			// --output file), not cmd's writer, so route the envelope to
			// a temp file via --output. That also exercises the reason
			// the gate must not os.Exit: the file has to be flushed.
			jsonPath := filepath.Join(t.TempDir(), "verify.json")
			if mode != "bare" {
				_ = cmd.Flags().Set("output", jsonPath)
			}

			err := renderAndGateVerify(cmd, "npm", "left-pad", "1.3.0", result)

			var coded *ExitCodeError
			if !errors.As(err, &coded) || coded.Code != ExitBlocked {
				t.Fatalf("%s: MISSING provenance must exit %d regardless of format, got %v", mode, ExitBlocked, err)
			}
			if mode == "bare" {
				return
			}
			body, rerr := os.ReadFile(jsonPath)
			if rerr != nil {
				t.Fatalf("%s: the JSON envelope must still be emitted alongside the failing gate: %v", mode, rerr)
			}
			if !strings.Contains(string(body), `"status": "missing"`) {
				t.Errorf("%s: expected the JSON envelope, got:\n%s", mode, body)
			}
		})
	}
}
