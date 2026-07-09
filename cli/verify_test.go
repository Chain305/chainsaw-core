package cli

import (
	"io"
	"os"
	"strings"
	"testing"

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
