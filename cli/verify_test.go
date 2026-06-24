package cli

import (
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/provenance"
)

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
