package cli

// Guards for `chainsaw doctor --bundle-id=<sha256>` (tutorial 10.5,
// docs/REFERENCE.md W11 row). Two defects:
//   - bare --bundle-id resolved to the default manager table, POSTed nothing
//     and exited 0 — the id was silently dropped;
//   - with --attest the CLI discarded the server's response, so the operator
//     never saw whether the bundle was recorded (applied /
//     attestation_seen_at).

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

const testBundleID = "deadbeef0000000000000000000000000000000000000000000000000000beef"

// TestDoctorDispatch_BundleIDImpliesAttest: --bundle-id alone must select the
// strict/attest runner, and conflicting with another mode must name it.
func TestDoctorDispatch_BundleIDImpliesAttest(t *testing.T) {
	cmd := doctorModeCmd(t)
	cmd.Flags().String("bundle-id", "", "")
	if err := cmd.Flags().Set("bundle-id", testBundleID); err != nil {
		t.Fatal(err)
	}
	mode, err := resolveDoctorMode(cmd)
	if err != nil {
		t.Fatalf("resolveDoctorMode: %v", err)
	}
	if !strings.Contains(mode.flags, "--bundle-id") {
		t.Fatalf("--bundle-id alone resolved to %q; it must imply --attest, not fall through to the default table", mode.flags)
	}

	if err := cmd.Flags().Set("offline", "true"); err != nil {
		t.Fatal(err)
	}
	_, err = resolveDoctorMode(cmd)
	var ece *ExitCodeError
	if !errors.As(err, &ece) || ece.Code != ExitUsage || !strings.Contains(err.Error(), "--bundle-id") {
		t.Fatalf("--bundle-id --offline must be a usage error naming --bundle-id; got %v", err)
	}
}

// runBundleDoctor runs the real strict runner with ONLY --bundle-id set
// (attest=false) against a stub server that answers with status/body.
func runBundleDoctor(t *testing.T, status int, body string, jsonOut bool) (stdout, stderr string, sentBundle string) {
	t.Helper()
	withHookEnv(t)
	withStubbedEgress(t, "blocked")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		sentBundle, _ = m["bundle_id"].(string)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	cmd := &cobra.Command{Use: "doctor"}
	cmd.Flags().Bool("json", jsonOut, "")
	cmd.Flags().Bool("no-color", true, "")
	cmd.Flags().String("device-id", "test-device", "")
	cmd.Flags().String("bundle-id", testBundleID, "")
	cmd.Flags().Bool("attest", false, "")
	cmd.Flags().Bool("no-egress-probe", false, "")
	cmd.Flags().String("server", srv.URL, "")
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	_ = runDoctorStrict(cmd, nil) // exit reflects hook-env drift, not the bundle
	if sentBundle != testBundleID {
		t.Fatalf("server never received bundle_id (got %q); --bundle-id alone must POST", sentBundle)
	}
	return out.String(), errOut.String(), sentBundle
}

func TestDoctorBundle_AppliedPrintsServerAnswer(t *testing.T) {
	out, _, _ := runBundleDoctor(t, http.StatusAccepted,
		`{"attestation":{},"applied":true,"attestation_seen_at":"2026-09-26T10:11:12Z"}`, false)
	for _, want := range []string{"hardening bundle " + testBundleID + ": applied", "attestation_seen_at: 2026-09-26T10:11:12Z", "recorded this bundle as applied"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestDoctorBundle_AlreadyAppliedIsRecorded(t *testing.T) {
	out, _, _ := runBundleDoctor(t, http.StatusAccepted,
		`{"attestation":{},"applied":false,"attestation_seen_at":"2026-09-26T10:11:12Z"}`, true)
	var got struct {
		BundleAttestation *bundleAttestResult `json:"bundle_attestation"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("--json output not JSON: %v\n%s", err, out)
	}
	b := got.BundleAttestation
	if b == nil || b.Status != "already_applied" || !b.Recorded || b.AttestationSeenAt == nil {
		t.Fatalf("want already_applied/recorded with timestamp, got %+v", b)
	}
}

func TestDoctorBundle_NotMatchedIsReported(t *testing.T) {
	out, _, _ := runBundleDoctor(t, http.StatusAccepted, `{"attestation":{},"applied":false}`, false)
	if !strings.Contains(out, ": not_matched") || !strings.Contains(out, "NOT recorded") {
		t.Fatalf("an unmatched bundle must be reported as NOT recorded:\n%s", out)
	}
}

func TestDoctorBundle_MissingOutcomeIsUnconfirmed(t *testing.T) {
	out, _, _ := runBundleDoctor(t, http.StatusAccepted, `{"attestation":{}}`, false)
	if !strings.Contains(out, ": unconfirmed") {
		t.Fatalf("a response without `applied` must not read as success or failure:\n%s", out)
	}
}

func TestDoctorBundle_RejectedPOSTReportsReason(t *testing.T) {
	out, stderr, _ := runBundleDoctor(t, http.StatusForbidden, `{"code":"CHW-1234","message":"permission denied"}`, false)
	if !strings.Contains(out, ": failed") || !strings.Contains(out, "permission denied") {
		t.Fatalf("a rejected POST must be reported as failed with the server's reason:\n%s", out)
	}
	if !strings.Contains(stderr, "attestation POST failed") {
		t.Fatalf("stderr should still carry the POST failure: %q", stderr)
	}
}
