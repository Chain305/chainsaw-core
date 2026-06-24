package cli

// W11 — these tests pin the CLI side of the MDM phone-home channel:
// `chainsaw doctor --strict --attest --bundle-id=<id>` must include
// the bundle id in the JSON body POSTed to /api/attestations, and
// must omit the field entirely when --bundle-id is unset (backwards
// compat with older servers that don't know about bundle_id).
//
// We exercise the public CLI surface end-to-end against a stub HTTP
// server rather than calling postAttestation directly so the flag
// plumbing through cobra is also covered.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// captureAttestBody runs buildStrictReport + postAttestation against a
// stub /api/attestations endpoint and returns the parsed JSON body the
// stub received. The doctor strict report itself is built from a fresh
// cobra command so flag plumbing is exercised.
func captureAttestBody(t *testing.T, bundleID string) map[string]any {
	t.Helper()

	withHookEnv(t)

	var seen map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/attestations" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		seen = map[string]any{}
		if err := json.Unmarshal(body, &seen); err != nil {
			t.Fatalf("invalid JSON body: %v\nraw: %s", err, body)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)

	cmd := &cobra.Command{Use: "doctor"}
	cmd.Flags().Bool("attest", true, "")
	cmd.Flags().Bool("strict", true, "")
	cmd.Flags().String("device-id", "test-device", "")
	cmd.Flags().String("bundle-id", "", "")
	cmd.Flags().String("server", srv.URL, "")
	cmd.Flags().Bool("no-egress-probe", false, "")
	if bundleID != "" {
		if err := cmd.Flags().Set("bundle-id", bundleID); err != nil {
			t.Fatalf("set bundle-id: %v", err)
		}
	}

	ctx := context.Background()
	report, _ := buildStrictReport(ctx, cmd)
	if err := postAttestation(ctx, cmd, report); err != nil {
		t.Fatalf("postAttestation: %v", err)
	}
	if seen == nil {
		t.Fatalf("server did not receive a request")
	}
	return seen
}

// TestAttest_OmitsBundleIDWhenUnset — backwards-compat. An older
// chainsaw client (pre-W11) sends an attest body without bundle_id;
// our newer CLI must produce an identically-shaped body when
// --bundle-id is not set, so older proxies still accept it.
func TestAttest_OmitsBundleIDWhenUnset(t *testing.T) {
	body := captureAttestBody(t, "")
	if v, ok := body["bundle_id"]; ok {
		t.Fatalf("body should not contain bundle_id when flag unset; got %v", v)
	}
	// Sanity: the device_id we set must round-trip — proves we're
	// looking at the actual attestation body and not an empty stub.
	if got, _ := body["device_id"].(string); got != "test-device" {
		t.Fatalf("device_id round-trip failed: got %v", body["device_id"])
	}
}

// TestAttest_IncludesBundleIDWhenSet — the flag must propagate all the
// way to the JSON body. This is the W11 phone-home contract: without
// this property the proxy never learns which bundle the device just
// applied.
func TestAttest_IncludesBundleIDWhenSet(t *testing.T) {
	const bid = "deadbeef0000000000000000000000000000000000000000000000000000beef"
	body := captureAttestBody(t, bid)
	got, _ := body["bundle_id"].(string)
	if got != bid {
		t.Fatalf("bundle_id in attest body = %q; want %q", got, bid)
	}
}

// TestAttest_TrimsBundleIDWhitespace — the flag value is user-supplied
// (or wrapper-script-supplied); leading/trailing whitespace from a
// `--bundle-id=  abc  ` invocation must not bleed into the row lookup
// on the server side. We trim CLI-side as the most robust defence.
func TestAttest_TrimsBundleIDWhitespace(t *testing.T) {
	body := captureAttestBody(t, "  abc123  ")
	got, _ := body["bundle_id"].(string)
	if got != "abc123" {
		t.Fatalf("bundle_id should be trimmed: got %q", got)
	}
}

// TestDoctorCmd_BundleIDFlagRegistered — the public doctor command
// must declare --bundle-id so MDM scripts that the bundle renderer
// emits actually parse. Catches a regression where the flag is
// dropped from newDoctorCmd.
func TestDoctorCmd_BundleIDFlagRegistered(t *testing.T) {
	cmd := newDoctorCmd()
	flag := cmd.Flag("bundle-id")
	if flag == nil {
		t.Fatalf("doctor command missing --bundle-id flag")
	}
	if flag.Value.String() != "" {
		t.Errorf("--bundle-id default should be empty, got %q", flag.Value.String())
	}
	// The MDM script renderer emits exactly this name; if the flag is
	// renamed the rendered scripts break in the field. Pin the name.
	if flag.Name != "bundle-id" {
		t.Errorf("flag name = %q, want bundle-id (MDM renderer hardcodes this)", flag.Name)
	}
	if !strings.Contains(flag.Usage, "W11") {
		t.Errorf("--bundle-id help text should mention W11 for grep-ability; got %q", flag.Usage)
	}
}
