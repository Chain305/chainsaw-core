package cli

// Tests for the strict-mode doctor CI-correctness fixes:
//   - egress "unknown" is a loud, soft-fail (exit 1), never a silent pass,
//     but always loses ties to a genuine drift/reachable/unsupported finding;
//   - --no-egress-probe short-circuits to "skipped" and never trips the
//     soft-fail;
//   - the probe prints a human progress line to stderr in non-JSON mode and
//     is silent under --json;
//   - the ecosystem table stays column-aligned when a Reason is wide.
//
// These exercise buildStrictReport/printStrictReport directly with a
// hand-built cobra command so no live network or server is needed. The
// egress classification is overridden by stubbing the probe seam.

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// strictTestCmd builds a cobra command carrying the flags buildStrictReport
// reads, so flag plumbing matches the production newDoctorCmd surface.
func strictTestCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "doctor"}
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("no-color", true, "")
	cmd.Flags().String("device-id", "test-device", "")
	cmd.Flags().String("bundle-id", "", "")
	cmd.Flags().Bool("no-egress-probe", false, "")
	return cmd
}

// withStubbedEgress swaps probeDirectEgress with a stub that returns a fixed
// classification and records whether it was called. Restores on cleanup.
func withStubbedEgress(t *testing.T, result string) *bool {
	t.Helper()
	called := false
	prev := probeDirectEgressFn
	probeDirectEgressFn = func(_ context.Context, _ io.Writer, _ bool) string {
		called = true
		return result
	}
	t.Cleanup(func() { probeDirectEgressFn = prev })
	return &called
}

// TestApplyEgressExit exercises the real production exit-merge (applyEgressExit)
// directly — hermetic, no manager-drift noise. This is the CI exit contract: a
// non-blocked-but-unconfirmed network (unknown) must soft-fail from a clean run
// but never downgrade a stronger finding; reachable is a hard finding; blocked
// and skipped are passes.
func TestApplyEgressExit(t *testing.T) {
	cases := []struct {
		name   string
		start  int
		egress string
		want   int
	}{
		{"unknown from clean soft-fails", doctorExitOK, "unknown", doctorExitEgressUnknown},
		{"unknown never downgrades drift", doctorExitDrift, "unknown", doctorExitDrift},
		{"unknown never downgrades reachable", doctorExitDirectReachable, "unknown", doctorExitDirectReachable},
		{"unknown never downgrades unsupported", doctorExitUnsupported, "unknown", doctorExitUnsupported},
		{"reachable from clean is a hard finding", doctorExitOK, "reachable", doctorExitDirectReachable},
		{"reachable upgrades drift", doctorExitDrift, "reachable", doctorExitDirectReachable},
		{"blocked is a pass", doctorExitOK, "blocked", doctorExitOK},
		{"blocked leaves a finding alone", doctorExitDrift, "blocked", doctorExitDrift},
		{"skipped never soft-fails", doctorExitOK, "skipped", doctorExitOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := applyEgressExit(c.start, c.egress); got != c.want {
				t.Fatalf("applyEgressExit(%d, %q) = %d, want %d", c.start, c.egress, got, c.want)
			}
		})
	}
	if applyEgressExit(doctorExitOK, "unknown") == doctorExitOK {
		t.Fatal("egress unknown must NOT exit 0 (CI would read a non-blocked network as a pass)")
	}
}

// TestStrict_NoEgressProbe_SkipsProbe proves the air-gap fix at the report
// level: the --no-egress-probe flag short-circuits the probe (it is never
// called) and the egress field reads the distinct "skipped" sentinel. The exit
// code is asserted via applyEgressExit (above) to keep this test independent of
// the host's real manager-drift state.
func TestStrict_NoEgressProbe_SkipsProbe(t *testing.T) {
	withHookEnv(t)
	called := withStubbedEgress(t, "unknown") // would soft-fail if it ran

	cmd := strictTestCmd(t)
	if err := cmd.Flags().Set("no-egress-probe", "true"); err != nil {
		t.Fatalf("set --no-egress-probe: %v", err)
	}
	report, _ := buildStrictReport(context.Background(), cmd)
	if *called {
		t.Fatalf("probeDirectEgress must not run when --no-egress-probe is set")
	}
	if report.DirectRegistryEgress != "skipped" {
		t.Fatalf("egress = %q, want skipped", report.DirectRegistryEgress)
	}
}

// TestStrict_ProbeProgress_PrintedNonJSON asserts the progress line is on
// stderr in non-JSON mode. We run the real probe through the seam to cover
// the Fprintf path; classification is irrelevant here.
func TestStrict_ProbeProgress_PrintedNonJSON(t *testing.T) {
	var stderr bytes.Buffer
	// Call the real implementation directly: quiet=false should print.
	probeDirectEgressImpl(context.Background(), &stderr, false)
	if !strings.Contains(stderr.String(), "probing direct egress to 3 registries") {
		t.Fatalf("expected progress line on stderr, got %q", stderr.String())
	}
}

// TestStrict_ProbeProgress_SilentUnderJSON asserts no progress line is
// emitted when quiet=true (the --json path).
func TestStrict_ProbeProgress_SilentUnderJSON(t *testing.T) {
	var stderr bytes.Buffer
	probeDirectEgressImpl(context.Background(), &stderr, true)
	if strings.Contains(stderr.String(), "probing direct egress") {
		t.Fatalf("progress line must be suppressed under --json; got %q", stderr.String())
	}
}

// TestStrict_EcosystemTable_AlignsWithWideReason guards Finding 4: a Reason
// longer than the old fixed 15/12 pads must not break column alignment. With
// tabwriter, every row's STATUS column starts at the same offset as the
// header's.
func TestStrict_EcosystemTable_AlignsWithWideReason(t *testing.T) {
	r := doctorStrictReport{
		DeviceID:        "d",
		User:            "u",
		Platform:        "p",
		ChainsawVersion: "v",
		Ecosystems: map[string]ecosystemState{
			"npm": {Status: "compliant", Reason: ""},
			"a-very-long-ecosystem-name": {
				Status: "drifted",
				Reason: "project-scope override detected at /a/very/long/path/.npmrc that exceeds fixed pad",
			},
		},
		DirectRegistryEgress: "blocked",
	}
	cmd := strictTestCmd(t)
	var out bytes.Buffer
	cmd.SetOut(&out)
	printStrictReport(cmd, r, doctorExitOK)

	text := out.String()
	statusCol := columnStart(text, "STATUS")
	if statusCol < 0 {
		t.Fatalf("no STATUS header found in:\n%s", text)
	}
	// Each ecosystem row's status token must start at the same column as the
	// STATUS header. tabwriter guarantees this; the old fixed-pad did not.
	for _, line := range tableRows(text) {
		got := tokenStart(line, 1)
		if got != statusCol {
			t.Fatalf("status column misaligned: header at %d, row %q token at %d\nfull:\n%s",
				statusCol, line, got, text)
		}
	}
}

// columnStart returns the rune index where header word first appears on its
// line, or -1.
func columnStart(text, header string) int {
	for _, line := range strings.Split(text, "\n") {
		if idx := strings.Index(line, header); idx >= 0 && strings.HasPrefix(strings.TrimSpace(line), "ECOSYSTEM") {
			return idx
		}
	}
	return -1
}

// tableRows returns the data rows of the ecosystem table (between the header
// and the blank line that precedes the egress summary).
func tableRows(text string) []string {
	var rows []string
	inTable := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "ECOSYSTEM") {
			inTable = true
			continue
		}
		if inTable {
			if strings.TrimSpace(line) == "" {
				break
			}
			rows = append(rows, line)
		}
	}
	return rows
}

// tokenStart returns the column index of the n-th whitespace-delimited token
// (0-based n), or -1 if there are fewer tokens.
func tokenStart(line string, n int) int {
	idx := 0
	tokens := 0
	for idx < len(line) {
		// skip leading whitespace
		for idx < len(line) && (line[idx] == ' ' || line[idx] == '\t') {
			idx++
		}
		if idx >= len(line) {
			return -1
		}
		if tokens == n {
			return idx
		}
		// skip the token
		for idx < len(line) && line[idx] != ' ' && line[idx] != '\t' {
			idx++
		}
		tokens++
	}
	return -1
}
