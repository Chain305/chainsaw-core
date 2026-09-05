package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// TestGuardStatusEmptyState runs `guard status` against a fresh config dir
// (no guard_state.json) and asserts it succeeds and prints the expected
// sections plus a conversion CTA.
func TestGuardStatusEmptyState(t *testing.T) {
	// CHAINSAW_CONFIG_HOME is honored on every OS; XDG_CONFIG_HOME is Linux-only
	// (platform.ConfigHome), so use the former to keep this hermetic on macOS too.
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := runGuardStatus(cmd, nil); err != nil {
		t.Fatalf("runGuardStatus returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"Install guard",
		"Installs checked",
		"First run",
		"never", // FirstRunUnix == 0 on empty state
		"Privacy",
		"Telemetry",
		// One id, one name: `telemetry status` prints the same value under
		// install_id, so this used to read "Device id" and made the two
		// commands look like they were reporting different identifiers.
		"Install id",
		"chain305.com", // a CTA link is always present
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

func TestOnOff(t *testing.T) {
	if onOff(true) != "on" {
		t.Errorf("onOff(true) = %q, want on", onOff(true))
	}
	if onOff(false) != "off" {
		t.Errorf("onOff(false) = %q, want off", onOff(false))
	}
}

// writeGuardStateForTest points the config dir at a temp dir and persists st
// there, so runGuardStatus reads exactly this state.
func writeGuardStateForTest(t *testing.T, st *guardState) {
	t.Helper()
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())
	saveGuardState(st)
}

// runGuardStatusText runs the text renderer and returns stdout.
func runGuardStatusText(t *testing.T) string {
	t.Helper()
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := runGuardStatus(cmd, nil); err != nil {
		t.Fatalf("runGuardStatus returned error: %v", err)
	}
	return buf.String()
}

// guardStatusRow returns the value cell of the tabwriter row whose label is
// `label` (e.g. "First block"), or "" when the row is absent.
func guardStatusRow(out, label string) string {
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, label+" ") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, label))
		}
	}
	return ""
}

// B5 (BUG-F-006): the first-block milestone was rendered as an "Activated"
// row, which a fresh install read as "the guard is not activated". The row is
// now "First block" with three renders: none yet / <date> / yes (date not
// recorded) for legacy state files that set Activated before FirstBlockAtUnix
// existed.
func TestGuardStatusFirstBlock_NoneYet(t *testing.T) {
	writeGuardStateForTest(t, &guardState{InstallsChecked: 3})
	out := runGuardStatusText(t)
	if got := guardStatusRow(out, "First block"); got != "none yet" {
		t.Fatalf("First block row = %q, want %q\n--- output ---\n%s", got, "none yet", out)
	}
}

func TestGuardStatusFirstBlock_Date(t *testing.T) {
	const ts = int64(1773576000) // 2026-03-15T12:00:00Z; date formatted in local time below
	writeGuardStateForTest(t, &guardState{Blocks: 1, Activated: true, FirstBlockAtUnix: ts})
	out := runGuardStatusText(t)
	want := time.Unix(ts, 0).Format("2006-01-02")
	if got := guardStatusRow(out, "First block"); got != want {
		t.Fatalf("First block row = %q, want %q\n--- output ---\n%s", got, want, out)
	}
	if strings.Contains(out, "yes (") {
		t.Fatalf("a recorded date must render as the bare date, not a yes-prefix\n--- output ---\n%s", out)
	}
}

func TestGuardStatusFirstBlock_LegacyNoDate(t *testing.T) {
	// Legacy state: Activated persisted before FirstBlockAtUnix was stamped.
	writeGuardStateForTest(t, &guardState{Blocks: 1, Activated: true, FirstBlockAtUnix: 0})
	out := runGuardStatusText(t)
	if got := guardStatusRow(out, "First block"); got != "yes (date not recorded)" {
		t.Fatalf("First block row = %q, want %q\n--- output ---\n%s", got, "yes (date not recorded)", out)
	}
}

// TestGuardStatusTextNeverPrintsActivatedOrSyncs covers B5 ("Activated" is a
// funnel-event name, not a user-facing label) and B8 (no claim that guard
// activity "syncs" anywhere — nothing dashboard-visible reads it), in both the
// signed-out and signed-in renders.
func TestGuardStatusTextNeverPrintsActivatedOrSyncs(t *testing.T) {
	for _, signedIn := range []bool{false, true} {
		t.Run(map[bool]string{false: "signed-out", true: "signed-in"}[signedIn], func(t *testing.T) {
			writeGuardStateForTest(t, &guardState{Blocks: 2, Activated: true, FirstBlockAtUnix: 1773576000})
			defer viper.Reset()
			if signedIn {
				viper.Set("token", "tok")
			}
			out := runGuardStatusText(t)
			for _, banned := range []string{"Activated", "syncs", "sync these across your team"} {
				if strings.Contains(out, banned) {
					t.Errorf("text renderer must never print %q\n--- output ---\n%s", banned, out)
				}
			}
		})
	}
}

// TestGuardStatusSignedInCopy pins the signed-in sentence. B8 first made
// it honest — blocks stayed on the machine and the dashboard did not show
// them — and P9F-UD-06 then made the dashboard true, so the sentence moved
// with the behaviour: a consented, signed-in install's blocks ARE recorded
// against the org now, and telemetry-off is the case where they stay local.
// Both halves are pinned so the copy cannot drift back to either the old
// false claim or the interim one. The dashboard link stays.
func TestGuardStatusSignedInCopy(t *testing.T) {
	writeGuardStateForTest(t, &guardState{})
	defer viper.Reset()
	viper.Set("token", "tok")
	out := runGuardStatusText(t)
	for _, want := range []string{
		"Signed in.",
		"With telemetry on, guard blocks from this machine are recorded against your org",
		"appear on the dashboard alongside proxy and CI activity",
		"With telemetry off, blocks stay on this machine",
		hostedGuardDashboardURL,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("signed-in output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, "Not signed in") {
		t.Errorf("signed-in render must not print the signed-out CTA\n--- output ---\n%s", out)
	}
}

// TestGuardStatusSignedOutCopy: the team-sync half of the CTA is gone; the
// org-wide-threats CTA and its signup link remain.
func TestGuardStatusSignedOutCopy(t *testing.T) {
	writeGuardStateForTest(t, &guardState{})
	defer viper.Reset()
	out := runGuardStatusText(t)
	for _, want := range []string{"Not signed in.", "org-wide threats", "chain305.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("signed-out output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, "Signed in") {
		t.Errorf("signed-out render must not print the signed-in line\n--- output ---\n%s", out)
	}
}

// TestGuardStatusShort: B8 renames the Short (it claimed "account sync status").
func TestGuardStatusShort(t *testing.T) {
	if got := guardStatusCmd.Short; got != "Show local guard activity and privacy state" {
		t.Fatalf("guard status Short = %q", got)
	}
	if strings.Contains(strings.ToLower(guardStatusCmd.Short), "sync") {
		t.Fatalf("guard status Short must not claim sync: %q", guardStatusCmd.Short)
	}
}

// TestGuardStatusJSONKeysStable: the B5 label rename is text-only. The JSON
// keys `activated` and `first_block_unix` are the scripted contract and must
// not move with the label.
func TestGuardStatusJSONKeysStable(t *testing.T) {
	const ts = int64(1773576000)
	writeGuardStateForTest(t, &guardState{
		InstallsChecked: 4, PackagesScanned: 9, Blocks: 1,
		Activated: true, FirstBlockAtUnix: ts, FirstRunUnix: ts - 86400,
	})
	defer viper.Reset()

	cmd := &cobra.Command{}
	cmd.Flags().Bool("json", true, "")
	cmd.Flags().String("format", "", "")
	cmd.Flags().String("output", "", "")
	var stderr bytes.Buffer
	cmd.SetOut(&stderr) // JSON goes to the result sink (os.Stdout), not cmd.Out

	raw := captureStdout(t, func() {
		if err := runGuardStatus(cmd, nil); err != nil {
			t.Errorf("runGuardStatus returned error: %v", err)
		}
	})
	var got map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("--json output is not JSON: %v\n--- output ---\n%s", err, raw)
	}
	for _, key := range []string{
		"installs_checked", "packages_scanned", "blocks", "activated",
		"first_block_unix", "first_run_unix", "telemetry_consent",
		"telemetry_label", "install_id", "signed_in",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("--json output missing key %q\n--- output ---\n%s", key, raw)
		}
	}
	if got["activated"] != true {
		t.Errorf("activated = %v, want true", got["activated"])
	}
	if v, _ := got["first_block_unix"].(float64); int64(v) != ts {
		t.Errorf("first_block_unix = %v, want %d", got["first_block_unix"], ts)
	}
	for _, absent := range []string{"first_block", "First block"} {
		if _, ok := got[absent]; ok {
			t.Errorf("--json output must not grow a %q key from the label rename", absent)
		}
	}
	if stderr.Len() != 0 {
		t.Errorf("--json must not also print the text table; got %q", stderr.String())
	}
}
