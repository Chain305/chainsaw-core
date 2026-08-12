package cli

// `chainsaw guard status` — the read-only conversion surface (D-NUDGE) for the
// free local install guard. It reflects the local funnel counters and privacy
// state back at the user, then points at the de-anonymizing conversion event
// (signup) or, once signed in, the dashboard. No network, no telemetry emit —
// just a clean snapshot plus a single CTA.

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// telemetryConsentLabel renders the guard's telemetry consent for `status`.
// An explicit env kill switch is shown as the authoritative state.
func telemetryConsentLabel(st *guardState) string {
	if envTruthy(os.Getenv("CHAINSAW_TELEMETRY_DISABLED")) || envTruthy(os.Getenv("CHAINSAW_OFFLINE")) {
		return "off (disabled by env)"
	}
	switch st.Consent {
	case consentGranted:
		return "on"
	case consentDeclined:
		return "off"
	default:
		return "not asked yet (off until you opt in)"
	}
}

var guardStatusCmd = &cobra.Command{
	Use:          "status",
	Short:        "Show local guard activity, privacy state, and account sync status",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runGuardStatus,
}

func init() {
	guardCmd.AddCommand(guardStatusCmd)
}

func runGuardStatus(cmd *cobra.Command, _ []string) error {
	st := loadGuardState()

	// X8: `guard status --json` printed the human table. This is the
	// documented local-guard status surface — `telemetry status` right next
	// to it already emitted parseable JSON — so a script reading guard
	// activity got "Install guard — activity on this machine" at rc=0.
	//
	// NOTE ON THE SIBLING EXEMPTION: `guard init --json` deliberately still
	// emits SHELL TEXT, not JSON. Its output is meant to be consumed by
	// `eval "$(chainsaw guard init)"`; emitting JSON there would break the
	// documented invocation. That is a correct exemption, not an oversight.
	if useJSON(cmd) {
		return PrintJSONTo(cmd, map[string]any{
			"installs_checked":  st.InstallsChecked,
			"packages_scanned":  st.PackagesScanned,
			"blocks":            st.Blocks,
			"activated":         st.Activated,
			"first_block_unix":  st.FirstBlockAtUnix,
			"first_run_unix":    st.FirstRunUnix,
			"telemetry_consent": st.Consent,
			"telemetry_label":   telemetryConsentLabel(st),
			"device_id":         cliInstallID(),
			"signed_in":         cfgToken() != "",
		})
	}

	firstRun := "never"
	if st.FirstRunUnix != 0 {
		firstRun = time.Unix(st.FirstRunUnix, 0).Format("2006-01-02")
	}

	// "Activated" is the first-block milestone (set once, persisted). Show the
	// date when it happened, "no" while the guard hasn't blocked anything yet.
	activated := "no"
	if st.Activated {
		if st.FirstBlockAtUnix != 0 {
			activated = "yes (" + time.Unix(st.FirstBlockAtUnix, 0).Format("2006-01-02") + ")"
		} else {
			activated = "yes"
		}
	}

	out := cmd.OutOrStdout()

	fmt.Fprintln(out, "Install guard — activity on this machine")
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "  Installs checked\t%d\n", st.InstallsChecked)
	fmt.Fprintf(tw, "  Packages scanned\t%d\n", st.PackagesScanned)
	fmt.Fprintf(tw, "  Blocks\t%d\n", st.Blocks)
	fmt.Fprintf(tw, "  Activated\t%s\n", activated)
	fmt.Fprintf(tw, "  First run\t%s\n", firstRun)
	_ = tw.Flush()

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Privacy")
	pw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintf(pw, "  Telemetry\t%s\n", telemetryConsentLabel(st))
	fmt.Fprintf(pw, "  Device id\t%s\n", cliInstallID())
	_ = pw.Flush()
	fmt.Fprintln(out, "  Change with: chainsaw telemetry on | off")

	fmt.Fprintln(out)
	if cfgToken() == "" {
		fmt.Fprintln(out, "Not signed in. Sign up free to sync these across your team and see org-wide threats → "+guardCTA(guardNudgeBaseSignup, st.Consent))
	} else {
		fmt.Fprintln(out, "Signed in — your guard activity syncs to your account. See the dashboard → https://chain305.com/chainsaw/overview")
	}

	return nil
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
