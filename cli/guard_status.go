package cli

// `chainsaw guard status` — the read-only conversion surface (D-NUDGE) for the
// free local install guard. It reflects the local funnel counters and privacy
// state back at the user, then points at the de-anonymizing conversion event
// (signup) or, once signed in, the dashboard. No network, no telemetry emit —
// just a clean snapshot plus a single CTA.

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/telemetry"
)

// telemetryConsentLabel renders the telemetry state for `guard status` AND
// for `telemetry status`, so the two can never word it differently.
//
// An environment kill switch is the authoritative state and is shown first.
// The check used to hand-roll two env vars (CHAINSAW_TELEMETRY_DISABLED,
// CHAINSAW_OFFLINE), which missed the other two routes to ModeDisabled —
// DO_NOT_TRACK=1 and a self-hosted build without CHAINSAW_TELEMETRY_ENABLED
// both silenced the SDK while this label still said "on". Defer to
// telemetry.ResolveMode so the env list has exactly one definition.
//
// Debug is reported as off because it is: nothing is sent.
//
// L-11/L-12 history, in order, because the wording has now moved twice:
// the label originally claimed "events printed, never sent", which was FALSE
// on a box that had not consented — emitAt returned at the consent gate
// before the debug sink existed, so debug printed nothing at all. Wave A
// therefore deleted the printing half of the claim. L-12 then moved the
// debug branch AHEAD of the consent gate (telemetry_runtime.go), so the
// printing claim is true again, for everyone, and the label says so. If that
// branch is ever moved back behind the consent gate, this string goes back
// to stating only the "nothing is sent" half.
//
// ModeDebug is still checked BEFORE ModeDisabled because ResolveMode returns
// them in that order (core/telemetry/consent.go:68-71) — swapping the arms
// here would mislabel a debug run that also set a kill switch. That ordering
// is load-bearing for a real combination: DO_NOT_TRACK=1 together with
// CHAINSAW_TELEMETRY_DEBUG=1 resolves to ModeDebug, which now prints locally
// (and still sends nothing, and still mints no install_id).
func telemetryConsentLabel(st *guardState) string {
	switch telemetry.ResolveMode() {
	case telemetry.ModeDisabled:
		return "off (disabled by env)"
	case telemetry.ModeDebug:
		return "off (debug mode: events are printed locally, nothing is sent)"
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

// hostedGuardDashboardURL is the dashboard for the hosted SaaS. Used only when
// no server is configured at all, where there is nothing better to point at.
const hostedGuardDashboardURL = "https://chain305.com/chainsaw/overview"

// guardDashboardURL is the "see the dashboard" link shown to a signed-in user.
//
// Y11b: this was hardcoded to the hosted SaaS console, so a self-hoster who had
// just signed in to THEIR server was pointed at someone else's dashboard.
// Derive it from the configured server through the same consoleURL helper the
// mint-URL guidance uses (auth.go), which maps a baked `…/chainproxy` API base
// onto the `…/chainsaw` web console.
func guardDashboardURL() string {
	if base := consoleURL(cfgServerURL()); base != "" {
		return base + "/overview"
	}
	return hostedGuardDashboardURL
}

var guardStatusCmd = &cobra.Command{
	Use:          "status",
	Short:        "Show local guard activity and privacy state",
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
	//
	// RENAME (device_id -> install_id): the id below is the SAME value
	// `telemetry status` prints as install_id — one id, one minting site
	// (telemetry.ProcessInstall), one file (install_id in the config dir).
	// Two names for it made reviewers believe there were two identifiers.
	// `install_id` wins because it matches the on-disk filename, the
	// function, the event property, and the sibling command. It also stops
	// colliding with the UNRELATED `device_id` on the compliance-attestation
	// surface (internal/server/compliance.go), which is a hostname/USER
	// string, not this UUID.
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
			"install_id":        displayInstallID(),
			"signed_in":         cfgToken() != "",
		})
	}

	firstRun := "never"
	if st.FirstRunUnix != 0 {
		firstRun = time.Unix(st.FirstRunUnix, 0).Format("2006-01-02")
	}

	firstBlock := firstBlockLabel(st)

	out := cmd.OutOrStdout()

	fmt.Fprintln(out, "Install guard — activity on this machine")
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "  Installs checked\t%d\n", st.InstallsChecked)
	fmt.Fprintf(tw, "  Packages scanned\t%d\n", st.PackagesScanned)
	fmt.Fprintf(tw, "  Blocks\t%d\n", st.Blocks)
	fmt.Fprintf(tw, "  First block\t%s\n", firstBlock)
	fmt.Fprintf(tw, "  First run\t%s\n", firstRun)
	_ = tw.Flush()

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Privacy")
	pw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintf(pw, "  Telemetry\t%s\n", telemetryConsentLabel(st))
	fmt.Fprintf(pw, "  Install id\t%s\n", displayInstallID())
	_ = pw.Flush()
	fmt.Fprintln(out, "  Change with: chainsaw telemetry on | off")

	fmt.Fprintln(out)
	// B8: what actually leaves the machine. With consent, the guard emits
	// install.guard.block/.activated/.daily_active to /api/telemetry/ingest,
	// which is forwarded to PostHog; nothing in the server or the UI reads
	// those events back, and the /api/scan preflight persists nothing. So
	// "your guard activity syncs to your account" was true only as
	// consent-gated analytics attribution and false as anything a user could
	// open on the dashboard. Say exactly that, and never the word "sync".
	if cfgToken() == "" {
		fmt.Fprintln(out, "Not signed in. Sign up free to see org-wide threats → "+guardCTA(guardNudgeBaseSignup, st.Consent))
	} else {
		fmt.Fprintln(out, "Signed in. With telemetry on, guard blocks from this machine are recorded against your org and appear on the dashboard alongside proxy and CI activity. With telemetry off, blocks stay on this machine and this command is the only record.")
		fmt.Fprintln(out, "See the dashboard → "+guardDashboardURL())
	}

	return nil
}

// firstBlockLabel renders the first-block milestone for the text table.
//
// B5 (BUG-F-006): this row used to be labelled "Activated" and read "no" on a
// fresh install, which a tester took to mean the guard itself was not active.
// Activated is the persisted first-EVER-block milestone (guard_nudge.go) —
// the funnel event install.guard.activated keeps that name (TELEMETRY.md) —
// but the user-facing label is now the fact it records. Three renders:
//
//	none yet                 — nothing blocked on this machine so far
//	<YYYY-MM-DD>             — the milestone with its stamped date
//	yes (date not recorded)  — legacy state files written before
//	                           FirstBlockAtUnix existed (Activated=true, 0 stamp)
//
// The --json keys `activated` / `first_block_unix` are untouched.
func firstBlockLabel(st *guardState) string {
	switch {
	case !st.Activated:
		return "none yet"
	case st.FirstBlockAtUnix != 0:
		return time.Unix(st.FirstBlockAtUnix, 0).Format("2006-01-02")
	default:
		return "yes (date not recorded)"
	}
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
