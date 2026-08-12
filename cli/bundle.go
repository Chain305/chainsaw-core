package cli

// bundle.go — `chainsaw bundle …` subcommands for the air-gap
// intelligence bundle (W4). Two operator-facing verbs:
//
//	chainsaw bundle verify <path>
//	    Reads the manifest, validates per-file content hashes, and
//	    runs the Sigstore signature check. Prints a human-readable
//	    summary plus exit codes:
//	      0 verified, fresh
//	      1 verified but stale (warn-only)
//	      2 verification failure, an unverified bundle without
//	        --allow-unverified, or a load error
//
//	chainsaw bundle apply <path>
//	    HIDDEN / UNAVAILABLE. It posted to /api/admin/intel-bundle/apply,
//	    a route that has never existed, so every invocation ended at a
//	    404 telling the operator to go debug their proxy. The SIGHUP
//	    fallback this header used to describe was never implemented
//	    either. It is not being wired up: the request body names a
//	    SERVER-LOCAL filesystem path chosen by a REMOTE CLIENT and feeds
//	    it to the bundle loader — path traversal and
//	    arbitrary-file-read-as-tarball on an authenticated admin
//	    endpoint, in exchange for skipping one proxy restart during an
//	    air-gap refresh the operator is already on the box for. Set
//	    CHAINSAW_INTEL_BUNDLE_PATH and restart instead.
//
// The manifest schema lives in internal/intelligence/bundle.go alongside
// the proxy-side loader; the signed-artefact pipeline is wired via the
// chainsaw-bundle CLI (cmd/chainsaw-bundle/main.go).

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/intelligence"
)

func init() {
	rootCmd.AddCommand(newBundleCmd())
}

func newBundleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "bundle",
		GroupID: GrpConfig,
		Short:   "Manage the offline intelligence bundle",
		Long: `Manage the air-gapped intelligence bundle that powers offline policy
evaluation (CHAINSAW_OFFLINE=1). The bundle is a signed tarball
shipped alongside the chainsaw-proxy release; see
docs/install/AIRGAP.md for the refresh cadence and per-provider matrix.`,
	}
	cmd.AddCommand(newBundleVerifyCmd())
	cmd.AddCommand(newBundleApplyCmd())
	return cmd
}

// bundleVerificationStatus renders the operator-facing one-liner for a
// loaded bundle's verification posture, mirroring the two layers in
// intelligence.verifyBundleSignature: skipped, digest-bound integrity only,
// or full Sigstore authenticity. Kept pure (no *Bundle) for testability.
func bundleVerificationStatus(verified, authenticated bool) (symbol, text string) {
	switch {
	case !verified:
		return "⚠", "skipped — signature not checked (CHAINSAW_INTEL_BUNDLE_SKIP_VERIFY=1)"
	case authenticated:
		return "✓", "authenticated — full Sigstore: Fulcio cert chain + Rekor inclusion + OIDC issuer + signer identity"
	default:
		return "✓", "integrity only — digest-bound; authenticity not checked (run with --strict or set CHAINSAW_INTEL_BUNDLE_STRICT_VERIFY=1)"
	}
}

func newBundleVerifyCmd() *cobra.Command {
	var strict bool
	var allowUnverified bool
	cmd := &cobra.Command{
		Use:   "verify <path>",
		Short: "Verify a bundle's manifest, hashes, and signature",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			// --strict (or CHAINSAW_INTEL_BUNDLE_STRICT_VERIFY=1, read inside
			// LoadBundle) opts into full Sigstore authenticity on top of the
			// always-on digest binding. Off by default — today's digest-only
			// bundles fail --strict by design until the signer-bot cutover.
			b, err := intelligence.LoadBundle(ctx, args[0], intelligence.BundleVerifyOptions{RequireAuthenticity: strict})
			if err != nil {
				// BUG-CLI-3: cobra's root error renderer prints `Error: <err>`
				// automatically (SilenceErrors=true on rootCmd flips through to
				// our renderError). Printing here too produced the bundle path
				// twice on the same screen. Let the renderer own the output.
				return fmt.Errorf("verify failed: %w", err)
			}
			out := cmd.OutOrStdout()
			m := b.Manifest()
			fmt.Fprintf(out, "Bundle:    %s\n", b.Path())
			fmt.Fprintf(out, "Schema:    %s\n", m.Schema)
			fmt.Fprintf(out, "Version:   %s\n", m.Version)
			fmt.Fprintf(out, "Digest:    sha256:%s\n", b.Digest())
			// A zero BuildTime has no honest age to report; printing
			// "0001-01-01T00:00:00Z (0s ago)" reads as brand new, which
			// is the misreading the Stale() fix exists to prevent.
			if m.BuildTime.IsZero() {
				fmt.Fprintln(out, "Built:     unknown — manifest carries no build_time")
			} else {
				fmt.Fprintf(out, "Built:     %s (%s ago)\n", m.BuildTime.Format(time.RFC3339), b.Age().Round(time.Hour))
			}
			sym, txt := bundleVerificationStatus(b.Verified(), b.Authenticated())
			fmt.Fprintf(out, "Signature: %s %s\n", sym, txt)
			// The verb whose entire job is verification must not report
			// success when verification did not run.
			// CHAINSAW_INTEL_BUNDLE_SKIP_VERIFY stays exactly as it is —
			// it is a documented, supported dev escape hatch
			// (docs/CONFIG_REFERENCE.md) and removing it would break local
			// builds and tests. What changes is only the exit code: a
			// CI job or runbook that inherits the env var (or a
			// compromised environment that sets it) used to get exit 0 on
			// an unsigned bundle. Saying so out loud requires an explicit
			// --allow-unverified from the operator.
			if !b.Verified() && !allowUnverified {
				return &ExitCodeError{
					Code: ExitOpError,
					Err: fmt.Errorf("signature verification did not run (%s is set) — this bundle is UNVERIFIED; pass --allow-unverified to accept it anyway",
						intelligence.BundleSkipVerifyEnvVar),
				}
			}
			if b.Stale() {
				fmt.Fprintf(out, "Freshness: ⚠ stale — bundle older than %s (or the manifest has no build_time); refresh recommended\n", intelligence.BundleStaleAfter)
				// Exit 1, not 2 — the file header has always documented
				// stale as warn-only and distinct from a verification
				// failure, but the plain fmt.Errorf here mapped to
				// ExitOpError(2), the SAME code a signature failure
				// produces. A CI gate could not tell "refresh due" from
				// "this bundle is not what it claims to be", and the
				// documented code 1 was unreachable.
				return &ExitCodeError{Code: ExitBlocked, Err: fmt.Errorf("stale bundle")}
			}
			fmt.Fprintln(out, "Freshness: ✓ fresh")
			fmt.Fprintln(out, "Contents:")
			for _, k := range b.ContentKeys() {
				fmt.Fprintf(out, "  - %s\n", k)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&strict, "strict", false,
		"Require full Sigstore authenticity (Fulcio cert chain + Rekor inclusion + OIDC issuer + signer identity), not just digest binding. Equivalent to CHAINSAW_INTEL_BUNDLE_STRICT_VERIFY=1. Off by default until the chainsaw-release-signer bot cutover; today's digest-only bundles fail --strict by design.")
	cmd.Flags().BoolVar(&allowUnverified, "allow-unverified", false,
		"Exit 0 even when signature verification was skipped via CHAINSAW_INTEL_BUNDLE_SKIP_VERIFY. Dev/test only — it makes `verify` report success on a bundle nothing checked.")
	return cmd
}

// errBundleApplyUnavailable is the single message `bundle apply` gives.
// Kept as a package-level var so the test pins the operator-facing text
// (the whole point of this subcommand now is to hand back a next step
// instead of a 404 that sends them to debug their proxy).
var errBundleApplyUnavailable = fmt.Errorf(
	"`chainsaw bundle apply` is not available: the hot-swap admin endpoint was never built, "+
		"and it is not going to be — it would have to read a server-local path chosen by a remote client.\n"+
		"To load a new bundle: verify it (`chainsaw bundle verify <path>`), place it on the proxy host, "+
		"set %s=<path>, and restart the proxy. Providers pick the new data up on their next refresh tick.",
	intelligence.BundleEnvVar)

func newBundleApplyCmd() *cobra.Command {
	var server string
	var strict bool
	cmd := &cobra.Command{
		Use:   "apply <path>",
		Short: "Unavailable — set CHAINSAW_INTEL_BUNDLE_PATH and restart the proxy",
		Long: `Not available. This subcommand POSTed to /api/admin/intel-bundle/apply,
a route that has never existed in any server build, so every invocation
ended at a 404 telling the operator to check their proxy wiring.

It is not being implemented. The request body names a path on the SERVER's
filesystem chosen by a REMOTE client and hands it to the bundle loader —
path traversal and arbitrary-file-read-as-tarball on an authenticated
admin endpoint — to save one proxy restart during an air-gap refresh the
operator is already logged into the box to perform.

Do this instead:

  chainsaw bundle verify /path/to/intel.tar.gz
  # copy it to the proxy host, then
  CHAINSAW_INTEL_BUNDLE_PATH=/path/to/intel.tar.gz  # and restart the proxy`,
		// Hidden so it stops appearing in help as a working verb. The
		// command itself stays registered: an operator following the old
		// AIRGAP.md runbook (or a script) gets the actionable message
		// above rather than "unknown command".
		Hidden: true,
		Args:   cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errBundleApplyUnavailable
		},
	}
	// Flags kept so an existing invocation fails on the SUBCOMMAND with
	// the explanation above, not on flag parsing with "unknown flag".
	cmd.Flags().StringVar(&server, "server", "", "No longer used.")
	cmd.Flags().BoolVar(&strict, "strict", false, "No longer used.")
	_ = cmd.Flags().MarkHidden("server")
	_ = cmd.Flags().MarkHidden("strict")
	return cmd
}
