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
//	      2 verification or freshness failure
//
//	chainsaw bundle apply <path>
//	    POSTs the bundle path to the running proxy's admin endpoint so
//	    providers swap to the new data without a restart. Falls back to
//	    a SIGHUP-style nudge (signal-based reload) when the admin
//	    endpoint is unreachable but the proxy is co-located on the same
//	    host. Hot-swap is best-effort: providers re-read the bundle on
//	    their next EnsureFresh tick (kev: ~24h) so the worst-case time
//	    to convergence is one refresh interval.
//
// The manifest schema lives in internal/intelligence/bundle.go alongside
// the proxy-side loader; the signed-artefact pipeline is wired via the
// chainsaw-bundle CLI (cmd/chainsaw-bundle/main.go).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/httpclient"
	"github.com/chain305/chainsaw-core/intelligence"
)

func init() {
	rootCmd.AddCommand(newBundleCmd())
}

func newBundleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Manage the offline intelligence bundle",
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
			fmt.Fprintf(out, "Built:     %s (%s ago)\n", m.BuildTime.Format(time.RFC3339), b.Age().Round(time.Hour))
			sym, txt := bundleVerificationStatus(b.Verified(), b.Authenticated())
			fmt.Fprintf(out, "Signature: %s %s\n", sym, txt)
			if b.Stale() {
				fmt.Fprintf(out, "Freshness: ⚠ stale — bundle older than %s; refresh recommended\n", intelligence.BundleStaleAfter)
				return fmt.Errorf("stale bundle")
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
	return cmd
}

func newBundleApplyCmd() *cobra.Command {
	var server string
	var strict bool
	cmd := &cobra.Command{
		Use:   "apply <path>",
		Short: "Hot-swap the running proxy's intel bundle (no restart)",
		Long: `Tells the running chainsaw-proxy to load the bundle at <path> as the
new offline intelligence source. Providers reflect the new data within
one refresh interval (kev/CVE: ~24h). Use 'chainsaw bundle verify'
first to confirm the bundle is signed and fresh before applying.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			path := args[0]
			// 1. Verify locally before pushing — fail fast on a bad
			//    bundle so the operator doesn't poison the proxy.
			b, err := intelligence.LoadBundle(ctx, path, intelligence.BundleVerifyOptions{RequireAuthenticity: strict})
			if err != nil {
				return fmt.Errorf("local verify failed: %w (refusing to apply)", err)
			}
			sym, txt := bundleVerificationStatus(b.Verified(), b.Authenticated())
			fmt.Fprintf(cmd.OutOrStdout(), "verified bundle %s (digest sha256:%s) — %s %s\n", b.Manifest().Version, b.Digest(), sym, txt)

			if server == "" {
				server = cfgServerURL()
			}
			if server == "" {
				return fmt.Errorf("--server is required (or set via `chainsaw setup`)")
			}
			body, _ := json.Marshal(map[string]string{
				"bundle_path": path,
				"digest":      b.Digest(),
			})
			endpoint, err := url.Parse(strings.TrimRight(server, "/") + "/api/admin/intel-bundle/apply")
			if err != nil {
				return fmt.Errorf("parse server URL: %w", err)
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(string(body)))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")
			if tok := cfgToken(); tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			resp, err := httpclient.New().Do(req)
			if err != nil {
				return fmt.Errorf("post to proxy: %w", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 300 {
				return fmt.Errorf("proxy returned %s — confirm the proxy is running and the admin endpoint is wired (see docs/install/AIRGAP.md)", resp.Status)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "✓ proxy accepted bundle; providers will refresh on their next tick")
			return nil
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "Override the chainsaw-proxy admin URL (default: configured server).")
	cmd.Flags().BoolVar(&strict, "strict", false,
		"Require full Sigstore authenticity for the local pre-apply verify (not just digest binding). Equivalent to CHAINSAW_INTEL_BUNDLE_STRICT_VERIFY=1. Off by default until the signer-bot cutover.")
	return cmd
}
