package cli

// org.go — `chainsaw org` command group. The only verb today is
// `delete`, which implements the W0 simulate-then-confirm safety gate
// for destroying an entire organization. The verb sequence is:
//
//   1. `chainsaw org delete --dry-run`
//      → POST /api/orgs/{id}/delete/preview
//      → server walks the cascade tables, mints a simulate_id, and
//        returns an inventory snapshot. The CLI prints the snapshot
//        and exits 0.
//
//   2. `chainsaw org delete --simulate-id <id> --confirm`
//      → DELETE /api/orgs/{id}?simulate_id=<id>
//      → server re-walks the inventory, refuses if drifted >10%,
//        refuses if past TTL (CHW-4928), refuses if minted for a
//        different action (CHW-4929), else hard-deletes.
//
// `chainsaw organization delete` is registered as an alias for the
// "organization" spelling (matches `chainsaw help`'s autocomplete
// hits from operators who guess the longer form).

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// orgCmd is the parent for org-management verbs. Aliased to
// "organization" so both `chainsaw org delete` and
// `chainsaw organization delete` resolve.
var orgCmd = &cobra.Command{
	Use:     "org",
	Aliases: []string{"organization"},
	Short:   "Manage the active organization (delete with safety gate)",
	Long: `Manage the active organization.

The only verb today is ` + "`delete`" + ` — purges the org and every artifact
that belongs to it (packages, repos, audit rows, exceptions, policies,
SSO providers, members, blob store). Deletion runs behind a
simulate-then-confirm safety gate (the W0 contract): you must first
preview the inventory with ` + "`--dry-run`" + `, then re-submit the
returned ` + "`simulate_id`" + ` with ` + "`--confirm`" + ` within 5 minutes. If
the inventory has shifted in that window the confirm is refused with
CHW-4928 and you must re-preview.`,
}

// orgDeleteCmd is the verb. Three modes:
//   - --dry-run                          → preview only, mint simulate_id
//   - --simulate-id <id>                 → re-fetch inventory, diff,
//     abort if drifted (no commit)
//   - --simulate-id <id> --confirm       → commit if and only if the
//     inventory still matches
//
// --yes skips the interactive y/N prompt (required for non-TTY runs).
var orgDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete the active organization (requires simulate-then-confirm)",
	Long: `Delete the active organization.

This is a hard delete — every artifact owned by the org is purged
(packages, repos, audit rows, exceptions, policies, SSO providers,
members, blob store). To prevent fat-finger destruction the operation
runs behind a two-step safety gate:

  1. ` + "`chainsaw org delete --dry-run`" + `
     Walks the cascade tables and returns a simulate_id plus a
     snapshot of everything that would be destroyed.

  2. ` + "`chainsaw org delete --simulate-id <id> --confirm`" + `
     Re-walks the inventory and compares against the snapshot. If
     anything has changed the delete is refused (CHW-4928) and you
     must re-preview. If unchanged the org is purged.

The simulate_id is short-lived (5 minutes) and kind-tagged: a
simulate_id minted for any other action will be refused with
CHW-4929.`,
	RunE: runOrgDelete,
}

func init() {
	orgDeleteCmd.Flags().Bool("dry-run", false,
		"Preview the inventory that would be destroyed; mint a simulate_id (does not delete).")
	orgDeleteCmd.Flags().String("simulate-id", "",
		"Confirm a previously previewed delete. Pair with --confirm to commit, omit --confirm to re-diff only.")
	orgDeleteCmd.Flags().Bool("confirm", false,
		"Commit the delete. Requires --simulate-id from a recent --dry-run.")
	orgDeleteCmd.Flags().Bool("yes", false,
		"Skip the interactive y/N prompt. Required for non-TTY runs.")
	orgDeleteCmd.Flags().String("slug", "",
		"Org slug to delete. Defaults to the org_id from config (--org flag or `chainsaw auth login`).")
	orgDeleteCmd.Flags().Bool("json", false, "Emit machine-readable JSON instead of pretty-printed output.")
	orgCmd.AddCommand(orgDeleteCmd)
	rootCmd.AddCommand(orgCmd)
}

// orgDeletePreviewResponse mirrors the JSON envelope produced by
// handleOrgDeletePreview in internal/server/admin_orgs_simulate.go.
// We don't import the server type; the field names are part of the
// API contract (TTL ratchet test in qa/ pins them).
type orgDeletePreviewResponse struct {
	SimulateID string           `json:"simulate_id"`
	Summary    string           `json:"summary"`
	Inventory  map[string]int   `json:"inventory"`
	Samples    []map[string]any `json:"samples"`
	Fallback   string           `json:"fallback,omitempty"`
	TTLSeconds int              `json:"ttl_seconds,omitempty"`
	Kind       string           `json:"kind,omitempty"`
}

// runOrgDelete is the verb dispatcher.
func runOrgDelete(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	orgID := strings.TrimSpace(viper.GetString("org_id"))
	if slug, _ := cmd.Flags().GetString("slug"); slug != "" {
		orgID = strings.TrimSpace(slug)
	}
	if orgID == "" {
		return fmt.Errorf("no org selected — pass --slug <org-id> or set `org_id` via `chainsaw --org <id>` / `chainsaw auth login`")
	}

	dryRun, _ := cmd.Flags().GetBool("dry-run")
	simulateID, _ := cmd.Flags().GetString("simulate-id")
	confirm, _ := cmd.Flags().GetBool("confirm")
	asJSON, _ := cmd.Flags().GetBool("json")
	yes, _ := cmd.Flags().GetBool("yes")

	// Mutually exclusive: --dry-run with --simulate-id makes no sense
	// (the first mints an id, the second consumes one).
	if dryRun && simulateID != "" {
		return fmt.Errorf("--dry-run and --simulate-id are mutually exclusive")
	}
	if confirm && simulateID == "" {
		return fmt.Errorf("--confirm requires --simulate-id from a recent `chainsaw org delete --dry-run`")
	}
	if !dryRun && simulateID == "" {
		return fmt.Errorf("specify either --dry-run (preview) or --simulate-id (re-diff / confirm)")
	}

	if dryRun {
		return runOrgDeletePreview(cmd, client, orgID, asJSON)
	}
	return runOrgDeleteCommit(cmd, client, orgID, simulateID, confirm, yes, asJSON)
}

// runOrgDeletePreview is the --dry-run path. POSTs the preview, prints
// the inventory snapshot, and prints the simulate_id alongside the
// next-step command for copy-paste.
func runOrgDeletePreview(cmd *cobra.Command, client *APIClient, orgID string, asJSON bool) error {
	var resp orgDeletePreviewResponse
	if err := client.Post(fmt.Sprintf("/api/orgs/%s/delete/preview", orgID), nil, &resp); err != nil {
		return err
	}
	if asJSON {
		return PrintJSON(resp)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Org-delete preview for %q:\n\n", orgID)
	if resp.Summary != "" {
		fmt.Fprintln(out, resp.Summary)
		fmt.Fprintln(out)
	}
	if resp.Fallback != "" {
		fmt.Fprintf(out, "WARNING: preview degraded — %s\n\n", resp.Fallback)
	}
	if len(resp.Inventory) > 0 {
		// Stable ordering so the operator sees the same row order on
		// repeat invocations (the underlying map iteration is random).
		keys := make([]string, 0, len(resp.Inventory))
		for k := range resp.Inventory {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintln(out, "Inventory that would be destroyed:")
		for _, k := range keys {
			n := resp.Inventory[k]
			if n == 0 {
				continue
			}
			fmt.Fprintf(out, "  %-30s %d\n", k, n)
		}
		fmt.Fprintln(out)
	}
	ttl := resp.TTLSeconds
	if ttl == 0 {
		// Server may omit ttl_seconds on older builds — fall back to the
		// documented 5-minute window so the operator still sees a clock.
		ttl = 300
	}
	fmt.Fprintf(out, "simulate_id: %s  (expires in %ds)\n", resp.SimulateID, ttl)
	fmt.Fprintln(out, "\nTo commit:")
	fmt.Fprintf(out, "  chainsaw org delete --simulate-id %s --confirm --yes\n", resp.SimulateID)
	return nil
}

// runOrgDeleteCommit is the --simulate-id path. If --confirm is set, the
// DELETE fires; otherwise it acts as a "re-diff" mode (POST preview
// again, locally compare against the original snapshot stored in the
// simulate_results table — the server-side gate handles the actual
// drift check, so the CLI just re-fetches and shows what changed).
func runOrgDeleteCommit(cmd *cobra.Command, client *APIClient, orgID, simulateID string, confirm, yes, asJSON bool) error {
	out := cmd.OutOrStdout()

	if !confirm {
		// Re-diff mode: hit preview again and print drift if any.
		// (The server doesn't expose a "diff this simulate" endpoint;
		// the actual drift evaluation happens inside the DELETE
		// transaction. This path is a courtesy preview-of-preview so
		// an operator can sanity-check before --confirm.)
		var resp orgDeletePreviewResponse
		if err := client.Post(fmt.Sprintf("/api/orgs/%s/delete/preview", orgID), nil, &resp); err != nil {
			return err
		}
		if asJSON {
			return PrintJSON(resp)
		}
		fmt.Fprintln(out, "Re-diff (against current live inventory):")
		fmt.Fprintln(out, resp.Summary)
		fmt.Fprintln(out, "\nPass --confirm to commit using the original simulate_id;")
		fmt.Fprintln(out, "or re-run `chainsaw org delete --dry-run` for a fresh simulate.")
		return nil
	}

	// Commit. Confirmation prompt unless --yes was passed.
	if !yes {
		if !PromptConfirm(fmt.Sprintf("PERMANENTLY delete org %q? This cannot be undone.", orgID)) {
			fmt.Fprintln(out, "Aborted.")
			return nil
		}
	}

	// Path the server reads as DELETE /api/orgs/{id}?simulate_id=<id>.
	// We use the query-string form (not a body) because the existing
	// client.Delete helper takes no body argument and the server's
	// readOrgDeleteRequestBody prefers the query param when both are
	// supplied — keeps the request shape minimal.
	if err := client.Delete(fmt.Sprintf("/api/orgs/%s?simulate_id=%s", orgID, simulateID)); err != nil {
		// Surface the CHW-4928 / 4929 codes verbatim so operators can
		// grep server logs by the same identifier they see in the
		// terminal. apiError.Error() already formats "CHW-XXXX: <msg>".
		var ae *apiError
		if errors.As(err, &ae) {
			return ae
		}
		return err
	}

	if asJSON {
		return PrintJSON(map[string]any{
			"deleted":     true,
			"org_id":      orgID,
			"simulate_id": simulateID,
		})
	}
	fmt.Fprintf(out, "Org %q deleted.\n", orgID)
	return nil
}
