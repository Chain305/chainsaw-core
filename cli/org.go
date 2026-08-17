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
	"net/url"
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
	GroupID: GrpConfig,
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
	// Y7: the prose back-ticks around the login command were consumed by
	// pflag's UnquoteUsage — it takes the FIRST back-quoted span in a usage
	// string as the flag's VALUE PLACEHOLDER — so `chainsaw org delete
	// --help` advertised "--slug chainsaw auth login". Single quotes here,
	// and exactly one back-quoted span (`org-id`) is deliberately absent so
	// the flag renders as the plain "--slug string".
	orgDeleteCmd.Flags().String("slug", "",
		"Org slug OR org id to delete. Resolved against the orgs this account can see; defaults to the org_id from config (--org flag or 'chainsaw auth login').")
	orgDeleteCmd.Flags().Bool("json", false, "Emit machine-readable JSON instead of pretty-printed output.")
	orgCmd.AddCommand(orgDeleteCmd)
	rootCmd.AddCommand(orgCmd)
}

// orgDeletePreviewResponse mirrors the JSON envelope produced by
// handleOrgDeletePreview in internal/server/admin_orgs_simulate.go.
// We don't import the server type; the field names are part of the
// API contract (TTL ratchet test in qa/ pins them).
//
// OrgID / OrgSlug / OrgName are CLI-populated (the server envelope has
// no org block) so a --json consumer can see WHICH org the preview
// resolved to. Additive: every server-sourced key keeps its name.
type orgDeletePreviewResponse struct {
	SimulateID string           `json:"simulate_id"`
	Summary    string           `json:"summary"`
	Inventory  map[string]int   `json:"inventory"`
	Samples    []map[string]any `json:"samples"`
	Fallback   string           `json:"fallback,omitempty"`
	TTLSeconds int              `json:"ttl_seconds,omitempty"`
	Kind       string           `json:"kind,omitempty"`

	OrgID   string `json:"org_id,omitempty"`
	OrgSlug string `json:"org_slug,omitempty"`
	OrgName string `json:"org_name,omitempty"`
}

// orgListItem is one element of the {"orgs":[…]} envelope served by
// GET /api/orgs (listUserOrgs in internal/server/orgs.go). Only the
// three identity fields are decoded — role/permissions/timestamps are
// irrelevant to identifier resolution.
type orgListItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// codeOrgNotFound is errcodes.CodeOrgNotFound. Duplicated as a literal
// because core/ is the open-core module (github.com/chain305/chainsaw-core)
// and cannot import the private module's internal/errcodes. Keep in sync
// with internal/errcodes/registry_orgs.go — the point of reusing the code
// is that a locally-detected missing org is indistinguishable, to an
// operator or a CI grep, from the server-side CHW-4201 the commit path
// already returns.
const codeOrgNotFound = "CHW-4201"

// errOrgNotFound builds the same CHW-4201 envelope the server's DELETE
// path returns, so `--dry-run` on a ghost org fails with the identical
// code the commit would have produced instead of printing a confident
// all-zeroes preview. Status 404 → classifyCLIError "not_found" →
// ExitOpError(2), matching the commit path's exit code exactly.
func errOrgNotFound(ident string) error {
	return &apiError{
		Code:   codeOrgNotFound,
		Status: 404,
		Message: fmt.Sprintf(
			"organization not found: %q matches no org id and no org slug visible to this account; verify the identifier and that the org has not been deleted",
			ident),
	}
}

// resolveOrgIdentifier turns the operator-supplied identifier (a slug OR
// a raw org id) into the org id the API expects, by looking it up in
// GET /api/orgs.
//
// N3: `--slug` was assigned STRAIGHT into orgID and sent as the org id,
// so the flag never accepted a slug at all — and because the preview
// endpoint walks the cascade tables with `WHERE org_id = <whatever>`, a
// slug, a typo, and a genuinely empty org all produced the same
// all-zeroes inventory at exit 0, followed by a copy-pasteable confirm
// line. The two-step gate exists so the operator sees what will be
// destroyed BEFORE confirming; a preview that cannot tell those three
// cases apart is safety theatre. Resolution happens once, in
// runOrgDelete, so the preview and the commit address the same org and a
// simulate_id minted from a slug is redeemable with the same slug.
//
// ID match wins over slug match: ids are the server's own handles, and
// an org whose slug happened to equal another org's id must not shadow
// it on the irreversible command.
//
// A lookup failure is returned, not swallowed. This is the only
// irreversible verb in the CLI; if we cannot enumerate the orgs this
// account can see, we must not hand back a preview that implies we
// verified anything. GET /api/orgs needs only an authenticated identity
// (requireIdentity), a strictly lower bar than the PermOrgDelete the
// delete itself requires, so any caller that could legitimately delete
// can also resolve.
func resolveOrgIdentifier(client *APIClient, ident string) (orgListItem, error) {
	var resp struct {
		Orgs []orgListItem `json:"orgs"`
	}
	if err := client.Get("/api/orgs", &resp); err != nil {
		return orgListItem{}, fmt.Errorf("cannot verify org %q: listing organizations failed: %w", ident, err)
	}
	for _, o := range resp.Orgs {
		if o.ID == ident {
			return o, nil
		}
	}
	for _, o := range resp.Orgs {
		if o.Slug != "" && o.Slug == ident {
			return o, nil
		}
	}
	return orgListItem{}, errOrgNotFound(ident)
}

// runOrgDelete is the verb dispatcher.
func runOrgDelete(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	// Auth BEFORE the confirmation prompt (see requireAuth, root.go). This
	// path already checked auth incidentally, via resolveOrgIdentifier below —
	// make the ordering a property of the command, not of the resolve.
	if err := requireAuth(cmd); err != nil {
		return err
	}

	ident := strings.TrimSpace(viper.GetString("org_id"))
	if slug, _ := cmd.Flags().GetString("slug"); strings.TrimSpace(slug) != "" {
		ident = strings.TrimSpace(slug)
	}
	if ident == "" {
		return fmt.Errorf("no org selected — pass --slug <org-slug|org-id> or set org_id via `chainsaw --org <id>` / `chainsaw auth login`")
	}

	dryRun, _ := cmd.Flags().GetBool("dry-run")
	simulateID, _ := cmd.Flags().GetString("simulate-id")
	confirm, _ := cmd.Flags().GetBool("confirm")
	asJSON := useJSON(cmd)
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

	// Resolve BEFORE dispatching so preview and commit address the same
	// org: a simulate_id minted from `--slug acme` must be redeemable with
	// `--slug acme`, which is only true if both legs send the same id.
	org, err := resolveOrgIdentifier(client, ident)
	if err != nil {
		return err
	}

	if dryRun {
		return runOrgDeletePreview(cmd, client, org, asJSON)
	}
	return runOrgDeleteCommit(cmd, client, org.ID, simulateID, confirm, yes, asJSON)
}

// runOrgDeletePreview is the --dry-run path. POSTs the preview, prints
// the inventory snapshot, and prints the simulate_id alongside the
// next-step command for copy-paste.
func runOrgDeletePreview(cmd *cobra.Command, client *APIClient, org orgListItem, asJSON bool) error {
	var resp orgDeletePreviewResponse
	if err := client.Post("/api/orgs/"+url.PathEscape(org.ID)+"/delete/preview", nil, &resp); err != nil {
		return err
	}
	// Stamp the resolved identity onto the envelope. Without it a --json
	// consumer sees an inventory with no way to tell which org produced it
	// — the same ambiguity the human path had.
	resp.OrgID, resp.OrgSlug, resp.OrgName = org.ID, org.Slug, org.Name
	if asJSON {
		return PrintJSONTo(cmd, resp)
	}

	out := cmd.OutOrStdout()
	// Echo BOTH the id and the slug: the operator typed one of them, and
	// on the irreversible command they should see the other before they
	// copy the confirm line.
	label := org.ID
	if org.Slug != "" {
		label = fmt.Sprintf("%s (slug %s)", org.ID, org.Slug)
	}
	if org.Name != "" {
		label += fmt.Sprintf(" — %q", org.Name)
	}
	fmt.Fprintf(out, "Org-delete preview for %s:\n\n", label)
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
	// Carry --slug through. The printed line used to omit it, so a preview
	// staged against one org and pasted into a shell whose config org_id
	// pointed elsewhere would send the simulate_id at the WRONG org. Naming
	// the resolved id makes the confirm line self-contained.
	fmt.Fprintf(out, "  chainsaw org delete --slug %s --simulate-id %s --confirm --yes\n", org.ID, resp.SimulateID)
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
		if err := client.Post("/api/orgs/"+url.PathEscape(orgID)+"/delete/preview", nil, &resp); err != nil {
			return err
		}
		if asJSON {
			return PrintJSONTo(cmd, resp)
		}
		fmt.Fprintln(out, "Re-diff (against current live inventory):")
		fmt.Fprintln(out, resp.Summary)
		fmt.Fprintln(out, "\nPass --confirm to commit using the original simulate_id;")
		fmt.Fprintln(out, "or re-run `chainsaw org delete --dry-run` for a fresh simulate.")
		return nil
	}

	// Commit. Confirmation prompt unless --yes was passed.
	if !yes {
		// A5: --yes is already documented as "Required for non-TTY runs"
		// (see the flag registration) but nothing enforced it — PromptConfirm
		// returns false off a TTY, so the org delete printed "Aborted." and
		// exited 0. Enforce the documented contract. Same guard, same
		// rationale, as policy delete.
		if !stdinIsTerminal() {
			return fmt.Errorf("refusing to delete org %s without --yes (stdin is not a TTY, so there is no confirmation prompt to display). Re-run with --yes to confirm.", orgID)
		}
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
	//
	// A8: orgID is a path SEGMENT and simulateID a query VALUE — both came
	// from user flags and were concatenated raw. Escape each with the right
	// escaper (PathEscape vs url.Values) so a slug or id carrying /, &, or a
	// space cannot re-target the request.
	delPath := "/api/orgs/" + url.PathEscape(orgID) + "?" + url.Values{"simulate_id": []string{simulateID}}.Encode()
	if err := client.Delete(delPath); err != nil {
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
		return PrintJSONTo(cmd, map[string]any{
			"deleted":     true,
			"org_id":      orgID,
			"simulate_id": simulateID,
		})
	}
	fmt.Fprintf(out, "Org %q deleted.\n", orgID)
	return nil
}
