package cli

// undo.go exposes the shared internal/undo service on the CLI surface,
// matching MCP's undo_last_action and Billy's propose_action type=undo.
// The subcommand is flat (not a `chainsaw undo <sub>` group) because
// there is only one verb — roll back — with two ways to target
// (last by default, or --action-id for a specific entry). Extending to
// `chainsaw undo list` etc. later means reshaping, but that's fine:
// the two existing flags are ergonomic enough today and a list is
// already available via `chainsaw audit` / the MCP list_recent_actions
// tool.
//
// Permission model: the server's /api/actions/undo-last and
// /api/actions/{id}/undo endpoints are gated only by requireIdentity.
// The per-action-type RBAC check lives inside internal/undo, which
// returns ErrForbidden (HTTP 403) when the caller lacks the permission
// required to perform the inverse of the targeted action. Clients see
// a 403 with CHW-1003 exactly like any other scope-denial.

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

// undoResult mirrors undo.UndoResult. Duplicated here (rather than
// imported) because the CLI package must not depend on server-side
// types — it only parses the JSON the server emits. The field shape
// is load-bearing: MCP's undoLastActionResult uses the same names so
// operators who scripted against `chainsaw undo --json` can drop in
// the MCP response verbatim.
type undoResult struct {
	Undone     bool   `json:"undone"`
	DryRun     bool   `json:"dry_run,omitempty"`
	ActionID   string `json:"action_id,omitempty"`
	ActionType string `json:"action_type,omitempty"`
	PolicyID   string `json:"policy_id,omitempty"`
	Message    string `json:"message"`
}

var undoCmd = &cobra.Command{
	Use:     "undo",
	GroupID: GrpConfig,
	Short:   "Roll back the most recent agent action (or a specific action by id)",
	Long: "Undoes the inverse of a previously recorded agent action in the " +
		"current org. By default, targets the ORG's most recent undoable " +
		"action — not the caller's own: the server resolves the target with " +
		"GetLastUndoable(orgID), so a teammate's or an agent's action can be " +
		"the one that gets reversed. Pass --action-id to target a specific " +
		"entry. " +
		"Use --dry-run to preview what would be undone without applying. " +
		"Permission is checked dynamically per action type: undoing a " +
		"policy mutation requires policies:manage, an exception mutation " +
		"requires exceptions:manage. The server returns 403 when the " +
		"caller lacks the inverse permission — even when they recorded " +
		"the original action.",
	RunE: runUndo,
}

func init() {
	undoCmd.Flags().String("action-id", "", "Action id to undo (default: the org's most recent undoable action)")
	undoCmd.Flags().Bool("dry-run", false, "Preview what would be undone without applying")
	undoCmd.Flags().Bool("yes", false, "Skip confirmation prompt (required on non-TTY)")
	undoCmd.Flags().Bool("json", false, "Output the server response as JSON")
	rootCmd.AddCommand(undoCmd)
}

func runUndo(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	actionID, _ := cmd.Flags().GetString("action-id")
	actionID = strings.TrimSpace(actionID)
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	// Path selection:
	//   --action-id set   → POST /api/actions/{id}/undo
	//   default           → POST /api/actions/undo-last
	// Both accept ?dry_run=true; we build the query suffix once.
	// C13: the id lands in a URL PATH segment, so escape it. Today's ids are
	// server-minted UUIDs, but --action-id is a user flag and the sibling call
	// sites in this package already build their paths safely.
	path := "/api/actions/undo-last"
	if actionID != "" {
		path = "/api/actions/" + url.PathEscape(actionID) + "/undo"
	}
	if dryRun {
		path = path + "?dry_run=true"
	}

	// Confirmation gate. `undo` reverses the last mutating action; an
	// unguarded POST would roll back blind. Skip the gate entirely for
	// --dry-run (already non-mutating, must stay prompt-free). Mirror the
	// runExceptionDelete idiom: require --yes on non-TTY, otherwise prompt.
	if !dryRun {
		yes, _ := cmd.Flags().GetBool("yes")
		if !yes {
			// Echo the target action first so the operator sees exactly what
			// will be reversed. A dry-run preview against the SAME endpoint
			// gives us the server's own description; this preview round-trip
			// only happens on the interactive/confirm path, never with --yes.
			targetDesc := "the most recent action"
			if actionID != "" {
				targetDesc = "action " + actionID
			}
			previewPath := path + "?dry_run=true"
			var preview undoResult
			var previewMsg string
			if perr := client.Post(previewPath, nil, &preview); perr == nil {
				// Y6: targetDesc used to be overwritten with preview.Message,
				// which is ALWAYS a complete sentence — the only two producers
				// of a 200 are internal/undo ("Dry run: would undo %s (action
				// %s). Run again without dry-run to apply.") and undo_api ("No
				// undoable actions found for this org."). Splicing either into
				// `Undo %s?` told the operator to "run again without dry-run"
				// while they were already at the live confirmation, and it
				// discarded the perfectly good "action <id>" set above. Build
				// the clause from the STRUCTURED fields and print the server's
				// sentence on its own line instead.
				if preview.ActionType != "" {
					targetDesc = preview.ActionType
					if preview.ActionID != "" {
						targetDesc = preview.ActionType + " (" + preview.ActionID + ")"
					}
				}
				previewMsg = strings.TrimSpace(preview.Message)
				// C7 (preview/confirm TOCTOU): the preview parsed ActionID and
				// then threw it away, and the confirmed POST re-hit the UNPINNED
				// /undo-last. The server resolves that with GetLastUndoable(orgID)
				// — ORG-scoped — so any teammate, MCP tool, or Billy agent that
				// records an action while the prompt sits open silently moves the
				// target: the operator reads "Would revert policy.update on pol-1"
				// and confirms a revert of policy.delete on pol-9. Pin the real
				// call to the id we actually showed. /api/actions/{id}/undo
				// already exists (internal/server/undo_api.go), so this is
				// CLI-only. If the server declined to name an id there is nothing
				// to pin to, and we leave the original path alone.
				if actionID == "" && preview.ActionID != "" {
					path = "/api/actions/" + url.PathEscape(preview.ActionID) + "/undo"
				}
			}

			if !stdinIsTerminal() {
				return fmt.Errorf("refusing to undo %s without --yes (stdin is not a TTY, so there is no confirmation prompt to display). Re-run with --yes to confirm.", targetDesc)
			}
			if previewMsg != "" {
				fmt.Println(previewMsg)
			}
			if !PromptConfirm(fmt.Sprintf("Undo %s?", targetDesc)) {
				fmt.Println("Aborted.")
				return nil
			}
		}
	}

	var resp undoResult
	if err := client.Post(path, nil, &resp); err != nil {
		return err
	}

	if useJSON(cmd) {
		return PrintJSONTo(cmd, resp)
	}

	// Human-readable rendering. The server's Message field is designed
	// to be surfaced verbatim; we add a status prefix so the caller can
	// see at a glance whether anything happened.
	switch {
	case resp.DryRun:
		fmt.Println("[dry-run] " + resp.Message)
	case resp.Undone:
		fmt.Println(resp.Message)
	default:
		// Undone=false + DryRun=false is the "nothing to undo" branch,
		// which the server sends with status 200 so scripts don't have
		// to treat it as an error. Echo the server's message as-is.
		fmt.Println(resp.Message)
	}
	return nil
}
