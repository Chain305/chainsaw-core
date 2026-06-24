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
	Use:   "undo",
	Short: "Roll back the most recent agent action (or a specific action by id)",
	Long: "Undoes the inverse of a previously recorded agent action in the " +
		"current org. By default, targets the caller's most recent " +
		"undoable action; pass --action-id to target a specific entry. " +
		"Use --dry-run to preview what would be undone without applying. " +
		"Permission is checked dynamically per action type: undoing a " +
		"policy mutation requires policies:manage, an exception mutation " +
		"requires exceptions:manage. The server returns 403 when the " +
		"caller lacks the inverse permission — even when they recorded " +
		"the original action.",
	RunE: runUndo,
}

func init() {
	undoCmd.Flags().String("action-id", "", "Action id to undo (default: caller's most recent undoable action)")
	undoCmd.Flags().Bool("dry-run", false, "Preview what would be undone without applying")
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
	path := "/api/actions/undo-last"
	if actionID != "" {
		path = "/api/actions/" + actionID + "/undo"
	}
	if dryRun {
		path = path + "?dry_run=true"
	}

	var resp undoResult
	if err := client.Post(path, nil, &resp); err != nil {
		return err
	}

	if useJSON(cmd) {
		return PrintJSON(resp)
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
