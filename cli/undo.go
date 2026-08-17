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
	"errors"
	"fmt"
	"net/http"
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
	// Auth BEFORE the confirmation prompt, not after it (see requireAuth in
	// root.go). Without this, an unauthenticated `chainsaw undo` printed a
	// preview-less "Undo the most recent action? [y/N]", waited for a y, and
	// only then failed at the transport.
	if err := requireAuth(cmd); err != nil {
		return err
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
			// Z1: this error used to be SWALLOWED — the call site read
			// `if perr := ...; perr == nil {` and simply fell through to the
			// prompt on any failure. See errUndoPreviewFailed for why a failed
			// preview must never reach a confirmation.
			if perr := client.Post(previewPath, nil, &preview); perr != nil {
				return errUndoPreviewFailed(previewPath, actionID, perr)
			}
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
			// Z1, second route to the same place. A preview can SUCCEED and
			// still name nothing: /api/actions/undo-last answers 200 with just
			// "No undoable actions found for this org." That left targetDesc at
			// the "the most recent action" placeholder and `path` unpinned — the
			// identical unnamed, unpinned confirmation the swallowed-error branch
			// produced, reached through a 200 instead of an error. Prompting is
			// worse than useless here: the server has told us there is nothing to
			// reverse, so a y can only revert something that appears in the org
			// between the preview and the POST.
			//
			// Report the server's own sentence and stop, at rc=0 — the same
			// contract the non-interactive "nothing to undo" branch at the bottom
			// of this function already publishes. Only the DEFAULT path takes
			// this exit: with --action-id the operator named the target
			// themselves, so it is both described and pinned regardless of what
			// the preview chose to echo back.
			if actionID == "" && preview.ActionID == "" {
				if previewMsg != "" {
					fmt.Println(previewMsg)
				} else {
					fmt.Println("Nothing to undo.")
				}
				return nil
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

// errUndoPreviewFailed aborts the interactive undo when the dry-run preview
// did not come back.
//
// Z1 — why aborting is the ONLY correct answer here, for every failure class,
// not just 401/403:
//
//  1. The preview and the rollback are THE SAME ENDPOINT, the same host, the
//     same credential — the preview is literally `path + "?dry_run=true"`. So a
//     failed preview is a near-certain prediction that the confirmed POST fails
//     too. Prompting is then asking a human to authorize an operation we
//     already have evidence we cannot perform. That covers the whole "network
//     blip" family: if the blip is real, the confirmed POST hits it as well and
//     the prompt bought nothing; the user re-runs either way.
//
//  2. If we are WRONG about (1) — the blip clears in the seconds the prompt is
//     open — the outcome is strictly worse, because the two things the preview
//     exists to provide are both missing:
//
//     • The DESCRIPTION. targetDesc degrades to the literal string "the most
//     recent action". The operator is asked to confirm a destructive,
//     irreversible-in-practice rollback that nobody, including the CLI, can
//     name. "Undo the most recent action? [y/N]" is not informed consent.
//
//     • The PIN. The C7 fix (see runUndo) only rewrites `path` to
//     /api/actions/{id}/undo when the preview named an id. With no preview
//     there is nothing to pin to, so the confirmed POST goes to the UNPINNED,
//     ORG-SCOPED /api/actions/undo-last, and the server resolves the target
//     with GetLastUndoable(orgID) at POST time — after the human said yes.
//     That is not merely C7's race (which needed a concurrent writer inside
//     the prompt window); it is C7 with the window widened to "whatever the
//     org's newest action happens to be when the packet lands". The comment
//     above the pinning block warns about exactly this path, and swallowing
//     the preview error routed every failure straight into it.
//
// This also matches the project's fail-closed posture for unavailable signals:
// when the input that makes a decision safe is missing, refuse rather than
// proceed on a degraded default.
//
// --yes remains the deliberate escape hatch: it skips the confirmation path
// (and therefore the preview) entirely, which is an explicit "I do not need to
// see it" from the operator rather than a silent downgrade behind a prompt.
// The error preserves the underlying failure — including its ExitCodeError, so
// an unauthenticated run still exits 3 rather than being flattened to 2.
func errUndoPreviewFailed(previewPath, actionID string, perr error) error {
	target := "the org's most recent undoable action"
	if actionID != "" {
		target = "action " + actionID
	}
	hint := "Re-run once the server is reachable."
	switch {
	case isUnauthorizedErr(perr):
		hint = "Your credentials were rejected — run `chainsaw auth login` and try again."
	case isForbiddenErr(perr):
		hint = "Your role lacks the permission to reverse this action type; the rollback would have been refused too."
	}
	suggest := "  chainsaw undo --dry-run          preview without confirming\n" +
		"  chainsaw audit                   see what the last recorded actions were\n" +
		"  chainsaw undo --yes              skip the confirmation deliberately (still resolves the target org-wide)"
	if actionID != "" {
		suggest = "  chainsaw undo --action-id " + actionID + " --dry-run   preview without confirming\n" +
			"  chainsaw undo --action-id " + actionID + " --yes       skip the confirmation deliberately"
	}
	return fmt.Errorf(`cannot preview %s: %w

Refusing to ask you to confirm a rollback that cannot be described. The preview
uses the same endpoint as the rollback itself (POST %s), so this
failure means the rollback would very likely fail too — and if it did not, the
target would be resolved server-side AFTER you confirmed, with no id to pin it
to and no description to show you.

%s

%s`, target, perr, previewPath, hint, suggest)
}

// isForbiddenErr reports whether err is the server's 403 envelope (CHW-1003 /
// scope denial). Mirrors isUnauthorizedErr (auth.go) and keys on the TRANSPORT
// STATUS for the same reason: a 500 whose body happens to mention 403 is not a
// permission denial.
func isForbiddenErr(err error) bool {
	if err == nil {
		return false
	}
	var ae *apiError
	if !errors.As(err, &ae) {
		return false
	}
	return ae.Status == http.StatusForbidden
}
