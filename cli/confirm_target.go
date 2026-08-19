package cli

// confirm_target.go — L-30.
//
// THE FINDING: five destructive verbs interpolated args[0] straight into their
// confirmation prompt and only discovered the target did not exist AFTER the
// operator had typed y. `chainsaw token revoke key_typo` asked "Revoke token
// \"key_typo\"? This cannot be undone." — a prompt that implies the thing exists
// and that answering yes will destroy it — and then failed with a 404. The
// operator learns nothing from the prompt, and worse, learns to trust a prompt
// that has verified nothing.
//
// `policy delete` already did it right by pre-fetching the policy name
// (policy.go). This file is that pattern, extracted once, for:
//
//	token revoke        exception delete       (their existing dry-runs)
//	token rotate        finding suppress       (their existing GETs)
//	auth client delete  (the list-and-filter already written for auth client rotate)
//
// DELIBERATELY NO NEW SERVER ENDPOINTS. There is no GET /api/clients/{id} and
// no GET /api/exceptions/{id}; adding them was explicitly ruled out for this
// wave. Every probe here is a call the CLI already makes somewhere.

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

// targetResolver probes the server for the object a destructive verb is about
// to act on and returns a human label for it (typically `"name" (id=…)`).
//
// It must return an error carrying HTTP 404 when the object does not exist.
// Any other error is treated as "could not check", not as "does not exist" —
// see confirmDestructive.
type targetResolver func() (string, error)

// promptConfirmFn is the confirmation seam. Indirected so tests can inject a
// stub that fails if the prompt is ever reached on a missing target.
var promptConfirmFn = PromptConfirm

// isNotFoundError reports whether err is the server saying the object does not
// exist. Strictly 404: a 403 means "you may not look", which is a completely
// different answer and must not be reported to the operator as "no such thing".
func isNotFoundError(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// notFoundError builds a 404-shaped error for a resolver that determines
// absence client-side (auth client delete filters a list; the server has no
// per-id GET to 404 for us).
func notFoundError(msg string) error {
	return &apiError{Code: fmt.Sprintf("HTTP %d", http.StatusNotFound), Message: msg, Status: http.StatusNotFound}
}

// confirmDestructive runs the shared pre-confirmation flow for a destructive
// verb and reports whether the caller should proceed.
//
// Call it ONLY on the non---yes path. `--yes` must fire no probe at all: a
// script that has already decided should not pay a round trip, and a
// read-permission gap must not be able to break an automated mutation that the
// caller is otherwise allowed to perform.
//
// Order of operations, and why:
//
//  1. TTY check FIRST. Off a terminal there is no prompt to show, so there is
//     nothing for a probe to inform — and A5 (fixed across every sibling verb)
//     requires a loud error here rather than a silent "Aborted." at exit 0.
//     Probing first would also mean a non-TTY run without --yes paid for a
//     request it could never use.
//  2. Probe. A 404 aborts BEFORE the prompt, which is the whole point.
//  3. A NON-404 failure (403, transport error, a server too old to answer)
//     degrades to a warning plus the raw id, and still prompts. This is
//     deliberate and load-bearing: read and write permissions are separate
//     grants, and an operator who may revoke a token but may not list tokens
//     must not be blocked by a courtesy lookup.
func confirmDestructive(cmd *cobra.Command, id, verb, warning string, resolve targetResolver) (bool, error) {
	if !stdinIsTerminal() {
		return false, fmt.Errorf("refusing to %s %s without --yes (stdin is not a TTY, so there is no confirmation prompt to display). Re-run with --yes to confirm.", verb, id)
	}

	label := fmt.Sprintf("%q", id)
	if resolve != nil {
		got, err := resolve()
		switch {
		case err == nil:
			if strings.TrimSpace(got) != "" {
				label = got
			}
		case isNotFoundError(err):
			// Fail BEFORE the prompt. Returning the server's own error keeps
			// the exit code and the CHW- code intact for scripts.
			return false, err
		default:
			fmt.Fprintf(cmd.ErrOrStderr(),
				"chainsaw: could not verify %s before asking (%v); confirming against the id you typed.\n", id, err)
		}
	}

	q := fmt.Sprintf("%s %s?", titleFirst(verb), label)
	if strings.TrimSpace(warning) != "" {
		q += " " + warning
	}
	if !promptConfirmFn(q) {
		fmt.Fprintln(cmd.OutOrStdout(), "Aborted.")
		return false, nil
	}
	return true, nil
}

// titleFirst upper-cases the first rune so "revoke token" becomes "Revoke
// token" at the head of a question. strings.Title is deprecated and would
// also capitalise "Token", which reads wrong.
func titleFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// describeTarget renders the standard `"name" (id=…)` label, falling back to
// the bare id when the server gave us no name to show.
func describeTarget(name, id string) string {
	name = strings.TrimSpace(name)
	if name == "" || name == id {
		return fmt.Sprintf("%q", id)
	}
	return fmt.Sprintf("%q (id=%s)", name, id)
}
