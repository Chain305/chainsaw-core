package cli

// exitcodes.go — the process exit-code contract for the chainsaw CLI.
//
// Two load-bearing invariants drive the numbering (see the Foundation plan):
//
//	(B) BLOCK-vs-ERROR: a policy block is an EXPECTED enforcement outcome, not
//	    a crash. It must be distinguishable from operational/tool errors by
//	    exit code. ExitBlocked stays 1 so every existing block-gating script
//	    (CI that branches on `chainsaw ... ; if [ $? -eq 1 ]`) is unchanged.
//	    Only OPERATIONAL errors move off 1 (they used to also exit 1) onto
//	    ExitOpError(2) — a documented, intended behavior change.
//
// Codes 0–4 are the cross-cutting buckets every command shares. Codes >=10 are
// reserved for command-specific outcomes that need to be told apart from the
// generic buckets (e.g. `admission soak clear` returning ExitSoakNotCleared so
// "gate not cleared" never collides with "config/auth failure").
const (
	// ExitOK — success.
	ExitOK = 0
	// ExitBlocked — the EXPECTED enforcement outcome: a policy block, a gate
	// failure, or findings at-or-above the configured threshold. Stays 1 so
	// existing block-gating scripts keep working.
	ExitBlocked = 1
	// ExitOpError — an operational error: network, server, IO, or an internal
	// failure. Previously these also exited 1; they now exit 2 so callers can
	// tell an enforcement block apart from a tool/infra failure.
	ExitOpError = 2
	// ExitConfigAuth — configuration or authentication problem (missing
	// server, unauthorized, forbidden).
	ExitConfigAuth = 3
	// ExitUsage — the invocation itself was wrong (unknown command/flag, bad
	// argument shape).
	ExitUsage = 4
)

// Command-specific outcome codes start at 10 so they never collide with the
// cross-cutting buckets above.
const (
	// ExitSoakNotCleared — `admission soak clear` ran successfully but the
	// shadow-mode soak gate is not yet cleared. Distinct from ExitConfigAuth(3)
	// (which it used to collide with) and ExitOpError(2) (HTTP/auth failure).
	ExitSoakNotCleared = 10
	// ExitIntelBlock — `intel scan` found at least one Quarantine or Replace
	// node: the strongest enforcement BLOCK the command emits. A command-specific
	// code (not ExitOpError(2)) so a CI block-gate never confuses a malicious
	// package with a server/IO failure (invariant B). Weaker Warn/UpgradeAvailable
	// trees still map to ExitBlocked(1); the ladder stays 0 < 1 < 11.
	ExitIntelBlock = 11
)

// ExitCodeError lets a Cobra RunE bubble up a specific process exit code
// without losing the error message. Execute() (see root.go) inspects the type
// via errors.As and calls os.Exit with the embedded code.
//
// Moved here from policy_preflight.go so the exit-code contract lives in one
// place; kept exported with the same Unwrap() behavior so existing callers and
// tests are unaffected.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string {
	if e.Err == nil {
		return fmtExitCode(e.Code)
	}
	return e.Err.Error()
}

func (e *ExitCodeError) Unwrap() error { return e.Err }

// fmtExitCode is split out so Error() doesn't pull "fmt" into this file's
// import set for a one-liner; kept tiny and allocation-light.
func fmtExitCode(code int) string {
	return "exit " + itoa(code)
}

// itoa is a minimal non-negative int formatter (exit codes are small and
// non-negative) avoiding an fmt import here.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
