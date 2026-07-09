package cli

// update_notice.go — P2.10. A gated, safe-by-default hook that may emit a
// single one-line "newer version available" hint to STDERR at the end of a
// command. It is wired into Execute() but DORMANT: this stub does not make any
// network call. The point is that the gating exists now, so a future live
// check can be dropped into latestKnownVersion() without revisiting the safety
// rules.
//
// SAFETY GATES (all must pass before anything is printed):
//   - CHAINSAW_OFFLINE is unset (an operator who opts out of all egress must
//     never see a notice that implies a phone-home).
//   - stderr is a TTY (don't pollute pipes, CI logs, or machine-readable
//     output; agents and scripts must never see this line).
//   - --quiet was not passed (explicit request for silence).
//   - a newer version is actually known (the stub returns "" so nothing fires
//     until a real source is wired in).

import (
	"fmt"
	"os"
)

// updateNoticeStderrIsTerminal is the TTY check, indirected for tests. Defaults
// to the shared stderrIsTerminal helper (see output.go).
var updateNoticeStderrIsTerminal = func() bool { return stderrIsTerminal() }

// updateNoticeWriter is where the hint is written. Indirected for tests so they
// can capture output without touching the real os.Stderr.
var updateNoticeWriter = func() *os.File { return os.Stderr }

// latestKnownVersion returns the newest version chainsaw knows about WITHOUT
// performing any network I/O on the call path of a normal command. The stub
// returns "" (unknown) so the hook is dormant. A future implementation may
// read a cached value written out-of-band (e.g. by `chainsaw guard update`),
// but must never block on the network here.
var latestKnownVersion = func() string { return "" }

// maybeNotifyUpdateAvailable prints at most one line to stderr when a newer
// version is known and every safety gate passes. Returns whether it printed,
// for tests. Never returns an error and never panics — it is best-effort UX.
func maybeNotifyUpdateAvailable() bool {
	// Gate 1: offline opt-out. Any non-empty value counts as set.
	if os.Getenv("CHAINSAW_OFFLINE") != "" {
		return false
	}
	// Gate 2: --quiet. Scanned from argv because --quiet is not (yet) a
	// registered persistent flag; once it is, this still works and is the
	// cheapest possible check.
	if argvHasQuiet(os.Args) {
		return false
	}
	// Gate 3: stderr must be a TTY — never write into pipes/CI/JSON consumers.
	if !updateNoticeStderrIsTerminal() {
		return false
	}
	// Gate 4: a newer version must actually be known. Stub returns "".
	latest := latestKnownVersion()
	if latest == "" {
		return false
	}
	current := resolveVersion().Version
	if latest == current {
		return false
	}

	fmt.Fprintf(updateNoticeWriter(),
		"chainsaw: a newer version (%s) is available; you're on %s. Run `chainsaw guard update` or reinstall.\n",
		latest, current)
	return true
}

// argvHasQuiet reports whether --quiet (or -q in its long form only) appears in
// argv. We match --quiet and the --quiet=... form; we deliberately do not match
// a bare -q to avoid clashing with a wrapped tool's short flags on the guard
// path (where argv is not chainsaw's own).
func argvHasQuiet(argv []string) bool {
	for _, a := range argv {
		if a == "--quiet" || a == "--quiet=true" {
			return true
		}
		if a == "--" {
			// Stop at an explicit end-of-flags marker.
			return false
		}
	}
	return false
}
