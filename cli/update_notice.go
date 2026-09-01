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

	"github.com/Masterminds/semver/v3"
	"github.com/spf13/viper"
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
	// Gate 1: offline opt-out. Use the same truthiness rule as every other
	// CHAINSAW_OFFLINE call site — a bare `!= ""` made CHAINSAW_OFFLINE=0
	// suppress the notice here while enabling egress everywhere else.
	if envTruthy(os.Getenv("CHAINSAW_OFFLINE")) {
		return false
	}
	// Gate 2: quiet. --quiet IS a registered persistent flag now (root.go),
	// but Execute() calls this outside any RunE so there is no *cobra.Command
	// in hand; viper carries the bound flag value, and the argv scan is the
	// backstop for the DisableFlagParsing guard path where cobra never parsed
	// it. CHAINSAW_QUIET is honored through the same viper binding as
	// quiet(cmd), plus a direct read so the two can't drift.
	//
	// R11: the previous comment claimed --quiet was "not (yet) a registered
	// persistent flag" and the scan matched neither -q nor CHAINSAW_QUIET, so
	// `CHAINSAW_QUIET=1 chainsaw …` would still have printed the hint.
	if quietForUpdateNotice() {
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
	// R11: this used to be `latest == current`, i.e. ANY different string
	// fired the notice — including "v1.2.3" vs "1.2.3" (which would have
	// printed "a newer version (v1.2.3) is available; you're on 1.2.3") and
	// an OLDER published version. Compare as semver and only speak up when
	// latest is genuinely NEWER. Unparseable input on either side falls back
	// to strict inequality, which is the pre-existing behaviour and cannot
	// be worse than it.
	if !isNewerVersion(latest, current) {
		return false
	}

	// `chainsaw guard update` fetches the OpenSSF malicious-package feed.
	// It cannot upgrade this binary, and telling a user it can sends them
	// in a circle. Point at the installer, which is what actually replaces
	// the binary.
	fmt.Fprintf(updateNoticeWriter(),
		"chainsaw: a newer version (%s) is available; you're on %s.\n"+
			"  Reinstall: curl -fsSL https://chain305.com/install.sh | sh\n",
		latest, current)
	return true
}

// quietForUpdateNotice resolves the quiet signal without a *cobra.Command.
// viper covers --quiet (BindPFlag), the config file, and CHAINSAW_QUIET
// (BindEnv); envTruthy re-reads the env var with the shared 1/true/yes/on
// vocabulary; argvHasQuiet is the DisableFlagParsing backstop.
func quietForUpdateNotice() bool {
	return viper.GetBool("quiet") || envTruthy(os.Getenv("CHAINSAW_QUIET")) || argvHasQuiet(os.Args)
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

// isNewerVersion reports whether latest is strictly newer than current.
// Both sides tolerate a leading "v" (semver.NewVersion strips it), so
// "v1.2.3" and "1.2.3" compare EQUAL rather than as an upgrade. When either
// side is unparseable we fall back to plain string inequality — the old
// behaviour, and the only sane answer for a non-semver build stamp like
// "dev".
func isNewerVersion(latest, current string) bool {
	lv, lerr := semver.NewVersion(latest)
	cv, cerr := semver.NewVersion(current)
	if lerr != nil || cerr != nil {
		return latest != current
	}
	return lv.GreaterThan(cv)
}
