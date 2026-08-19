package cli

import (
	"strings"
	"testing"
)

// envMap builds a consoleEnv lookup from a map, distinguishing "set to empty"
// from "unset" the way os.LookupEnv does. A nil map means nothing is set.
func envMap(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

// TestDecideUnicode_PlatformMatrix exercises every rung of the ladder in
// unicode_decide.go on the Linux/macOS test host. That is the entire point of
// the file having no build tag: the failure it governs is Windows-only, there
// is no Windows runner, and a rule that can only be exercised on a machine we
// do not have is a rule that stops being tested.
//
// Two rows here are the actual defect and FAIL against the previous
// GetConsoleOutputCP probe:
//
//   - "windows/conhost/no-signal" — the probe scored a CP437 conhost as
//     capable whenever the user had run `chcp 65001`, and scored a
//     65001+Consolas console (the one users are TOLD to adopt) as capable too,
//     even though Consolas has no ✓ U+2713. Both got boxes. This is now false.
//   - "windows/redirected" — GetConsoleOutputCP succeeds whenever the PROCESS
//     has a console attached, regardless of whether stdout IS that console, so
//     `doctor --offline > report.txt` from a legacy window wrote the ASCII
//     fallback into the FILE. This is now true: a file has no font.
func TestDecideUnicode_PlatformMatrix(t *testing.T) {
	cases := []struct {
		name    string
		goos    string
		console bool
		env     map[string]string
		want    bool
	}{
		// ── rule 1: CHAINSAW_NO_UNICODE outranks everything ──────────────
		{
			name: "rule1/opt-out beats a capable non-windows host",
			goos: "linux",
			env:  map[string]string{"CHAINSAW_NO_UNICODE": "1"},
			want: false,
		},
		{
			name: "rule1/bare-set counts as on",
			goos: "linux",
			env:  map[string]string{"CHAINSAW_NO_UNICODE": ""},
			want: false,
		},
		{
			name: "rule1/explicit falsey declines to be the reason",
			goos: "linux",
			env:  map[string]string{"CHAINSAW_NO_UNICODE": "0"},
			want: true,
		},
		{
			name:    "rule1/explicit falsey does NOT rescue a conhost",
			goos:    "windows",
			console: true,
			env:     map[string]string{"CHAINSAW_NO_UNICODE": "false"},
			want:    false,
		},
		{
			// The precedence question the ladder exists to answer: an opt-IN
			// must never override an opt-OUT the user set because their
			// terminal was visibly broken.
			name:    "rule1/opt-out outranks opt-in",
			goos:    "windows",
			console: true,
			env: map[string]string{
				"CHAINSAW_NO_UNICODE": "1",
				"CHAINSAW_UNICODE":    "1",
			},
			want: false,
		},

		// ── rule 2: CHAINSAW_UNICODE, the escape hatch ───────────────────
		{
			name:    "rule2/opt-in alone rescues a conhost",
			goos:    "windows",
			console: true,
			env:     map[string]string{"CHAINSAW_UNICODE": "1"},
			want:    true,
		},
		{
			name:    "rule2/opt-in vocabulary matches envTruthy",
			goos:    "windows",
			console: true,
			env:     map[string]string{"CHAINSAW_UNICODE": "on"},
			want:    true,
		},
		{
			// Presence is not enough — same R7 reasoning as CHAINSAW_NO_UNICODE,
			// from the other side. `CHAINSAW_UNICODE=0` must not force it ON.
			name:    "rule2/falsey opt-in is not an opt-in",
			goos:    "windows",
			console: true,
			env:     map[string]string{"CHAINSAW_UNICODE": "0"},
			want:    false,
		},
		{
			// THE gen-cli-docs SAFETY PROPERTY. Rules 4-9 are unreachable off
			// Windows, so no amount of Windows-shaped env on the generating
			// host can change what gets rendered into /cli-reference. The
			// opt-in is true here but INERT: rule 3 would have said true too.
			name: "rule2/inert on linux — rule 3 would say true anyway",
			goos: "linux",
			env:  map[string]string{"CHAINSAW_UNICODE": "1"},
			want: true,
		},

		// ── rule 3: non-Windows short-circuit ────────────────────────────
		{name: "rule3/linux bare", goos: "linux", want: true},
		{name: "rule3/darwin bare", goos: "darwin", want: true},
		{
			// Every Windows-only signal set, on a non-Windows host, with
			// stdout NOT a console: rule 3 must fire before any of them.
			name: "rule3/windows signals are inert off windows",
			goos: "darwin",
			env: map[string]string{
				"WT_SESSION": "", "TERM": "dumb", "MSYSTEM": "",
			},
			want: true,
		},

		// ── rule 4: redirected output (bug 2) ────────────────────────────
		{
			// MUST FAIL against the old probe. `> report.txt` from a legacy
			// window used to emit the ASCII fallback INTO the file.
			name:    "windows/redirected",
			goos:    "windows",
			console: false,
			want:    true,
		},
		{
			// Redirection beats the absence of every terminal signal — that is
			// the whole point; it is not asking about a terminal at all.
			name:    "rule4/redirected from a signal-free conhost",
			goos:    "windows",
			console: false,
			env:     map[string]string{"TERM": "dumb"},
			want:    true,
		},
		{
			// ...but an explicit opt-out still wins, because rule 1 is above it.
			name:    "rule4/opt-out still outranks redirection",
			goos:    "windows",
			console: false,
			env:     map[string]string{"CHAINSAW_NO_UNICODE": "1"},
			want:    false,
		},

		// ── rules 5-8: the terminal recogniser ───────────────────────────
		{
			name:    "rule5/windows terminal",
			goos:    "windows",
			console: true,
			env:     map[string]string{"WT_SESSION": "6f4a1b2c-0000-4000-8000-000000000000"},
			want:    true,
		},
		{
			name:    "rule6/vscode integrated terminal",
			goos:    "windows",
			console: true,
			env:     map[string]string{"TERM_PROGRAM": "vscode"},
			want:    true,
		},
		{
			// Some other TERM_PROGRAM value is not a recognised signal on its
			// own — this rule is an allow-list, not a presence test.
			name:    "rule6/other TERM_PROGRAM is not a signal",
			goos:    "windows",
			console: true,
			env:     map[string]string{"TERM_PROGRAM": "Apple_Terminal"},
			want:    false,
		},
		{
			name:    "rule7/wsl",
			goos:    "windows",
			console: true,
			env:     map[string]string{"WSL_DISTRO_NAME": "Ubuntu-22.04"},
			want:    true,
		},
		{
			name:    "rule7/git bash (msys)",
			goos:    "windows",
			console: true,
			env:     map[string]string{"MSYSTEM": "MINGW64"},
			want:    true,
		},
		{
			name:    "rule8/TERM set is a positive signal on windows",
			goos:    "windows",
			console: true,
			env:     map[string]string{"TERM": "xterm-256color"},
			want:    true,
		},
		{
			// "dumb" is the conventional "assume nothing" value, so it is the
			// one TERM that does not vouch for anything.
			name:    "rule8/TERM=dumb is not a signal",
			goos:    "windows",
			console: true,
			env:     map[string]string{"TERM": "dumb"},
			want:    false,
		},
		{
			name:    "rule8/TERM set-but-empty is not a signal",
			goos:    "windows",
			console: true,
			env:     map[string]string{"TERM": ""},
			want:    false,
		},

		// ── rule 9: the fix ──────────────────────────────────────────────
		{
			// MUST FAIL against the old probe, which returned true for any
			// console reporting codepage 65001 — including the `chcp 65001` +
			// Consolas window that boxes ✓ U+2713 today.
			name:    "windows/conhost/no-signal",
			goos:    "windows",
			console: true,
			want:    false,
		},
		{
			// PowerShell 5.1 in its own window sets PSModulePath but none of
			// the terminal signals. Same answer, and deliberately so.
			name:    "rule9/powershell 5.1 native window",
			goos:    "windows",
			console: true,
			env:     map[string]string{"PSModulePath": `C:\Program Files\WindowsPowerShell\Modules`},
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideUnicode(consoleEnv{
				goos:            tc.goos,
				stdoutIsConsole: tc.console,
				lookup:          envMap(tc.env),
			})
			if got != tc.want {
				t.Errorf("decideUnicode(goos=%q console=%v env=%v) = %v, want %v",
					tc.goos, tc.console, tc.env, got, tc.want)
			}
		})
	}
}

// A zero-value consoleEnv must not panic. Nothing constructs one today, but
// the nil lookup is the kind of thing a future adapter forgets to fill in, and
// a panic in the glyph selector would take down every command that prints.
func TestDecideUnicode_ZeroValueIsSafe(t *testing.T) {
	if got := decideUnicode(consoleEnv{goos: "windows", stdoutIsConsole: true}); got {
		t.Errorf("zero-value consoleEnv on a conhost = %v, want false", got)
	}
	if got := decideUnicode(consoleEnv{goos: "linux"}); !got {
		t.Errorf("zero-value consoleEnv on linux = %v, want true", got)
	}
}

// ── help text is console-independent ───────────────────────────────────────

// TestDoctorOfflineFlagHelp_IsConsoleIndependent replaces the former
// TestDoctorOfflineFlagHelp_NamesTheRenderedAlphabet, which asserted the
// OPPOSITE and was the one place the package's own rule — never build
// Short/Long/flag usage from glyphs() — was violated.
//
// Why the old assertion had to go rather than be kept alongside: flag usage is
// built at command-CONSTRUCTION time, and cmd/gen-cli-docs constructs the tree
// on a developer's machine to render
// how-tos-site/content/cli-reference/doctor.md. So the PUBLISHED reference
// varied with the generating host's console. At HEAD only CHAINSAW_NO_UNICODE
// in the generator env could flip it; the Unicode ladder (unicode_decide.go)
// adds WT_SESSION, TERM_PROGRAM, WSL_DISTRO_NAME, MSYSTEM and TERM as further
// inputs. All of those are gated behind rule 3, so generation on Linux/macOS
// stays deterministic — but "deterministic because of a rule two files away"
// is not a property worth relying on when the string can simply be constant.
//
// The console-aware naming did not vanish. It lives on doctor_offline.go's
// legend line, which is rendered at RUN time from the same resolved set as the
// rows above it and is pinned by
// TestDoctorOffline_LegendMatchesRenderedAlphabet.
func TestDoctorOfflineFlagHelp_IsConsoleIndependent(t *testing.T) {
	usage := func() string {
		f := newDoctorCmd().Flags().Lookup("offline")
		if f == nil {
			t.Fatal("doctor has no --offline flag")
		}
		return f.Usage
	}

	// Four consoles that between them cover both halves of the resolution:
	// the package var the force* helpers pivot on, and both env vars the
	// ladder reads.
	forceUnicodeConsole(t)
	baseline := usage()

	forceASCIIGlyphs(t)
	if got := usage(); got != baseline {
		t.Errorf("--offline usage varies with the console:\n ascii %q\nunicode %q", got, baseline)
	}

	t.Setenv("CHAINSAW_NO_UNICODE", "1")
	if got := usage(); got != baseline {
		t.Errorf("--offline usage varies with CHAINSAW_NO_UNICODE:\n got %q\nwant %q", got, baseline)
	}

	t.Setenv("CHAINSAW_NO_UNICODE", "0")
	t.Setenv("CHAINSAW_UNICODE", "1")
	if got := usage(); got != baseline {
		t.Errorf("--offline usage varies with CHAINSAW_UNICODE:\n got %q\nwant %q", got, baseline)
	}

	// And it is the UNICODE set that is baked in, byte-for-byte matching what
	// gen-cli-docs has published into
	// how-tos-site/content/cli-reference/doctor.md.
	const want = "Air-gap diagnostics (W4): walk every intelligence condition and report whether it runs offline (✓), is degraded (⚠), or requires a refreshed bundle (✗). The matrix prints an ASCII alphabet instead on consoles that cannot render these; its legend names whichever set it used. Reads CHAINSAW_INTEL_BUNDLE_PATH and CHAINSAW_OFFLINE_FAIL_MODE."
	if baseline != want {
		t.Errorf("--offline help changed; regenerate the docs (make gen-cli-docs):\n got %q\nwant %q", baseline, want)
	}
	for _, g := range []string{unicodeGlyphs.ok, unicodeGlyphs.warn, unicodeGlyphs.fail} {
		if !strings.Contains(baseline, "("+g+")") {
			t.Errorf("--offline help no longer names the canonical marker %q: %q", g, baseline)
		}
	}
}
