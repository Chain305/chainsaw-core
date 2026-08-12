package cli

// Regression tests for scan-repo: X1 (missing root fails open), X2 (unreadable
// candidate reads as clean), S5 (mixed-case Dockerfile FROM evades the rule),
// S7 (every file in the tree is read fully into memory), S9 (--output ignored
// on the JSON path).

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func newScanRepoTestCmd(out, errOut *strings.Builder) *cobra.Command {
	cmd := &cobra.Command{Use: "scan-repo", RunE: runScanRepo}
	cmd.Flags().Bool("json", false, "")
	// Inherited-from-root persistent flags scan-repo relies on.
	cmd.Flags().String("format", "table", "")
	cmd.Flags().String("output", "", "")
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs(nil)
	return cmd
}

func scanRepoExitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var coded *ExitCodeError
	if errors.As(err, &coded) {
		return coded.Code
	}
	t.Fatalf("runScanRepo returned a non-ExitCodeError: %v", err)
	return -1
}

// ── S5: mixed-case Dockerfile FROM ─────────────────────────────────────────

// TestInspectFile_DockerfileFromIsCaseInsensitive pins that the EXTRACTION is
// as case-insensitive as the detection. `From ghcr.io/...` is valid Dockerfile
// syntax; before the fix the two literal TrimPrefix calls left image == "From",
// which dockerImageRoutesThroughChainsaw waved through as a bare Docker Hub
// name. Measured before: FROM→1 finding, from→1, From→0.
func TestInspectFile_DockerfileFromIsCaseInsensitive(t *testing.T) {
	for _, kw := range []string{"FROM", "from", "From", "FrOm", "fROM"} {
		t.Run(kw, func(t *testing.T) {
			got := inspectFile("Dockerfile", "Dockerfile", kw+" ghcr.io/o/r:1\n")
			if len(got) != 1 {
				t.Fatalf("%q: got %d findings, want 1 (%+v)", kw, len(got), got)
			}
			if !strings.Contains(got[0].Detail, "ghcr.io/o/r:1") {
				t.Errorf("finding should name the real image, got %q", got[0].Detail)
			}
		})
	}
}

// TestInspectFile_DockerfileFromNeverPanics covers the structural guard: a
// bare "FROM" with no argument must be skipped, not indexed into.
func TestInspectFile_DockerfileFromNeverPanics(t *testing.T) {
	for _, line := range []string{"FROM", "FROM   ", "from"} {
		if got := inspectFile("Dockerfile", "Dockerfile", line+"\n"); len(got) != 0 {
			t.Errorf("%q: want no findings, got %+v", line, got)
		}
	}
}

// ── S7: candidate predicate ────────────────────────────────────────────────

// TestScanRepoCandidatePredicate_CoversEveryInspectFileArm asserts the read
// gate accepts the basename of EVERY `case` arm in inspectFile. If a new rule
// is added without extending scanRepoCandidateBasenames, the rule silently
// stops firing — this test is the tripwire.
func TestScanRepoCandidatePredicate_CoversEveryInspectFileArm(t *testing.T) {
	// One representative basename per case arm, in source order.
	arms := []string{
		".npmrc",
		".yarnrc", ".yarnrc.yml",
		"bunfig.toml", ".bunfig.toml",
		"pip.conf", "pip.ini",
		"requirements.txt", "requirements-dev.txt",
		"pyproject.toml",
		"pom.xml",
		"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
		"nuget.config", "NuGet.Config",
		"config.toml",
		"Gemfile",
		"Podfile",
		"Package.swift",
		"Dockerfile", "Dockerfile.ci",
	}
	for _, base := range arms {
		if !isScanRepoCandidate(base) {
			t.Errorf("isScanRepoCandidate(%q) = false; inspectFile has a case arm for it, so it would never be read", base)
		}
	}

	// Sanity: the predicate must actually exclude something, or it buys no
	// memory back.
	for _, base := range []string{"asset.bin", "main.go", "README.md", "package-lock.json", "yarn.lock"} {
		if isScanRepoCandidate(base) {
			t.Errorf("isScanRepoCandidate(%q) = true; no rule can match it", base)
		}
	}
}

// TestRunScanRepo_SkipsOversizeCandidate pins the size cap: an oversized
// candidate is reported as not-inspected rather than read into memory (and
// rather than silently scanned). Before the cap, this file was read fully,
// copied again by string(data), and produced a finding.
func TestRunScanRepo_SkipsOversizeCandidate(t *testing.T) {
	dir := t.TempDir()
	big := make([]byte, scanRepoMaxFileBytes+1)
	for i := range big {
		big[i] = 'x'
	}
	copy(big, []byte("registry=https://registry.npmjs.org/\n"))
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), big, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var out, errOut strings.Builder
	cmd := newScanRepoTestCmd(&out, &errOut)
	_ = cmd.Flags().Set("json", "true")
	err := runScanRepo(cmd, []string{dir})

	var report scanReport
	if jerr := json.Unmarshal([]byte(out.String()), &report); jerr != nil {
		t.Fatalf("json: %v\n%s", jerr, out.String())
	}
	if len(report.Findings) != 0 {
		t.Errorf("oversize file must not be inspected, got findings %+v", report.Findings)
	}
	if len(report.Unreadable) != 1 || report.Unreadable[0] != ".npmrc" {
		t.Errorf("unreadable = %v, want [.npmrc]", report.Unreadable)
	}
	if !strings.Contains(errOut.String(), "not inspected") {
		t.Errorf("skip must be loud on stderr, got %q", errOut.String())
	}
	if code := scanRepoExitCode(t, err); code != ExitOpError {
		t.Errorf("exit code = %d, want %d (tree is not provably clean)", code, ExitOpError)
	}
}

// ── X1: missing root ───────────────────────────────────────────────────────

// TestRunScanRepo_MissingPathIsOperationalError is the X1 guard. Before the
// fix, `scan-repo /does/not/exist` printed "no bypass files found" and exited
// 0 — a typo in a required CI status check silently disarmed the gate.
//
// The code must be ExitOpError(2), NOT doctorExitDrift(10): 10 means "a bypass
// was found", so a mistyped path would be reported as a security finding.
func TestRunScanRepo_MissingPathIsOperationalError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no", "such", "dir")

	var out, errOut strings.Builder
	cmd := newScanRepoTestCmd(&out, &errOut)
	err := runScanRepo(cmd, []string{missing})

	if code := scanRepoExitCode(t, err); code != ExitOpError {
		t.Fatalf("exit code = %d, want %d", code, ExitOpError)
	}
	if strings.Contains(out.String(), "no bypass files found") {
		t.Errorf("a missing root must not report a clean tree, stdout:\n%s", out.String())
	}
}

// ── X2: unreadable candidate ───────────────────────────────────────────────

// TestRunScanRepo_UnreadableCandidateEscalates is the X2 guard: a candidate
// file the walk cannot read is a rule that could not be evaluated, so it must
// not read as clean.
func TestRunScanRepo_UnreadableCandidateEscalates(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 000 is still readable")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, ".npmrc")
	if err := os.WriteFile(path, []byte("registry=https://registry.npmjs.org/\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Skipf("chmod 000 unsupported here: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	var out, errOut strings.Builder
	cmd := newScanRepoTestCmd(&out, &errOut)
	_ = cmd.Flags().Set("json", "true")
	err := runScanRepo(cmd, []string{dir})

	var report scanReport
	if jerr := json.Unmarshal([]byte(out.String()), &report); jerr != nil {
		t.Fatalf("json: %v\n%s", jerr, out.String())
	}
	if len(report.Unreadable) != 1 || report.Unreadable[0] != ".npmrc" {
		t.Fatalf("unreadable = %v, want [.npmrc]", report.Unreadable)
	}
	if code := scanRepoExitCode(t, err); code != ExitOpError {
		t.Errorf("exit code = %d, want %d", code, ExitOpError)
	}
}

// TestRunScanRepo_CleanTreeJSONHasNoUnreadableKey pins the omitempty
// contract: a clean repo's JSON stays byte-identical to the pre-X2 shape, so
// existing consumers see no new key.
func TestRunScanRepo_CleanTreeJSONHasNoUnreadableKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hi\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var out, errOut strings.Builder
	cmd := newScanRepoTestCmd(&out, &errOut)
	_ = cmd.Flags().Set("json", "true")
	if err := runScanRepo(cmd, []string{dir}); err != nil {
		t.Fatalf("runScanRepo: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal([]byte(out.String()), &generic); err != nil {
		t.Fatalf("json: %v\n%s", err, out.String())
	}
	if _, present := generic["unreadable"]; present {
		t.Errorf("clean tree must not carry an `unreadable` key: %s", out.String())
	}
	if len(generic) != 2 {
		t.Errorf("clean-tree envelope should stay {root, findings}, got %v", generic)
	}
}

// ── S9: --output on the JSON path ──────────────────────────────────────────

// TestRunScanRepo_JSONHonorsOutputFlag: --output is documented as "write
// results to this file instead of stdout"; the JSON branch wrote to
// cmd.OutOrStdout() and created no file.
func TestRunScanRepo_JSONHonorsOutputFlag(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hi\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	outFile := filepath.Join(t.TempDir(), "report.json")

	var out, errOut strings.Builder
	cmd := newScanRepoTestCmd(&out, &errOut)
	_ = cmd.Flags().Set("json", "true")
	_ = cmd.Flags().Set("output", outFile)
	if err := runScanRepo(cmd, []string{dir}); err != nil {
		t.Fatalf("runScanRepo: %v", err)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("--output file not created: %v", err)
	}
	var report scanReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("output file is not the JSON report: %v\n%s", err, data)
	}
	if strings.TrimSpace(out.String()) != "" {
		t.Errorf("with --output set, the command sink must stay empty, got %q", out.String())
	}
}
