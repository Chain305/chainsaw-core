package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/doctor"
)

// requireConventionalPortsFree skips the calling test when any of the
// conventional proxy ports the doctor binds (doctor.DefaultServerPorts) is
// already held by another process. The "all green" doctor checks assert those
// ports are bindable, so a busy port on a dev machine (commonly :8080) would
// otherwise produce a spurious failure. A clean CI runner has them free.
func requireConventionalPortsFree(t *testing.T) {
	t.Helper()
	for _, p := range doctor.DefaultServerPorts {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			t.Skipf("conventional proxy port %d is in use in this environment; skipping all-green doctor check", p)
		}
		_ = l.Close()
	}
}

// captureExit swaps in a test-friendly exit hook for the duration
// of t. The original hook is restored by t.Cleanup.
func captureExit(t *testing.T) *int {
	t.Helper()
	var code int
	prev := doctorExitOverride
	doctorExitOverride = func(c int) { code = c }
	t.Cleanup(func() { doctorExitOverride = prev })
	return &code
}

func TestDoctorUpgradeCheck_AllGreen_Exit0(t *testing.T) {
	requireConventionalPortsFree(t)
	code := captureExit(t)

	dir := t.TempDir()
	// seed a proper data dir with correct perms
	for _, name := range []string{"generated_password", "generated_jwt_secret"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x\n"), 0o400); err != nil {
			t.Fatalf("seed: %v", err)
		}
		_ = os.Chmod(p, 0o400)
	}

	t.Setenv("CHAINSAW_DATABASE_URL", "postgres://x")
	t.Setenv("CHAINSAW_STRICT_JWT", "1")
	t.Setenv("CHAINSAW_FLAGS", "")

	cmd := newDoctorCmd()
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("no-color", true, "")
	_ = cmd.Flags().Set("upgrade-check", "true")
	_ = cmd.Flags().Set("skip-network", "true")
	_ = cmd.Flags().Set("data-dir", dir)

	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
	}

	text := out.String()
	if !strings.Contains(text, "safe to upgrade") {
		t.Fatalf("expected 'safe to upgrade' verdict, got: %s", text)
	}
	if *code != 0 {
		t.Fatalf("exit code = %d, want 0", *code)
	}
}

func TestDoctorUpgradeCheck_BreakingFlag_Exit2(t *testing.T) {
	code := captureExit(t)

	t.Setenv("CHAINSAW_DATABASE_URL", "postgres://x")
	t.Setenv("CHAINSAW_STRICT_JWT", "1")
	t.Setenv("CHAINSAW_FLAGS", "--embedded-ui")

	cmd := newDoctorCmd()
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("no-color", true, "")
	_ = cmd.Flags().Set("upgrade-check", "true")
	_ = cmd.Flags().Set("skip-network", "true")

	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
	}

	if *code != 2 {
		t.Fatalf("exit code = %d, want 2 (breaking), output:\n%s", *code, out.String())
	}
	if !strings.Contains(out.String(), "DO NOT UPGRADE") {
		t.Fatalf("expected 'DO NOT UPGRADE' verdict, got: %s", out.String())
	}
}

func TestDoctorUpgradeCheck_Warning_Exit1(t *testing.T) {
	code := captureExit(t)

	dir := t.TempDir()
	// Intentionally leave CHAINSAW_STRICT_JWT unset — env-flip is
	// the warning driver here.
	t.Setenv("CHAINSAW_DATABASE_URL", "postgres://x")
	_ = os.Unsetenv("CHAINSAW_STRICT_JWT")
	t.Setenv("CHAINSAW_FLAGS", "")

	cmd := newDoctorCmd()
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("no-color", true, "")
	_ = cmd.Flags().Set("upgrade-check", "true")
	_ = cmd.Flags().Set("skip-network", "true")
	_ = cmd.Flags().Set("data-dir", dir)

	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
	}

	if *code != 1 {
		t.Fatalf("exit code = %d, want 1 (warn), output:\n%s", *code, out.String())
	}
}

func TestDoctorUpgradeCheck_JSON(t *testing.T) {
	_ = captureExit(t)

	dir := t.TempDir()
	t.Setenv("CHAINSAW_DATABASE_URL", "postgres://x")
	t.Setenv("CHAINSAW_STRICT_JWT", "1")
	t.Setenv("CHAINSAW_FLAGS", "")

	cmd := newDoctorCmd()
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("no-color", true, "")
	_ = cmd.Flags().Set("upgrade-check", "true")
	_ = cmd.Flags().Set("skip-network", "true")
	_ = cmd.Flags().Set("data-dir", dir)
	_ = cmd.Flags().Set("json", "true")

	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
	}

	var report doctor.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, out.String())
	}
	if len(report.Findings) == 0 {
		t.Fatalf("expected >= 1 finding, got 0")
	}
	for _, f := range report.Findings {
		if f.SeverityName == "" {
			t.Errorf("finding %q missing severity in JSON", f.Check)
		}
	}
}

func TestDoctorUpgradeCheck_Fix_GeneratesJWTSecret(t *testing.T) {
	_ = captureExit(t)

	dir := t.TempDir()
	// Unset CHAINSAW_STRICT_JWT to trigger the env-flip warning,
	// which the --fix path translates into "seed a generated_jwt_secret".
	_ = os.Unsetenv("CHAINSAW_STRICT_JWT")
	t.Setenv("CHAINSAW_DATABASE_URL", "postgres://x")
	t.Setenv("CHAINSAW_FLAGS", "")

	cmd := newDoctorCmd()
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("no-color", true, "")
	_ = cmd.Flags().Set("fix", "true")
	_ = cmd.Flags().Set("skip-network", "true")
	_ = cmd.Flags().Set("data-dir", dir)

	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
	}

	secretPath := filepath.Join(dir, "generated_jwt_secret")
	fi, err := os.Stat(secretPath)
	if err != nil {
		t.Fatalf("expected generated_jwt_secret at %s after --fix: %v\noutput:\n%s", secretPath, err, out.String())
	}
	if fi.Mode().Perm() != 0o400 {
		t.Errorf("generated_jwt_secret mode = %04o, want 0400", fi.Mode().Perm())
	}
	data, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(strings.TrimSpace(string(data))) < 20 {
		t.Errorf("generated secret looks too short: %q", string(data))
	}
}

func TestDoctorHelp_MentionsUpgradeCheck(t *testing.T) {
	cmd := newDoctorCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("help: %v", err)
	}
	// Note: --json is a persistent flag on rootCmd, not on newDoctorCmd()
	// in isolation. End-to-end invocations inherit it; the help body
	// itself lists the doctor-local flags.
	for _, want := range []string{"--upgrade-check", "--fix", "MIGRATIONS.md"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("--help missing %q", want)
		}
	}
}
