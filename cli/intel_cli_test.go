package cli

// X11 — the whole intel tree named the wrong command in its server-required
// error ("'chainsaw' is a server-required command", and because
// trimChainsaw("chainsaw") is a no-op the suggested fix read
// "chainsaw --server <url> chainsaw ...").
// X12 — `intel scan --lockfile` dispatched on BASENAME and never opened the
// file, so a valid npm lockfile under another name was rejected as
// "unsupported", and a missing path exited 4 instead of 2.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestNewV1Client_NamesTheCommand(t *testing.T) {
	prevURL := viper.GetString("server_url")
	viper.Set("server_url", "")
	t.Cleanup(func() { viper.Set("server_url", prevURL) })

	root := &cobra.Command{Use: "chainsaw"}
	intel := &cobra.Command{Use: "intel"}
	scan := &cobra.Command{Use: "scan"}
	intel.AddCommand(scan)
	root.AddCommand(intel)

	_, err := newV1Client(scan)
	if err == nil {
		t.Fatal("expected a server-not-configured error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "'chainsaw intel scan' is a server-required command") {
		t.Errorf("error should name the actual command; got:\n%s", msg)
	}
	if strings.Contains(msg, "chainsaw --server <url> chainsaw ") {
		t.Errorf("the one-shot hint still duplicates the binary name:\n%s", msg)
	}
	if !strings.Contains(msg, "chainsaw --server <url> intel scan") {
		t.Errorf("the one-shot hint should name the subcommand path:\n%s", msg)
	}
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != ExitConfigAuth {
		t.Errorf("want ExitConfigAuth, got %v", err)
	}
}

func TestLockfileTypeFromContent(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"npm v3", `{"name":"app","lockfileVersion":3,"packages":{}}`, "npm"},
		{"npm v1", `{"dependencies":{"chalk":{"version":"4.1.2"}}}`, "npm"},
		{"pnpm", "lockfileVersion: '6.0'\n\nsettings:\n  autoInstallPeers: true\n", "pnpm"},
		{"pnpm with comment", "# generated\nlockfileVersion: '9.0'\n", "pnpm"},
		{"unrelated json", `{"hello":"world"}`, ""},
		{"yaml but not a lockfile", "name: app\nversion: 1\n", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		if got := lockfileTypeFromContent([]byte(tc.body)); got != tc.want {
			t.Errorf("%s: lockfileTypeFromContent = %q, want %q", tc.name, got, tc.want)
		}
	}
	// BOM-prefixed npm lockfile still identifies.
	bom := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"lockfileVersion":3,"packages":{}}`)...)
	if got := lockfileTypeFromContent(bom); got != "npm" {
		t.Errorf("BOM-prefixed lockfile: got %q, want npm", got)
	}
}

func newIntelScanTestCmd() *cobra.Command {
	c := &cobra.Command{Use: "scan", RunE: runIntelScan}
	c.Flags().String("lockfile", "", "")
	c.Flags().Bool("json", false, "")
	c.Flags().String("format", "", "")
	c.Flags().String("output", "", "")
	c.SetOut(&bytes.Buffer{})
	c.SetErr(&bytes.Buffer{})
	return c
}

// TestIntelScan_MissingLockfileIsOpError: a nonexistent path used to yield
// ExitUsage(4) here while scan-actions / sbom diff / bundle verify all return
// ExitOpError(2) for the same condition.
func TestIntelScan_MissingLockfileIsOpError(t *testing.T) {
	cmd := newIntelScanTestCmd()
	missing := filepath.Join(t.TempDir(), "package-lock.json")
	if err := cmd.Flags().Set("lockfile", missing); err != nil {
		t.Fatalf("set lockfile: %v", err)
	}
	err := runIntelScan(cmd, nil)
	if err == nil {
		t.Fatal("expected an error for a missing lockfile")
	}
	var coded *ExitCodeError
	if !errors.As(err, &coded) {
		t.Fatalf("expected *ExitCodeError, got %T: %v", err, err)
	}
	if coded.Code != ExitOpError {
		t.Errorf("exit code = %d, want ExitOpError(%d)", coded.Code, ExitOpError)
	}
}

// TestIntelScan_RenamedLockfileIsAccepted: a genuine npm lockfile under another
// basename used to be rejected as "unsupported lockfile" without the file ever
// being opened. It should now get past detection and fail only on the missing
// server, proving the content was read and identified.
func TestIntelScan_RenamedLockfileIsAccepted(t *testing.T) {
	prevURL := viper.GetString("server_url")
	viper.Set("server_url", "")
	t.Cleanup(func() { viper.Set("server_url", prevURL) })

	path := filepath.Join(t.TempDir(), "npm-lock-backup.json")
	if err := os.WriteFile(path, []byte(`{"name":"app","lockfileVersion":3,"packages":{"":{"version":"1.0.0"}}}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cmd := newIntelScanTestCmd()
	if err := cmd.Flags().Set("lockfile", path); err != nil {
		t.Fatalf("set lockfile: %v", err)
	}
	err := runIntelScan(cmd, nil)
	if err == nil {
		t.Fatal("expected the server-not-configured error (detection should have succeeded)")
	}
	if strings.Contains(err.Error(), "unsupported lockfile") {
		t.Fatalf("a valid npm lockfile was rejected on its filename alone: %v", err)
	}
	if !strings.Contains(err.Error(), "server URL not configured") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestIntelScan_TrulyUnsupportedStillUsage is the negative control: a file that
// is neither an npm nor a pnpm lockfile must still be a usage error.
func TestIntelScan_TrulyUnsupportedStillUsage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(path, []byte("just some notes\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cmd := newIntelScanTestCmd()
	if err := cmd.Flags().Set("lockfile", path); err != nil {
		t.Fatalf("set lockfile: %v", err)
	}
	err := runIntelScan(cmd, nil)
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != ExitUsage {
		t.Fatalf("want ExitUsage(%d) for unrecognised content, got %v", ExitUsage, err)
	}
}
