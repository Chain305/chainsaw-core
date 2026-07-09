package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestRunGuardUpdate_NoTokenStillUsesPublicFeed verifies `guard update` is not
// account-gated: with no token resolvable, the command still enters the public
// OpenSSF sync path. The context is canceled so the test never downloads the
// real dataset.
func TestRunGuardUpdate_NoTokenStillUsesPublicFeed(t *testing.T) {
	// Isolated config + empty file cred store ⇒ cfgToken() resolves to "".
	withIsolatedConfigHome(t)
	withFileCredStore(t)

	dst := filepath.Join(t.TempDir(), "known_malicious.json")
	t.Setenv(guardDBEnv, dst)

	var stderr bytes.Buffer
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	err := runGuardUpdate(cmd, nil)
	_ = w.Close()
	os.Stderr = oldStderr
	_, _ = stderr.ReadFrom(r)

	if err == nil {
		t.Fatal("expected canceled public fetch to error, got nil")
	}
	if strings.Contains(err.Error(), "free account") || strings.Contains(err.Error(), "signed in") {
		t.Fatalf("guard update should no longer be auth-gated, got error: %v", err)
	}
	if strings.Contains(stderr.String(), "auth login") || strings.Contains(stderr.String(), "Sign up") {
		t.Fatalf("stderr should not ask for auth, got:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "fetching the OpenSSF malicious-packages dataset") {
		t.Fatalf("stderr should show public OpenSSF fetch started, got:\n%s", stderr.String())
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Fatalf("cache file must not be written after canceled fetch; stat err = %v", statErr)
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{10 * 1048576, "10.0 MB"},
		{1073741824, "1.0 GB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.n); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

// TestNewGuardUpdateProgress_NonTTYHeartbeat verifies the non-interactive
// progress path emits a coarse heartbeat (every ~16 MB) rather than one line
// per read — so CI logs show liveness without thousands of lines.
func TestNewGuardUpdateProgress_NonTTYHeartbeat(t *testing.T) {
	const mb = 1 << 20
	var buf bytes.Buffer
	fn := newGuardUpdateProgress(&buf, false)

	// 40 MB of growth in 1 MB steps crosses the 16 MB and 32 MB thresholds:
	// exactly two heartbeats, each on its own line.
	for i := 0; i <= 40; i++ {
		fn(int64(i) * mb)
	}

	lines := strings.Count(buf.String(), "\n")
	if lines != 2 {
		t.Fatalf("expected 2 heartbeat lines, got %d:\n%s", lines, buf.String())
	}
	if strings.Contains(buf.String(), "\r") {
		t.Errorf("non-TTY path must not emit carriage returns:\n%q", buf.String())
	}
}

// TestNewGuardUpdateProgress_TTYRewritesLine verifies the interactive path uses
// a carriage return to rewrite one line, never appending newlines.
func TestNewGuardUpdateProgress_TTYRewritesLine(t *testing.T) {
	var buf bytes.Buffer
	fn := newGuardUpdateProgress(&buf, true)
	fn(1024)
	fn(2048)
	if got := buf.String(); !strings.HasPrefix(got, "\r") || strings.Contains(got, "\n") {
		t.Fatalf("TTY path should rewrite a single line via \\r and emit no newline, got %q", got)
	}
}
