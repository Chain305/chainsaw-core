package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/malware"
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
	// Hermetic: `guard update` now refuses under the offline umbrella, so an
	// exported CHAINSAW_OFFLINE=1 would make this assert on the wrong stderr.
	t.Setenv(guardUpdateOfflineEnv, "")

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

// TestRunGuardUpdateRefusesUnderOfflineUmbrella pins X7: `guard update` is the
// guard's ONLY networked command, so CHAINSAW_OFFLINE must stop it before it
// dials — an air-gapped box should get a clear refusal, not a DNS error against
// a procurement claim that says nothing leaves the network.
//
// The refusal must name BOTH ways forward. CHAINSAW_OFFLINE is also documented
// as a telemetry kill switch, so someone who set it for THAT reason still needs
// their malware feed: --allow-network for a box with egress, a signed bundle (or
// a pre-populated cache file) for one without. A bare refusal would be a
// baffling wall, and net-negative.
func TestRunGuardUpdateRefusesUnderOfflineUmbrella(t *testing.T) {
	withIsolatedConfigHome(t)
	dst := filepath.Join(t.TempDir(), "known_malicious.json")
	t.Setenv(guardDBEnv, dst)

	// The tolerant truthy parse (G9) is part of the contract: these are all
	// "offline" to intelligence.IsOffline and coverage.isTruthy too.
	for _, value := range []string{"1", "true", "Yes", "ON", " 1 "} {
		t.Setenv(guardUpdateOfflineEnv, value)
		cmd := newGuardUpdateTestCmd(false)
		err := runGuardUpdate(cmd, nil)
		if err == nil {
			t.Fatalf("%s=%q: want a refusal, got nil", guardUpdateOfflineEnv, value)
		}
		msg := err.Error()
		for _, want := range []string{guardUpdateOfflineEnv, "--allow-network", "CHAINSAW_INTEL_BUNDLE_PATH"} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s=%q: refusal should name %q, got: %v", guardUpdateOfflineEnv, value, want, msg)
			}
		}
		if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
			t.Fatalf("nothing should be written on a refusal; stat err = %v", statErr)
		}
	}

	// A non-truthy value is not the umbrella: the command proceeds (and then
	// fails on the canceled fetch, not on the offline check).
	t.Setenv(guardUpdateOfflineEnv, "0")
	if err := runGuardUpdate(newGuardUpdateTestCmd(false), nil); err == nil ||
		strings.Contains(err.Error(), "--allow-network") {
		t.Fatalf("CHAINSAW_OFFLINE=0 must not refuse, got: %v", err)
	}
}

// --allow-network is the escape hatch: offline set, flag passed, the fetch runs
// (and here fails only because the context is already canceled).
func TestRunGuardUpdateAllowNetworkOverridesOffline(t *testing.T) {
	withIsolatedConfigHome(t)
	t.Setenv(guardDBEnv, filepath.Join(t.TempDir(), "known_malicious.json"))
	t.Setenv(guardUpdateOfflineEnv, "1")

	var stderr bytes.Buffer
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	err := runGuardUpdate(newGuardUpdateTestCmd(true), nil)
	_ = w.Close()
	os.Stderr = oldStderr
	_, _ = stderr.ReadFrom(r)

	if err == nil || strings.Contains(err.Error(), "--allow-network") {
		t.Fatalf("--allow-network should proceed past the offline check, got: %v", err)
	}
	if !strings.Contains(stderr.String(), "fetching the OpenSSF malicious-packages dataset") {
		t.Fatalf("--allow-network should reach the fetch, stderr:\n%s", stderr.String())
	}
}

// newGuardUpdateTestCmd builds a cobra command carrying guard update's flags
// with an already-canceled context, so the fetch never leaves the machine.
func newGuardUpdateTestCmd(allowNetwork bool) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().Bool("force", false, "")
	cmd.Flags().Bool("allow-network", allowNetwork, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd.SetContext(ctx)
	return cmd
}

// TestRunGuardUpdate_SlowLinkIsNotKilledByACommandDeadline is BUG-04 at the
// CLI entry point. The first fix (v0.22.1) repaired core/malware and tested
// the Syncer directly, so it never saw the 5-minute context.WithTimeout that
// runGuardUpdate wrapped around the whole command — which capped the syncer's
// own 1h ceiling and killed a progressing ~46 MB download on a slow link.
//
// Two halves, because a real 5-minute deadline cannot be waited out in a unit
// test:
//   - the context that reaches the syncer must carry no deadline of its own
//     (cmd.Context() has none here) — this catches the literal 5-minute
//     WithTimeout coming back, instantly;
//   - a valid tarball streamed slowly but steadily must still produce a cache
//     file. With a scaled-down stand-in deadline (shorter than the ~450ms
//     drip) restored in runGuardUpdate, this half fails the same way the
//     vendor's run did.
func TestRunGuardUpdate_SlowLinkIsNotKilledByACommandDeadline(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	t.Setenv(guardUpdateOfflineEnv, "")
	dst := filepath.Join(t.TempDir(), "known_malicious.json")
	t.Setenv(guardDBEnv, dst)

	body := slowLinkTarball(t)
	const chunks = 10
	const interval = 50 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-gzip")
		step := (len(body) + chunks - 1) / chunks
		for off := 0; off < len(body); off += step {
			time.Sleep(interval)
			_, _ = w.Write(body[off:min(off+step, len(body))])
			w.(http.Flusher).Flush()
		}
	}))
	defer srv.Close()
	oldURL := malware.TarballURL
	malware.TarballURL = srv.URL
	defer func() { malware.TarballURL = oldURL }()

	oldSync := syncGuardDataset
	syncGuardDataset = func(s *malware.Syncer, ctx context.Context) error {
		if dl, ok := ctx.Deadline(); ok {
			t.Errorf("guard update handed the syncer a context with its own deadline (%v from now); "+
				"that caps the syncer's 1h refresh ceiling and is BUG-04", time.Until(dl).Round(time.Second))
		}
		return oldSync(s, ctx)
	}
	defer func() { syncGuardDataset = oldSync }()

	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	var stderr bytes.Buffer
	done := make(chan struct{})
	go func() { _, _ = stderr.ReadFrom(r); close(done) }()

	cmd := &cobra.Command{}
	cmd.Flags().Bool("force", false, "")
	cmd.Flags().Bool("allow-network", false, "")
	cmd.SetContext(context.Background())
	start := time.Now()
	err := runGuardUpdate(cmd, nil)
	elapsed := time.Since(start)
	_ = w.Close()
	os.Stderr = oldStderr
	<-done

	if err != nil {
		t.Fatalf("slow-but-steady download failed after %v: %v\nstderr:\n%s", elapsed, err, stderr.String())
	}
	if elapsed < chunks*interval {
		t.Fatalf("finished in %v, faster than the %v drip: the test no longer exercises a slow link", elapsed, chunks*interval)
	}
	if fi, statErr := os.Stat(dst); statErr != nil || fi.Size() == 0 {
		t.Fatalf("cache not written: %v", statErr)
	}
}

// slowLinkTarball is a minimal OpenSSF-shaped dataset: one npm advisory.
func slowLinkTarball(t *testing.T) []byte {
	t.Helper()
	const entry = `{"id":"MAL-2024-0002","summary":"malicious npm package","modified":"2024-01-01T00:00:00Z",` +
		`"affected":[{"package":{"name":"evil-pkg","ecosystem":"npm"}}]}`
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	root := "malicious-packages-abc1234/"
	for _, d := range []string{"", "osv/", "osv/malicious/", "osv/malicious/npm/", "osv/malicious/npm/evil-pkg/"} {
		if err := tw.WriteHeader(&tar.Header{Name: root + d, Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
	}
	name := root + "osv/malicious/npm/evil-pkg/MAL-2024-0002.json"
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(entry))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(entry)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
