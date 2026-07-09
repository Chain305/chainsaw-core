package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestReportLogResult covers the empty-output disambiguation:
//   - read==0 → couldn't read any logs (wrong target / empty window) → error
//   - read>0 && kept==0 → logs read but nothing matched → explicit note, no error
//   - read>0 && kept>0 → matches printed → nothing extra, no error
func TestReportLogResult(t *testing.T) {
	newCmd := func() (*cobra.Command, *bytes.Buffer) {
		c := &cobra.Command{}
		var errb bytes.Buffer
		c.SetErr(&errb)
		return c, &errb
	}

	t.Run("no lines read is an error", func(t *testing.T) {
		c, _ := newCmd()
		if err := reportLogResult(c, 0, 0, "warn+", "deploy/chainsaw-proxy"); err == nil {
			t.Fatal("read==0 must return a non-nil error (couldn't read any logs)")
		}
	})

	t.Run("read but none matched notes and succeeds", func(t *testing.T) {
		c, errb := newCmd()
		if err := reportLogResult(c, 42, 0, "warn+", "stdin"); err != nil {
			t.Fatalf("read>0,kept==0 must succeed, got: %v", err)
		}
		if !strings.Contains(errb.String(), "no lines at or above") {
			t.Fatalf("expected an all-clear note on stderr, got: %q", errb.String())
		}
	})

	t.Run("matches present is silent success", func(t *testing.T) {
		c, errb := newCmd()
		if err := reportLogResult(c, 42, 3, "warn+", "stdin"); err != nil {
			t.Fatalf("read>0,kept>0 must succeed, got: %v", err)
		}
		if errb.String() != "" {
			t.Fatalf("matches present should emit no extra note, got: %q", errb.String())
		}
	})
}
