package cli

// C13 — `pkg list --repo <name>` interpolated a user flag straight into a URL
// path segment ("/api/repos/" + repo + "/packages") while the sibling call
// sites in the same file already built a url.Values.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/spf13/cobra"
)

func TestPkgList_RepoNameIsPathEscaped(t *testing.T) {
	var mu sync.Mutex
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath = r.URL.EscapedPath()
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"repository":"x","packages":[]}`))
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := &cobra.Command{Use: "list"}
	cmd.Flags().String("repo", "", "")
	cmd.Flags().String("ecosystem", "", "")
	cmd.Flags().Int("limit", 50, "")
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("format", "", "")
	cmd.Flags().String("output", "", "")
	if err := cmd.Flags().Set("repo", "team/private"); err != nil {
		t.Fatalf("set repo: %v", err)
	}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	if err := runPkgList(cmd, nil); err != nil {
		t.Fatalf("runPkgList: %v", err)
	}

	mu.Lock()
	got := gotPath
	mu.Unlock()
	if want := "/api/repos/team%2Fprivate/packages"; got != want {
		t.Errorf("request path = %q, want %q (repo name must be path-escaped)", got, want)
	}
}
