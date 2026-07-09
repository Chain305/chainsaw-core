package cli

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// TestSoakClear_NotCleared_ReturnsExitSoakNotCleared pins the renumber: a
// not-cleared soak gate must return ExitCodeError{Code: ExitSoakNotCleared(10)}
// so it no longer collides with ExitConfigAuth(3).
func TestSoakClear_NotCleared_ReturnsExitSoakNotCleared(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"cleared": false,
			"missing": [{"name":"days","met":false,"evidence":"2/7 days observed"}],
			"suggestion": "let it soak a few more days"
		}`))
	}))
	defer srv.Close()

	// Point the client at the test server via viper (newClient reads cfg*).
	defer viper.Reset()
	viper.Set("server_url", srv.URL)
	viper.Set("token", "tok")

	cmd := &cobra.Command{}
	cmd.Flags().Int("days", 0, "")
	cmd.Flags().Float64("max-deny-rate", -1, "")
	cmd.Flags().Bool("json", false, "")
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)

	err := runAdmissionSoakClear(cmd, nil)
	if err == nil {
		t.Fatal("expected a not-cleared error, got nil")
	}
	var coded *ExitCodeError
	if !errors.As(err, &coded) {
		t.Fatalf("expected *ExitCodeError, got %T: %v", err, err)
	}
	if coded.Code != ExitSoakNotCleared {
		t.Fatalf("soak-not-cleared exit code = %d; want ExitSoakNotCleared(%d)", coded.Code, ExitSoakNotCleared)
	}
	if coded.Code == ExitConfigAuth {
		t.Fatalf("soak exit code still collides with ExitConfigAuth(3)")
	}
	if errb.Len() == 0 {
		t.Error("expected missing-criteria output on stderr")
	}
}

// TestSoakClear_Cleared_ExitZero proves the happy path returns nil (exit 0) and
// prints the kubectl patch to stdout.
func TestSoakClear_Cleared_ExitZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"cleared": true, "kubectl_patch": "kubectl patch ... failurePolicy=Fail"}`))
	}))
	defer srv.Close()

	defer viper.Reset()
	viper.Set("server_url", srv.URL)
	viper.Set("token", "tok")

	cmd := &cobra.Command{}
	cmd.Flags().Int("days", 0, "")
	cmd.Flags().Float64("max-deny-rate", -1, "")
	cmd.Flags().Bool("json", false, "")
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	if err := runAdmissionSoakClear(cmd, nil); err != nil {
		t.Fatalf("cleared gate should return nil (exit 0), got: %v", err)
	}
	if got := out.String(); got == "" {
		t.Error("expected kubectl patch on stdout for a cleared gate")
	}
}
