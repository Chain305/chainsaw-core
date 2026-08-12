package cli

// C2 — `admission soak clear` must return the same exit code in every output
// format. The existing exit-code tests both set json=false, so the contract was
// unpinned for the machine-readable path CI actually reads: `--json` (and the
// global `--format json`) returned before the resp.Cleared check and exited 0
// while the gate was still failing. A pipeline gating the failurePolicy: Fail
// flip on that code flipped it mid-soak.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newSoakClearTestCmd() *cobra.Command {
	c := &cobra.Command{Use: "clear", RunE: runAdmissionSoakClear}
	c.Flags().Int("days", 0, "")
	c.Flags().Float64("max-deny-rate", -1, "")
	c.Flags().Bool("json", false, "")
	c.Flags().String("format", "", "")
	c.Flags().String("output", "", "")
	return c
}

func TestSoakClear_ExitCodeIsFormatIndependent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"cleared": false,
			"missing": [{"name":"days","met":false,"evidence":"2/7 days observed"}],
			"suggestion": "let it soak a few more days"
		}`))
	}))
	defer srv.Close()

	defer viper.Reset()
	viper.Set("server_url", srv.URL)
	viper.Set("token", "tok")

	cases := []struct {
		name  string
		flags map[string]string
		json  bool
	}{
		{name: "bare"},
		{name: "--json", flags: map[string]string{"json": "true"}, json: true},
		{name: "--format json", flags: map[string]string{"format": "json"}, json: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newSoakClearTestCmd()
			for k, v := range tc.flags {
				if err := cmd.Flags().Set(k, v); err != nil {
					t.Fatalf("set %s: %v", k, err)
				}
			}
			// PrintJSONTo renders to outWriter(cmd) — os.Stdout unless --output
			// names a file. Capture the machine-readable result through --output
			// so the JSON document can be asserted alongside the exit code.
			var resultPath string
			if tc.json {
				resultPath = filepath.Join(t.TempDir(), "soak.json")
				if err := cmd.Flags().Set("output", resultPath); err != nil {
					t.Fatalf("set output: %v", err)
				}
			}
			var out, errb bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&errb)

			err := runAdmissionSoakClear(cmd, nil)
			if err == nil {
				t.Fatalf("a NOT-cleared gate returned nil (exit 0) in %s mode — "+
					"choosing a render format must never weaken the verdict", tc.name)
			}
			var coded *ExitCodeError
			if !errors.As(err, &coded) {
				t.Fatalf("expected *ExitCodeError, got %T: %v", err, err)
			}
			if coded.Code != ExitSoakNotCleared {
				t.Fatalf("exit code = %d, want ExitSoakNotCleared(%d)", coded.Code, ExitSoakNotCleared)
			}
			if tc.json {
				// The JSON document must still be emitted — the gate is applied
				// IN ADDITION to rendering, not instead of it.
				data, rerr := os.ReadFile(resultPath)
				if rerr != nil {
					t.Fatalf("%s mode emitted no JSON result: %v", tc.name, rerr)
				}
				var doc soakClearDTO
				if uerr := json.Unmarshal(data, &doc); uerr != nil {
					t.Fatalf("%s mode did not emit a JSON document (%v): %q",
						tc.name, uerr, string(data))
				}
				if doc.Cleared {
					t.Errorf("rendered document disagrees with the gate: %+v", doc)
				}
			}
		})
	}
}

// TestSoakClear_ClearedIsZeroInEveryFormat is the negative control: the fix
// must not turn a PASSING gate into a failure in JSON mode.
func TestSoakClear_ClearedIsZeroInEveryFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"cleared": true, "kubectl_patch": "kubectl patch ... failurePolicy=Fail"}`))
	}))
	defer srv.Close()

	defer viper.Reset()
	viper.Set("server_url", srv.URL)
	viper.Set("token", "tok")

	for _, flags := range []map[string]string{nil, {"json": "true"}, {"format": "json"}} {
		cmd := newSoakClearTestCmd()
		for k, v := range flags {
			if err := cmd.Flags().Set(k, v); err != nil {
				t.Fatalf("set %s: %v", k, err)
			}
		}
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		if err := runAdmissionSoakClear(cmd, nil); err != nil {
			t.Fatalf("cleared gate returned %v with flags %v; want nil", err, flags)
		}
	}
}
