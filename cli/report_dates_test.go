package cli

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// decodeQueryForTest parses a recorded raw query so assertions compare VALUES
// rather than url.Values' percent-escaping rules.
func decodeQueryForTest(t *testing.T, raw string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatalf("recorded query %q is not parseable: %v", raw, err)
	}
	return v
}

// reportCmdForTest builds a bare cobra command carrying the flag set the
// `report` runners read, wired to a server that records the query string it
// was called with. The recorder is what makes "what actually went on the wire"
// assertable — the defect being pinned is a WIRE-FORMAT one, so asserting on
// rendered output would miss it entirely.
func reportCmdForTest(t *testing.T, run func(*cobra.Command, []string) error, gotQuery *string) *cobra.Command {
	t.Helper()

	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		*gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	prevURL := viper.GetString("server_url")
	prevTok := viper.GetString("token")
	viper.Set("server_url", srv.URL)
	viper.Set("token", "test-token")
	t.Cleanup(func() {
		viper.Set("server_url", prevURL)
		viper.Set("token", prevTok)
	})

	cmd := &cobra.Command{Use: "r", RunE: run}
	cmd.Flags().String("format", "table", "")
	cmd.Flags().String("output", "", "")
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("ecosystem", "", "")
	cmd.Flags().String("start", "", "")
	cmd.Flags().String("end", "", "")
	cmd.Flags().String("since", "", "")
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(nil)
	return cmd
}

// L-24. `report exposure` and `report sla` parsed their date flags with a bare
// time.Parse(time.RFC3339) and wrapped the failure with %w, so a user who
// typed the obvious thing got Go's internal layout constant read back at them:
//
//	--start must be RFC3339: parsing time "2026-01-01" as
//	"2006-01-02T15:04:05Z07:00": cannot parse "" as "T"
//
// `audit view` had already solved this — parseDate takes either form and says
// so in words — so these now route through it.
func TestReportDates_BareDateIsAccepted(t *testing.T) {
	t.Run("exposure: start anchors to midnight, end extends past the named day", func(t *testing.T) {
		var query string
		cmd := reportCmdForTest(t, runReportExposure, &query)
		_ = cmd.Flags().Set("start", "2026-01-01")
		_ = cmd.Flags().Set("end", "2026-04-30")

		if err := runReportExposure(cmd, nil); err != nil {
			t.Fatalf("bare dates must be accepted: %v", err)
		}
		// NEXT-DAY MIDNIGHT, not 23:59:59. The server window is half-open --
		// internal/reports/exposure.go:9-10 documents End as EXCLUSIVE -- so
		// only 2026-05-01T00:00:00Z covers the whole of the 30th. 23:59:59
		// would drop that final second, reintroducing a smaller version of
		// the off-by-one this flag already had. Deliberately NOT the same
		// arithmetic as `audit view --end`, which subtracts a second because
		// it filters an already-fetched slice with an inclusive compare.
		if want := "end=2026-05-01T00%3A00%3A00Z"; !strings.Contains(query, want) {
			t.Errorf("--end 2026-04-30 must reach the server as 2026-05-01T00:00:00Z (exclusive bound); query=%q", query)
		}
		if want := "start=2026-01-01T00%3A00%3A00Z"; !strings.Contains(query, want) {
			t.Errorf("--start 2026-01-01 must reach the server as 00:00:00Z; query=%q", query)
		}
	})

	t.Run("sla: since anchors to midnight", func(t *testing.T) {
		var query string
		cmd := reportCmdForTest(t, runReportSLA, &query)
		_ = cmd.Flags().Set("since", "2026-01-01")

		if err := runReportSLA(cmd, nil); err != nil {
			t.Fatalf("bare date must be accepted: %v", err)
		}
		// --since is an at-or-AFTER bound, so a bare date takes the START of
		// the day. Extending it would move the bound a day forward and hide
		// results, which is the opposite of what --end needs.
		if want := "since=2026-01-01T00%3A00%3A00Z"; !strings.Contains(query, want) {
			t.Errorf("--since 2026-01-01 must reach the server as 00:00:00Z; query=%q", query)
		}
	})
}

// An explicit RFC3339 stamp means exactly what it says. It is forwarded
// BYTE-FOR-BYTE rather than round-tripped through time.Format, which would
// drop fractional seconds and rewrite the offset — editing a value the
// operator stated precisely, in a compliance export, with no indication.
// This is the same C6 reasoning parseDate's dateOnly return exists to serve.
func TestReportDates_ExplicitRFC3339PassesThroughUnchanged(t *testing.T) {
	cases := []struct {
		name  string
		start string
		end   string
	}{
		{"utc", "2026-01-01T00:00:00Z", "2026-04-30T00:00:00Z"},
		{"offset", "2026-01-01T09:30:00+04:00", "2026-04-30T17:45:12-07:00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var query string
			cmd := reportCmdForTest(t, runReportExposure, &query)
			_ = cmd.Flags().Set("start", tc.start)
			_ = cmd.Flags().Set("end", tc.end)

			if err := runReportExposure(cmd, nil); err != nil {
				t.Fatalf("run: %v", err)
			}
			// Decode rather than compare escaped forms, so the assertion is
			// about the VALUE and not about url.Values' escaping rules.
			q := decodeQueryForTest(t, query)
			if q.Get("start") != tc.start {
				t.Errorf("--start was rewritten: got %q, want %q", q.Get("start"), tc.start)
			}
			if q.Get("end") != tc.end {
				t.Errorf("--end was rewritten: got %q, want %q", q.Get("end"), tc.end)
			}
		})
	}
}

// THE ACTUAL DEFECT, stated as a negative assertion. The old error wrapped
// Go's parse failure with %w, which put the layout constant "2006-01-02T15:04:
// 05Z07:00" in front of a user who has no reason to know it is a Go idiom and
// every reason to read it as a date they were supposed to type. The positive
// half (does the message name the accepted forms) is worth little without it:
// a message can name YYYY-MM-DD and still trail the layout dump behind a colon.
func TestReportDates_ErrorNamesTheFormatWithoutLeakingTheGoLayout(t *testing.T) {
	runs := []struct {
		name string
		run  func(*cobra.Command, []string) error
		flag string
		val  string
	}{
		{"exposure/start", runReportExposure, "start", "01/02/2026"},
		{"exposure/end", runReportExposure, "end", "not-a-date"},
		{"sla/since", runReportSLA, "since", "last tuesday"},
	}
	for _, tc := range runs {
		t.Run(tc.name, func(t *testing.T) {
			var query string
			cmd := reportCmdForTest(t, tc.run, &query)
			// exposure needs both ends set; fill the other with a valid one.
			if tc.flag != "since" {
				_ = cmd.Flags().Set("start", "2026-01-01")
				_ = cmd.Flags().Set("end", "2026-04-30")
			}
			_ = cmd.Flags().Set(tc.flag, tc.val)

			err := tc.run(cmd, nil)
			if err == nil {
				t.Fatalf("--%s %q must be rejected", tc.flag, tc.val)
			}
			msg := err.Error()
			if !strings.Contains(msg, "YYYY-MM-DD") {
				t.Errorf("error must name the accepted date form, got %q", msg)
			}
			if !strings.Contains(msg, "RFC3339") {
				t.Errorf("error must name the accepted timestamp form, got %q", msg)
			}
			if !strings.Contains(msg, "--"+tc.flag) {
				t.Errorf("error must name the flag that was wrong, got %q", msg)
			}
			if strings.Contains(msg, "2006-01-02") {
				t.Errorf("error leaks the Go layout constant at the user: %q", msg)
			}
		})
	}
}

// The "both are required" message is the FIRST thing a user of `report
// exposure` sees, and it named only RFC3339 — so the message that teaches the
// format taught the narrower one.
func TestReportExposure_RequiredErrorNamesBothForms(t *testing.T) {
	var query string
	cmd := reportCmdForTest(t, runReportExposure, &query)

	err := runReportExposure(cmd, nil)
	if err == nil {
		t.Fatal("--start and --end are required")
	}
	for _, want := range []string{"RFC3339", "YYYY-MM-DD"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("required-flag error must name %s, got %q", want, err.Error())
		}
	}
}
