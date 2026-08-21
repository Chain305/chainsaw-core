package cli

// auth_status_sliding_expiry_test.go covers the client half of L-10's
// sliding window: once a CLI key's expiry EXTENDS ON USE, the countdown
// wording shipped in v0.20.8 stops being true.
//
// "expires in 90 days" is wrong for a sliding key in the most confusing way
// available: `auth status` is itself an authenticated request, so by the time
// the number is printed the clock it describes has already been reset. A user
// who reads it as a deadline will re-login for no reason; a user who watches
// it never move will conclude the display is broken. The line has to describe
// the RULE (N days of disuse), not a date the key is counting down to.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// meAndKeysServerWindow is meAndKeysServer plus the sliding-window field the
// server sends for keys it minted for the CLI.
func meAndKeysServerWindow(t *testing.T, prefix string, expiresAt *time.Time, windowSeconds *int64) string {
	t.Helper()
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/auth/me":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_id": "u-1", "org_id": "org-1",
				"role": "admin", "email": "dev@example.test",
			})
		case "/api/api-keys":
			key := map[string]any{
				"id": "ak-1", "name": "cli:build-box@2026-08-22",
				"key_type": "personal", "prefix": prefix,
				"active": true, "created_at": time.Now().UTC(),
			}
			if expiresAt != nil {
				key["expires_at"] = expiresAt.UTC()
			}
			if windowSeconds != nil {
				key["expiry_window_seconds"] = *windowSeconds
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"api_keys": []any{key}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	return srv.URL
}

const (
	slidingTestToken  = "c305_pat_abcdefghijklmnop_qrstuvwxyz_012345"
	slidingTestPrefix = "abcdefghijklmnop"
)

func ninetyDaysSeconds() *int64 {
	s := int64((90 * 24 * time.Hour) / time.Second)
	return &s
}

// The wording test. A sliding key must be described as an IDLE deadline, and
// must NOT be given the countdown phrasing reserved for hard expiries.
func TestAuthStatusDescribesASlidingExpiryAsIdleNotACountdown(t *testing.T) {
	expires := time.Now().Add(90 * 24 * time.Hour)
	server := meAndKeysServerWindow(t, slidingTestPrefix, &expires, ninetyDaysSeconds())

	out, err := runAuthStatus(t, server, slidingTestToken, false)
	if err != nil {
		t.Fatalf("auth status: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "expires after 90 days unused") {
		t.Fatalf("a sliding expiry must be stated as an idle window, got:\n%s", out)
	}
	if strings.Contains(out, "expires in 90 days") {
		t.Fatalf("the countdown wording is a lie under a sliding window — this very "+
			"command reset the clock. Got:\n%s", out)
	}
	// The user still needs to know that using the CLI is what keeps the key
	// alive, otherwise the number reads as an unexplained constant.
	if !strings.Contains(out, "reset") {
		t.Fatalf("the line should say the clock was just reset, got:\n%s", out)
	}
	// The date is still shown, framed as "if untouched" rather than "on".
	if !strings.Contains(out, expires.UTC().Format("2006-01-02")) {
		t.Fatalf("the current deadline should still be visible, got:\n%s", out)
	}
}

// A sliding key inside 14 days must NOT get the "run auth login before then"
// urgency the hard-expiry branch prints. Nothing is about to break: the
// request that produced this output already pushed the deadline back out.
func TestAuthStatusDoesNotNagAboutANearSlidingDeadline(t *testing.T) {
	expires := time.Now().Add(3 * 24 * time.Hour)
	server := meAndKeysServerWindow(t, slidingTestPrefix, &expires, ninetyDaysSeconds())

	out, err := runAuthStatus(t, server, slidingTestToken, false)
	if err != nil {
		t.Fatalf("auth status: %v\noutput: %s", err, out)
	}
	if strings.Contains(out, "before then") {
		t.Fatalf("a sliding key must not urge a pre-emptive re-login, got:\n%s", out)
	}
	if !strings.Contains(out, "expires after 90 days unused") {
		t.Fatalf("expected the idle-window wording, got:\n%s", out)
	}
}

// A HARD expiry — an operator-dated key, or any key from a server that
// predates sliding — keeps the v0.20.8 countdown verbatim. The new wording
// must not leak onto keys it does not describe.
func TestAuthStatusKeepsTheCountdownForAHardExpiry(t *testing.T) {
	expires := time.Now().Add(30 * 24 * time.Hour)
	server := meAndKeysServerWindow(t, slidingTestPrefix, &expires, nil)

	out, err := runAuthStatus(t, server, slidingTestToken, false)
	if err != nil {
		t.Fatalf("auth status: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "expires in 30 days") {
		t.Fatalf("a hard expiry should still count down, got:\n%s", out)
	}
	if strings.Contains(out, "unused") {
		t.Fatalf("the idle wording must not appear for a hard expiry, got:\n%s", out)
	}
}

// A lapsed sliding key reports EXPIRED, not "expires after N days unused".
// Sliding buys a live key more time; it never revives a dead one, and the
// status line must not imply otherwise.
func TestAuthStatusReportsALapsedSlidingKeyAsExpired(t *testing.T) {
	expires := time.Now().Add(-24 * time.Hour)
	server := meAndKeysServerWindow(t, slidingTestPrefix, &expires, ninetyDaysSeconds())

	out, err := runAuthStatus(t, server, slidingTestToken, false)
	if err != nil {
		t.Fatalf("auth status: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "EXPIRED") {
		t.Fatalf("a lapsed key must read as expired regardless of its window, got:\n%s", out)
	}
	if !strings.Contains(out, "chainsaw auth login") {
		t.Fatalf("a lapsed key must name the fix, got:\n%s", out)
	}
}

// --json consumers get an explicit idle_expiry_days so a script can tell the
// two regimes apart instead of misreading expires_in_days as a countdown.
func TestAuthStatusJSONCarriesIdleExpiryDays(t *testing.T) {
	expires := time.Now().Add(90 * 24 * time.Hour)
	server := meAndKeysServerWindow(t, slidingTestPrefix, &expires, ninetyDaysSeconds())

	out, err := runAuthStatus(t, server, slidingTestToken, true)
	if err != nil {
		t.Fatalf("auth status --json: %v\noutput: %s", err, out)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode --json output: %v\n%s", err, out)
	}
	v, ok := got["idle_expiry_days"]
	if !ok {
		t.Fatalf("sliding key should expose idle_expiry_days: %s", out)
	}
	if n, _ := v.(float64); int(n) != 90 {
		t.Fatalf("idle_expiry_days = %v, want 90", v)
	}

	// And the field is absent for a hard expiry, so its presence alone is a
	// reliable "this key slides" test for a script.
	hardServer := meAndKeysServerWindow(t, slidingTestPrefix, &expires, nil)
	out, err = runAuthStatus(t, hardServer, slidingTestToken, true)
	if err != nil {
		t.Fatalf("auth status --json (hard): %v\noutput: %s", err, out)
	}
	got = map[string]any{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode --json output: %v\n%s", err, out)
	}
	if _, ok := got["idle_expiry_days"]; ok {
		t.Fatalf("a hard expiry must not report idle_expiry_days: %s", out)
	}
}

// ── token list ────────────────────────────────────────────────────────────────

func TestExpiryWindowDays(t *testing.T) {
	now := time.Now()
	day := int64(60 * 60 * 24)
	cases := []struct {
		name string
		item tokenItem
		want int
	}{
		{"no window", tokenItem{ExpiresAt: &now}, 0},
		{"window but no expiry", tokenItem{ExpiryWindowSeconds: &day}, 0},
		{"one day", tokenItem{ExpiresAt: &now, ExpiryWindowSeconds: &day}, 1},
		{"ninety days", tokenItem{ExpiresAt: &now, ExpiryWindowSeconds: ninetyDaysSeconds()}, 90},
		{"zero window is not sliding", tokenItem{ExpiresAt: &now, ExpiryWindowSeconds: int64Ptr(0)}, 0},
		// Sub-day windows are pathological but still sliding; reporting 0
		// would misfile them as hard expiries.
		{"sub-day window still slides", tokenItem{ExpiresAt: &now, ExpiryWindowSeconds: int64Ptr(60)}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.item.expiryWindowDays(); got != tc.want {
				t.Fatalf("expiryWindowDays() = %d, want %d", got, tc.want)
			}
		})
	}
}

func int64Ptr(v int64) *int64 { return &v }

// `token list` must not print a bare date in the EXPIRES column for a sliding
// key — read as a deadline, it tells an operator a key is about to die when
// in fact every use pushes the date out. The row is marked and the mark is
// explained once, and neither appears when no key in the org slides.
func TestTokenListMarksAndExplainsSlidingExpiries(t *testing.T) {
	expires := time.Now().Add(90 * 24 * time.Hour)
	hard := time.Now().Add(30 * 24 * time.Hour)

	t.Run("sliding key is marked and the mark is explained", func(t *testing.T) {
		srv, _ := mockTokenRevokeServer(t, []tokenItem{
			{
				ID: "ak-cli", Name: "cli:laptop@2026-08-22", KeyType: "personal",
				Prefix: "clipfx", Active: true, ExpiresAt: &expires,
				ExpiryWindowSeconds: ninetyDaysSeconds(),
			},
		})
		authedAgainst(t, srv)

		cmd := &cobra.Command{Use: "list", SilenceUsage: true}
		cmd.Flags().Bool("json", false, "")
		cmd.Flags().String("key-type", "", "")
		var legend strings.Builder
		cmd.SetOut(&legend)

		table := captureStdout(t, func() {
			if err := runTokenList(cmd, nil); err != nil {
				t.Fatalf("token list: %v", err)
			}
		})

		want := expires.Format("2006-01-02") + "*"
		if !strings.Contains(table, want) {
			t.Fatalf("sliding row should carry the %q marker, got:\n%s", want, table)
		}
		combined := table + legend.String()
		if !strings.Contains(combined, "sliding expiry") {
			t.Fatalf("the marker must be explained below the table, got:\n%s", combined)
		}
		if !strings.Contains(combined, "NOT used again") {
			t.Fatalf("the legend must say the date is the lapse-if-unused date, got:\n%s", combined)
		}
	})

	t.Run("hard expiries are unmarked and unexplained", func(t *testing.T) {
		srv, _ := mockTokenRevokeServer(t, []tokenItem{
			{ID: "ak-ci", Name: "ci-deploy", KeyType: "personal", Prefix: "cipfx", Active: true, ExpiresAt: &hard},
			{ID: "ak-none", Name: "legacy", KeyType: "personal", Prefix: "nonpfx", Active: true},
		})
		authedAgainst(t, srv)

		cmd := &cobra.Command{Use: "list", SilenceUsage: true}
		cmd.Flags().Bool("json", false, "")
		cmd.Flags().String("key-type", "", "")
		var legend strings.Builder
		cmd.SetOut(&legend)

		table := captureStdout(t, func() {
			if err := runTokenList(cmd, nil); err != nil {
				t.Fatalf("token list: %v", err)
			}
		})

		combined := table + legend.String()
		if strings.Contains(combined, "*") {
			t.Fatalf("no key slides, so nothing should be marked:\n%s", combined)
		}
		if strings.Contains(combined, "sliding expiry") {
			t.Fatalf("the legend must stay off the output when it explains nothing:\n%s", combined)
		}
	})
}
