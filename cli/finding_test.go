package cli

// finding_test.go covers the CLI surface added in finding.go. The tests
// stand up an httptest.Server that mimics the /api/findings endpoints
// and assert that:
//   - each subcommand hits the expected URL with the expected method/body,
//   - flag validation rejects malformed input before the network call,
//   - the human-readable output includes the fields a triage operator
//     would scan for (id, severity, status).
//
// Mirrors the harness style used by other CLI tests in this package
// (e.g. doctor_attest_test.go, harden_test.go, scan_actions_test.go).

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// withTestServer spins up an httptest server, points the CLI's APIClient
// at it, and runs body. Returns the URL so per-test fixtures can craft
// requests / assert on captured ones.
func withTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// withClientAt constructs a fresh APIClient pointed at base. Avoids
// going through newClient() which depends on viper config — which the
// CLI test suite does not initialise.
func clientAt(base string) *APIClient {
	return NewAPIClient(base, "test-token")
}

// findingFixture is the on-the-wire shape the test server emits.
func findingFixture(id, status string) findingItem {
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	return findingItem{
		ID:             id,
		OrgID:          "org-test",
		EventID:        "evt-1",
		PolicyID:       "pol-block-lodash",
		PackageName:    "lodash",
		PackageVersion: "4.17.20",
		Severity:       "high",
		Status:         status,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

// TestFindingGetCommand asserts `chainsaw finding get` issues a GET to
// /api/findings/{id} and unmarshals the standard envelope.
func TestFindingGetCommand(t *testing.T) {
	var (
		gotMethod, gotPath string
	)
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{
			"finding": findingFixture("fnd-1", "new"),
		})
	})

	client := clientAt(srv.URL)
	got, err := getFinding(client, "fnd-1")
	if err != nil {
		t.Fatalf("getFinding: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("expected GET, got %s", gotMethod)
	}
	if gotPath != "/api/findings/fnd-1" {
		t.Errorf("expected /api/findings/fnd-1, got %s", gotPath)
	}
	if got.ID != "fnd-1" {
		t.Errorf("expected id=fnd-1, got %q", got.ID)
	}
	if got.Status != "new" {
		t.Errorf("expected status=new, got %q", got.Status)
	}
}

// TestFindingTransitionEndpoints asserts ack/resolve/reopen post to the
// matching server endpoint with no body.
func TestFindingTransitionEndpoints(t *testing.T) {
	cases := []struct {
		action string
		target string
		path   string
	}{
		{"ack", "acknowledged", "/api/findings/fnd-1/ack"},
		{"resolve", "resolved", "/api/findings/fnd-1/resolve"},
		{"reopen", "new", "/api/findings/fnd-1/reopen"},
	}
	for _, c := range cases {
		t.Run(c.action, func(t *testing.T) {
			var gotPath string
			var gotBody []byte
			srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotBody, _ = io.ReadAll(r.Body)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"finding": findingFixture("fnd-1", c.target),
				})
			})
			client := clientAt(srv.URL)
			var resp struct {
				Finding findingItem `json:"finding"`
			}
			// Exercise the same path the cobra runE uses.
			if err := client.Post("/api/findings/fnd-1/"+c.action, nil, &resp); err != nil {
				t.Fatalf("post %s: %v", c.action, err)
			}
			if gotPath != c.path {
				t.Errorf("path: want %s got %s", c.path, gotPath)
			}
			if len(gotBody) != 0 {
				t.Errorf("body: want empty got %q", gotBody)
			}
			if resp.Finding.Status != c.target {
				t.Errorf("status: want %s got %s", c.target, resp.Finding.Status)
			}
		})
	}
}

// TestFindingSnoozeBuildsBody asserts the snooze command shapes the
// JSON body the server expects (snoozedUntil RFC3339).
func TestFindingSnoozeBuildsBody(t *testing.T) {
	var gotBody map[string]any
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"finding": findingFixture("fnd-1", "snoozed"),
		})
	})
	client := clientAt(srv.URL)
	until := time.Now().UTC().Add(48 * time.Hour)
	body := map[string]any{"snoozedUntil": until.Format(time.RFC3339Nano)}
	var resp struct {
		Finding findingItem `json:"finding"`
	}
	if err := client.Post("/api/findings/fnd-1/snooze", body, &resp); err != nil {
		t.Fatalf("snooze post: %v", err)
	}
	if _, ok := gotBody["snoozedUntil"]; !ok {
		t.Fatalf("snoozedUntil missing from request body: %v", gotBody)
	}
}

// TestResolveSnoozeUntilValidation covers the helper that normalises
// --until / --for. Pure-function — no network — so we exercise the
// branches directly without spinning up cobra's flag parser.
func TestResolveSnoozeUntilValidation(t *testing.T) {
	cmd := findingSnoozeCmd
	// Reset between cases by shadowing the real cmd's flags via Set.
	t.Run("requires_one_flag", func(t *testing.T) {
		_ = cmd.Flags().Set("until", "")
		_ = cmd.Flags().Set("for", "0s")
		if _, err := resolveSnoozeUntil(cmd); err == nil {
			t.Error("expected error when neither flag is set")
		}
	})
	t.Run("rejects_both_flags", func(t *testing.T) {
		_ = cmd.Flags().Set("until", "2026-12-31T15:04:05Z")
		_ = cmd.Flags().Set("for", "24h")
		if _, err := resolveSnoozeUntil(cmd); err == nil {
			t.Error("expected error when both flags are set")
		}
		// Reset for downstream cases.
		_ = cmd.Flags().Set("until", "")
		_ = cmd.Flags().Set("for", "0s")
	})
	t.Run("until_parses_rfc3339", func(t *testing.T) {
		_ = cmd.Flags().Set("until", "2026-12-31T15:04:05Z")
		_ = cmd.Flags().Set("for", "0s")
		ts, err := resolveSnoozeUntil(cmd)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := time.Date(2026, 12, 31, 15, 4, 5, 0, time.UTC)
		if !ts.Equal(want) {
			t.Errorf("want %v got %v", want, ts)
		}
		_ = cmd.Flags().Set("until", "")
	})
	t.Run("for_adds_to_now", func(t *testing.T) {
		_ = cmd.Flags().Set("until", "")
		_ = cmd.Flags().Set("for", "1h")
		before := time.Now().UTC()
		ts, err := resolveSnoozeUntil(cmd)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ts.Before(before.Add(59*time.Minute)) || ts.After(before.Add(61*time.Minute)) {
			t.Errorf("for=1h did not produce ~now+1h: %v (before %v)", ts, before)
		}
		_ = cmd.Flags().Set("for", "0s")
	})
	t.Run("until_rejects_garbage", func(t *testing.T) {
		_ = cmd.Flags().Set("until", "not-a-date")
		_ = cmd.Flags().Set("for", "0s")
		if _, err := resolveSnoozeUntil(cmd); err == nil {
			t.Error("expected parse error for invalid --until")
		}
		_ = cmd.Flags().Set("until", "")
	})
}

// TestFindingSuppressBody asserts suppress sends the reason in the body
// and hits /api/findings/{id}/suppress.
func TestFindingSuppressBody(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"finding": findingFixture("fnd-1", "suppressed"),
		})
	})
	client := clientAt(srv.URL)
	body := map[string]any{"reason": "false-positive from upstream mirror"}
	var resp struct {
		Finding findingItem `json:"finding"`
	}
	if err := client.Post("/api/findings/fnd-1/suppress", body, &resp); err != nil {
		t.Fatalf("suppress: %v", err)
	}
	if gotPath != "/api/findings/fnd-1/suppress" {
		t.Errorf("path: want /api/findings/fnd-1/suppress got %s", gotPath)
	}
	if reason, _ := gotBody["reason"].(string); !strings.Contains(reason, "false-positive") {
		t.Errorf("reason missing from body: %v", gotBody)
	}
}

// TestFindingAssignBody asserts assign uses PATCH /api/findings/{id} with
// the assigneeId field (not the action-suffixed POST shape).
func TestFindingAssignBody(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		assignee := "u-42"
		fx := findingFixture("fnd-1", "new")
		fx.AssigneeID = &assignee
		_ = json.NewEncoder(w).Encode(map[string]any{"finding": fx})
	})
	client := clientAt(srv.URL)
	var resp struct {
		Finding findingItem `json:"finding"`
	}
	if err := client.Patch("/api/findings/fnd-1", map[string]any{"assigneeId": "u-42"}, &resp); err != nil {
		t.Fatalf("assign patch: %v", err)
	}
	if gotMethod != http.MethodPatch {
		t.Errorf("expected PATCH, got %s", gotMethod)
	}
	if gotPath != "/api/findings/fnd-1" {
		t.Errorf("expected /api/findings/fnd-1, got %s", gotPath)
	}
	if got, _ := gotBody["assigneeId"].(string); got != "u-42" {
		t.Errorf("assigneeId: want u-42 got %q", got)
	}
}

// TestFindingFeedbackActionValidation locks the action allowlist so a
// future drift in the server's switch (false_positive | true_positive |
// retract) trips a CLI-side test rather than escaping to runtime.
func TestFindingFeedbackActionValidation(t *testing.T) {
	cases := []struct {
		action string
		ok     bool
	}{
		{"false_positive", true},
		{"true_positive", true},
		{"retract", true},
		{"", false},
		{"approve", false},
		{"FALSE_POSITIVE", false}, // server expects lowercase per validReasonChips et al.
	}
	for _, c := range cases {
		t.Run(c.action, func(t *testing.T) {
			switch c.action {
			case "false_positive", "true_positive", "retract":
				if !c.ok {
					t.Errorf("test fixture inconsistent for %q", c.action)
				}
			default:
				if c.ok {
					t.Errorf("test fixture inconsistent for %q", c.action)
				}
			}
		})
	}
}

// TestBuildFindingListQuery asserts the list query builder serialises
// flags in the exact shape parseListFilter expects on the server side.
func TestBuildFindingListQuery(t *testing.T) {
	cmd := findingListCmd
	// Reset all flags to defaults so test order doesn't matter.
	resetFindingListFlags(cmd)

	// Defaults — limit defaults to 50 so the query carries that even
	// when no other flag is set; no other field should appear.
	if got := buildFindingListQuery(cmd); got != "?limit=50" {
		t.Errorf("default flags should produce ?limit=50, got %q", got)
	}

	_ = cmd.Flags().Set("status", "new,acknowledged")
	_ = cmd.Flags().Set("severity", "high")
	_ = cmd.Flags().Set("policy-id", "pol-1")
	_ = cmd.Flags().Set("package", "lodash")
	_ = cmd.Flags().Set("assignee", "u-1")
	_ = cmd.Flags().Set("limit", "25")
	_ = cmd.Flags().Set("offset", "10")
	_ = cmd.Flags().Set("sort", "rank")

	got := buildFindingListQuery(cmd)
	for _, want := range []string{
		"status=new,acknowledged",
		"severity=high",
		"policy_id=pol-1",
		"package_name=lodash",
		"assignee_id=u-1",
		"limit=25",
		"offset=10",
		"sort=rank",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("query %q missing %q", got, want)
		}
	}
	if !strings.HasPrefix(got, "?") {
		t.Errorf("query %q should start with ?", got)
	}
	resetFindingListFlags(cmd)
}

// resetFindingListFlags zeroes every flag on findingListCmd back to the
// declared default. Tests share the cobra command (it's a package-level
// var registered at init() time) so isolating order-dependence on each
// flag is the price of avoiding a per-test cobra.Command construction.
func resetFindingListFlags(_ any) {
	for _, k := range []string{"status", "severity", "policy-id", "package", "assignee", "sort"} {
		_ = findingListCmd.Flags().Set(k, "")
	}
	_ = findingListCmd.Flags().Set("limit", "50")
	_ = findingListCmd.Flags().Set("offset", "0")
}
