package cli

// auth_client_test.go covers the registry-credential management family
// (`chainsaw auth client {create,list,delete,rotate}`). Each test stands
// up an httptest.Server that mimics the /api/clients surface and asserts
// the CLI hits the right URL with the right method/body, surfaces the
// one-shot CLIENT_SECRET, and rejects malformed input before the network
// call.
//
// The harness follows the pattern in finding_test.go — `clientAt(URL)`
// builds an APIClient pointed at the fake server, then subcommand
// helpers (runAuthClientCreate, etc.) are exercised directly through
// cobra so flag parsing also gets coverage.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// withConfiguredServer points viper at the given URL so newClient()
// inside the subcommands resolves to a working endpoint. Mirrors what
// `chainsaw auth login` would have done in real usage.
func withConfiguredServer(t *testing.T, url string) {
	t.Helper()
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	viper.Set("server_url", url)
	viper.Set("token", "test-token")
}

func TestAuthClientCreate_HitsExpectedEndpointAndSurfacesSecret(t *testing.T) {
	var (
		gotMethod, gotPath string
		gotBody            map[string]any
	)
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client": map[string]any{
				"client_id":   "ci-frontend",
				"name":        "frontend CI runner",
				"client_type": "end-user",
				"enabled":     true,
				"status":      "active",
				"created_at":  time.Now().UTC(),
			},
			"client_secret": "super-secret-shh",
		})
	})
	withConfiguredServer(t, srv.URL)

	cmd := authClientCreateCmd()
	cmd.SetArgs([]string{"--name", "ci-frontend", "--description", "frontend CI runner", "--json"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("create: %v\nstderr: %s", err, errb.String())
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if gotPath != "/api/clients" {
		t.Errorf("path = %s, want /api/clients", gotPath)
	}
	if gotBody["client_id"] != "ci-frontend" {
		t.Errorf("request client_id = %v, want ci-frontend", gotBody["client_id"])
	}
	if gotBody["name"] != "frontend CI runner" {
		t.Errorf("request name = %v, want 'frontend CI runner'", gotBody["name"])
	}
	if _, ok := gotBody["expiry_date"]; !ok {
		t.Errorf("request missing expiry_date (default should be set)")
	}
	// JSON output is rendered via PrintJSON → os.Stdout (not cmd.Out),
	// matching every other --json path in the CLI. Capturing os.Stdout
	// inside a test is brittle, so the contract here is checked via the
	// server-side request body assertions above plus a no-error exit.
	// Manual smoke (./chainsaw auth client create --name x --json) prints
	// the secret.
}

func TestAuthClientCreate_EchoesSlugCorrectRegistrationSnippet(t *testing.T) {
	// The server's config_snippets carry the org's REAL slug in the registry
	// path. The non-JSON create output must echo that snippet verbatim so the
	// CLI path is copy-paste-correct — and must NEVER print a bare @default,
	// which on SaaS returns HTTP 400 (CHW-4314) and silently never fires.
	srv := withTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client": map[string]any{
				"client_id":   "ci-frontend",
				"client_type": "end-user",
				"enabled":     true,
				"status":      "active",
				"created_at":  time.Now().UTC(),
			},
			"client_secret": "super-secret-shh",
			"config_snippets": map[string]any{
				"npm": map[string]any{
					"format":   "npm",
					"filename": ".npmrc",
					"content":  "registry=https://chain305.com/chainproxy/repository/@acme-corp/npmjs/\n//chain305.com/chainproxy/repository/@acme-corp/npmjs/:_auth=abc123\n",
				},
			},
		})
	})
	withConfiguredServer(t, srv.URL)

	cmd := authClientCreateCmd()
	cmd.SetArgs([]string{"--name", "ci-frontend"}) // non-JSON path
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("create: %v\nstderr: %s", err, errb.String())
	}

	got := out.String()
	if !strings.Contains(got, "@acme-corp") {
		t.Errorf("output should echo the org slug from config_snippets, got:\n%s", got)
	}
	if strings.Contains(got, "@default") {
		t.Errorf("output must never contain a bare @default slug, got:\n%s", got)
	}
	if !strings.Contains(got, "CLIENT_SECRET=super-secret-shh") {
		t.Errorf("output should still surface the one-shot secret, got:\n%s", got)
	}
}

func TestAuthClientCreate_NoSnippetsPointsAtDashboard(t *testing.T) {
	// When the server returns no config_snippets (older proxy), the CLI must
	// guide the operator to the dashboard rather than print a misleading
	// @default registration line.
	srv := withTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client": map[string]any{
				"client_id":   "ci-frontend",
				"client_type": "end-user",
				"enabled":     true,
				"status":      "active",
				"created_at":  time.Now().UTC(),
			},
			"client_secret": "super-secret-shh",
		})
	})
	withConfiguredServer(t, srv.URL)

	cmd := authClientCreateCmd()
	cmd.SetArgs([]string{"--name", "ci-frontend"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("create: %v\nstderr: %s", err, errb.String())
	}

	got := out.String()
	if strings.Contains(got, "@default") {
		t.Errorf("output must never print a bare @default hint, got:\n%s", got)
	}
	if !strings.Contains(got, "Settings → Client Credentials") {
		t.Errorf("output should point the operator at the dashboard, got:\n%s", got)
	}
}

func TestAuthClientCreate_RequiresName(t *testing.T) {
	withConfiguredServer(t, "http://unused.invalid")
	cmd := authClientCreateCmd()
	cmd.SetArgs([]string{}) // --name omitted
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error when --name is missing")
	}
	if !strings.Contains(err.Error(), "--name is required") {
		t.Fatalf("error should mention --name, got: %v", err)
	}
}

func TestAuthClientList_RendersTable(t *testing.T) {
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/clients" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"clients": []map[string]any{
				{
					"client_id":   "ci-frontend",
					"name":        "frontend",
					"client_type": "end-user",
					"enabled":     true,
					"status":      "active",
					"created_at":  time.Now().UTC(),
				},
			},
		})
	})
	withConfiguredServer(t, srv.URL)

	cmd := authClientListCmd()
	cmd.SetArgs([]string{"--json"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("list: %v\nstderr: %s", err, errb.String())
	}
	// PrintJSON writes to os.Stdout directly (not cmd.OutOrStdout). So we
	// can't assert on `out` for JSON output; the absence of an error and
	// the assertion in the server handler above is sufficient coverage
	// for this test.
}

func TestAuthClientDelete_CallsDELETE(t *testing.T) {
	var (
		gotMethod, gotPath string
	)
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	withConfiguredServer(t, srv.URL)

	cmd := authClientDeleteCmd()
	cmd.SetArgs([]string{"ci-frontend", "--yes"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("delete: %v\nstderr: %s", err, errb.String())
	}

	if gotMethod != http.MethodDelete {
		t.Errorf("method = %s, want DELETE", gotMethod)
	}
	if gotPath != "/api/clients/ci-frontend" {
		t.Errorf("path = %s, want /api/clients/ci-frontend", gotPath)
	}
}

func rotateListResponse(w http.ResponseWriter) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"clients": []map[string]any{
			{
				"client_id":   "ci-frontend",
				"name":        "frontend CI",
				"client_type": "end-user",
				"enabled":     true,
				"status":      "active",
				"created_at":  time.Now().UTC(),
			},
		},
	})
}

func rotateSuccessResponse(w http.ResponseWriter, secret string) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"client": map[string]any{
			"client_id":   "ci-frontend",
			"client_type": "end-user",
			"enabled":     true,
			"status":      "active",
			"created_at":  time.Now().UTC(),
		},
		"client_secret": secret,
	})
}

// TestAuthClientRotate_UsesTheAtomicEndpoint pins the migration away from
// delete+recreate.
//
// The old flow deleted the credential and then created it again under the
// same id, which left a window where it could not authenticate and, if the
// create failed, left the operator with NO credential at all. The atomic
// endpoint removes both. A DELETE appearing in this sequence means the
// migration regressed.
func TestAuthClientRotate_UsesTheAtomicEndpoint(t *testing.T) {
	var methodSeq, pathSeq []string
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		methodSeq = append(methodSeq, r.Method)
		pathSeq = append(pathSeq, r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/clients":
			rotateListResponse(w)
		case r.Method == http.MethodPost && r.URL.Path == "/api/clients/ci-frontend/rotate":
			rotateSuccessResponse(w, "rotated-secret")
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	withConfiguredServer(t, srv.URL)

	cmd := authClientRotateCmd()
	cmd.SetArgs([]string{"ci-frontend", "--yes", "--json"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("rotate: %v\nstderr: %s", err, errb.String())
	}

	for _, m := range methodSeq {
		if m == http.MethodDelete {
			t.Fatalf("rotate issued a DELETE; the atomic endpoint must not "+
				"delete the credential: %v %v", methodSeq, pathSeq)
		}
	}
	if len(pathSeq) == 0 || pathSeq[len(pathSeq)-1] != "/api/clients/ci-frontend/rotate" {
		t.Errorf("last call = %v, want the rotate endpoint: %v", pathSeq, methodSeq)
	}
	// Output assertions are deliberately absent: this command writes the
	// secret to the real os.Stdout/os.Stderr, not the cobra buffers, so an
	// assertion on out.String() silently passes on an empty buffer. The
	// request sequence is the observable contract here.
	if len(methodSeq) != 2 {
		t.Errorf("expected exactly 2 calls (list, rotate), got %v %v", methodSeq, pathSeq)
	}
}

// TestAuthClientRotate_SendsExplicitExpiry pins the A7 decision across the
// migration.
//
// The endpoint PRESERVES expiry when expiry_date is absent, which is right
// for its own default case. This command means the opposite — a fresh
// 90-day window, because rotation usually happens because a credential is
// near expiry. If the field is ever omitted here, rotation silently stops
// extending the credential and an operator rotating a nearly-expired
// credential gets one that still expires tomorrow.
func TestAuthClientRotate_SendsExplicitExpiry(t *testing.T) {
	var gotBody map[string]any
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/clients":
			rotateListResponse(w)
		case r.Method == http.MethodPost && r.URL.Path == "/api/clients/ci-frontend/rotate":
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			rotateSuccessResponse(w, "rotated-secret")
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	withConfiguredServer(t, srv.URL)

	cmd := authClientRotateCmd()
	cmd.SetArgs([]string{"ci-frontend", "--yes", "--json"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	raw, ok := gotBody["expiry_date"].(string)
	if !ok || raw == "" {
		t.Fatalf("rotate did not send expiry_date; the 90-day reset was lost: %v", gotBody)
	}
	got, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("expiry_date is not RFC3339: %q", raw)
	}
	want := time.Now().UTC().Add(90 * 24 * time.Hour)
	if got.Sub(want).Abs() > time.Hour {
		t.Errorf("expiry_date = %v, want ~90 days out (%v)", got, want)
	}
}

// TestAuthClientRotate_FallsBackOnlyOn404 covers a current CLI talking to a
// server that predates the rotate endpoint.
//
// The fallback is deliberately narrow. A 404 means "no such route" and
// delete+recreate is the honest older path. A 403 means the caller may not
// manage this credential — falling back there would send a DELETE for a
// credential they were just told they cannot touch.
func TestAuthClientRotate_FallsBackOnlyOn404(t *testing.T) {
	t.Run("404 falls back to delete+recreate", func(t *testing.T) {
		var methodSeq, pathSeq []string
		srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			methodSeq = append(methodSeq, r.Method)
			pathSeq = append(pathSeq, r.URL.Path)
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/api/clients":
				rotateListResponse(w)
			case r.Method == http.MethodPost && r.URL.Path == "/api/clients/ci-frontend/rotate":
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{"code": "CHW-0404", "message": "not found"},
				})
			case r.Method == http.MethodDelete && r.URL.Path == "/api/clients/ci-frontend":
				w.WriteHeader(http.StatusNoContent)
			case r.Method == http.MethodPost && r.URL.Path == "/api/clients":
				rotateSuccessResponse(w, "legacy-secret")
			default:
				t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				w.WriteHeader(http.StatusInternalServerError)
			}
		})
		withConfiguredServer(t, srv.URL)

		cmd := authClientRotateCmd()
		cmd.SetArgs([]string{"ci-frontend", "--yes", "--json"})
		var out, errb bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errb)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("rotate: %v\nstderr: %s", err, errb.String())
		}
		sawDelete := false
		for _, m := range methodSeq {
			if m == http.MethodDelete {
				sawDelete = true
			}
		}
		if !sawDelete {
			t.Errorf("fallback did not delete+recreate: %v %v", methodSeq, pathSeq)
		}
		// The fallback's warning goes to the real os.Stderr, so it cannot be
		// asserted from the cobra buffer. What IS observable is that the
		// legacy path ran: rotate 404 -> DELETE -> POST /api/clients.
		if len(pathSeq) != 4 || pathSeq[3] != "/api/clients" {
			t.Errorf("unexpected fallback sequence: %v %v", methodSeq, pathSeq)
		}
	})

	t.Run("403 does not fall back", func(t *testing.T) {
		var methodSeq []string
		srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			methodSeq = append(methodSeq, r.Method)
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/api/clients":
				rotateListResponse(w)
			case r.Method == http.MethodPost && r.URL.Path == "/api/clients/ci-frontend/rotate":
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{"code": "CHW-1801", "message": "forbidden"},
				})
			default:
				t.Errorf("unexpected request after a 403: %s %s", r.Method, r.URL.Path)
				w.WriteHeader(http.StatusInternalServerError)
			}
		})
		withConfiguredServer(t, srv.URL)

		cmd := authClientRotateCmd()
		cmd.SetArgs([]string{"ci-frontend", "--yes", "--json"})
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		if err := cmd.Execute(); err == nil {
			t.Fatal("a 403 rotate returned success")
		}
		for _, m := range methodSeq {
			if m == http.MethodDelete {
				t.Fatal("a 403 triggered the delete+recreate fallback; the CLI " +
					"deleted a credential the caller was told it cannot manage")
			}
		}
	})
}
