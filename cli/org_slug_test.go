package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func orgListServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/orgs" {
			http.NotFound(w, r)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"orgs": []map[string]string{
			{"id": "org-1", "slug": "acme"},
			{"id": "org-2", "slug": "other"},
		}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestRememberOrgSlugRecordsOnlyTheLoggedInOrg: the install guard exempts
// <server>/repository/@<slug>/ on the strength of this value, so it must be
// the logged-in org's slug and nothing else — never a neighbour's, never a
// guess when the list fails.
func TestRememberOrgSlugRecordsOnlyTheLoggedInOrg(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		orgID  string
		want   string
	}{
		{"own org listed", http.StatusOK, "org-1", "acme"},
		{"org not listed", http.StatusOK, "org-9", ""},
		{"list fails", http.StatusInternalServerError, "org-1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withIsolatedConfigHome(t)
			withFileCredStore(t)
			viper.Set("org_slug", "")
			srv := orgListServer(t, tc.status)
			if err := saveConfig(srv.URL, "tok", tc.orgID); err != nil {
				t.Fatalf("saveConfig: %v", err)
			}
			rememberOrgSlug(NewAPIClient(srv.URL, "tok"), tc.orgID)
			if got := viper.GetString("org_slug"); got != tc.want {
				t.Fatalf("org_slug = %q, want %q", got, tc.want)
			}
			raw, _ := os.ReadFile(configFilePath())
			if tc.want != "" && !strings.Contains(string(raw), "org_slug: "+tc.want) {
				t.Fatalf("config.yaml lacks org_slug %q:\n%s", tc.want, raw)
			}
		})
	}
}

// TestSaveConfigAndLogoutDropOrgSlug: a login to another org, or a logout,
// must not leave the previous org's slug exempting its repository.
func TestSaveConfigAndLogoutDropOrgSlug(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	viper.Set("org_slug", "old-org")
	if err := saveConfig("https://chainsaw.example", "", "org-2"); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	if got := viper.GetString("org_slug"); got != "" {
		t.Fatalf("org_slug after saveConfig = %q, want cleared", got)
	}
	raw, _ := os.ReadFile(configFilePath())
	if strings.Contains(string(raw), "old-org") {
		t.Fatalf("config.yaml kept the old slug:\n%s", raw)
	}
	viper.Set("org_slug", "acme")
	if err := clearConfig(); err != nil {
		t.Fatalf("clearConfig: %v", err)
	}
	if got := viper.GetString("org_slug"); got != "" {
		t.Fatalf("org_slug after logout = %q, want cleared", got)
	}
}

// TestRememberedSlugExemptsOnlyOwnRepository ties the two halves together:
// after login records the slug, the guard treats the user's own org
// repository on their server as the registry, and nothing else on that host.
func TestRememberedSlugExemptsOnlyOwnRepository(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	viper.Set("org_slug", "")
	srv := orgListServer(t, http.StatusOK)
	if err := saveConfig(srv.URL, "tok", "org-1"); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	t.Cleanup(func() { viper.Set("server_url", ""); viper.Set("org_slug", ""); viper.Set("org_id", "") })
	rememberOrgSlug(NewAPIClient(srv.URL, "tok"), "org-1")
	for raw, want := range map[string]bool{
		srv.URL + "/repository/@acme/pypi/simple":     true,
		srv.URL + "/repository/@other/pypi/simple":    false,
		srv.URL + "/repository/@acme/../@other/x":     false,
		"https://elsewhere.example/repository/@acme/": false,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := ownChainsawRepository(u); got != want {
			t.Errorf("ownChainsawRepository(%s) = %v, want %v", raw, got, want)
		}
	}
}
