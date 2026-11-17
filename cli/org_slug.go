package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/chain305/chainsaw-core/cli/secureio"
)

// The install guard exempts an index URL on the command line only when it is
// the user's OWN org repository on their Chainsaw server
// (<server>/repository/@<slug>/…, ownChainsawRepository): any org can create
// a proxy repository on a shared host, so the host alone proves nothing. The
// guard runs offline, so the slug has to be on disk. Until v0.22.95 nothing
// wrote it, and every Chainsaw URL typed on a command line read "not assessed".
//
// Login and setup now record it (`org_slug` in config.yaml), saveConfig
// clears it so a login to a different org never keeps the old org's slug, and
// logout clears it with the rest of the config.

// orgSlugFor returns the slug of org orgID as listed by GET /api/orgs, or ""
// when the call fails or the org is not listed. Never guesses: a slug that is
// not the logged-in org's would exempt another org's repository.
func orgSlugFor(client *APIClient, orgID string) string {
	orgID = strings.TrimSpace(orgID)
	if client == nil || orgID == "" {
		return ""
	}
	var resp struct {
		Orgs []struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
		} `json:"orgs"`
	}
	if err := client.Get("/api/orgs", &resp); err != nil {
		return ""
	}
	for _, o := range resp.Orgs {
		if o.ID == orgID {
			return strings.TrimSpace(o.Slug)
		}
	}
	return ""
}

// rememberOrgSlug records the logged-in org's slug in config.yaml. Best
// effort: login must not fail because the org list is unavailable — the guard
// then keeps treating Chainsaw URLs as undeclared, which is the safe side.
func rememberOrgSlug(client *APIClient, orgID string) {
	if slug := orgSlugFor(client, orgID); slug != "" {
		_ = saveOrgSlug(slug)
	}
}

// recordOrgSlugOnly writes org_slug into config.yaml and changes nothing else
// in the file. saveOrgSlug snapshots every viper setting, so run under
// `install-hook --server X` it would also persist X as server_url; an MDM
// wiring must record which org it used, not repoint the user's CLI.
func recordOrgSlugOnly(slug string) error {
	doc := map[string]any{}
	if data, err := os.ReadFile(configFilePath()); err == nil {
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("parse %s: %w", configFilePath(), err)
		}
		if doc == nil {
			doc = map[string]any{}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	doc["org_slug"] = slug
	out, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return err
	}
	if err := secureio.WriteFile(configFilePath(), out); err != nil {
		return err
	}
	viper.Set("org_slug", slug)
	return nil
}

// saveOrgSlug persists slug ("" clears it) without touching the rest of the
// config.
func saveOrgSlug(slug string) error {
	viper.Set("org_slug", slug)
	return writeConfigYAML()
}
