// Package composer parses composer.lock (PHP).
//
// Format: JSON. Top-level keys "packages" (prod) and "packages-dev" each
// hold an array of {name, version, source, dist, notification-url, ...}
// entries. We emit both with dev-flag set appropriately.
//
// Where a package comes from (docs/PLANS_INTELLIGENCE.md
// #plan-non-registry-sources). composer.lock never records the repository a
// package was resolved from, so the rule reads what each repository type
// leaves behind, in this order:
//
//  1. dist.type "path" — a `path` repository (a directory of this project,
//     drupal/core in drupal/drupal): Origin "file:<dist.url>".
//  2. notification-url — written only for packages from a Composer
//     repository (packages.json), copied from its `notify-batch`:
//     packagist.org's is https://packagist.org/downloads/, so that host (an
//     origin.Classify composer alias) means Packagist (no Origin). Any other (Private Packagist, wp-packages.org, an
//     Artifactory or Nexus Composer remote) is the registry protocol on
//     another host: Origin "registry+<notification-url>", decided by the
//     server (mirror or private) and printed with the registry_mirrors hint
//     by the guard. NOT dist.url: a Packagist package's dist.url is a GitHub
//     zipball API URL (api.github.com/repos/…/zipball/<sha>), and a Chainsaw
//     or Artifactory mirror rewrites it to itself, so the dist host says
//     nothing about the registry. Except: notification-url is copied from
//     any repository's notify-batch, so a Packagist notification-url with a
//     dist.url off the code hosts Packagist writes (packagistDistHosts) is
//     Origin "registry+<scheme>://<dist host>/" — Composer downloads dist.url.
//  3. no notification-url, source.type git/hg/svn/fossil — a `vcs`
//     repository (or a Satis without notify-batch, indistinguishable here):
//     Origin "<type>+<source.url>#<source.reference>".
//  4. no notification-url, no source — a `package` or `artifact`
//     repository: Origin "url+<dist.url>" (artifact: a local zip path). The
//     "url+" prefix keeps a URL with no archive suffix (a zipball API URL)
//     from reading as a registry address to origin.Classify.
//
// No Hash: dist.shasum is a sha1 Packagist leaves empty for GitHub zipballs
// (whose bytes GitHub does not keep stable), and source.reference is a git
// commit, never an artifact hash.
//
// Trivy reference: pkg/dependency/parser/php/composer/parse.go.
package composer

import (
	"encoding/json"
	"io"
	"net/url"
	"strings"

	"github.com/chain305/chainsaw-core/depparser/origin"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type entry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  struct {
		Type      string `json:"type"`
		URL       string `json:"url"`
		Reference string `json:"reference"`
	} `json:"source"`
	Dist struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"dist"`
	NotificationURL string `json:"notification-url"`
}

type lockfile struct {
	Packages    []entry `json:"packages"`
	PackagesDev []entry `json:"packages-dev"`
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	var lf lockfile
	if err := json.NewDecoder(r).Decode(&lf); err != nil {
		return nil, err
	}
	var out []ftypes.Package
	push := func(e entry, dev bool) {
		if e.Name == "" || e.Version == "" {
			return
		}
		// Composer sometimes prefixes "v" on version strings (e.g.
		// "v1.2.3"); strip it for matching against vuln-scan DBs that
		// index semver without the v.
		v := strings.TrimPrefix(e.Version, "v")
		out = append(out, ftypes.Package{Name: e.Name, Version: v, Dev: dev, Origin: entryOrigin(e)})
	}
	for _, e := range lf.Packages {
		push(e, false)
	}
	for _, e := range lf.PackagesDev {
		push(e, true)
	}
	return out, nil
}

// packagistDistHosts are the hosts Packagist writes a dist.url on: the
// archive APIs of the code hosts it reads packages from.
var packagistDistHosts = map[string]bool{
	"api.github.com": true, "codeload.github.com": true, "github.com": true,
	"gitlab.com": true, "bitbucket.org": true, "api.bitbucket.org": true,
}

// entryOrigin applies the package comment's rule; "" is Packagist.
func entryOrigin(e entry) string {
	switch {
	case e.Dist.Type == "path":
		return origin.Sanitize("file:" + e.Dist.URL)
	case e.NotificationURL != "":
		if origin.Classify("composer", e.NotificationURL) != origin.Public {
			return origin.Sanitize("registry+" + e.NotificationURL)
		}
		// Any repository can copy Packagist's notify-batch, and Composer
		// downloads from dist.url whatever notification-url says. Packagist
		// only ever writes a dist on a code host's archive API; anything
		// else is the registry protocol on that host (a mirror that
		// rewrites dist URLs, or not Packagist at all), decided by the
		// server.
		if e.Dist.URL == "" || packagistDistHosts[origin.Host(e.Dist.URL)] {
			return ""
		}
		if u, err := url.Parse(e.Dist.URL); err == nil && u.Host != "" {
			return origin.Sanitize("registry+" + strings.ToLower(u.Scheme) + "://" + u.Host + "/")
		}
		return origin.Sanitize("url+" + e.Dist.URL)
	case e.Source.URL != "" && e.Source.Type != "":
		src := strings.ToLower(e.Source.Type) + "+" + e.Source.URL
		if e.Source.Reference != "" {
			src += "#" + e.Source.Reference
		}
		return origin.Sanitize(src)
	case e.Dist.URL != "":
		return origin.Sanitize("url+" + e.Dist.URL)
	}
	// Nothing recorded at all: still not a Packagist package (Packagist
	// always writes notification-url).
	return "url+(unrecorded)"
}
