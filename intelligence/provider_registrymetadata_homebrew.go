package intelligence

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/homebrew"
)

// runHomebrew reads formulae.brew.sh/api/formula/<name>.json — the one
// document Homebrew publishes per formula — and, for the current version
// only, the bottle manifest on ghcr.io for its publish time.
//
// The API holds the CURRENT version and nothing else: no version list, no
// publish dates, no per-package publisher
// (docs/PLANS_INTELLIGENCE.md#plan-homebrew-ecosystem §1). So:
//
//   - a requested version other than the current pkg_version is NOT
//     version_not_found. Homebrew simply does not say; the package-level
//     facts (licence, deprecation, source repo) still describe the formula.
//   - Release.PublishedAt is set only when the requested version IS the
//     current one, from the bottle manifest's org.opencontainers.image.created
//     (a rebuild re-stamps it, which errs young — towards holding).
//   - a third-party tap name ("user/tap/foo") is not on formulae.brew.sh at
//     all; it is reported as not applicable rather than looked up, because a
//     lookup of the short name would describe a different (core) formula.
//
// A 404 is NOT promoted to package_not_found: a bare name missing from
// homebrew/core may still be a tap formula brew resolves, so homebrew is not
// in singleCanonicalRegistryEcosystems.
func (p *registryMetadataProvider) runHomebrew(ctx context.Context, pkg, ver string) (PartialReport, error) {
	name := homebrew.NormalizeName(pkg)
	if homebrew.IsThirdPartyTapName(name) {
		return PartialReport{Warnings: []Warning{{
			Provider: "registrymetadata",
			Code:     WarnUnsupported,
			Message:  "third-party tap formula " + name + ": formulae.brew.sh serves homebrew/core only",
			At:       p.now(),
		}}}, nil
	}
	endpoint := strings.TrimRight(p.endpoints.homebrew, "/") + "/formula/" + url.PathEscape(name) + ".json"
	var doc struct {
		homebrew.Formula
		// Analytics are on the per-formula document only (not formula.json),
		// keyed by "<name>" and "<name> --HEAD"-style option rows.
		Analytics struct {
			Install map[string]map[string]int `json:"install"`
		} `json:"analytics"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &doc)
	if err != nil {
		return PartialReport{}, err
	}
	pr := PartialReport{}
	if warn != nil {
		pr.Warnings = append(pr.Warnings, *warn)
		return pr, nil
	}
	f := &doc.Formula
	if canon := homebrew.NormalizeName(f.Name); canon != "" {
		name = canon // an alias or old name resolves to the formula's own name
	}
	f.Name = name

	release := &ReleaseSection{LatestVersion: f.PkgVersion()}
	release.Deprecated = homebrewDeprecation(f)
	if ver == f.PkgVersion() {
		release.PublishedAt = p.homebrewBottleCreated(ctx, f)
	}

	urls := &URLSection{MetadataURL: endpoint, HomepageURL: strings.TrimSpace(f.Homepage)}
	urls.SourceRepoURL = homebrewRepoURL(f)

	pr.Release = release
	pr.URLs = urls
	if lic, desc := strings.TrimSpace(f.License), strings.TrimSpace(f.Desc); lic != "" || desc != "" {
		pr.Metadata = &MetadataSection{LicenseExpression: lic, Description: desc}
	}
	if urls.SourceRepoURL != "" {
		pr.Provenance = &ProvenanceSection{SourceRepo: urls.SourceRepoURL}
	}
	// 90-day installs, every install option summed. `install` (not
	// install_on_request) because a library pulled in as a dependency is
	// adopted too: libpng is installed 324k times in 90 days, almost never
	// on request. Measured 2026-11-04.
	if window, ok := doc.Analytics.Install["90d"]; ok {
		n := 0
		for k, c := range window {
			if k == name || strings.HasPrefix(k, name+" ") {
				n += c
			}
		}
		at := p.now()
		pr.Maintenance = &MaintenanceSection{Downloads: &DownloadCount{Count: n, Window: DownloadWindow90Days, FetchedAt: &at}}
	}
	return pr, nil
}

// homebrewDeprecation renders deprecated/disabled as the maintainer
// deprecation string. Disabled is the stronger state (brew refuses to
// install), so it wins.
func homebrewDeprecation(f *homebrew.Formula) string {
	state, reason, repl := "", "", ""
	switch {
	case f.Disabled:
		state, reason, repl = "disabled", f.DisableReason, f.DisableReplacement
	case f.Deprecated:
		state, reason, repl = "deprecated", f.DeprecationReason, f.DeprecationReplacement
	default:
		return ""
	}
	if r := strings.TrimSpace(reason); r != "" {
		state += ": " + r
	}
	if r := strings.TrimSpace(repl); r != "" {
		state += "; replaced by " + r
	}
	return state
}

// homebrewRepoURL is the source repository the formula builds from: the
// stable tarball URL when it is on GitHub or GitLab, else the homepage when
// that is a repository URL. Anything else (a project website, a mirror)
// names no repository.
func homebrewRepoURL(f *homebrew.Formula) string {
	for _, raw := range []string{f.URLs.Stable.URL, f.Homepage} {
		if owner, repo, ok := parseGitHubRepo(raw); ok {
			return "https://github.com/" + owner + "/" + repo
		}
		if forge, owner, repo, ok := parseForgeRepo(raw); ok && forge == "gitlab" {
			return "https://gitlab.com/" + owner + "/" + repo
		}
	}
	return ""
}

// homebrewBottleCreated reads the bottle manifest index's
// org.opencontainers.image.created. Best effort: nil on any failure, like
// pub's /score and /publisher follow-ups — the primary document already
// answered. ghcr.io wants the anonymous token "QQ==" (brew sends the same).
func (p *registryMetadataProvider) homebrewBottleCreated(ctx context.Context, f *homebrew.Formula) *time.Time {
	tag := f.BottleTag()
	if !f.Versions.Bottle || len(f.Bottle.Stable.Files) == 0 || tag == "" {
		return nil
	}
	endpoint := strings.TrimRight(p.endpoints.homebrewBottles, "/") + "/v2/" + homebrew.CoreImagePrefix +
		homebrew.ImageName(f.Name) + "/manifests/" + url.PathEscape(tag)
	ctx, cancel := context.WithTimeout(ctx, ecosystemTimeout(ctx))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/vnd.oci.image.index.v1+json")
	req.Header.Set("Authorization", "Bearer QQ==")
	req.Header.Set("User-Agent", UserAgent("registry-metadata"))
	resp, err := p.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var idx struct {
		Annotations map[string]string `json:"annotations"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&idx) != nil {
		return nil
	}
	t, ok := parseTime(idx.Annotations["org.opencontainers.image.created"])
	if !ok {
		return nil
	}
	return &t
}
