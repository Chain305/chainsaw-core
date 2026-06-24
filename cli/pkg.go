package cli

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// --- Types ---

// repoPackageSummary mirrors index.PackageSummary returned by /api/repos/{repo}/packages.
type repoPackageSummary struct {
	Name     string   `json:"name"`
	Format   string   `json:"format"`
	Versions []string `json:"versions"`
}

// pkgSlugItem mirrors packageSlugPayload from /api/packages.
type pkgSlugItem struct {
	ID            string    `json:"id"`
	Repository    string    `json:"repository"`
	PackageName   string    `json:"package_name"`
	Format        string    `json:"format"`
	Description   string    `json:"description,omitempty"`
	VersionsCount int       `json:"versions_count"`
	LatestVersion string    `json:"latest_version,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// bomEntry mirrors the enriched BOM entry from /api/bom.
type bomEntry struct {
	Format             string `json:"format"`
	Repository         string `json:"repository"`
	PackageName        string `json:"package_name"`
	PackageVersion     string `json:"package_version"`
	LastInstallAttempt string `json:"last_install_attempt"`
	InstallCount       int    `json:"install_count"`
	LastOutcome        string `json:"last_outcome"`
	TrustScore         *int   `json:"trust_score,omitempty"`
	ProvenanceStatus   string `json:"provenance_status,omitempty"`
	MalwareStatus      string `json:"malware_status,omitempty"`
	MalwareID          string `json:"malware_id,omitempty"`
	TyposquatStatus    string `json:"typosquat_status,omitempty"`
	TyposquatSimilarTo string `json:"typosquat_similar_to,omitempty"`
	ChecksumVerified   *bool  `json:"checksum_verified,omitempty"`
	SourceRepo         string `json:"source_repo,omitempty"`
	RepoLinkStatus     string `json:"repo_link_status,omitempty"`

	// Signals added by the 13-PR consolidation. All omitempty so
	// clients pinned on the legacy BOM shape still parse cleanly.
	// Matches package_metadata.PackageMetadata naming.
	InstallScriptKind     string   `json:"install_script_kind,omitempty"`
	PublisherSet          []string `json:"publisher_set,omitempty"`
	PublisherChanged      *bool    `json:"publisher_changed,omitempty"`
	VersionAnomalyFlags   []string `json:"version_anomaly_flags,omitempty"`
	HiddenUnicodeHits     int      `json:"hidden_unicode_hits,omitempty"`
	PublishVelocity24h    int      `json:"publish_velocity_24h,omitempty"`
	RepoLinkLastCheckedAt string   `json:"repo_link_last_checked_at,omitempty"`
	ChecksumDeclared      string   `json:"checksum_declared,omitempty"`
	ChecksumActual        string   `json:"checksum_actual,omitempty"`
	TrustScoreBreakdown   string   `json:"trust_score_breakdown,omitempty"`
}

// --- Commands ---

var pkgCmd = &cobra.Command{
	Use:   "pkg",
	Short: "Package discovery and inspection commands",
}

// ── pkg list ──────────────────────────────────────────────────────────────────

var pkgListCmd = &cobra.Command{
	Use:   "list",
	Short: "List packages in a proxied registry",
	RunE:  runPkgList,
}

func init() {
	pkgListCmd.Flags().String("repo", "", "Repository name (required when --ecosystem is not set)")
	pkgListCmd.Flags().String("ecosystem", "", "Filter by ecosystem (npm, pypi, maven, …); routes to cross-repo inventory")
	pkgListCmd.Flags().Int("limit", 50, "Maximum number of rows to return")
	pkgListCmd.Flags().Bool("json", false, "Output as JSON")
	pkgCmd.AddCommand(pkgListCmd)
}

func runPkgList(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	repo, _ := cmd.Flags().GetString("repo")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	limit, _ := cmd.Flags().GetInt("limit")
	if limit <= 0 {
		limit = 50
	}
	asJSON, _ := cmd.Flags().GetBool("json")

	repo = strings.TrimSpace(repo)
	ecosystem = strings.TrimSpace(ecosystem)

	// Route to the cross-repo inventory endpoint when --ecosystem is set
	// or no --repo is given. The /api/inventory?view=by-package handler
	// (internal/server/inventory_api.go) returns rows aggregated across
	// every repository the caller can see.
	if ecosystem != "" || repo == "" {
		q := url.Values{}
		q.Set("view", "by-package")
		q.Set("limit", fmt.Sprintf("%d", limit))

		var resp struct {
			View string `json:"view"`
			Rows []struct {
				Ecosystem       string `json:"ecosystem"`
				PackageName     string `json:"package_name"`
				Version         string `json:"version"`
				Installs30d     int    `json:"installs_30d"`
				DistinctClients int    `json:"distinct_clients"`
				LastOutcome     string `json:"last_outcome,omitempty"`
			} `json:"rows"`
			Count int `json:"count"`
		}
		if err := client.Get("/api/inventory?"+q.Encode(), &resp); err != nil {
			return err
		}

		// Server doesn't filter by ecosystem natively (yet) — apply
		// client-side so --ecosystem still narrows the result set.
		filtered := resp.Rows[:0]
		for _, r := range resp.Rows {
			if ecosystem != "" && !strings.EqualFold(r.Ecosystem, ecosystem) {
				continue
			}
			filtered = append(filtered, r)
		}

		if asJSON {
			return PrintJSON(filtered)
		}

		if len(filtered) == 0 {
			fmt.Fprintln(cmd.ErrOrStderr(), "No packages found.")
			return nil
		}

		rows := make([][]string, len(filtered))
		for i, p := range filtered {
			rows[i] = []string{
				p.PackageName,
				p.Ecosystem,
				p.Version,
				fmt.Sprintf("%d", p.Installs30d),
				fmt.Sprintf("%d", p.DistinctClients),
			}
		}
		PrintTable([]string{"NAME", "ECOSYSTEM", "VERSION", "INSTALLS_30D", "CLIENTS"}, rows)
		return nil
	}

	// Per-repo path — preserves the legacy behavior when --repo is set
	// and --ecosystem is not.
	var resp struct {
		Repository string               `json:"repository"`
		Packages   []repoPackageSummary `json:"packages"`
	}
	if err := client.Get("/api/repos/"+repo+"/packages", &resp); err != nil {
		return err
	}

	if limit > 0 && len(resp.Packages) > limit {
		resp.Packages = resp.Packages[:limit]
	}

	if asJSON {
		return PrintJSON(resp.Packages)
	}

	if len(resp.Packages) == 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "No packages found in repository %q.\n", repo)
		return nil
	}

	rows := make([][]string, len(resp.Packages))
	for i, p := range resp.Packages {
		latest := ""
		if len(p.Versions) > 0 {
			latest = p.Versions[len(p.Versions)-1]
		}
		rows[i] = []string{
			p.Name,
			p.Format,
			fmt.Sprintf("%d", len(p.Versions)),
			latest,
		}
	}
	PrintTable([]string{"NAME", "FORMAT", "VERSIONS", "LATEST"}, rows)
	return nil
}

// ── pkg search ────────────────────────────────────────────────────────────────

var pkgSearchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search packages across all repositories",
	Args:  cobra.ExactArgs(1),
	RunE:  runPkgSearch,
}

func init() {
	pkgSearchCmd.Flags().Bool("json", false, "Output as JSON")
	pkgCmd.AddCommand(pkgSearchCmd)
}

func runPkgSearch(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	q := url.Values{}
	q.Set("search", args[0])

	var resp struct {
		Packages []pkgSlugItem `json:"packages"`
	}
	if err := client.Get("/api/packages?"+q.Encode(), &resp); err != nil {
		return err
	}

	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		return PrintJSON(resp.Packages)
	}

	if len(resp.Packages) == 0 {
		fmt.Printf("No packages found matching %q.\n", args[0])
		return nil
	}

	rows := make([][]string, len(resp.Packages))
	for i, p := range resp.Packages {
		rows[i] = []string{
			p.PackageName,
			p.Repository,
			p.Format,
			fmt.Sprintf("%d", p.VersionsCount),
			p.LatestVersion,
			p.UpdatedAt.Format("2006-01-02"),
		}
	}
	PrintTable([]string{"NAME", "REPOSITORY", "FORMAT", "VERSIONS", "LATEST", "UPDATED"}, rows)
	return nil
}

// ── pkg info ──────────────────────────────────────────────────────────────────

var pkgInfoCmd = &cobra.Command{
	Use:   "info <name@version>",
	Short: "Show detailed info for a package: installs, vulnerabilities, trust score",
	Args:  cobra.ExactArgs(1),
	RunE:  runPkgInfo,
}

func init() {
	pkgInfoCmd.Flags().Bool("json", false, "Output as JSON")
	pkgCmd.AddCommand(pkgInfoCmd)
	rootCmd.AddCommand(pkgCmd)
}

func runPkgInfo(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	pkgName, pkgVersion := splitPackageArg(args[0])
	if pkgName == "" {
		return fmt.Errorf("invalid package argument — expected name@version")
	}

	q := url.Values{}
	q.Set("package_name", pkgName)
	if pkgVersion != "" {
		q.Set("version", pkgVersion)
	}
	q.Set("limit", "1")

	var resp struct {
		Entries []bomEntry `json:"entries"`
		Total   int        `json:"total"`
	}
	if err := client.Get("/api/bom?"+q.Encode(), &resp); err != nil {
		return err
	}

	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		if len(resp.Entries) == 0 {
			return PrintJSON(map[string]any{"package": args[0], "found": false})
		}
		return PrintJSON(resp.Entries[0])
	}

	if len(resp.Entries) == 0 {
		fmt.Printf("Package %q not found in BOM.\n", args[0])
		return nil
	}

	e := resp.Entries[0]
	fmt.Printf("Package:     %s@%s\n", e.PackageName, e.PackageVersion)
	fmt.Printf("Ecosystem:   %s\n", e.Format)
	fmt.Printf("Repository:  %s\n", e.Repository)
	fmt.Printf("Last seen:   %s\n", e.LastInstallAttempt)
	fmt.Printf("Installs:    %d\n", e.InstallCount)
	fmt.Printf("Outcome:     %s\n", e.LastOutcome)
	if e.TrustScore != nil {
		fmt.Printf("Trust score: %d\n", *e.TrustScore)
	}
	if e.ProvenanceStatus != "" {
		fmt.Printf("Provenance:  %s\n", e.ProvenanceStatus)
	}
	if e.MalwareStatus != "" {
		status := e.MalwareStatus
		if e.MalwareID != "" {
			status += " (" + e.MalwareID + ")"
		}
		fmt.Printf("Malware:     %s\n", status)
	}
	if e.TyposquatStatus != "" {
		status := e.TyposquatStatus
		if e.TyposquatSimilarTo != "" {
			status += " (similar to " + e.TyposquatSimilarTo + ")"
		}
		fmt.Printf("Typosquat:   %s\n", status)
	}
	if e.ChecksumVerified != nil {
		verified := "no"
		if *e.ChecksumVerified {
			verified = "yes"
		}
		fmt.Printf("Checksum:    %s\n", verified)
	}
	if e.SourceRepo != "" {
		fmt.Printf("Source repo: %s\n", e.SourceRepo)
	}
	if e.RepoLinkStatus != "" {
		fmt.Printf("Repo link:   %s\n", e.RepoLinkStatus)
	}

	// Supply-chain signals section — only printed when at least one of
	// the new condition inputs is populated, so packages scanned
	// before the 13-PR rollout render exactly as before.
	if hasSupplyChainSection(e) {
		printSupplyChainSection(e)
	}

	if resp.Total > 1 {
		fmt.Printf("\n(showing 1 of %d matching entries)\n", resp.Total)
	}

	// Show license from SBOM if available.
	var sbomResp struct {
		Components []struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Licenses []struct {
				License struct {
					ID string `json:"id"`
				} `json:"license"`
			} `json:"licenses,omitempty"`
		} `json:"components"`
	}
	sbomQ := url.Values{}
	sbomQ.Set("package_name", pkgName)
	if pkgVersion != "" {
		sbomQ.Set("version", pkgVersion)
	}
	if err := client.Get("/api/sbom?"+sbomQ.Encode(), &sbomResp); err == nil {
		for _, c := range sbomResp.Components {
			if strings.EqualFold(c.Name, pkgName) && (pkgVersion == "" || c.Version == pkgVersion) {
				for _, lic := range c.Licenses {
					if lic.License.ID != "" {
						fmt.Printf("License:     %s\n", lic.License.ID)
					}
				}
				break
			}
		}
	}

	return nil
}

// hasSupplyChainSection reports whether the BOM entry carries any of
// the 13-PR supply-chain signals worth rendering in a dedicated
// "Supply chain signals" section. Provenance/typosquat/malware are
// already shown in the legacy block above, so only the *new* fields
// trigger this section.
func hasSupplyChainSection(e bomEntry) bool {
	if e.InstallScriptKind != "" && e.InstallScriptKind != "none" {
		return true
	}
	if len(e.PublisherSet) > 0 || (e.PublisherChanged != nil && *e.PublisherChanged) {
		return true
	}
	if len(e.VersionAnomalyFlags) > 0 {
		return true
	}
	if e.HiddenUnicodeHits > 0 {
		return true
	}
	if e.PublishVelocity24h > 0 {
		return true
	}
	if e.RepoLinkLastCheckedAt != "" {
		return true
	}
	if e.ChecksumDeclared != "" || e.ChecksumActual != "" {
		return true
	}
	if e.TrustScoreBreakdown != "" {
		return true
	}
	return false
}

// printSupplyChainSection writes a "Supply chain signals" block mirroring
// the existing field-formatting conventions (label-aligned, trailing
// newline on each row, no color). Long checksum values are truncated
// to keep the block readable — the full value is always available in
// the JSON output via `--json`.
func printSupplyChainSection(e bomEntry) {
	fmt.Println()
	fmt.Println("Supply chain signals:")
	if e.InstallScriptKind != "" && e.InstallScriptKind != "none" {
		fmt.Printf("  Install-script:       %s\n", e.InstallScriptKind)
	}
	if len(e.PublisherSet) > 0 {
		changed := ""
		if e.PublisherChanged != nil && *e.PublisherChanged {
			changed = " (CHANGED vs prior version)"
		}
		fmt.Printf("  Publisher set:        %s%s\n", strings.Join(e.PublisherSet, ", "), changed)
	} else if e.PublisherChanged != nil && *e.PublisherChanged {
		fmt.Printf("  Publisher changed:    yes\n")
	}
	if len(e.VersionAnomalyFlags) > 0 {
		fmt.Printf("  Version anomaly:      %s\n", strings.Join(e.VersionAnomalyFlags, ", "))
	}
	if e.HiddenUnicodeHits > 0 {
		fmt.Printf("  Hidden unicode hits:  %d\n", e.HiddenUnicodeHits)
	}
	if e.PublishVelocity24h > 0 {
		fmt.Printf("  Publish velocity 24h: %d\n", e.PublishVelocity24h)
	}
	if e.RepoLinkStatus != "" || e.RepoLinkLastCheckedAt != "" {
		line := e.RepoLinkStatus
		if line == "" {
			line = "unknown"
		}
		if e.RepoLinkLastCheckedAt != "" {
			line += " (last checked " + e.RepoLinkLastCheckedAt + ")"
		}
		fmt.Printf("  Repo link:            %s\n", line)
	}
	if e.ChecksumDeclared != "" || e.ChecksumActual != "" {
		fmt.Printf("  Checksum declared:    %s\n", truncateHashPkg(e.ChecksumDeclared))
		fmt.Printf("  Checksum actual:      %s\n", truncateHashPkg(e.ChecksumActual))
	}
	if e.TrustScore != nil && e.TrustScoreBreakdown != "" {
		fmt.Printf("  Trust score:          %d (breakdown: %s)\n", *e.TrustScore, e.TrustScoreBreakdown)
	}
}

// truncateHashPkg truncates a potentially long hex string for display.
// Keeps first 20 chars — enough for operators to eyeball the prefix —
// and appends an ellipsis. Named with a `Pkg` suffix to avoid
// clobbering the scan.go helper of the same intent with a different
// truncation length.
func truncateHashPkg(s string) string {
	if s == "" {
		return "—"
	}
	if len(s) <= 24 {
		return s
	}
	return s[:20] + "..."
}
