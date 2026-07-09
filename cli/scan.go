package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	depanalyzer "github.com/chain305/chainsaw-core/depparser/analyzer"
)

// scanSchemaVersion identifies the JSON envelope shape `chainsaw scan` emits.
// P2.11 — a top-level schemaVersion lets a structured consumer pin on a known
// envelope and detect a future breaking change without diffing the whole body.
// Bump only on a backward-incompatible envelope change; additive fields keep
// the same version.
const scanSchemaVersion = "chainsaw.scan/v1"

// scanStdin is the input stream stdin-batch mode reads from. Indirected so
// tests can feed a deterministic reader without touching the real os.Stdin.
// Production leaves it pointing at os.Stdin.
var scanStdin io.Reader = os.Stdin

// severityRank maps severity strings to ordinal values for comparison.
var severityRank = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"none":     0,
}

// supplyChainConditionSeverity maps a triggered supply-chain condition
// name to the severity level it contributes for the `--severity` /
// `--fail-on` filters. These mirror the product decisions taken in the
// 13-PR consolidation:
//
//   - publisherChanged / installScriptFetchesRemote / hasHiddenUnicode
//     / publishVelocityAnomaly / malware / repo_link=missing →  high —
//     these are the “treat as actively hostile” signals; a CI that
//     pins `--fail-on high` should break the build.
//   - hasInstallScript (alone) / versionAnomaly / typosquat → medium —
//     suspicious but not yet indicative of compromise.
//   - provenance=unverified / repo_link=archived → low — worth
//     flagging but not CI-breaking by default.
//
// Any condition not listed here contributes "none" and is therefore
// informational only.
var supplyChainConditionSeverity = map[string]string{
	"publisherChanged":           "high",
	"installScriptFetchesRemote": "high",
	"hasHiddenUnicode":           "high",
	"publishVelocityAnomaly":     "high",
	"malware":                    "high",
	"repoLinkMissing":            "high",
	"hasInstallScript":           "medium",
	"versionAnomaly":             "medium",
	"typosquat":                  "medium",
	"provenanceUnverified":       "low",
	"repoLinkArchived":           "low",
}

type scanPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type scanResultItem struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Repository string   `json:"repository,omitempty"`
	Status     string   `json:"status"`
	Severity   string   `json:"severity,omitempty"`
	CVSSScore  *float64 `json:"cvss_score,omitempty"`
	EPSSScore  *float64 `json:"epss_score,omitempty"`
	CVEs       []string `json:"cves,omitempty"`

	// Supply-chain signals surfaced from the 13-PR consolidation. The
	// server populates these from package_metadata on the scan path; the
	// CLI just re-emits them in JSON and collapses them into the text
	// table when any value is non-default. Every field is `omitempty`
	// so the JSON schema stays backward-compatible for consumers that
	// pin on the legacy vulnerability-only shape.
	TrustScore                *int     `json:"trust_score,omitempty"`
	InstallScriptKind         string   `json:"install_script_kind,omitempty"`
	PublisherChanged          *bool    `json:"publisher_changed,omitempty"`
	PublisherSet              []string `json:"publisher_set,omitempty"`
	VersionAnomalyFlags       []string `json:"version_anomaly_flags,omitempty"`
	HiddenUnicodeHits         int      `json:"hidden_unicode_hits,omitempty"`
	HiddenUnicodeKinds        []string `json:"hidden_unicode_kinds,omitempty"`
	PublishVelocity24h        int      `json:"publish_velocity_24h,omitempty"`
	RepoLinkStatus            string   `json:"repo_link_status,omitempty"`
	RepoLinkLastCheckedAt     string   `json:"repo_link_last_checked_at,omitempty"`
	ChecksumDeclared          string   `json:"checksum_declared,omitempty"`
	ChecksumActual            string   `json:"checksum_actual,omitempty"`
	ChecksumUnavailableReason string   `json:"checksum_unavailable_reason,omitempty"`
	ProvenanceStatus          string   `json:"provenance_status,omitempty"`
	MalwareStatus             string   `json:"malware_status,omitempty"`
	TyposquatStatus           string   `json:"typosquat_status,omitempty"`
	// TriggeredConditions lists policy conditions that fire for this
	// package (CLI derives from the signal values above — see
	// deriveTriggeredConditions). Used for `--fail-on` and severity
	// mapping, and echoed in JSON so CI integrations can gate on
	// specific supply-chain conditions without re-implementing the
	// derivation.
	TriggeredConditions []string `json:"triggered_conditions,omitempty"`
}

type scanAPIResponse struct {
	Results    []scanResultItem `json:"results"`
	Total      int              `json:"total"`
	Vulnerable int              `json:"vulnerable"`
	Unscanned  int              `json:"unscanned"`
}

var scanCmd = &cobra.Command{
	Use:     "scan [package@version | -]",
	GroupID: GrpScan,
	Short:   "Scan packages for vulnerabilities",
	Long: `Scan one or more packages for known vulnerabilities using the Chainsaw server.

Output formats (--format / --json / --output):
  table   human-readable table (default)
  json    structured envelope (--json is sugar for --format=json)
  sarif   SARIF 2.1.0 log for code-scanning ingesters (normally with --output)

Batch input:
  chainsaw scan -            read newline-delimited package specs / lockfile
  chainsaw scan --stdin      paths from stdin (opt-in; bare scan never reads stdin)

Examples:
  chainsaw scan lodash@4.17.11
  chainsaw scan --path .
  chainsaw scan --path . --severity high
  chainsaw scan --path . --fail-on critical --json
  chainsaw scan --path . --format sarif --output results.sarif
  cat specs.txt | chainsaw scan -`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().String("path", "", "Scan all dependencies found in a local project manifest")
	scanCmd.Flags().String("severity", "", "Minimum severity to display: critical, high, medium, low")
	scanCmd.Flags().String("fail-on", "", "Exit 1 only when vulnerabilities at or above this severity are found")
	scanCmd.Flags().Bool("stdin", false, "Read newline-delimited package specs / lockfile paths from stdin (opt-in; same as the `-` arg)")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	scanStart := time.Now()
	pathFlag, _ := cmd.Flags().GetString("path")
	severityFlag, _ := cmd.Flags().GetString("severity")
	failOnFlag, _ := cmd.Flags().GetString("fail-on")
	stdinFlag, _ := cmd.Flags().GetBool("stdin")

	// P2.9 — stdin batch is STRICTLY opt-in. It engages only when the user
	// passes --stdin or the conventional `-` arg; a bare `chainsaw scan` must
	// never block waiting on stdin. We strip the `-` sentinel from args so the
	// later positional-package path doesn't try to parse it as name@version.
	useStdin := stdinFlag
	rest := args
	if len(rest) > 0 && rest[0] == "-" {
		useStdin = true
		rest = rest[1:]
	}

	if !useStdin && len(rest) == 0 && pathFlag == "" {
		// Bad argument shape → ExitUsage(4), consistent with cobra's own
		// unknown-flag handling (invariant B: usage != operational error).
		return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf("specify a package (e.g. lodash@4.17.11), --path <dir>, or - / --stdin to read from stdin")}
	}

	if severityFlag != "" {
		if _, ok := severityRank[severityFlag]; !ok {
			return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf("unknown --severity %q; use critical, high, medium, or low", severityFlag)}
		}
	}
	if failOnFlag != "" {
		if _, ok := severityRank[failOnFlag]; !ok {
			return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf("unknown --fail-on %q; use critical, high, medium, or low", failOnFlag)}
		}
	}

	client := newClient()
	if client.baseURL == "" {
		// Missing server config → ExitConfigAuth(3).
		return &ExitCodeError{Code: ExitConfigAuth, Err: errServerNotConfigured(cmd)}
	}
	if cfgToken() == "" {
		// Not authenticated → ExitConfigAuth(3).
		return &ExitCodeError{Code: ExitConfigAuth, Err: fmt.Errorf("not authenticated — run 'chainsaw auth login' first")}
	}

	const maxPackages = 10_000

	var packages []scanPkg
	switch {
	case useStdin:
		var err error
		packages, err = collectFromStdin(scanStdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		if len(packages) == 0 {
			fmt.Fprintln(os.Stderr, "error: no package specs or parseable lockfile paths read from stdin")
			os.Exit(2)
		}
		if len(packages) > maxPackages {
			fmt.Fprintf(os.Stderr, "error: read %d packages from stdin; maximum per scan is %d — narrow the input\n", len(packages), maxPackages)
			os.Exit(2)
		}
	case pathFlag != "":
		if _, err := os.Stat(pathFlag); err != nil {
			fmt.Fprintf(os.Stderr, "error: --path %q: %v\n", pathFlag, err)
			os.Exit(2)
		}
		var err error
		packages, err = collectFromManifests(pathFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		if len(packages) == 0 {
			fmt.Fprintf(os.Stderr, "error: no pinned dependencies found in %s\n", pathFlag)
			os.Exit(2)
		}
		if len(packages) > maxPackages {
			fmt.Fprintf(os.Stderr, "error: found %d packages; maximum per scan is %d — narrow the scope with a subdirectory\n", len(packages), maxPackages)
			os.Exit(2)
		}
	default:
		pkg, err := parsePackageRef(rest[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		packages = []scanPkg{pkg}
	}

	// Resolve the result format up-front: it gates both the progress notice
	// below and the final output rendering. --json is sugar for --format=json
	// (resolveFormat reconciles the two); --format=sarif selects the SARIF
	// emitter. Any non-table format is "machine-readable" for the purpose of
	// keeping stderr clean.
	format := resolveFormat(cmd)
	machineFmt := format != "table"

	// Surface a one-line progress notice before the (potentially long,
	// blocking) scan POST so the user isn't staring at a frozen terminal
	// while up to 10k packages are evaluated server-side. Suppressed for any
	// machine format so structured consumers see no extra stderr line. The
	// notice is chatter — quiet() also suppresses it (it MUST NOT change a
	// block reason or exit code, only chatter).
	if !machineFmt && !quiet(cmd) {
		fmt.Fprintf(os.Stderr, "scanning %d package(s)…\n", len(packages))
	}

	var resp scanAPIResponse
	if err := client.Post("/api/scan", map[string]any{"packages": packages}, &resp); err != nil {
		// Return the error so Execute()/classifyCLIError buckets it: 401/403 →
		// ExitConfigAuth(3), network/IO → ExitOpError(2). A bare os.Exit(2) here
		// mislabels an auth failure as an operational error (invariant B).
		return err
	}

	// Derive triggered supply-chain conditions for each result — uses
	// the signals the server merged in from package_metadata. We fold
	// them back into the result so downstream text/JSON/--fail-on
	// paths can treat supply-chain conditions as first-class
	// citizens alongside CVE-based severity.
	for i := range resp.Results {
		resp.Results[i].TriggeredConditions = deriveTriggeredConditions(resp.Results[i])
		resp.Results[i].Severity = resolveHighestSeverity(resp.Results[i])
	}

	// Apply severity display filter. A result is shown when its
	// effective severity (CVE severity OR the highest supply-chain
	// condition severity) is at or above --severity. This means
	// `--severity high` now surfaces publisherChanged /
	// hasHiddenUnicode / etc. packages even if they carry no CVE —
	// which is the whole point of wiring the new conditions in.
	displayed := resp.Results
	if severityFlag != "" {
		minRank := severityRank[severityFlag]
		// Allocate a fresh slice rather than filtering in place
		// (displayed[:0]) — the exit-code gate below iterates the
		// unfiltered resp.Results, and an in-place filter would alias and
		// overwrite that backing array, silently defeating the gate.
		filtered := make([]scanResultItem, 0, len(resp.Results))
		for _, r := range resp.Results {
			if severityRank[r.Severity] >= minRank {
				filtered = append(filtered, r)
			}
		}
		displayed = filtered
	}

	switch format {
	case "json":
		// P2.11 — schemaVersion is a NEW top-level field; every pre-existing
		// key (results/total/vulnerable/unscanned) keeps its name and meaning so
		// existing --json consumers stay byte-compatible apart from the added
		// field. Results go to the --output sink (a file when set, else stdout)
		// so JSON purity holds: stdout carries only the envelope, logs stay on
		// stderr.
		_ = PrintJSONTo(cmd, map[string]any{
			"schemaVersion": scanSchemaVersion,
			"results":       displayed,
			"total":         resp.Total,
			"vulnerable":    resp.Vulnerable,
			"unscanned":     resp.Unscanned,
		})
	case "sarif":
		// SARIF is normally redirected to a file via --output; outWriter honors
		// that and falls back to stdout otherwise. We emit the FULL result set
		// (not the --severity-filtered view) so a code-scanning ingester sees
		// every finding the gate considered — --severity is a human display
		// filter, not a SARIF-scope control.
		if err := writeScanSARIF(outWriter(cmd), resp.Results); err != nil {
			fmt.Fprintf(os.Stderr, "error: write sarif: %v\n", err)
			os.Exit(2)
		}
	default:
		// Surface the unscanned count before the table/clean message so an
		// operator never reads "no signals found" as "tree is clean" when
		// the server actually could not evaluate some packages. JSON output
		// already carries `unscanned`, so this is the human-path equivalent.
		// quiet() gates this NOTE (chatter), never the table itself.
		if resp.Unscanned > 0 && !quiet(cmd) {
			fmt.Fprintf(os.Stderr, "note: %d package(s) could not be scanned\n", resp.Unscanned)
		}
		printScanTable(displayed)
	}

	emit("cli.scan.completed", map[string]any{
		"duration_ms":      time.Since(scanStart).Milliseconds(),
		"packages_scanned": resp.Total,
		"blocked_count":    resp.Vulnerable,
	})

	// Determine exit code.
	// --fail-on integrates BOTH vulnerability-derived severity AND the
	// new supply-chain triggered conditions. A package with no CVE but
	// publisherChanged=true will still break the build at
	// `--fail-on high` — which is the behavior CI users asked for in
	// the 13-PR consolidation review.
	//
	// A threshold breach is the EXPECTED enforcement outcome, so it is returned
	// as ExitCodeError{Code: ExitBlocked} (NOT a raw os.Exit(1)). ExitBlocked is
	// still 1, so every existing block-gating script is unchanged; routing it
	// through the typed error lets Execute() classify it as a block rather than
	// an operational failure (which now maps to ExitOpError(2)). The error
	// carries no message so renderError stays silent — the findings already
	// printed above are the user-facing block reason.
	if failOnFlag != "" {
		threshold := severityRank[failOnFlag]
		for _, r := range resp.Results {
			if severityRank[r.Severity] >= threshold {
				return &ExitCodeError{Code: ExitBlocked}
			}
		}
	} else {
		// Default: block if any vulnerable result OR any high/critical
		// supply-chain condition was triggered. The gate scans the full
		// resp.Results set, NOT the --severity-filtered `displayed` slice:
		// `--severity` controls only what the user sees, so a high or
		// vulnerable package filtered out of the view must still break the
		// build. Mirrors the --fail-on branch above, which also iterates
		// resp.Results.
		for _, r := range resp.Results {
			if r.Status == "vulnerable" {
				return &ExitCodeError{Code: ExitBlocked}
			}
			if severityRank[r.Severity] >= severityRank["high"] {
				return &ExitCodeError{Code: ExitBlocked}
			}
		}
	}
	return nil
}

// deriveTriggeredConditions inspects the enriched scan result and
// returns the ordered list of supply-chain conditions that are
// effectively "tripped" for this package. The condition names match
// the policy.Conditions JSON keys (so CI integrations can cross-match
// against a `chainsaw policy list` output) with two exceptions that
// collapse the signal namespace onto our severity map:
// "malware"/"typosquat" subsume the per-status strings,
// "repoLinkMissing"/"repoLinkArchived" subsume the per-status
// RepoLinkStatus values, and "provenanceUnverified" covers
// {unverified, missing, failed}.
func deriveTriggeredConditions(r scanResultItem) []string {
	var out []string
	if r.InstallScriptKind != "" && r.InstallScriptKind != "none" {
		out = append(out, "hasInstallScript")
		if r.InstallScriptKind == "fetches_remote" || r.InstallScriptKind == "eval_encoded" {
			out = append(out, "installScriptFetchesRemote")
		}
	}
	if r.PublisherChanged != nil && *r.PublisherChanged {
		out = append(out, "publisherChanged")
	}
	if len(r.VersionAnomalyFlags) > 0 {
		out = append(out, "versionAnomaly")
	}
	if r.HiddenUnicodeHits > 0 {
		out = append(out, "hasHiddenUnicode")
	}
	if r.PublishVelocity24h > 0 {
		// The server persists the counter; the *threshold* is policy-
		// driven, so the CLI treats any non-zero 24h velocity as
		// "the policy condition could fire" for display purposes.
		// Actual pass/fail gating happens at policy evaluation time
		// on the server — this is informational for the scan view.
		out = append(out, "publishVelocityAnomaly")
	}
	switch r.MalwareStatus {
	case "malicious":
		out = append(out, "malware")
	}
	switch r.TyposquatStatus {
	case "suspected", "confirmed":
		out = append(out, "typosquat")
	}
	switch r.RepoLinkStatus {
	case "missing", "ownership_mismatch":
		out = append(out, "repoLinkMissing")
	case "archived":
		out = append(out, "repoLinkArchived")
	}
	switch r.ProvenanceStatus {
	case "unverified", "missing", "failed":
		out = append(out, "provenanceUnverified")
	}
	return out
}

// resolveHighestSeverity picks the max of the CVE-derived severity and
// every supply-chain condition's contributed severity. Used by the
// display filter and --fail-on gate so a non-vulnerable package with
// a high-severity supply-chain signal still surfaces.
func resolveHighestSeverity(r scanResultItem) string {
	best := r.Severity
	if best == "" && r.Status == "vulnerable" {
		best = "low"
	}
	bestRank := severityRank[best]
	for _, cond := range r.TriggeredConditions {
		sev, ok := supplyChainConditionSeverity[cond]
		if !ok {
			continue
		}
		if severityRank[sev] > bestRank {
			bestRank = severityRank[sev]
			best = sev
		}
	}
	return best
}

func printScanTable(results []scanResultItem) {
	if len(results) == 0 {
		fmt.Println("No vulnerabilities or supply-chain signals found.")
		return
	}
	rows := make([][]string, len(results))
	anySignals := false
	for i, r := range results {
		cvss := "—"
		if r.CVSSScore != nil {
			cvss = fmt.Sprintf("%.1f", *r.CVSSScore)
		}
		cves := "—"
		if len(r.CVEs) > 0 {
			cves = strings.Join(r.CVEs, ", ")
		}
		severity := r.Severity
		if severity == "" {
			severity = r.Status
		}
		signals := "—"
		if len(r.TriggeredConditions) > 0 {
			signals = strings.Join(r.TriggeredConditions, ", ")
			anySignals = true
		}
		rows[i] = []string{r.Name, r.Version, severity, cvss, cves, signals}
	}
	PrintTable([]string{"PACKAGE", "VERSION", "SEVERITY", "CVSS", "CVEs", "SIGNALS"}, rows)

	// Per-package detail lines for the non-trivial supply-chain signals.
	// We keep the table compact and drop the full context underneath
	// — matches the existing `pkg info` aesthetic and avoids wrapping
	// long repo-status / checksum / publisher-set strings into the
	// tabwriter columns.
	if anySignals {
		fmt.Println()
		for _, r := range results {
			if !hasNonDefaultSupplyChainSignal(r) {
				continue
			}
			fmt.Printf("%s@%s\n", r.Name, r.Version)
			if r.InstallScriptKind != "" && r.InstallScriptKind != "none" {
				fmt.Printf("  install-script:       %s\n", r.InstallScriptKind)
			}
			if r.PublisherChanged != nil && *r.PublisherChanged {
				fmt.Printf("  publisher-changed:    yes\n")
			}
			if len(r.VersionAnomalyFlags) > 0 {
				fmt.Printf("  version-anomaly:      %s\n", strings.Join(r.VersionAnomalyFlags, ","))
			}
			if r.HiddenUnicodeHits > 0 {
				kinds := ""
				if len(r.HiddenUnicodeKinds) > 0 {
					kinds = " (" + strings.Join(r.HiddenUnicodeKinds, ",") + ")"
				}
				fmt.Printf("  hidden-unicode:       %d hit(s)%s\n", r.HiddenUnicodeHits, kinds)
			}
			if r.PublishVelocity24h > 0 {
				fmt.Printf("  publish-velocity-24h: %d\n", r.PublishVelocity24h)
			}
			if r.RepoLinkStatus != "" && r.RepoLinkStatus != "ok" {
				fmt.Printf("  repo-link-status:     %s\n", r.RepoLinkStatus)
			}
			if r.ChecksumDeclared != "" || r.ChecksumActual != "" {
				fmt.Printf("  checksum:             declared=%s actual=%s\n",
					truncateHash(r.ChecksumDeclared), truncateHash(r.ChecksumActual))
			}
			if r.ChecksumUnavailableReason != "" {
				fmt.Printf("  checksum-unavailable: %s\n", r.ChecksumUnavailableReason)
			}
		}
	}
}

// hasNonDefaultSupplyChainSignal reports whether a scan result carries
// any non-default supply-chain signal — used to decide whether the
// per-package detail block is worth printing for this row.
func hasNonDefaultSupplyChainSignal(r scanResultItem) bool {
	if r.InstallScriptKind != "" && r.InstallScriptKind != "none" {
		return true
	}
	if r.PublisherChanged != nil && *r.PublisherChanged {
		return true
	}
	if len(r.VersionAnomalyFlags) > 0 {
		return true
	}
	if r.HiddenUnicodeHits > 0 {
		return true
	}
	if r.PublishVelocity24h > 0 {
		return true
	}
	if r.RepoLinkStatus != "" && r.RepoLinkStatus != "ok" {
		return true
	}
	if r.ChecksumDeclared != "" || r.ChecksumActual != "" {
		return true
	}
	if r.ChecksumUnavailableReason != "" {
		return true
	}
	return false
}

// truncateHash renders a potentially-long checksum string for the
// text table: keeps the first 12 hex chars, collapses the rest.
// Empty input returns an em dash.
func truncateHash(s string) string {
	if s == "" {
		return "—"
	}
	if len(s) <= 16 {
		return s
	}
	return s[:12] + "..."
}

func parsePackageRef(ref string) (scanPkg, error) {
	idx := strings.LastIndex(ref, "@")
	if idx <= 0 {
		return scanPkg{}, fmt.Errorf("invalid package ref %q — use name@version (e.g. lodash@4.17.11)", ref)
	}
	return scanPkg{Name: ref[:idx], Version: ref[idx+1:]}, nil
}

// collectFromManifests walks dir recursively and returns every pinned
// (name, version) pair produced by chainsaw's dependency-parser
// registry. Every manifest and lockfile format is discovered and parsed
// by internal/depparser/analyzer — there is no in-package switch here;
// adding a new ecosystem is a new file under internal/depparser/parser/,
// not an edit to this function.
//
// Parser errors for a single file are surfaced as a single aggregate
// warning (the walk continues), so one malformed lockfile in a monorepo
// does not fail the overall scan. A complete absence of parseable files
// returns an error to preserve the old CLI behaviour of "tell the user
// we scanned nothing".
func collectFromManifests(dir string) ([]scanPkg, error) {
	regPkgs, err := depanalyzer.WalkDir(context.Background(), dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: depparser walk: %v\n", err)
	}
	if len(regPkgs) == 0 {
		return nil, fmt.Errorf("no supported manifest or lockfile found in %s (see internal/depparser/analyzer for the full supported list)", dir)
	}

	all := make([]scanPkg, 0, len(regPkgs))
	seen := make(map[string]bool, len(regPkgs))
	for _, p := range regPkgs {
		if p.Name == "" || p.Version == "" {
			continue
		}
		key := p.Name + "@" + p.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		all = append(all, scanPkg{Name: p.Name, Version: p.Version})
	}
	return all, nil
}

// collectFromStdin reads newline-delimited input (P2.9 stdin batch) and returns
// the deduplicated package set. Each non-blank, non-comment line is either:
//
//   - a package spec "name@version" (e.g. lodash@4.17.11), or
//   - a filesystem path to a manifest/lockfile (parsed via the depparser
//     registry) or a directory (walked recursively).
//
// Spec lines and path lines may be freely interleaved. A line that is neither a
// valid spec nor an existing path is reported as a single aggregate warning to
// stderr and skipped, so one bad line never aborts a large batch. The caller
// (runScan) decides what an EMPTY result means — this function only returns an
// error for a hard read failure on the stream itself.
//
// SECURITY/SAFETY: this is only ever reached when the user explicitly opted in
// with `-` or --stdin; a bare `chainsaw scan` never calls it, so the CLI never
// blocks waiting on stdin by default.
func collectFromStdin(r io.Reader) ([]scanPkg, error) {
	if r == nil {
		return nil, nil
	}
	all := make([]scanPkg, 0, 16)
	seen := make(map[string]bool, 16)
	add := func(name, version string) {
		if name == "" || version == "" {
			return
		}
		key := name + "@" + version
		if seen[key] {
			return
		}
		seen[key] = true
		all = append(all, scanPkg{Name: name, Version: version})
	}

	var skipped int
	sc := bufio.NewScanner(r)
	// Lockfile paths are short; a generous line cap guards against a pathological
	// single line without allowing unbounded growth.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // blank line or comment
		}

		// Prefer a filesystem path: a manifest/lockfile or directory expands to
		// its full pinned dependency set. We check Stat first so a path that
		// happens to contain "@" (unusual, but possible) isn't mis-parsed as a
		// spec.
		if info, err := os.Stat(line); err == nil {
			pkgs, perr := collectFromPath(line, info.IsDir())
			if perr != nil {
				fmt.Fprintf(os.Stderr, "warning: stdin path %q: %v\n", line, perr)
				skipped++
				continue
			}
			for _, p := range pkgs {
				add(p.Name, p.Version)
			}
			continue
		}

		// Otherwise treat the line as a name@version spec.
		if pkg, err := parsePackageRef(line); err == nil {
			add(pkg.Name, pkg.Version)
			continue
		}

		fmt.Fprintf(os.Stderr, "warning: stdin line %q is neither a package spec (name@version) nor an existing path; skipping\n", line)
		skipped++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	_ = skipped // surfaced per-line above; kept for future telemetry hooks
	return all, nil
}

// collectFromPath returns the pinned packages for a single stdin-supplied path:
// a directory is walked recursively (collectFromManifests), a single file is
// parsed by content through the depparser registry. Split out so collectFromStdin
// stays readable and both branches share the (name, version) normalization.
func collectFromPath(path string, isDir bool) ([]scanPkg, error) {
	if isDir {
		return collectFromManifests(path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	regPkgs, err := depanalyzer.ParseBytes(context.Background(), path, content)
	if err != nil {
		return nil, err
	}
	out := make([]scanPkg, 0, len(regPkgs))
	for _, p := range regPkgs {
		if p.Name == "" || p.Version == "" {
			continue
		}
		out = append(out, scanPkg{Name: p.Name, Version: p.Version})
	}
	return out, nil
}
