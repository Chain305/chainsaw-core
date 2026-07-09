package cli

// doctor_offline.go — `chainsaw doctor --offline` implementation (W4).
//
// Walks every intelligence provider / signal Chainsaw evaluates and
// reports whether it can run in an air-gapped deployment:
//
//   ✓ runs offline   — local data, no network call needed.
//   ↻ refreshable    — ships in the offline bundle; status depends on
//                       whether CHAINSAW_INTEL_BUNDLE_PATH is set + fresh.
//   ○ no coverage    — remote-only signal under fail-open: effectively
//                       OFF (allow-by-default), so it reads as no
//                       coverage rather than a degraded-but-running one.
//   ⚠ degraded       — remote-only signal under the condition default;
//                       honours CHAINSAW_OFFLINE_FAIL_MODE for the verdict.
//
// The output matrix is the operator-facing equivalent of the per-
// provider table in docs/install/AIRGAP.md — keep the two in sync
// when adding new providers.

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/intelligence"
)

// providerOfflineRow is one row in the doctor matrix. The column shape
// matches the markdown table in docs/install/AIRGAP.md so an operator
// can paste the doctor output directly into a runbook.
type providerOfflineRow struct {
	Name      string
	Category  string // "local", "refreshable", "remote-only"
	Status    string // "✓", "↻", "⚠", "✗"
	Detail    string
	BundleKey string // empty for local providers
}

// providerMatrix is the canonical mapping consulted by the doctor. New
// providers MUST get a row here when they land — the doctor refuses to
// build a "runs offline ✓" verdict for any provider it doesn't know
// about.
var providerMatrix = []providerOfflineRow{
	// Local — pure on-disk computation, no remote calls.
	{Name: "typosquat", Category: "local", Status: "✓", Detail: "BK-tree over local seeds"},
	{Name: "hiddenunicode", Category: "local", Status: "✓", Detail: "byte-level scan of artefact"},
	{Name: "installscripts", Category: "local", Status: "✓", Detail: "tarball inspection"},
	{Name: "checksum", Category: "local", Status: "✓", Detail: "hash compare against pinned digest"},
	{Name: "codesmell", Category: "local", Status: "✓", Detail: "AST scan (uses_eval, network, shell, fs, env, native_code, eval, urlstrings, minified)"},
	{Name: "shrinkwrap", Category: "local", Status: "✓", Detail: "lockfile drift detection"},
	{Name: "capability", Category: "local", Status: "✓", Detail: "static capability extraction"},
	{Name: "manifestconfusion", Category: "local", Status: "✓", Detail: "package.json vs tarball cross-check"},
	{Name: "manifestconfusion-pypi", Category: "local", Status: "✓", Detail: "PyPI METADATA cross-check"},
	{Name: "provenance", Category: "local", Status: "✓", Detail: "Sigstore bundle verification (offline trust root in bundle)"},
	{Name: "signature_verify", Category: "local", Status: "✓", Detail: "GPG / Sigstore signature check"},
	{Name: "agenttool_verify", Category: "local", Status: "✓", Detail: "MCP tool manifest verification"},
	{Name: "aiartifact-pickle", Category: "local", Status: "✓", Detail: "pickle scan"},
	{Name: "aiartifact-modelcard", Category: "local", Status: "✓", Detail: "model card extraction"},
	{Name: "aiartifact-agenttool", Category: "local", Status: "✓", Detail: "agent tool detection"},
	{Name: "wave4-trivial", Category: "local", Status: "✓", Detail: "trivial-package heuristic"},
	{Name: "wave4-toomanyfiles", Category: "local", Status: "✓", Detail: "tarball file-count cap"},
	{Name: "transitiverisk", Category: "local", Status: "✓", Detail: "lockfile graph derived from local data"},
	{Name: "reservedns", Category: "local", Status: "✓", Detail: "static reserved-namespace list"},

	// Refreshable — ships in the intel bundle; offline mode loads from
	// CHAINSAW_INTEL_BUNDLE_PATH instead of phoning home.
	{Name: "cve", Category: "refreshable", BundleKey: "trivy-db", Detail: "Trivy DB snapshot — consumed on-disk at hooks.trivial.dbpath (pre-seed the DB), not via the bundle handle"},
	{Name: "kev", Category: "refreshable", BundleKey: "kev", Detail: "CISA KEV catalogue (loaded from the bundle offline)"},
	{Name: "malware", Category: "refreshable", BundleKey: "osv-malware", Detail: "OSV / GHSA malware feed (loaded from the bundle offline)"},
	{Name: "ghsa-swift", Category: "refreshable", BundleKey: "ghsa-swift", Detail: "GHSA snapshot for Swift — RESERVED: shipped in the bundle but no provider consumes it yet"},
	{Name: "typosquat-refdata", Category: "refreshable", BundleKey: "typosquat", Detail: "BK-tree reference data refresh"},

	// Remote-only — no bundle counterpart. Honours CHAINSAW_OFFLINE_FAIL_MODE.
	{Name: "downloads", Category: "remote-only", Status: "⚠", Detail: "npm/PyPI download counts (5-day rolling)"},
	{Name: "weekly_downloads", Category: "remote-only", Status: "⚠", Detail: "weekly download trend"},
	{Name: "metadiff", Category: "remote-only", Status: "⚠", Detail: "publisher-set diff vs prior version"},
	{Name: "publishvelocity", Category: "remote-only", Status: "⚠", Detail: "24h publish-velocity anomaly"},
	{Name: "registrymetadata", Category: "remote-only", Status: "⚠", Detail: "registry packument fetch"},
	{Name: "maintenance", Category: "remote-only", Status: "⚠", Detail: "deprecated/archived/stale signals"},
	{Name: "wave4-rtt", Category: "remote-only", Status: "⚠", Detail: "non_existent_author + first_time_collaborator + suspicious_repo_stars (GitHub API)"},
	{Name: "wave4-maintainer-age", Category: "remote-only", Status: "⚠", Detail: "GitHub maintainer account-age check"},
	{Name: "repolink", Category: "remote-only", Status: "⚠", Detail: "registry → repo URL resolution"},
}

func runDoctorOffline(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()

	bundle := intelligence.ActiveBundle()
	failMode := intelligence.EffectiveFailMode()

	// Header — orient the operator on the global state before the matrix.
	fmt.Fprintln(out, "Offline-mode diagnostics")
	if path := os.Getenv(intelligence.BundleEnvVar); path != "" {
		fmt.Fprintf(out, "  bundle env:  %s=%s\n", intelligence.BundleEnvVar, path)
	} else {
		fmt.Fprintf(out, "  bundle env:  %s (unset)\n", intelligence.BundleEnvVar)
	}
	if bundle != nil {
		fmt.Fprintf(out, "  bundle:      version=%s digest=sha256:%s built=%s\n",
			bundle.Manifest().Version, shortBundleDigest(bundle.Digest()), bundle.Manifest().BuildTime.Format("2006-01-02"))
		if bundle.Stale() {
			fmt.Fprintf(out, "  ⚠ stale: bundle is older than %s — schedule a refresh.\n", intelligence.BundleStaleAfter)
		}
		// Verification posture: skipped, digest-bound integrity only, or full
		// Sigstore authenticity. Distinguishes the two layers so operators
		// know whether the loaded bundle is merely tamper-checked or actually
		// bot-signed. Active bundle picks up CHAINSAW_INTEL_BUNDLE_STRICT_VERIFY
		// at load time, so this reflects the operator's chosen posture.
		sym, txt := bundleVerificationStatus(bundle.Verified(), bundle.Authenticated())
		fmt.Fprintf(out, "  verify:      %s %s\n", sym, txt)
	} else {
		fmt.Fprintln(out, "  bundle:      (not loaded — refreshable providers will run with empty data)")
	}
	fmt.Fprintf(out, "  fail mode:   %s (CHAINSAW_OFFLINE_FAIL_MODE)\n", failMode)
	fmt.Fprintln(out)

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PROVIDER\tCATEGORY\tSTATUS\tDETAIL")
	for _, row := range providerMatrix {
		status := row.Status
		detail := row.Detail
		switch row.Category {
		case "refreshable":
			if bundle == nil {
				status = "✗"
				detail = detail + " — bundle missing"
			} else if data := bundle.File(row.BundleKey); len(data) == 0 {
				status = "✗"
				detail = detail + " — bundle missing key " + row.BundleKey
			} else if bundle.Stale() {
				status = "↻"
				detail = detail + " — refresh recommended"
			} else {
				status = "✓"
			}
		case "remote-only":
			switch failMode {
			case intelligence.FailModeOpen:
				// Fail-open means the signal is effectively OFF — installs
				// are allowed with no coverage. "⚠ degraded" reads as
				// "partially working"; "○ no coverage" reads honestly as
				// what it is: an inert, allow-by-default signal.
				status = "○"
				detail = detail + " — fail-open: allows installs"
			case intelligence.FailModeClosed:
				detail = detail + " — fail-closed: blocks installs without bundle data"
				status = "✗"
			default:
				detail = detail + " — condition default (SevUnknown)"
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", row.Name, row.Category, status, detail)
	}
	w.Flush()

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Legend:  ✓ runs offline   ↻ refresh recommended   ○ no coverage (fail-open: signal off, installs allowed)   ⚠ degraded   ✗ requires bundle refresh / fail-closed")
	return nil
}

func shortBundleDigest(d string) string {
	if len(d) <= 16 {
		return d
	}
	return d[:16]
}
