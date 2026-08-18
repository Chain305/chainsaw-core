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
//   ℹ informational  — the doctor cannot decide this row from anything
//                       readable on a workstation, so it reports the
//                       situation instead of inventing a verdict.
//
// The markers above are the Unicode rendering. The matrix carries a
// SEMANTIC status (statusKind) and resolves it through glyphs() at print
// time, so a console that cannot encode the Unicode set gets the ASCII
// one (+ X ! ~ - i) instead of five states collapsed into one
// replacement box. See glyphSet in output.go.
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

// statusKind is the SEMANTIC state of a matrix row, decoupled from the glyph
// that renders it. The matrix used to store the glyph itself, which baked a
// presentation decision into a data table and made the Windows codepage fix
// impossible to apply in one place. Rendering happens once, in
// statusGlyph, against the set glyphs() picks for the live terminal.
type statusKind int

const (
	// statusUnset is the zero value: a row whose state is COMPUTED at print
	// time from bundle/fail-mode state rather than declared in the table.
	// Every refreshable row is unset.
	statusUnset statusKind = iota
	statusOK
	statusFail
	statusWarn
	statusRefresh
	statusNoCoverage
	statusInfo
)

// statusGlyph maps a semantic state to the marker for the live terminal.
// An unmapped/unset kind yields the info marker rather than an empty cell:
// a blank STATUS column would read as "nothing to report", which is the one
// thing a diagnostics matrix must never imply by accident.
func statusGlyph(g glyphSet, k statusKind) string {
	switch k {
	case statusOK:
		return g.ok
	case statusFail:
		return g.fail
	case statusWarn:
		return g.warn
	case statusRefresh:
		return g.refresh
	case statusNoCoverage:
		return g.none
	default:
		return g.info
	}
}

// providerOfflineRow is one row in the doctor matrix. The column shape
// matches the markdown table in docs/install/AIRGAP.md so an operator
// can paste the doctor output directly into a runbook.
type providerOfflineRow struct {
	Name      string
	Category  string // "local", "refreshable", "remote-only"
	Status    statusKind
	Detail    string
	BundleKey string // empty for local providers
	// Informational marks a row the doctor must REPORT but must not GRADE.
	//
	// Three refreshable rows named a bundle key that no provider reads, and
	// grading them on that key was wrong in both directions. An air-gapped
	// operator who pre-seeded the Trivy DB on disk but built a bundle
	// without trivy-db/db.bolt was told "cve ✗ requires bundle refresh" and
	// sent to rebuild a bundle that would change nothing; conversely a
	// bundle that CONTAINED the key reported "cve ✓ runs offline" while CVE
	// classification was failing open as SevUnknown.
	//
	// We report the situation instead of inventing a verdict. Deliberately
	// NOT re-graded against hooks.trivial.db_path: that is a server-side,
	// DB-backed setting which this command — running on a workstation —
	// cannot read, so grading on it would just relocate the wrong answer.
	Informational bool
}

// providerMatrix is the canonical mapping consulted by the doctor. New
// providers MUST get a row here when they land — the doctor refuses to
// build a "runs offline ✓" verdict for any provider it doesn't know
// about.
var providerMatrix = []providerOfflineRow{
	// Local — pure on-disk computation, no remote calls.
	{Name: "typosquat", Category: "local", Status: statusOK, Detail: "BK-tree over local seeds"},
	{Name: "hiddenunicode", Category: "local", Status: statusOK, Detail: "byte-level scan of artefact"},
	{Name: "installscripts", Category: "local", Status: statusOK, Detail: "tarball inspection"},
	{Name: "checksum", Category: "local", Status: statusOK, Detail: "hash compare against pinned digest"},
	{Name: "codesmell", Category: "local", Status: statusOK, Detail: "AST scan (uses_eval, network, shell, fs, env, native_code, eval, urlstrings, minified)"},
	{Name: "shrinkwrap", Category: "local", Status: statusOK, Detail: "lockfile drift detection"},
	{Name: "capability", Category: "local", Status: statusOK, Detail: "static capability extraction"},
	{Name: "manifestconfusion", Category: "local", Status: statusOK, Detail: "package.json vs tarball cross-check"},
	{Name: "manifestconfusion-pypi", Category: "local", Status: statusOK, Detail: "PyPI METADATA cross-check"},
	{Name: "provenance", Category: "local", Status: statusOK, Detail: "Sigstore bundle verification (offline trust root in bundle)"},
	{Name: "signature_verify", Category: "local", Status: statusOK, Detail: "GPG / Sigstore signature check"},
	{Name: "agenttool_verify", Category: "local", Status: statusOK, Detail: "MCP tool manifest verification"},
	{Name: "aiartifact-pickle", Category: "local", Status: statusOK, Detail: "pickle scan"},
	{Name: "aiartifact-modelcard", Category: "local", Status: statusOK, Detail: "model card extraction"},
	{Name: "aiartifact-agenttool", Category: "local", Status: statusOK, Detail: "agent tool detection"},
	{Name: "wave4-trivial", Category: "local", Status: statusOK, Detail: "trivial-package heuristic"},
	{Name: "wave4-toomanyfiles", Category: "local", Status: statusOK, Detail: "tarball file-count cap"},
	{Name: "transitiverisk", Category: "local", Status: statusOK, Detail: "lockfile graph derived from local data"},
	{Name: "reservedns", Category: "local", Status: statusOK, Detail: "static reserved-namespace list"},

	// Refreshable — ships in the intel bundle; offline mode loads from
	// CHAINSAW_INTEL_BUNDLE_PATH instead of phoning home.
	// kev and malware are the only two rows a bundle key genuinely decides:
	// provider_kev.go and provider_malware.go are the only callers of
	// ActiveBundle().
	{Name: "kev", Category: "refreshable", BundleKey: "kev", Detail: "CISA KEV catalogue (loaded from the bundle offline)"},
	{Name: "malware", Category: "refreshable", BundleKey: "osv-malware", Detail: "OSV / GHSA malware feed (loaded from the bundle offline)"},
	// Informational — see providerOfflineRow.Informational.
	{Name: "cve", Category: "refreshable", BundleKey: "trivy-db", Informational: true, Detail: "Trivy DB snapshot — consumed on-disk at hooks.trivial.db_path (pre-seed the DB), not via the bundle handle, so the bundle cannot decide this row"},
	{Name: "ghsa-swift", Category: "refreshable", BundleKey: "ghsa-swift", Informational: true, Detail: "GHSA snapshot for Swift — RESERVED: shipped in the bundle but no provider consumes it yet"},
	{Name: "typosquat-refdata", Category: "refreshable", BundleKey: "typosquat", Informational: true, Detail: "BK-tree reference data refresh — the detector runs from embedded seeds; no provider reads this bundle key yet"},

	// Remote-only — no bundle counterpart. Honours CHAINSAW_OFFLINE_FAIL_MODE.
	{Name: "downloads", Category: "remote-only", Status: statusWarn, Detail: "npm/PyPI download counts (5-day rolling)"},
	{Name: "weekly_downloads", Category: "remote-only", Status: statusWarn, Detail: "weekly download trend"},
	{Name: "metadiff", Category: "remote-only", Status: statusWarn, Detail: "publisher-set diff vs prior version"},
	{Name: "publishvelocity", Category: "remote-only", Status: statusWarn, Detail: "24h publish-velocity anomaly"},
	{Name: "registrymetadata", Category: "remote-only", Status: statusWarn, Detail: "registry packument fetch"},
	{Name: "maintenance", Category: "remote-only", Status: statusWarn, Detail: "deprecated/archived/stale signals"},
	{Name: "wave4-rtt", Category: "remote-only", Status: statusWarn, Detail: "non_existent_author + first_time_collaborator + suspicious_repo_stars (GitHub API)"},
	{Name: "wave4-maintainer-age", Category: "remote-only", Status: statusWarn, Detail: "GitHub maintainer account-age check"},
	{Name: "repolink", Category: "remote-only", Status: statusWarn, Detail: "registry → repo URL resolution"},
}

func runDoctorOffline(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()

	bundle := intelligence.ActiveBundle()
	failMode := intelligence.EffectiveFailMode()

	// Resolved ONCE for the whole command: the header note, all 25 matrix
	// rows, and the legend must agree on one alphabet, or the legend would
	// explain markers the table does not use.
	g := glyphs()

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
			fmt.Fprintf(out, "  %s stale: bundle is older than %s — schedule a refresh.\n", g.warn, intelligence.BundleStaleAfter)
		}
		// Verification posture: skipped, digest-bound integrity only, or full
		// Sigstore authenticity. Distinguishes the two layers so operators
		// know whether the loaded bundle is merely tamper-checked or actually
		// bot-signed. Active bundle picks up CHAINSAW_INTEL_BUNDLE_STRICT_VERIFY
		// at load time, so this reflects the operator's chosen posture.
		sym, txt := bundleVerificationStatus(g, bundle.Verified(), bundle.Authenticated())
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
		if row.Informational {
			// Reported, never graded. Skipping the switch entirely is the
			// point: no bundle state can turn this row into an ok or a fail.
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", row.Name, row.Category, g.info, detail)
			continue
		}
		switch row.Category {
		case "refreshable":
			if bundle == nil {
				status = statusFail
				detail = detail + " — bundle missing"
			} else if data := bundle.File(row.BundleKey); len(data) == 0 {
				status = statusFail
				detail = detail + " — bundle missing key " + row.BundleKey
			} else if bundle.Stale() {
				status = statusRefresh
				detail = detail + " — refresh recommended"
			} else {
				status = statusOK
			}
		case "remote-only":
			switch failMode {
			case intelligence.FailModeOpen:
				// Fail-open means the signal is effectively OFF — installs
				// are allowed with no coverage. "degraded" reads as
				// "partially working"; "no coverage" reads honestly as
				// what it is: an inert, allow-by-default signal.
				status = statusNoCoverage
				detail = detail + " — fail-open: allows installs"
			case intelligence.FailModeClosed:
				// CHAINSAW_OFFLINE_FAIL_MODE is ADVISORY — this command is
				// its only consumer. Saying "blocks installs" here was
				// false: nothing enforced it. Enforcement is the opt-in
				// coverage gate (CHAINSAW_COVERAGE_MODE=closed), so point
				// at that rather than claiming a block we do not perform.
				detail = detail + " — intent: fail-closed (advisory; set CHAINSAW_COVERAGE_MODE=closed to enforce)"
				status = statusFail
			default:
				detail = detail + " — condition default (SevUnknown)"
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", row.Name, row.Category, statusGlyph(g, status), detail)
	}
	w.Flush()

	fmt.Fprintln(out)
	// The legend is built from the SAME glyph set the table just used. It was
	// a hard-coded Unicode string, so on a console that could not render the
	// markers the legend was doubly useless: it boxed its own markers AND
	// would have described an alphabet the rows no longer spoke.
	fmt.Fprintf(out, "Legend:  %s runs offline   %s refresh recommended   %s no coverage (signal off, installs allowed)   %s degraded   %s requires bundle refresh   %s informational (not graded — see detail)\n",
		g.ok, g.refresh, g.none, g.warn, g.fail, g.info)
	fmt.Fprintln(out, "Note:    CHAINSAW_OFFLINE_FAIL_MODE is advisory and reported here only. To refuse installs on missing coverage, set CHAINSAW_COVERAGE_MODE=closed with CHAINSAW_COVERAGE_REQUIRED=<sources>.")
	return nil
}

func shortBundleDigest(d string) string {
	if len(d) <= 16 {
		return d
	}
	return d[:16]
}
