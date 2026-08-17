package cli

// `chainsaw why <ecosystem> <package>@<version>` — explain why an install
// was blocked. BUG-16: pip / npm collapse the proxy's rich 403 JSON to a
// one-liner, so the developer has to come back here to learn what hit them.
//
// Two lookup paths:
//   --request-id <id>   — match by correlation_id in /api/audit/logs.
//   (no --request-id)   — most-recent blocked row for that ecosystem +
//                         package@version from /api/violations/blocked.

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// blockedViolation mirrors entries returned by GET /api/violations/blocked.
type blockedViolation struct {
	ID         int64     `json:"id"`
	RecordedAt time.Time `json:"recordedAt"`
	Format     string    `json:"format"`
	PackageID  string    `json:"package"`
	Version    string    `json:"version"`
	Reason     string    `json:"reason"`
	Severity   string    `json:"severity,omitempty"`
	CVEIDs     []string  `json:"cveIds,omitempty"`
	CVSS       float64   `json:"cvss,omitempty"`
	PolicyName string    `json:"policyName,omitempty"`
}

type blockedViolationsResponse struct {
	Violations []blockedViolation `json:"violations"`
}

// auditEventWithCorr is a slim view over /api/audit/logs entries.
type auditEventWithCorr struct {
	ID            string                 `json:"id"`
	Status        string                 `json:"status"`
	Timestamp     time.Time              `json:"timestamp"`
	CorrelationID string                 `json:"correlation_id,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

type auditLogResponseCorr struct {
	Events []auditEventWithCorr `json:"events"`
}

// whySchemaVersion identifies the wire shape of the `why` --json envelope
// (P2.11 verdict envelopes). Shared by the server-backed and local-guard paths
// so both emit the same top-level "schemaVersion". Bumped only on a breaking
// field change; additive fields keep the version. `why` is informational, so
// the envelope never carries a non-OK exit code.
const whySchemaVersion = "1.0"

var whyCmd = &cobra.Command{
	Use:     "why <ecosystem> <package>@<version>",
	GroupID: GrpScan,
	Short:   "Explain why a package install was blocked",
	Long: `Look up the most recent block decision for a package and render
policy / CVE / contact details that pip and npm hide.

Examples:
  chainsaw why pip requests@2.31.0
  chainsaw why npm lodash@4.17.20 --request-id a22794f3a2134e13
  chainsaw why pip requests@2.31.0 --json`,
	Args: exactArgsWithUsage(2,
		"chainsaw why <ecosystem> <package>@<version>",
		"chainsaw why npm lodash@4.17.20"),
	RunE: runWhy,
}

func init() {
	whyCmd.Flags().String("request-id", "", "Look up the exact decision for this request id")
	whyCmd.Flags().Bool("json", false, "Output machine-readable JSON")
	rootCmd.AddCommand(whyCmd)
}

// parsePackageAtVersion splits "name@version". npm-scoped names contain
// @ in the name itself, so split on the LAST @.
func parsePackageAtVersion(s string) (string, string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", fmt.Errorf("package coordinate is required (e.g. requests@2.31.0)")
	}
	at := strings.LastIndex(s, "@")
	if at <= 0 {
		return s, "", nil
	}
	return s[:at], s[at+1:], nil
}

func runWhy(cmd *cobra.Command, args []string) error {
	ecosystem := strings.TrimSpace(args[0])
	name, version, err := parsePackageAtVersion(args[1])
	if err != nil {
		return err
	}
	reqID, _ := cmd.Flags().GetString("request-id")
	reqID = strings.TrimSpace(reqID)

	client := newClient()
	if client.baseURL == "" {
		// No server configured — this is the free, account-free path. The local
		// install guard records its recent blocks, so explain from those instead
		// of dead-ending on "server not configured".
		return runWhyLocal(cmd, ecosystem, name, version)
	}

	// Y5: the local guard ledger used to be reachable ONLY when no server was
	// configured. But /api/violations/blocked is built from the server `events`
	// table (internal/server/violations_query.go), which can never contain a
	// LOCAL guard block — so for anyone with a server configured, a block the
	// guard had just printed came back "no recent block found" at rc=2. The
	// ledger is now a FALLBACK: the server still answers first, and we consult
	// this machine only when the server has nothing (or cannot be reached).
	//
	// --request-id is excluded on purpose: a request id is a server correlation
	// id with no local analogue, so its distinct "may have expired from the
	// audit buffer" error stays exactly as it was.
	v, source, err := lookupBlock(client, ecosystem, name, version, reqID)
	if err != nil {
		if reqID == "" {
			if rec := lookupLocalBlock(ecosystem, name, version); rec != nil {
				fmt.Fprintf(os.Stderr,
					"chainsaw: could not reach the configured server (%v); answering from this machine's local guard ledger only — team-wide history is not included.\n",
					err)
				return renderWhyLocal(cmd, rec)
			}
		}
		return err
	}
	if v == nil {
		if reqID != "" {
			return fmt.Errorf("no blocked decision found for request-id %s (it may have expired from the audit buffer)", reqID)
		}
		if rec := lookupLocalBlock(ecosystem, name, version); rec != nil {
			return renderWhyLocal(cmd, rec)
		}
		return fmt.Errorf("no recent block found for %s/%s@%s", ecosystem, name, version)
	}

	if useJSON(cmd) {
		return PrintJSONTo(cmd, map[string]any{
			"schemaVersion": whySchemaVersion,
			"ecosystem":     ecosystem, "package": v.PackageID, "version": v.Version,
			"outcome": "BLOCKED", "policy_name": v.PolicyName, "reason": v.Reason,
			"cvss": v.CVSS, "cves": v.CVEIDs, "severity": v.Severity,
			"decided_at": v.RecordedAt.UTC().Format(time.RFC3339),
			"request_id": reqID, "source": source,
		})
	}
	renderWhyTable(os.Stdout, ecosystem, v, reqID, source)
	return nil
}

// lookupBlock returns the most recent block matching args + a label
// ("audit"|"violations") describing the source. Either may be nil on no-match.
func lookupBlock(client *APIClient, ecosystem, name, version, reqID string) (*blockedViolation, string, error) {
	if reqID != "" {
		var resp auditLogResponseCorr
		if err := client.Get("/api/audit/logs", &resp); err != nil {
			return nil, "", err
		}
		for _, e := range resp.Events {
			if e.CorrelationID == reqID {
				return blockedFromAuditEvent(e, ecosystem, name, version), "audit", nil
			}
		}
		return nil, "audit", nil
	}
	var resp blockedViolationsResponse
	if err := client.Get("/api/violations/blocked", &resp); err != nil {
		return nil, "", err
	}
	var best *blockedViolation
	for i := range resp.Violations {
		row := &resp.Violations[i]
		if !strings.EqualFold(row.Format, ecosystem) || !strings.EqualFold(row.PackageID, name) {
			continue
		}
		if version != "" && row.Version != version {
			continue
		}
		if best == nil || row.RecordedAt.After(best.RecordedAt) {
			best = row
		}
	}
	return best, "violations", nil
}

// blockedFromAuditEvent synthesises a row from an audit event's loose metadata.
func blockedFromAuditEvent(e auditEventWithCorr, ecosystem, name, version string) *blockedViolation {
	get := func(k string) string {
		if s, ok := e.Metadata[k].(string); ok {
			return s
		}
		return ""
	}
	v := &blockedViolation{
		RecordedAt: e.Timestamp, Format: ecosystem,
		PackageID: name, Version: version,
		Reason: get("reason"), PolicyName: get("policy_name"),
	}
	if pkg := get("package"); pkg != "" {
		v.PackageID = pkg
	}
	if ver := get("version"); ver != "" {
		v.Version = ver
	}
	if score, ok := e.Metadata["cvss_score"].(float64); ok {
		v.CVSS = score
	}
	if raw, ok := e.Metadata["cves"].([]interface{}); ok {
		for _, item := range raw {
			if s, ok := item.(string); ok {
				v.CVEIDs = append(v.CVEIDs, s)
			}
		}
	}
	return v
}

func renderWhyTable(w *os.File, ecosystem string, v *blockedViolation, reqID, source string) {
	policy := v.PolicyName
	if policy == "" {
		policy = "(unnamed policy)"
	}
	// Package name/version/reason/ecosystem trace back to an install someone
	// attempted, so treat them as untrusted and scrub terminal control sequences
	// before echoing. (policy is printed with %q, which already escapes them.)
	eco := sanitizeForTerminal(ecosystem)
	pkg := sanitizeForTerminal(v.PackageID)
	ver := sanitizeForTerminal(v.Version)
	fmt.Fprintf(w, "Package:    %s/%s@%s\n", eco, pkg, ver)
	fmt.Fprintln(w, "Outcome:    BLOCKED")
	fmt.Fprintf(w, "Policy:     %q\n", policy)
	if v.Reason != "" {
		fmt.Fprintf(w, "Reason:     %s\n", sanitizeForTerminal(v.Reason))
	}
	if len(v.CVEIDs) > 0 {
		// C12: the CVE list comes from the SAME untrusted place as the fields
		// above it — blockedFromAuditEvent lifts it out of
		// e.Metadata["cves"].([]interface{}) — and was the one field printed
		// raw. An id carrying ANSI (e.g. "\x1b[2K\rPackage: safe-lib") could
		// rewrite the operator's view of the block report. Scrub per element,
		// before joining, so the separator cannot be smuggled either.
		cves := make([]string, len(v.CVEIDs))
		for i, id := range v.CVEIDs {
			cves[i] = sanitizeForTerminal(id)
		}
		fmt.Fprintf(w, "CVEs:       %s\n", strings.Join(cves, ", "))
	}
	if v.CVSS > 0 {
		fmt.Fprintf(w, "CVSS:       %.1f\n", v.CVSS)
	}
	if !v.RecordedAt.IsZero() {
		fmt.Fprintf(w, "Decided:    %s\n", v.RecordedAt.UTC().Format(time.RFC3339))
	}
	if reqID != "" {
		fmt.Fprintf(w, "Request ID: %s\n", reqID)
	}
	if source == "audit" {
		fmt.Fprintln(w, "Source:     audit log (request-id match)")
	}
	fmt.Fprintln(w, "\nNext steps:")
	fmt.Fprintf(w, "  • Pin to a patched version of %s/%s, or\n", eco, pkg)
	fmt.Fprintf(w, "  • Request an exception:  chainsaw exception create --repository <repo> --package %s --version %s\n",
		pkg, ver)
}

// runWhyLocal answers `chainsaw why` from the local install guard's recorded
// blocks when no server is configured (the free, account-free path). The guard
// already prints the reason inline at block time; this lets a developer ask
// again afterwards instead of hitting "server not configured".
func runWhyLocal(cmd *cobra.Command, ecosystem, name, version string) error {
	rec := lookupLocalBlock(ecosystem, name, version)
	if rec == nil {
		coord := ecosystem + "/" + name
		if version != "" {
			coord += "@" + version
		}
		return fmt.Errorf(`no local block recorded for %s.

The install guard only records packages it has blocked on this machine; it
prints the reason inline at block time. No server is configured, so there is
no server-side history to query here.

  See guard activity:   chainsaw guard status
  CVE / policy detail and team-wide history need an account:
    Sign up free → https://chain305.com/chainsaw/signup`, coord)
	}
	return renderWhyLocal(cmd, rec)
}

// renderWhyLocal renders one local guard ledger entry. Split out of
// runWhyLocal so the Y5 server-first fallback path can render a record it has
// already found without re-running the lookup — and, more importantly, without
// risking runWhyLocal's "no server is configured" not-found text on a run where
// a server very much IS configured.
func renderWhyLocal(cmd *cobra.Command, rec *guardBlockRecord) error {
	if useJSON(cmd) {
		return PrintJSONTo(cmd, map[string]any{
			"schemaVersion": whySchemaVersion,
			"ecosystem":     rec.Ecosystem, "package": rec.Name, "version": rec.Version,
			"outcome": "BLOCKED", "reason": rec.Reason, "severity": rec.Severity,
			"decided_at": time.Unix(rec.AtUnix, 0).UTC().Format(time.RFC3339),
			"source":     "local-guard",
		})
	}

	w := os.Stdout
	ver := rec.Version
	if ver == "" {
		ver = "(unpinned)"
	}
	// rec.Name/Reason are the crafted install arg the guard recorded — scrub
	// terminal control sequences before echoing (see sanitizeForTerminal).
	fmt.Fprintf(w, "Package:    %s/%s@%s\n", sanitizeForTerminal(rec.Ecosystem), sanitizeForTerminal(rec.Name), sanitizeForTerminal(ver))
	fmt.Fprintln(w, "Outcome:    BLOCKED (local install guard)")
	if rec.Severity != "" {
		fmt.Fprintf(w, "Severity:   %s\n", sanitizeForTerminal(rec.Severity))
	}
	if rec.Reason != "" {
		fmt.Fprintf(w, "Reason:     %s\n", sanitizeForTerminal(rec.Reason))
	}
	if rec.AtUnix != 0 {
		fmt.Fprintf(w, "Blocked:    %s\n", time.Unix(rec.AtUnix, 0).UTC().Format(time.RFC3339))
	}
	fmt.Fprintln(w, "Source:     this machine's offline guard (known-malicious floor + typosquat)")
	fmt.Fprintln(w, "\nNext steps:")
	fmt.Fprintf(w, "  • Install a trusted package instead (check the name for typos).\n")
	// Two DISTINCT calls to action, deliberately not merged: the full OpenSSF
	// malicious-packages set is a public download that needs no account (see
	// TestGuardUpdateNudgePublicFeedNoAuth), so bundling it into the signup
	// pitch would sell a gate that does not exist. Signing in syncs this
	// device's guard activity to an account — that, and team-wide history,
	// is the honest reason to sign up.
	fmt.Fprintln(w, "  • Pull the full OpenSSF malicious-packages set (free, no account):")
	fmt.Fprintln(w, "    chainsaw guard update")
	fmt.Fprintln(w, "  • Sync this device's guard activity to your account for team-wide")
	fmt.Fprintln(w, "    history → sign up free:")
	fmt.Fprintln(w, "    https://chain305.com/chainsaw/signup")
	return nil
}

// lookupLocalBlock returns the most recent local guard block matching the
// ecosystem + name (and version when pinned), or nil. Newest entries are last
// in the ring, so iterate in reverse.
func lookupLocalBlock(ecosystem, name, version string) *guardBlockRecord {
	return findLocalBlock(loadGuardState().RecentBlocks, ecosystem, name, version)
}

// findLocalBlock is the pure matcher: most recent (newest entries are last in
// the ring) block matching ecosystem + name, and version when both the query
// and the record pin one. Returns nil on no match.
func findLocalBlock(blocks []guardBlockRecord, ecosystem, name, version string) *guardBlockRecord {
	for i := len(blocks) - 1; i >= 0; i-- {
		r := blocks[i]
		if !strings.EqualFold(r.Ecosystem, ecosystem) || !strings.EqualFold(r.Name, name) {
			continue
		}
		if version != "" && r.Version != "" && r.Version != version {
			continue
		}
		rec := r
		return &rec
	}
	return nil
}
