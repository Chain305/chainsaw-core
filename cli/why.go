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

var whyCmd = &cobra.Command{
	Use:   "why <ecosystem> <package>@<version>",
	Short: "Explain why a package install was blocked",
	Long: `Look up the most recent block decision for a package and render
policy / CVE / contact details that pip and npm hide.

Examples:
  chainsaw why pip requests@2.31.0
  chainsaw why npm lodash@4.17.20 --request-id a22794f3a2134e13
  chainsaw why pip requests@2.31.0 --json`,
	Args: cobra.ExactArgs(2),
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
		return errServerNotConfigured(cmd)
	}

	v, source, err := lookupBlock(client, ecosystem, name, version, reqID)
	if err != nil {
		return err
	}
	if v == nil {
		if reqID != "" {
			return fmt.Errorf("no blocked decision found for request-id %s (it may have expired from the audit buffer)", reqID)
		}
		return fmt.Errorf("no recent block found for %s/%s@%s", ecosystem, name, version)
	}

	if useJSON(cmd) {
		return PrintJSON(map[string]any{
			"ecosystem": ecosystem, "package": v.PackageID, "version": v.Version,
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
	fmt.Fprintf(w, "Package:    %s/%s@%s\n", ecosystem, v.PackageID, v.Version)
	fmt.Fprintln(w, "Outcome:    BLOCKED")
	fmt.Fprintf(w, "Policy:     %q\n", policy)
	if v.Reason != "" {
		fmt.Fprintf(w, "Reason:     %s\n", v.Reason)
	}
	if len(v.CVEIDs) > 0 {
		fmt.Fprintf(w, "CVEs:       %s\n", strings.Join(v.CVEIDs, ", "))
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
	fmt.Fprintf(w, "  • Pin to a patched version of %s/%s, or\n", ecosystem, v.PackageID)
	fmt.Fprintf(w, "  • Request an exception:  chainsaw exception propose %s %s@%s\n",
		ecosystem, v.PackageID, v.Version)
}
