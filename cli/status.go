package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show server, org, and authentication status",
	RunE:  runStatus,
}

func init() {
	statusCmd.Flags().Bool("json", false, "Output as JSON")
	rootCmd.AddCommand(statusCmd)
}

type statusReport struct {
	ServerURL string `json:"server_url"`
	OrgID     string `json:"org_id"`
	Auth      struct {
		Valid     bool   `json:"valid"`
		UserID    string `json:"user_id,omitempty"`
		OrgID     string `json:"org_id,omitempty"`
		Role      string `json:"role,omitempty"`
		ExpiresAt string `json:"expires_at,omitempty"`
		Error     string `json:"error,omitempty"`
	} `json:"auth"`
	Server struct {
		Reachable bool   `json:"reachable"`
		Status    string `json:"status,omitempty"`
		Error     string `json:"error,omitempty"`
	} `json:"server"`
}

func runStatus(cmd *cobra.Command, _ []string) error {
	report := statusReport{
		ServerURL: cfgServerURL(),
		OrgID:     cfgOrgID(),
	}

	// ── Server reachability ───────────────────────────────────────────────────
	if report.ServerURL == "" {
		report.Server.Error = "server URL not configured"
	} else {
		probe := NewAPIClient(report.ServerURL, "")
		var health map[string]string
		if err := probe.Get("/healthz", &health); err != nil {
			report.Server.Error = err.Error()
		} else {
			report.Server.Reachable = true
			report.Server.Status = health["status"]
		}
	}

	// ── Auth validity ─────────────────────────────────────────────────────────
	if cfgToken() == "" {
		report.Auth.Error = "no token configured — run 'chainsaw setup' or 'chainsaw auth login'"
	} else if report.ServerURL == "" {
		report.Auth.Error = "server URL not configured"
	} else {
		client := newClient()
		var me struct {
			UserID    string    `json:"user_id"`
			Email     string    `json:"email"`
			OrgID     string    `json:"org_id"`
			Role      string    `json:"role"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		if err := client.Get("/api/auth/me", &me); err != nil {
			report.Auth.Valid = false
			report.Auth.Error = err.Error()
		} else {
			report.Auth.Valid = true
			report.Auth.UserID = coalesce(me.UserID, me.Email)
			report.Auth.OrgID = me.OrgID
			report.Auth.Role = me.Role
			if !me.ExpiresAt.IsZero() {
				report.Auth.ExpiresAt = me.ExpiresAt.Local().Format(time.RFC3339)
			}
		}
	}

	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		return PrintJSON(report)
	}

	printStatusLine := func(label, val, errVal string, ok bool) {
		tick := "✓"
		cross := "✗"
		if ok {
			fmt.Printf("  %s  %-18s %s\n", tick, label+":", val)
		} else {
			fmt.Printf("  %s  %-18s %s\n", cross, label+":", errVal)
		}
	}

	fmt.Println("=== Chainsaw Status ===")
	fmt.Println()

	fmt.Println("Server")
	if report.ServerURL == "" {
		printStatusLine("URL", "", "not configured", false)
	} else {
		printStatusLine("URL", report.ServerURL, "", true)
		printStatusLine("Reachable", report.Server.Status, report.Server.Error, report.Server.Reachable)
	}
	fmt.Println()

	fmt.Println("Org")
	if report.OrgID == "" {
		printStatusLine("Org ID", "", "not configured", false)
	} else {
		printStatusLine("Org ID", report.OrgID, "", true)
	}
	fmt.Println()

	fmt.Println("Auth")
	printStatusLine("Token", "configured", report.Auth.Error, report.Auth.Valid)
	if report.Auth.Valid {
		if report.Auth.UserID != "" {
			printStatusLine("Identity", report.Auth.UserID, "", true)
		}
		if report.Auth.Role != "" {
			printStatusLine("Role", report.Auth.Role, "", true)
		}
		if report.Auth.ExpiresAt != "" {
			printStatusLine("Expires", report.Auth.ExpiresAt, "", true)
		}
	}
	fmt.Println()
	fmt.Printf("Config file: %s\n", configFilePath())
	return nil
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
