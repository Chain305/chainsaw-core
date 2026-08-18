package cli

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:     "report",
	Short:   "Cross-org reports derived from install events",
	GroupID: GrpAudit,
}

var reportMultiVersionCmd = &cobra.Command{
	Use:   "multiversion",
	Short: "Show packages installed at multiple versions across repos",
	RunE:  runReportMultiVersion,
}

// provenance-coverage
var reportProvenanceCmd = &cobra.Command{
	Use:   "provenance",
	Short: "Show what fraction of installed packages have verified provenance attestations",
	RunE:  runReportProvenance,
}

// provenance-coverage end

// exposure-window
var reportExposureCmd = &cobra.Command{
	Use:   "exposure",
	Short: `Answer "between dates X and Y, what packages did we install?" — IR-class exposure-window query`,
	RunE:  runReportExposure,
}

// exposure-window end

// owner-sla
var reportSLACmd = &cobra.Command{
	Use:   "sla",
	Short: "Per-team mean and median time-to-remediate for resolved violations",
	RunE:  runReportSLA,
}

// owner-sla end

func init() {
	reportMultiVersionCmd.Flags().String("ecosystem", "", "Filter by ecosystem (e.g. npm, pypi, maven)")
	reportMultiVersionCmd.Flags().Int("min-versions", 0, "Exclude packages with fewer distinct versions")
	reportMultiVersionCmd.Flags().String("format", "text", "Output format: text or json")
	reportCmd.AddCommand(reportMultiVersionCmd)
	// provenance-coverage
	reportProvenanceCmd.Flags().String("ecosystem", "", "Filter by ecosystem (e.g. npm, pypi, maven)")
	reportProvenanceCmd.Flags().String("format", "text", "Output format: text or json")
	reportCmd.AddCommand(reportProvenanceCmd)
	// provenance-coverage end
	// exposure-window
	reportExposureCmd.Flags().String("start", "", "Inclusive RFC3339 start of window (required)")
	reportExposureCmd.Flags().String("end", "", "Exclusive RFC3339 end of window (required)")
	reportExposureCmd.Flags().String("ecosystem", "", "Filter by ecosystem (e.g. npm, pypi, maven)")
	reportExposureCmd.Flags().String("format", "text", "Output format: text or json")
	reportCmd.AddCommand(reportExposureCmd)
	// exposure-window end
	// owner-sla
	reportSLACmd.Flags().String("since", "", "Only consider violations resolved at-or-after this RFC3339 timestamp")
	reportSLACmd.Flags().String("format", "text", "Output format: text or json")
	reportCmd.AddCommand(reportSLACmd)
	// owner-sla end
	rootCmd.AddCommand(reportCmd)
}

// resolveReportFormat resolves the output format for every `report`
// subcommand.
//
// S8 — these four commands read only their LOCAL --format and ignored the root
// persistent --json, which root.go documents as "sugar for --format=json" and
// which scan / scan-repo / deps / affected all honor. `chainsaw report sla
// --json | jq` therefore got a tabwriter table and exit 0. resolveFormat
// reconciles the two; "table" (resolveFormat's no-format default) is folded
// onto this family's "text" spelling so a value the user never typed can't
// produce an "unknown format" error.
func resolveReportFormat(cmd *cobra.Command) string {
	format := strings.ToLower(strings.TrimSpace(resolveFormat(cmd)))
	if format == "" || format == "table" {
		return "text"
	}
	return format
}

// reportTabWriter returns the tabwriter every `report` subcommand renders its
// TEXT result through.
//
// S9b — all four subcommands wrote the text table to a `tabwriter.NewWriter(
// os.Stdout, …)`, so --output was honoured on the json path and silently
// dropped on the text path: `report exposure --format text --output R` exited
// 0, created no file, and put 8,405 bytes on stdout. root.go's
// formatIsMachineReadable explicitly lets `report {exposure,multiversion,
// provenance,sla} --format text --output X` through the validator on the
// grounds that this family routes its result through a sink that honours
// --output — this is the sink that makes that true.
//
// Routing through cmd.OutOrStdout() (not raw os.Stdout) additionally makes the
// text path honour cobra's SetOut, which is how every test in this package
// captures output.
func reportTabWriter(cmd *cobra.Command) *tabwriter.Writer {
	return tabwriter.NewWriter(outWriterOr(cmd, cmd.OutOrStdout()), 0, 0, 2, ' ', 0)
}

type reportMultiVersionRow struct {
	Version string   `json:"version"`
	Repos   []string `json:"repos"`
	Count   int      `json:"count"`
}

type reportMultiVersionEntry struct {
	Ecosystem string                  `json:"ecosystem"`
	Package   string                  `json:"package"`
	Versions  []reportMultiVersionRow `json:"versions"`
}

type reportMultiVersionEnvelope struct {
	Data []reportMultiVersionEntry `json:"data"`
}

func runReportMultiVersion(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	format := resolveReportFormat(cmd)
	if format != "text" && format != "json" {
		return fmt.Errorf("unknown format %q — supported values: text, json", format)
	}

	q := url.Values{}
	if eco, _ := cmd.Flags().GetString("ecosystem"); eco != "" {
		q.Set("ecosystem", eco)
	}
	if mv, _ := cmd.Flags().GetInt("min-versions"); mv > 0 {
		q.Set("min_versions", strconv.Itoa(mv))
	}

	path := "/api/v1/reports/multiversion"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	var env reportMultiVersionEnvelope
	if err := client.Get(path, &env); err != nil {
		return err
	}

	if format == "json" {
		// S9 — honor --output. encodeJSON is byte-identical to the previous
		// MarshalIndent+Println pair (two-space indent, trailing newline).
		return encodeJSON(outWriterOr(cmd, cmd.OutOrStdout()), env.Data)
	}

	// Empty state before the header. A bare header row with nothing under it
	// reads as "the query failed" rather than "the answer is none", and these
	// reports are most often run precisely to confirm a clean result. The text
	// names what was looked for so the operator can tell an empty answer from
	// a wrong filter.
	if len(env.Data) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No packages installed at multiple versions.")
		return nil
	}

	tw := reportTabWriter(cmd)
	fmt.Fprintln(tw, "ECOSYSTEM\tPACKAGE\tVERSIONS\tREPOS")
	for _, e := range env.Data {
		repoSet := make(map[string]struct{})
		for _, v := range e.Versions {
			for _, r := range v.Repos {
				repoSet[r] = struct{}{}
			}
		}
		repos := make([]string, 0, len(repoSet))
		for r := range repoSet {
			repos = append(repos, r)
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\n",
			e.Ecosystem, e.Package, len(e.Versions), len(repos))
	}
	return tw.Flush()
}

// provenance-coverage
type reportProvenanceEntry struct {
	Ecosystem      string  `json:"ecosystem"`
	TotalInstalls  int     `json:"totalInstalls"`
	WithProvenance int     `json:"withProvenance"`
	Coverage       float64 `json:"coverage"`
}

type reportProvenanceEnvelope struct {
	Data []reportProvenanceEntry `json:"data"`
}

func runReportProvenance(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	format := resolveReportFormat(cmd)
	if format != "text" && format != "json" {
		return fmt.Errorf("unknown format %q — supported values: text, json", format)
	}

	q := url.Values{}
	if eco, _ := cmd.Flags().GetString("ecosystem"); eco != "" {
		q.Set("ecosystem", eco)
	}

	path := "/api/v1/reports/provenance"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	var env reportProvenanceEnvelope
	if err := client.Get(path, &env); err != nil {
		return err
	}

	if format == "json" {
		// S9 — honor --output. encodeJSON is byte-identical to the previous
		// MarshalIndent+Println pair (two-space indent, trailing newline).
		return encodeJSON(outWriterOr(cmd, cmd.OutOrStdout()), env.Data)
	}

	// Empty state before the header. A bare header row with nothing under it
	// reads as "the query failed" rather than "the answer is none", and these
	// reports are most often run precisely to confirm a clean result. The text
	// names what was looked for so the operator can tell an empty answer from
	// a wrong filter.
	if len(env.Data) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No install events with provenance data.")
		return nil
	}

	tw := reportTabWriter(cmd)
	fmt.Fprintln(tw, "ECOSYSTEM\tINSTALLS\tWITH PROVENANCE\tCOVERAGE")
	for _, e := range env.Data {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%.1f%%\n",
			e.Ecosystem, e.TotalInstalls, e.WithProvenance, e.Coverage*100)
	}
	return tw.Flush()
}

// provenance-coverage end

// exposure-window
type reportExposureEntry struct {
	Ecosystem  string    `json:"ecosystem"`
	Package    string    `json:"package"`
	Version    string    `json:"version"`
	Repository string    `json:"repository"`
	At         time.Time `json:"at"`
}

type reportExposureEnvelope struct {
	Data []reportExposureEntry `json:"data"`
}

func runReportExposure(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	start, _ := cmd.Flags().GetString("start")
	end, _ := cmd.Flags().GetString("end")
	if start == "" || end == "" {
		return fmt.Errorf("--start and --end are required (RFC3339)")
	}
	if _, err := time.Parse(time.RFC3339, start); err != nil {
		return fmt.Errorf("--start must be RFC3339: %w", err)
	}
	if _, err := time.Parse(time.RFC3339, end); err != nil {
		return fmt.Errorf("--end must be RFC3339: %w", err)
	}

	format := resolveReportFormat(cmd)
	if format != "text" && format != "json" {
		return fmt.Errorf("unknown format %q — supported values: text, json", format)
	}

	q := url.Values{}
	q.Set("start", start)
	q.Set("end", end)
	if eco, _ := cmd.Flags().GetString("ecosystem"); eco != "" {
		q.Set("ecosystem", eco)
	}

	var env reportExposureEnvelope
	if err := client.Get("/api/v1/reports/exposure?"+q.Encode(), &env); err != nil {
		return err
	}

	if format == "json" {
		// S9 — honor --output. encodeJSON is byte-identical to the previous
		// MarshalIndent+Println pair (two-space indent, trailing newline).
		return encodeJSON(outWriterOr(cmd, cmd.OutOrStdout()), env.Data)
	}

	// Empty state before the header. A bare header row with nothing under it
	// reads as "the query failed" rather than "the answer is none", and these
	// reports are most often run precisely to confirm a clean result. The text
	// names what was looked for so the operator can tell an empty answer from
	// a wrong filter.
	if len(env.Data) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No packages installed in that window.")
		return nil
	}

	tw := reportTabWriter(cmd)
	fmt.Fprintln(tw, "AT\tECOSYSTEM\tPACKAGE\tVERSION\tREPOSITORY")
	for _, e := range env.Data {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			e.At.Format(time.RFC3339), e.Ecosystem, e.Package, e.Version, e.Repository)
	}
	return tw.Flush()
}

// exposure-window end

// owner-sla
type reportSLAEntry struct {
	Owners        []string `json:"owners"`
	Resolved      int      `json:"resolved"`
	MeanSeconds   float64  `json:"meanSeconds"`
	MedianSeconds float64  `json:"medianSeconds"`
}

type reportSLAEnvelope struct {
	Data []reportSLAEntry `json:"data"`
}

func runReportSLA(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	format := resolveReportFormat(cmd)
	if format != "text" && format != "json" {
		return fmt.Errorf("unknown format %q — supported values: text, json", format)
	}

	q := url.Values{}
	if since, _ := cmd.Flags().GetString("since"); since != "" {
		if _, err := time.Parse(time.RFC3339, since); err != nil {
			return fmt.Errorf("--since must be RFC3339: %w", err)
		}
		q.Set("since", since)
	}

	path := "/api/v1/reports/sla"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	var env reportSLAEnvelope
	if err := client.Get(path, &env); err != nil {
		return err
	}

	if format == "json" {
		// S9 — honor --output. encodeJSON is byte-identical to the previous
		// MarshalIndent+Println pair (two-space indent, trailing newline).
		return encodeJSON(outWriterOr(cmd, cmd.OutOrStdout()), env.Data)
	}

	// Empty state before the header. A bare header row with nothing under it
	// reads as "the query failed" rather than "the answer is none", and these
	// reports are most often run precisely to confirm a clean result. The text
	// names what was looked for so the operator can tell an empty answer from
	// a wrong filter.
	if len(env.Data) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No resolved violations to measure.")
		return nil
	}

	tw := reportTabWriter(cmd)
	fmt.Fprintln(tw, "OWNERS\tRESOLVED\tMEAN\tMEDIAN")
	for _, e := range env.Data {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n",
			strings.Join(e.Owners, ","), e.Resolved,
			time.Duration(e.MeanSeconds*float64(time.Second)).Round(time.Second),
			time.Duration(e.MedianSeconds*float64(time.Second)).Round(time.Second))
	}
	return tw.Flush()
}

// owner-sla end
