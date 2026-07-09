package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
	"github.com/chain305/chainsaw-core/sbom"
)

var sbomCmd = &cobra.Command{
	Use:     "sbom",
	GroupID: GrpScan,
	Short:   "Software Bill of Materials commands",
}

var sbomExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export org SBOM in CycloneDX format",
	RunE:  runSBOMExport,
}

var sbomVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a Sigstore-signed CycloneDX SBOM bundle",
	Long: `Verify a Sigstore-signed CycloneDX SBOM bundle against the SBOM document
it attests to. Confirms:

  - The bundle's signature validates against the live Sigstore trust root
    (Rekor + Fulcio).
  - The in-toto subject digest matches sha256(canonical(SBOM)).
  - The predicateType is CycloneDX (not a different in-toto predicate).

On success the verified signer identity is printed: source repository
URL, builder OIDC subject, and OIDC issuer. Exits non-zero on any
failure so CI pipelines can gate on the verify step.`,
	RunE: runSBOMVerify,
}

// sbom diff
var sbomDiffCmd = &cobra.Command{
	Use:   "diff <a.json> <b.json>",
	Short: "Diff two SBOMs (CycloneDX or in-toto), reporting added, removed, and version-changed components",
	Long: `Diff two SBOM files. The format of each input is auto-detected: CycloneDX
documents (bomFormat="CycloneDX") and in-toto Statements wrapping a CycloneDX
predicate are both accepted. Both inputs must be the same format — mixing
CycloneDX and in-toto in a single diff is not supported in this iteration.`,
	Args: cobra.ExactArgs(2),
	RunE: runSBOMDiff,
}

func init() {
	sbomExportCmd.Flags().String("repo", "", "Filter by ecosystem/format (e.g. npm, pip, maven)")
	sbomExportCmd.Flags().String("package", "", "Filter by package name@version")
	sbomExportCmd.Flags().String("format", "cyclonedx", "SBOM format: cyclonedx (default) or spdx (SPDX 2.3, rendered client-side from the CycloneDX document)")
	sbomExportCmd.Flags().String("output", "", "Write SBOM to file instead of stdout")
	sbomExportCmd.Flags().Bool("with-attribution", false, "Include per-component attribution properties (chainsaw:attribution:*) derived from existing audit data. Overrides the server's sbom.attribution_enabled config for this export.")
	sbomCmd.AddCommand(sbomExportCmd)

	sbomVerifyCmd.Flags().String("bom", "", "Path to the CycloneDX SBOM JSON file the bundle attests to (required)")
	sbomVerifyCmd.Flags().String("bundle", "", "Path to the Sigstore bundle JSON file (required)")
	sbomVerifyCmd.Flags().String("cache-dir", "", "Optional Sigstore bundle cache directory (defaults to no caching)")
	sbomVerifyCmd.Flags().Duration("cache-ttl", 24*time.Hour, "Cache entry TTL when --cache-dir is set")
	sbomVerifyCmd.Flags().Bool("json", false, "Emit machine-readable JSON instead of the human summary")
	_ = sbomVerifyCmd.MarkFlagRequired("bom")
	_ = sbomVerifyCmd.MarkFlagRequired("bundle")
	sbomCmd.AddCommand(sbomVerifyCmd)

	// sbom diff
	sbomDiffCmd.Flags().String("format", "text", "Output format: text or json")
	sbomCmd.AddCommand(sbomDiffCmd)

	// sbom vex
	registerSBOMVexCmd()

	rootCmd.AddCommand(sbomCmd)
}

// sbom vex — see internal/sbom/vex.go for the mapping rules.
//
// Subtree shape: `chainsaw sbom vex export [--org] [-o vex.json]`. Kept
// separate from `sbom export` because VEX speaks vulnerabilities, not
// components, and downstream consumers expect a separate document.

var sbomVexCmd = &cobra.Command{
	Use:   "vex",
	Short: "CycloneDX VEX commands",
}

var sbomVexExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export org exceptions as a CycloneDX 1.6 VEX document",
	Long: `Export active exceptions as CycloneDX VEX statements. Each active
exception with a CVE reference becomes a vulnerabilities[] entry whose
analysis.state and analysis.justification reflect Chainsaw's stance:

  decision=allow → not_affected (code_not_present, or
                   vulnerable_code_not_in_execute_path when the note
                   indicates the vulnerable sink is unreachable)
  decision=monitor → in_triage

Denied and expired exceptions are excluded.`,
	RunE: runSBOMVexExport,
}

func registerSBOMVexCmd() {
	sbomVexExportCmd.Flags().String("org", "", "Org id (defaults to configured org)")
	sbomVexExportCmd.Flags().StringP("output", "o", "", "Write VEX to file instead of stdout")
	sbomVexCmd.AddCommand(sbomVexExportCmd)
	sbomCmd.AddCommand(sbomVexCmd)
}

func runSBOMVexExport(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	var resp struct {
		Entries []exceptionItem `json:"entries"`
	}
	if err := client.Get("/api/exceptions", &resp); err != nil {
		return err
	}

	exceptions := exceptionItemsToVEXInput(resp.Entries)
	orgID, _ := cmd.Flags().GetString("org")
	vex, err := sbom.BuildVEX(orgID, exceptions)
	if err != nil {
		return fmt.Errorf("build VEX: %w", err)
	}

	out, err := vex.ToJSON()
	if err != nil {
		return fmt.Errorf("encode VEX: %w", err)
	}
	out = append(out, '\n')

	outputFile, _ := cmd.Flags().GetString("output")
	if outputFile != "" {
		if err := os.WriteFile(outputFile, out, 0o644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		// Confirmation is chatter → stderr, keeping stdout clean under --output.
		fmt.Fprintf(os.Stderr, "VEX written to %s\n", outputFile)
		return nil
	}
	_, err = cmd.OutOrStdout().Write(out)
	return err
}

// exceptionItemsToVEXInput adapts the wire-format exceptionItem to the
// sbom.Exception DTO. Server-side exceptionEntry now carries Decision/CVE/
// Note, so we forward them straight through. Empty Decision falls back to
// "allow" so historical rows (written before the columns existed and now
// surfaced as NULL → "") still produce the same VEX output as before this
// change — see internal/sbom/vex.go::analyzeException for the mapping rules.
func exceptionItemsToVEXInput(items []exceptionItem) []sbom.Exception {
	out := make([]sbom.Exception, 0, len(items))
	for _, e := range items {
		decision := strings.ToLower(strings.TrimSpace(e.Decision))
		if decision == "" {
			decision = "allow"
		}
		out = append(out, sbom.Exception{
			ID:         e.ID,
			Decision:   decision,
			Repository: e.Repository,
			Ecosystem:  e.Format,
			Name:       e.PackageID,
			Version:    e.Version,
			CVE:        e.CVE,
			Note:       e.Note,
			CreatedAt:  e.CreatedAt,
			ExpiresAt:  e.ExpiresAt,
		})
	}
	return out
}

func runSBOMExport(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	sbomFmt, _ := cmd.Flags().GetString("format")
	asSPDX := strings.EqualFold(sbomFmt, "spdx")
	if !asSPDX && !strings.EqualFold(sbomFmt, "cyclonedx") {
		return fmt.Errorf("unknown format %q — supported values: cyclonedx, spdx", sbomFmt)
	}

	q := url.Values{}
	if repo, _ := cmd.Flags().GetString("repo"); repo != "" {
		q.Set("format", repo)
	}
	if withAttribution, _ := cmd.Flags().GetBool("with-attribution"); withAttribution {
		// One-off override of the server's sbom.attribution_enabled
		// config. The server treats `attribution=1` as additive — a
		// `false` here just falls back to the server-side default.
		q.Set("attribution", "1")
	}
	if pkg, _ := cmd.Flags().GetString("package"); pkg != "" {
		pkgName, pkgVersion := splitPackageArg(pkg)
		if pkgName != "" {
			q.Set("package_name", pkgName)
		}
		if pkgVersion != "" {
			q.Set("version", pkgVersion)
		}
	}

	path := "/api/sbom"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	var raw json.RawMessage
	if err := client.Get(path, &raw); err != nil {
		return err
	}

	var buf bytes.Buffer
	if asSPDX {
		// The server speaks CycloneDX only; project its document into SPDX 2.3
		// client-side. Parse the CycloneDX payload, convert, then re-encode.
		var cdx sbom.CycloneDXBOM
		if err := json.Unmarshal(raw, &cdx); err != nil {
			return fmt.Errorf("parse CycloneDX SBOM for SPDX conversion: %w", err)
		}
		out, err := json.MarshalIndent(cycloneDXToSPDX(&cdx), "", "  ")
		if err != nil {
			return fmt.Errorf("encode SPDX SBOM: %w", err)
		}
		buf.Write(out)
	} else if err := json.Indent(&buf, raw, "", "  "); err != nil {
		buf.Write(raw)
	}
	buf.WriteByte('\n')

	outputFile, _ := cmd.Flags().GetString("output")
	if outputFile != "" {
		if err := os.WriteFile(outputFile, buf.Bytes(), 0o644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		// Confirmation is chatter, not a result — send it to stderr so
		// `sbom export --output x | consumer` keeps stdout empty/clean
		// (invariant C).
		fmt.Fprintf(os.Stderr, "SBOM written to %s\n", outputFile)
		return nil
	}

	_, err := os.Stdout.Write(buf.Bytes())
	return err
}

func runSBOMVerify(cmd *cobra.Command, _ []string) error {
	bomPath, _ := cmd.Flags().GetString("bom")
	bundlePath, _ := cmd.Flags().GetString("bundle")
	cacheDir, _ := cmd.Flags().GetString("cache-dir")
	cacheTTL, _ := cmd.Flags().GetDuration("cache-ttl")
	asJSON := useJSON(cmd)

	bomBytes, err := os.ReadFile(bomPath)
	if err != nil {
		return fmt.Errorf("read SBOM: %w", err)
	}
	var bom sbom.CycloneDXBOM
	if err := json.Unmarshal(bomBytes, &bom); err != nil {
		return fmt.Errorf("parse SBOM: %w", err)
	}

	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}

	var cache *sigstoreverify.BundleCache
	if cacheDir != "" {
		c, err := sigstoreverify.NewBundleCache(cacheDir, cacheTTL)
		if err != nil {
			return fmt.Errorf("open cache: %w", err)
		}
		cache = c
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
	defer cancel()

	// Sigstore verification can take up to the 60s timeout above with no
	// output. Surface progress on stderr so the --json stdout payload stays
	// clean.
	fmt.Fprintln(os.Stderr, "verifying signature…")

	result, err := sbom.VerifySignedSBOM(ctx, bundleBytes, &bom, cache)
	if err != nil {
		// Exit non-zero so CI gates on verify failure. Print the error
		// to stderr (cobra prints to stdout by default for RunE errors,
		// which makes scripting messier).
		fmt.Fprintf(os.Stderr, "verify failed: %v\n", err)
		os.Exit(1)
	}

	if asJSON {
		out := map[string]any{
			"verified":         true,
			"sourceRepo":       result.Identity.SourceRepo,
			"builderId":        result.Identity.BuilderID,
			"issuer":           result.Identity.Issuer,
			"sbomDigestSha256": encodeHexLower(result.SBOMDigest[:]),
			"cacheStale":       result.CacheStale,
		}
		buf, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(buf))
		return nil
	}

	fmt.Println("SBOM signature: VERIFIED")
	if result.Identity.SourceRepo != "" {
		fmt.Printf("  Source repo:  %s\n", result.Identity.SourceRepo)
	}
	if result.Identity.BuilderID != "" {
		fmt.Printf("  Builder:      %s\n", result.Identity.BuilderID)
	}
	if result.Identity.Issuer != "" {
		fmt.Printf("  OIDC issuer:  %s\n", result.Identity.Issuer)
	}
	fmt.Printf("  SBOM digest:  sha256:%s\n", encodeHexLower(result.SBOMDigest[:]))
	if result.CacheStale {
		fmt.Println("  WARNING: served from stale Sigstore cache (Rekor/Fulcio unreachable)")
	}
	return nil
}

// encodeHexLower mirrors hex.EncodeToString without dragging another
// import into this CLI file.
func encodeHexLower(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0f]
	}
	return string(out)
}

// sbom diff
func runSBOMDiff(cmd *cobra.Command, args []string) error {
	aData, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read %s: %w", args[0], err)
	}
	bData, err := os.ReadFile(args[1])
	if err != nil {
		return fmt.Errorf("read %s: %w", args[1], err)
	}

	result, err := sbom.DiffFiles(aData, bData)
	if err != nil {
		return err
	}

	format, _ := cmd.Flags().GetString("format")
	switch strings.ToLower(format) {
	case "json":
		buf, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(buf))
		return nil
	case "", "text":
		writeDiffText(cmd.OutOrStdout(), result)
		return nil
	default:
		return fmt.Errorf("unknown format %q — supported values: text, json", format)
	}
}

func writeDiffText(w interface{ Write(p []byte) (int, error) }, r sbom.DiffResult) {
	fmt.Fprintln(w, "Added:")
	for _, c := range r.Added {
		fmt.Fprintf(w, "  %s@%s (%s)\n", c.Name, c.Version, ecosystemLabel(c.PURL))
	}
	fmt.Fprintln(w, "Removed:")
	for _, c := range r.Removed {
		fmt.Fprintf(w, "  %s@%s (%s)\n", c.Name, c.Version, ecosystemLabel(c.PURL))
	}
	fmt.Fprintln(w, "Changed:")
	for _, c := range r.Changed {
		fmt.Fprintf(w, "  %s (%s): %s -> %s\n", c.Name, c.Ecosystem, c.OldVersion, c.NewVersion)
	}
}

// ecosystemLabel pulls the PURL ecosystem prefix for the text formatter.
// Mirrors the logic in internal/sbom but avoids exporting it; the diff
// rendering is the only consumer that needs it on the CLI side.
func ecosystemLabel(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return ""
	}
	return rest[:slash]
}
