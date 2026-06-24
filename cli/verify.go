package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/provenance"
	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

var verifyCmd = &cobra.Command{
	Use:   "verify <ecosystem> <package> <version>",
	Short: "Verify a package's provenance attestation chain",
	Long: `Verify a package's provenance attestation chain end-to-end. Runs the
same checker chainsaw's intelligence pipeline runs (npm, PyPI, Maven,
Go, Docker, APT, ...), prints the verified SLSA level, builder identity,
source repo + commit, transparency log entry, and exits non-zero on any
failure.

This is the primary "show me the chain of custody" tool — operators
diagnosing why a policy fired, or auditors confirming a deployment
artifact's claims.

Sigstore verification runs online by default; pass --cache-dir to
reuse a previous verification when Rekor/Fulcio are unreachable.`,
	Args: cobra.ExactArgs(3),
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().Duration("timeout", 60*time.Second, "Total verification timeout")
	verifyCmd.Flags().String("cache-dir", "", "Optional Sigstore bundle cache directory (defaults to no caching)")
	verifyCmd.Flags().Duration("cache-ttl", 24*time.Hour, "Cache entry TTL when --cache-dir is set")
	verifyCmd.Flags().Bool("json", false, "Emit machine-readable JSON instead of the human chain summary")
	verifyCmd.Flags().String("source-url", "", "Optional upstream URL hint for source-aware ecosystems (APT/DNF/YUM)")
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	ecosystem, pkgName, version := args[0], args[1], args[2]
	timeout, _ := cmd.Flags().GetDuration("timeout")
	cacheDir, _ := cmd.Flags().GetString("cache-dir")
	cacheTTL, _ := cmd.Flags().GetDuration("cache-ttl")
	asJSON, _ := cmd.Flags().GetBool("json")
	sourceURL, _ := cmd.Flags().GetString("source-url")

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	opts := []provenance.CheckerOption{}
	if cacheDir != "" {
		cache, err := sigstoreverify.NewBundleCache(cacheDir, cacheTTL)
		if err != nil {
			return fmt.Errorf("open cache: %w", err)
		}
		opts = append(opts, provenance.WithSigstoreCache(cache))
	}
	checker := provenance.NewChecker(logger, opts...)

	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	result := checker.CheckWithSource(ctx, ecosystem, pkgName, version, sourceURL)

	if asJSON {
		buf, err := json.MarshalIndent(verifyJSON(ecosystem, pkgName, version, result), "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(buf))
	} else {
		printVerifyHuman(ecosystem, pkgName, version, result)
	}

	switch result.Status {
	case provenance.StatusVerified:
		return nil
	default:
		// Exit non-zero on anything other than fully-verified so CI
		// gates and `set -e` shell scripts treat missing/failed/
		// unverified attestations as failures.
		os.Exit(1)
	}
	return nil
}

// verifyJSON shapes the human-readable output for machine consumption.
// Stable: dashboards, audit pipelines, and CI scripts depend on the
// field names. Add fields rather than rename.
func verifyJSON(ecosystem, pkgName, version string, r provenance.Result) map[string]any {
	out := map[string]any{
		"ecosystem":       ecosystem,
		"package":         pkgName,
		"version":         version,
		"status":          string(r.Status),
		"verified":        r.Status == provenance.StatusVerified,
		"attestationType": r.AttestationType,
		"slsaLevel":       r.SLSALevel,
		"builderId":       r.BuilderID,
		"sourceRepo":      r.SourceRepo,
		"sourceCommit":    r.SourceCommit,
		"subjectDigest":   r.SubjectDigest,
		"bundleFormat":    r.BundleFormat,
		"transparencyLog": r.TransparencyLogURL,
		"cacheStale":      r.CacheStale,
		"warnings":        r.Warnings,
		"verifiedAt":      r.VerifiedAt,
	}
	if r.Error != "" {
		out["error"] = r.Error
	}
	return out
}

func printVerifyHuman(ecosystem, pkgName, version string, r provenance.Result) {
	fmt.Printf("Verifying %s/%s@%s\n", ecosystem, pkgName, version)
	switch r.Status {
	case provenance.StatusVerified:
		fmt.Println("  Status:        VERIFIED")
	case provenance.StatusUnverified:
		fmt.Println("  Status:        UNVERIFIED (attestation present, not validated)")
	case provenance.StatusMissing:
		fmt.Println("  Status:        MISSING (ecosystem supports attestations; package has none)")
	case provenance.StatusUnavailable:
		fmt.Println("  Status:        UNAVAILABLE (ecosystem does not expose attestations)")
	case provenance.StatusFailed:
		fmt.Println("  Status:        FAILED")
	default:
		fmt.Printf("  Status:        %s\n", r.Status)
	}
	if r.AttestationType != "" {
		fmt.Printf("  Attestation:   %s\n", r.AttestationType)
	}
	if r.SLSALevel > 0 {
		fmt.Printf("  SLSA level:    %d\n", r.SLSALevel)
	}
	if r.BuilderID != "" {
		fmt.Printf("  Builder:       %s\n", r.BuilderID)
	}
	if r.SourceRepo != "" {
		fmt.Printf("  Source repo:   %s\n", r.SourceRepo)
	}
	if r.SourceCommit != "" {
		fmt.Printf("  Source commit: %s\n", r.SourceCommit)
	}
	if r.SubjectDigest != "" {
		fmt.Printf("  Subject:       %s\n", r.SubjectDigest)
	}
	if r.TransparencyLogURL != "" {
		fmt.Printf("  Rekor entry:   %s\n", r.TransparencyLogURL)
	}
	if r.BundleFormat != "" {
		fmt.Printf("  Bundle:        %s\n", r.BundleFormat)
	}
	if r.CacheStale {
		fmt.Println("  WARNING: served from stale Sigstore cache (Rekor/Fulcio unreachable)")
	}
	for _, w := range r.Warnings {
		fmt.Printf("  Warning:       %s\n", w)
	}
	if r.Error != "" {
		fmt.Fprintf(os.Stderr, "  Error:         %s\n", r.Error)
	}
}
