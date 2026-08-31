package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/provenance"
	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

var verifyCmd = &cobra.Command{
	Use:     "verify <ecosystem> <package> <version>",
	GroupID: GrpIntel,
	Short:   "Verify a package's provenance attestation chain",
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
	verifyCmd.Flags().String("source-url", "", "Repository/registry base URL. REQUIRED for apt, yum, dnf and swift; an optional upstream hint elsewhere")
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	ecosystem, pkgName, version := args[0], args[1], args[2]
	timeout, _ := cmd.Flags().GetDuration("timeout")
	cacheDir, _ := cmd.Flags().GetString("cache-dir")
	cacheTTL, _ := cmd.Flags().GetDuration("cache-ttl")
	sourceURL, _ := cmd.Flags().GetString("source-url")

	// Refuse the invocation BEFORE building a checker or dialling
	// anything. Without --source-url these ecosystems can only report
	// StatusUnavailable, which the human renderer used to spell
	// "ecosystem does not expose attestations" — a false claim about APT,
	// YUM, DNF and Swift, all of which do. See P8-47 / P8-48.
	if err := requireSourceURL(ecosystem, sourceURL); err != nil {
		return err
	}

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
	// Swift takes its registry base URL from Checker state rather than the
	// per-call sourceURL, because swiftChecker is not a SourceAwareChecker.
	// Without this the CLI could never reach a Swift registry at all: the
	// server reads provenance.swift_registry_url from config, and the CLI
	// has no config plumbing for it.
	if isSwiftEcosystem(ecosystem) {
		checker.WithSwiftRegistryURL(sourceURL)
	}
	// npm is the CLI's counterpart to the server reading its configured
	// npm upstream: npmChecker is not a SourceAwareChecker either, so
	// --source-url is the only way a user on a mirrored or air-gapped
	// network can point `chainsaw verify npm ...` at the registry the
	// tarball actually came from. Unlike swift, --source-url is optional
	// here (it is an "upstream hint" per the flag help): omitting it
	// leaves the explicit public-registry fallback in place rather than
	// disabling the probe.
	if isNPMEcosystem(ecosystem) {
		checker.WithNPMRegistryURL(sourceURL)
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	// Live Sigstore/Rekor/Fulcio verification can run up to --timeout (60s
	// default) with no output. Emit progress on stderr — printVerifyHuman
	// prints an identical line to stdout after the call, so keeping this on
	// stderr avoids an apparent duplicate and keeps stdout/JSON clean.
	fmt.Fprintf(os.Stderr, "Verifying %s/%s@%s…\n", ecosystem, pkgName, version)

	result := checker.CheckWithSource(ctx, ecosystem, pkgName, version, sourceURL)

	// Render, THEN gate — always, in both formats. The --json branch used
	// to `return` before the status switch, so `verify --json` exited 0 on
	// MISSING / FAILED / UNVERIFIED: the verification ran, was printed, and
	// was thrown away. useJSON also trips on the global `--format json`, so
	// an org-wide format setting silently disarmed every verify call in the
	// pipeline. Choosing a machine-readable rendering must never weaken a
	// verdict; emitAndGate makes that structural (see output.go).
	//
	// The gate returns an error rather than calling os.Exit, so the deferred
	// cancel() runs and a --output file is flushed before the process ends.
	return renderAndGateVerify(cmd, ecosystem, pkgName, version, result)
}

// renderAndGateVerify is runVerify minus the live Sigstore call: given a
// finished result, render it in the resolved format and apply the gate.
// Split out so the "a machine-readable rendering never weakens a verdict"
// property is testable without a network round trip — the property is the
// whole point of the fix, so it must be pinned by a test that exercises
// this exact composition rather than a hand-rolled stand-in.
func renderAndGateVerify(cmd *cobra.Command, ecosystem, pkgName, version string, result provenance.Result) error {
	return emitAndGate(cmd,
		verifyJSON(ecosystem, pkgName, version, result),
		func() error {
			printVerifyHuman(ecosystem, pkgName, version, result)
			return nil
		},
		func() error { return verifyExitError(result.Status) },
	)
}

// sourceURLRequiredEcosystems are the ecosystems where (name, version)
// alone cannot identify a trust domain, so a verification attempt is
// impossible without --source-url.
//
// apt/yum/dnf: the repository URL determines which keyring signs the
// metadata. swift: SE-0292 registries are not centrally hosted, so there
// is no registry to query until one is named.
//
// Deliberately NOT a defaulted value. A default mirror is a guess, and a
// guess that happens to carry a matching name+version walks a real
// signed chain and returns VERIFIED for bytes the user never installed —
// openssl 3.0.2 exists in both Ubuntu jammy and Debian. A false
// attestation is strictly worse than a refused invocation. In the common
// case the guess misses and the checker returns FAILED, the same status a
// tampered package gets. See P8-47.
var sourceURLRequiredEcosystems = map[string]string{
	"apt":   "--source-url https://deb.debian.org/debian/dists/bookworm",
	"yum":   "--source-url https://dl.fedoraproject.org/pub/fedora/linux/releases/40/Everything/x86_64/os",
	"dnf":   "--source-url https://dl.fedoraproject.org/pub/fedora/linux/releases/40/Everything/x86_64/os",
	"swift": "--source-url https://swift-registry.example.com",
}

func isSwiftEcosystem(ecosystem string) bool {
	return strings.ToLower(strings.TrimSpace(ecosystem)) == "swift"
}

// isNPMEcosystem matches the ecosystem key the provenance dispatcher
// registers the npm checker under. Only "npm" — yarn and bun proxy the
// same packages but are not registered aliases of the npm checker, so
// widening this would silently configure nothing.
func isNPMEcosystem(ecosystem string) bool {
	return strings.ToLower(strings.TrimSpace(ecosystem)) == "npm"
}

// requireSourceURL refuses the invocation with exit 4 (bad invocation)
// when a source-aware ecosystem was asked for without --source-url.
//
// Exit 4, not exit 1: nothing was verified and nothing was refused —
// the command was malformed. Collapsing that into the blocked/failed
// exit code is how "you forgot a flag" ends up looking like "this
// package has no provenance" in a CI log.
func requireSourceURL(ecosystem, sourceURL string) error {
	key := strings.ToLower(strings.TrimSpace(ecosystem))
	example, needs := sourceURLRequiredEcosystems[key]
	if !needs || strings.TrimSpace(sourceURL) != "" {
		return nil
	}
	var what string
	switch key {
	case "swift":
		what = "Swift Package Registries (SE-0292) are not centrally hosted, so there is no " +
			"default registry to query"
	default:
		what = "the repository URL determines which keyring signs the metadata, and guessing a " +
			"mirror could verify bytes you never installed"
	}
	detail := "chainsaw implements a verifier for it"
	if key == "swift" {
		detail = "chainsaw implements the SE-0391 CMS probe (full chain validation additionally " +
			"needs provenance.swift_full_verify)"
	}
	return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf(
		"chainsaw verify %s requires --source-url: %s.\n"+
			"  %s does publish verifiable provenance and %s — but it cannot be reached "+
			"from (package, version) alone.\n"+
			"  Try: chainsaw verify %s <package> <version> %s",
		key, what, key, detail, key, example)}
}

// verifyExitError maps a provenance status to the process exit-code
// contract. Anything short of fully-verified is a gate failure, matching
// the command's own help ("exits non-zero on any failure") — CI gates and
// `set -e` scripts must treat missing/failed/unverified attestations as
// failures. Pure so the mapping is table-testable without running a live
// Sigstore check.
//
// Err is left nil, mirroring the simulate/auth convention: the verdict is
// already on stdout, and the coded error only carries the exit code, which
// keeps the stdout JSON envelope byte-clean for parsers.
//
// There is deliberately no --exit-zero escape hatch here. Most packages
// carry no attestations at all, so a flag to suppress the failure would be
// reached for reflexively and would re-create the original bug behind a
// flag name. Teams collecting-without-gating should branch on the `status`
// field in the JSON envelope.
func verifyExitError(status provenance.Status) error {
	if status == provenance.StatusVerified {
		return nil
	}
	return &ExitCodeError{Code: ExitBlocked}
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
		"reason":          r.Reason,
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

// unavailableGloss turns a provenance Reason code into the one-line
// gloss printed beside UNAVAILABLE.
//
// This line used to be the hardcoded "ecosystem does not expose
// attestations" for every cause. That is true of cargo, composer and
// cocoapods; it is FALSE of APT (which publishes signed InRelease
// metadata), of Swift (SE-0391 CMS), and of any ecosystem chainsaw
// simply has not written a checker for. Printing a claim about the
// ecosystem when the real cause is a missing flag, unset config, or a
// gap in chainsaw is the defect. See P8-47 / P8-48.
func unavailableGloss(reason string) string {
	switch reason {
	case provenance.ReasonEcosystemNoStandard:
		return "this ecosystem publishes no verifiable attestations"
	case provenance.ReasonNoCheckerRegistered:
		return "chainsaw has no checker for this ecosystem — a coverage gap, not an ecosystem property"
	case provenance.ReasonNotConfigured:
		return "required configuration is unset; nothing was attempted"
	case provenance.ReasonSourceURLRequired:
		return "no --source-url supplied; nothing was attempted"
	case provenance.ReasonKeyringUnavailable:
		return "no trusted keys available; trust could not be evaluated"
	case provenance.ReasonInconclusive:
		return "the chain could not be walked to a conclusion"
	case provenance.ReasonOfflineMode, provenance.ReasonEcosystemDisabled:
		return "verification is switched off by configuration"
	case provenance.ReasonArtifactTooLarge:
		return "artifact exceeds the verification size cap"
	case provenance.ReasonUpstreamError:
		return "upstream registry could not be reached"
	case "":
		return "no reason recorded"
	default:
		return reason
	}
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
		fmt.Printf("  Status:        UNAVAILABLE (%s)\n", unavailableGloss(r.Reason))
	case provenance.StatusFailed:
		fmt.Println("  Status:        FAILED")
	default:
		fmt.Printf("  Status:        %s\n", r.Status)
	}
	if r.Reason != "" {
		fmt.Printf("  Reason:        %s\n", r.Reason)
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
