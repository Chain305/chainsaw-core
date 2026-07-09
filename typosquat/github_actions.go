package typosquat

import "strings"

// GitHub Actions corpus and normalizer for typosquat detection.
//
// Identity model:
//
//   - The canonical identity of an Action is "<owner>/<name>" — no version,
//     no path component, no leading scheme. A workflow line like
//     `uses: actions/checkout@v4` references the same Action as
//     `uses: actions/checkout@v3.5.2` or `uses: actions/checkout/foo@main`
//     (composite-action path); they are all the `actions/checkout` repo.
//     The detector strips the `@<ref>` suffix and any path component beyond
//     `owner/name` at lookup time so a typosquat detector seeded with bare
//     `owner/name` strings still fires.
//
//   - Owner is part of identity. `actions/checkout` and
//     `attacker/checkout` are different repos owned by different parties —
//     stripping the owner would collapse every fork onto the legitimate
//     name and silent-pass owner-shadow attacks (the same class of bug
//     Maven/Composer/HuggingFace/Docker normalize against). We keep the
//     full coordinate.
//
//   - GitHub repository names are case-insensitive (`Actions/Checkout`
//     resolves to the same repo as `actions/checkout`), so we lowercase
//     for comparison.
//
// Sourcing rationale for the curated corpus below:
//
//   - GitHub Marketplace and the public usage telemetry that surfaces in
//     starboard / OSS supply-chain reports consistently rank the
//     `actions/*` first-party Actions plus a small set of vendor-published
//     Actions (aws-actions, docker, github, microsoft, azure,
//     google-github-actions, goreleaser, golangci) at the top of the
//     long tail by usage count across public workflows.
//
//   - The list is intentionally focused on Actions that (a) appear in a
//     large fraction of real CI pipelines and (b) have been impersonated
//     in the wild or are obvious typosquat targets (singular `action`
//     vs plural `actions`, dropped vowels, etc.).
//
//   - There is no public top-N Marketplace API; this list is curated by
//     hand and refreshed out-of-band, mirroring the Cocoapods/Go seed
//     pattern. ~80 entries is the operational sweet spot — large enough
//     to cover the bulk of real workflow `uses:` references, small
//     enough that an attacker can't hide a spoof inside a long tail of
//     low-signal entries.

// NormalizeGitHubActions canonicalizes a GitHub Actions reference for
// typosquat comparison. It:
//
//  1. Lowercases (GitHub repos are case-insensitive).
//  2. Strips a leading `uses:` or whitespace (defensive — workflow YAML
//     parsers strip this, but if a caller passes a raw line we do too).
//  3. Strips `@<ref>` version pinning suffix.
//  4. Strips any path component beyond `owner/name` (composite-action
//     subpaths like `actions/cache/save` resolve to the `actions/cache`
//     repo's identity for typosquat purposes).
//  5. Replaces the owner/name slash with `-` so the reorder index sees
//     owner and name as two ordinary tokens. GitHub has no single-segment
//     Actions namespace (every Action lives under an owner), so this can't
//     collide with a real bare name. The collapse lets the detector catch
//     `checkout/actions` reordered against popular `actions/checkout` —
//     a known typosquat shape that pure edit distance misses because the
//     character set is identical.
func NormalizeGitHubActions(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)
	// Defensive: strip a `uses:` prefix if a caller passes the raw YAML
	// fragment. Real callers should pass the resolved value, but handling
	// it here keeps the detector robust.
	name = strings.TrimPrefix(name, "uses:")
	name = strings.TrimSpace(name)
	// Strip `@<ref>` version suffix.
	if at := strings.Index(name, "@"); at >= 0 {
		name = name[:at]
	}
	// Reduce composite-action subpaths to `owner/name`.
	parts := strings.SplitN(name, "/", 3)
	if len(parts) >= 2 {
		name = parts[0] + "/" + parts[1]
	}
	// Collapse the owner/name slash into `-` so reorder + delimiter
	// normalization see owner and name as siblings. See doc comment.
	name = strings.ReplaceAll(name, "/", "-")
	return name
}

// PopularGitHubActions returns the curated list of well-known GitHub
// Actions used as the "known-good" corpus for typosquat detection.
// Order is popularity-descending; rank ties are broken by alphabetic
// owner/name. The detector lowercases at lookup time via
// NormalizeGitHubActions.
//
// Refresh cadence: hand-curated, refreshed when GitHub publishes
// updated Marketplace usage data or when a new Action enters the
// top-of-funnel for typosquat targeting. See the file header for
// the sourcing rationale.
func PopularGitHubActions() []PopularPackage {
	names := []string{
		// actions/* — first-party.
		"actions/checkout",
		"actions/setup-node",
		"actions/setup-python",
		"actions/setup-go",
		"actions/setup-java",
		"actions/setup-dotnet",
		"actions/setup-ruby",
		"actions/cache",
		"actions/upload-artifact",
		"actions/download-artifact",
		"actions/github-script",
		"actions/labeler",
		"actions/stale",
		"actions/create-release",
		"actions/configure-pages",
		"actions/deploy-pages",
		"actions/upload-pages-artifact",
		"actions/first-interaction",
		"actions/dependency-review-action",
		"actions/add-to-project",
		"actions/attest-build-provenance",

		// AWS.
		"aws-actions/configure-aws-credentials",
		"aws-actions/amazon-ecr-login",
		"aws-actions/amazon-ecs-deploy-task-definition",
		"aws-actions/amazon-ecs-render-task-definition",
		"aws-actions/aws-cloudformation-github-deploy",
		"aws-actions/setup-sam",

		// Docker.
		"docker/login-action",
		"docker/build-push-action",
		"docker/setup-buildx-action",
		"docker/setup-qemu-action",
		"docker/metadata-action",
		"docker/bake-action",

		// GitHub.
		"github/codeql-action",
		"github/super-linter",
		"github/issue-labeler",

		// Microsoft / Azure.
		"microsoft/setup-msbuild",
		"microsoft/playwright-github-action",
		"azure/login",
		"azure/k8s-deploy",
		"azure/webapps-deploy",
		"azure/aks-set-context",
		"azure/arm-deploy",

		// Google.
		"google-github-actions/auth",
		"google-github-actions/setup-gcloud",
		"google-github-actions/get-gke-credentials",
		"google-github-actions/deploy-cloudrun",

		// Go.
		"golangci/golangci-lint-action",
		"goreleaser/goreleaser-action",

		// Pre-commit / release tooling.
		"pre-commit/action",
		"peaceiris/actions-gh-pages",
		"peaceiris/actions-hugo",
		"JS-DevTools/npm-publish",
		"softprops/action-gh-release",
		"ncipollo/release-action",
		"release-drafter/release-drafter",
		"semantic-release/semantic-release",

		// Common utility / quality Actions.
		"codecov/codecov-action",
		"coverallsapp/github-action",
		"reviewdog/action-eslint",
		"shogo82148/actions-goveralls",
		"crazy-max/ghaction-import-gpg",
		"sigstore/cosign-installer",
		"slsa-framework/slsa-github-generator",
		"step-security/harden-runner",
		"trufflesecurity/trufflehog",
		"gitleaks/gitleaks-action",
		"snyk/actions",
		"aquasecurity/trivy-action",
		"anchore/scan-action",

		// Test / coverage.
		"nick-fields/retry",
		"actions-rs/toolchain",
		"actions-rs/cargo",
		"dtolnay/rust-toolchain",
		"swatinem/rust-cache",
		"ruby/setup-ruby",
		"hashicorp/setup-terraform",
		"pulumi/actions",
	}

	out := make([]PopularPackage, len(names))
	for i, n := range names {
		out[i] = PopularPackage{Name: n, Rank: i}
	}
	return out
}
