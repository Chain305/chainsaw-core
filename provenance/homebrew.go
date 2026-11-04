package provenance

// Homebrew bottle provenance.
//
// homebrew-core's CI publishes a GitHub artifact attestation (Sigstore bundle,
// SLSA v1) for every bottle, keyed by the bottle's sha256 under
// GET api.github.com/repos/Homebrew/homebrew-core/attestations/sha256:<d>.
// brew itself checks it with `gh attestation verify --repo
// Homebrew/homebrew-core` (HOMEBREW_VERIFY_ATTESTATIONS), i.e. any workflow
// of that repository: bottles are signed from several of them
// (publish-commit-bottles.yml on 2026-11-04 for jq, dispatch-build-bottle.yml
// and dispatch-rebottle.yml per brew's attestation.rb). So the identity
// pinned here is the repository on refs/heads/main via GitHub's OIDC issuer,
// not one workflow file.
//
// The bottle digests come from the formula document for the CURRENT
// pkg_version only — Homebrew publishes no other — so an older version is
// inconclusive, never failed.
//
// One attestation covers every bottle of a publish run (its in-toto subjects
// list them all), so verifying one declared digest proves the run; the
// digest checked is the first platform in sorted order, deterministically.
//
// Bottles last built before 2024-03-14 have no homebrew-core attestation, only
// the trailofbits/homebrew-brew-verify backfill; brew falls back to it, and so
// does this checker (13 of 150 sampled current bottles on 2026-11-04 needed it,
// all 13 had one).

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/homebrew"
	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

const (
	homebrewCoreRepo        = "Homebrew/homebrew-core"
	homebrewBuilderPrefix   = "https://github.com/Homebrew/homebrew-core/.github/workflows/"
	homebrewBuilderRef      = "@refs/heads/main"
	githubActionsOIDCIssuer = "https://token.actions.githubusercontent.com"

	// brew's Homebrew::Attestation::BACKFILL_REPO / BACKFILL_CUTOFF.
	homebrewBackfillRepo   = "trailofbits/homebrew-brew-verify"
	homebrewBackfillPrefix = "https://github.com/trailofbits/homebrew-brew-verify/.github/workflows/"
)

var homebrewBackfillCutoff = time.Date(2024, 3, 14, 0, 0, 0, 0, time.UTC)

type homebrewChecker struct {
	client    *http.Client
	logger    *slog.Logger
	apiBase   string // Homebrew JSON API; empty → homebrew.ConfiguredAPIBase()
	githubAPI string // empty → https://api.github.com
	cacheFor  func() *sigstoreverify.BundleCache
	// verify is the Sigstore step; tests replace it.
	verify func(ctx context.Context, cache *sigstoreverify.BundleCache, bundle, digest []byte) (*sigstoreverify.VerifyResult, error)
}

func newHomebrewChecker(client *http.Client, logger *slog.Logger, cacheFor func() *sigstoreverify.BundleCache) *homebrewChecker {
	return &homebrewChecker{client: client, logger: logger, cacheFor: cacheFor, verify: runSigstoreVerify}
}

func (c *homebrewChecker) Ecosystem() string { return homebrew.Ecosystem }

func (c *homebrewChecker) result(status Status, reason, msg string) Result {
	return Result{Status: status, Ecosystem: homebrew.Ecosystem, Reason: reason, Error: msg}
}

func (c *homebrewChecker) Check(ctx context.Context, packageName, version string) Result {
	name := homebrew.NormalizeName(packageName)
	if homebrew.IsThirdPartyTapName(name) {
		return c.result(StatusUnavailable, ReasonEcosystemNoStandard,
			"third-party tap bottles are not attested by "+homebrewCoreRepo)
	}
	apiBase := c.apiBase
	if apiBase == "" {
		apiBase = homebrew.ConfiguredAPIBase()
	}
	f, err := homebrew.FetchFormula(ctx, c.client, apiBase, name)
	if errors.Is(err, homebrew.ErrNotFound) {
		return c.result(StatusUnavailable, ReasonInconclusive, fmt.Sprintf("%s is not a homebrew/core formula", name))
	}
	if err != nil {
		return c.result(StatusUnavailable, ReasonUpstreamError, "read formula: "+err.Error())
	}
	if pv := f.PkgVersion(); version != pv {
		return c.result(StatusUnavailable, ReasonInconclusive,
			fmt.Sprintf("Homebrew publishes bottle digests for the current version %s only, not %s", pv, version))
	}
	digest := firstBottleDigest(f)
	if digest == "" {
		return c.result(StatusUnavailable, ReasonInconclusive, name+" "+version+" has no bottles to attest")
	}
	digestBytes, err := hex.DecodeString(digest)
	if err != nil || len(digestBytes) != 32 {
		return c.result(StatusUnavailable, ReasonInconclusive, "formula declares a malformed bottle sha256")
	}

	r, found := c.attest(ctx, homebrewCoreRepo, digest, digestBytes, homebrewIdentityErr)
	if found {
		return r
	}
	// No homebrew-core attestation: bottles last built before 2024-03-14 carry
	// only the trailofbits backfill, which brew accepts (attestation.rb
	// check_core_attestation) when its verified timestamp is before the cutoff.
	if r, found := c.attest(ctx, homebrewBackfillRepo, digest, digestBytes, homebrewBackfillErr); found {
		return r
	}
	return c.result(StatusMissing, ReasonNoAttestationFound,
		"no "+homebrewCoreRepo+" or "+homebrewBackfillRepo+" attestation for bottle sha256:"+digest)
}

// attest fetches repo's attestations for digest and returns the first bundle
// that verifies and that accept passes. found is false only when the repo
// holds no attestation for the digest (404 or an empty list); every other
// outcome, including an upstream error, is a final answer.
func (c *homebrewChecker) attest(ctx context.Context, repo, digest string, digestBytes []byte, accept func(sigstoreverify.Identity) error) (Result, bool) {
	githubAPI := c.githubAPI
	if githubAPI == "" {
		githubAPI = "https://api.github.com"
	}
	apiURL := fmt.Sprintf("%s/repos/%s/attestations/sha256:%s", strings.TrimRight(githubAPI, "/"), repo, digest)
	body, status, err := fetchBytesBearer(ctx, c.client, apiURL, 10<<20, strings.TrimSpace(os.Getenv("CHAINSAW_GITHUB_TOKEN")))
	switch {
	case err == nil:
	case isNotFound(status):
		return Result{}, false
	case status == http.StatusTooManyRequests || status == http.StatusForbidden:
		return c.result(StatusUnavailable, ReasonRateLimited, "GitHub attestations API: "+err.Error()), true
	default:
		return c.result(StatusUnavailable, ReasonUpstreamError, "GitHub attestations API: "+err.Error()), true
	}
	var wrap struct {
		Attestations []struct {
			Bundle json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return c.result(StatusUnverified, ReasonAttestationUnparseable, "parse attestations response: "+err.Error()), true
	}
	if len(wrap.Attestations) == 0 {
		return Result{}, false
	}

	// Several bundles may bind the digest (a rebottle re-attests); the first
	// that verifies AND passes accept wins.
	var lastErr error
	for _, a := range wrap.Attestations {
		bundle := []byte(a.Bundle)
		vr, err := c.verify(ctx, c.cacheFor(), bundle, digestBytes)
		if err != nil {
			if strings.HasPrefix(err.Error(), "sigstore trust root:") {
				// Could not check at all — not evidence of tampering.
				r := c.result(StatusUnverified, ReasonTrustRootsUnavailable, err.Error())
				noteUnverifiedBundle(&r, bundle, "")
				return r, true
			}
			lastErr = err
			continue
		}
		if err := accept(vr.Identity); err != nil {
			lastErr = err
			continue
		}
		r := Result{Status: StatusVerified, Ecosystem: homebrew.Ecosystem}
		applySigstoreToResult(&r, vr, bundle)
		r.SubjectDigest = "sha256:" + digest
		return r, true
	}
	failed := c.result(StatusFailed, "", lastErr.Error())
	failed.AttestationType = "sigstore"
	failed.SubjectDigest = "sha256:" + digest
	return failed, true
}

// homebrewIdentityErr pins the signer to homebrew-core's own workflows on main.
func homebrewIdentityErr(id sigstoreverify.Identity) error {
	if id.Issuer == githubActionsOIDCIssuer &&
		strings.HasPrefix(id.BuilderID, homebrewBuilderPrefix) &&
		strings.HasSuffix(id.BuilderID, homebrewBuilderRef) {
		return nil
	}
	return fmt.Errorf("signed by %q (issuer %q), not %s CI on main", id.BuilderID, id.Issuer, homebrewCoreRepo)
}

// homebrewBackfillErr accepts a backfill bundle the way brew does: signed by
// any workflow of the backfill repository (it signed from both 'main' and
// 'backfill'), with a verified timestamp no later than the cutoff — a
// compromise of that repository after the cutoff cannot mint a valid one.
func homebrewBackfillErr(id sigstoreverify.Identity) error {
	if id.Issuer != githubActionsOIDCIssuer || !strings.HasPrefix(id.BuilderID, homebrewBackfillPrefix) {
		return fmt.Errorf("signed by %q (issuer %q), not %s", id.BuilderID, id.Issuer, homebrewBackfillRepo)
	}
	if id.SignedAt.IsZero() {
		return errors.New("backfill attestation is missing a verified timestamp")
	}
	if id.SignedAt.After(homebrewBackfillCutoff) {
		return fmt.Errorf("backfill attestation signed %s, after the %s cutoff",
			id.SignedAt.Format(time.RFC3339), homebrewBackfillCutoff.Format("2006-01-02"))
	}
	return nil
}

func firstBottleDigest(f *homebrew.Formula) string {
	plats := make([]string, 0, len(f.Bottle.Stable.Files))
	for p := range f.Bottle.Stable.Files {
		plats = append(plats, p)
	}
	sort.Strings(plats)
	for _, p := range plats {
		if d := strings.ToLower(strings.TrimSpace(f.Bottle.Stable.Files[p].SHA256)); d != "" {
			return d
		}
	}
	return ""
}
