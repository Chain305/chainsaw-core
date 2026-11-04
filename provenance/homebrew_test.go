package provenance

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

const hbDigest = "ef70e236f58a8a781436ee400f9bdf847ad7d12e75115871fb6a94b9214a1a41"

func newHomebrewTestChecker(t *testing.T, attestations string, id sigstoreverify.Identity, verifyErr error) (*homebrewChecker, *[]string) {
	t.Helper()
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		switch r.URL.Path {
		case "/formula/jq.json":
			_, _ = w.Write([]byte(`{"name":"jq","versions":{"stable":"1.8.2","bottle":true},
				"bottle":{"stable":{"files":{"sonoma":{"sha256":"aaaa"},"arm64_sequoia":{"sha256":"` + hbDigest + `"}}}}}`))
		case "/repos/Homebrew/homebrew-core/attestations/sha256:" + hbDigest:
			if attestations == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(attestations))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c := newHomebrewChecker(srv.Client(), nil, func() *sigstoreverify.BundleCache { return nil })
	c.apiBase, c.githubAPI = srv.URL, srv.URL
	c.verify = func(_ context.Context, _ *sigstoreverify.BundleCache, _, digest []byte) (*sigstoreverify.VerifyResult, error) {
		if verifyErr != nil {
			return nil, verifyErr
		}
		return &sigstoreverify.VerifyResult{Identity: id}, nil
	}
	return c, &asked
}

var homebrewCI = sigstoreverify.Identity{
	Issuer:    "https://token.actions.githubusercontent.com",
	BuilderID: "https://github.com/Homebrew/homebrew-core/.github/workflows/publish-commit-bottles.yml@refs/heads/main",
}

const oneAttestation = `{"attestations":[{"bundle":{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}}]}`

func TestHomebrewProvenance(t *testing.T) {
	for _, tc := range []struct {
		name         string
		version      string
		attestations string
		id           sigstoreverify.Identity
		verifyErr    error
		want         Status
		wantReason   string
	}{
		{"verified", "1.8.2", oneAttestation, homebrewCI, nil, StatusVerified, ""},
		{"no attestation", "1.8.2", "", homebrewCI, nil, StatusMissing, ReasonNoAttestationFound},
		{"bad signature", "1.8.2", oneAttestation, homebrewCI, errors.New("sigstore verify: digest mismatch"), StatusFailed, ""},
		{"trust root down", "1.8.2", oneAttestation, homebrewCI, errors.New("sigstore trust root: tuf unreachable"), StatusUnverified, ReasonTrustRootsUnavailable},
		{"other signer", "1.8.2", oneAttestation, sigstoreverify.Identity{
			Issuer:    "https://token.actions.githubusercontent.com",
			BuilderID: "https://github.com/evil/homebrew-core/.github/workflows/x.yml@refs/heads/main",
		}, nil, StatusFailed, ""},
		{"branch build", "1.8.2", oneAttestation, sigstoreverify.Identity{
			Issuer:    homebrewCI.Issuer,
			BuilderID: "https://github.com/Homebrew/homebrew-core/.github/workflows/x.yml@refs/heads/pr",
		}, nil, StatusFailed, ""},
		{"older version", "1.7.1", oneAttestation, homebrewCI, nil, StatusUnavailable, ReasonInconclusive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, asked := newHomebrewTestChecker(t, tc.attestations, tc.id, tc.verifyErr)
			got := c.Check(context.Background(), "jq", tc.version)
			if got.Status != tc.want || got.Reason != tc.wantReason {
				t.Fatalf("got %s/%q (%s), want %s/%q", got.Status, got.Reason, got.Error, tc.want, tc.wantReason)
			}
			if got.Status != StatusVerified && got.Error == "" {
				t.Error("non-verified result carries no Error")
			}
			if tc.version == "1.8.2" && got.SubjectDigest != "" && got.SubjectDigest != "sha256:"+hbDigest {
				t.Errorf("subject = %s, want the first platform in sorted order", got.SubjectDigest)
			}
			if tc.version != "1.8.2" && len(*asked) > 1 {
				t.Errorf("asked GitHub for a version Homebrew publishes no digests for: %v", *asked)
			}
		})
	}
}

func TestHomebrewTapIsNotAttested(t *testing.T) {
	c, asked := newHomebrewTestChecker(t, oneAttestation, homebrewCI, nil)
	if got := c.Check(context.Background(), "someone/tap/jq", "1.8.2"); got.Status != StatusUnavailable || len(*asked) != 0 {
		t.Fatalf("tap formula: %+v, requests %v", got, *asked)
	}
}

func TestHomebrewIsRegistered(t *testing.T) {
	if !SupportsProvenance("homebrew") {
		t.Fatal("SupportsProvenance(homebrew) = false")
	}
	c := NewChecker(nil)
	if _, ok := c.checkers["homebrew"].(*homebrewChecker); !ok {
		t.Fatal("homebrew dispatches to the wrong checker (oci.go would build homebrew/core/<f>)")
	}
}

const hbBackfillPath = "/repos/trailofbits/homebrew-brew-verify/attestations/sha256:" + hbDigest

// newHomebrewBackfillChecker serves core and backfill attestations
// separately; verify returns coreID for the core bundle and backfillID for
// the backfill one (told apart by the bundle bytes).
func newHomebrewBackfillChecker(t *testing.T, core, backfill string, coreID, backfillID sigstoreverify.Identity) (*homebrewChecker, *[]string) {
	t.Helper()
	c, asked := newHomebrewTestChecker(t, core, coreID, nil)
	inner := c.client.Transport
	c.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == hbBackfillPath {
			*asked = append(*asked, r.URL.Path)
			if backfill == "" {
				return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
			}
			rec := httptest.NewRecorder()
			_, _ = rec.WriteString(backfill)
			res := rec.Result()
			res.Request = r
			return res, nil
		}
		return inner.RoundTrip(r)
	})}
	c.verify = func(_ context.Context, _ *sigstoreverify.BundleCache, bundle, _ []byte) (*sigstoreverify.VerifyResult, error) {
		if strings.Contains(string(bundle), "backfill") {
			return &sigstoreverify.VerifyResult{Identity: backfillID}, nil
		}
		return &sigstoreverify.VerifyResult{Identity: coreID}, nil
	}
	return c, asked
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const backfillAttestation = `{"attestations":[{"bundle":{"mediaType":"backfill"}}]}`

func backfillID(signedAt time.Time) sigstoreverify.Identity {
	return sigstoreverify.Identity{
		Issuer:    "https://token.actions.githubusercontent.com",
		BuilderID: "https://github.com/trailofbits/homebrew-brew-verify/.github/workflows/backfill_signatures.yml@refs/heads/main",
		SignedAt:  signedAt,
	}
}

func TestHomebrewBackfill(t *testing.T) {
	before := time.Date(2024, 3, 8, 16, 30, 36, 0, time.UTC) // bison's real backfill integratedTime
	for _, tc := range []struct {
		name       string
		core       string
		backfill   string
		backfillID sigstoreverify.Identity
		want       Status
		wantReason string
	}{
		{"backfill before cutoff", "", backfillAttestation, backfillID(before), StatusVerified, ""},
		{"backfill on cutoff instant", "", backfillAttestation, backfillID(homebrewBackfillCutoff), StatusVerified, ""},
		{"backfill after cutoff", "", backfillAttestation, backfillID(homebrewBackfillCutoff.Add(time.Second)), StatusFailed, ""},
		{"backfill without timestamp", "", backfillAttestation, backfillID(time.Time{}), StatusFailed, ""},
		{"backfill other signer", "", backfillAttestation, sigstoreverify.Identity{
			Issuer:    "https://token.actions.githubusercontent.com",
			BuilderID: "https://github.com/trailofbits/homebrew-brew-verify-evil/.github/workflows/x.yml@refs/heads/main",
			SignedAt:  before,
		}, StatusFailed, ""},
		{"neither", "", "", backfillID(before), StatusMissing, ReasonNoAttestationFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newHomebrewBackfillChecker(t, tc.core, tc.backfill, homebrewCI, tc.backfillID)
			got := c.Check(context.Background(), "jq", "1.8.2")
			if got.Status != tc.want || got.Reason != tc.wantReason {
				t.Fatalf("got %s/%q (%s), want %s/%q", got.Status, got.Reason, got.Error, tc.want, tc.wantReason)
			}
			if got.Status == StatusVerified && got.BuilderID != tc.backfillID.BuilderID {
				t.Errorf("builder = %q, want the backfill workflow", got.BuilderID)
			}
		})
	}
}

// A core attestation that FAILS is evidence; brew falls back only when the
// core attestation is missing, and so must we.
func TestHomebrewFailedCoreDoesNotFallBack(t *testing.T) {
	evil := sigstoreverify.Identity{Issuer: homebrewCI.Issuer, BuilderID: "https://github.com/evil/x/.github/workflows/x.yml@refs/heads/main"}
	c, asked := newHomebrewBackfillChecker(t, oneAttestation, backfillAttestation, evil, backfillID(time.Date(2024, 3, 8, 0, 0, 0, 0, time.UTC)))
	if got := c.Check(context.Background(), "jq", "1.8.2"); got.Status != StatusFailed {
		t.Fatalf("got %s, want failed", got.Status)
	}
	for _, p := range *asked {
		if p == hbBackfillPath {
			t.Fatal("asked the backfill repo after a failed core attestation")
		}
	}
}
