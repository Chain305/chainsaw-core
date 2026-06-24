package provenance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHuggingFaceSigstoreReportsIdentityOnly asserts the new honest-degrade
// path: when a model.sig sidecar is present but cannot be cryptographically
// verified (no manifest fetch), we report StatusUnverified with a clear
// error message rather than the pre-fix behavior of StatusUnverified with
// a misleading digest-mismatch error (or, worse, false-positive verified).
func TestHuggingFaceSigstoreReportsIdentityOnly(t *testing.T) {
	// A deliberately malformed bundle — InspectBundleIdentity should fail
	// cleanly with StatusFailed and a parse-error message. The key
	// assertion is that we no longer try to Verify() and no longer return
	// a digest-mismatch error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/model.sig") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not-a-real-bundle"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newHuggingFaceChecker(srv.Client(), nil)
	c.baseURL = srv.URL

	got := c.Check(context.Background(), "org/model", "main")
	if got.Status != StatusFailed {
		t.Errorf("malformed bundle: want StatusFailed, got %+v", got)
	}
	if got.AttestationType != "sigstore" {
		t.Errorf("malformed bundle: want AttestationType=sigstore, got %q", got.AttestationType)
	}
	if !strings.Contains(got.Error, "inspect bundle") {
		t.Errorf("malformed bundle: want error mentioning 'inspect bundle', got %q", got.Error)
	}
	if strings.Contains(got.Error, "digest mismatch") {
		t.Errorf("must not regress to digest-mismatch error path: %q", got.Error)
	}
}

func TestHuggingFaceFallsBackToCommitSig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/model.sig") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if strings.Contains(r.URL.Path, "/api/models/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"gpg_verified":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newHuggingFaceChecker(srv.Client(), nil)
	c.baseURL = srv.URL

	got := c.Check(context.Background(), "org/model", "main")
	if got.Status != StatusUnverified {
		t.Errorf("commit-sig path: want StatusUnverified, got %+v", got)
	}
	if got.AttestationType != "pgp-commit" {
		t.Errorf("commit-sig path: want AttestationType=pgp-commit, got %q", got.AttestationType)
	}
}

// TestHuggingFaceDistinguishesNetworkFromMissing asserts C1: a 5xx on the
// commits API is surfaced as StatusFailed (network/server error), not
// StatusMissing (no signal), so operators can tell them apart.
func TestHuggingFaceDistinguishesNetworkFromMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/model.sig") {
			w.WriteHeader(http.StatusNotFound) // absent → fall back to commit-sig
			return
		}
		if strings.Contains(r.URL.Path, "/api/models/") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newHuggingFaceChecker(srv.Client(), nil)
	c.baseURL = srv.URL

	got := c.Check(context.Background(), "org/model", "main")
	if got.Status != StatusFailed {
		t.Errorf("5xx on commits API: want StatusFailed, got %+v", got)
	}
}

func TestHuggingFaceMissingEverywhereIsMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newHuggingFaceChecker(srv.Client(), nil)
	c.baseURL = srv.URL

	got := c.Check(context.Background(), "org/model", "main")
	if got.Status != StatusMissing {
		t.Errorf("no signals anywhere: want StatusMissing, got %+v", got)
	}
}
