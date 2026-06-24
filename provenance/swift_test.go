package provenance

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	swiftformat "github.com/chain305/chainsaw-core/formats/swift"
)

// metadataResponse builds a SE-0292 release metadata response in the
// shape the swiftChecker expects.
func metadataResponse(signed bool, signatureB64 string) string {
	signing := ""
	if signed {
		signing = `, "signing": {"signatureFormat": "cms-1.0.0", "signature": "` + signatureB64 + `"}`
	}
	return fmt.Sprintf(`{
		"resources": [
			{"name": "source-archive"%s}
		],
		"metadata": {"repositoryURLs": ["https://github.com/example/pkg"]}
	}`, signing)
}

func newSwiftCheckerForTest(t *testing.T, registryURL string) *swiftChecker {
	t.Helper()
	// verifier closure returns nil — presence-only mode. Verifier-
	// enabled tests construct a real Checker via NewChecker +
	// WithSwiftFullVerify, which exercises the same wiring end-to-end.
	return newSwiftChecker(
		&http.Client{Timeout: 5 * time.Second},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		func() string { return registryURL },
		func() *swiftformat.Verifier { return nil },
	)
}

// --- Tests ---

func TestSwiftChecker_NoSignatureReturnsMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(metadataResponse(false, "")))
	}))
	defer srv.Close()

	c := newSwiftCheckerForTest(t, srv.URL)
	got := c.Check(context.Background(), "scope.pkg", "1.2.3")
	if got.Status != StatusMissing {
		t.Errorf("Status = %s, want missing", got.Status)
	}
}

func TestSwiftChecker_PresenceOnlyReturnsUnverified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(metadataResponse(true, base64.StdEncoding.EncodeToString([]byte("anything")))))
	}))
	defer srv.Close()

	c := newSwiftCheckerForTest(t, srv.URL)
	got := c.Check(context.Background(), "scope.pkg", "1.2.3")
	if got.Status != StatusUnverified {
		t.Errorf("Status = %s, want unverified", got.Status)
	}
	if got.AttestationType != "cms-se0391" {
		t.Errorf("AttestationType = %q, want cms-se0391", got.AttestationType)
	}
	if got.SourceRepo != "https://github.com/example/pkg" {
		t.Errorf("SourceRepo = %q, want metadata URL", got.SourceRepo)
	}
}

func TestSwiftChecker_FullVerifyMissingArchiveFails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/scope/pkg/1.2.3", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(metadataResponse(true, base64.StdEncoding.EncodeToString([]byte("dummy-cms")))))
	})
	mux.HandleFunc("/scope/pkg/1.2.3.zip", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	checker := NewChecker(slog.New(slog.NewTextHandler(io.Discard, nil)))
	checker.WithSwiftRegistryURL(srv.URL)
	checker.WithSwiftFullVerify(x509.NewCertPool())

	got := checker.Check(context.Background(), "swift", "scope.pkg", "1.2.3")
	if got.Status != StatusFailed {
		t.Errorf("Status = %s, want failed; result = %+v", got.Status, got)
	}
	if !strings.Contains(got.Error, "archive") {
		t.Errorf("Error = %q, want it to mention archive fetch", got.Error)
	}
}

func TestSwiftChecker_FullVerifyEmptySignaturePayloadFails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/scope/pkg/1.2.3", func(w http.ResponseWriter, r *http.Request) {
		// signed=true but signature payload is empty — the registry
		// is misbehaving.
		_, _ = w.Write([]byte(metadataResponse(true, "")))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	checker := NewChecker(slog.New(slog.NewTextHandler(io.Discard, nil)))
	checker.WithSwiftRegistryURL(srv.URL)
	checker.WithSwiftFullVerify(x509.NewCertPool())

	got := checker.Check(context.Background(), "swift", "scope.pkg", "1.2.3")
	if got.Status != StatusFailed {
		t.Errorf("Status = %s, want failed", got.Status)
	}
	if !strings.Contains(got.Error, "signature payload is empty") {
		t.Errorf("Error = %q, want empty-signature message", got.Error)
	}
}

func TestSwiftChecker_FullVerifyInvalidCMSReturnsFailed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/scope/pkg/1.2.3", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(metadataResponse(true, base64.StdEncoding.EncodeToString([]byte("not-a-real-cms-envelope")))))
	})
	mux.HandleFunc("/scope/pkg/1.2.3.zip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write([]byte("PK\x03\x04not-a-real-zip"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	checker := NewChecker(slog.New(slog.NewTextHandler(io.Discard, nil)))
	checker.WithSwiftRegistryURL(srv.URL)
	checker.WithSwiftFullVerify(x509.NewCertPool())

	got := checker.Check(context.Background(), "swift", "scope.pkg", "1.2.3")
	if got.Status != StatusFailed {
		t.Errorf("Status = %s, want failed (verifier should reject malformed CMS)", got.Status)
	}
	if got.Error == "" {
		t.Errorf("Error should be populated from verifier")
	}
}

func TestSwiftChecker_NoRegistryURLReturnsUnavailable(t *testing.T) {
	c := newSwiftCheckerForTest(t, "")
	got := c.Check(context.Background(), "scope.pkg", "1.2.3")
	if got.Status != StatusUnavailable {
		t.Errorf("Status = %s, want unavailable", got.Status)
	}
}
