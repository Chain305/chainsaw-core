package provenance

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
)

// pypiChecker queries the PyPI attestation API (PEP 740) for Sigstore
// bundles.
type pypiChecker struct {
	client *http.Client
	logger *slog.Logger
}

func newPyPIChecker(client *http.Client, logger *slog.Logger) *pypiChecker {
	return &pypiChecker{client: client, logger: logger}
}

func (c *pypiChecker) Ecosystem() string { return "pip" }

func (c *pypiChecker) Check(ctx context.Context, packageName, version string) Result {
	encodedPkg := url.PathEscape(packageName)
	encodedVer := url.PathEscape(version)
	reqURL := fmt.Sprintf("https://pypi.org/integrity/%s/%s/", encodedPkg, encodedVer)

	// Same rule as npm.go: the "no attestation" verdict is decided by the
	// HTTP status code, not by whether the error string happens to contain
	// "404". A package literally named `404` used to satisfy that sniff.
	_, status, err := fetchJSONStatus(ctx, c.client, reqURL)
	if err != nil {
		if isNotFound(status) {
			return Result{Status: StatusMissing, Ecosystem: "pip"}
		}
		return Result{Status: StatusFailed, Ecosystem: "pip", Error: err.Error()}
	}

	// Attestation exists but we don't cryptographically verify the Sigstore
	// bundle yet — that requires the shared sigstore helper.
	return Result{
		Status:          StatusUnverified,
		Ecosystem:       "pip",
		AttestationType: "sigstore",
	}
}
