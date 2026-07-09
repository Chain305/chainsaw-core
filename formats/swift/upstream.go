package swift

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/chain305/chainsaw-core/formats/common"
)

// CompositeRoundTripper implements http.RoundTripper by trying a
// configured upstream SE-0292 registry first and falling back to a
// GitUpstream that synthesizes SE-0292 responses from git remotes.
//
// The fallback is only triggered on 404 responses (or when no registry
// is configured). 5xx responses from the registry are returned to the
// caller unchanged — operators should fix their upstream rather than
// get silently-different answers from git.
//
// Register this as the Transport on the http.Client handed to
// proxy.Facet for a Swift-format repository.
type CompositeRoundTripper struct {
	// Registry is the SE-0292 upstream transport. May be nil when the
	// user configured only git translation.
	Registry http.RoundTripper
	// RegistryBase is the absolute base URL of the SE-0292 registry.
	// Required when Registry is set.
	RegistryBase *url.URL
	// Git synthesizes responses from github.com tags. May be nil when
	// the user requires every package to live on a real registry.
	Git *GitUpstream
}

// RoundTrip implements http.RoundTripper.
func (c *CompositeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// 1) Try the configured registry upstream.
	if c.Registry != nil && c.RegistryBase != nil {
		resp, err := c.Registry.RoundTrip(req)
		if err == nil && resp != nil {
			if resp.StatusCode != http.StatusNotFound || c.Git == nil {
				return resp, nil
			}
			// 404 from registry: drain and try git fallback.
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		} else if err != nil && c.Git == nil {
			return nil, err
		}
	}

	// 2) Git fallback.
	if c.Git == nil {
		return syntheticErrorResponse(req, http.StatusNotFound, "not found"), nil
	}
	return c.serveFromGit(req)
}

// serveFromGit translates an SPM request URL into the appropriate
// GitUpstream call and returns a synthetic http.Response.
func (c *CompositeRoundTripper) serveFromGit(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	path := strings.Trim(req.URL.Path, "/")

	// /identifiers?url=<git>: reverse lookup via the identifier map.
	if strings.EqualFold(path, "identifiers") {
		gitURL := req.URL.Query().Get("url")
		id, ok := c.Git.Map.ReverseLookup(gitURL)
		if !ok {
			return syntheticErrorResponse(req, http.StatusNotFound, "no identifier for url"), nil
		}
		body, _ := json.Marshal(map[string]any{"identifiers": []string{id}})
		return syntheticJSONResponse(req, http.StatusOK, body), nil
	}

	segments := common.SplitPathSegments(path)
	switch {
	case len(segments) == 2:
		// /{scope}/{name} — list releases
		id := NormalizeIdentifier(segments[0], segments[1])
		releases, err := c.Git.ListReleases(ctx, id, proxyPrefixFromRequest(req))
		if errors.Is(err, ErrNotFound) {
			return syntheticErrorResponse(req, http.StatusNotFound, "unknown package"), nil
		}
		if err != nil {
			return syntheticErrorResponse(req, http.StatusBadGateway, err.Error()), nil
		}
		body, _ := json.Marshal(releases)
		return syntheticJSONResponse(req, http.StatusOK, body), nil

	case len(segments) == 3 && strings.HasSuffix(segments[2], ".zip"):
		// /{scope}/{name}/{version}.zip — source archive
		id := NormalizeIdentifier(segments[0], segments[1])
		version := strings.TrimSuffix(segments[2], ".zip")
		zipBytes, digest, err := c.Git.BuildArchive(ctx, id, version)
		if errors.Is(err, ErrNotFound) {
			return syntheticErrorResponse(req, http.StatusNotFound, "unknown version"), nil
		}
		if err != nil {
			return syntheticErrorResponse(req, http.StatusBadGateway, err.Error()), nil
		}
		return syntheticZipResponse(req, zipBytes, digest), nil

	case len(segments) == 3:
		// /{scope}/{name}/{version} — release metadata
		id := NormalizeIdentifier(segments[0], segments[1])
		meta, err := c.Git.GetReleaseMetadata(ctx, id, segments[2], proxyPrefixFromRequest(req))
		if errors.Is(err, ErrNotFound) {
			return syntheticErrorResponse(req, http.StatusNotFound, "unknown version"), nil
		}
		if err != nil {
			return syntheticErrorResponse(req, http.StatusBadGateway, err.Error()), nil
		}
		body, _ := json.Marshal(meta)
		return syntheticJSONResponse(req, http.StatusOK, body), nil

	case len(segments) == 4 && strings.EqualFold(segments[3], "Package.swift"):
		// /{scope}/{name}/{version}/Package.swift — manifest
		id := NormalizeIdentifier(segments[0], segments[1])
		swiftVer := req.URL.Query().Get("swift-version")
		manifest, err := c.Git.FetchManifest(ctx, id, segments[2], swiftVer)
		if errors.Is(err, ErrNotFound) {
			return syntheticErrorResponse(req, http.StatusNotFound, "manifest not found"), nil
		}
		if err != nil {
			return syntheticErrorResponse(req, http.StatusBadGateway, err.Error()), nil
		}
		return syntheticManifestResponse(req, manifest), nil
	}

	return syntheticErrorResponse(req, http.StatusNotFound, "unrecognized path"), nil
}

// proxyPrefixFromRequest extracts a URL prefix that subsequent SPM
// requests can use to continue routing through the proxy. When the
// request is served behind chainsaw, the path includes the
// `/repository/<repo>` prefix before the SE-0292 path begins — we
// surface an empty prefix here and let the response transformer
// rewrite absolute URLs once the facet emits them.
func proxyPrefixFromRequest(req *http.Request) string {
	// The git upstream's URL synthesis treats the prefix as optional —
	// absolute URLs are rewritten again by the response transformer
	// when they leave the facet. Returning an empty string keeps the
	// synthetic responses self-contained and lets the transformer do
	// its job.
	return ""
}

func syntheticJSONResponse(req *http.Request, status int, body []byte) *http.Response {
	h := make(http.Header)
	h.Set("Content-Type", "application/vnd.swift.registry.v1+json")
	h.Set("Content-Version", "1")
	h.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return &http.Response{
		StatusCode:    status,
		Header:        h,
		Body:          io.NopCloser(bytes.NewReader(body)),
		Request:       req,
		ContentLength: int64(len(body)),
		Proto:         "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
	}
}

func syntheticZipResponse(req *http.Request, body []byte, digest string) *http.Response {
	h := make(http.Header)
	h.Set("Content-Type", "application/zip")
	h.Set("Content-Version", "1")
	h.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	if digest != "" {
		h.Set("Digest", "sha-256="+digest)
	}
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        h,
		Body:          io.NopCloser(bytes.NewReader(body)),
		Request:       req,
		ContentLength: int64(len(body)),
		Proto:         "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
	}
}

func syntheticManifestResponse(req *http.Request, body []byte) *http.Response {
	h := make(http.Header)
	h.Set("Content-Type", "text/x-swift")
	h.Set("Content-Version", "1")
	h.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        h,
		Body:          io.NopCloser(bytes.NewReader(body)),
		Request:       req,
		ContentLength: int64(len(body)),
		Proto:         "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
	}
}

func syntheticErrorResponse(req *http.Request, status int, detail string) *http.Response {
	body, _ := json.Marshal(map[string]any{
		"status": status,
		"detail": detail,
	})
	h := make(http.Header)
	h.Set("Content-Type", "application/problem+json")
	h.Set("Content-Version", "1")
	h.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return &http.Response{
		StatusCode:    status,
		Header:        h,
		Body:          io.NopCloser(bytes.NewReader(body)),
		Request:       req,
		ContentLength: int64(len(body)),
		Proto:         "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
	}
}

// compile-time assertion
var _ http.RoundTripper = (*CompositeRoundTripper)(nil)

// errContextCancelled is returned when the request context is cancelled
// mid-git-operation.
var errContextCancelled = errors.New("swift upstream: context cancelled")

// discardBody drains and closes a response body. Exposed for tests.
func discardBody(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// Ensure ctx is still sane before we start an expensive git op.
func ctxAlive(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return errContextCancelled
	default:
		return nil
	}
}
