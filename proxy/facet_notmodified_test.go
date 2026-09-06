package proxy

import (
	"context"
	"net/http"
	"testing"

	"github.com/chain305/chainsaw-core/storage"
)

// TestHandleUpstreamStatusNeverStoresA304 pins that a 304 short-circuits
// rather than falling through to storeUpstream.
//
// A 304 Not Modified carries an empty body. handleUpstreamStatus used to
// return (false, nil) for it — "a success that still needs to be stored"
// — because its only branches were 404, >=500 and >=400. storeUpstream
// would then have written those zero bytes over the cached packument.
//
// This is unreachable today (stripConditionalHeaders removes the client's
// conditional headers and the proxy sends none of its own), so the test
// guards a latent landmine rather than a live bug. It exists because the
// obvious next step for the metadata-freshness work is to add
// If-None-Match from the stored meta.ETag, and that change would detonate
// this the first time upstream answered 304.
//
// Verified by deletion: removing the StatusNotModified branch from
// handleUpstreamStatus makes this test fail with handled=false.
func TestHandleUpstreamStatusNeverStoresA304(t *testing.T) {
	f := &facet{}

	handled, resp := f.handleUpstreamStatus(
		context.Background(),
		"lodash",
		"npm/lodash",
		&http.Response{StatusCode: http.StatusNotModified, Header: http.Header{}},
	)

	if !handled {
		t.Fatal("304 was not short-circuited: it would fall through to storeUpstream " +
			"and overwrite the cached body with the empty 304 payload")
	}
	if resp == nil {
		t.Fatal("304 handled but no response returned")
	}
	if resp.StatusCode != http.StatusNotModified {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusNotModified)
	}
}

// TestHandleUpstreamStatusStillStores200 is the negative control: an
// ordinary success must keep falling through to storeUpstream, so a
// failure above is attributable to the 304 branch and not to the
// short-circuit having swallowed everything.
func TestHandleUpstreamStatusStillStores200(t *testing.T) {
	f := &facet{}

	handled, resp := f.handleUpstreamStatus(
		context.Background(),
		"lodash",
		"npm/lodash",
		&http.Response{StatusCode: http.StatusOK, Header: http.Header{}},
	)

	if handled {
		t.Fatalf("200 was short-circuited (resp=%+v); it must reach storeUpstream", resp)
	}
}

// TestIdentityEncodingTerminatesTheRepairLoop pins the fix for the
// permanent cache-miss loop on pip simple-index pages.
//
// needsEncodingRepair forces a cache MISS whenever a "simple*" path has
// an empty ContentEncoding, so that entries cached before the encoding
// was captured get re-fetched once. But storeUpstream wrote the upstream
// header back verbatim, so an identity-encoded page stored an empty
// encoding again and missed again — forever, with no caching at all.
//
// Recording "identity" ends the loop after one repair.
func TestIdentityEncodingTerminatesTheRepairLoop(t *testing.T) {
	// A legacy entry with no recorded encoding is repaired once.
	legacy := storage.ContentMetadata{
		LogicalPath:     "simple/requests/",
		ContentType:     "text/html; charset=utf-8",
		ContentEncoding: "",
	}
	if !needsEncodingRepair(legacy) {
		t.Fatal("a simple-index entry with no recorded encoding must be repaired")
	}

	// After the repair fetch, an upstream that sent no Content-Encoding
	// must leave the entry in a state that does NOT repair again.
	repaired := legacy
	repaired.ContentEncoding = recordedContentEncoding("")
	if repaired.ContentEncoding == "" {
		t.Fatal("recordedContentEncoding returned empty; the loop would continue")
	}
	if needsEncodingRepair(repaired) {
		t.Fatal("entry still wants repair after a store: permanent re-fetch loop")
	}

	// A real encoding is preserved verbatim.
	if got := recordedContentEncoding("gzip"); got != "gzip" {
		t.Errorf("recordedContentEncoding(\"gzip\") = %q, want \"gzip\"", got)
	}
}

// TestIdentityEncodingIsNeverServed pins that the internal marker stays
// internal. RFC 7231 §3.1.2.2 says identity must not appear in a
// Content-Encoding header, and a client seeing one may reject the body.
func TestIdentityEncodingIsNeverServed(t *testing.T) {
	h := headersFromMetadata(storage.ContentMetadata{
		ContentType:     "text/html",
		ContentEncoding: encodingIdentity,
	})
	if got := h.Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want it absent", got)
	}

	// Negative control: a real encoding is still served.
	h = headersFromMetadata(storage.ContentMetadata{ContentEncoding: "gzip"})
	if got := h.Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding = %q, want \"gzip\"", got)
	}
}
