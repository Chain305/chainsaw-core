package intelligence

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRegistryTruncationIsNotReportedAsADecodeError pins the distinction
// between "their document is malformed" and "our ceiling cut it short".
//
// io.LimitedReader signals exhaustion with io.EOF mid-document, which
// json.Decode reports as a parse error indistinguishable from genuine
// malformation. Collapsing the two is how an 8 MiB cap became eleven
// "upstream coverage misses" on @solana/web3.js — a package
// registry.npmjs.org serves at 11.4 MB — in the corpus study. The row said
// `unknown` with "the registry returned a document we could not parse",
// and the registry had done nothing wrong.
func TestRegistryTruncationIsNotReportedAsADecodeError(t *testing.T) {
	// One byte past the ceiling: valid JSON that cannot arrive whole.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"name":"huge","pad":"`)
		chunk := strings.Repeat("x", 1<<20)
		for written := 0; written <= registryMaxBodyBytes; written += len(chunk) {
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
		}
		_, _ = io.WriteString(w, `"}`)
	}))
	defer srv.Close()

	p := &registryMetadataProvider{
		client: srv.Client(),
		now:    func() time.Time { return time.Unix(0, 0).UTC() },
	}
	var out map[string]any
	warn, _, _, err := p.fetchOnce(context.Background(), srv.URL, "application/json",
		func(r io.Reader) error { return json.NewDecoder(r).Decode(&out) })

	if err == nil || warn == nil {
		t.Fatal("an over-ceiling body must not be reported as success")
	}
	if warn.Code == WarnRegistryDecode {
		t.Fatalf("truncation at our own %d-byte ceiling was reported as %q, "+
			"which reads as a malformed upstream document. That attribution is "+
			"what filed 11 @solana/web3.js rows as coverage misses.",
			registryMaxBodyBytes, warn.Code)
	}
	if warn.Code != WarnRegistryBodyTooLarge {
		t.Errorf("code = %q, want %q", warn.Code, WarnRegistryBodyTooLarge)
	}
	if !strings.Contains(warn.Message, "our limit") {
		t.Errorf("the message must say whose limit it is, got %q", warn.Message)
	}
}

// TestRegistryCeilingClearsARealPackument — the cap must actually admit the
// document that motivated raising it. A ceiling that still truncates
// @solana/web3.js would pass the test above while fixing nothing.
func TestRegistryCeilingClearsARealPackument(t *testing.T) {
	const solanaWeb3JSBytes = 11_993_809 // measured against registry.npmjs.org, 2026-09-16
	if registryMaxBodyBytes <= solanaWeb3JSBytes {
		t.Fatalf("registryMaxBodyBytes = %d does not admit @solana/web3.js at %d bytes; "+
			"the 11 rows this was raised for would still come back unknown",
			registryMaxBodyBytes, solanaWeb3JSBytes)
	}
}

// TestRegistryGenuineMalformationStillDecodes — the other direction. A short,
// genuinely broken body must still be a decode error, or the new code just
// launders upstream defects.
func TestRegistryGenuineMalformationStillDecodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"name": not-json}`)
	}))
	defer srv.Close()

	p := &registryMetadataProvider{client: srv.Client(), now: func() time.Time { return time.Unix(0, 0).UTC() }}
	var out map[string]any
	warn, _, _, err := p.fetchOnce(context.Background(), srv.URL, "application/json",
		func(r io.Reader) error { return json.NewDecoder(r).Decode(&out) })
	if err == nil || warn == nil {
		t.Fatal("malformed JSON must be an error")
	}
	if warn.Code != WarnRegistryDecode {
		t.Errorf("a genuinely malformed body must stay %q, got %q", WarnRegistryDecode, warn.Code)
	}
}
