package provenance

// The 26 huggingface attestation failures in the production corpus, 2026-09-24.
// Two unrelated causes, and neither is a verification failure:
//
//	21x HTTP 401 — a repository we cannot SEE. HF answers private, deleted and
//	     gated repos with 401 rather than 404 so existence is not disclosed.
//	     Nearly all of these are QA fixtures (t-est/hf-model-*) that do not
//	     exist upstream.
//	 5x HTTP 307 — a SAME-HOST repo rename. HF moved its canonical legacy
//	     models under organisations: /api/models/gpt2 ->
//	     /api/models/openai-community/gpt2, bert-base-uncased -> google-bert/…,
//	     t5-base -> google-t5/… . All five corpus failures are those models.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The checker must follow HF's own redirects. Without this, every canonical
// legacy model reports a failed attestation forever.
func TestHuggingFaceCheckerFollowsSameHostRenames(t *testing.T) {
	base := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	c := newHuggingFaceChecker(base, nil)
	if c.client == nil || c.client.CheckRedirect == nil {
		t.Fatal("huggingface checker has no redirect policy")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://huggingface.co/api/models/openai-community/gpt2", nil)
	if err := c.client.CheckRedirect(req, nil); err != nil {
		t.Errorf("the checker refuses HF's own rename redirect (%v); gpt2, bert-base-uncased and "+
			"t5-base all 307 to their org-qualified paths, so provenance stays broken for the "+
			"canonical models", err)
	}
	// The narrowing must survive: an unlisted host is still refused.
	other, _ := http.NewRequest(http.MethodGet, "https://example.com/x", nil)
	if err := c.client.CheckRedirect(other, nil); err != http.ErrUseLastResponse {
		t.Errorf("the checker followed a hop to an unlisted host (err=%v) — a provenance fetch "+
			"must not become an open proxy", err)
	}
}

// A repository we cannot see is not a repository whose provenance failed. The
// two need opposite responses: one is "chase the signature", the other is
// "we were never shown the model".
func TestHuggingFaceUnseeableRepoIsUnavailableNotFailed(t *testing.T) {
	srv := newStatusServer(t, http.StatusUnauthorized)
	defer srv.Close()

	c := newHuggingFaceChecker(srv.Client(), nil)
	c.baseURL = srv.URL

	got := c.Check(t.Context(), "t-est/hf-model-20260403192202", "v0.0.192202")
	if got.Status == StatusFailed {
		t.Errorf("a 401 reported StatusFailed; HF answers private, removed and gated repos with "+
			"401 rather than 404, so this reads as a provenance failure for a model we never "+
			"saw. result=%+v", got)
	}
	if got.Status != StatusUnavailable {
		t.Errorf("Status = %q, want %q", got.Status, StatusUnavailable)
	}
	if got.Reason == "" {
		t.Error("no Reason set — Status alone conflates this with 'the ecosystem publishes nothing'")
	}
}

// newStatusServer answers every request with one status and an empty body.
func newStatusServer(t *testing.T, code int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
	}))
}
