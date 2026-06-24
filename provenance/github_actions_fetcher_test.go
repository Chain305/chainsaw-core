package provenance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testDigest = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

func TestGitHubAPIFetcher_Fetch_OK(t *testing.T) {
	bundle := json.RawMessage(`{"bundle":"abc"}`)
	body, _ := json.Marshal(githubAttestationsResponse{
		Attestations: []struct {
			Bundle json.RawMessage `json:"bundle"`
		}{{Bundle: bundle}},
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantPath := fmt.Sprintf("/repos/actions/checkout/attestations/sha256:%s", testDigest)
		if r.URL.Path != wantPath {
			t.Errorf("unexpected path: got %q want %q", r.URL.Path, wantPath)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer testtoken" {
			t.Errorf("Authorization header: got %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
			t.Errorf("Accept header: got %q", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	f := NewGitHubAPIFetcher(srv.Client(), "testtoken")
	f.BaseURL = srv.URL

	gotBundle, gotDigest, err := f.Fetch(context.Background(), "actions", "checkout", testDigest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotDigest != testDigest {
		t.Fatalf("digest: got %q want %q", gotDigest, testDigest)
	}
	if !strings.Contains(string(gotBundle), "abc") {
		t.Fatalf("bundle bytes do not contain expected content: %s", gotBundle)
	}
}

func TestGitHubAPIFetcher_Fetch_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	f := NewGitHubAPIFetcher(srv.Client(), "")
	f.BaseURL = srv.URL

	_, _, err := f.Fetch(context.Background(), "actions", "checkout", testDigest)
	if !errors.Is(err, ErrNoAttestation) {
		t.Fatalf("want ErrNoAttestation, got %v", err)
	}
}

func TestGitHubAPIFetcher_Fetch_Malformed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{not json"))
	}))
	defer srv.Close()

	f := NewGitHubAPIFetcher(srv.Client(), "")
	f.BaseURL = srv.URL

	_, _, err := f.Fetch(context.Background(), "actions", "checkout", testDigest)
	if err == nil {
		t.Fatalf("expected parse error, got nil")
	}
	if !strings.Contains(err.Error(), "parse response") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestGitHubAPIFetcher_Fetch_EmptyAttestations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"attestations":[]}`))
	}))
	defer srv.Close()

	f := NewGitHubAPIFetcher(srv.Client(), "")
	f.BaseURL = srv.URL

	_, _, err := f.Fetch(context.Background(), "actions", "checkout", testDigest)
	if !errors.Is(err, ErrNoAttestation) {
		t.Fatalf("want ErrNoAttestation, got %v", err)
	}
}

func TestGitHubAPIFetcher_Fetch_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := NewGitHubAPIFetcher(srv.Client(), "")
	f.BaseURL = srv.URL

	_, _, err := f.Fetch(context.Background(), "actions", "checkout", testDigest)
	if err == nil {
		t.Fatalf("expected error on 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected 500 in error, got %v", err)
	}
}

func TestGitHubAPIFetcher_Fetch_BadDigest(t *testing.T) {
	f := NewGitHubAPIFetcher(nil, "")
	_, _, err := f.Fetch(context.Background(), "actions", "checkout", "v4.0.0")
	if err == nil {
		t.Fatalf("expected error for non-sha256 ref")
	}
	if !strings.Contains(err.Error(), "hex sha256") {
		t.Fatalf("expected hex sha256 error, got %v", err)
	}
}
