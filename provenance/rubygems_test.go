package provenance

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestExtractRubyGemsAttestation(t *testing.T) {
	inlineRaw := []byte("fake-bundle-bytes")
	inlineB64 := base64.StdEncoding.EncodeToString(inlineRaw)

	cases := []struct {
		name       string
		body       map[string]any
		wantURL    string
		wantInline []byte
		wantSHA256 string
	}{
		{
			name: "attestations array with URL",
			body: map[string]any{
				"sha": "abcdef0123456789",
				"attestations": []any{
					map[string]any{"url": "https://rubygems.org/api/v1/attestations/foo-1.0.0.bundle"},
				},
			},
			wantURL:    "https://rubygems.org/api/v1/attestations/foo-1.0.0.bundle",
			wantSHA256: "abcdef0123456789",
		},
		{
			name: "no attestation",
			body: map[string]any{
				"sha": "deadbeef",
			},
			wantSHA256: "deadbeef",
		},
		{
			name: "attestation_url single field",
			body: map[string]any{
				"attestation_url": "https://example.com/b",
			},
			wantURL: "https://example.com/b",
		},
		{
			name: "inline base64 bundle",
			body: map[string]any{
				"sha": "cafebabe",
				"attestations": []any{
					map[string]any{"bundle": inlineB64},
				},
			},
			wantInline: inlineRaw,
			wantSHA256: "cafebabe",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, inline, sha := extractRubyGemsAttestation(tc.body)
			if u != tc.wantURL {
				t.Errorf("URL: got %q, want %q", u, tc.wantURL)
			}
			if !bytes.Equal(inline, tc.wantInline) {
				t.Errorf("inline: got %q, want %q", inline, tc.wantInline)
			}
			if sha != tc.wantSHA256 {
				t.Errorf("SHA256: got %q, want %q", sha, tc.wantSHA256)
			}
		})
	}
}

func TestStatusFromErr(t *testing.T) {
	cases := []struct {
		err  string
		want int
	}{
		{"404 not found", 404},
		{"HTTP 500", 500},
		{"HTTP 200", 200},
		{"other", 0},
	}
	for _, c := range cases {
		got := statusFromErr(testErr(c.err))
		if got != c.want {
			t.Errorf("statusFromErr(%q) = %d, want %d", c.err, got, c.want)
		}
	}
}

type testErr string

func (e testErr) Error() string { return string(e) }
