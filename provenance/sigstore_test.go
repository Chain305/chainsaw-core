package provenance

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

func makeBundle(t *testing.T, payload any, tlogIndex int64) []byte {
	t.Helper()
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]any{
		"dsseEnvelope": map[string]any{
			"payload":     base64.StdEncoding.EncodeToString(rawPayload),
			"payloadType": "application/vnd.in-toto+json",
		},
	}
	if tlogIndex > 0 {
		env["verificationMaterial"] = map[string]any{
			"tlogEntries": []any{
				map[string]any{"logIndex": tlogIndex, "logId": "abcd"},
			},
		}
	}
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestExtractInTotoStatement(t *testing.T) {
	bundle := makeBundle(t, map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []any{
			map[string]any{
				"name":   "pkg:npm/foo@1.0.0",
				"digest": map[string]any{"sha256": strings.Repeat("ab", 32)},
			},
		},
		"predicate": map[string]any{
			"builder": map[string]any{"id": "https://github.com/slsa-framework/slsa-github-generator"},
		},
	}, 12345)

	stmt, env, err := extractInTotoStatement(bundle)
	if err != nil {
		t.Fatalf("extractInTotoStatement: %v", err)
	}
	if stmt.PredicateType != "https://slsa.dev/provenance/v1" {
		t.Errorf("predicateType = %q", stmt.PredicateType)
	}
	if got := transparencyLogURL(env); !strings.Contains(got, "12345") {
		t.Errorf("transparency log URL = %q", got)
	}
}

func TestSubjectSHA256(t *testing.T) {
	want := strings.Repeat("ab", 32)
	stmt := &inTotoStatement{
		Subject: []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		}{{Digest: map[string]string{"sha256": want}}},
	}
	got, err := subjectSHA256(stmt)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != want {
		t.Errorf("got %x want %s", got, want)
	}

	if _, err := subjectSHA256(&inTotoStatement{}); err == nil {
		t.Error("empty subject: want error")
	}
}

func TestSLSALevelFromPredicate(t *testing.T) {
	cases := []struct {
		name      string
		predType  string
		predicate map[string]any
		want      int
	}{
		{
			name:     "v1 hosted github generator → L3",
			predType: "https://slsa.dev/provenance/v1",
			predicate: map[string]any{
				"builder":         map[string]any{"id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1"},
				"buildDefinition": map[string]any{},
			},
			want: 3,
		},
		{
			name:     "v1 with builder + buildDefinition → L2",
			predType: "https://slsa.dev/provenance/v1",
			predicate: map[string]any{
				"builder":         map[string]any{"id": "https://example.com/builder"},
				"buildDefinition": map[string]any{},
			},
			want: 2,
		},
		{
			name:      "v1 without buildDefinition → L1",
			predType:  "https://slsa.dev/provenance/v1",
			predicate: map[string]any{"builder": map[string]any{"id": "https://example.com/b"}},
			want:      1,
		},
		{
			name:      "v0.2 with builder.id → L2",
			predType:  "https://slsa.dev/provenance/v0.2",
			predicate: map[string]any{"builder": map[string]any{"id": "https://example.com/b"}},
			want:      2,
		},
		{
			name:      "v0.2 no builder.id → L1",
			predType:  "https://slsa.dev/provenance/v0.2",
			predicate: map[string]any{},
			want:      1,
		},
		{
			name:      "unknown predicate type → 0",
			predType:  "https://example.com/other",
			predicate: map[string]any{},
			want:      0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := slsaLevelFromPredicate(tc.predType, tc.predicate)
			if got != tc.want {
				t.Errorf("got %d want %d", got, tc.want)
			}
		})
	}
}

func TestSourceCommitFromPredicate(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]any
		want string
	}{
		{
			name: "v1 resolvedDependencies gitCommit",
			in: map[string]any{
				"buildDefinition": map[string]any{
					"resolvedDependencies": []any{
						map[string]any{
							"digest": map[string]any{"gitCommit": "deadbeef"},
						},
					},
				},
			},
			want: "deadbeef",
		},
		{
			name: "v0.2 materials gitCommit",
			in: map[string]any{
				"materials": []any{
					map[string]any{
						"digest": map[string]any{"gitCommit": "cafef00d"},
					},
				},
			},
			want: "cafef00d",
		},
		{
			name: "fallback to sha1 in materials",
			in: map[string]any{
				"materials": []any{
					map[string]any{"digest": map[string]any{"sha1": "abc"}},
				},
			},
			want: "abc",
		},
		{name: "nothing", in: map[string]any{}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sourceCommitFromPredicate(tc.in)
			if got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestApplySigstoreToResultPopulatesSLSAFields(t *testing.T) {
	bundle := makeBundle(t, map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []any{
			map[string]any{"digest": map[string]any{"sha256": strings.Repeat("aa", 32)}},
		},
		"predicate": map[string]any{
			"builder":         map[string]any{"id": "https://github.com/slsa-framework/slsa-github-generator"},
			"buildDefinition": map[string]any{"resolvedDependencies": []any{map[string]any{"digest": map[string]any{"gitCommit": "feedface"}}}},
		},
	}, 99)

	r := &Result{Status: StatusVerified, Ecosystem: "npm"}
	vr := &sigstoreverify.VerifyResult{
		Identity: sigstoreverify.Identity{
			SourceRepo: "https://github.com/foo/bar",
			BuilderID:  "https://github.com/foo/bar/.github/workflows/release.yml",
			Issuer:     "https://token.actions.githubusercontent.com",
		},
		VerifiedAt: time.Now(),
	}
	applySigstoreToResult(r, vr, bundle)

	if r.SLSALevel != 3 {
		t.Errorf("SLSALevel = %d, want 3", r.SLSALevel)
	}
	if r.SourceCommit != "feedface" {
		t.Errorf("SourceCommit = %q", r.SourceCommit)
	}
	if !strings.HasPrefix(r.SubjectDigest, "sha256:") {
		t.Errorf("SubjectDigest = %q", r.SubjectDigest)
	}
	if r.SourceRepo != "https://github.com/foo/bar" {
		t.Errorf("SourceRepo = %q", r.SourceRepo)
	}
	if !strings.Contains(r.TransparencyLogURL, "99") {
		t.Errorf("TransparencyLogURL = %q", r.TransparencyLogURL)
	}
	if r.BundleFormat != "sigstore-bundle" {
		t.Errorf("BundleFormat = %q", r.BundleFormat)
	}
	if len(r.AttestationBundle) == 0 {
		t.Error("AttestationBundle empty")
	}
}

func TestApplySigstoreToResultStaleAddsWarning(t *testing.T) {
	bundle := makeBundle(t, map[string]any{
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject":       []any{},
		"predicate":     map[string]any{},
	}, 0)
	r := &Result{}
	vr := &sigstoreverify.VerifyResult{
		Identity:   sigstoreverify.Identity{SourceRepo: "https://x/y"},
		VerifiedAt: time.Now(),
		CacheStale: true,
	}
	applySigstoreToResult(r, vr, bundle)
	if !r.CacheStale {
		t.Error("CacheStale not propagated")
	}
	if len(r.Warnings) == 0 {
		t.Error("expected stale warning")
	}
}
