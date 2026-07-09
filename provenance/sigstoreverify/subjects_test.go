package sigstoreverify

import (
	"crypto/sha256"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestBundleSubjectsParsesInlineStatement(t *testing.T) {
	files := map[string][]byte{
		"model.safetensors": []byte("weights-bytes"),
		"config.json":       []byte(`{"hidden":1}`),
	}
	var ts []TestSubject
	for name, body := range files {
		ts = append(ts, TestSubject{Name: name, Bytes: body, WithSHA256: true})
	}
	bundleJSON := NewModelSigningBundleForTesting(t, ts)

	subs, err := BundleSubjects(bundleJSON)
	if err != nil {
		t.Fatalf("BundleSubjects: %v", err)
	}
	if len(subs) != len(files) {
		t.Fatalf("want %d subjects, got %d", len(files), len(subs))
	}
	for _, s := range subs {
		want, ok := files[s.Name]
		if !ok {
			t.Errorf("unexpected subject %q", s.Name)
			continue
		}
		sum := sha256.Sum256(want)
		if len(s.SHA256) != 32 || string(s.SHA256) != string(sum[:]) {
			t.Errorf("subject %q: digest mismatch", s.Name)
		}
	}
}

func TestBundleSubjectsOmitsSubjectWithoutSHA256(t *testing.T) {
	bundleJSON := NewModelSigningBundleForTesting(t, []TestSubject{
		{Name: "no-digest.bin", WithSHA256: false},
	})
	subs, err := BundleSubjects(bundleJSON)
	if err != nil {
		t.Fatalf("BundleSubjects: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("want 1 subject, got %d", len(subs))
	}
	if subs[0].SHA256 != nil {
		t.Errorf("want nil SHA256 for digest-less subject, got %x", subs[0].SHA256)
	}
}

func TestBundleSubjectsRejectsNonBundle(t *testing.T) {
	if _, err := BundleSubjects([]byte("not-a-bundle")); err == nil {
		t.Fatal("want error for malformed bundle, got nil")
	}
}

func TestBundleSubjectsRejectsMessageSignatureBundle(t *testing.T) {
	// A message-signature bundle (no DSSE envelope) has no in-toto statement
	// to walk — BundleSubjects must error rather than return zero subjects.
	b := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{Hint: "test"},
			},
		},
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    make([]byte, 32),
				},
				Signature: []byte("sig"),
			},
		},
	}
	raw, err := protojson.Marshal(b)
	if err != nil {
		t.Fatalf("marshal message-signature bundle: %v", err)
	}
	if _, err := BundleSubjects(raw); err == nil {
		t.Fatal("want error for message-signature bundle, got nil")
	}
}
