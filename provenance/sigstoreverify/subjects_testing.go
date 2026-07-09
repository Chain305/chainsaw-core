package sigstoreverify

// This file is named *_testing.go (not *_test.go) so it ships in the
// regular package surface and is importable from other packages' tests
// (notably the provenance package's huggingface manifest tests). It builds
// SYNTHETIC, UNSIGNED Sigstore bundles that are structurally valid enough
// for the parse/subject-extraction path (BundleSubjects). They carry no real
// signature or trust chain, so they must NEVER be fed to Verify with an
// expectation of success — they exist purely to exercise manifest parsing
// and the caller's subject-driven logic offline.

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"google.golang.org/protobuf/encoding/protojson"
)

// TestSubject describes one file to embed as an in-toto subject in a
// synthetic model-signing bundle. If WithSHA256 is true the subject carries
// the sha256 of Bytes; otherwise it carries an (invalid) subject with no
// sha256 digest, to exercise the "no anchorable subject" guard.
type TestSubject struct {
	Name       string
	Bytes      []byte
	WithSHA256 bool
}

// NewModelSigningBundleForTesting builds a structurally-valid, UNSIGNED
// Sigstore bundle whose DSSE payload is an in-toto statement listing the
// given subjects. For offline tests only.
func NewModelSigningBundleForTesting(t *testing.T, subjects []TestSubject) []byte {
	if t == nil {
		panic("NewModelSigningBundleForTesting requires a *testing.T")
	}

	var parts []string
	for _, s := range subjects {
		digest := ""
		if s.WithSHA256 {
			sum := sha256.Sum256(s.Bytes)
			digest = `"sha256":"` + hex.EncodeToString(sum[:]) + `"`
		}
		parts = append(parts, `{"name":"`+s.Name+`","digest":{`+digest+`}}`)
	}
	statement := `{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[` + strings.Join(parts, ",") + `],` +
		`"predicateType":"https://model_signing/signature/v1.0",` +
		`"predicate":{}` +
		`}`

	env := &protodsse.Envelope{
		Payload:     []byte(statement),
		PayloadType: "application/vnd.in-toto+json",
		Signatures:  []*protodsse.Signature{{Sig: []byte("not-a-real-sig")}},
	}
	b := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{Hint: "test"},
			},
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: env},
	}
	out, err := protojson.Marshal(b)
	if err != nil {
		t.Fatalf("marshal synthetic bundle: %v", err)
	}
	return out
}
