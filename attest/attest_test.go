package attest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/sbom"
)

// ---------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------

// stubSigner records exactly what it was asked to sign so tests can
// assert the signature covers the PAE and not the raw statement or the
// base64 payload. It performs no crypto — key material never belongs in
// this package, in tests or otherwise.
type stubSigner struct {
	sig    []byte
	keyID  string
	err    error
	seen   [][]byte // every payload handed to Sign, in order
	callCt int
}

func (s *stubSigner) Sign(_ context.Context, payload []byte) ([]byte, string, error) {
	s.callCt++
	s.seen = append(s.seen, append([]byte(nil), payload...))
	if s.err != nil {
		return nil, "", s.err
	}
	return s.sig, s.keyID, nil
}

// ---------------------------------------------------------------------
// Golden fixtures — HAND-WRITTEN. Do not regenerate these from the
// implementation; their whole value is being an independent statement of
// what the bytes must be.
// ---------------------------------------------------------------------

const goldenSHA256 = "ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34"
const goldenSHA1 = "0123456789abcdef0123456789abcdef01234567"

// goldenStatement is the exact canonical JSON BuildStatement must emit
// for goldenSubject + goldenVSA. Note the digest map is sorted
// ("sha1" < "sha256") and the predicate fields follow the SLSA v1 order.
const goldenStatement = `{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"pkg:oci/nginx","digest":{"sha1":"0123456789abcdef0123456789abcdef01234567","sha256":"ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34"}}],"predicateType":"https://slsa.dev/verification_summary/v1","predicate":{"verifier":{"id":"https://chain305.com/chainsaw@v0.21.23"},"timeVerified":"2026-09-11T12:34:56Z","resourceUri":"pkg:oci/nginx","policy":{"uri":"https://chain305.com/policy/default","annotations":{"chainsaw.dev/policyVersion":"v7"}},"verificationResult":"PASSED","verifiedLevels":["SLSA_BUILD_LEVEL_0"]}}`

// goldenStatementLen and goldenPAELen were counted by hand (wc -c on the
// literal above), NOT taken from a test run. They pin the ASCII decimal
// lengths PAE embeds: an off-by-one in either is a signature nothing can
// verify.
const goldenStatementLen = 592

// goldenPAE is the Pre-Authentication Encoding of goldenStatement,
// assembled by hand from the DSSE v1 rule:
//
//	"DSSEv1" SP len("application/vnd.in-toto+json")=28 SP
//	<type> SP len(body)=592 SP <body>
const goldenPAE = "DSSEv1 28 application/vnd.in-toto+json 592 " + goldenStatement

// 6 + 1 + 2 + 1 + 28 + 1 + 3 + 1 + 592
const goldenPAELen = 635

func goldenSubject() Subject {
	return Subject{
		Name: "pkg:oci/nginx",
		Digest: map[string]string{
			"sha256": goldenSHA256,
			"sha1":   goldenSHA1,
		},
	}
}

func goldenVSA() VSA {
	return VSA{
		Verifier: "https://chain305.com/chainsaw@v0.21.23",
		// Sub-second component is deliberately non-zero: the golden
		// timestamp proves it is dropped, not rendered.
		TimeVerified:       time.Date(2026, 9, 11, 12, 34, 56, 789_000_000, time.UTC),
		ResourceURI:        "pkg:oci/nginx",
		PolicyURI:          "https://chain305.com/policy/default",
		PolicyVersion:      "v7",
		VerificationResult: ResultPassed,
		VerifiedLevels:     []string{"SLSA_BUILD_LEVEL_0"},
	}
}

// ---------------------------------------------------------------------
// Golden bytes
// ---------------------------------------------------------------------

func TestGoldenFixtureLengthsAreSelfConsistent(t *testing.T) {
	// Guards the hand-counted constants above against a careless edit
	// of the literal. If this fails, the literal changed and the
	// lengths (and therefore goldenPAE) must be re-counted by hand.
	if len(goldenStatement) != goldenStatementLen {
		t.Fatalf("goldenStatement is %d bytes, hand-counted constant says %d", len(goldenStatement), goldenStatementLen)
	}
	if len(goldenPAE) != goldenPAELen {
		t.Fatalf("goldenPAE is %d bytes, hand-counted constant says %d", len(goldenPAE), goldenPAELen)
	}
	if len(PayloadType) != 28 {
		t.Fatalf("PayloadType is %d bytes, golden PAE hard-codes 28", len(PayloadType))
	}
}

func TestBuildStatementGoldenBytes(t *testing.T) {
	got, err := BuildStatement(goldenSubject(), goldenVSA())
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	if string(got) != goldenStatement {
		t.Errorf("statement bytes differ\n got: %s\nwant: %s", got, goldenStatement)
	}
}

func TestPAEGoldenBytes(t *testing.T) {
	stmt, err := BuildStatement(goldenSubject(), goldenVSA())
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	got := pae(PayloadType, stmt)
	if string(got) != goldenPAE {
		t.Errorf("PAE bytes differ\n got: %q\nwant: %q", got, goldenPAE)
	}
}

// TestPAEVectors covers the encoding independently of the statement:
// empty inputs, a non-in-toto type, and a multi-byte body that proves
// len() is a BYTE count, not a rune count.
func TestPAEVectors(t *testing.T) {
	tests := []struct {
		name        string
		payloadType string
		body        string
		want        string
	}{
		{
			name:        "empty type and body",
			payloadType: "",
			body:        "",
			want:        "DSSEv1 0  0 ",
		},
		{
			name:        "dsse spec shaped vector",
			payloadType: "http://example.com/HelloWorld",
			body:        "hello world",
			want:        "DSSEv1 29 http://example.com/HelloWorld 11 hello world",
		},
		{
			name:        "multibyte body counts bytes not runes",
			payloadType: "application/vnd.in-toto+json",
			// 9 runes, 10 bytes: é is two bytes in UTF-8.
			body: `{"a":"é"}`,
			want: `DSSEv1 28 application/vnd.in-toto+json 10 {"a":"é"}`,
		},
		{
			name:        "body containing spaces is not re-delimited",
			payloadType: "t",
			body:        "a b c",
			want:        "DSSEv1 1 t 5 a b c",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := string(pae(tc.payloadType, []byte(tc.body)))
			if got != tc.want {
				t.Errorf("pae() = %q, want %q", got, tc.want)
			}
			// Every separator is exactly one ASCII space, and there
			// are exactly four of them before the body starts.
			if !strings.HasPrefix(got, "DSSEv1 ") {
				t.Errorf("pae() does not start with %q: %q", "DSSEv1 ", got)
			}
		})
	}
}

// ---------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------

func TestBuildStatementDeterministic(t *testing.T) {
	// Enough map entries that Go's randomised map iteration would
	// reliably produce a different order between two calls if the
	// serialiser did not sort.
	subj := Subject{
		Name: "pkg:npm/lodash@4.17.21",
		Digest: map[string]string{
			"sha1":   goldenSHA1,
			"sha256": goldenSHA256,
			"sha384": strings.Repeat("c0ffee", 16),
			"sha512": strings.Repeat("ab12cd34", 16),
		},
	}
	v := goldenVSA()
	v.DependencyLevels = map[string]int{
		"SLSA_BUILD_LEVEL_3": 3,
		"SLSA_BUILD_LEVEL_2": 2,
		"SLSA_BUILD_LEVEL_1": 1,
		"SLSA_BUILD_LEVEL_0": 0,
	}
	v.InputAttestations = []Subject{
		{Name: "https://upstream/att-b", Digest: map[string]string{"sha256": goldenSHA256}},
		{Name: "https://upstream/att-a", Digest: map[string]string{"sha256": goldenSHA256}},
	}

	first, err := BuildStatement(subj, v)
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := BuildStatement(subj, v)
		if err != nil {
			t.Fatalf("BuildStatement (run %d): %v", i, err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("run %d differs\n got: %s\nwant: %s", i, again, first)
		}
	}

	// Sorted-ness is the mechanism, so assert it directly rather than
	// only via equality (two identically-wrong runs would pass above).
	s := string(first)
	for _, pair := range [][2]string{
		{`"sha1"`, `"sha256"`},
		{`"sha256"`, `"sha384"`},
		{`"sha384"`, `"sha512"`},
		{`"SLSA_BUILD_LEVEL_0":0`, `"SLSA_BUILD_LEVEL_1":1`},
		{`"SLSA_BUILD_LEVEL_2":2`, `"SLSA_BUILD_LEVEL_3":3`},
	} {
		if strings.Index(s, pair[0]) > strings.Index(s, pair[1]) {
			t.Errorf("map keys not sorted: %s appears after %s", pair[0], pair[1])
		}
	}
	// InputAttestations is a SLICE, so caller order is preserved — it
	// is an ordered list of what we consumed, not a set.
	if strings.Index(s, "att-b") > strings.Index(s, "att-a") {
		t.Errorf("inputAttestations were reordered; slice order must be preserved")
	}
}

func TestTimeVerifiedNormalisedToUTCSeconds(t *testing.T) {
	loc := time.FixedZone("UTC+5", 5*3600)
	v := goldenVSA()
	// 17:34:56.789 +05:00 is 12:34:56 UTC — the same instant as the
	// golden timestamp, so the bytes must be identical.
	v.TimeVerified = time.Date(2026, 9, 11, 17, 34, 56, 789_000_000, loc)

	got, err := BuildStatement(goldenSubject(), v)
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	if string(got) != goldenStatement {
		t.Errorf("non-UTC input did not normalise\n got: %s\nwant: %s", got, goldenStatement)
	}
	if strings.Contains(string(got), ".789") {
		t.Errorf("sub-second precision leaked into timeVerified: %s", got)
	}
}

// ---------------------------------------------------------------------
// Interop with the existing in-toto READ paths
// ---------------------------------------------------------------------

// TestStatementParsesWithCoreSBOMReader proves the write path produces
// something core/sbom's existing in-toto reader can parse. That reader
// is what `chainsaw sbom verify` uses; if our Statement did not fit it,
// every downstream consumer in the tree would need a second parser.
func TestStatementParsesWithCoreSBOMReader(t *testing.T) {
	raw, err := BuildStatement(goldenSubject(), goldenVSA())
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}

	var stmt sbom.InTotoStatement
	if err := json.Unmarshal(raw, &stmt); err != nil {
		t.Fatalf("sbom.InTotoStatement could not parse our statement: %v", err)
	}
	if stmt.Type != "https://in-toto.io/Statement/v1" {
		t.Errorf("_type = %q, want the in-toto v1 statement type", stmt.Type)
	}
	if stmt.PredicateType != PredicateTypeVSA {
		t.Errorf("predicateType = %q, want %q", stmt.PredicateType, PredicateTypeVSA)
	}
	if len(stmt.Subject) != 1 {
		t.Fatalf("subject count = %d, want 1", len(stmt.Subject))
	}
	if stmt.Subject[0].Name != "pkg:oci/nginx" {
		t.Errorf("subject name = %q", stmt.Subject[0].Name)
	}
	if got := stmt.Subject[0].Digest["sha256"]; got != goldenSHA256 {
		t.Errorf("subject sha256 = %q, want %q", got, goldenSHA256)
	}
	// The reader's predicate is json.RawMessage; confirm it is a real
	// VSA body and not, say, an empty object.
	var pred struct {
		Verifier struct {
			ID string `json:"id"`
		} `json:"verifier"`
		TimeVerified       string `json:"timeVerified"`
		ResourceURI        string `json:"resourceUri"`
		VerificationResult string `json:"verificationResult"`
	}
	if err := json.Unmarshal(stmt.Predicate, &pred); err != nil {
		t.Fatalf("parse predicate: %v", err)
	}
	if pred.Verifier.ID == "" || pred.TimeVerified == "" || pred.ResourceURI == "" || pred.VerificationResult != "PASSED" {
		t.Errorf("predicate did not round-trip: %+v", pred)
	}
}

// TestNeverEmitsProvenancePredicate is the A1 guardrail as a test: no
// input may steer the predicate type towards SLSA Provenance.
func TestNeverEmitsProvenancePredicate(t *testing.T) {
	if PredicateTypeVSA != "https://slsa.dev/verification_summary/v1" {
		t.Fatalf("predicate type changed to %q", PredicateTypeVSA)
	}
	v := goldenVSA()
	v.VerifiedLevels = []string{"SLSA_BUILD_LEVEL_3"}
	raw, err := BuildStatement(goldenSubject(), v)
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	if strings.Contains(string(raw), "slsa.dev/provenance") {
		t.Errorf("statement mentions a provenance predicate: %s", raw)
	}
	if !strings.Contains(string(raw), `"predicateType":"https://slsa.dev/verification_summary/v1"`) {
		t.Errorf("statement does not carry the VSA predicate type: %s", raw)
	}
}

// ---------------------------------------------------------------------
// Validation — every rejection has a test
// ---------------------------------------------------------------------

func TestBuildStatementRejects(t *testing.T) {
	tests := []struct {
		name    string
		subject Subject
		mutate  func(*VSA)
		wantErr string
	}{
		// --- Subject digest shape (requirement 4) ---
		{
			name:    "nil digest map",
			subject: Subject{Name: "pkg:oci/nginx"},
			wantErr: "empty digest map",
		},
		{
			name:    "empty digest map",
			subject: Subject{Name: "pkg:oci/nginx", Digest: map[string]string{}},
			wantErr: "empty digest map",
		},
		{
			name:    "empty digest value",
			subject: Subject{Digest: map[string]string{"sha256": ""}},
			wantErr: `digest "sha256" is empty`,
		},
		{
			name:    "empty algorithm key",
			subject: Subject{Digest: map[string]string{"": goldenSHA256}},
			wantErr: "empty algorithm key",
		},
		{
			name:    "non-hex digest",
			subject: Subject{Digest: map[string]string{"sha256": strings.Repeat("z", 64)}},
			wantErr: "not lowercase hex",
		},
		{
			name:    "uppercase hex digest",
			subject: Subject{Digest: map[string]string{"sha256": strings.ToUpper(goldenSHA256)}},
			wantErr: "not lowercase hex",
		},
		{
			name:    "algorithm-prefixed digest value",
			subject: Subject{Digest: map[string]string{"sha256": "sha256:" + goldenSHA256}},
			wantErr: "carries an algorithm prefix",
		},
		{
			name:    "sha256 too short",
			subject: Subject{Digest: map[string]string{"sha256": goldenSHA256[:63]}},
			wantErr: "has 63 hex chars, want 64",
		},
		{
			name:    "sha256 too long",
			subject: Subject{Digest: map[string]string{"sha256": goldenSHA256 + "ab"}},
			wantErr: "has 66 hex chars, want 64",
		},
		{
			name:    "sha512 at sha256 length",
			subject: Subject{Digest: map[string]string{"sha512": goldenSHA256}},
			wantErr: "has 64 hex chars, want 128",
		},
		{
			name:    "unknown algorithm with odd hex length",
			subject: Subject{Digest: map[string]string{"blake3": "abc"}},
			wantErr: "odd hex length",
		},

		// --- Predicate required fields (requirements 4 and 5) ---
		{
			name:    "empty verifier",
			mutate:  func(v *VSA) { v.Verifier = "" },
			wantErr: "empty verifier",
		},
		{
			name:    "empty resource uri",
			mutate:  func(v *VSA) { v.ResourceURI = "" },
			wantErr: "empty resource uri",
		},
		{
			name:    "empty policy uri",
			mutate:  func(v *VSA) { v.PolicyURI = "" },
			wantErr: "empty policy uri",
		},
		{
			name:    "empty policy version",
			mutate:  func(v *VSA) { v.PolicyVersion = "" },
			wantErr: "empty policy version",
		},
		{
			name:    "empty verification result",
			mutate:  func(v *VSA) { v.VerificationResult = "" },
			wantErr: "empty verification result",
		},
		{
			name:    "bogus verification result",
			mutate:  func(v *VSA) { v.VerificationResult = Result("MAYBE") },
			wantErr: `is not PASSED or FAILED`,
		},
		{
			name:    "lowercase verification result",
			mutate:  func(v *VSA) { v.VerificationResult = Result("passed") },
			wantErr: `is not PASSED or FAILED`,
		},
		{
			name:    "zero time verified",
			mutate:  func(v *VSA) { v.TimeVerified = time.Time{} },
			wantErr: "zero time verified",
		},

		// --- Input attestations are validated like subjects ---
		{
			name: "input attestation with no digest",
			mutate: func(v *VSA) {
				v.InputAttestations = []Subject{{Name: "https://upstream/att"}}
			},
			wantErr: "input attestation 0 has an empty digest map",
		},
		{
			name: "input attestation with bad digest",
			mutate: func(v *VSA) {
				v.InputAttestations = []Subject{
					{Name: "ok", Digest: map[string]string{"sha256": goldenSHA256}},
					{Name: "bad", Digest: map[string]string{"sha256": "nope"}},
				}
			},
			wantErr: "input attestation 1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			subj := tc.subject
			if subj.Digest == nil && subj.Name == "" {
				subj = goldenSubject()
			}
			v := goldenVSA()
			if tc.mutate != nil {
				tc.mutate(&v)
			}
			got, err := BuildStatement(subj, v)
			if err == nil {
				t.Fatalf("BuildStatement accepted invalid input, emitted: %s", got)
			}
			if got != nil {
				t.Errorf("BuildStatement returned %d bytes alongside an error; it must emit nothing", len(got))
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestBuildStatementAccepts(t *testing.T) {
	tests := []struct {
		name    string
		subject Subject
		mutate  func(*VSA)
		want    string // substring that must appear
	}{
		{
			name:   "failed result is a valid attestation",
			mutate: func(v *VSA) { v.VerificationResult = ResultFailed },
			want:   `"verificationResult":"FAILED"`,
		},
		{
			name:   "empty verified levels emits an array not null",
			mutate: func(v *VSA) { v.VerifiedLevels = nil },
			want:   `"verifiedLevels":[]`,
		},
		{
			name:   "hex policy version becomes a sha256 digest",
			mutate: func(v *VSA) { v.PolicyVersion = goldenSHA256 },
			want:   `"policy":{"uri":"https://chain305.com/policy/default","digest":{"sha256":"` + goldenSHA256 + `"}}`,
		},
		{
			name:   "opaque policy version becomes an annotation",
			mutate: func(v *VSA) { v.PolicyVersion = "2026-09-11.3" },
			want:   `"annotations":{"chainsaw.dev/policyVersion":"2026-09-11.3"}`,
		},
		{
			name:    "empty subject name is allowed; verifiers key off the digest",
			subject: Subject{Digest: map[string]string{"sha256": goldenSHA256}},
			want:    `"subject":[{"digest":{"sha256":"` + goldenSHA256 + `"}}]`,
		},
		{
			// An unknown algorithm still rides along, but it can no
			// longer be the ONLY binding — subjectDescriptor requires at
			// least one strong digest, so the sha256 here is load-bearing
			// rather than incidental.
			name: "unknown algorithm with even hex length is carried through",
			subject: Subject{Name: "x", Digest: map[string]string{
				"blake3": strings.Repeat("ab", 32),
				"sha256": strings.Repeat("cd", 32),
			}},
			want: `"blake3"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			subj := tc.subject
			if subj.Digest == nil {
				subj = goldenSubject()
			}
			v := goldenVSA()
			if tc.mutate != nil {
				tc.mutate(&v)
			}
			got, err := BuildStatement(subj, v)
			if err != nil {
				t.Fatalf("BuildStatement: %v", err)
			}
			if !strings.Contains(string(got), tc.want) {
				t.Errorf("statement missing %q:\n%s", tc.want, got)
			}
		})
	}
}

// TestBuildStatementDoesNotAliasCallerDigest guards against a caller
// mutating the map after we validated it.
func TestBuildStatementDoesNotAliasCallerDigest(t *testing.T) {
	subj := goldenSubject()
	first, err := BuildStatement(subj, goldenVSA())
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	subj.Digest["sha256"] = strings.Repeat("f", 64)
	if !bytes.Equal(first, []byte(goldenStatement)) {
		t.Errorf("emitted bytes changed after the caller mutated its map")
	}
}

// ---------------------------------------------------------------------
// Sign / DSSE envelope
// ---------------------------------------------------------------------

func TestSignEnvelope(t *testing.T) {
	s := &stubSigner{sig: []byte{0x01, 0x02, 0x03, 0xff}, keyID: "awskms:///alias/chainsaw"}
	env, err := Sign(context.Background(), s, goldenSubject(), goldenVSA())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if env.PayloadType != "application/vnd.in-toto+json" {
		t.Errorf("payloadType = %q", env.PayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("payload is not standard base64: %v", err)
	}
	if string(payload) != goldenStatement {
		t.Errorf("payload decodes to\n%s\nwant\n%s", payload, goldenStatement)
	}
	if len(env.Signatures) != 1 {
		t.Fatalf("signature count = %d, want 1", len(env.Signatures))
	}
	if env.Signatures[0].KeyID != "awskms:///alias/chainsaw" {
		t.Errorf("keyid = %q", env.Signatures[0].KeyID)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("sig is not standard base64: %v", err)
	}
	if !bytes.Equal(sig, s.sig) {
		t.Errorf("sig = %x, want %x", sig, s.sig)
	}

	// THE point of the test: the signer saw the PAE, not the raw
	// statement and not the base64 payload.
	if s.callCt != 1 {
		t.Fatalf("signer called %d times, want 1", s.callCt)
	}
	if string(s.seen[0]) != goldenPAE {
		t.Errorf("signer saw\n%q\nwant\n%q", s.seen[0], goldenPAE)
	}
	if string(s.seen[0]) == goldenStatement {
		t.Error("signer was handed the raw statement instead of the PAE")
	}
	if string(s.seen[0]) == env.Payload {
		t.Error("signer was handed the base64 payload instead of the PAE")
	}
}

func TestSignEnvelopeJSONShape(t *testing.T) {
	s := &stubSigner{sig: []byte("sig")}
	env, err := Sign(context.Background(), s, goldenSubject(), goldenVSA())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	// A DSSE envelope with no keyid must omit the field, not emit "".
	if strings.Contains(string(raw), `"keyid"`) {
		t.Errorf("empty keyid was emitted: %s", raw)
	}
	for _, want := range []string{`"payloadType":"application/vnd.in-toto+json"`, `"payload":"`, `"signatures":[`, `"sig":"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("envelope JSON missing %s: %s", want, raw)
		}
	}
}

func TestSignRejects(t *testing.T) {
	valid := goldenVSA()

	t.Run("nil signer", func(t *testing.T) {
		if _, err := Sign(context.Background(), nil, goldenSubject(), valid); err == nil {
			t.Fatal("Sign accepted a nil signer")
		}
	})

	t.Run("invalid vsa never reaches the signer", func(t *testing.T) {
		s := &stubSigner{sig: []byte("sig")}
		bad := valid
		bad.TimeVerified = time.Time{}
		if _, err := Sign(context.Background(), s, goldenSubject(), bad); err == nil {
			t.Fatal("Sign accepted a VSA with no timeVerified")
		}
		if s.callCt != 0 {
			t.Errorf("signer was invoked %d times for an invalid VSA; there must be no sign-anyway path", s.callCt)
		}
	})

	t.Run("signer error propagates", func(t *testing.T) {
		want := errors.New("kms unavailable")
		s := &stubSigner{err: want}
		_, err := Sign(context.Background(), s, goldenSubject(), valid)
		if err == nil {
			t.Fatal("Sign swallowed the signer error")
		}
		if !errors.Is(err, want) {
			t.Errorf("error %v does not wrap %v", err, want)
		}
	})

	t.Run("empty signature is refused", func(t *testing.T) {
		s := &stubSigner{sig: nil, keyID: "k"}
		if _, err := Sign(context.Background(), s, goldenSubject(), valid); err == nil {
			t.Fatal("Sign emitted an envelope with an empty signature")
		}
	})
}

func TestSignDeterministic(t *testing.T) {
	a := &stubSigner{sig: []byte("sig"), keyID: "k"}
	b := &stubSigner{sig: []byte("sig"), keyID: "k"}
	envA, err := Sign(context.Background(), a, goldenSubject(), goldenVSA())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	envB, err := Sign(context.Background(), b, goldenSubject(), goldenVSA())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	rawA, _ := json.Marshal(envA)
	rawB, _ := json.Marshal(envB)
	if !bytes.Equal(rawA, rawB) {
		t.Errorf("envelopes differ\n%s\n%s", rawA, rawB)
	}
	if !bytes.Equal(a.seen[0], b.seen[0]) {
		t.Errorf("PAE differs between runs")
	}
}

// TestBuildStatementRejectsWeakOnlyDigests pins the strong-digest floor.
//
// A VSA whose only binding is an md5 is forgeable for the cost of a
// chosen-prefix collision — seconds of compute — which would let one
// signed attestation cover an artifact that was never evaluated. sha1 is
// the same shape at higher cost. Both were accepted before this floor
// existed, and both were in the length table, which made them look
// deliberate.
func TestBuildStatementRejectsWeakOnlyDigests(t *testing.T) {
	weak := map[string]string{
		"md5":  strings.Repeat("ab", 16),
		"sha1": strings.Repeat("ab", 20),
	}
	for algo, val := range weak {
		t.Run(algo+" alone is refused", func(t *testing.T) {
			_, err := BuildStatement(Subject{Name: "x", Digest: map[string]string{algo: val}}, goldenVSA())
			if err == nil {
				t.Fatalf("%s-only subject was accepted; a weak-only binding must not be signed", algo)
			}
		})
		t.Run(algo+" alongside sha256 is fine", func(t *testing.T) {
			d := map[string]string{algo: val, "sha256": strings.Repeat("cd", 32)}
			if _, err := BuildStatement(Subject{Name: "x", Digest: d}, goldenVSA()); err != nil {
				t.Fatalf("weak digest alongside a strong one should be carried: %v", err)
			}
		})
	}
}

// TestBuildStatementRejectsMalformedAlgorithmKeys pins the algorithm-key
// shape check.
//
// The length table is keyed on an exact lowercase name. Before this
// check, a variant key missed the table and fell through to the
// permissive unknown-algorithm branch — so "SHA256" with 62 hex chars
// was signed as a valid subject with a TRUNCATED digest.
func TestBuildStatementRejectsMalformedAlgorithmKeys(t *testing.T) {
	strong := strings.Repeat("cd", 32)
	bad := []string{"SHA256", "sha-256", "sha256 ", " sha256", "sha_256", " "}
	for _, algo := range bad {
		t.Run("algo="+algo, func(t *testing.T) {
			d := map[string]string{"sha256": strong, algo: strings.Repeat("ab", 31)}
			if _, err := BuildStatement(Subject{Name: "x", Digest: d}, goldenVSA()); err == nil {
				t.Errorf("algorithm key %q was accepted; a variant key skips the length check", algo)
			}
		})
	}
}

// TestBuildStatementRejectsBlankRequiredFields pins TrimSpace on the
// A8.1 bindings. A single space satisfies `== ""`, and an attestation
// whose policy binding is " " names no policy at all.
func TestBuildStatementRejectsBlankRequiredFields(t *testing.T) {
	blanks := []string{" ", "\t", "\n", "   "}
	mutators := map[string]func(*VSA, string){
		"verifier":      func(v *VSA, b string) { v.Verifier = b },
		"resourceURI":   func(v *VSA, b string) { v.ResourceURI = b },
		"policyURI":     func(v *VSA, b string) { v.PolicyURI = b },
		"policyVersion": func(v *VSA, b string) { v.PolicyVersion = b },
	}
	for field, mutate := range mutators {
		for _, b := range blanks {
			v := goldenVSA()
			mutate(&v, b)
			if _, err := BuildStatement(goldenSubject(), v); err == nil {
				t.Errorf("%s = %q was accepted; a whitespace binding is not a binding", field, b)
			}
		}
	}
}

// TestBuildStatementRejectsUnknownVerifiedLevels pins the SLSA
// vocabulary. Asserting a level outside it is over-claiming, which is
// the thing this package exists to prevent.
func TestBuildStatementRejectsUnknownVerifiedLevels(t *testing.T) {
	bad := []string{"anything at all", "SLSA_BUILD_LEVEL_4", "slsa_build_level_1", "LEVEL_3", ""}
	for _, lvl := range bad {
		v := goldenVSA()
		v.VerifiedLevels = []string{"SLSA_BUILD_LEVEL_0", lvl}
		if _, err := BuildStatement(goldenSubject(), v); err == nil {
			t.Errorf("verified level %q was accepted", lvl)
		}
	}
	for _, lvl := range []string{"SLSA_BUILD_LEVEL_0", "SLSA_BUILD_LEVEL_1", "SLSA_BUILD_LEVEL_2", "SLSA_BUILD_LEVEL_3"} {
		v := goldenVSA()
		v.VerifiedLevels = []string{lvl}
		if _, err := BuildStatement(goldenSubject(), v); err != nil {
			t.Errorf("verified level %q was refused: %v", lvl, err)
		}
	}
}
