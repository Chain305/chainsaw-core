package provenance

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// VerifyClearsigned names the subkey that signed, so a Signed-By pin can
// be checked with apt's semantics: primary or subkey fingerprint, "!" for
// the subkey only, and nothing else.
func TestVerifyClearsignedSignerMatchesSignedBy(t *testing.T) {
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}
	e, err := openpgp.NewEntity("Archive", "", "archive@example.org", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.AddSigningSubkey(cfg); err != nil {
		t.Fatal(err)
	}
	sub := e.Subkeys[len(e.Subkeys)-1]
	var buf bytes.Buffer
	w, err := clearsign.Encode(&buf, sub.PrivateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("Suite: stable\n"))
	w.Close()

	text, k, err := VerifyClearsigned(buf.Bytes(), openpgp.EntityList{e})
	if err != nil || string(text) != "Suite: stable\n" {
		t.Fatalf("verify: %q %v", text, err)
	}
	primary, subFP := fmt.Sprintf("%X", e.PrimaryKey.Fingerprint), fmt.Sprintf("%X", sub.PublicKey.Fingerprint)
	if k.Signing != subFP || k.Primary != primary {
		t.Fatalf("signer = %+v, want signing %s primary %s", k, subFP, primary)
	}
	other, _ := openpgp.NewEntity("Other", "", "o@example.org", cfg)
	for _, tc := range []struct {
		fps  []string
		want bool
	}{
		{[]string{primary}, true},
		{[]string{subFP}, true},
		{[]string{subFP + "!"}, true},
		{[]string{primary + "!"}, false},
		{[]string{fmt.Sprintf("%x", other.PrimaryKey.Fingerprint)}, false},
		{nil, false},
		{[]string{""}, false},
	} {
		if got := k.MatchesSignedBy(tc.fps); got != tc.want {
			t.Errorf("MatchesSignedBy(%v) = %v, want %v", tc.fps, got, tc.want)
		}
	}
}
