package provenance

import (
	"encoding/hex"
	"testing"
)

func TestSplitOCIName(t *testing.T) {
	cases := []struct {
		in                string
		wantReg, wantRepo string
	}{
		{"nginx", "registry-1.docker.io", "library/nginx"},
		{"library/nginx", "registry-1.docker.io", "library/nginx"},
		{"bitnami/redis", "registry-1.docker.io", "bitnami/redis"},
		{"ghcr.io/sigstore/cosign", "ghcr.io", "sigstore/cosign"},
		{"registry.example.com:5000/team/app", "registry.example.com:5000", "team/app"},
	}
	for _, c := range cases {
		reg, repo := splitOCIName(c.in)
		if reg != c.wantReg || repo != c.wantRepo {
			t.Errorf("splitOCIName(%q) = (%q, %q), want (%q, %q)",
				c.in, reg, repo, c.wantReg, c.wantRepo)
		}
	}
}

func TestSplitOCIRepo(t *testing.T) {
	cases := []struct {
		in                 string
		wantOwner, wantImg string
	}{
		{"sigstore/cosign", "sigstore", "cosign"},
		{"acme/team/app", "acme", "team/app"},
		{"single", "", "single"},
	}
	for _, c := range cases {
		o, i := splitOCIRepo(c.in)
		if o != c.wantOwner || i != c.wantImg {
			t.Errorf("splitOCIRepo(%q) = (%q, %q), want (%q, %q)",
				c.in, o, i, c.wantOwner, c.wantImg)
		}
	}
}

func TestDecodeHexDigest(t *testing.T) {
	raw := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	got, err := decodeHexDigest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 {
		t.Fatalf("len = %d, want 32", len(got))
	}
	if hex.EncodeToString(got) != raw[len("sha256:"):] {
		t.Fatalf("round-trip mismatch")
	}

	if _, err := decodeHexDigest("sha512:abc"); err == nil {
		t.Error("want error for unsupported algorithm")
	}
}
