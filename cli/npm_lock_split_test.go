package cli

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"testing"

	"github.com/chain305/chainsaw-core/depparser/parser/nodejs/nodesource"
)

// TestHashToSRIMultiToken: a lockfile Hash carries EVERY integrity token
// (nodesource.Integrity), and hashToSRI must turn all of them back into the
// guard's byte anchor. It returned "" for any multi-token Hash, which is
// "no anchor" — the guard then analysed whatever bytes it was handed.
// Break it like this: convert only a single "<algo>:<hex>" again.
func TestHashToSRIMultiToken(t *testing.T) {
	good, bad := []byte("the public tarball"), []byte("something else")
	s512, s1 := sha512.Sum512(good), sha1.Sum(good)
	sri := "sha1-" + base64.StdEncoding.EncodeToString(s1[:]) + " sha512-" + base64.StdEncoding.EncodeToString(s512[:])
	anchor := hashToSRI(nodesource.Integrity(sri))
	if anchor != sri {
		t.Fatalf("hashToSRI = %q, want %q", anchor, sri)
	}
	if res := anchorVerdict(good, anchor); res != acquireOK {
		t.Errorf("anchor on the right bytes = %v, want OK", res)
	}
	if res := anchorVerdict(bad, anchor); res != acquireDigestMismatch {
		t.Errorf("anchor on other bytes = %v, want digest mismatch", res)
	}
	if hashToSRI("") != "" || hashToSRI("md5:00") != "" {
		t.Error("no usable token must be no anchor")
	}
}
