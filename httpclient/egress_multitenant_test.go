package httpclient

import (
	"strings"
	"testing"
)

// R2-G3: these suffixes each admit hosts nobody reviewed (anyone's bucket or
// app, a rebinding name for any IP, an OAST collector) and were accepted.
func TestEgressAllowRefusesMultiTenantSuffixes(t *testing.T) {
	for _, e := range []string{
		".r2.cloudflarestorage.com", ".on.aws", ".cloudapp.azure.com", ".wasabisys.com", ".backblazeb2.com",
		".railway.app", ".glitch.me", ".surge.sh", ".googleusercontent.com",
		".raw.githubusercontent.com", ".objects.githubusercontent.com", ".githubusercontent.com",
		".nip.io", ".sslip.io", ".lvh.me", ".localtest.me",
		".oast.pro", ".oast.live", ".oast.site", ".oast.online", ".oast.fun", ".oast.me",
		".interact.sh", ".burpcollaborator.net", ".oastify.com",
	} {
		if p := parseEgressAllow(e); p.err == nil {
			t.Errorf("%s accepted as a suffix entry", e)
		}
	}
	// A named bucket or app under one of them is still listable.
	if p := parseEgressAllow(".my-bucket.r2.cloudflarestorage.com, osv-vulnerabilities.storage.googleapis.com"); p.err != nil {
		t.Errorf("specific bucket entries refused: %v", p.err)
	}
}

// R2-G3: an exact path-style multi-tenant host admits every bucket or repo
// on it. It is accepted (the upstream may have no virtual-hosted name) but
// warned about at boot.
func TestEgressAllowlistWarnsOnPathStyleMultiTenantHosts(t *testing.T) {
	t.Setenv(EgressAllowEnv, "s3.amazonaws.com, s3.eu-west-1.amazonaws.com, s3-us-west-2.amazonaws.com, storage.googleapis.com, "+
		"raw.githubusercontent.com, objects.githubusercontent.com, "+
		"my-bucket.s3.amazonaws.com, my-bucket.s3.eu-west-1.amazonaws.com, registry.npmjs.org, .npmjs.org")
	ws := EgressAllowlistWarnings()
	joined := strings.Join(ws, "\n")
	for _, h := range []string{"s3.amazonaws.com", "s3.eu-west-1.amazonaws.com", "s3-us-west-2.amazonaws.com",
		"storage.googleapis.com", "raw.githubusercontent.com", "objects.githubusercontent.com"} {
		if !strings.Contains(joined, `"`+h+`"`) {
			t.Errorf("no warning for %s", h)
		}
	}
	if len(ws) != 6 {
		t.Errorf("want exactly 6 warnings (virtual-hosted buckets and registries are fine), got %d:\n%s", len(ws), joined)
	}
	t.Setenv(EgressAllowEnv, "")
	if ws := EgressAllowlistWarnings(); len(ws) != 0 {
		t.Errorf("unset allowlist warned: %v", ws)
	}
}
