package swift

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/httpclient"
)

// R2-G7 (round-2 review 2026-11-17): behind a forward proxy the target was
// only allowlist-checked, so an IP-literal remote on 169.254.169.254 or
// RFC 1918 went to the proxy unchecked; and with a socks5:// proxy curl
// resolves the target locally and connects to whatever it gets.
func TestPlanRemoteProxiedTargetChecks(t *testing.T) {
	for _, k := range []string{"CHAINSAW_ALLOW_PRIVATE_UPSTREAMS", "CHAINSAW_ALLOW_CGNAT_UPSTREAMS", "CHAINSAW_EGRESS_ALLOW", "NO_PROXY", "no_proxy", "https_proxy"} {
		t.Setenv(k, "")
	}
	noDNS := func(context.Context, string) ([]net.IP, error) {
		t.Fatal("resolved the remote with the direct-route lookup")
		return nil, nil
	}
	t.Setenv("HTTPS_PROXY", "http://10.0.0.9:3128")
	for _, remote := range []string{
		"https://169.254.169.254/a/b",
		"https://10.0.0.5/a/b",
		"https://[fd00:ec2::254]/a/b",
		"https://metadata.google.internal/a/b",
		"https://2130706433/a/b",
	} {
		if _, err := planRemote(context.Background(), remote, noDNS); err == nil || !httpclient.IsSSRFBlocked(err) {
			t.Errorf("%s through the proxy: err = %v, want an SSRF refusal", remote, err)
		}
	}
	if r, err := planRemote(context.Background(), "https://140.82.112.3/a/b", noDNS); err != nil || r.proxy == "" {
		t.Errorf("public literal through the private proxy: route %+v err %v", r, err)
	}
	for _, p := range []string{"socks5://10.0.0.9:1080", "socks5h://proxy.example:1080"} {
		t.Setenv("HTTPS_PROXY", p)
		if _, err := planRemote(context.Background(), "https://140.82.112.3/a/b", noDNS); err == nil || !strings.Contains(err.Error(), "only http and https proxies") {
			t.Errorf("proxy %s: err = %v, want a scheme refusal", p, err)
		}
	}
}
