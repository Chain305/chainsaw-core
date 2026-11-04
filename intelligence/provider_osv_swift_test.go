package intelligence

import (
	"context"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/intelligence/osv"
)

// With a SwiftURL corpus loaded, a Swift coordinate in `owner.repo` form is
// a real lookup (hit or clean stamp); a bare SwiftPM identity is a gap. The
// bare-name branch is what stops the GitHub-keyed corpus from grading every
// unkeyable Swift name clean (shape 2′ on a name it could never hold).
func TestOSVSwiftBareIdentityIsAGapNotClean(t *testing.T) {
	idx, err := osv.Load(strings.NewReader(`[{"ecosystem":"SwiftURL","package":"github.com/vapor/vapor",
		"vulnerable_ranges":[{"introduced":"0","fixed":"4.84.2"}],"advisory_id":"GHSA-swift-p-0001","aliases":["CVE-2026-0003"]}]`))
	if err != nil {
		t.Fatal(err)
	}
	run := func(pkg, ver string) PartialReport {
		t.Helper()
		out, err := (&osvProvider{idx: idx}).Run(context.Background(), Request{
			Key: Key{Ecosystem: "swift", Package: pkg, Version: ver},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	if out := run("vapor.vapor", "4.80.0"); out.Vulns == nil || !out.Vulns.IsVulnerable {
		t.Fatalf("vapor.vapor@4.80.0: %+v, want the advisory", out.Vulns)
	}
	if out := run("apple.swift-nio", "2.60.0"); out.Vulns == nil || out.Vulns.IsVulnerable || len(out.Warnings) != 0 {
		t.Fatalf("owner.repo absent from a covered corpus must stamp clean, got %+v", out)
	}
	out := run("vapor", "4.80.0")
	if out.Vulns != nil {
		t.Fatalf("bare identity stamped a VulnSection %+v — a false clean", out.Vulns)
	}
	if len(out.Warnings) != 1 || out.Warnings[0].Code != warnOSVBundleDormant {
		t.Fatalf("bare identity warnings = %+v, want one %s", out.Warnings, warnOSVBundleDormant)
	}
}
