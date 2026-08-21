package cli

// scan_bare_ref_ecosystem_test.go — `chainsaw scan <name>@<version>` reported
// severity "unscanned" for every bare ref.
//
// parsePackageRef built a coordinate with no ecosystem and `scan` exposed no
// way to supply one, so the request reached the server unplaceable and
// scanFallback (internal/server/scan.go) bailed before it could look anything
// up. The command most people type first answered nothing, and answered it at
// rc=0. These tests pin the three halves of the fix: the flag, the inference
// that makes the flag unnecessary where the name is unambiguous, and the
// refusal to let an unplaceable single ref exit 0.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// unscannedNoEcosystemResponse mirrors what the live server returns for a
// coordinate it cannot place: an "unscanned" row carrying the reason, and no
// ecosystem echoed back.
func unscannedNoEcosystemResponse(name, version string) scanAPIResponse {
	return scanAPIResponse{
		Results: []scanResultItem{{
			Name:            name,
			Version:         version,
			Status:          "unscanned",
			UnscannedReason: "the request named no ecosystem this server can resolve",
		}},
		Total:     1,
		Unscanned: 1,
	}
}

// scanEcosystemEcho stands up a server that echoes each request coordinate
// back as a "safe" row and records what arrived on the wire.
func scanEcosystemEcho(t *testing.T, got *[]scanPkg) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Packages []scanPkg `json:"packages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "decode", http.StatusBadRequest)
			return
		}
		resp := scanAPIResponse{}
		for _, p := range body.Packages {
			*got = append(*got, p)
			resp.Results = append(resp.Results, scanResultItem{
				Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem, Status: "safe",
			})
		}
		resp.Total = len(resp.Results)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestParsePackageRefInfersUnambiguousEcosystems covers the shapes that belong
// to exactly one registry's naming grammar. Getting these for free is what
// keeps --ecosystem from being a tax on every scan.
func TestParsePackageRefInfersUnambiguousEcosystems(t *testing.T) {
	cases := []struct {
		ref  string
		want string
		why  string
	}{
		{"@babel/core@7.24.0", "npm", "a scoped name is npm's grammar and nobody else's"},
		{"@types/node@20.11.0", "npm", "scoped, one slash"},
		{"github.com/gin-gonic/gin@v1.9.0", "go", "a domain-shaped first segment at a v-prefixed version is a Go module path"},
		{"golang.org/x/text@v0.14.0", "go", "same, three segments"},
		{"lodash@4.17.11", "", "a plain name is registrable on npm, PyPI, RubyGems and crates.io alike"},
		{"commander@2.20.3", "", "the defect's own example: npm and PyPI both have one"},
		{"requests@2.31.0", "", "PyPI's, but nothing in the string says so"},
	}
	for _, tc := range cases {
		t.Run(tc.ref, func(t *testing.T) {
			pkg, err := parsePackageRef(tc.ref)
			if err != nil {
				t.Fatalf("parsePackageRef(%q): %v", tc.ref, err)
			}
			if pkg.Ecosystem != tc.want {
				t.Errorf("ecosystem = %q, want %q — %s", pkg.Ecosystem, tc.want, tc.why)
			}
		})
	}
}

// TestScanEcosystemFlagReachesTheWire is the flag half: an explicit
// --ecosystem must arrive on the coordinate, canonicalised the way the server
// spells it (pypi → pip).
func TestScanEcosystemFlagReachesTheWire(t *testing.T) {
	var got []scanPkg
	configureScan(t, scanEcosystemEcho(t, &got))
	if err := scanCmd.Flags().Set("ecosystem", "pypi"); err != nil {
		t.Fatalf("set ecosystem: %v", err)
	}

	var runErr error
	captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"commander@2.20.3"})
	})
	if code := scanExitCode(t, runErr); code != ExitOK {
		t.Fatalf("exit code = %d, want %d: %v", code, ExitOK, runErr)
	}
	if len(got) != 1 {
		t.Fatalf("server received %d coordinate(s), want 1: %+v", len(got), got)
	}
	if got[0].Ecosystem != "pip" {
		t.Errorf("ecosystem on the wire = %q, want %q (the alias must be folded, not forwarded)",
			got[0].Ecosystem, "pip")
	}
}

// TestScanEcosystemFlagRejectsUnknownValue: an ecosystem the CLI cannot place
// must fail at the flag, not become an unplaceable coordinate whose
// "unscanned" row blames the package.
func TestScanEcosystemFlagRejectsUnknownValue(t *testing.T) {
	var got []scanPkg
	configureScan(t, scanEcosystemEcho(t, &got))
	if err := scanCmd.Flags().Set("ecosystem", "notaregistry"); err != nil {
		t.Fatalf("set ecosystem: %v", err)
	}

	var runErr error
	captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"lodash@4.17.11"})
	})
	if code := scanExitCode(t, runErr); code != ExitUsage {
		t.Fatalf("exit code = %d, want %d (bad flag value)", code, ExitUsage)
	}
	if !strings.Contains(runErr.Error(), "notaregistry") {
		t.Errorf("error must quote the rejected value: %v", runErr)
	}
	if len(got) != 0 {
		t.Errorf("a rejected --ecosystem still reached the server: %+v", got)
	}
}

// TestScanEcosystemFlagDoesNotOverrideALockfile: --ecosystem fills gaps, it
// does not restamp coordinates whose registry the parser already proved.
// Restamping a mixed tree as one ecosystem is the cross-registry collision the
// per-item field exists to prevent.
func TestScanEcosystemFlagDoesNotOverrideALockfile(t *testing.T) {
	var got []scanPkg
	configureScan(t, scanEcosystemEcho(t, &got))
	if err := scanCmd.Flags().Set("path", twoCommanderTree(t)); err != nil {
		t.Fatalf("set path: %v", err)
	}
	if err := scanCmd.Flags().Set("ecosystem", "npm"); err != nil {
		t.Fatalf("set ecosystem: %v", err)
	}

	captureScanRun(t, func() { _ = runScan(newScanTestCmd(), nil) })

	seen := map[string]bool{}
	for _, p := range got {
		if p.Name == "commander" {
			seen[p.Ecosystem] = true
		}
	}
	if !seen["npm"] || !seen["pip"] {
		t.Fatalf("lockfile ecosystems on the wire = %v; want both npm and pip preserved", seen)
	}
}

// TestScanBareRefRefusesToExitZeroUnscanned is the headline: the single
// positional ref whose registry could be neither inferred nor supplied must
// not answer "unscanned" at rc=0. It fails as a usage error and names the flag
// that fixes it.
func TestScanBareRefRefusesToExitZeroUnscanned(t *testing.T) {
	configureScan(t, runScanTestServer(t, unscannedNoEcosystemResponse("lodash", "4.17.11")))

	var runErr error
	_, stderr := captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"lodash@4.17.11"})
	})

	if code := scanExitCode(t, runErr); code != ExitUsage {
		t.Fatalf("exit code = %d, want %d — an unscanned bare ref is a non-answer, not a pass", code, ExitUsage)
	}
	if !strings.Contains(runErr.Error(), "--ecosystem") {
		t.Errorf("the error must name the flag that fixes it: %v", runErr)
	}
	if !strings.Contains(stderr, "--ecosystem") {
		t.Errorf("stderr should also point at the flag:\n%s", stderr)
	}
}

// TestScanBareRefWithEcosystemGetsAVerdict is the other side of the same
// coin: once the registry is named, the coordinate resolves and the command
// behaves like any other scan.
func TestScanBareRefWithEcosystemGetsAVerdict(t *testing.T) {
	url := runScanTestServer(t, scanAPIResponse{
		Results: []scanResultItem{{
			Name: "lodash", Version: "4.17.11", Ecosystem: "npm",
			Status: "vulnerable", Severity: "high", CVEs: []string{"CVE-2019-10744"},
		}},
		Total:      1,
		Vulnerable: 1,
	})
	configureScan(t, url)
	if err := scanCmd.Flags().Set("ecosystem", "npm"); err != nil {
		t.Fatalf("set ecosystem: %v", err)
	}

	var runErr error
	stdout, _ := captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"lodash@4.17.11"})
	})
	if code := scanExitCode(t, runErr); code != ExitBlocked {
		t.Fatalf("exit code = %d, want %d (a real high-severity verdict)", code, ExitBlocked)
	}
	if !strings.Contains(stdout, "CVE-2019-10744") {
		t.Errorf("table missing the verdict:\n%s", stdout)
	}
}

// TestScanScopedRefNeedsNoFlag: the inference must actually reach the wire,
// not just parsePackageRef. A scoped npm name is the one bare ref shape a new
// user is most likely to type after a plain one.
func TestScanScopedRefNeedsNoFlag(t *testing.T) {
	var got []scanPkg
	configureScan(t, scanEcosystemEcho(t, &got))

	var runErr error
	captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"@babel/core@7.24.0"})
	})
	if code := scanExitCode(t, runErr); code != ExitOK {
		t.Fatalf("exit code = %d, want %d: %v", code, ExitOK, runErr)
	}
	if len(got) != 1 || got[0].Ecosystem != "npm" {
		t.Fatalf("wire coordinates = %+v; want one npm coordinate", got)
	}
}

// TestScanPathUnscannedStillExitsZero is the blast-radius guard. The
// single-ref refusal must not leak into --path: a lockfile scan is usually a
// CI gate, its unscanned rows have causes --ecosystem cannot fix, and
// --fail-on-unscanned is the documented switch for making them fail.
func TestScanPathUnscannedStillExitsZero(t *testing.T) {
	configureScan(t, runScanTestServer(t, unscannedNoEcosystemResponse("commander", "2.20.3")))
	if err := scanCmd.Flags().Set("path", twoCommanderTree(t)); err != nil {
		t.Fatalf("set path: %v", err)
	}

	var runErr error
	captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), nil) })
	if code := scanExitCode(t, runErr); code != ExitOK {
		t.Fatalf("exit code = %d, want %d — the default unscanned posture must not change", code, ExitOK)
	}
}
