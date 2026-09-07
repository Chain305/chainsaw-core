package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/sbom"
)

func TestSBOMDiffCmd_TextOutput(t *testing.T) {
	a := filepath.Join("..", "sbom", "testdata", "diff", "mixed_a.json")
	b := filepath.Join("..", "sbom", "testdata", "diff", "mixed_b.json")

	var buf bytes.Buffer
	cmd := sbomDiffCmd
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Flags().Set("format", "text"); err != nil {
		t.Fatalf("set format: %v", err)
	}
	if err := runSBOMDiff(cmd, []string{a, b}); err != nil {
		t.Fatalf("runSBOMDiff: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"Added:",
		"axios@1.6.0 (npm)",
		"Removed:",
		"left-pad@1.3.0 (npm)",
		"Changed:",
		"lodash (npm): 4.17.20 -> 4.17.21",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestSBOMDiffCmd_InTotoTextOutput(t *testing.T) {
	a := filepath.Join("..", "sbom", "testdata", "diff", "intoto_a.json")
	b := filepath.Join("..", "sbom", "testdata", "diff", "intoto_b.json")

	var buf bytes.Buffer
	cmd := sbomDiffCmd
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Flags().Set("format", "text"); err != nil {
		t.Fatalf("set format: %v", err)
	}
	if err := runSBOMDiff(cmd, []string{a, b}); err != nil {
		t.Fatalf("runSBOMDiff (in-toto): %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"Added:",
		"axios@1.6.0 (npm)",
		"Removed:",
		"left-pad@1.3.0 (npm)",
		"Changed:",
		"lodash (npm): 4.17.20 -> 4.17.21",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestSBOMDiffCmd_FormatMixingRejected(t *testing.T) {
	a := filepath.Join("..", "sbom", "testdata", "diff", "mixed_a.json")
	b := filepath.Join("..", "sbom", "testdata", "diff", "intoto_a.json")

	var buf bytes.Buffer
	cmd := sbomDiffCmd
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Flags().Set("format", "text"); err != nil {
		t.Fatalf("set format: %v", err)
	}
	err := runSBOMDiff(cmd, []string{a, b})
	if err == nil {
		t.Fatal("want error on mixed formats, got nil")
	}
	if !strings.Contains(err.Error(), "mixed formats") {
		t.Errorf("error should call out mixed formats, got: %v", err)
	}
}

func TestSBOMDiffCmd_JSONOutput(t *testing.T) {
	a := filepath.Join("..", "sbom", "testdata", "diff", "added_a.json")
	b := filepath.Join("..", "sbom", "testdata", "diff", "added_b.json")

	var buf bytes.Buffer
	cmd := sbomDiffCmd
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Flags().Set("format", "json"); err != nil {
		t.Fatalf("set format: %v", err)
	}
	if err := runSBOMDiff(cmd, []string{a, b}); err != nil {
		t.Fatalf("runSBOMDiff: %v", err)
	}

	var got sbom.DiffResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal JSON output: %v\noutput: %s", err, buf.String())
	}
	if len(got.Added) != 1 || got.Added[0].Name != "lodash" {
		t.Errorf("want lodash added, got %+v", got.Added)
	}
	if len(got.Removed) != 0 || len(got.Changed) != 0 {
		t.Errorf("unexpected removed/changed: %+v", got)
	}
}

// TestExceptionItemsToVEXInput pins the wire-to-DTO adapter the
// `chainsaw sbom vex export` CLI uses. The server-side exceptionEntry now
// carries Decision/CVE/Note, and the adapter must forward them — empty
// Decision falls back to "allow" so historical rows produce the same VEX
// shape they did before the columns existed.
func TestExceptionItemsToVEXInput(t *testing.T) {
	created := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	expires := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	t.Run("empty decision falls back to allow (back-compat)", func(t *testing.T) {
		items := []exceptionItem{
			{
				ID:         "ex1",
				Repository: "npm-prod",
				Format:     "npm",
				PackageID:  "lodash",
				Version:    "4.17.20",
				CreatedAt:  created,
				ExpiresAt:  expires,
				Status:     "active",
			},
		}
		got := exceptionItemsToVEXInput(items)
		if len(got) != 1 {
			t.Fatalf("want 1 exception, got %d", len(got))
		}
		if got[0].Decision != "allow" {
			t.Errorf("Decision = %q, want allow (empty-string back-compat fallback)", got[0].Decision)
		}
		if got[0].Ecosystem != "npm" || got[0].Name != "lodash" || got[0].Version != "4.17.20" {
			t.Errorf("identity drift: got %+v", got[0])
		}
		if !got[0].ExpiresAt.Equal(expires) {
			t.Errorf("ExpiresAt = %v, want %v", got[0].ExpiresAt, expires)
		}
	})

	t.Run("monitor decision is forwarded with CVE and note", func(t *testing.T) {
		items := []exceptionItem{
			{
				ID: "ex2", Repository: "pypi-prod", Format: "pypi",
				PackageID: "requests", Version: "2.31.0",
				CreatedAt: created, ExpiresAt: expires, Status: "active",
				Decision: "monitor",
				CVE:      "CVE-2024-22222",
				Note:     "tracking upstream patch",
			},
		}
		got := exceptionItemsToVEXInput(items)
		if got[0].Decision != "monitor" {
			t.Errorf("Decision = %q, want monitor", got[0].Decision)
		}
		if got[0].CVE != "CVE-2024-22222" {
			t.Errorf("CVE = %q, want CVE-2024-22222", got[0].CVE)
		}
		if got[0].Note != "tracking upstream patch" {
			t.Errorf("Note = %q, want forwarded", got[0].Note)
		}
	})

	t.Run("deny decision is forwarded as-is so BuildVEX can exclude it", func(t *testing.T) {
		items := []exceptionItem{
			{
				ID: "ex3", Repository: "npm-prod", Format: "npm",
				PackageID: "blocked", Version: "1.0.0",
				Decision: "deny", CVE: "CVE-2024-44444",
			},
		}
		got := exceptionItemsToVEXInput(items)
		if got[0].Decision != "deny" {
			t.Errorf("Decision = %q, want deny (BuildVEX must see real value to exclude)", got[0].Decision)
		}
	})

	t.Run("decision is normalized to lowercase", func(t *testing.T) {
		items := []exceptionItem{
			{ID: "ex4", Repository: "r", Format: "npm", PackageID: "p", Version: "1", Decision: "  ALLOW  "},
		}
		got := exceptionItemsToVEXInput(items)
		if got[0].Decision != "allow" {
			t.Errorf("Decision = %q, want lowercase trimmed 'allow'", got[0].Decision)
		}
	})
}

// TestSBOMVexExport_RegistersAndProducesVEX confirms the subcommand is
// wired into the cobra tree and that the BuildVEX path produces a valid
// CycloneDX 1.6 VEX envelope when fed adapter output. We don't run the
// command end-to-end (it requires a configured server) — the contract is
// "registered + adapter shape + BuildVEX envelope".
func TestSBOMVexExport_RegistersAndProducesVEX(t *testing.T) {
	vex, _, err := sbomCmd.Find([]string{"vex", "export"})
	if err != nil {
		t.Fatalf("sbom vex export not registered: %v", err)
	}
	if vex.Use != "export" {
		t.Errorf("found wrong command: %q", vex.Use)
	}

	future := time.Now().UTC().Add(24 * time.Hour)
	exceptions := exceptionItemsToVEXInput([]exceptionItem{
		{
			ID: "ex1", Repository: "npm-prod", Format: "npm",
			PackageID: "lodash", Version: "4.17.20",
			CreatedAt: time.Now().UTC(), ExpiresAt: future,
		},
	})
	exceptions[0].CVE = "CVE-2024-12345"

	doc, err := sbom.BuildVEX("org-test", exceptions)
	if err != nil {
		t.Fatalf("BuildVEX: %v", err)
	}
	bs, err := doc.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(bs, &parsed); err != nil {
		t.Fatalf("parse VEX: %v", err)
	}
	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", parsed["bomFormat"])
	}
	if parsed["specVersion"] != "1.6" {
		t.Errorf("specVersion = %v, want 1.6", parsed["specVersion"])
	}
	vulns, ok := parsed["vulnerabilities"].([]any)
	if !ok || len(vulns) != 1 {
		t.Fatalf("vulnerabilities[] missing or wrong size: %v", parsed["vulnerabilities"])
	}
}

// TestExceptionItemsToVEXInput_ForwardsStatus pins the F2 fix at the
// adapter boundary. The defect was that exceptionItem.Status was parsed
// off the wire and then dropped on the floor, so BuildVEX had no way to
// tell an approved carve-out from a draft. Status must be forwarded
// verbatim — including the empty string, which BuildVEX treats as "in
// effect" — and must NOT be normalised here, or the deny-list judgement
// would exist in two places.
func TestExceptionItemsToVEXInput_ForwardsStatus(t *testing.T) {
	for _, status := range []string{"", "active", "expiring_soon", "expired", "pending_approval", "denied", "  Pending_Approval  "} {
		items := []exceptionItem{{
			ID: "ex-status", Repository: "npm-prod", Format: "npm",
			PackageID: "lodash", Version: "4.17.20",
			Decision: "allow", CVE: "CVE-2024-12345",
			Status: status,
		}}
		got := exceptionItemsToVEXInput(items)
		if len(got) != 1 {
			t.Fatalf("status=%q: want 1 adapted exception, got %d", status, len(got))
		}
		if got[0].Status != status {
			t.Errorf("status=%q: Status = %q, want verbatim forward", status, got[0].Status)
		}
	}
}

// TestSBOMVexExport_ExcludesUnapprovedExceptions is the end-to-end half of
// F2: adapter output fed straight into BuildVEX, asserting a pending
// exception never reaches the CycloneDX document while an approved one
// alongside it does. Both rows are decision=allow with a live expiry, so
// the only thing separating them is the lifecycle status.
func TestSBOMVexExport_ExcludesUnapprovedExceptions(t *testing.T) {
	future := time.Now().UTC().Add(30 * 24 * time.Hour)
	items := []exceptionItem{
		{
			ID: "approved", Repository: "npm-prod", Format: "npm",
			PackageID: "lodash", Version: "4.17.20",
			Decision: "allow", CVE: "CVE-2024-APPROVED",
			Status: "active", CreatedAt: time.Now().UTC(), ExpiresAt: future,
		},
		{
			ID: "pending", Repository: "npm-prod", Format: "npm",
			PackageID: "left-pad", Version: "1.0.0",
			Decision: "allow", CVE: "CVE-2024-PENDING",
			Status: "pending_approval", CreatedAt: time.Now().UTC(), ExpiresAt: future,
		},
		{
			ID: "denied", Repository: "npm-prod", Format: "npm",
			PackageID: "blocked", Version: "1.0.0",
			Decision: "allow", CVE: "CVE-2024-DENIED",
			Status: "denied", CreatedAt: time.Now().UTC(), ExpiresAt: future,
		},
		{
			// Inside the 14-day renew window: still enforced, still a true
			// statement. An allow-list filter would drop this.
			ID: "renewing", Repository: "npm-prod", Format: "npm",
			PackageID: "renewing", Version: "1.0.0",
			Decision: "allow", CVE: "CVE-2024-RENEWING",
			Status: "expiring_soon", CreatedAt: time.Now().UTC(),
			ExpiresAt: time.Now().UTC().Add(3 * 24 * time.Hour),
		},
	}

	doc, err := sbom.BuildVEX("org-test", exceptionItemsToVEXInput(items))
	if err != nil {
		t.Fatalf("BuildVEX: %v", err)
	}
	ids := map[string]bool{}
	for _, v := range doc.Vulnerabilities {
		ids[v.ID] = true
	}
	for _, want := range []string{"CVE-2024-APPROVED", "CVE-2024-RENEWING"} {
		if !ids[want] {
			t.Errorf("%s missing from VEX document; got %v", want, ids)
		}
	}
	for _, forbidden := range []string{"CVE-2024-PENDING", "CVE-2024-DENIED"} {
		if ids[forbidden] {
			t.Errorf("%s was exported as an authoritative VEX statement; got %v", forbidden, ids)
		}
	}
}
