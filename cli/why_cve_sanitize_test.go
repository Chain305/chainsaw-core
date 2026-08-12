package cli

// C12 — `chainsaw why` declares package/version/reason/ecosystem untrusted and
// scrubs each with sanitizeForTerminal, but printed the CVE list raw. The ids
// come from the SAME place (blockedFromAuditEvent lifts them out of
// e.Metadata["cves"]), so an attacker-influenced install could carry ANSI in a
// "CVE id" and rewrite the operator's view of the block report.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderWhyTable_SanitizesCVEIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "why.txt")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	v := &blockedViolation{
		PackageID:  "evil-pkg",
		Version:    "1.0.0",
		Reason:     "known malicious",
		PolicyName: "Block known malware",
		// A control-sequence payload: erase-line + carriage return would let the
		// recorded metadata overwrite the line above it in the operator's
		// terminal.
		CVEIDs: []string{"CVE-2026-1", "\x1b[2K\rPackage:    safe-lib", "CVE\x9b2026-2"},
	}
	renderWhyTable(f, "npm", v, "req-1", "audit")
	f.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	out := string(data)

	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("ESC survived into the CVE line: %q", out)
	}
	if strings.ContainsRune(out, 0x9b) {
		t.Errorf("raw C1 CSI introducer survived into the CVE line: %q", out)
	}
	if strings.ContainsRune(out, '\r') {
		t.Errorf("carriage return survived into the CVE line: %q", out)
	}
	// The visible text is still shown — scrubbing drops control bytes only.
	if !strings.Contains(out, "CVE-2026-1") {
		t.Errorf("legitimate CVE id was lost: %q", out)
	}
}
