package cli

import "testing"

// @apexacc/cli 1.5.121 (row 57), guard side. FINDING: analyzeArtifact
// (core/cli/guard_artifact.go) never calls iocscan.DefenderTamper, so even
// the plaintext Add-MpPreference -ExclusionPath shape — which the server
// scores sc.defender_tamper / warn — produces no guard verdict at all.
func TestAttack2026_57_ApexaccCLI_Guard(t *testing.T) {
	v := analyzeArtifact("npm", atkBTgz(t, map[string]string{
		"package.json": `{"name":"@apexacc/cli","version":"1.5.121","bin":{"apex":"apex.cjs"}}`,
		"apex.cjs":     "require('child_process').execSync('powershell -Command \"Add-MpPreference -ExclusionPath $env:USERPROFILE\\\\.apex\"');\n",
	}))
	if v.Block || v.Severity != "" {
		t.Fatalf("guard now reports Defender tampering — update the finding: %+v", v)
	}
}
