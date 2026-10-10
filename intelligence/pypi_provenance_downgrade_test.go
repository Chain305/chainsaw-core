package intelligence

import (
	"net/http"
	"strings"
	"testing"
)

// pf is one simple-index file: version, upload day, provenance present.
func pf(name string, day string, prov bool) pypiSimpleFile {
	f := pypiSimpleFile{Filename: name, UploadTime: "2026-" + day + "T00:00:00Z"}
	if prov {
		f.Provenance = []byte(`"https://pypi.org/integrity/p/x/` + name + `/provenance"`)
	} else {
		f.Provenance = []byte(`null`)
	}
	return f
}

func TestPyPIProvenanceDowngrade(t *testing.T) {
	files := []pypiSimpleFile{
		pf("p-0.9.tar.gz", "01-01", false),
		pf("p-1.0.tar.gz", "02-01", true), pf("p-1.0-py3-none-any.whl", "02-01", true),
		pf("p-1.1.tar.gz", "03-01", true), pf("p-1.1-py3-none-any.whl", "03-01", true),
		pf("p-1.2.tar.gz", "04-01", true), pf("p-1.2-py3-none-any.whl", "04-01", true),
		pf("p-1.3.tar.gz", "05-01", false), pf("p-1.3-py3-none-any.whl", "05-01", false),
		// partially attested: one wheel built outside the trusted publisher
		pf("p-1.4.tar.gz", "06-01", false), pf("p-1.4-py3-none-any.whl", "06-01", true),
		pf("p-2.0rc1.tar.gz", "07-01", false),
		// backport onto 1.1.x after the 1.2 line: its predecessors are 1.1, 1.0, 0.9
		pf("p-1.1.1.tar.gz", "08-01", false),
	}
	for ver, want := range map[string]string{
		"1.3":    "1.2", // three fully attested predecessors
		"1.3.0":  "1.2", // PEP 440 equality: the index spells it 1.3
		"1.4":    "",    // a file carries provenance: not a downgrade
		"1.2":    "",    // attested itself
		"2.0rc1": "",    // prereleases are never judged
		"1.1.1":  "",    // only two attested predecessors (1.1, 1.0)
		"9.9":    "",    // not on the index
	} {
		got := pypiProvenanceDowngrade(files, ver)
		if (got == nil) != (want == "") || (got != nil && got.LastAttestedVersion != want) {
			t.Errorf("%s: got %+v, want last attested %q", ver, got, want)
		}
	}
	if got := pypiProvenanceDowngrade(files, "1.3"); got == nil || got.PriorAttestedCount != 3 {
		t.Errorf("1.3: want PriorAttestedCount 3, got %+v", got)
	}

	// A prerelease straight after three attested releases is still not judged.
	pre := append(files[1:7:7], pf("p-1.3rc1.tar.gz", "04-15", false))
	if got := pypiProvenanceDowngrade(pre, "1.3rc1"); got != nil {
		t.Errorf("prerelease 1.3rc1 judged: %+v", got)
	}

	// Partial attestation, after three fully attested releases. As a target it
	// is not a downgrade; as a prior it ends the run.
	mixed := []pypiSimpleFile{
		pf("q-1.0.tar.gz", "01-01", true), pf("q-1.1.tar.gz", "02-01", true), pf("q-1.2.tar.gz", "03-01", true),
		pf("q-1.3.tar.gz", "04-01", false), pf("q-1.3-py3-none-any.whl", "04-01", true),
		pf("q-1.4.tar.gz", "05-01", true), pf("q-1.5.tar.gz", "06-01", true),
		pf("q-1.6.tar.gz", "07-01", false),
	}
	for _, ver := range []string{"1.3", "1.6"} {
		if got := pypiProvenanceDowngrade(mixed, ver); got != nil {
			t.Errorf("%s: partially attested 1.3 must neither fire nor extend a run, got %+v", ver, got)
		}
	}
}

func TestPyPIFileVersion(t *testing.T) {
	for name, want := range map[string]string{
		"sigstore-4.5.0.tar.gz":                             "4.5.0",
		"azure-storage-0.36.0.tar.gz":                       "0.36.0",
		"sigstore-4.5.0-py3-none-any.whl":                   "4.5.0",
		"numpy-2.1.0-cp312-cp312-manylinux_2_17_x86_64.whl": "2.1.0",
		"pkg-1.0-py2.7.egg":                                 "",
		"broken.whl":                                        "",
	} {
		if got := pypiFileVersion(name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
}

// simpleJSON is a PEP 691 index whose last release dropped provenance.
const simpleJSON = `{"meta":{"api-version":"1.4"},"name":"oldpkg",
 "project-status":{"status":"archived","reason":"Moved to newpkg"},
 "files":[
  {"filename":"oldpkg-0.7.tar.gz","upload-time":"2026-01-01T00:00:00Z","provenance":"https://pypi.org/integrity/oldpkg/0.7/oldpkg-0.7.tar.gz/provenance"},
  {"filename":"oldpkg-0.8.tar.gz","upload-time":"2026-02-01T00:00:00Z","provenance":"https://pypi.org/integrity/oldpkg/0.8/oldpkg-0.8.tar.gz/provenance"},
  {"filename":"oldpkg-0.9.tar.gz","upload-time":"2026-03-01T00:00:00Z","provenance":"https://pypi.org/integrity/oldpkg/0.9/oldpkg-0.9.tar.gz/provenance"},
  {"filename":"oldpkg-1.0.tar.gz","upload-time":"2026-04-01T00:00:00Z","provenance":null}]}`

// TestRunPyPIReadsSimpleJSON drives the real provider: the simple index is
// asked for PEP 691 JSON, and one document yields both the project status and
// the provenance downgrade.
func TestRunPyPIReadsSimpleJSON(t *testing.T) {
	mux := pypiStub("")
	var accept string
	mux.HandleFunc("/simple/jsonpkg/", func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
		_, _ = w.Write([]byte(strings.ReplaceAll(simpleJSON, "oldpkg", "jsonpkg")))
	})
	mux.HandleFunc("/pypi/jsonpkg/1.0/json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"info":{"name":"jsonpkg","version":"1.0","yanked":false},"urls":[]}`)
	})
	mux.HandleFunc("/pypi/jsonpkg/json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"info":{"version":"1.0"},"releases":{"1.0":[{"upload_time_iso_8601":"2026-04-01T00:00:00Z"}]}}`)
	})
	pr := runStub(t, mux, "pypi", "jsonpkg", "1.0")
	if !strings.Contains(accept, "application/vnd.pypi.simple.v1+json") {
		t.Errorf("simple index asked for %q, want PEP 691 JSON", accept)
	}
	if pr.Release == nil || pr.Release.Deprecated != "project status: archived: Moved to newpkg" {
		t.Errorf("project status from JSON: %+v", pr.Release)
	}
	if pr.SupplyChain == nil || pr.SupplyChain.ProvenanceDowngrade == nil ||
		pr.SupplyChain.ProvenanceDowngrade.LastAttestedVersion != "0.9" {
		t.Fatalf("no provenance downgrade for 1.0: %+v", pr.SupplyChain)
	}
}

// TestRunPyPIHTMLIndexInfersNoDowngrade: an index that answers HTML still
// gives the status, and never a downgrade — HTML carries no provenance, so
// every release would otherwise look unattested.
func TestRunPyPIHTMLIndexInfersNoDowngrade(t *testing.T) {
	pr := runStub(t, pypiStub(`<meta name="pypi:project-status" content="deprecated">`), "pypi", "oldpkg", "1.0")
	if pr.Release == nil || pr.Release.Deprecated != "project status: deprecated" {
		t.Errorf("status from HTML: %+v", pr.Release)
	}
	if pr.SupplyChain != nil && pr.SupplyChain.ProvenanceDowngrade != nil {
		t.Fatalf("HTML index produced a downgrade: %+v", pr.SupplyChain.ProvenanceDowngrade)
	}
}
