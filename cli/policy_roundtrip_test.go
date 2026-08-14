package cli

// policy_roundtrip_test.go covers Y1: `policy export --output policies.json`
// with no --format writes YAML (--format defaults to "yaml" and the output
// extension is never consulted), and `policy import` used to pick its decoder
// from that same extension — `.json` → json.Unmarshal, no fallback. The one
// combination a user is most likely to produce was therefore the one that could
// not be re-imported.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func newPolicyExportCmdForTest() *cobra.Command {
	c := &cobra.Command{Use: "export", RunE: runPolicyExport, SilenceUsage: true}
	c.Flags().String("format", "yaml", "")
	c.Flags().String("output", "", "")
	return c
}

// policyListServer serves GET /api/policies with one policy and accepts every
// POST /api/policies, recording the bodies it was handed.
func policyListServer(t *testing.T, created *[]map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if created != nil {
				*created = append(*created, body)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"policy": policyItem{ID: "pol-new"}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"policies":[{"id":"pol-1","name":"block-criticals","mode":"block","status":"active"}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestPolicyExportImport_RoundTripsThroughJSONExtension is the Y1 regression.
// export --output policies.json (no --format) → import policies.json must work.
func TestPolicyExportImport_RoundTripsThroughJSONExtension(t *testing.T) {
	var created []map[string]any
	srv := policyListServer(t, &created)
	setViperServer(t, srv.URL)

	path := filepath.Join(t.TempDir(), "policies.json")

	exp := newPolicyExportCmdForTest()
	exp.SetArgs([]string{"--output", path})
	var expBuf bytes.Buffer
	exp.SetOut(&expBuf)
	exp.SetErr(&expBuf)
	if err := exp.Execute(); err != nil {
		t.Fatalf("export: %v\n%s", err, expBuf.String())
	}

	// Sanity: the file really does hold YAML despite its .json name — that is
	// the export-side half of the defect this test pins.
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("read export: %v", rerr)
	}
	if json.Valid(data) {
		t.Skip("export now writes real JSON into a .json file; the import-tolerance case below no longer applies")
	}

	imp := newPolicyImportCmdForTest()
	imp.SetArgs([]string{path})
	var impBuf bytes.Buffer
	imp.SetOut(&impBuf)
	imp.SetErr(&impBuf)
	if err := imp.Execute(); err != nil {
		t.Fatalf("re-importing chainsaw's own export failed: %v\n%s", err, impBuf.String())
	}
	if len(created) != 1 {
		t.Fatalf("expected 1 policy POSTed, got %d", len(created))
	}
	if created[0]["name"] != "block-criticals" {
		t.Fatalf("imported policy lost its fields: %#v", created[0])
	}
}

// TestPolicyImport_AcceptsRealJSONInAYAMLFile is the mirror case: a .yaml file
// holding genuine JSON. yaml.Unmarshal is a superset decoder, so both survive.
func TestPolicyImport_AcceptsRealJSONInAYAMLFile(t *testing.T) {
	var created []map[string]any
	srv := policyListServer(t, &created)
	setViperServer(t, srv.URL)

	file := writeTempPolicyFile(t, "policies.yaml", `[{"name":"a","mode":"block"}]`)
	cmd := newPolicyImportCmdForTest()
	cmd.SetArgs([]string{file})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("JSON in a .yaml file should import, got: %v\n%s", err, buf.String())
	}
	if len(created) != 1 {
		t.Fatalf("expected 1 policy POSTed, got %d", len(created))
	}
}

// TestPolicyImport_MalformedFileStillErrors is the must-not-regress guard: a
// tolerant decoder must not become a silent one, and the message keeps the
// filename so the user knows which input is bad.
func TestPolicyImport_MalformedFileStillErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("server must not be hit for an unparseable file")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	file := writeTempPolicyFile(t, "broken.json", "{{{ not a policy list at all ][")
	cmd := newPolicyImportCmdForTest()
	cmd.SetArgs([]string{file})
	cmd.SilenceErrors = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("malformed file must error; out: %s", buf.String())
	}
	if !strings.Contains(err.Error(), "broken.json") {
		t.Fatalf("parse error should name the file, got: %v", err)
	}
}

// TestPolicyExport_WarnsWhenExtensionContradictsFormat covers the advisory
// half: the file is still written (and now still importable), but chainsaw says
// out loud that .json is about to receive YAML.
func TestPolicyExport_WarnsWhenExtensionContradictsFormat(t *testing.T) {
	srv := policyListServer(t, nil)
	setViperServer(t, srv.URL)

	path := filepath.Join(t.TempDir(), "policies.json")
	cmd := newPolicyExportCmdForTest()
	cmd.SetArgs([]string{"--output", path})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("export: %v", err)
	}
	if !strings.Contains(errb.String(), "--format json") {
		t.Fatalf("export to a .json file while serializing YAML should warn on stderr; got %q", errb.String())
	}

	// Matching extension + format: silent.
	yamlPath := filepath.Join(t.TempDir(), "policies.yaml")
	quiet := newPolicyExportCmdForTest()
	quiet.SetArgs([]string{"--output", yamlPath})
	var qout, qerr bytes.Buffer
	quiet.SetOut(&qout)
	quiet.SetErr(&qerr)
	if err := quiet.Execute(); err != nil {
		t.Fatalf("export: %v", err)
	}
	if strings.Contains(qerr.String(), "--format") {
		t.Fatalf("matching extension must not warn; got %q", qerr.String())
	}
}
