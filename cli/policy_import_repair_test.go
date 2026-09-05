package cli

// policy_import_repair_test.go covers P9F-UD-05, the residual left behind by
// B7 (commit 72445469). B7 fixed `policy export --format yaml` so int64
// precedence is no longer rendered as a float. It did nothing for the export
// files users already hold, and the ledger's claim about what happens to those
// files is WRONG in the direction that matters:
//
//	B7 / P9F-051 said: "the re-import POSTed a float the server's
//	`Precedence int` rejects" — i.e. the row is skipped.
//
// It is not rejected. yaml.v3 decodes `-1.7874035210424883e+18` to float64;
// encoding/json marshals that float64 back as the plain integer literal
// `-1787403521042488300` (Go only uses exponent form for |v| >= 1e21, and no
// int64 reaches 1e21), and `json.Unmarshal` into an `int` field accepts a JSON
// number with no fraction and no exponent. So the server takes the row and
// stores a precedence that is 124 away from the one that was exported. The
// failure mode is silent CORRUPTION of policy ordering, not a skipped row —
// strictly worse than the documented one, and invisible to the user.
//
// float64 round-trip evidence (measured with go run, Go 1.25.4, darwin/arm64;
// IEEE-754 binary64 so platform-independent):
//
//	original int64          : -1787403521042488196
//	yaml float64            : -1.7874035210424883e+18
//	exact value of that f64 : -1787403521042488320   (int64(f))
//	shortest decimal for it : -1787403521042488300   (what encoding/json writes)
//	int64(f) == original    : false   (delta -124)
//	f == math.Trunc(f)      : true    (it IS integral — "integral" proves nothing)
//	float64(original) == f  : true    (the original maps INTO this float…)
//	ulp at this magnitude   : 256     (…and so do 255 other int64 values)
//
// The value is integral yet unrecoverable: 256 distinct int64 precedences all
// encode to this one float64. Recovering "the" integer would fabricate an
// id-like number the user never wrote. So the honest behaviour is to refuse
// the row with an actionable error — never to guess, and never to let it
// through silently.

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// preFixExportYAML is a verbatim-shaped `policy export --format yaml` file as
// produced before 72445469: precedence rendered in float notation.
const preFixExportYAML = `- id: pol-1
  name: lowest
  mode: block
  status: active
  precedence: -1.7874035210424883e+18
`

// postFixExportYAML is the same export taken after 72445469.
const postFixExportYAML = `- id: pol-1
  name: lowest
  mode: block
  status: active
  precedence: -1787403521042488196
`

// recordingPolicyPostServer accepts every POST /api/policies and records the
// raw request bytes. Raw bytes, not a decoded map: decoding into `any` would
// itself route the number through float64 and hide the very defect under test.
func recordingPolicyPostServer(t *testing.T, posted *[][]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if posted != nil {
			*posted = append(*posted, body)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"policy": policyItem{ID: "pol-new"}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestFloat64CannotRecoverInt64Precedence pins the arithmetic the refusal is
// built on, so nobody "improves" the refusal into a silent repair later.
func TestFloat64CannotRecoverInt64Precedence(t *testing.T) {
	const original int64 = -1787403521042488196

	var decoded []map[string]any
	if err := yaml.Unmarshal([]byte(preFixExportYAML), &decoded); err != nil {
		t.Fatalf("decode pre-fix export: %v", err)
	}
	f, ok := decoded[0]["precedence"].(float64)
	if !ok {
		t.Fatalf("pre-fix export must decode precedence as float64, got %T", decoded[0]["precedence"])
	}
	if f != math.Trunc(f) {
		t.Fatalf("the trap value is integral; being integral is exactly why a naive repair looks safe")
	}
	if float64(original) != f {
		t.Fatalf("the original int64 must map into this float64, else the premise is wrong")
	}
	if int64(f) == original {
		t.Fatalf("float64 round-tripped the int64 exactly — the residual would not exist; got %d", int64(f))
	}
	if got, want := int64(f), int64(-1787403521042488320); got != want {
		t.Fatalf("nearest double changed: got %d want %d", got, want)
	}
	if ulp := math.Nextafter(math.Abs(f), math.Inf(1)) - math.Abs(f); ulp != 256 {
		t.Fatalf("ulp at this magnitude changed: %v (256 int64 values share this float)", ulp)
	}
	// And the corruption really does reach the wire as a valid integer, which
	// is why the server never rejected it.
	wire, _ := json.Marshal(map[string]any{"precedence": f})
	if !bytes.Contains(wire, []byte(`-1787403521042488300`)) {
		t.Fatalf("encoding/json no longer emits the corrupted integer literal: %s", wire)
	}
	var srvSide struct {
		Precedence int `json:"precedence"`
	}
	if err := json.Unmarshal(wire, &srvSide); err != nil {
		t.Fatalf("server-side decode of the float-derived literal must SUCCEED (that is the bug): %v", err)
	}
	if srvSide.Precedence == int(original) {
		t.Fatalf("server would have stored the right value; premise wrong")
	}
}

// TestPolicyImport_RefusesPrecisionLostPrecedence is the P9F-UD-05 regression.
// Before the fix this POSTed -1787403521042488300 and reported success.
func TestPolicyImport_RefusesPrecisionLostPrecedence(t *testing.T) {
	var posted [][]byte
	srv := recordingPolicyPostServer(t, &posted)
	setViperServer(t, srv.URL)

	file := writeTempPolicyFile(t, "policies.yaml", preFixExportYAML)
	cmd := newPolicyImportCmdForTest()
	cmd.SetArgs([]string{file})
	cmd.SilenceErrors = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()

	if len(posted) != 0 {
		t.Fatalf("a precision-lost precedence must never reach the server; POSTed:\n%s", posted[0])
	}
	if err == nil {
		t.Fatalf("import of a pre-fix export must fail, not report success; out:\n%s", buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"policies.yaml",           // names the file
		"precedence",              // names the field
		"-1.7874035210424883e+18", // names the value as written
		"chainsaw policy export",  // names the fix
		"72445469",                // names the commit the file predates
		"-1787403521042488300",    // names what would actually have been stored
	} {
		if !strings.Contains(out, want) && !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal must mention %q; got err=%v out:\n%s", want, err, out)
		}
	}
	if strings.Contains(out, "-1787403521042488196") {
		t.Fatalf("must not claim to have recovered the original value; out:\n%s", out)
	}
	// The message must name the literal the SERVER would have stored (the
	// shortest decimal encoding/json emits), not the exact value of the double
	// (-1787403521042488320) — the user would never see that second number.
	if strings.Contains(out, "-1787403521042488320") {
		t.Fatalf("message names int64(f) rather than the wire literal; out:\n%s", out)
	}
}

// TestPolicyImport_PostFixIntegerPrecedenceUnchanged: a file taken after B7
// carries the literal integer and must import byte-for-byte unchanged. The
// refusal must not become a blanket ban on large precedences.
func TestPolicyImport_PostFixIntegerPrecedenceUnchanged(t *testing.T) {
	var posted [][]byte
	srv := recordingPolicyPostServer(t, &posted)
	setViperServer(t, srv.URL)

	file := writeTempPolicyFile(t, "policies.yaml", postFixExportYAML)
	cmd := newPolicyImportCmdForTest()
	cmd.SetArgs([]string{file})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("post-fix export must import: %v\n%s", err, buf.String())
	}
	if len(posted) != 1 {
		t.Fatalf("expected 1 POST, got %d", len(posted))
	}
	if want := `"precedence":-1787403521042488196`; !bytes.Contains(posted[0], []byte(want)) {
		t.Fatalf("want %s in body:\n%s", want, posted[0])
	}
}

// TestPolicyImport_FractionalPrecedenceStillErrors: a genuinely fractional
// value in an integer field is still an error, and is refused locally with a
// message about whole numbers rather than bounced off the server.
func TestPolicyImport_FractionalPrecedenceStillErrors(t *testing.T) {
	var posted [][]byte
	srv := recordingPolicyPostServer(t, &posted)
	setViperServer(t, srv.URL)

	file := writeTempPolicyFile(t, "policies.yaml", "- name: frac\n  mode: block\n  precedence: 1.5\n")
	cmd := newPolicyImportCmdForTest()
	cmd.SetArgs([]string{file})
	cmd.SilenceErrors = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err == nil {
		t.Fatalf("a fractional precedence must error; out:\n%s", buf.String())
	}
	if len(posted) != 0 {
		t.Fatalf("fractional precedence must not be POSTed:\n%s", posted[0])
	}
	if !strings.Contains(buf.String(), "whole number") {
		t.Fatalf("fractional refusal should say whole number; got:\n%s", buf.String())
	}
}

// TestPolicyImport_ExactIntegralFloatPrecedenceImports: below 2^53 every
// integer is exactly representable, so `precedence: 100.0` names exactly one
// integer and must still import. The guard keys on unrecoverability, not on
// "the YAML node happened to be a float".
func TestPolicyImport_ExactIntegralFloatPrecedenceImports(t *testing.T) {
	var posted [][]byte
	srv := recordingPolicyPostServer(t, &posted)
	setViperServer(t, srv.URL)

	file := writeTempPolicyFile(t, "policies.yaml", "- name: hundred\n  mode: block\n  precedence: 100.0\n")
	cmd := newPolicyImportCmdForTest()
	cmd.SetArgs([]string{file})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("an exactly-representable integral float must import: %v\n%s", err, buf.String())
	}
	if len(posted) != 1 {
		t.Fatalf("expected 1 POST, got %d", len(posted))
	}
	if want := `"precedence":100`; !bytes.Contains(posted[0], []byte(want)) {
		t.Fatalf("want %s in body:\n%s", want, posted[0])
	}
}

// TestPolicyImport_RefusalIsLoudOnPartialImport: the good rows still import,
// but the command must not exit 0 while a policy was dropped. Losing a row
// silently is the whole defect.
func TestPolicyImport_RefusalIsLoudOnPartialImport(t *testing.T) {
	var posted [][]byte
	srv := recordingPolicyPostServer(t, &posted)
	setViperServer(t, srv.URL)

	file := writeTempPolicyFile(t, "policies.yaml",
		"- name: good\n  mode: block\n  precedence: 10\n"+
			"- name: lowest\n  mode: block\n  precedence: -1.7874035210424883e+18\n")
	cmd := newPolicyImportCmdForTest()
	cmd.SetArgs([]string{file})
	cmd.SilenceErrors = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("a partially-refused import must exit non-zero; out:\n%s", buf.String())
	}
	if len(posted) != 1 {
		t.Fatalf("the good row should import and the bad row must not; POSTs=%d", len(posted))
	}
	if !strings.Contains(buf.String(), "lowest") {
		t.Fatalf("the refusal must name the policy that was dropped; out:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "✓") && !strings.Contains(err.Error(), "refused") {
		t.Fatalf("must not render as an unqualified success; out:\n%s", buf.String())
	}
}

// TestPolicyImport_DryRunReportsRefusal: --dry-run is the "will this work?"
// affordance; it must not answer "would import 1" for a file that cannot be
// imported.
func TestPolicyImport_DryRunReportsRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("dry-run must not hit the server")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	file := writeTempPolicyFile(t, "policies.yaml", preFixExportYAML)
	cmd := newPolicyImportCmdForTest()
	cmd.SetArgs([]string{file, "--dry-run"})
	cmd.SilenceErrors = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err == nil {
		t.Fatalf("dry-run over an unimportable file must report failure; out:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "72445469") {
		t.Fatalf("dry-run should explain the refusal; out:\n%s", buf.String())
	}
}

// TestPolicyExportJSON_Int64PrecedenceRoundTrips answers the "is --format json
// affected too?" half of P9F-UD-05: it is not, and this pins why. The JSON
// branch of `policy export` marshals `[]json.RawMessage` (policy.go:987), so
// the server's bytes are re-emitted verbatim and never pass through float64.
// The import then decodes with yaml.v3, which keeps the literal as an int. So
// a JSON export of the same policy round-trips exactly, before and after B7 —
// only the YAML branch ever lost precision.
func TestPolicyExportJSON_Int64PrecedenceRoundTrips(t *testing.T) {
	const precedence = "-1787403521042488196"

	var posted [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			posted = append(posted, body)
			_ = json.NewEncoder(w).Encode(map[string]any{"policy": policyItem{ID: "pol-new"}})
			return
		}
		_, _ = w.Write([]byte(`{"policies":[{"id":"pol-1","name":"lowest","mode":"block","status":"active","precedence":` + precedence + `}]}`))
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	path := filepath.Join(t.TempDir(), "policies.json")
	exp := newPolicyExportCmdForTest()
	exp.SetArgs([]string{"--format", "json", "--output", path})
	var expBuf bytes.Buffer
	exp.SetOut(&expBuf)
	exp.SetErr(&expBuf)
	if err := exp.Execute(); err != nil {
		t.Fatalf("export: %v\n%s", err, expBuf.String())
	}
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("read export: %v", rerr)
	}
	if !strings.Contains(string(data), precedence) {
		t.Fatalf("JSON export must carry the literal integer:\n%s", data)
	}

	imp := newPolicyImportCmdForTest()
	imp.SetArgs([]string{path})
	var impBuf bytes.Buffer
	imp.SetOut(&impBuf)
	imp.SetErr(&impBuf)
	if err := imp.Execute(); err != nil {
		t.Fatalf("re-import of a JSON export failed: %v\n%s", err, impBuf.String())
	}
	if len(posted) != 1 {
		t.Fatalf("expected 1 POST, got %d", len(posted))
	}
	if want := `"precedence":` + precedence; !bytes.Contains(posted[0], []byte(want)) {
		t.Fatalf("want %s in body:\n%s", want, posted[0])
	}
}
