package cli

// policy_dsl_input_fidelity_test.go — the anti-drift invariant for
// `chainsaw policy gate`.
//
// This is deliberately NOT a coverage check on a named translation
// function. It asserts a PROPERTY of the command: whatever policy.Input
// the operator writes in the fixture is the policy.Input the Rego bundle
// evaluates, field for field, with only `surface` stamped by the
// subcommand argument. Phrased that way it survived the deletion of
// cli.inputToContext (the hand-maintained Input→EvaluationContext copy
// that had silently fallen three fields behind: signalsUnavailable,
// releaseDate, buildRsExecutes) and it fails again the moment anybody
// reintroduces a copy layer anywhere between readInputFixture and OPA.
//
// The fixture is populated by reflection, so a field added to
// policy.Input tomorrow is covered without editing this file.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/policy"
	"github.com/chain305/chainsaw-core/policyengine"
)

// echoInputRego emits one monitor violation whose message is the JSON
// serialization of the document OPA actually received. That makes the
// input observable from outside the process without adding a test-only
// seam to the command, which is the point: a seam could itself drift.
//
// monitor (not block) so runPolicyGate does not os.Exit(1) mid-test.
const echoInputRego = `package chainsaw.policy

decision contains d if {
	d := {
		"rule_id": "echo-input",
		"action": "monitor",
		"message": json.marshal(input),
	}
}
`

// populateEveryField fills every exported field of a struct with a
// distinct non-zero value. Distinctness is load-bearing: a copy layer
// that assigns the right TYPE to the wrong field (a real class of
// hand-maintained-mapping bug) survives an "everything is true" fixture
// and dies on this one.
func populateEveryField(t *testing.T, v reflect.Value) {
	t.Helper()
	typ := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if !f.CanSet() {
			continue
		}
		name := typ.Field(i).Name
		switch f.Kind() {
		case reflect.String:
			// SetString works through a named string type (SurfaceTag).
			f.SetString("val-" + name)
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			f.SetInt(int64(i + 1))
		case reflect.Float32, reflect.Float64:
			// Halves are exactly representable, so the JSON round trip
			// through OPA's number handling is bit-for-bit.
			f.SetFloat(float64(i) + 0.5)
		case reflect.Slice:
			if f.Type().Elem().Kind() != reflect.String {
				t.Fatalf("policy.Input.%s: unhandled slice element kind %v — extend populateEveryField", name, f.Type().Elem().Kind())
			}
			f.Set(reflect.ValueOf([]string{name + "-a", name + "-b"}))
		case reflect.Pointer:
			if f.Type().Elem().Kind() != reflect.Bool {
				t.Fatalf("policy.Input.%s: unhandled pointer element kind %v — extend populateEveryField", name, f.Type().Elem().Kind())
			}
			b := true
			f.Set(reflect.ValueOf(&b))
		default:
			t.Fatalf("policy.Input.%s: unhandled kind %v — extend populateEveryField so the invariant keeps covering every field", name, f.Kind())
		}
	}
}

// newGateTestCmd mirrors the flag set policyGateCmd registers, so the
// test drives runPolicyGate through the same flag lookups the real
// command does.
func newGateTestCmd(buf *bytes.Buffer, bundle, input string) *cobra.Command {
	cmd := &cobra.Command{Use: "gate"}
	cmd.Flags().String("bundle", bundle, "")
	cmd.Flags().String("input", input, "")
	cmd.Flags().Bool("json", true, "")
	cmd.Flags().String("format", "table", "")
	cmd.Flags().String("output", "", "")
	_ = cmd.Flags().Set("json", "true")
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	return cmd
}

// TestPolicyGateInputFidelity is the invariant: the input OPA evaluates
// under `policy gate` equals the fixture, modulo the stamped surface.
func TestPolicyGateInputFidelity(t *testing.T) {
	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "bundle")
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatalf("mkdir bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "echo.rego"), []byte(echoInputRego), 0o644); err != nil {
		t.Fatalf("write rego: %v", err)
	}

	var want policy.Input
	populateEveryField(t, reflect.ValueOf(&want).Elem())

	fixture, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	inputPath := filepath.Join(dir, "input.json")
	if err := os.WriteFile(inputPath, fixture, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var buf bytes.Buffer
	cmd := newGateTestCmd(&buf, bundleDir, inputPath)
	if err := runPolicyGate(cmd, []string{"publish"}); err != nil {
		t.Fatalf("policy gate: %v\n%s", err, buf.String())
	}

	var dec policyengine.Decision
	if err := json.Unmarshal(buf.Bytes(), &dec); err != nil {
		t.Fatalf("decode decision: %v\nraw:\n%s", err, buf.String())
	}
	if len(dec.Violations) != 1 {
		t.Fatalf("expected exactly one echoed violation, got %d: %+v", len(dec.Violations), dec.Violations)
	}

	var got policy.Input
	if err := json.Unmarshal([]byte(dec.Violations[0].Message), &got); err != nil {
		t.Fatalf("decode echoed input: %v\nmessage:\n%s", err, dec.Violations[0].Message)
	}

	// `surface` is the one field gate legitimately owns: it comes from
	// the subcommand argument, not the fixture.
	if got.Surface != policy.SurfacePublish {
		t.Errorf("surface = %q, want %q (gate must stamp the surface it was invoked for)", got.Surface, policy.SurfacePublish)
	}
	got.Surface = want.Surface

	if !reflect.DeepEqual(got, want) {
		t.Errorf("the input OPA evaluated is not the input the fixture declared.\n%s", diffInputFields(want, got))
	}
}

// diffInputFields names the fields that failed to survive the trip, so a
// reintroduced copy layer reports exactly which fields it forgot rather
// than dumping two 60-field structs.
func diffInputFields(want, got policy.Input) string {
	wv := reflect.ValueOf(want)
	gv := reflect.ValueOf(got)
	typ := wv.Type()
	var b strings.Builder
	for i := 0; i < wv.NumField(); i++ {
		w := wv.Field(i).Interface()
		g := gv.Field(i).Interface()
		if reflect.DeepEqual(w, g) {
			continue
		}
		fmt.Fprintf(&b, "  %s: fixture=%v evaluated=%v\n", typ.Field(i).Name, deref(w), deref(g))
	}
	if b.Len() == 0 {
		return "  (no field-level difference — check for a type-level mismatch)\n"
	}
	return b.String()
}

func deref(v any) any {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return "<nil>"
		}
		return rv.Elem().Interface()
	}
	return v
}
