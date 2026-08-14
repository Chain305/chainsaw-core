package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

const diffBOMA = `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[
  {"type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"},
  {"type":"library","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}]}`

const diffBOMB = `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[
  {"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"},
  {"type":"library","name":"chalk","version":"5.3.0","purl":"pkg:npm/chalk@5.3.0"}]}`

func writeBOM(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// runSBOMDiffJSON drives the real command through a fresh cobra command so the
// --format/--output flags resolve exactly as they do in production.
func runSBOMDiffJSON(t *testing.T, a, b string) map[string]any {
	t.Helper()
	cmd := &cobra.Command{RunE: sbomDiffCmd.RunE}
	cmd.Flags().String("format", "json", "")
	cmd.Flags().String("output", "", "")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := cmd.RunE(cmd, []string{a, b}); err != nil {
		t.Fatalf("sbom diff: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	return got
}

// TestSBOMDiffJSON_KeysAreLowercaseAndVersioned pins the published machine
// contract. Before this, `sbom diff --format json` serialized the bare Go
// struct, so the documented machine format emitted Go-style capitalized keys —
// "Added", "Name", "OldVersion" — unlike every other machine format the CLI
// emits, and with no schemaVersion for a consumer to pin.
func TestSBOMDiffJSON_KeysAreLowercaseAndVersioned(t *testing.T) {
	dir := t.TempDir()
	got := runSBOMDiffJSON(t,
		writeBOM(t, dir, "a.json", diffBOMA),
		writeBOM(t, dir, "b.json", diffBOMB))

	if got["schemaVersion"] != sbomDiffSchemaVersion {
		t.Errorf("schemaVersion = %v, want %q", got["schemaVersion"], sbomDiffSchemaVersion)
	}
	for _, k := range []string{"added", "removed", "changed"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing top-level key %q; got %v", k, keysOf(got))
		}
	}
	// The exact regression: capitalized Go field names must not appear.
	for _, k := range []string{"Added", "Removed", "Changed", "SchemaVersion"} {
		if _, ok := got[k]; ok {
			t.Errorf("capitalized key %q present — the struct is being serialized without json tags", k)
		}
	}

	added, _ := got["added"].([]any)
	if len(added) != 1 {
		t.Fatalf("added = %v, want exactly chalk", added)
	}
	comp, _ := added[0].(map[string]any)
	for _, k := range []string{"name", "version", "type", "ecosystem", "purl"} {
		if _, ok := comp[k]; !ok {
			t.Errorf("component missing lowercase key %q; got %v", k, keysOf(comp))
		}
	}
	if comp["Name"] != nil {
		t.Errorf("component carries capitalized \"Name\"")
	}

	changed, _ := got["changed"].([]any)
	if len(changed) != 1 {
		t.Fatalf("changed = %v, want exactly lodash", changed)
	}
	ch, _ := changed[0].(map[string]any)
	if ch["oldVersion"] != "4.17.20" || ch["newVersion"] != "4.17.21" {
		t.Errorf("change = %v, want oldVersion 4.17.20 -> newVersion 4.17.21", ch)
	}
}

// TestSBOMDiffJSON_EmptyDiffEmitsArraysNotNull covers the most common outcome
// of a diff. `"added": null` forces every consumer to special-case the
// no-difference case before iterating.
func TestSBOMDiffJSON_EmptyDiffEmitsArraysNotNull(t *testing.T) {
	dir := t.TempDir()
	same := writeBOM(t, dir, "same.json", diffBOMA)
	got := runSBOMDiffJSON(t, same, same)

	for _, k := range []string{"added", "removed", "changed"} {
		v, ok := got[k]
		if !ok {
			t.Fatalf("missing key %q", k)
		}
		if v == nil {
			t.Errorf("%q is null; want an empty array so consumers can iterate unconditionally", k)
			continue
		}
		if arr, ok := v.([]any); !ok || len(arr) != 0 {
			t.Errorf("%q = %v, want []", k, v)
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
