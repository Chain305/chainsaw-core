package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestConditionSurfaceDriftBillyMCP guards the two user-facing surfaces
// that advertise the policy Conditions schema:
//
//  1. Billy's system prompt (internal/billy/agent.go) — Billy needs to
//     know every condition key so it can draft correct policies from
//     natural-language requests.
//  2. The MCP propose_policy / simulate_policy input schemas
//     (internal/server/server_mcp.go) — agents calling these tools need
//     to know every condition key.
//
// When a new Conditions field is added, both surfaces must be updated
// in the same PR or this test fails with a precise per-surface list.
// Modeled on TestSupportMatrixMatchesMarkdown — reflection over the
// source of truth, substring check against the downstream surfaces.
func TestConditionSurfaceDriftBillyMCP(t *testing.T) {
	keys := conditionJSONKeys(t)
	if len(keys) == 0 {
		t.Fatal("no Conditions fields found — struct reflection broke")
	}

	billySource := readFileAbove(t, filepath.Join("internal", "billy", "agent.go"))
	mcpSource := readFileAbove(t, filepath.Join("internal", "server", "server_mcp.go"))

	// Narrow the check to the two MCP tool registrations so a stray
	// mention elsewhere in the file can't satisfy the drift test.
	proposeBlock := extractToolRegistration(t, mcpSource, "propose_policy")
	simulateBlock := extractToolRegistration(t, mcpSource, "simulate_policy")

	var missingBilly, missingPropose, missingSimulate []string
	for _, key := range keys {
		if !strings.Contains(billySource, key) {
			missingBilly = append(missingBilly, key)
		}
		if !strings.Contains(proposeBlock, key) {
			missingPropose = append(missingPropose, key)
		}
		if !strings.Contains(simulateBlock, key) {
			missingSimulate = append(missingSimulate, key)
		}
	}

	if len(missingBilly) == 0 && len(missingPropose) == 0 && len(missingSimulate) == 0 {
		return
	}

	t.Errorf("policy.Conditions field drift detected — every JSON-tagged field on policy.Conditions must appear in Billy's system prompt AND in the MCP propose_policy/simulate_policy schemas.")
	if len(missingBilly) > 0 {
		t.Errorf("  missing from internal/billy/agent.go (system prompt): %v", missingBilly)
	}
	if len(missingPropose) > 0 {
		t.Errorf("  missing from internal/server/server_mcp.go propose_policy schema: %v", missingPropose)
	}
	if len(missingSimulate) > 0 {
		t.Errorf("  missing from internal/server/server_mcp.go simulate_policy schema: %v", missingSimulate)
	}
}

// conditionJSONKeys returns the JSON tag (minus ",omitempty" and any
// other options) for every exported field of policy.Conditions.
func conditionJSONKeys(t *testing.T) []string {
	t.Helper()
	typ := reflect.TypeOf(Conditions{})
	out := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		// json tag is "name,opts,..." — take only "name".
		if comma := strings.Index(tag, ","); comma >= 0 {
			tag = tag[:comma]
		}
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		out = append(out, tag)
	}
	return out
}

// readFileAbove walks up from the test's working directory looking for
// a file at the relative path. Mirrors findMatrixMarkdown so the test
// works whether `go test` is run from the package dir or the repo root.
func readFileAbove(t *testing.T, rel string) string {
	t.Helper()
	start, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := start
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, rel)
		if data, err := os.ReadFile(candidate); err == nil {
			return string(data)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	// Monorepo-only consistency check: this reads enterprise sources
	// (internal/billy/agent.go, internal/server/server_mcp.go) that do not exist
	// in the standalone chainsaw-core checkout. Skip rather than fail there.
	t.Skipf("%s not found above %s — monorepo-only consistency check", rel, start)
	return ""
}

// extractToolRegistration returns the substring of src that covers the
// MCP tool registration named toolName. We locate the literal
// `Name: "<toolName>"` and then walk forward until brace depth returns
// to zero, which is the end of the mcp.Tool{...} literal. This scopes
// the condition-key check to the right tool so an unrelated mention of
// "isVulnerable" elsewhere in the file can't satisfy the test.
func extractToolRegistration(t *testing.T, src, toolName string) string {
	t.Helper()
	marker := `Name: "` + toolName + `"`
	idx := strings.Index(src, marker)
	if idx < 0 {
		t.Fatalf("could not find tool registration for %q in server_mcp.go", toolName)
	}
	// Walk backwards a little to include the `mcp.Tool{` header — not
	// strictly required for the substring check but keeps the slice
	// self-describing if the test ever dumps it on failure.
	start := idx
	for start > 0 && src[start] != '{' {
		start--
	}
	depth := 0
	for i := start; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[start : i+1]
			}
		}
	}
	t.Fatalf("unbalanced braces while scanning %q tool registration", toolName)
	return ""
}
