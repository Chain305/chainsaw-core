package intelligence

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/coverage"
)

// codeLiteral matches `Code: "some_code"` in the provider sources.
var codeLiteral = regexp.MustCompile(`Code:\s*"([a-z0-9_]+)"`)

// TestEveryEmittedWarnCodeIsClassified fails when a provider emits a warn code
// that coverage.StatusForWarnCode does not explicitly recognise.
//
// Unrecognised codes classify as StatusError, which never blocks — safe, but
// it means a genuine outage in a new provider would silently stop counting as
// unavailable. Adding a code must therefore be a deliberate act: classify it
// in core/coverage/status.go, or add it to knownUnclassified below with a
// reason.
func TestEveryEmittedWarnCodeIsClassified(t *testing.T) {
	// Codes deliberately left to the StatusError default, with why.
	knownUnclassified := map[string]string{
		"namespace_extracted": "informational, not a failure",
		"decode":              "malformed upstream payload — our parse path, not an outage",
		"request_build":       "we built a bad request — our bug",
		"parse_failed":        "the explicit our-bug code",
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range codeLiteral.FindAllStringSubmatch(string(src), -1) {
			seen[m[1]] = true
		}
	}
	if len(seen) == 0 {
		t.Fatal("scanned no warn codes — the regex or the package layout changed")
	}
	for raw := range seen {
		if _, ok := knownUnclassified[raw]; ok {
			continue
		}
		if coverage.StatusForWarnCode(raw) == coverage.StatusError {
			t.Errorf("warn code %q is emitted by a provider but not classified in "+
				"core/coverage/status.go — classify it, or add it to knownUnclassified "+
				"with a reason", raw)
		}
	}
}
