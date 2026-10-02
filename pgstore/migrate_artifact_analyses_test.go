package pgstore

// Guards for the artifact_analyses migration (A-3).
//
// ensure*Schema helpers are NOT self-registering: the table exists only
// because ensureEnhancedColumns calls the helper. Deleting that one line
// leaves a green build, a green `go vet` and no table — and the only symptom
// in production is that no artifact analysis is ever reused, which looks like
// a cold cache rather than a defect. The AST guard below is the same shape as
// TestVerdictHistorySchemaIsWiredIntoMigrate, for the same reason.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"
)

func TestArtifactAnalysesSchemaIsWiredIntoMigrate(t *testing.T) {
	const file = "migrate_columns.go"
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	var fn *ast.FuncDecl
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if ok && fd.Name.Name == "ensureEnhancedColumns" && fd.Body != nil {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatal("ensureEnhancedColumns not found in migrate_columns.go: the migration " +
			"entry point moved; re-point this guard at its new home")
	}

	var called bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "ensureArtifactAnalysesSchema" {
			called = true
		}
		return true
	})
	if !called {
		t.Fatal("call site missing: ensureEnhancedColumns no longer calls " +
			"s.ensureArtifactAnalysesSchema(). Without it artifact_analyses is never " +
			"created, every reuse lookup and every write fails soft, and the build " +
			"stays green while no analysis is ever reused.")
	}
}

// TestEnsureArtifactAnalysesSchema_Idempotent is the DB half: running the
// helper twice must succeed, because Open() runs it on every boot.
func TestEnsureArtifactAnalysesSchema_Idempotent(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	store, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	for i := 0; i < 2; i++ {
		if err := store.ensureArtifactAnalysesSchema(); err != nil {
			t.Fatalf("ensureArtifactAnalysesSchema (run %d): %v", i+1, err)
		}
	}

	// The primary key IS the design: without analyzer_version in it, a version
	// bump would overwrite the previous generation instead of adding one, and
	// the selective backfill would have nothing to select on.
	rows, err := store.DB().Query(`
		SELECT a.attname
		  FROM pg_index i
		  JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
		 WHERE i.indrelid = 'artifact_analyses'::regclass AND i.indisprimary`)
	if err != nil {
		t.Fatalf("read primary key: %v", err)
	}
	defer func() { _ = rows.Close() }()

	got := map[string]bool{}
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			t.Fatalf("scan pk column: %v", err)
		}
		got[col] = true
	}
	// All FIVE. The cache is correct only if a row's content is a function of
	// everything in its key, and four cacheable analyzers take an input that
	// is neither the bytes nor their own version:
	//
	//	artifact_sha256   the bytes
	//	ecosystem         installscripts branches npm vs pip; capability picks
	//	                  a per-ecosystem scanner
	//	analyzer          scopes an upgrade to one detector
	//	analyzer_version  makes a bump ADD a generation, not replace one
	//	analyzer_config   the operator thresholds and the capability lane flag,
	//	                  which are unordered and so cannot live in the version
	want := []string{
		"artifact_sha256", "ecosystem", "analyzer", "analyzer_version", "analyzer_config",
	}
	for _, col := range want {
		if !got[col] {
			t.Errorf("primary key is missing %q (has %v). Every component is "+
				"load-bearing: a cacheable analyzer's output must be a function of the "+
				"whole key, or the first answer written is served forever and nothing "+
				"evicts it.", col, keysOfBool(got))
		}
	}
	if len(got) != len(want) {
		t.Errorf("primary key has %d columns (%v), want exactly %d (%v). An EXTRA "+
			"column is as wrong as a missing one: it splits rows that should share a "+
			"key and the cache simply never hits.", len(got), keysOfBool(got), len(want), want)
	}
	if len(got) == 0 {
		t.Fatal("artifact_analyses has no primary key columns, so the assertions above " +
			"checked nothing — the table was not created")
	}
}

func keysOfBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
