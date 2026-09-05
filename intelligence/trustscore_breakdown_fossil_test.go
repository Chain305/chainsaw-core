package intelligence

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// P9F-307 / F-03. `SupplyChainSection.TrustScoreBreakdown` was a string
// holding JSON-encoded JSON, so every intelligence Report served by
// /api/admin/intelligence/inspect and the /api/v1/intel/* family carried
// a nested-escaped blob:
//
//	"supplyChain":{"trustScore":96,"trustScoreBreakdown":"{\"malwareCheck\":0,…}"}
//
// The audit that retired it (2026-09-04) found exactly one writer
// (ComputeTrustScoreForOrg, core/intelligence/trustscore.go), one
// plumbing copy (mergeSupplyChain, scanner.go) and ZERO readers:
//
//   - `package_metadata.trust_score_breakdown` was DROPPED from the schema
//     by F-02 (core/pgstore/migrate.go), and had had no writer since
//     d625ef0e (2026-04-24) long before that.
//   - No Go caller ever read the field back — not the policy evaluator
//     (ToLegacyCheckResult builds trustscore.Score with Total only and
//     leaves Breakdown zero), not the CLI, not MCP, not BOM/SBOM export.
//   - No UI caller: the only component that could render the shape,
//     components/dashboard/trust-score-breakdown.tsx, was reachable solely
//     through an EMPTY named import (`import { } from …`) on the packages
//     page, whose "Score breakdown" block is hardcoded to its empty state.
//   - No API contract: the key appears in neither docs/api/openapi.yaml
//     nor internal/server/docs/openapi.yaml, and in no generated TS type.
//
// So it was written on every scan and read by nothing. Deleting the field
// is what these tests pin. Two independent guards, because each covers a
// way the fossil could come back that the other misses.
//
// NOT a migration: rows already persisted in `intelligence_reports.payload`
// still carry the `trustScoreBreakdown` key inside their stored JSONB.
// Nothing rewrites them and nothing needs to — Go ignores unknown keys on
// unmarshal, so the stale key is inert on read and simply stops being
// re-emitted the next time a report is marshalled.
//
// The legacy per-signal blend itself is NOT deleted: trustscore.Compute
// still runs (its Total is the defensive fallback when risk-V2 returns no
// evaluation) and core/trustscore/score_test.go still covers the signal
// contributions directly. What is gone is the projection of that blend
// onto the served Report, which contradicted the risk-V2 `trustScore`
// sitting beside it — see TestLegacyBreakdownNotPairedWithV2Score in
// internal/server for the ordering inversion that made the pairing false.

// TestReportJSONHasNoTrustScoreBreakdown is the behavioural half: run the
// real scoring path over a populated report and assert the wire payload
// never grows the key back.
func TestReportJSONHasNoTrustScoreBreakdown(t *testing.T) {
	past := time.Now().Add(-200 * 24 * time.Hour)
	report := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "acme", Version: "1.2.3"},
		Release:  ReleaseSection{PublishedAt: &past},
		URLs:     URLSection{SourceRepoURL: "https://github.com/example/acme"},
		Artifact: ArtifactSection{Digests: ArtifactDigest{SHA256: "deadbeef", Verified: true}},
		Metadata: MetadataSection{LicenseExpression: "MIT"},
		Provenance: ProvenanceSection{
			Status: "verified", Available: true, Verified: true, SLSALevel: 3,
		},
		SupplyChain: SupplyChainSection{
			MalwareStatus:   "clean",
			TyposquatStatus: "clean",
			RepoLinkStatus:  "ok",
		},
		Vulnerabilities: VulnSection{IsVulnerable: false},
		Scan:            ArtifactScanSection{Performed: true},
	}

	ComputeTrustScore(report)

	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	payload := string(raw)

	// Vacuity guard. `omitempty` means an absent key proves nothing unless
	// the sibling that IS live made it onto the wire — otherwise a report
	// that failed to score would pass this test for the wrong reason.
	if !strings.Contains(payload, `"trustScore":`) {
		t.Fatalf("report JSON carries no \"trustScore\" key — the scoring path did not run, "+
			"so the absence of \"trustScoreBreakdown\" below would be vacuous.\npayload: %s", payload)
	}
	if report.SupplyChain.TrustScore <= 0 {
		t.Fatalf("expected a positive risk-V2 trustScore for this clean package, got %d",
			report.SupplyChain.TrustScore)
	}

	if strings.Contains(payload, "trustScoreBreakdown") {
		t.Errorf("report JSON emits \"trustScoreBreakdown\".\n" +
			"That field was a JSON-encoded JSON string with a writer and no readers, " +
			"and it contradicted the risk-V2 \"trustScore\" beside it. If a consumer " +
			"genuinely needs the per-signal legacy blend, serve it as a STRUCTURED " +
			"object (or json.RawMessage) under its own name — never as escaped JSON " +
			"inside JSON, and never adjacent to the v2 composite it disagrees with.")
	}

	// The unmarshal direction must stay tolerant: rows persisted before
	// the removal still carry the key, and decoding one must not error.
	legacy := []byte(`{"supplyChain":{"trustScore":42,` +
		`"trustScoreBreakdown":"{\"malwareCheck\":0,\"installScript\":-20}"}}`)
	var decoded Report
	if err := json.Unmarshal(legacy, &decoded); err != nil {
		t.Fatalf("decoding a pre-removal payload must not fail (stored JSONB still "+
			"carries the key; nothing rewrites those rows): %v", err)
	}
	if decoded.SupplyChain.TrustScore != 42 {
		t.Errorf("sibling field lost on decode of a legacy payload: trustScore = %d, want 42",
			decoded.SupplyChain.TrustScore)
	}
}

// TestNoGoSourceCarriesTrustScoreBreakdown is the structural half.
//
// The behavioural test above only proves the key is absent from what
// ComputeTrustScore produces. Someone could reintroduce the field on a
// path that test does not exercise — a provider, the merge helper, a new
// adapter — and it would stay green. This walks the two modules' non-test
// Go sources instead, so any reintroduction anywhere fails.
//
// Scoped to non-test files deliberately: internal/server's
// trustscore_copy_guard_test.go names the identifier as a string literal
// (it is a source guard banning the RENDER from three UI/CLI files, and it
// stays valuable), and this file names it in prose.
func TestNoGoSourceCarriesTrustScoreBreakdown(t *testing.T) {
	root := repoRootForFossilGuard(t)
	if root == "" {
		t.Skip("repo root not locatable (vendored/extracted build)")
	}

	var scanned int
	var offenders []string

	for _, mod := range []string{"core", "internal", "cmd"} {
		base := filepath.Join(root, mod)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if name := d.Name(); name == "testdata" || name == "vendor" || name == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			scanned++
			src := string(raw)
			if !strings.Contains(src, "TrustScoreBreakdown") && !strings.Contains(src, "trustScoreBreakdown") {
				return nil
			}
			// A bare mention in a comment is allowed — the tombstone
			// comments explaining WHY the field is gone are the point.
			// Parse and look for a real declaration or reference instead.
			if identifierIsLiveInGoSource(src) {
				rel, _ := filepath.Rel(root, path)
				offenders = append(offenders, rel)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}

	// Vacuity: a walk that visited nothing reports zero offenders and
	// looks exactly like a pass. This is the failure mode CLAUDE.md calls
	// out — "a guard that cannot run is not a guard".
	if scanned < 500 {
		t.Fatalf("only %d non-test .go files scanned — the walk did not reach the tree, "+
			"so a clean result here means nothing", scanned)
	}

	for _, f := range offenders {
		t.Errorf("%s declares or references TrustScoreBreakdown / trustScoreBreakdown in code.\n"+
			"The field was retired 2026-09-04 (P9F-307): one writer, zero readers, no column, "+
			"no OpenAPI entry, no UI consumer. Reintroducing it re-adds a JSON-encoded JSON "+
			"string to every served report. If the legacy per-signal blend must be exposed, "+
			"give it a structured type under its own name — do not revive this one.", f)
	}
}

// identifierIsLiveInGoSource reports whether the fossil name appears
// outside comments. Comment-only mentions (the tombstones) are fine;
// a field, assignment, selector, or string literal is not.
func identifierIsLiveInGoSource(src string) bool {
	fset := token.NewFileSet()
	// ParseComments so comment text is attached to the CommentMap rather
	// than inspected as code. On a parse error, fall back to "live" — an
	// unparseable file must not silently exempt itself.
	file, err := parser.ParseFile(fset, "x.go", src, parser.ParseComments)
	if err != nil {
		return true
	}
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		if found {
			return false
		}
		switch v := n.(type) {
		case *ast.Ident:
			if v.Name == "TrustScoreBreakdown" || v.Name == "trustScoreBreakdown" {
				found = true
			}
		case *ast.BasicLit:
			if v.Kind == token.STRING &&
				(strings.Contains(v.Value, "TrustScoreBreakdown") ||
					strings.Contains(v.Value, "trustScoreBreakdown")) {
				found = true
			}
		}
		return !found
	})
	return found
}

// repoRootForFossilGuard walks up from the package directory until it
// finds go.work (the two-module root), returning "" when it cannot.
func repoRootForFossilGuard(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		return ""
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}
