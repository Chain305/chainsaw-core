package policy

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSupportMatrixMatchesMarkdown parses POLICY_PROXY_MATRIX.md and asserts
// every (ecosystem, condition) cell agrees with SupportMatrix. If this fails,
// either the markdown or the Go struct drifted — update both.
func TestSupportMatrixMatchesMarkdown(t *testing.T) {
	path := findMatrixMarkdown(t)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open matrix markdown: %v", err)
	}
	defer f.Close()

	rows := parseMatrixTable(t, f)
	if len(rows) == 0 {
		t.Fatal("no rows parsed from matrix table; did the format change?")
	}

	// Map markdown proxy names to matrix Ecosystem keys.
	aliasToEco := map[string]Ecosystem{
		"npm":         EcoNPM,
		"pip / pypi":  EcoPyPI,
		"maven":       EcoMaven,
		"gradle":      EcoGradle,
		"cargo":       EcoCargo,
		"composer":    EcoComposer,
		"rubygems":    EcoRubyGems,
		"nuget":       EcoNuGet,
		"gomod / go":  EcoGo,
		"huggingface": EcoHuggingFace,
		"cocoapods":   EcoCocoaPods,
		"swift":       EcoSwift,
		"docker":      EcoDocker,
		"apt":         EcoAPT,
		"yum":         EcoYum,
		"dnf":         EcoDNF,
	}

	// Column header labels (normalised) → matrix ConditionType.
	columnToCondition := map[string]ConditionType{
		"openssf scorecard":             ConditionScorecard,
		"openssf malware index":         ConditionMalwareIndex,
		"epss":                          ConditionEPSS,
		"trivy / cve":                   ConditionCVE,
		"package age":                   ConditionPackageAge,
		"license":                       ConditionLicense,
		"provenance (slsa)":             ConditionHasProvenance,
		"typosquat":                     ConditionTyposquat,
		"cvss":                          ConditionCVSS,
		"reserved namespaces":           ConditionReservedNamespaces,
		"has install script":            ConditionHasInstallScript,
		"install script fetches remote": ConditionInstallScriptFetchesRemote,
		"publisher changed":             ConditionPublisherChanged,
		"version anomaly":               ConditionVersionAnomaly,
		"hidden unicode":                ConditionHasHiddenUnicode,
		"publish velocity anomaly":      ConditionPublishVelocityAnomaly,
		"license copyleft":              ConditionLicenseCopyleft,
		"license non-permissive":        ConditionLicenseNonPermissive,
		"license exception present":     ConditionLicenseExceptionPresent,
		"license ambiguous":             ConditionLicenseAmbiguousClassifier,
		"license unidentified":          ConditionLicenseUnidentified,
		"deprecated by maintainer":      ConditionDeprecatedByMaintainer,
		"shrinkwrap present":            ConditionShrinkwrapPresent,
		"manifest confusion":            ConditionManifestConfusion,
		"git dependency":                ConditionGitDependency,
		"http tarball dependency":       ConditionHTTPTarballDependency,
		"wildcard dependency range":     ConditionWildcardDependencyRange,
		"bad dependency semver":         ConditionBadDependencySemver,
		"uses eval":                     ConditionUsesEval,
		"network access":                ConditionNetworkAccess,
		"shell access":                  ConditionShellAccess,
		"filesystem access":             ConditionFilesystemAccess,
		"env var access":                ConditionEnvVarAccess,
		"native binary present":         ConditionNativeBinaryPresent,
		"high entropy strings":          ConditionHighEntropyStrings,
		"url strings":                   ConditionURLStrings,
		"minified code":                 ConditionMinifiedCode,
		"trivial package":               ConditionTrivialPackage,
		"too many files":                ConditionTooManyFiles,
		"nonexistent author":            ConditionNonExistentAuthor,
		"first-time collaborator":       ConditionFirstTimeCollaborator,
		"suspicious repo stars":         ConditionSuspiciousRepoStars,
	}

	if len(rows[0].cells) != len(columnToCondition) {
		t.Fatalf("markdown has %d columns, expected %d", len(rows[0].cells), len(columnToCondition))
	}

	// First row carries the column headers.
	header := rows[0]
	columnMapping := make([]ConditionType, len(header.cells))
	for i, h := range header.cells {
		key := strings.ToLower(strings.TrimSpace(h))
		cond, ok := columnToCondition[key]
		if !ok {
			t.Fatalf("unknown column header %q", h)
		}
		columnMapping[i] = cond
	}

	seenEcos := make(map[Ecosystem]struct{})
	for _, row := range rows[1:] {
		label := strings.ToLower(strings.TrimSpace(row.name))
		eco, ok := aliasToEco[label]
		if !ok {
			t.Fatalf("unknown proxy row label %q", row.name)
		}
		seenEcos[eco] = struct{}{}

		for i, cell := range row.cells {
			cond := columnMapping[i]
			wantLevel := classifyCell(cell)
			gotLevel := Support(eco, cond)
			if wantLevel != gotLevel {
				t.Errorf("matrix drift: %s / %s — markdown says %s (%q), code says %s",
					eco, cond, wantLevel, cell, gotLevel)
			}
		}
	}

	for eco := range SupportMatrix {
		if _, ok := seenEcos[eco]; !ok {
			t.Errorf("ecosystem %s is in SupportMatrix but missing from markdown", eco)
		}
	}
}

// TestSupportHelperReturnsFullForUnknown protects callers from surprising
// warnings when a novel ecosystem/condition flows through.
func TestSupportHelperReturnsFullForUnknown(t *testing.T) {
	if got := Support(Ecosystem("mystery"), ConditionHasProvenance); got != SupportFull {
		t.Errorf("unknown ecosystem: expected SupportFull fallback, got %s", got)
	}
	if got := Support(EcoNPM, ConditionType("NewFangledRule")); got != SupportFull {
		t.Errorf("unknown condition: expected SupportFull fallback, got %s", got)
	}
}

// TestConditionsUsedByCovers spot-checks the Conditions→matrix mapping.
func TestConditionsUsedByCovers(t *testing.T) {
	hp := true
	c := Conditions{HasProvenance: &hp}
	used := ConditionsUsedBy(c)
	if len(used) != 1 || used[0] != ConditionHasProvenance {
		t.Errorf("expected [HasProvenance], got %v", used)
	}
}

// --- parsing helpers ---------------------------------------------------

type matrixRow struct {
	name  string
	cells []string
}

// parseMatrixTable reads the `## Matrix` section and returns rows. The first
// row is the column header; subsequent rows are one per ecosystem. Cells are
// returned verbatim so classifyCell can inspect emoji + parenthetical text.
func parseMatrixTable(t *testing.T, r *os.File) []matrixRow {
	t.Helper()
	scanner := bufio.NewScanner(r)
	// Markdown lines can be long (our table has a lot of padding).
	scanner.Buffer(make([]byte, 0, 1<<16), 1<<20)

	inMatrix := false
	var rows []matrixRow
	for scanner.Scan() {
		line := scanner.Text()
		trim := strings.TrimSpace(line)
		if !inMatrix {
			if strings.HasPrefix(trim, "## Matrix") {
				inMatrix = true
			}
			continue
		}
		// Leave the matrix section at the next `---` horizontal rule or `##`.
		if trim == "---" || strings.HasPrefix(trim, "## ") {
			break
		}
		if !strings.HasPrefix(trim, "|") {
			continue
		}
		cells := splitMarkdownRow(trim)
		if len(cells) < 2 {
			continue
		}
		// Skip the markdown separator row (| --- | :---: | ...).
		if isSeparatorRow(cells) {
			continue
		}
		name := cells[0]
		rows = append(rows, matrixRow{name: name, cells: cells[1:]})
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan matrix: %v", err)
	}
	return rows
}

func splitMarkdownRow(line string) []string {
	line = strings.Trim(line, "|")
	fields := strings.Split(line, "|")
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, strings.TrimSpace(f))
	}
	return out
}

func isSeparatorRow(cells []string) bool {
	for _, c := range cells {
		// Separator rows are made of dashes, colons, and whitespace.
		trimmed := strings.ReplaceAll(strings.ReplaceAll(c, ":", ""), "-", "")
		trimmed = strings.TrimSpace(trimmed)
		if trimmed != "" {
			return false
		}
	}
	return true
}

// classifyCell inspects one cell's body (e.g. "❌ (no standard)", "⚠️ (via GHSA)",
// "✅") and returns the SupportLevel it implies.
func classifyCell(cell string) SupportLevel {
	trim := strings.TrimSpace(cell)
	// Order matters: ❌ first (red X), then ⚠️ (warning), then ✅ (check).
	if strings.Contains(trim, "❌") {
		return SupportNone
	}
	if strings.Contains(trim, "⚠️") || strings.Contains(trim, "⚠") {
		return SupportPartial
	}
	if strings.Contains(trim, "✅") {
		return SupportFull
	}
	return SupportLevel("unknown:" + trim)
}

// findMatrixMarkdown walks up from the test's working directory looking for
// POLICY_PROXY_MATRIX.md. `go test` sets cwd to the package dir
// (internal/policy) so we need to climb two levels. The markdown was
// relocated from the repo root to docs/ so each candidate dir is checked
// in both locations.
func findMatrixMarkdown(t *testing.T) string {
	t.Helper()
	start, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := start
	for i := 0; i < 6; i++ {
		for _, rel := range []string{"POLICY_PROXY_MATRIX.md", filepath.Join("docs", "POLICY_PROXY_MATRIX.md")} {
			candidate := filepath.Join(dir, rel)
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	// Monorepo-only consistency check: docs/POLICY_PROXY_MATRIX.md lives in the
	// enterprise monorepo, not in the standalone chainsaw-core checkout. Skip
	// (rather than fail) when it is absent so the public repo's suite is green.
	t.Skipf("POLICY_PROXY_MATRIX.md not found above %s — monorepo-only consistency check", start)
	return ""
}
