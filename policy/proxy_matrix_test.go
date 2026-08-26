package policy

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
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
		"cargo":       EcoCargo,
		"composer":    EcoComposer,
		"rubygems":    EcoRubyGems,
		"nuget":       EcoNuGet,
		"gomod / go":  EcoGo,
		"huggingface": EcoHuggingFace,
		"cocoapods":   EcoCocoaPods,
		"swift":       EcoSwift,
		"pub":         EcoPub,
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
		"cooldown":                      ConditionCooldown,
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
		"import-time execution":         ConditionImportTimeExecution,
		"malicious ioc":                 ConditionMaliciousIOC,
		"build.rs executes":             ConditionBuildRsExecutes,
		"maintainer account age":        ConditionMaintainerAccountAge,
		// AI artifacts (Wave 6).
		"dangerous pickle":                ConditionDangerousPickle,
		"unsafe serialization format":     ConditionUnsafeSerializationFormat,
		"model card injection":            ConditionModelCardInjection,
		"agent tool dangerous capability": ConditionAgentToolDangerousCapability,
		"mcp server declared":             ConditionMCPServerDeclared,
		"prompt template injection":       ConditionPromptTemplateInjection,
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

// conditionsNotMatrixMapped enumerates Conditions fields that
// ConditionsUsedBy does not map to a matrix ConditionType, with the reason.
// Every entry is a deliberate decision or a recorded gap — a field that is
// neither mapped nor listed here fails TestEveryConditionFieldIsMatrixMapped.
//
// This is the guard that would have caught the Wave-6 AI conditions: they
// shipped as working policy gates (evaluator.go) with no ConditionType, so
// ConditionsUsedBy silently returned nothing for them and every downstream
// consumer — the policy.rule.skipped audit event, `chainsaw policy lint`,
// policy preflight, and rejectStandaloneContextOnlyConditions — went blind.
var conditionsNotMatrixMapped = map[string]string{
	// --- By design -------------------------------------------------------
	"Ecosystems":                  "scoping selector, not a signal — it narrows which ecosystems a rule applies to",
	"TrustScoreMin":               "composite derived from other signals; no single matrix column",
	"TrustScoreMax":               "composite derived from other signals; no single matrix column",
	"PublishVelocityThreshold24h": "threshold parameter for PublishVelocityAnomaly, which is mapped",
	"RequireSLSALevel":            "attestation substrate; provenance availability is covered by ConditionHasProvenance",
	"RequireBuilderID":            "attestation substrate; see RequireSLSALevel",
	"RequireBuilderIssuer":        "attestation substrate; see RequireSLSALevel",
	"RequireSourceRepo":           "attestation substrate; see RequireSLSALevel",
	"RequireTransparencyLog":      "attestation substrate; see RequireSLSALevel",
	"RequireAttestation":          "attestation substrate; see RequireSLSALevel",
	"ForbidCacheStale":            "cache-freshness gate; not an ecosystem-support question",
}

// TestEveryConditionFieldIsMatrixMapped reflects over every Conditions field
// and asserts it either resolves to at least one matrix ConditionType via
// ConditionsUsedBy, or is explicitly listed in conditionsNotMatrixMapped.
//
// Adding a Conditions field without doing one or the other fails here, which
// is the point: a policy condition that the matrix cannot see is a rule that
// can be silently inert with no warning to the operator.
func TestEveryConditionFieldIsMatrixMapped(t *testing.T) {
	t.Parallel()

	ct := reflect.TypeOf(Conditions{})
	if ct.NumField() == 0 {
		t.Fatal("Conditions has no fields — struct reflection broke")
	}

	for i := 0; i < ct.NumField(); i++ {
		field := ct.Field(i)
		if field.PkgPath != "" {
			continue // unexported
		}
		t.Run(field.Name, func(t *testing.T) {
			var c Conditions
			v := reflect.ValueOf(&c).Elem().Field(i)
			if !setNonZero(v) {
				t.Skipf("unsupported field kind %s — extend setNonZero", field.Type.Kind())
			}

			used := ConditionsUsedBy(c)
			reason, excused := conditionsNotMatrixMapped[field.Name]

			switch {
			case len(used) > 0 && excused:
				t.Errorf("field %s is now mapped to %v — remove it from conditionsNotMatrixMapped (was: %s)",
					field.Name, used, reason)
			case len(used) == 0 && !excused:
				t.Errorf("field %s maps to no matrix ConditionType.\n"+
					"Either add a ConditionType + SupportMatrix rows + a ConditionsUsedBy mapping, "+
					"or add %q to conditionsNotMatrixMapped with a reason.",
					field.Name, field.Name)
			}
		})
	}
}

// setNonZero puts a non-zero, non-nil value into v so ConditionsUsedBy's
// nil/len checks fire. Reports false for a kind it doesn't handle.
func setNonZero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Ptr:
		v.Set(reflect.New(v.Type().Elem()))
		elem := v.Elem()
		switch elem.Kind() {
		case reflect.Bool:
			elem.SetBool(true)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			elem.SetInt(1)
		case reflect.Float32, reflect.Float64:
			elem.SetFloat(1)
		case reflect.String:
			elem.SetString("x")
		default:
			return false
		}
		return true
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		if s.Index(0).Kind() == reflect.String {
			s.Index(0).SetString("x")
		}
		v.Set(s)
		return true
	default:
		return false
	}
}

// TestEcosystemsDocMatchesSupportMatrix is the P8-62 rail.
//
// core/docs/ecosystems.md publishes a per-ecosystem Full/Partial/None table
// and a list of every condition name. Every number in that table used to
// disagree with a mechanical count of SupportMatrix (root cause: the doc was
// written against 46 conditions while the matrix carried 53), and the doc
// asserted in prose that "a drift test asserts it matches the published
// matrix" — which was false. The only such test compared against
// docs/POLICY_PROXY_MATRIX.md and nothing read this file at all. This is that
// test.
func TestEcosystemsDocMatchesSupportMatrix(t *testing.T) {
	path := findEcosystemsDoc(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ecosystems doc: %v", err)
	}
	text := string(raw)

	// Doc label → matrix row key.
	labelToEco := map[string]Ecosystem{
		"npm": EcoNPM, "pypi": EcoPyPI, "maven": EcoMaven, "cargo": EcoCargo,
		"composer": EcoComposer, "rubygems": EcoRubyGems, "nuget": EcoNuGet,
		"go": EcoGo, "hugging face": EcoHuggingFace, "cocoapods": EcoCocoaPods,
		"swift": EcoSwift, "pub (dart)": EcoPub, "docker / oci": EcoDocker,
		"apt": EcoAPT, "yum": EcoYum, "dnf": EcoDNF,
	}

	seen := make(map[Ecosystem]struct{})
	countRow := regexp.MustCompile(`(?m)^\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|$`)
	for _, m := range countRow.FindAllStringSubmatch(text, -1) {
		eco, ok := labelToEco[strings.ToLower(strings.TrimSpace(m[1]))]
		if !ok {
			continue
		}
		seen[eco] = struct{}{}
		wantFull, wantPartial, wantNone := countSupportLevels(eco)
		gotFull, _ := strconv.Atoi(m[2])
		gotPartial, _ := strconv.Atoi(m[3])
		gotNone, _ := strconv.Atoi(m[4])
		if gotFull != wantFull || gotPartial != wantPartial || gotNone != wantNone {
			t.Errorf("ecosystems.md drift for %s: doc says %d/%d/%d (full/partial/none), "+
				"SupportMatrix counts %d/%d/%d",
				eco, gotFull, gotPartial, gotNone, wantFull, wantPartial, wantNone)
		}
	}
	for eco := range SupportMatrix {
		if _, ok := seen[eco]; !ok {
			t.Errorf("ecosystem %s is in SupportMatrix but has no row in %s", eco, path)
		}
	}

	// The advertised condition count and the name list must both match the
	// matrix's real column set — the 46-vs-53 gap is what desynced the table.
	columns := matrixColumns()
	if !strings.Contains(text, fmt.Sprintf("**%d policy conditions**", len(columns))) {
		t.Errorf("%s does not advertise %d policy conditions; SupportMatrix has that many columns",
			path, len(columns))
	}
	if !strings.Contains(text, fmt.Sprintf("## The %d policy conditions", len(columns))) {
		t.Errorf("%s heading does not say %d policy conditions", path, len(columns))
	}
	for _, c := range columns {
		if !regexp.MustCompile(`\b` + regexp.QuoteMeta(string(c)) + `\b`).MatchString(text) {
			t.Errorf("%s does not list condition %s", path, c)
		}
	}
}

func countSupportLevels(eco Ecosystem) (full, partial, none int) {
	for _, level := range SupportMatrix[eco] {
		switch level {
		case SupportFull:
			full++
		case SupportPartial:
			partial++
		case SupportNone:
			none++
		}
	}
	return full, partial, none
}

// matrixColumns returns every condition that has a cell in SupportMatrix,
// sorted for stable output.
func matrixColumns() []ConditionType {
	seen := make(map[ConditionType]struct{})
	for _, row := range SupportMatrix {
		for c := range row {
			seen[c] = struct{}{}
		}
	}
	out := make([]ConditionType, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	return out
}

// findEcosystemsDoc walks up from the test's working directory to core/docs.
func findEcosystemsDoc(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "docs", "ecosystems.md")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate core/docs/ecosystems.md")
	return ""
}
