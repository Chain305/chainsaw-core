package cli

// socket_comparison_eval_test.go — the Chainsaw vs socket.dev signal-quality
// comparison.
//
// ─── WHAT THIS IS FOR ───────────────────────────────────────────────────────
//
// Everything in this repo that mentions Socket is DESIGN parity: the five risk
// categories mirror their package-scores model (core/risk/category.go:30-37),
// socket_alignment_test.go asserts that mirror holds, docs/POLICY_PROXY_MATRIX.md
// carries a gap analysis derived from their published alert list. Nothing has
// ever compared the two products' actual verdicts on the same packages. This
// does, over the labelled corpus in scripts/detection-eval/corpus-seed.tsv.
//
// ─── FIVE WAYS THIS COULD PRODUCE AN AUTHORITATIVE-LOOKING LIE ──────────────
//
//  1. A SINGLE RECALL NUMBER. core/malware/sync.go pulls ossf/malicious-packages
//     and Socket both contributes to and consumes the same public feeds. A
//     malicious row sourced from OSSF measures FEED PARITY for both vendors, not
//     detection. So the summary emits recall_A1 / retention_A2 / recall_B /
//     cve_fidelity_C / discrimination_D / fp_E as separate keys and there is
//     deliberately NO key called "recall" for someone to grab.
//
//  2. SOCKET 404 SCORED AS A MISS. Coverage and quality are different questions.
//     Rows where either side has no opinion are excluded from the paired matrix
//     and reported as their own coverage statistic.
//
//  3. RESCALING 0-100 AGAINST 0.0-1.0. Neither vendor publishes a calibration
//     curve, so any affine map is a free parameter you tune until the chart is
//     flattering. Scores are compared by RANK (Spearman) or not at all, and the
//     headline rho is computed over strata C and D only — on the malicious
//     strata both sides floor out on a lookup and rho ~ 1 is arithmetic.
//
//  4. THRESHOLD SHOPPING. Socket publishes no verdict, only alerts, so "Socket
//     detected it" needs a severity threshold. Picking one is picking a winner,
//     so the harness sweeps every threshold and prints the whole grid.
//
//  5. HOME-FIELD CORPUS. expected_signals is a column of OUR signal IDs and the
//     corpus was assembled to exercise OUR registry. The only honest mitigation
//     is publishing socket_only_concepts — the findings our corpus cannot even
//     ask about — next to the flattering numbers. The harness always prints it.
//
// Fails ONLY on corpus faults (unreadable inputs, seed-hash mismatch, zero
// overlap). Never on a threshold: there is no agreed threshold, and a number
// nobody has looked at should not become a gate.
//
// Run:
//
//	scripts/detection-eval/build-labelled-corpus.sh <dir>          # our side
//	scripts/detection-eval/socket-harvest.js  (browser)            # their side
//	scripts/detection-eval/socket-snapshot.py --out <dir2>
//	CHAINSAW_LABELLED_CORPUS=<dir>/reports.jsonl \
//	  CHAINSAW_LABELLED_SEED=scripts/detection-eval/corpus-seed.tsv \
//	  CHAINSAW_SOCKET_SNAPSHOT=<dir2>/socket.jsonl \
//	  CHAINSAW_SOCKET_COMPARE_OUT=<dir2> \
//	  go test ./core/cli/ -run TestSocketComparison -v -count=1

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/intelligence"
	"github.com/chain305/chainsaw-core/risk"
)

// ─── the signal <-> alert map ───────────────────────────────────────────────

type mapGrade string

const (
	gradeExact  mapGrade = "EXACT"   // same claim, comparable one-to-one
	gradePartia mapGrade = "PARTIAL" // overlapping claim, different firing set
	gradeNoneSt mapGrade = "NONE_STRUCTURAL"
	gradeNone   mapGrade = "NONE" // no Socket equivalent that this repo can name
)

type conceptMapping struct {
	Socket   []string // socket alert `type` names, verbatim from /api/ecosystems/alert/alert-types
	Grade    mapGrade
	Inferred bool   // true when the pairing is judgement, not something the repo records
	Bucket   string // "metadata" | "artifact" | "advisory" — see conceptBucket
	Note     string
}

// Concept buckets. Mixing these three in one agreement ratio produces a number
// that looks like detector quality and is mostly architecture.
//
//	metadata — both products can reach this from registry metadata alone. This
//	           is the bucket where a disagreement is a real detector difference.
//	artifact — needs the package BYTES. Chainsaw's public package-intelligence
//	           path is metadata-only (the artifact-bound providers declare
//	           NeedsArtifact() and are skipped), and cap.* additionally needs
//	           CHAINSAW_CAPABILITY_SCAN=1 and is npm-only. So these read as
//	           "Socket only" on this surface REGARDLESS of detector quality.
//	           That is a real difference in what the public feed reports, and a
//	           useless measure of who has the better detector. Reported apart.
//	advisory — CVE matching. Reported apart for a different reason: Chainsaw
//	           fires ONE vuln.cvss_* signal at the WORST severity, while Socket
//	           fires ONE ALERT PER TIER PRESENT. Pairing tier-to-tier scores a
//	           row where both products agree there is a critical CVE as two
//	           disagreements. Collapsed to one concept, with tier agreement
//	           measured separately.
const (
	bucketMetadata = "metadata"
	bucketArtifact = "artifact"
	bucketAdvisory = "advisory"
)

// socketConceptMap pairs every registered Chainsaw signal with the socket.dev
// alert types that mean the same thing.
//
// THE SOCKET NAMES ARE NOT GUESSED. Every string in a Socket slice is a `type`
// value observed in socket.dev/api/ecosystems/alert/alert-types (98 entries,
// fetched 2026-09-14). TestSocketAlertNamesAreReal re-checks them against the
// snapshot's taxonomy, so a renamed or retired Socket alert fails the build
// instead of silently scoring as "Socket missed it".
//
// NONE_STRUCTURAL is not the same as NONE. Nine Chainsaw signals are POSITIVE
// (`sc.provenance_verified`, `qual.checksum_verified`, `maint.healthy_cadence`,
// …): they ADD score for evidence of good practice. Socket's model is
// negative-only — it has no concept of an alert that improves a package. Those
// pairings can never exist, so counting them as Socket misses is a category
// error, and they are excluded from the concept metric rather than thresholded
// out of it. Same for the `sc.transitive_*` rollups (our dependency-tree
// arithmetic, which Socket surfaces on a different page) and `action.*`
// (GitHub Actions, a different product surface with no corpus rows).
var socketConceptMap = map[string]conceptMapping{
	// ── supply chain ────────────────────────────────────────────────────
	"sc.known_malicious":                   {Socket: []string{"malware", "gptMalware"}, Bucket: bucketMetadata, Grade: gradeExact},
	"sc.typosquat_high":                    {Socket: []string{"didYouMean", "gptDidYouMean"}, Bucket: bucketMetadata, Grade: gradePartia, Note: "3 Chainsaw tiers vs 2 Socket alerts; no tier correspondence exists — never compare tier to tier"},
	"sc.typosquat_medium":                  {Socket: []string{"didYouMean", "gptDidYouMean"}, Bucket: bucketMetadata, Grade: gradePartia},
	"sc.typosquat_low":                     {Socket: []string{"didYouMean", "gptDidYouMean"}, Bucket: bucketMetadata, Grade: gradePartia},
	"sc.publisher_changed":                 {Socket: []string{"unstableOwnership"}, Bucket: bucketMetadata, Grade: gradePartia, Inferred: true},
	"sc.first_time_collaborator":           {Socket: []string{"newAuthor"}, Bucket: bucketMetadata, Grade: gradeExact},
	"sc.non_existent_author":               {Socket: []string{"missingAuthor"}, Bucket: bucketMetadata, Grade: gradeExact},
	"sc.install_script_fetches_remote":     {Socket: []string{"installScripts"}, Bucket: bucketArtifact, Grade: gradePartia, Note: "ours is strictly narrower: theirs fires on scripts EXISTING"},
	"sc.install_script_only":               {Socket: []string{"installScripts"}, Bucket: bucketArtifact, Grade: gradePartia},
	"sc.hidden_unicode":                    {Socket: []string{"obfuscatedFile"}, Bucket: bucketArtifact, Grade: gradePartia, Inferred: true, Note: "different detector class; overlapping intent"},
	"sc.repo_archived":                     {Socket: []string{"unmaintained"}, Bucket: bucketMetadata, Grade: gradePartia, Inferred: true},
	"sc.git_url_dependency":                {Socket: []string{"gitDependency", "gitHubDependency"}, Bucket: bucketMetadata, Grade: gradeExact},
	"sc.http_url_dependency":               {Socket: []string{"httpDependency"}, Bucket: bucketMetadata, Grade: gradeExact},
	"sc.shrinkwrap_present":                {Socket: []string{"shrinkwrap"}, Bucket: bucketMetadata, Grade: gradeExact},
	"sc.deprecated_by_maintainer":          {Socket: []string{"deprecated"}, Bucket: bucketMetadata, Grade: gradeExact},
	"sc.suspicious_repo_stars":             {Socket: []string{"suspiciousStarActivity"}, Bucket: bucketMetadata, Grade: gradeExact},
	"sc.manifest_confusion":                {Socket: []string{"manifestConfusion"}, Bucket: bucketMetadata, Grade: gradeExact},
	"sc.publish_velocity_anomaly":          {Socket: []string{"recentlyPublished"}, Bucket: bucketMetadata, Grade: gradePartia, Inferred: true},
	"sc.repo_missing":                      {Socket: nil, Grade: gradeNone, Note: "the 98-type taxonomy has no missing-repository alert"},
	"sc.repo_ownership_mismatch":           {Socket: nil, Grade: gradeNone},
	"sc.pom_developer_list_changed":        {Socket: nil, Grade: gradeNone, Note: "Maven-specific"},
	"sc.reserved_namespace_violation":      {Socket: nil, Grade: gradeNone},
	"sc.maintainer_account_very_young":     {Socket: nil, Grade: gradeNone},
	"sc.maintainer_account_young":          {Socket: nil, Grade: gradeNone},
	"sc.maintainer_account_somewhat_young": {Socket: nil, Grade: gradeNone},
	"sc.provenance_verified":               {Socket: nil, Grade: gradeNoneSt, Note: "POSITIVE signal; Socket's model is negative-only"},
	"sc.signature_verified":                {Socket: nil, Grade: gradeNoneSt, Note: "POSITIVE signal"},
	"sc.slsa_level_bonus":                  {Socket: nil, Grade: gradeNoneSt, Note: "POSITIVE signal"},
	"sc.transitive_critical_vuln":          {Socket: nil, Grade: gradeNoneSt, Note: "our dependency-tree rollup; Socket surfaces transitive risk elsewhere"},
	"sc.transitive_high_vuln":              {Socket: nil, Grade: gradeNoneSt},
	"sc.transitive_malware":                {Socket: nil, Grade: gradeNoneSt},

	// ── capability (npm only, flag-gated) ────────────────────────────────
	"cap.network":          {Socket: []string{"networkAccess"}, Bucket: bucketArtifact, Grade: gradeExact},
	"cap.shell":            {Socket: []string{"shellAccess"}, Bucket: bucketArtifact, Grade: gradeExact},
	"cap.env_access":       {Socket: []string{"envVars"}, Bucket: bucketArtifact, Grade: gradeExact},
	"cap.native_code":      {Socket: []string{"hasNativeCode"}, Bucket: bucketArtifact, Grade: gradeExact},
	"cap.dynamic_eval":     {Socket: []string{"usesEval", "dynamicRequire"}, Bucket: bucketArtifact, Grade: gradeExact},
	"cap.filesystem_read":  {Socket: []string{"filesystemAccess"}, Bucket: bucketArtifact, Grade: gradePartia, Note: "2 Chainsaw signals -> 1 Socket alert"},
	"cap.filesystem_write": {Socket: []string{"filesystemAccess"}, Bucket: bucketArtifact, Grade: gradePartia},

	// ── vulnerability ───────────────────────────────────────────────────
	"vuln.cvss_critical": {Socket: []string{"criticalCVE"}, Bucket: bucketAdvisory, Grade: gradeExact},
	"vuln.cvss_high":     {Socket: []string{"cve"}, Bucket: bucketAdvisory, Grade: gradeExact, Note: "Socket's generic `cve` carries severity 2 = high"},
	"vuln.cvss_medium":   {Socket: []string{"mediumCVE"}, Bucket: bucketAdvisory, Grade: gradeExact},
	"vuln.cvss_low":      {Socket: []string{"mildCVE"}, Bucket: bucketAdvisory, Grade: gradeExact},
	"vuln.kev":           {Socket: nil, Grade: gradeNone, Note: "CISA KEV cross-reference; no Socket equivalent in the taxonomy"},
	"vuln.epss_high":     {Socket: nil, Grade: gradeNone},
	"vuln.fix_available": {Socket: nil, Grade: gradeNoneSt, Note: "POSITIVE signal"},

	// ── maintenance ─────────────────────────────────────────────────────
	"maint.unpopular_package": {Socket: []string{"unpopularPackage"}, Bucket: bucketMetadata, Grade: gradeExact},
	"maint.abandoned_repo":    {Socket: []string{"unmaintained"}, Bucket: bucketMetadata, Grade: gradePartia, Note: "2 Chainsaw signals -> 1 Socket alert"},
	"maint.no_recent_release": {Socket: []string{"unmaintained"}, Bucket: bucketMetadata, Grade: gradePartia},
	"maint.very_new_package":  {Socket: []string{"recentlyPublished"}, Bucket: bucketMetadata, Grade: gradePartia, Inferred: true},
	"maint.single_maintainer": {Socket: nil, Grade: gradeNone},
	"maint.healthy_cadence":   {Socket: nil, Grade: gradeNoneSt, Note: "POSITIVE signal"},

	// ── licence ─────────────────────────────────────────────────────────
	"lic.missing":                       {Socket: []string{"noLicenseFound"}, Bucket: bucketMetadata, Grade: gradeExact},
	"license.copyleft":                  {Socket: []string{"copyleftLicense"}, Bucket: bucketMetadata, Grade: gradeExact},
	"license.non_permissive":            {Socket: []string{"nonpermissiveLicense"}, Bucket: bucketMetadata, Grade: gradePartia, Note: "our firing set is narrower than our own tag (weak-copyleft suppression)"},
	"license.exception_present":         {Socket: []string{"licenseException"}, Bucket: bucketMetadata, Grade: gradeExact},
	"license.ambiguous_classifier":      {Socket: []string{"ambiguousClassifier"}, Bucket: bucketMetadata, Grade: gradeExact},
	"license.unidentified":              {Socket: []string{"unidentifiedLicense", "explicitlyUnlicensedItem"}, Bucket: bucketMetadata, Grade: gradePartia},
	"lic.changed_from_previous_version": {Socket: nil, Grade: gradeNone, Note: "no licence-change alert in the 98-type taxonomy"},
	"lic.spdx_present":                  {Socket: nil, Grade: gradeNoneSt, Note: "POSITIVE signal"},

	// ── quality ─────────────────────────────────────────────────────────
	"qual.minified_code":     {Socket: []string{"minifiedFile"}, Bucket: bucketArtifact, Grade: gradeExact},
	"qual.version_anomaly":   {Socket: []string{"badSemverDependency", "floatingDependency"}, Bucket: bucketMetadata, Grade: gradePartia, Inferred: true},
	"qual.checksum_mismatch": {Socket: nil, Grade: gradeNone, Note: "registry-proxy property; Socket is not in the mirror path"},
	"qual.checksum_verified": {Socket: nil, Grade: gradeNoneSt, Note: "POSITIVE signal"},

	// ── AI artifact ─────────────────────────────────────────────────────
	// Socket's gpt* alerts are LLM review of ANY package, not model-artifact
	// scanning; pairing them with pickle-opcode or MCP checks would be a
	// pairing of convenience. Left NONE until a HuggingFace row exists to
	// settle it with data.
	"ai.dangerous_pickle_opcode":         {Socket: nil, Grade: gradeNone},
	"ai.suspicious_pickle_opcode":        {Socket: nil, Grade: gradeNone},
	"ai.unsafe_serialization_format":     {Socket: nil, Grade: gradeNone},
	"ai.model_card_injection":            {Socket: nil, Grade: gradeNone},
	"ai.prompt_template_injection":       {Socket: nil, Grade: gradeNone},
	"ai.agent_tool_dangerous_capability": {Socket: nil, Grade: gradeNone},
	"ai.agent_tool_declared":             {Socket: nil, Grade: gradeNone},
	"ai.mcp_server_unverified":           {Socket: nil, Grade: gradeNone},
	"ai.prefers_safetensors":             {Socket: nil, Grade: gradeNoneSt, Note: "POSITIVE signal"},

	// ── GitHub Actions ──────────────────────────────────────────────────
	"action.unpinned_ref":      {Socket: nil, Grade: gradeNoneSt, Note: "different product surface (Socket's gha* family); no corpus rows"},
	"action.unknown_publisher": {Socket: nil, Grade: gradeNoneSt},
	"action.typosquat":         {Socket: nil, Grade: gradeNoneSt},
	"action.malicious":         {Socket: nil, Grade: gradeNoneSt},
}

// chainsawDetectsButDoesNotScore are findings Chainsaw WRITES INTO THE REPORT
// and exposes as policy conditions but which carry no risk signal, so they move
// no verdict (core/intelligence/report.go:326-338,
// core/policy/proxy_matrix.go:130-140). They belong in the concept metric —
// leaving them out would score a real Chainsaw capability as a Socket-only
// finding — and must stay OUT of the verdict metric, where they genuinely do
// nothing. Keyed by the Socket alert type they correspond to.
var chainsawDetectsButDoesNotScore = map[string]string{
	"highEntropyStrings": "SupplyChain.HighEntropyStrings",
	"urlStrings":         "SupplyChain.URLStrings",
	"trivialPackage":     "SupplyChain.TrivialPackage",
	"tooManyFiles":       "SupplyChain.TooManyFiles",
}

// TestSocketMapCoversRegistry is the anti-rot guard, modelled on
// registry_docs_drift_test.go. A signal added to core/risk later fails this
// test until somebody decides what its Socket status is — which is the point.
// Without it the map silently degrades into "everything unmapped is a Socket
// win".
func TestSocketMapCoversRegistry(t *testing.T) {
	all := risk.AllSignals()
	seen := map[string]bool{}
	for _, s := range all {
		m, ok := socketConceptMap[s.ID]
		if !ok {
			t.Errorf("signal %q is not in socketConceptMap — decide its Socket status "+
				"(EXACT / PARTIAL / NONE / NONE_STRUCTURAL) rather than letting it "+
				"default to 'Socket missed it'", s.ID)
			continue
		}
		seen[s.ID] = true
		switch m.Grade {
		case gradeExact, gradePartia:
			if len(m.Socket) == 0 {
				t.Errorf("signal %q graded %s but names no Socket alert", s.ID, m.Grade)
			}
			switch m.Bucket {
			case bucketMetadata, bucketArtifact, bucketAdvisory:
			default:
				t.Errorf("signal %q graded %s has no concept bucket — without one it "+
					"lands in the metadata ratio, where an architecture difference "+
					"reads as a detector difference", s.ID, m.Grade)
			}
		case gradeNone, gradeNoneSt:
			if len(m.Socket) != 0 {
				t.Errorf("signal %q graded %s but names Socket alerts %v", s.ID, m.Grade, m.Socket)
			}
		default:
			t.Errorf("signal %q has no explicit grade", s.ID)
		}
	}
	for id := range socketConceptMap {
		if !seen[id] {
			t.Errorf("socketConceptMap has %q, which is not a registered signal — "+
				"stale entry, or a typo that silently maps nothing", id)
		}
	}
	t.Logf("map covers %d/%d registered signals", len(seen), len(all))
}

// ─── snapshot types ─────────────────────────────────────────────────────────

type socketAlert struct {
	ID   int    `json:"id"`
	Type string `json:"type"`
	Cat  string `json:"cat"`
	Sev  int    `json:"sev"`
}

type socketRow struct {
	Idx    int                `json:"idx"`
	Eco    string             `json:"eco"`
	SK     string             `json:"sk"`
	Pkg    string             `json:"pkg"`
	Ver    string             `json:"ver"`
	Label  string             `json:"label"`
	Status string             `json:"socket_status"`
	HTTP   int                `json:"http_status"`
	Scores map[string]float64 `json:"scores"`
	Caps   map[string]bool    `json:"capabilities"`
	NDeps  *int               `json:"ndeps"`
	Alerts []socketAlert      `json:"alerts"`
}

func readSocketSnapshot(path string) ([]socketRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []socketRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<22)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r socketRow
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("socket snapshot line %d: %w", len(out)+1, err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// readSeedCitations returns the trailing `# …` citation column, which
// readLabelledSeed drops. The `# MAL-…` marker is what separates a malicious
// row sourced from ossf/malicious-packages (stratum A) from one sourced
// independently (stratum B) — and that split is the ONLY thing keeping the
// circularity honest, so it is read from the seed rather than inferred.
func readSeedCitations(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 5 {
			continue
		}
		cite := ""
		if len(f) >= 7 {
			cite = strings.TrimSpace(f[6])
		}
		out[labelKey(f[0], f[1], f[2])] = cite
	}
	return out, sc.Err()
}

// ─── statistics ─────────────────────────────────────────────────────────────

// spearman returns the rank correlation of two equal-length samples, and the n
// it used. Rank-based on purpose: Chainsaw scores 0-100 and Socket scores
// 0.0-1.0, neither vendor publishes a calibration curve, and any affine map
// between them is a knob you turn until the answer is nice.
func spearman(x, y []float64) (float64, int) {
	n := len(x)
	if n != len(y) || n < 3 {
		return math.NaN(), n
	}
	rx, ry := rankOf(x), rankOf(y)
	var sx, sy float64
	for i := 0; i < n; i++ {
		sx += rx[i]
		sy += ry[i]
	}
	mx, my := sx/float64(n), sy/float64(n)
	var num, dx, dy float64
	for i := 0; i < n; i++ {
		a, b := rx[i]-mx, ry[i]-my
		num += a * b
		dx += a * a
		dy += b * b
	}
	if dx == 0 || dy == 0 {
		return math.NaN(), n // one side is constant: correlation is undefined, not 0
	}
	return num / math.Sqrt(dx*dy), n
}

// rankOf assigns average ranks, so ties do not manufacture correlation.
func rankOf(v []float64) []float64 {
	type pair struct {
		val float64
		idx int
	}
	ps := make([]pair, len(v))
	for i, x := range v {
		ps[i] = pair{x, i}
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].val < ps[j].val })
	out := make([]float64, len(v))
	for i := 0; i < len(ps); {
		j := i
		for j+1 < len(ps) && ps[j+1].val == ps[i].val {
			j++
		}
		avg := float64(i+j)/2 + 1
		for k := i; k <= j; k++ {
			out[ps[k].idx] = avg
		}
		i = j + 1
	}
	return out
}

// cohensKappa on a 2x2 agreement table. Raw agreement is reported too, but the
// corpus is ~77% positive and raw agreement is inflated by that base rate,
// which is exactly the number a reader would misread.
func cohensKappa(bothYes, bothNo, aOnly, bOnly int) (kappa, raw float64) {
	n := float64(bothYes + bothNo + aOnly + bOnly)
	if n == 0 {
		return math.NaN(), math.NaN()
	}
	po := float64(bothYes+bothNo) / n
	pa := float64(bothYes+aOnly) / n
	pb := float64(bothYes+bOnly) / n
	pe := pa*pb + (1-pa)*(1-pb)
	if pe == 1 {
		return math.NaN(), po
	}
	return (po - pe) / (1 - pe), po
}

func sha256File(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return "unreadable"
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ─── CVE tier handling ──────────────────────────────────────────────────────
//
// The two products model advisory severity differently, and pairing them
// tier-to-tier manufactures disagreement. Chainsaw fires exactly ONE
// vuln.cvss_* signal, at the WORST severity present. Socket fires ONE ALERT PER
// TIER PRESENT — a package with a critical and two mediums gets criticalCVE +
// cve + mediumCVE. Scored naively, a row where both products correctly agree
// "this has a critical CVE" produces one agreement and two Socket-only
// findings. Measured over this corpus that alone accounted for ~70 phantom
// Socket-only concepts.
//
// So the CVE family collapses to a single concept and the TIERS are compared
// separately, worst against worst.

const conceptCVEAny = "cve:any"

func cvsTierOfSignal(id string) int {
	switch id {
	case "vuln.cvss_critical":
		return 4
	case "vuln.cvss_high":
		return 3
	case "vuln.cvss_medium":
		return 2
	case "vuln.cvss_low":
		return 1
	}
	return 0
}

func cvsTierOfAlert(t string) int {
	switch t {
	case "criticalCVE":
		return 4
	case "cve": // Socket's generic `cve` carries severity 2 = high
		return 3
	case "mediumCVE":
		return 2
	case "mildCVE":
		return 1
	}
	return 0
}

func worseCVE(a, b int) int {
	if b > a {
		return b
	}
	return a
}

var cveTierName = map[int]string{0: "none", 1: "low", 2: "medium", 3: "high", 4: "critical"}

// ─── the comparison ─────────────────────────────────────────────────────────

// stratumOf classifies a seed row by WHAT ITS GROUND TRUTH CAN CLAIM, which is
// not the same as what it is labelled.
//
//	A1 malicious, cited to an OSSF MAL-* id, coordinate still resolvable
//	A2 malicious, cited to an OSSF MAL-* id, coordinate unpublished
//	B  malicious, cited to something else (GHSA / public write-up)
//	C  vulnerable — a published advisory affects this exact version
//	D  suspicious — a registry-native fact, no advisory
//	E  benign
//
// A1/A2/B exist because core/malware/sync.go pulls ossf/malicious-packages and
// Socket contributes to the same feed. On stratum A both products are doing a
// LOOKUP AGAINST THE SAME TABLE. Reporting that as detection flatters both
// vendors and informs nobody.
func stratumOf(label, citation string, resolvable bool) string {
	switch label {
	case "benign":
		return "E"
	case "vulnerable":
		return "C"
	case "suspicious":
		return "D"
	case "malicious":
		if strings.Contains(citation, "MAL-") {
			if resolvable {
				return "A1"
			}
			return "A2"
		}
		return "B"
	}
	return "?"
}

var stratumMeaning = map[string]string{
	"A1": "malicious, OSSF-sourced, resolvable   -> FEED PARITY only (shared source)",
	"A2": "malicious, OSSF-sourced, unpublished  -> TOMBSTONE RETENTION only",
	"B":  "malicious, independently sourced      -> independent-source coverage",
	"C":  "vulnerable (advisory on this version) -> advisory-matching fidelity",
	"D":  "suspicious (registry-native fact)     -> INFERENCE quality",
	"E":  "benign                                -> FALSE POSITIVES",
}

var stratumOrder = []string{"A1", "A2", "B", "C", "D", "E"}

type sideOutcome int

const (
	outDetected sideOutcome = iota
	outCleared
	outNotEvaluated
)

func (o sideOutcome) String() string {
	switch o {
	case outDetected:
		return "detected"
	case outCleared:
		return "cleared"
	}
	return "not_evaluated"
}

// socketDetected applies a severity threshold to Socket's alert list. Socket
// publishes no verdict, so this IS the judgement call — hence the sweep.
func socketDetected(r socketRow, minSev int) sideOutcome {
	if r.Status != "indexed" && r.Status != "revalidate" {
		return outNotEvaluated
	}
	for _, a := range r.Alerts {
		if a.Sev >= minSev {
			return outDetected
		}
	}
	return outCleared
}

type cmpRow struct {
	Eco, Pkg, Ver, Label, Stratum     string
	CSVerdict                         string
	CSOverall                         int
	CSCats                            map[string]int
	CSSignals                         []string
	CSResolvable                      bool
	CSOut                             sideOutcome
	SK                                socketRow
	ConceptBoth, ConceptCS, ConceptSK []string
	// Worst CVE tier each side assigned: 0 none, 1 low .. 4 critical. Kept
	// separately from the concept sets because the two products tier
	// differently and pairing tiers manufactures disagreement.
	CSWorstCVE, SKWorstCVE int
}

func TestSocketComparison(t *testing.T) {
	corpusPath := os.Getenv("CHAINSAW_LABELLED_CORPUS")
	seedPath := os.Getenv("CHAINSAW_LABELLED_SEED")
	snapPath := os.Getenv("CHAINSAW_SOCKET_SNAPSHOT")
	if corpusPath == "" || seedPath == "" || snapPath == "" {
		t.Skip("set CHAINSAW_LABELLED_CORPUS, CHAINSAW_LABELLED_SEED and CHAINSAW_SOCKET_SNAPSHOT")
	}
	outDir := os.Getenv("CHAINSAW_SOCKET_COMPARE_OUT")

	seed, err := readLabelledSeed(seedPath)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	cites, err := readSeedCitations(seedPath)
	if err != nil {
		t.Fatalf("read seed citations: %v", err)
	}
	rows, err := readServerRiskCorpus(corpusPath)
	if err != nil {
		t.Fatalf("read chainsaw corpus: %v", err)
	}
	snap, err := readSocketSnapshot(snapPath)
	if err != nil {
		t.Fatalf("read socket snapshot: %v", err)
	}

	// CORPUS FAULT: a snapshot taken against a different seed revision joins on
	// coordinates that mean something else.
	metaPath := filepath.Join(filepath.Dir(snapPath), "socket.meta")
	if b, err := os.ReadFile(metaPath); err == nil {
		want := sha256File(seedPath)
		if !strings.Contains(string(b), want) {
			t.Fatalf("socket.meta seed_sha256 does not match %s (%s...) — the snapshot was "+
				"taken against a different corpus revision; re-harvest rather than grade it",
				seedPath, want[:12])
		}
		t.Logf("snapshot provenance OK: socket.meta seed_sha256 matches %s...", want[:12])
	} else {
		t.Log("NOTE: no socket.meta beside the snapshot — provenance unverified")
	}

	ours := map[string]serverRiskRow{}
	for _, r := range rows {
		ours[labelKey(r.Eco, r.Pkg, r.Ver)] = r
	}

	// socketAlertBucket inverts the map: Socket alert type -> concept bucket,
	// for EXACT pairings only.
	socketAlertBucket := map[string]string{}
	for _, m := range socketConceptMap {
		if m.Grade == gradeExact {
			for _, s := range m.Socket {
				socketAlertBucket[s] = m.Bucket
			}
		}
	}
	bucketTally := map[string]*[3]int{
		bucketMetadata: {}, bucketArtifact: {}, bucketAdvisory: {},
	}

	var ledger []cmpRow
	unmapped := map[string]int{}
	socketOnlyAll := map[string]int{}

	// ─── THE F-1 GATE ───────────────────────────────────────────────────
	//
	// On 2026-09-14 this harness reported that our maintenance signals fail
	// to fire on packages abandoned since 2020, and that finding was
	// published as a product defect. It was not one. Every maintenance input
	// has exactly one writer, internal/intelligence/premium/*, which lives in
	// the ROOT module; core/cli is in chainsaw-core and cannot import it
	// (`go list -deps -test ./core/cli/` → 1043 packages, none matching
	// "premium"). The provider never ran, the inputs were nil, the signals
	// correctly stayed dormant, and the harness attributed that silence to
	// the engine.
	//
	// server_risk_fp_eval_test.go already carried the table that detects
	// this — serverRiskInputProbes — under a heading that reads "READ THIS
	// BEFORE TRUSTING ANY ZERO IN THIS FILE'S OUTPUT". This file did not
	// consult it. Its warning is that an unseeable zero "launders CANNOT SEE
	// into MEASURED CLEAN"; this file laundered it into MEASURED MISS, which
	// is worse, because a miss gets a finding number and a remediation ticket.
	//
	// So: probe every row. A signal whose input field had data on NO row is
	// UNOBSERVABLE here, and is excluded from the concept metric on BOTH
	// sides — excluding it only from ours would still let the equivalent
	// Socket alert count as a Socket-only finding, which is exactly how F-1
	// was manufactured.
	probeSawData := map[string]bool{}

	// SECOND GATE, different mechanism. The sc.transitive_* family is not fed
	// by a premium-only Input field, so serverRiskInputProbes cannot see it.
	// Its counts come from Report.Risk.Resolution.TransitiveSeverity, written
	// by evaluateTransitiveRisk during a dependency-TREE evaluation that this
	// scanner never performs. risk_projection.go:448-451 spells out the trap:
	// "TransitiveSeverity itself is a value type, so once Risk is non-nil an
	// unevaluated tree folds in zeros." Report.Risk IS non-nil on every
	// persisted row here, so the gate that guards it passes and the counts are
	// silently zero.
	//
	// Verified rather than inferred: 0 of 174 corpus rows carry a single
	// TransitiveBlame entry, while production's npm/express@5.2.1 carries 3
	// with transitiveSeverity {mediumCount: 2}. The evaluation runs there and
	// not here.
	//
	// "No blame anywhere" could in principle mean the corpus genuinely has no
	// transitive risk. Over 174 rows including 67 with a confirmed advisory
	// that is not credible, and the conservative direction is to refuse to
	// grade rather than to attribute the silence to the engine — which is the
	// error F-1 made.
	treeEvaluated := false

	for _, sr := range snap {
		key := labelKey(sr.Eco, sr.Pkg, sr.Ver)
		lr, ok := seed[key]
		if !ok {
			continue
		}
		orow, haveOurs := ours[key]
		if !haveOurs {
			continue
		}
		row := cmpRow{Eco: sr.Eco, Pkg: sr.Pkg, Ver: sr.Ver, Label: lr.Label,
			SK: sr, CSCats: map[string]int{}}

		var rep intelligence.Report
		if err := json.Unmarshal(orow.Report, &rep); err == nil {
			// Run the input probes for this row. This is the gate that F-1
			// needed and did not have: see the block below.
			in := intelligence.ProjectToRiskInput(&rep)
			for _, pr := range serverRiskInputProbes {
				if pr.HasData(in) {
					probeSawData[pr.Field] = true
				}
			}
			if len(rep.Risk.Resolution.TransitiveBlame) > 0 ||
				in.TransitiveCriticalCount > 0 || in.TransitiveHighCount > 0 ||
				in.TransitiveMediumCount > 0 {
				treeEvaluated = true
			}
			dormant := map[string]bool{}
			for _, w := range rep.Observation.Warnings {
				if unavailabilityWarnCodes[w.Code] {
					dormant[w.Provider] = true
				}
			}
			for _, pt := range rep.Observation.ProviderTimings {
				// registrymetadata PRODUCING is the operational definition of
				// "this coordinate still exists upstream".
				if pt.Provider == "registrymetadata" && !dormant[pt.Provider] {
					row.CSResolvable = true
				}
			}
			if ev := risk.EvaluatePackage(intelligence.ProjectToRiskInput(&rep), risk.Options{}); ev != nil {
				row.CSVerdict = string(ev.Verdict)
				row.CSOverall = ev.DirectScore.Overall
				for cat, cs := range ev.DirectScore.Categories {
					if cs.DataAvailable {
						row.CSCats[string(cat)] = cs.Score
					}
					for _, fs := range cs.FiredSignals {
						row.CSSignals = append(row.CSSignals, fs.ID)
					}
				}
				switch {
				case ev.Verdict == risk.VerdictUnknown:
					row.CSOut = outNotEvaluated
				case verdictIsAdverse(ev.Verdict):
					row.CSOut = outDetected
				default:
					row.CSOut = outCleared
				}
			} else {
				row.CSOut = outNotEvaluated
			}
		} else {
			row.CSOut = outNotEvaluated
		}
		sort.Strings(row.CSSignals)
		row.Stratum = stratumOf(lr.Label, cites[key], row.CSResolvable)

		// Concept level. EXACT pairings only; NONE_STRUCTURAL is excluded from
		// BOTH sides, because a positive signal has no possible counterpart.
		// Each concept is tagged with its bucket so the ratios stay separate.
		csC := map[string]string{} // concept -> bucket
		skC := map[string]string{}
		for _, id := range row.CSSignals {
			m, ok := socketConceptMap[id]
			if !ok || m.Grade != gradeExact {
				continue
			}
			if m.Bucket == bucketAdvisory {
				// Collapse the CVE tiers: we fire ONE signal at the worst
				// severity, Socket fires one alert per tier present. Tier
				// agreement is measured separately below.
				csC[conceptCVEAny] = bucketAdvisory
				row.CSWorstCVE = worseCVE(row.CSWorstCVE, cvsTierOfSignal(id))
				continue
			}
			for _, s := range m.Socket {
				csC[s] = m.Bucket
			}
		}
		for _, a := range sr.Alerts {
			if strings.HasPrefix(a.Type, "unknown:") {
				unmapped[a.Type]++
			}
			if b, ok := socketAlertBucket[a.Type]; ok {
				if b == bucketAdvisory {
					skC[conceptCVEAny] = bucketAdvisory
					row.SKWorstCVE = worseCVE(row.SKWorstCVE, cvsTierOfAlert(a.Type))
					continue
				}
				skC[a.Type] = b
			}
			if _, ours := chainsawDetectsButDoesNotScore[a.Type]; ours {
				// We detect it and write it into the report; it just moves no
				// verdict. Counting it as a Socket-only finding would
				// under-report a real capability.
				csC[a.Type] = bucketArtifact
				skC[a.Type] = bucketArtifact
			}
		}
		for c, b := range csC {
			if _, ok := skC[c]; ok {
				row.ConceptBoth = append(row.ConceptBoth, c)
				bucketTally[b][0]++
			} else {
				row.ConceptCS = append(row.ConceptCS, c)
				bucketTally[b][1]++
			}
		}
		for c, b := range skC {
			if _, ok := csC[c]; !ok {
				row.ConceptSK = append(row.ConceptSK, c)
				socketOnlyAll[c]++
				bucketTally[b][2]++
			}
		}
		sort.Strings(row.ConceptBoth)
		sort.Strings(row.ConceptCS)
		sort.Strings(row.ConceptSK)
		ledger = append(ledger, row)
	}

	if len(ledger) == 0 {
		t.Fatal("CORPUS FAULT: zero overlap between the seed, our reports and the socket snapshot")
	}

	// ─── unobservable signals, and the Socket alerts they pair with ──────
	unobservable := map[string]string{}   // chainsaw signal -> why
	unobservableSK := map[string]string{} // socket alert    -> why
	if !treeEvaluated {
		for _, sig := range []string{
			"sc.transitive_critical_vuln", "sc.transitive_high_vuln", "sc.transitive_malware",
		} {
			unobservable[sig] = "TransitiveSeverity (dependency tree never evaluated)"
			if m, ok := socketConceptMap[sig]; ok && m.Grade == gradeExact {
				for _, sk := range m.Socket {
					unobservableSK[sk] = "TransitiveSeverity"
				}
			}
		}
	}
	for _, pr := range serverRiskInputProbes {
		if probeSawData[pr.Field] {
			continue
		}
		for _, sig := range pr.Feeds {
			unobservable[sig] = pr.Field
			if m, ok := socketConceptMap[sig]; ok && m.Grade == gradeExact {
				for _, sk := range m.Socket {
					unobservableSK[sk] = pr.Field
				}
			}
		}
	}
	// Re-tally concepts with the unobservable pairs removed from BOTH sides.
	if len(unobservable) > 0 {
		for k := range bucketTally {
			bucketTally[k] = &[3]int{}
		}
		socketOnlyAll = map[string]int{}
		for i := range ledger {
			l := &ledger[i]
			keep := func(ss []string) []string {
				out := ss[:0:0]
				for _, s := range ss {
					if _, bad := unobservableSK[s]; bad {
						continue
					}
					out = append(out, s)
				}
				return out
			}
			l.ConceptBoth, l.ConceptCS, l.ConceptSK = keep(l.ConceptBoth), keep(l.ConceptCS), keep(l.ConceptSK)
			bump := func(ss []string, idx int) {
				for _, s := range ss {
					b := bucketMetadata
					for id, m := range socketConceptMap {
						if m.Grade != gradeExact {
							continue
						}
						hit := false
						for _, x := range m.Socket {
							if x == s {
								hit = true
							}
						}
						if hit && m.Bucket != "" {
							b = m.Bucket
							_ = id
							break
						}
					}
					if s == conceptCVEAny {
						b = bucketAdvisory
					}
					if _, ours := chainsawDetectsButDoesNotScore[s]; ours {
						b = bucketArtifact
					}
					bucketTally[b][idx]++
					if idx == 2 {
						socketOnlyAll[s]++
					}
				}
			}
			bump(l.ConceptBoth, 0)
			bump(l.ConceptCS, 1)
			bump(l.ConceptSK, 2)
		}
	}

	t.Log("OBSERVABILITY GATE (serverRiskInputProbes) — read before any zero below")
	if len(unobservable) == 0 {
		t.Log("  every probed input had data on at least one row; no signal is excluded")
	} else {
		var us []string
		for s := range unobservable {
			us = append(us, s)
		}
		sort.Strings(us)
		t.Logf("  %d signal(s) UNOBSERVABLE in this build — their silence says NOTHING", len(us))
		for _, s := range us {
			t.Logf("    %-34s input %q had data on no row", s, unobservable[s])
		}
		var sk []string
		for s := range unobservableSK {
			sk = append(sk, s)
		}
		sort.Strings(sk)
		t.Logf("  the Socket alerts they pair with are excluded too, so their firing")
		t.Logf("  cannot be counted as a Chainsaw blind spot: %s", strings.Join(sk, ", "))
		t.Log("  This is the gate F-1 needed. Without it, a dormant provider reads as a")
		t.Log("  product defect.")
	}
	t.Log("")
	sort.Slice(ledger, func(i, j int) bool {
		a, b := ledger[i], ledger[j]
		if a.Eco != b.Eco {
			return a.Eco < b.Eco
		}
		if a.Pkg != b.Pkg {
			return a.Pkg < b.Pkg
		}
		return a.Ver < b.Ver
	})

	t.Logf("joined %d coordinates (seed %d, our reports %d, socket rows %d)",
		len(ledger), len(seed), len(ours), len(snap))
	t.Log("")

	// ─── 1. COVERAGE, before any accuracy number ─────────────────────────
	t.Log("COVERAGE — does the vendor have an opinion at all? (threshold-independent)")
	t.Logf("  %-10s %6s %8s %8s %9s %9s", "ecosystem", "rows", "cs_op", "sk_op", "cs_blind", "sk_blind")
	byEco := map[string][]cmpRow{}
	for _, l := range ledger {
		byEco[l.Eco] = append(byEco[l.Eco], l)
	}
	var ecos []string
	for e := range byEco {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	totCSOp, totSKOp := 0, 0
	for _, e := range ecos {
		csOp, skOp := 0, 0
		for _, l := range byEco[e] {
			if l.CSOut != outNotEvaluated {
				csOp++
			}
			if socketDetected(l.SK, 0) != outNotEvaluated {
				skOp++
			}
		}
		totCSOp += csOp
		totSKOp += skOp
		t.Logf("  %-10s %6d %8d %8d %9d %9d", e, len(byEco[e]), csOp, skOp,
			len(byEco[e])-csOp, len(byEco[e])-skOp)
	}
	t.Logf("  %-10s %6d %8d %8d %9d %9d", "TOTAL", len(ledger), totCSOp, totSKOp,
		len(ledger)-totCSOp, len(ledger)-totSKOp)
	states := map[string]int{}
	for _, l := range ledger {
		states[l.SK.Status]++
	}
	t.Logf("  socket snapshot states: %v", states)
	t.Log("")

	// ─── 2. THE THRESHOLD SWEEP ──────────────────────────────────────────
	// Socket publishes alerts, not a verdict. Rather than pick the threshold
	// that flatters us, print every one.
	t.Log("THRESHOLD SWEEP — Socket has no verdict, so 'Socket detected it' needs a")
	t.Log("severity floor. Picking one picks a winner, so here is the whole grid.")
	t.Log("Socket severities: 0 low .. 3 critical. Chainsaw is its own default ladder.")
	t.Logf("  %-14s %10s %10s %10s %10s", "socket floor", "sk_detect", "sk_fp(E)", "cs_detect", "cs_fp(E)")
	csDet, csFP, csGrad, csGradE := 0, 0, 0, 0
	for _, l := range ledger {
		if l.CSOut == outDetected {
			csDet++
			if l.Stratum == "E" {
				csFP++
			}
		}
		if l.CSOut != outNotEvaluated {
			csGrad++
			if l.Stratum == "E" {
				csGradE++
			}
		}
	}
	type sweepPt struct {
		Floor  int    `json:"floor"`
		Name   string `json:"name"`
		SKDet  int    `json:"sk_detected"`
		SKFP   int    `json:"sk_false_positives"`
		SKGrad int    `json:"sk_gradable"`
	}
	var sweep []sweepPt
	for _, f := range []struct {
		sev  int
		name string
	}{{0, "any (>=low)"}, {1, ">=medium"}, {2, ">=high"}, {3, "critical only"}} {
		d, fp, grad := 0, 0, 0
		for _, l := range ledger {
			o := socketDetected(l.SK, f.sev)
			if o == outNotEvaluated {
				continue
			}
			grad++
			if o == outDetected {
				d++
				if l.Stratum == "E" {
					fp++
				}
			}
		}
		sweep = append(sweep, sweepPt{f.sev, f.name, d, fp, grad})
		t.Logf("  %-14s %10d %10d %10d %10d", f.name, d, fp, csDet, csFP)
	}
	t.Logf("  (chainsaw gradable: %d rows, of which %d benign)", csGrad, csGradE)
	t.Log("")

	// ─── 3. PER-STRATUM, PER-ECOSYSTEM ───────────────────────────────────
	const headlineFloor = 1 // >= medium; stated as an assumption, swept above
	t.Logf("PER-STRATUM OUTCOMES  (socket floor = severity >= %d)", headlineFloor)
	t.Log("  Each stratum answers a DIFFERENT question. There is deliberately no")
	t.Log("  blended recall figure — see stratumMeaning below.")
	for _, s := range stratumOrder {
		t.Logf("  %-3s %s", s, stratumMeaning[s])
	}
	t.Log("")
	t.Logf("  %-4s %-10s %5s | %8s %8s %6s | %8s %8s %6s", "str", "ecosystem", "n",
		"cs_det", "cs_clr", "cs_na", "sk_det", "sk_clr", "sk_na")
	type key2 struct{ s, e string }
	agg := map[key2][6]int{}
	for _, l := range ledger {
		k := key2{l.Stratum, l.Eco}
		v := agg[k]
		switch l.CSOut {
		case outDetected:
			v[0]++
		case outCleared:
			v[1]++
		default:
			v[2]++
		}
		switch socketDetected(l.SK, headlineFloor) {
		case outDetected:
			v[3]++
		case outCleared:
			v[4]++
		default:
			v[5]++
		}
		agg[k] = v
	}
	var keys []key2
	for k := range agg {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].s != keys[j].s {
			return idxOf(stratumOrder, keys[i].s) < idxOf(stratumOrder, keys[j].s)
		}
		return keys[i].e < keys[j].e
	})
	for _, k := range keys {
		v := agg[k]
		n := v[0] + v[1] + v[2]
		t.Logf("  %-4s %-10s %5d | %8d %8d %6d | %8d %8d %6d",
			k.s, k.e, n, v[0], v[1], v[2], v[3], v[4], v[5])
	}
	t.Log("")
	t.Log("  COUNTS ONLY. No percentage is printed per (stratum, ecosystem): these")
	t.Log("  cells are n=1..15 and at that size one row moves the figure 7-100 points.")
	t.Log("  This repo already retired a 0.00% for exactly that reason.")
	t.Log("")

	// ─── 4. STRATUM TOTALS, each under its own name ──────────────────────
	metricName := map[string]string{
		"A1": "feed_parity_A1", "A2": "tombstone_retention_A2", "B": "recall_B",
		"C": "cve_fidelity_C", "D": "discrimination_D", "E": "false_positives_E",
	}
	t.Log("STRATUM TOTALS — note the metric NAMES. There is no key called 'recall'.")
	t.Logf("  %-24s %5s | %8s %8s | %8s %8s", "metric", "n", "cs_det", "cs_grad", "sk_det", "sk_grad")
	stratTotals := map[string]map[string]int{}
	for _, s := range stratumOrder {
		var n, cd, cg, sd, sg int
		for _, l := range ledger {
			if l.Stratum != s {
				continue
			}
			n++
			if l.CSOut != outNotEvaluated {
				cg++
				if l.CSOut == outDetected {
					cd++
				}
			}
			o := socketDetected(l.SK, headlineFloor)
			if o != outNotEvaluated {
				sg++
				if o == outDetected {
					sd++
				}
			}
		}
		if n == 0 {
			continue
		}
		stratTotals[metricName[s]] = map[string]int{"n": n, "cs_detected": cd,
			"cs_gradable": cg, "sk_detected": sd, "sk_gradable": sg}
		t.Logf("  %-24s %5d | %8d %8d | %8d %8d", metricName[s], n, cd, cg, sd, sg)
	}
	t.Log("")

	// ─── 5. AGREEMENT (kappa, not raw) ───────────────────────────────────
	bothY, bothN, csOnly, skOnly := 0, 0, 0, 0
	for _, l := range ledger {
		so := socketDetected(l.SK, headlineFloor)
		if l.CSOut == outNotEvaluated || so == outNotEvaluated {
			continue
		}
		switch {
		case l.CSOut == outDetected && so == outDetected:
			bothY++
		case l.CSOut == outCleared && so == outCleared:
			bothN++
		case l.CSOut == outDetected:
			csOnly++
		default:
			skOnly++
		}
	}
	kap, raw := cohensKappa(bothY, bothN, csOnly, skOnly)
	t.Log("VERDICT AGREEMENT over PAIRED-GRADABLE rows (both sides had an opinion)")
	t.Logf("  both detected %d | both cleared %d | chainsaw only %d | socket only %d",
		bothY, bothN, csOnly, skOnly)
	t.Logf("  raw agreement %.3f   Cohen's kappa %.3f", raw, kap)
	t.Log("  Kappa, not raw agreement: this corpus is ~77% positive and raw agreement")
	t.Log("  is inflated by that base rate.")
	t.Log("")

	// ─── 6. SCORE CORRELATION (rank, C+D only) ───────────────────────────
	t.Log("CATEGORY SCORE CORRELATION — Spearman rank, strata C+D only.")
	t.Log("  On the malicious strata both products floor out on a lookup, so rho ~ 1")
	t.Log("  there is arithmetic, not agreement. Rank-only: neither vendor publishes a")
	t.Log("  calibration curve, so any affine 0-100 <-> 0.0-1.0 map is a free parameter.")
	catPairs := []struct{ ours, theirs string }{
		{"vulnerability", "vulnerability"}, {"supply_chain", "supplyChain"},
		{"maintenance", "maintenance"}, {"license", "license"}, {"quality", "quality"},
	}
	rhoOut := map[string]map[string]any{}
	for _, cp := range catPairs {
		var xs, ys []float64
		for _, l := range ledger {
			if l.Stratum != "C" && l.Stratum != "D" {
				continue
			}
			cv, ok := l.CSCats[cp.ours] // absent => DataAvailable false; never impute
			if !ok || l.SK.Scores == nil {
				continue
			}
			sv, ok2 := l.SK.Scores[cp.theirs]
			if !ok2 {
				continue
			}
			xs = append(xs, float64(cv))
			ys = append(ys, sv)
		}
		r, n := spearman(xs, ys)
		// NaN is not representable in JSON — encoding/json REFUSES to marshal it,
		// and swallowing that error is how this summary first shipped as a 0-byte
		// file while the test reported success. An undefined correlation is
		// written as null, which is what it means; 0 would be a claim.
		entry := map[string]any{"n": n}
		if math.IsNaN(r) {
			entry["rho"] = nil
		} else {
			entry["rho"] = r
		}
		rhoOut[cp.ours] = entry
		note := ""
		if cp.ours == "quality" || cp.ours == "maintenance" {
			note = "  (NAME COLLISION, not semantic parity — do not headline)"
		}
		if math.IsNaN(r) {
			t.Logf("  %-14s rho=   n/a  n=%3d%s", cp.ours, n, note)
		} else {
			t.Logf("  %-14s rho=%6.3f  n=%3d%s", cp.ours, r, n, note)
		}
	}
	t.Log("")

	// ─── 7. CONCEPT-LEVEL FIDELITY, PER BUCKET ───────────────────────────
	t.Log("CONCEPT-LEVEL FIDELITY (EXACT pairings only; positive signals and")
	t.Log("transitive rollups excluded structurally, not thresholded out).")
	t.Log("Three buckets, NEVER one ratio — mixing them reports architecture as")
	t.Log("detector quality:")
	t.Log("  metadata  both sides reach it from registry metadata: a real comparison")
	t.Log("  artifact  needs package BYTES. Our public intelligence path is")
	t.Log("            metadata-only (artifact providers declare NeedsArtifact and are")
	t.Log("            skipped) and cap.* additionally needs CHAINSAW_CAPABILITY_SCAN=1")
	t.Log("            and is npm-only. Socket-only here is ARCHITECTURE, not blindness.")
	t.Log("  advisory  CVE presence, tiers collapsed (see cvsTierOfSignal)")
	t.Logf("  %-10s %8s %12s %12s %10s", "bucket", "both", "chainsaw_only", "socket_only", "agreement")
	conceptOut := map[string]map[string]int{}
	var both, csO, skO int
	for _, b := range []string{bucketMetadata, bucketArtifact, bucketAdvisory} {
		v := bucketTally[b]
		den := v[0] + v[1] + v[2]
		both += v[0]
		csO += v[1]
		skO += v[2]
		conceptOut[b] = map[string]int{"both": v[0], "chainsaw_only": v[1], "socket_only": v[2]}
		if den == 0 {
			t.Logf("  %-10s %8d %12d %12d %10s", b, v[0], v[1], v[2], "n/a")
			continue
		}
		t.Logf("  %-10s %8d %12d %12d %9.1f%%", b, v[0], v[1], v[2],
			100*float64(v[0])/float64(den))
	}
	t.Logf("  %-10s %8d %12d %12d", "(all)", both, csO, skO)
	t.Log("")

	// CVE TIER AGREEMENT — the other half of the advisory bucket.
	t.Log("CVE TIER AGREEMENT (worst tier each side assigns, rows where both saw a CVE)")
	tierAgree, tierTotal := 0, 0
	tierMat := map[string]int{}
	for _, l := range ledger {
		if l.CSWorstCVE == 0 || l.SKWorstCVE == 0 {
			continue
		}
		tierTotal++
		if l.CSWorstCVE == l.SKWorstCVE {
			tierAgree++
		}
		tierMat[cveTierName[l.CSWorstCVE]+"->"+cveTierName[l.SKWorstCVE]]++
	}
	if tierTotal > 0 {
		t.Logf("  exact tier match: %d/%d = %.1f%%", tierAgree, tierTotal,
			100*float64(tierAgree)/float64(tierTotal))
		var tk []string
		for k := range tierMat {
			tk = append(tk, k)
		}
		sort.Slice(tk, func(i, j int) bool { return tierMat[tk[i]] > tierMat[tk[j]] })
		for _, k := range tk {
			t.Logf("    chainsaw %-22s n=%d", k, tierMat[k])
		}
	} else {
		t.Log("  no row where both sides reported a CVE")
	}
	t.Log("")
	t.Log("  SOCKET-ONLY CONCEPTS — the blind-spot number. This corpus is HOME FIELD:")
	t.Log("  expected_signals is a column of OUR signal ids and the rows were chosen to")
	t.Log("  exercise OUR registry. This list is the honest counterweight, so it is")
	t.Log("  printed next to every flattering figure above.")
	type kv struct {
		k string
		v int
	}
	var so []kv
	for k, v := range socketOnlyAll {
		so = append(so, kv{k, v})
	}
	sort.Slice(so, func(i, j int) bool {
		if so[i].v != so[j].v {
			return so[i].v > so[j].v
		}
		return so[i].k < so[j].k
	})
	for _, e := range so {
		t.Logf("    %-28s fired on %d rows where Chainsaw fired no equivalent", e.k, e.v)
	}
	if len(unmapped) > 0 {
		t.Log("")
		t.Log("  UNMAPPED SOCKET ALERT IDS (add to the taxonomy, then to the map):")
		for k, v := range unmapped {
			t.Logf("    %s x%d", k, v)
		}
	}

	// ─── 8. ARTIFACTS ────────────────────────────────────────────────────
	if outDir == "" {
		t.Log("")
		t.Log("set CHAINSAW_SOCKET_COMPARE_OUT to write the adjudication ledger")
		return
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir out: %v", err)
	}
	ledgerPath := filepath.Join(outDir, "socket-comparison-ledger.tsv")
	lf, err := os.Create(ledgerPath)
	if err != nil {
		t.Fatalf("create ledger: %v", err)
	}
	hdr := []string{"ecosystem", "package", "version", "label", "stratum",
		"cs_verdict", "cs_overall", "cs_vuln", "cs_sc", "cs_maint", "cs_lic", "cs_qual",
		"cs_resolvable", "cs_signals", "sk_status", "sk_overall", "sk_supplyChain",
		"sk_quality", "sk_maintenance", "sk_vulnerability", "sk_license", "sk_alerts",
		"cs_outcome", "sk_outcome", "outcome", "concepts_both", "concepts_cs_only",
		"concepts_sk_only", "adjudication", "adjudicator", "adjudicated_at"}
	fmt.Fprintln(lf, strings.Join(hdr, "\t"))
	catCell := func(m map[string]int, k string) string {
		if v, ok := m[k]; ok {
			return fmt.Sprint(v)
		}
		return "" // DataAvailable=false. Blank, never 0 — 0 is a real score.
	}
	skCell := func(m map[string]float64, k string) string {
		if m == nil {
			return ""
		}
		if v, ok := m[k]; ok {
			return fmt.Sprintf("%.4f", v)
		}
		return ""
	}
	for _, l := range ledger {
		so := socketDetected(l.SK, headlineFloor)
		outcome := "both_clear"
		switch {
		case l.CSOut == outNotEvaluated && so == outNotEvaluated:
			outcome = "both_blind"
		case l.CSOut == outNotEvaluated:
			outcome = "cs_blind"
		case so == outNotEvaluated:
			outcome = "sk_blind"
		case l.CSOut == outDetected && so == outDetected:
			outcome = "both_detect"
		case l.CSOut == outDetected:
			outcome = "cs_only"
		case so == outDetected:
			outcome = "sk_only"
		}
		cells := []string{l.Eco, l.Pkg, l.Ver, l.Label, l.Stratum,
			l.CSVerdict, fmt.Sprint(l.CSOverall),
			catCell(l.CSCats, "vulnerability"), catCell(l.CSCats, "supply_chain"),
			catCell(l.CSCats, "maintenance"), catCell(l.CSCats, "license"),
			catCell(l.CSCats, "quality"),
			fmt.Sprint(l.CSResolvable), strings.Join(l.CSSignals, ","),
			l.SK.Status, skCell(l.SK.Scores, "overall"), skCell(l.SK.Scores, "supplyChain"),
			skCell(l.SK.Scores, "quality"), skCell(l.SK.Scores, "maintenance"),
			skCell(l.SK.Scores, "vulnerability"), skCell(l.SK.Scores, "license"),
			strings.Join(skAlertTypes(l.SK), ","),
			l.CSOut.String(), so.String(), outcome,
			strings.Join(l.ConceptBoth, ","), strings.Join(l.ConceptCS, ","),
			strings.Join(l.ConceptSK, ","), "", "", ""}
		for i, c := range cells {
			if strings.ContainsAny(c, "\t\n") {
				t.Fatalf("ledger field %d for %s/%s contains a tab or newline: %q",
					i, l.Eco, l.Pkg, c)
			}
		}
		fmt.Fprintln(lf, strings.Join(cells, "\t"))
	}
	lf.Close()

	summary := map[string]any{
		"generated_from": map[string]string{
			"seed":             seedPath,
			"seed_sha256":      sha256File(seedPath),
			"chainsaw_reports": corpusPath,
			"reports_sha256":   sha256File(corpusPath),
			"socket_snapshot":  snapPath,
			"snapshot_sha256":  sha256File(snapPath),
		},
		"headline_socket_severity_floor": headlineFloor,
		"joined_rows":                    len(ledger),
		"coverage": map[string]int{"chainsaw_has_opinion": totCSOp,
			"socket_has_opinion": totSKOp, "rows": len(ledger)},
		"socket_states":              states,
		"threshold_sweep":            sweep,
		"stratum_totals":             stratTotals,
		"agreement":                  map[string]any{"both_detected": bothY, "both_cleared": bothN, "chainsaw_only": csOnly, "socket_only": skOnly, "kappa": jsonNum(kap), "raw_agreement": jsonNum(raw)},
		"category_spearman":          rhoOut,
		"concepts_by_bucket":         conceptOut,
		"concepts_all":               map[string]int{"both": both, "chainsaw_only": csO, "socket_only": skO},
		"cve_tier_agreement":         map[string]any{"exact": tierAgree, "n": tierTotal, "matrix": tierMat},
		"socket_only_concepts":       socketOnlyAll,
		"unmapped_socket_alerts":     unmapped,
		"unobservable_signals":       unobservable,
		"unobservable_socket_alerts": unobservableSK,
	}
	sb, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		// Do NOT swallow this. A dropped marshal error (NaN is not valid JSON) is
		// exactly how this file first shipped as 0 bytes while the test passed.
		t.Fatalf("marshal summary: %v", err)
	}
	summaryPath := filepath.Join(outDir, "socket-comparison-summary.json")
	if err := os.WriteFile(summaryPath, sb, 0o644); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	if fi, err := os.Stat(summaryPath); err != nil || fi.Size() == 0 {
		t.Fatalf("summary at %s is empty — refusing to report success", summaryPath)
	}
	t.Log("")
	t.Logf("wrote %s", ledgerPath)
	t.Logf("wrote %s", filepath.Join(outDir, "socket-comparison-summary.json"))
	t.Log("The ledger's last three columns are blank ON PURPOSE: adjudication is a")
	t.Log("human pass against ground truth, and it is the actual deliverable.")
}

func idxOf(ss []string, s string) int {
	for i, x := range ss {
		if x == s {
			return i
		}
	}
	return len(ss)
}

// skAlertTypes lists the alert types Socket returned, deduplicated. Socket
// repeats an alert per offending FILE; for a concept-level comparison the
// repetition is noise, and keeping it would make "number of alerts" look like
// a severity measure when it is a file count.
func skAlertTypes(r socketRow) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range r.Alerts {
		if seen[a.Type] {
			continue
		}
		seen[a.Type] = true
		out = append(out, a.Type)
	}
	sort.Strings(out)
	return out
}

// jsonNum renders a float that may be NaN. encoding/json cannot represent NaN
// and errors out on it; null is the honest encoding of "undefined", where 0
// would be a claim about the data.
func jsonNum(f float64) any {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil
	}
	return f
}
