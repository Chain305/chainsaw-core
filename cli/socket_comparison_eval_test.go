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
	_ "embed"
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

// cadence is how fresh a signal's underlying fact actually is. Codes are the
// legend from docs/SIGNAL_CADENCE_MAP.md §1; that document's §3 table is the
// source for the per-signal assignment below. Typed so a typo is a compile
// error rather than a cell nobody reads.
type cadence string

const (
	cadR24          cadence = "R24"            // 24h report TTL, refreshed by the 1h walk; metadata fetch only
	cadR24B         cadence = "R24+B"          // the same, plus an artifact byte fetch (50 MiB scheduled cap)
	cadR24OSV       cadence = "R24+OSV"        // R24 with the 6h OSV bundle behind it
	cadR24EPSS      cadence = "R24+EPS"        // R24 with the 24h EPSS feed behind it
	cadR24Feed      cadence = "R24+FEED"       // R24 with the malware feed sync plus the embedded floor behind it
	cadR24Embed     cadence = "R24+EMB"        // R24 with a build-time embedded corpus behind it — redeploy only
	cadR24BPrior    cadence = "R24+B+PRI"      // R24+B, and meaningless without a prior scan of another version
	cadR24Rederived cadence = "R24/re-derived" // stored on R24, but reclassified at every projection
	cadFrozen       cadence = "FROZEN"         // refetched on R24, but the stored value is a day-count that does not age
	cadNever        cadence = "NEVER"          // registered and weighted, but its input field is never populated
	cadWorkflow     cadence = "WORKFLOW"       // not on the package path; fires only on a scanned workflow file
)

// knownCadences gates the map. A zero Cadence is an undecided signal, which is
// the thing TestSocketMapCoversRegistry exists to refuse.
var knownCadences = map[cadence]bool{
	cadR24: true, cadR24B: true, cadR24OSV: true, cadR24EPSS: true,
	cadR24Feed: true, cadR24Embed: true, cadR24BPrior: true,
	cadR24Rederived: true, cadFrozen: true, cadNever: true, cadWorkflow: true,
}

type conceptMapping struct {
	Socket   []string // socket alert `type` names, verbatim from /api/ecosystems/alert/alert-types
	Grade    mapGrade
	Inferred bool    // true when the pairing is judgement, not something the repo records
	Bucket   string  // "metadata" | "artifact" | "advisory" — see conceptBucket
	Cadence  cadence // refresh clock of the underlying fact — see docs/SIGNAL_CADENCE_MAP.md §3
	Note     string
	// Measured is the concept tally behind the grade (both, ours only,
	// theirs only), printed by TestSocketComparison: rev5
	// (docs/socket-comparison-2026-10-03-corpus-v1-rev5 regraded at this map),
	// or rev6 where the Note says so -- pairings whose lane was dark on rev5. EXACT needs it at
	// >= exactMinAgreement over >= minCoFire agreeing rows. A pairing that
	// carries one stays in the concept metric whatever its grade: demoting it
	// changes the CLAIM, not the count, or the demotion would delete its own
	// socket-only rows from the blind-spot list.
	Measured *agreeCounts
	// CoFire is the count of rows where this signal fired and Socket raised a
	// paired alert, on the revision the Note names. An Inferred PARTIAL needs >= minCoFire.
	CoFire int
}

// agreeCounts is one pairing's row tally: concept on both sides, ours only,
// theirs only.
type agreeCounts struct{ Both, CSOnly, SKOnly int }

// agreement is positive agreement 2b/(2b+cs+sk), NaN when neither side fired.
func (a agreeCounts) agreement() float64 {
	d := 2*a.Both + a.CSOnly + a.SKOnly
	if d == 0 {
		return math.NaN()
	}
	return float64(2*a.Both) / float64(d)
}

// The data floor under a grade. Until 2026-10-09 EXACT was asserted, not
// measured, and every EXACT concept but malware, CVE and filesystemAccess
// scored below 0.60 on rev5 — shrinkwrap and missingAuthor at 0.00.
const (
	exactMinAgreement = 0.60
	minCoFire         = 5
)

// compared reports whether the pairing enters the concept metric: every EXACT
// one, and every PARTIAL one demoted on a measurement.
func (m conceptMapping) compared() bool {
	return m.Grade == gradeExact || (m.Grade == gradePartia && m.Measured != nil)
}

// Concept buckets. Mixing these three in one agreement ratio produces a number
// that looks like detector quality and is mostly architecture.
//
//	metadata — both products can reach this from registry metadata alone. This
//	           is the bucket where a disagreement is a real detector difference.
//	artifact — needs the package BYTES. Chainsaw's public package-intelligence
//	           path is metadata-only (the artifact-bound providers declare
//	           NeedsArtifact() and are skipped). cap.* needs no flag (the
//	           premium scanner is npm-family only and default ON; codesmell
//	           feeds it on every ecosystem with bytes). So these read as
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
	"sc.known_malicious":               {Socket: []string{"malware"}, Bucket: bucketMetadata, Grade: gradeExact, Measured: &agreeCounts{420, 180, 0}, Note: "FEED PARITY, not detection: both sides read the same OSSF feed. gptMalware is an LLM verdict, declined with gptAnomaly/gptSecurity", Cadence: cadR24Feed},
	"sc.typosquat_high":                {Socket: []string{"didYouMean", "gptDidYouMean"}, Bucket: bucketMetadata, Grade: gradePartia, Measured: &agreeCounts{1, 104, 82}, Note: "3 Chainsaw tiers vs 2 Socket alerts; no tier correspondence exists — never compare tier to tier. Unmeasured until rev6 (the typosquat lane was dark on rev5); rev6 agreement 0.01, so it now counts in the concept metric", Cadence: cadR24Embed},
	"sc.typosquat_medium":              {Socket: []string{"didYouMean", "gptDidYouMean"}, Bucket: bucketMetadata, Grade: gradePartia, Measured: &agreeCounts{1, 104, 82}, Note: "rev6 agreement 0.01 (concept tally, all three tiers)", Cadence: cadR24Embed},
	"sc.typosquat_low":                 {Socket: []string{"didYouMean", "gptDidYouMean"}, Bucket: bucketMetadata, Grade: gradePartia, Measured: &agreeCounts{1, 104, 82}, Note: "rev6 agreement 0.01 (concept tally, all three tiers)", Cadence: cadR24Embed},
	"sc.publisher_changed":             {Socket: nil, Grade: gradeNone, Note: "was PARTIAL (inferred) to unstableOwnership/newAuthor; rev5 co-fire 0 rows (< 5); rev6 still 0 with the lane running (PublisherChangeEvaluated on every row; ours fired on none, Socket's newAuthor on 1), so unproven -- see socketUnprovenPairings. newAuthor: ours fires when the publisher is in neither the previous version's publishers nor its maintainers; theirs on any first-time publisher, listed maintainer or not. Its exact counterpart sc.first_time_collaborator was deleted in v0.22.39", Cadence: cadR24},
	"sc.non_existent_author":           {Socket: []string{"missingAuthor"}, Bucket: bucketMetadata, Grade: gradePartia, Measured: &agreeCounts{0, 8, 0}, Note: "demoted 2026-10-09: rev5 agreement 0.00, and Socket raised missingAuthor on no row", Cadence: cadR24},
	"sc.install_script_fetches_remote": {Socket: []string{"installScripts"}, Bucket: bucketArtifact, Grade: gradePartia, Note: "ours is strictly narrower: theirs fires on scripts EXISTING", Cadence: cadR24B},
	"sc.install_script_only":           {Socket: []string{"installScripts"}, Bucket: bucketArtifact, Grade: gradePartia, Cadence: cadR24B},
	// Static indicators of malicious intent. Socket's closest concept is its
	// (AI) malware verdict, which covers the intent and not the mechanism.
	"sc.exfil_sink_used":       {Socket: nil, Grade: gradeNone, Note: "was PARTIAL (inferred) to malware; rev5 co-fire 0 rows, rev6 1 (< 5). Ours is one static indicator: a hard-coded exfil sink the same file sends to", Cadence: cadR24B},
	"sc.import_time_shell":     {Socket: []string{"shellAccess"}, Bucket: bucketArtifact, Grade: gradePartia, Note: "ours is narrower: a shell spawned at Python module top level, not anywhere", Cadence: cadR24B},
	"sc.dependency_credential": {Socket: []string{"gitDependency", "httpDependency"}, Bucket: bucketArtifact, Grade: gradePartia, Note: "ours is narrower: the URL dependency also embeds a credential", Cadence: cadR24B},
	"sc.app_credential_exfil":  {Socket: nil, Grade: gradeNone, Note: "was PARTIAL (inferred) to malware; rev5 co-fire 0 rows, rev6 0 (ours 1 row) (< 5). Ours: an app's private credential store read and sent from one file", Cadence: cadR24B},
	// EXACT for the npm-only half: since 7c473d3b it fires on exactly the
	// hooks a registry install runs (preinstall/install/postinstall), which
	// is socket's installScripts on npm. rev5 non-malicious npm: 6 both, 0
	// socket-only, 2 ours-only (at-builder, ov-electron-overlay, both with a
	// real install hook). sc.install_script_only stays PARTIAL: it also
	// fires on PyPI setup.py, composer `bin` and NuGet install.ps1, which
	// socket does not flag (107 ours-only rows on rev5), even though on
	// cargo build.rs it agrees (12 both, 0 socket-only).
	"sc.install_script_only_npm": {Socket: []string{"installScripts"}, Bucket: bucketArtifact, Grade: gradePartia, Measured: &agreeCounts{9, 2, 118}, Note: "demoted 2026-10-09: rev5 agreement 0.13: npm-only against a cross-ecosystem alert, so most of Socket's installScripts rows are out of our scope by construction", Cadence: cadR24B},
	// Cross-version diff signals. Socket has no per-version capability-diff
	// alert, so these are ours-only by construction rather than a gap in
	// their taxonomy — graded as such so the harness does not read them as
	// a miss on their side.
	"sc.shell_access_appeared":             {Socket: nil, Bucket: bucketArtifact, Grade: gradeNone, Note: "cross-version diff; socket.dev exposes no capability-appeared alert", Cadence: cadR24BPrior},
	"sc.filesystem_access_appeared":        {Socket: nil, Bucket: bucketArtifact, Grade: gradeNone, Note: "cross-version diff; socket.dev exposes no capability-appeared alert", Cadence: cadR24BPrior},
	"sc.env_access_appeared":               {Socket: nil, Bucket: bucketArtifact, Grade: gradeNone, Note: "cross-version diff; socket.dev exposes no capability-appeared alert", Cadence: cadR24BPrior},
	"sc.release_after_dormancy":            {Socket: nil, Grade: gradeNone, Note: "timeline gap before this release; socket.dev's unmaintained alert is package age, not a release after silence", Cadence: cadR24},
	"sc.hidden_unicode":                    {Socket: nil, Grade: gradeNone, Note: "was PARTIAL (inferred) to obfuscatedFile; rev5: ours 15 rows, theirs 10, co-fire 0 -- measured disjoint; rev6: ours 4, theirs 0", Cadence: cadR24B},
	"sc.repo_archived":                     {Socket: []string{"unmaintained"}, Bucket: bucketMetadata, Grade: gradePartia, Inferred: true, CoFire: 12, Measured: &agreeCounts{147, 771, 7}, Note: "re-paired 2026-10-09 on rev6: co-fire 12 rows (>= 5; ours 41, Socket 154). rev5 read 0 because the repo-liveness lane did not run there (repoLinkStatus on 0 rows). Measured is the unmaintained concept tally, rev6 agreement 0.27", Cadence: cadR24},
	"sc.git_url_dependency":                {Socket: []string{"gitDependency", "gitHubDependency"}, Bucket: bucketMetadata, Grade: gradePartia, Measured: &agreeCounts{1, 0, 1}, Note: "demoted 2026-10-09: rev5 agreement on 3 rows, below the 5-row floor", Cadence: cadR24},
	"sc.http_url_dependency":               {Socket: []string{"httpDependency"}, Bucket: bucketMetadata, Grade: gradePartia, Measured: &agreeCounts{0, 0, 2}, Note: "demoted 2026-10-09: rev5 agreement 0.00 (Socket 2 rows, ours none)", Cadence: cadR24},
	"sc.shrinkwrap_present":                {Socket: []string{"shrinkwrap"}, Bucket: bucketMetadata, Grade: gradePartia, Measured: &agreeCounts{0, 115, 0}, Note: "demoted 2026-10-09: rev5 agreement 0.00: ours 115 rows, Socket's shrinkwrap on none", Cadence: cadR24B},
	"sc.deprecated_by_maintainer":          {Socket: []string{"deprecated"}, Bucket: bucketMetadata, Grade: gradePartia, Measured: &agreeCounts{10, 42, 9}, Note: "demoted 2026-10-09: rev5 agreement 0.28: ours-only rows are cargo/nuget/composer, theirs-only are all go -- a scope difference, not shown to be Socket's error", Cadence: cadR24},
	"sc.manifest_confusion":                {Socket: []string{"manifestConfusion"}, Bucket: bucketMetadata, Grade: gradePartia, Measured: &agreeCounts{0, 0, 0}, Note: "demoted 2026-10-09: neither side fired on any rev5 row, so the pairing is unmeasured", Cadence: cadR24B},
	"sc.publish_velocity_anomaly":          {Socket: nil, Grade: gradeNone, Note: "was PARTIAL (inferred) to recentlyPublished; rev5 co-fire 0 rows (< 5); rev6 0, Socket raised recentlyPublished on no row", Cadence: cadR24},
	"sc.repo_missing":                      {Socket: nil, Grade: gradeNone, Note: "the 98-type taxonomy has no missing-repository alert", Cadence: cadR24},
	"sc.repo_missing_established":          {Socket: nil, Grade: gradeNone, Note: "sc.repo_missing on a package and version older than 90 days, without the warn ceiling", Cadence: cadR24},
	"sc.repo_ownership_mismatch":           {Socket: nil, Grade: gradeNone, Cadence: cadR24},
	"sc.pom_developer_list_changed":        {Socket: nil, Grade: gradeNone, Note: "Maven-specific", Cadence: cadR24},
	"sc.maintainer_account_very_young":     {Socket: nil, Grade: gradeNone, Cadence: cadFrozen},
	"sc.maintainer_account_young":          {Socket: nil, Grade: gradeNone, Cadence: cadFrozen},
	"sc.maintainer_account_somewhat_young": {Socket: nil, Grade: gradeNone, Cadence: cadFrozen},
	"sc.provenance_verified":               {Socket: nil, Grade: gradeNoneSt, Note: "POSITIVE signal; Socket's model is negative-only", Cadence: cadR24},
	"sc.signature_verified":                {Socket: nil, Grade: gradeNoneSt, Note: "POSITIVE signal", Cadence: cadR24},
	"sc.builder_ref_version_mismatch":      {Socket: nil, Grade: gradeNone, Note: "weight-0 observation (S-3)", Cadence: cadR24},
	"sc.slsa_level_bonus":                  {Socket: nil, Grade: gradeNoneSt, Note: "POSITIVE signal", Cadence: cadR24},
	"sc.transitive_critical_vuln":          {Socket: nil, Grade: gradeNoneSt, Note: "our dependency-tree rollup; Socket surfaces transitive risk elsewhere", Cadence: cadR24OSV},
	"sc.transitive_high_vuln":              {Socket: nil, Grade: gradeNoneSt, Cadence: cadR24OSV},
	"sc.transitive_malware":                {Socket: nil, Grade: gradeNoneSt, Cadence: cadR24Feed},

	// ── capability (all 8 source ecosystems since v0.22.60; default ON) ───
	"cap.network":      {Socket: []string{"networkAccess"}, Bucket: bucketArtifact, Grade: gradePartia, Measured: &agreeCounts{277, 114, 266}, Note: "demoted 2026-10-09: rev5 agreement 0.59", Cadence: cadR24B},
	"cap.shell":        {Socket: []string{"shellAccess"}, Bucket: bucketArtifact, Grade: gradePartia, Measured: &agreeCounts{159, 80, 289}, Note: "demoted 2026-10-09: rev5 agreement 0.46", Cadence: cadR24B},
	"cap.env_access":   {Socket: []string{"envVars"}, Bucket: bucketArtifact, Grade: gradePartia, Measured: &agreeCounts{156, 179, 113}, Note: "demoted 2026-10-09: rev5 agreement 0.52", Cadence: cadR24B},
	"cap.native_code":  {Socket: []string{"hasNativeCode"}, Bucket: bucketArtifact, Grade: gradePartia, Measured: &agreeCounts{57, 295, 33}, Note: "demoted 2026-10-09: rev5 agreement 0.26: 110 of our 295 ours-only rows are nuget and 100 maven, managed assemblies and bytecode Socket does not call native", Cadence: cadR24B},
	"cap.dynamic_eval": {Socket: []string{"usesEval"}, Bucket: bucketArtifact, Grade: gradePartia, Measured: &agreeCounts{140, 80, 311}, Note: "demoted 2026-10-09: rev5 agreement 0.42", Cadence: cadR24B},
	// The weight-0 sibling fed by the codesmell regex detector. Mapped to
	// the same Socket concepts: it is the same observation, reached with
	// weaker evidence, and the harness grades the CONCEPT not the weight.
	"cap.dynamic_eval_observed": {Socket: []string{"usesEval"}, Bucket: bucketArtifact, Grade: gradePartia, Measured: &agreeCounts{140, 80, 311}, Note: "demoted 2026-10-09: rev5 agreement 0.42", Cadence: cadR24B},
	// Socket's own "URL strings" alert; the same codesmell URL scan feeds it.
	"cap.url_strings":                {Socket: []string{"urlStrings"}, Bucket: bucketArtifact, Grade: gradePartia, Measured: &agreeCounts{153, 324, 266}, Note: "demoted 2026-10-09: rev5 agreement 0.34", Cadence: cadR24B},
	"sc.install_script_eval_encoded": {Socket: []string{"installScripts", "obfuscatedFile"}, Bucket: bucketArtifact, Grade: gradePartia, Measured: &agreeCounts{9, 2, 126}, Note: "strictly narrower than both alerts (an install script that decodes and evals), the reason sc.install_script_fetches_remote is PARTIAL; never EXACT. Fired on 0 rev5 rows", Cadence: cadR24B},
	// EXACT, though two signals feed one alert: Socket's filesystemAccess is
	// "accesses the file system" with no read/write split, and each of ours is
	// a sub-case of it, so either one firing satisfies Socket's definition and
	// the concept (read OR write) is the same set. That is unlike
	// maint.abandoned_repo/no_recent_release -> unmaintained below, where the
	// two signals measure different facts from Socket's.
	"cap.filesystem_read":  {Socket: []string{"filesystemAccess"}, Bucket: bucketArtifact, Grade: gradeExact, Measured: &agreeCounts{404, 220, 240}, Note: "read OR write == Socket's undivided filesystemAccess", Cadence: cadR24B},
	"cap.filesystem_write": {Socket: []string{"filesystemAccess"}, Bucket: bucketArtifact, Grade: gradeExact, Measured: &agreeCounts{404, 220, 240}, Note: "read OR write == Socket's undivided filesystemAccess", Cadence: cadR24B},

	// PARTIAL, not EXACT: Socket does not publish either rule. Ours are
	// the shapes checked against the bytes of corpus packages Socket raised
	// them on (core/codesmell/debug_telemetry.go): vm/inspector/v8 imports
	// fire on vm2, ys-coffee and ys-coffee-script but miss seekcode, whose
	// import sits past the 64 KiB per-file window; telemetry fires on
	// dagster 1.10.16. The two malicious npm telemetry rows are unpublished.
	"cap.debug_access": {Socket: nil, Grade: gradeNone, Note: "was PARTIAL (inferred) to debugAccess; rev5 co-fire 0 rows, the detector postdates that corpus; rev6 co-fire 4 (< 5; ours 7 rows, Socket 11, agreement 0.44). node vm/inspector/v8 imports and process.binding only; Socket's wording also covers reflection", Cadence: cadR24B},
	"cap.telemetry":    {Socket: nil, Grade: gradeNone, Note: "was PARTIAL (inferred) to telemetry; rev5 co-fire 0 rows, the detector postdates that corpus; rev6 co-fire 0 (ours 2 rows, Socket 3). A telemetry endpoint or telemetry env switch; Socket's detector is unpublished", Cadence: cadR24B},

	// dynamicRequire used to be paired with cap.dynamic_eval*, which is a
	// different claim (eval/Function) and produced ~117 Chainsaw-only rows
	// against Socket's 8. Its own detector, on rev5 npm with bytes: both 4,
	// Socket-only 0, Chainsaw-only 10 — all ten checked by hand and genuine
	// non-literal requires (require(path.join(PWD, ...)), require(`./${name}`)).
	"cap.dynamic_require": {Socket: []string{"dynamicRequire"}, Bucket: bucketArtifact, Grade: gradePartia, Measured: &agreeCounts{4, 22, 4}, Note: "demoted 2026-10-09: the hand count above is 0.44, and rev5 cannot measure it (its lane did not run); rev6 measures 0.24", Cadence: cadR24B},

	// ── vulnerability ───────────────────────────────────────────────────
	"vuln.cvss_critical": {Socket: []string{"criticalCVE"}, Bucket: bucketAdvisory, Grade: gradeExact, Measured: &agreeCounts{195, 45, 1}, Cadence: cadR24OSV},
	"vuln.cvss_high":     {Socket: []string{"cve"}, Bucket: bucketAdvisory, Grade: gradeExact, Measured: &agreeCounts{195, 45, 1}, Note: "Socket's generic `cve` carries severity 2 = high", Cadence: cadR24OSV},
	"vuln.cvss_medium":   {Socket: []string{"mediumCVE"}, Bucket: bucketAdvisory, Grade: gradeExact, Measured: &agreeCounts{195, 45, 1}, Cadence: cadR24OSV},
	"vuln.cvss_low":      {Socket: []string{"mildCVE"}, Bucket: bucketAdvisory, Grade: gradeExact, Measured: &agreeCounts{195, 45, 1}, Cadence: cadR24OSV},
	"vuln.kev":           {Socket: nil, Grade: gradeNone, Note: "CISA KEV cross-reference; no Socket equivalent in the taxonomy", Cadence: cadR24},
	// Deliberately unmapped. Socket's four CVE alerts (criticalCVE, cve,
	// mediumCVE, mildCVE) are ALL severity-bearing, and this signal exists
	// precisely for the case where no severity is available — 81% of OSV
	// advisories, 96.8% on npm. Mapping it onto any of those tiers would
	// claim an agreement that cannot exist and would inflate the advisory
	// bucket with a pairing neither side can satisfy.
	// `potentialVulnerability` is not it either: that is severity 1 in
	// Socket's supplyChainRisk category, not a confirmed advisory.
	"vuln.known_vulnerable": {Socket: nil, Grade: gradeNone, Note: "confirmed advisory of UNKNOWN severity; every Socket CVE alert requires a severity tier", Cadence: cadR24OSV},
	"vuln.epss_high":        {Socket: nil, Grade: gradeNone, Cadence: cadR24EPSS},
	"vuln.fix_available":    {Socket: nil, Grade: gradeNoneSt, Note: "POSITIVE signal", Cadence: cadR24OSV},

	// ── maintenance ─────────────────────────────────────────────────────
	"maint.unpopular_package": {Socket: []string{"unpopularPackage"}, Bucket: bucketMetadata, Grade: gradePartia, Measured: &agreeCounts{131, 169, 509}, Note: "demoted 2026-10-09: rev5 agreement 0.28 (0.09 on the published ledger)", Cadence: cadR24},
	"maint.abandoned_repo":    {Socket: []string{"unmaintained"}, Bucket: bucketMetadata, Grade: gradePartia, Measured: &agreeCounts{147, 771, 7}, Note: "4 Chainsaw signals -> 1 Socket alert. Unmeasured until rev6 (the repo-liveness lane was dark on rev5); rev6 concept agreement 0.27", Cadence: cadR24},
	"maint.no_recent_release": {Socket: []string{"unmaintained"}, Bucket: bucketMetadata, Grade: gradePartia, Measured: &agreeCounts{147, 771, 7}, Note: "measured with its concept on rev6, agreement 0.27", Cadence: cadR24},
	"maint.very_new_package":  {Socket: nil, Grade: gradeNone, Note: "was PARTIAL (inferred) to recentlyPublished; rev5 co-fire 0 rows (< 5); rev6 0 (ours 1 row, Socket none)", Cadence: cadR24},
	"maint.relocated":         {Socket: nil, Grade: gradeNone, Note: "Maven <relocation>; Socket has no relocation alert", Cadence: cadR24},
	"maint.outdated_version":  {Socket: []string{"unmaintained"}, Bucket: bucketMetadata, Grade: gradePartia, Measured: &agreeCounts{147, 771, 7}, Note: "version age; Socket's unmaintained is package-level. Measured with its concept on rev6, agreement 0.27", Cadence: cadR24},
	"maint.single_maintainer": {Socket: nil, Grade: gradeNone, Cadence: cadR24},
	"maint.healthy_cadence":   {Socket: nil, Grade: gradeNoneSt, Note: "POSITIVE signal", Cadence: cadR24},

	// ── licence ─────────────────────────────────────────────────────────
	"lic.missing":                       {Socket: []string{"noLicenseFound"}, Bucket: bucketMetadata, Grade: gradePartia, Measured: &agreeCounts{47, 103, 129}, Note: "demoted 2026-10-09: rev5 agreement 0.29", Cadence: cadR24},
	"license.copyleft":                  {Socket: []string{"copyleftLicense"}, Bucket: bucketMetadata, Grade: gradePartia, Measured: &agreeCounts{82, 54, 42}, Note: "demoted 2026-10-09: 0.63 regraded here but 0.59 on the published rev5 ledger -- within 0.04 of the bar either way, so not EXACT", Cadence: cadR24Rederived},
	"license.non_permissive":            {Socket: []string{"nonpermissiveLicense"}, Bucket: bucketMetadata, Grade: gradePartia, Note: "our firing set is narrower than our own tag (weak-copyleft suppression)", Cadence: cadR24Rederived},
	"license.exception_present":         {Socket: []string{"licenseException"}, Bucket: bucketMetadata, Grade: gradePartia, Measured: &agreeCounts{1, 0, 6}, Note: "demoted 2026-10-09: rev5 agreement 0.25 on 7 rows", Cadence: cadR24Rederived},
	"license.ambiguous_classifier":      {Socket: []string{"ambiguousClassifier"}, Bucket: bucketMetadata, Grade: gradePartia, Note: "different object: ours is an SPDX expression joining >1 licence family; theirs is a PyPI trove classifier that names no single licence (\"BSD License\", bare \"OSI Approved\"). 0 of 10 rev4 rows agree", Cadence: cadR24Rederived},
	"license.unidentified":              {Socket: []string{"unidentifiedLicense", "explicitlyUnlicensedItem", "miscLicenseIssues"}, Bucket: bucketMetadata, Grade: gradePartia, Note: "miscLicenseIssues (licence present but unparseable): rev4, ours co-fires on 6 of the 7 evaluated rows theirs does, all six on a NON-EMPTY odd expression (UNLICENSED, Commercial, Nonstandard, a URL). Of our 574 firings, 462 are an EMPTY expression, where lic.missing also fires; the overlap lives in the other 112", Cadence: cadR24Rederived},
	"lic.changed_from_previous_version": {Socket: nil, Grade: gradeNone, Note: "no licence-change alert in the 98-type taxonomy", Cadence: cadR24},
	"lic.spdx_present":                  {Socket: nil, Grade: gradeNoneSt, Note: "POSITIVE signal", Cadence: cadR24},

	// ── quality ─────────────────────────────────────────────────────────
	"qual.minified_code":     {Socket: []string{"minifiedFile"}, Bucket: bucketArtifact, Grade: gradePartia, Measured: &agreeCounts{13, 106, 3}, Note: "demoted 2026-10-09: rev5 agreement 0.19: ours 119 rows, theirs 16", Cadence: cadR24B},
	"qual.version_anomaly":   {Socket: nil, Grade: gradeNone, Note: "was PARTIAL (inferred) to badSemverDependency/floatingDependency; rev5 co-fire 0 rows (< 5); rev6 0 (ours 4 rows, Socket 4)", Cadence: cadR24},
	"qual.checksum_mismatch": {Socket: nil, Grade: gradeNone, Note: "registry-proxy property; Socket is not in the mirror path", Cadence: cadR24B},
	"qual.checksum_verified": {Socket: nil, Grade: gradeNoneSt, Note: "POSITIVE signal", Cadence: cadR24B},

	// ── AI artifact ─────────────────────────────────────────────────────
	// Socket's gpt* alerts are LLM review of ANY package, not model-artifact
	// scanning; pairing them with pickle-opcode or MCP checks would be a
	// pairing of convenience. Left NONE until a HuggingFace row exists to
	// settle it with data.
	"ai.dangerous_pickle_opcode":         {Socket: nil, Grade: gradeNone, Cadence: cadR24B},
	"ai.suspicious_pickle_opcode":        {Socket: nil, Grade: gradeNone, Cadence: cadR24B},
	"ai.unsafe_serialization_format":     {Socket: nil, Grade: gradeNone, Cadence: cadR24B},
	"ai.model_card_injection":            {Socket: nil, Grade: gradeNone, Cadence: cadR24B},
	"ai.prompt_template_injection":       {Socket: nil, Grade: gradeNone, Cadence: cadR24B},
	"ai.agent_tool_dangerous_capability": {Socket: nil, Grade: gradeNone, Cadence: cadR24B},
	"ai.agent_tool_declared":             {Socket: nil, Grade: gradeNone, Cadence: cadR24B},
	"ai.mcp_server_unverified":           {Socket: nil, Grade: gradeNone, Cadence: cadR24B},
	"ai.prefers_safetensors":             {Socket: nil, Grade: gradeNoneSt, Note: "POSITIVE signal", Cadence: cadR24B},

	// ── GitHub Actions ──────────────────────────────────────────────────
	"action.unpinned_ref":      {Socket: nil, Grade: gradeNoneSt, Note: "different product surface (Socket's gha* family); no corpus rows", Cadence: cadWorkflow},
	"action.unknown_publisher": {Socket: nil, Grade: gradeNoneSt, Cadence: cadWorkflow},
	"action.typosquat":         {Socket: nil, Grade: gradeNoneSt, Cadence: cadWorkflow},
	"action.malicious":         {Socket: nil, Grade: gradeNoneSt, Cadence: cadWorkflow},
}

// ─── declined surfaces: G-3 and the 2026-10-03 decisions ────────────────────

// Socket surface names used by socketDeclinedSurfaces. One constant per
// surface so a typo is a compile error and the per-surface counts below can be
// asserted.
const (
	surfaceAgentSkills   = "AI agent-skills"
	surfaceOpenVSX       = "OpenVSX / VS Code extensions"
	surfaceActionsFlow   = "GitHub Actions data-flow"
	surfaceBrowserExtens = "Chrome + browser extensions"

	// The 2026-10-03 decisions on the last 19 undecided alerts. 15 are
	// declined here; the other four are paired in socketConceptMap
	// (debugAccess, telemetry, newAuthor, miscLicenseIssues).
	surfaceProjectScan    = "project-scan findings"
	surfaceReportState    = "report state, not a signal"
	surfaceVendorWorkflow = "Socket platform workflow"
	surfaceAnalystVerdict = "analyst or AI judgement"
	surfaceOrgLicencePol  = "org licence allow/deny policy"
	surfaceRetiredSignal  = "retired signal, fact env-gated"
)

// socketDeclinedSurfaces records a DECISION about 53 Socket alert types that no
// Chainsaw signal maps to, so they stop reading as "undecided": 37 across the
// four G-3 surfaces, 15 across six more decided on 2026-10-03, and gptMalware,
// moved here on 2026-10-09 from an EXACT pairing with sc.known_malicious.
//
// A DECISION IS NOT COVERAGE, and this map is deliberately inert in every
// metric: it is read only by the reverse REPORT in TestSocketAlertNamesAreReal
// and by the guard below. Declining a surface must not move a single number.
//
// WHERE THESE 53 ACTUALLY SIT IN THE METRIC, because it is not where the plan
// entry assumed. socketAlertBucket — the only thing that lets a Socket alert
// enter the concept comparison at all — is built from socketConceptMap for
// EXACT pairings ONLY. An alert no signal maps to is therefore absent from
// socketAlertBucket, never enters skC, and never reaches socketOnlyAll or any
// bucket tally. So these 52 are NOT "graded as socket wins": they are OUTSIDE
// the published concept metric entirely, and were before this map existed. That
// is true of every unmapped alert, declined or not; the decision changes
// nothing about it.
//
// The thing that MUST stay true is the converse: declining an alert must never
// become a way to make it count as AGREEMENT. There are two routes to that and
// the guard below refuses both. It is in particular NOT
// chainsawDetectsButDoesNotScore, which writes our side of the concept from a
// report field and so can score its slugs as agreement.
//
// WHY EACH SURFACE IS DECLINED, with the documented refusal rather than mere
// absence. In all four cases the subject never traverses the install path, so
// POSITIONING.md §17 Hard Rule 3 applies: "If it doesn't traverse the proxy,
// Chainsaw doesn't see it and won't claim to."
//
//   - GitHub Actions data-flow (the gha* taint family: arg/context/env reaching
//     an env, an output or a sink) is refused TWICE over. §17 Hard Rule 1:
//     Chainsaw "does not read application code, .git history, repo CI
//     configuration, or anything inside the customer's repository" — a workflow
//     YAML is repo CI configuration. And §18: "Not a SAST product. No callgraph
//     reachability"; "Not a CI posture auditor." Note this is NOT the whole
//     GitHub Actions surface: the four action.* signals cover action REFERENCE
//     hygiene (unpinned ref, unknown publisher, typosquat, known-malicious) and
//     are already graded NONE_STRUCTURAL above. Reference hygiene and taint
//     data-flow are different claims, and mapping one onto the other would
//     relabel a real gap as covered.
//
//   - AI agent-skills (skill*) have the strongest reopen condition of the four,
//     because AI artifacts ARE in scope: huggingface is a supported ecosystem
//     and core/risk/registry_aiartifact.go already scores pickle opcodes, model
//     cards, declared agent tools and MCP servers. What is missing is the
//     SUBJECT. Those signals read package artifact BYTES (cadence R24+B, via
//     ArtifactScanSection), and an agent skill is not a package coordinate on
//     any registry the proxy fronts — there is no skill fetcher anywhere in
//     core/ or internal/. So ai.prompt_template_injection cannot fire on
//     skillPromptInjection's subject, and the two firing sets are DISJOINT
//     rather than overlapping. Pairing them would claim an agreement neither
//     side can ever satisfy, which is the same reasoning that leaves
//     vuln.known_vulnerable unmapped above.
//
//   - OpenVSX / VS Code extensions (vsx*) and Chrome + browser extensions
//     (chrome*, browserExtension*) are installed by the EDITOR and the BROWSER
//     from their own marketplaces, not by a package manager through the proxy.
//     §18's "what you buy" is enumerated as "every npm install, pip install,
//     docker pull, and go get that traverses the proxy"; neither marketplace is
//     one of those, there is no openvsx or Chrome Web Store fetcher in the tree,
//     and no doc commits to either surface.
//
// WHAT WOULD REOPEN EACH ONE is recorded per surface in the G-3 decision report,
// not here; the short version is a proxied install path for the artifact class.
//
// ─── the 2026-10-03 decisions: six more surfaces, 15 alerts ─────────────────
//
// Same contract: inert in every metric, guarded against counting as agreement.
// Each states the reason and what would reopen it.
//
//   - project-scan findings (missingLockfile, oversizedManifest,
//     unresolvedPomReference, unresolvedYarnDependency). Their subject is the
//     customer's repository manifest and lockfile, not a package version.
//     docs/SIGNAL_CADENCE_MAP.md F-5: internal/monitorsweep/sweep.go refuses a
//     second results table, because two sources of truth for one coordinate
//     surface their disagreement as phantom alerts. Reopen: a project-finding
//     surface keyed on the project, not on the package-version key.
//
//   - report state, not a signal (pendingScan, notFound). These ARE on the
//     report: Observation.Partial with TierComplete/TierTotal is pendingScan
//     with progress, and WarnPackageNotFound / WarnVersionNotFound route to
//     VerdictUnknown with a stated reason (PLANS_INTELLIGENCE A-4). They are
//     declined as SIGNAL pairings only, because this map compares signals and
//     a scan's completion state is not a finding about the package. Reopen:
//     never as a signal; a report-state comparison would be its own metric.
//
//   - Socket platform workflow (generic, policy, socketUpgradeAvailable).
//     generic is "ad-hoc, uploaded by user or produced by system diagnostics";
//     policy is a placeholder added "so the artifact can still be triaged"
//     when it has no other alert; socketUpgradeAvailable means Socket's own
//     optimized override package exists (`npx socket optimize`) — a vendor
//     catalogue, not package age, so maint.outdated_version is NOT it. None
//     says anything about the package. Reopen: never as detection.
//
//   - analyst or AI judgement (gptAnomaly, gptMalware, gptSecurity,
//     potentialVulnerability, troll). gpt* are an LLM's read of the code;
//     gptMalware was EXACT to sc.known_malicious until 2026-10-09, which
//     graded one LLM verdict as our feed lookup and declined its two siblings; potentialVulnerability is
//     "initial human review ... pending further analysis"; troll is "a list of
//     troll packages that Socket maintains", AI-flagged and human-verified.
//     Each is a curated verdict with no rule to reproduce. sc.known_malicious
//     may share a few protestware rows through the public malware feeds, which
//     measures feed parity, not detection. Reopen: an LLM review provider, or
//     an ingestible protestware feed, measured against the labelled corpus.
//
//   - org licence allow/deny policy (licenseSpdxDisj, "not allowed per your
//     license policy"). Declined as a SIGNAL pairing only: the capability
//     exists as policy, Conditions.PackageLicense (core/policy/store.go:152,
//     enforced at core/policy/evaluator.go:1514), and lic.policy_blocked was
//     deregistered because no signal input carries the org's list. A policy
//     verdict is not a signal, so it counts as covered outside the registry
//     in the parity line, never as agreement.
//
//   - retired signal, fact env-gated (suspiciousStarActivity).
//     sc.suspicious_repo_stars was DELETED in v0.22.39 because its provider is
//     gated off by CHAINSAW_WAVE4_SUSPICIOUS_REPO_STARS; the fact survives only
//     as the SuspiciousRepoStars policy condition. A deleted signal cannot be
//     paired, and chainsawDetectsButDoesNotScore would count it as agreement on
//     every row Socket raises it, with or without the fact. Reopen: enable the
//     provider, measure it on the labelled corpus, and re-register the signal.
var socketDeclinedSurfaces = map[string]string{
	// AI agent-skills — 13.
	"skillAutonomyAbuse":    surfaceAgentSkills,
	"skillCommandInjection": surfaceAgentSkills,
	"skillDataExfiltration": surfaceAgentSkills,
	"skillDiscoveryAbuse":   surfaceAgentSkills,
	"skillHardcodedSecrets": surfaceAgentSkills,
	"skillObfuscation":      surfaceAgentSkills,
	"skillPreExecution":     surfaceAgentSkills,
	"skillPromptInjection":  surfaceAgentSkills,
	"skillResourceAbuse":    surfaceAgentSkills,
	"skillSupplyChain":      surfaceAgentSkills,
	"skillToolAbuse":        surfaceAgentSkills,
	"skillToolChaining":     surfaceAgentSkills,
	"skillTransitiveTrust":  surfaceAgentSkills,

	// OpenVSX / VS Code extensions — 9.
	"vsxActivationWildcard":          surfaceOpenVSX,
	"vsxDebuggerContribution":        surfaceOpenVSX,
	"vsxExtensionDependency":         surfaceOpenVSX,
	"vsxExtensionPack":               surfaceOpenVSX,
	"vsxProposedApiUsage":            surfaceOpenVSX,
	"vsxUntrustedWorkspaceSupported": surfaceOpenVSX,
	"vsxVirtualWorkspaceSupported":   surfaceOpenVSX,
	"vsxWebviewContribution":         surfaceOpenVSX,
	"vsxWorkspaceContainsActivation": surfaceOpenVSX,

	// GitHub Actions data-flow — 7.
	"ghaArgToEnv":        surfaceActionsFlow,
	"ghaArgToOutput":     surfaceActionsFlow,
	"ghaArgToSink":       surfaceActionsFlow,
	"ghaContextToEnv":    surfaceActionsFlow,
	"ghaContextToOutput": surfaceActionsFlow,
	"ghaContextToSink":   surfaceActionsFlow,
	"ghaEnvToSink":       surfaceActionsFlow,

	// Chrome + browser extensions — 8.
	"browserExtensionContentScript":          surfaceBrowserExtens,
	"browserExtensionHostPermission":         surfaceBrowserExtens,
	"browserExtensionPermission":             surfaceBrowserExtens,
	"browserExtensionWildcardHostPermission": surfaceBrowserExtens,
	"chromeContentScript":                    surfaceBrowserExtens,
	"chromeHostPermission":                   surfaceBrowserExtens,
	"chromePermission":                       surfaceBrowserExtens,
	"chromeWildcardHostPermission":           surfaceBrowserExtens,

	// 2026-10-03 — 15 across six surfaces.
	"missingLockfile":          surfaceProjectScan,
	"oversizedManifest":        surfaceProjectScan,
	"unresolvedPomReference":   surfaceProjectScan,
	"unresolvedYarnDependency": surfaceProjectScan,
	"pendingScan":              surfaceReportState,
	"notFound":                 surfaceReportState,
	"generic":                  surfaceVendorWorkflow,
	"policy":                   surfaceVendorWorkflow,
	"socketUpgradeAvailable":   surfaceVendorWorkflow,
	"gptAnomaly":               surfaceAnalystVerdict,
	"gptMalware":               surfaceAnalystVerdict,
	"gptSecurity":              surfaceAnalystVerdict,
	"potentialVulnerability":   surfaceAnalystVerdict,
	"troll":                    surfaceAnalystVerdict,
	"licenseSpdxDisj":          surfaceOrgLicencePol,
	"suspiciousStarActivity":   surfaceRetiredSignal,
}

// expectedDeclinedPerSurface pins the shape of the decisions. The G-3 counts are
// the ones in the plan entry, so a slug silently added to or dropped from a
// surface fails rather than quietly changing what was decided.
var expectedDeclinedPerSurface = map[string]int{
	surfaceAgentSkills:   13,
	surfaceOpenVSX:       9,
	surfaceActionsFlow:   7,
	surfaceBrowserExtens: 8,

	surfaceProjectScan:    4,
	surfaceReportState:    2,
	surfaceVendorWorkflow: 3,
	surfaceAnalystVerdict: 5,
	surfaceOrgLicencePol:  1,
	surfaceRetiredSignal:  1,
}

// socketUnprovenPairings are Socket alerts whose only pairing was an Inferred
// PARTIAL that co-fired on fewer than minCoFire rev5 rows, so the pairing was
// removed on 2026-10-09; re-measured on rev6, where every one is still below. DECIDED, not covered: the reverse guard accepts them,
// they sit outside every agreement number, and the parity line counts them as
// alerts we lack. Re-pair one only with a measured co-fire count.
var socketUnprovenPairings = map[string]string{
	"newAuthor":           "sc.publisher_changed: 0 co-fire rows on rev5 and rev6 (Socket 1 row)",
	"unstableOwnership":   "sc.publisher_changed: Socket raised it on no row, rev5 or rev6",
	"recentlyPublished":   "sc.publish_velocity_anomaly, maint.very_new_package: Socket raised it on no row, rev5 or rev6",
	"debugAccess":         "cap.debug_access: rev6 co-fire 4 rows (Socket 11, ours 7); rev5 0, detector postdates it",
	"telemetry":           "cap.telemetry: rev6 co-fire 0 rows (Socket 3, ours 2); rev5 0, detector postdates it",
	"badSemverDependency": "qual.version_anomaly: Socket raised it on no row, rev5 or rev6",
	"floatingDependency":  "qual.version_anomaly: 0 co-fire rows on rev5 and rev6 (Socket 4 on rev6, ours 4)",
}

// otherProductSurfaces are declined surfaces whose subject is not a registry
// package version. They leave the parity denominator; the same-surface
// declines (analyst verdicts, org licence policy, the retired star signal)
// stay in it, because Socket raises those on the packages we both grade.
var otherProductSurfaces = map[string]bool{
	surfaceAgentSkills: true, surfaceOpenVSX: true, surfaceActionsFlow: true,
	surfaceBrowserExtens: true, surfaceProjectScan: true, surfaceReportState: true,
	surfaceVendorWorkflow: true,
}

// coveredOutsideRegistry are package alerts we implement as something other
// than a risk signal. They count in the parity denominator and on neither the
// EXACT nor the "we lack" side.
var coveredOutsideRegistry = map[string]string{
	"licenseSpdxDisj": "policy DSL Conditions.PackageLicense (core/policy/store.go:152, core/policy/evaluator.go:1514)",
}

// chainsawDetectsButDoesNotScore are findings Chainsaw WRITES INTO THE REPORT
// and exposes as policy conditions but which carry no risk signal, so they move
// no verdict (core/intelligence/report.go:326-338,
// core/policy/proxy_matrix.go:130-140). They belong in the concept metric —
// leaving them out would score a real Chainsaw capability as a Socket-only
// finding — and must stay OUT of the verdict metric, where they genuinely do
// nothing. Keyed by the Socket alert type they correspond to; the value reads
// the report field (ArtifactScanSection) that is our side of the concept.
var chainsawDetectsButDoesNotScore = map[string]func(*intelligence.ArtifactScanSection) bool{
	"highEntropyStrings": func(s *intelligence.ArtifactScanSection) bool { return s.HighEntropyStrings },
	"urlStrings":         func(s *intelligence.ArtifactScanSection) bool { return s.URLStrings },
	"trivialPackage":     func(s *intelligence.ArtifactScanSection) bool { return s.TrivialPackage },
	"tooManyFiles":       func(s *intelligence.ArtifactScanSection) bool { return s.TooManyFiles },
}

// reportOnlyConcepts splits the chainsawDetectsButDoesNotScore concepts into
// ours (the report field is set) and theirs (Socket raised the alert). Until
// 2026-10-03 the loop wrote BOTH sides whenever Socket alerted, without
// reading our report, so every such alert scored as agreement.
func reportOnlyConcepts(scan *intelligence.ArtifactScanSection, socketAlerts []string) (ours, theirs []string) {
	raised := map[string]bool{}
	for _, a := range socketAlerts {
		raised[a] = true
	}
	for typ, has := range chainsawDetectsButDoesNotScore {
		if has(scan) {
			ours = append(ours, typ)
		}
		if raised[typ] {
			theirs = append(theirs, typ)
		}
	}
	sort.Strings(ours)
	sort.Strings(theirs)
	return ours, theirs
}

// socketAlertBucket inverts the map: Socket alert type -> concept bucket, for
// compared pairings only.
var socketAlertBucket = func() map[string]string {
	out := map[string]string{}
	for _, m := range socketConceptMap {
		if m.compared() {
			for _, s := range m.Socket {
				out[s] = m.Bucket
			}
		}
	}
	return out
}()

// conceptMalwareAny collapses Socket's two malware verdicts, the confirmed
// `malware` and the LLM-judged `gptMalware`, into ONE concept, as the CVE
// tiers collapse into conceptCVEAny. sc.known_malicious is one finding; mapped
// to both alerts it was counted twice, and on a row where Socket raised only
// one of them it scored an agreement AND a Chainsaw-only at the same time
// (gptMalware Chainsaw-only: 576 on rev 5). Since 2026-10-09 gptMalware is a
// declined LLM verdict and never enters socketAlertBucket, so on a row where
// Socket raised only gptMalware the concept is ours alone; the alias stays so
// the concept keeps its published name.
const conceptMalwareAny = "malware:any"

var conceptAlias = map[string]string{"malware": conceptMalwareAny, "gptMalware": conceptMalwareAny}

func aliasConcept(c string) string {
	if a, ok := conceptAlias[c]; ok {
		return a
	}
	return c
}

// rowConcepts builds one row's concept sets (concept -> bucket) for each side,
// compared pairings only, and the worst CVE tier each side assigned. signals are
// our fired signal IDs, unmeasured those that fired on their SevUnknown arm,
// alerts Socket's alert types for the row.
func rowConcepts(signals []string, unmeasured map[string]bool, scan *intelligence.ArtifactScanSection, alerts []string) (csC, skC map[string]string, csWorst, skWorst int) {
	csC, skC = map[string]string{}, map[string]string{}
	for _, id := range signals {
		m, ok := socketConceptMap[id]
		if !ok || !m.compared() {
			continue
		}
		// A signal on its SevUnknown arm says we could NOT measure the
		// thing ("Download count unavailable"), so it claims nothing a
		// Socket alert could agree with. Counting it made rev4 score 178
		// npm/PyPI rows as unpopularPackage agreement where the download
		// fetch had failed — 394 of 424 npm rows carried the -1 sentinel.
		if unmeasured[id] {
			continue
		}
		if m.Bucket == bucketAdvisory {
			// Collapse the CVE tiers: we fire ONE signal at the worst
			// severity, Socket fires one alert per tier present. Tier
			// agreement is measured separately.
			csC[conceptCVEAny] = bucketAdvisory
			csWorst = worseCVE(csWorst, cvsTierOfSignal(id))
			continue
		}
		for _, s := range m.Socket {
			csC[aliasConcept(s)] = m.Bucket
		}
	}
	for _, a := range alerts {
		if b, ok := socketAlertBucket[a]; ok {
			if b == bucketAdvisory {
				skC[conceptCVEAny] = bucketAdvisory
				skWorst = worseCVE(skWorst, cvsTierOfAlert(a))
				continue
			}
			skC[aliasConcept(a)] = b
		}
	}
	// Findings we write into the report but do not score: our side is the
	// report field, theirs is the alert. Agreement needs both.
	ours, theirs := reportOnlyConcepts(scan, alerts)
	for _, c := range ours {
		csC[c] = bucketArtifact
	}
	for _, c := range theirs {
		skC[c] = bucketArtifact
	}
	return csC, skC, csWorst, skWorst
}

// recoveredConceptSignals returns the fact-backed signals of a report whose
// projection short-circuited to "not evaluated" (Input.SignalsUnavailable:
// registry metadata missing, cancelled or undecodable, or the coordinate
// gone). The verdict stays Unknown and the ledger's cs_signals stay empty: that
// is right for the VERDICT metric. But the concept metric then lost every
// observation we did make -- the artifact scan and the advisory match do not
// depend on registry metadata -- and scored Socket's alerts on those rows as
// Socket-only. 564 of 1,885 rows were Unknown in at least one of two runs.
//
// The report is re-projected with its warnings cleared, and only ARTIFACT and
// ADVISORY bucket signals are kept. Metadata-bucket signals are dropped: with
// no registry document, lic.missing and friends would fire on nothing.
func recoveredConceptSignals(rep *intelligence.Report) (ids []string, unmeasured map[string]bool) {
	if !intelligence.ProjectToRiskInput(rep).SignalsUnavailable {
		return nil, nil
	}
	cp := *rep
	cp.Observation.Warnings = nil
	in := intelligence.ProjectToRiskInput(&cp)
	if in.SignalsUnavailable {
		return nil, nil // unavailable for a reason that is not a warning
	}
	ev := risk.EvaluatePackage(in, risk.Options{})
	if ev == nil {
		return nil, nil
	}
	unmeasured = map[string]bool{}
	for _, c := range ev.DirectScore.Categories {
		for _, fs := range c.FiredSignals {
			m, ok := socketConceptMap[fs.ID]
			if !ok || (m.Bucket != bucketArtifact && m.Bucket != bucketAdvisory) {
				continue
			}
			ids = append(ids, fs.ID)
			if !countsTowardConcept(fs) {
				unmeasured[fs.ID] = true
			}
		}
	}
	sort.Strings(ids)
	return ids, unmeasured
}

// withoutRepoLiveness is the input as if RepoLiveness had never answered:
// status, archived flag and last commit cleared. The verdict on it, next to
// the real one, says which flags RepoLiveness DECIDES. Counting rows that
// merely carry a repo signal over-counts: on abf9a1f8, 34 presumed-benign
// flags carried sc.repo_archived or maint.abandoned_repo, but 9 of them stayed
// warn without those inputs, and sc.repo_missing decided 4 that set never named.
func withoutRepoLiveness(in risk.Input) risk.Input {
	in.RepoLinkStatus, in.RepoArchived, in.LastRepoCommitAt = "", nil, nil
	return in
}

// headlineInput is the input the competition metrics grade: the row as
// scored, except that a Go row loses every Transitive*Count (judge round 2,
// B1). A module-level transitive critical CVE quarantines Go packages on its
// own -- 265 of 300 sampled prod Go reports are non-allow ONLY because of
// sc.transitive_* (TestTransitiveVerdictAttribution, 88.3%) -- so on Go it
// ranks nothing, and Socket does not fold transitive risk into a package's
// alerts. The verdict as scored stays in the ledger beside it, disclosed.
func headlineInput(eco string, in risk.Input) risk.Input {
	if eco == "go" {
		in.TransitiveCriticalCount, in.TransitiveHighCount, in.TransitiveMediumCount = 0, 0, 0
		in.TransitiveLowCount, in.TransitiveMalwareCount, in.TransitiveBlockedCount = 0, 0, 0
	}
	return in
}

// headlineEval evaluates one row three ways: the headline (headlineInput),
// the verdict as scored with sc.transitive_* kept, and the headline with
// withoutRepoLiveness applied. head is nil when the engine returns nothing.
func headlineEval(eco string, in risk.Input) (head *risk.Evaluation, withTransitive, noRepo string) {
	h := headlineInput(eco, in)
	if ev := risk.EvaluatePackage(withoutRepoLiveness(h), risk.Options{}); ev != nil {
		noRepo = string(ev.Verdict)
	}
	if ev := risk.EvaluatePackage(in, risk.Options{}); ev != nil {
		withTransitive = string(ev.Verdict)
	}
	return risk.EvaluatePackage(h, risk.Options{}), withTransitive, noRepo
}

// cmpOutcome is a Chainsaw verdict's detection outcome.
func cmpOutcome(v risk.Verdict) sideOutcome {
	switch {
	case v == "" || v == risk.VerdictUnknown:
		return outNotEvaluated
	case verdictIsAdverse(v):
		return outDetected
	default:
		return outCleared
	}
}

// countsTowardConcept is false for a signal on its SevUnknown arm: "Download
// count unavailable" says we could NOT measure the thing, so it claims nothing
// a Socket alert could agree with.
func countsTowardConcept(fs risk.FiredSignal) bool {
	return fs.Severity != risk.SevUnknown
}

// feedKnownMalicious marks rows whose verdict came from the malware feed. On
// those the engine emits sc.known_malicious and nothing else, so every Socket
// behaviour alert on them is Socket-only by construction. The behavioural
// concept view leaves them out; the full view keeps them. Report both.
func feedKnownMalicious(l *cmpRow) bool {
	for _, s := range l.CSSignals {
		if s == "sc.known_malicious" {
			return true
		}
	}
	return false
}

// conceptTotals counts concept agreement over the ledger rows keep admits.
func conceptTotals(ledger []cmpRow, keep func(*cmpRow) bool) (both, csOnly, skOnly int, skOnlyBy map[string]int) {
	skOnlyBy = map[string]int{}
	for i := range ledger {
		l := &ledger[i]
		if !keep(l) {
			continue
		}
		both += len(l.ConceptBoth)
		csOnly += len(l.ConceptCS)
		skOnly += len(l.ConceptSK)
		for _, c := range l.ConceptSK {
			skOnlyBy[c]++
		}
	}
	return both, csOnly, skOnly, skOnlyBy
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
		if !knownCadences[m.Cadence] {
			t.Errorf("signal %q has no cadence decision (%q) — decide how fresh its "+
				"underlying fact is (see docs/SIGNAL_CADENCE_MAP.md §1 for the codes "+
				"and §3 for the per-signal table) rather than letting it default to "+
				"the flat 24h report TTL", s.ID, m.Cadence)
		}
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
			// B8: a grade has a data floor, or it is an assertion.
			if m.Grade == gradeExact {
				switch {
				case m.Measured == nil:
					t.Errorf("signal %q is EXACT with no recorded agreement — run "+
						"TestSocketComparison and record its measured counts, or grade it PARTIAL", s.ID)
				case !(m.Measured.agreement() >= exactMinAgreement) || m.Measured.Both < minCoFire:
					t.Errorf("signal %q is EXACT at agreement %.2f over %d agreeing rows — EXACT "+
						"needs >= %.2f over >= %d; grade it PARTIAL",
						s.ID, m.Measured.agreement(), m.Measured.Both, exactMinAgreement, minCoFire)
				}
			}
			if m.Grade == gradePartia && m.Inferred && m.CoFire < minCoFire {
				t.Errorf("signal %q is an inferred PARTIAL with %d co-fire rows — a judgement "+
					"pairing needs >= %d measured rows or grade NONE", s.ID, m.CoFire, minCoFire)
			}
		case gradeNone, gradeNoneSt:
			if len(m.Socket) != 0 {
				t.Errorf("signal %q graded %s but names Socket alerts %v", s.ID, m.Grade, m.Socket)
			}
			if m.Measured != nil || m.Inferred {
				t.Errorf("signal %q graded %s carries a measurement or Inferred — neither means anything without a pairing", s.ID, m.Grade)
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

// socketAlertTypesJSON is a mirror of the taxonomy capture at
// docs/socket-comparison-2026-09-14/socket-alert-types.json (fetched
// 2026-09-14, 98 alert types). That file is the canonical historical evidence;
// this is the guard's input.
//
// TWO COPIES OF ONE LIST, embedded for the same reason core/typosquat mirrors
// the guard seeds (established.go:135-145): go:embed cannot reach outside its
// own directory, and core/cli ships in the open-core module while the private
// repo's docs/ does not. A path walk up to docs/ would resolve in the monorepo
// and SKIP forever in the published chainsaw-core checkout — a guard that does
// not execute where it is published, which is CLAUDE.md §3 by a different
// mechanism. It would also start skipping here the day those five
// docs/socket-comparison-* directories get archived, silently, with the suite
// still green. Embedded, a deleted file is a compile error instead.
//
// Not byte-pinned against the docs/ copy on purpose: the capture is frozen
// evidence of what socket.dev published on 2026-09-14, and a re-fetch updates
// this one.
//
//go:embed seeds/socket-alert-types.json
var socketAlertTypesJSON []byte

// TestSocketAlertNamesAreReal is the socket half of the anti-rot guard, and the
// comment at the top of socketConceptMap has claimed it existed since the map
// was written. It did not, so until now a renamed or retired Socket alert
// scored silently as "Socket missed it" — the map is the ONLY source of socket
// slugs the harness consults (socketAlertBucket is built from the map itself,
// so it is structurally incapable of noticing an alert the map gets wrong).
//
// Unlike TestSocketComparison this needs no corpus and no env vars: the
// taxonomy is checked into the repo, so the guard runs in an ordinary pass.
func TestSocketAlertNamesAreReal(t *testing.T) {
	const taxonomyPath = "core/cli/seeds/socket-alert-types.json"
	// Keyed by stringified numeric id; the id is also repeated in the value.
	var taxonomy map[string]socketAlert
	if err := json.Unmarshal(socketAlertTypesJSON, &taxonomy); err != nil {
		t.Fatalf("parse embedded socket taxonomy %s: %v", taxonomyPath, err)
	}
	if len(taxonomy) == 0 {
		t.Fatalf("embedded socket taxonomy %s parsed to zero entries — an empty map would "+
			"make every assertion below vacuously pass", taxonomyPath)
	}

	byType := map[string]socketAlert{}
	for _, a := range taxonomy {
		byType[a.Type] = a
	}

	// Forward: every slug the map names must still be a real alert type.
	mentioned := map[string]bool{}
	var ids []string
	for id := range socketConceptMap {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		for _, slug := range socketConceptMap[id].Socket {
			mentioned[slug] = true
			if _, ok := byType[slug]; !ok {
				t.Errorf("signal %q maps to Socket alert %q, which is not in the %d-type "+
					"taxonomy (%s) — the alert was renamed or retired, so the pairing now "+
					"scores as 'Socket missed it'. Re-fetch socket.dev/alerts, then either "+
					"update the slug or regrade the signal NONE",
					id, slug, len(taxonomy), taxonomyPath)
			}
		}
	}

	// Reverse: every taxonomy entry must be DECIDED — paired by a signal, in
	// chainsawDetectsButDoesNotScore, or declined with a reason in
	// socketDeclinedSurfaces. This used to be report-only, because the
	// undecided set was large; since 2026-10-03 it is empty, and an alert
	// that becomes undecided (a re-fetched taxonomy adds one, or a pairing is
	// dropped) fails here until somebody decides it, the same contract
	// TestSocketMapCoversRegistry holds for our side. Deciding is not
	// covering: a declined alert still counts in no agreement number.
	var unmapped, declined []string
	for typ := range byType {
		if mentioned[typ] {
			continue
		}
		if _, ok := chainsawDetectsButDoesNotScore[typ]; ok {
			continue
		}
		// G-3: a DECIDED non-goal is not an undecided gap. Split rather than
		// skip, so the declined count stays visible — these alerts still
		// count as socket-only in every agreement number, and hiding them
		// here would be the first step toward reading a decision as coverage.
		if _, ok := socketDeclinedSurfaces[typ]; ok {
			declined = append(declined, typ)
			continue
		}
		if _, ok := socketUnprovenPairings[typ]; ok {
			continue
		}
		unmapped = append(unmapped, typ)
	}
	sort.Strings(unmapped)
	sort.Strings(declined)
	// Conditional on purpose: an unconditional "all present" line printed
	// alongside the t.Errorf above contradicts it, and the reader of a failed
	// run has to decide which of the two to believe.
	if t.Failed() {
		t.Logf("forward: %d distinct Socket slugs named by socketConceptMap; at least one is NOT in the %d-type taxonomy — see the failure above",
			len(mentioned), len(taxonomy))
	} else {
		t.Logf("forward: %d distinct Socket slugs named by socketConceptMap, all present in the %d-type taxonomy",
			len(mentioned), len(taxonomy))
	}
	if len(unmapped) > 0 {
		t.Errorf("reverse: %d of %d taxonomy entries are UNDECIDED — neither mapped, "+
			"nor in chainsawDetectsButDoesNotScore, nor declined in "+
			"socketDeclinedSurfaces: %v. Decide each: pair it with a signal at an "+
			"honest grade, or decline it with a reason and a reopen condition. "+
			"Never pair it to make this pass.",
			len(unmapped), len(taxonomy), unmapped)
	}
	bySurface := map[string]int{}
	for _, slug := range declined {
		bySurface[socketDeclinedSurfaces[slug]]++
	}
	t.Logf("reverse (DECIDED, outside the concept metric like every unmapped alert): "+
		"%d of %d taxonomy entries are declined product surfaces: %v",
		len(declined), len(taxonomy), bySurface)
	for slug := range socketUnprovenPairings {
		if mentioned[slug] {
			t.Errorf("%q is in socketUnprovenPairings and also paired in socketConceptMap — pick one", slug)
		}
		if _, ok := byType[slug]; !ok {
			t.Errorf("socketUnprovenPairings names %q, which is not in the taxonomy", slug)
		}
	}
	t.Log(parityLine(byType))
}

// parityLine is the claim the concept map supports, stated with its
// denominator: D is every taxonomy alert minus the declined OTHER-product
// surfaces; an alert counts EXACT when any pairing is EXACT, else PARTIAL
// (and inferred when every PARTIAL pairing is), else covered outside the
// registry, else lacking.
func parityLine(byType map[string]socketAlert) string {
	best := map[string]mapGrade{}
	inferredOnly := map[string]bool{}
	for _, m := range socketConceptMap {
		for _, slug := range m.Socket {
			switch {
			case m.Grade == gradeExact:
				best[slug] = gradeExact
			case m.Grade == gradePartia && best[slug] != gradeExact:
				if best[slug] != gradePartia {
					inferredOnly[slug] = true
				}
				best[slug] = gradePartia
				inferredOnly[slug] = inferredOnly[slug] && m.Inferred
			}
		}
	}
	var d, e, p, inf, outside int
	var lack []string
	for typ := range byType {
		if otherProductSurfaces[socketDeclinedSurfaces[typ]] {
			continue
		}
		d++
		_, reportOnly := chainsawDetectsButDoesNotScore[typ]
		_, policy := coveredOutsideRegistry[typ]
		switch {
		case best[typ] == gradeExact:
			e++
		case best[typ] == gradePartia:
			p++
			if inferredOnly[typ] {
				inf++
			}
		case reportOnly || policy:
			outside++
		default:
			lack = append(lack, typ)
		}
	}
	sort.Strings(lack)
	return fmt.Sprintf("parity: %d EXACT / %d PARTIAL (%d inferred) of %d comparable package alerts; "+
		"%d more covered outside the signal registry (report-only fields, policy DSL); %d lacking: %v",
		e, p, inf, d, outside, len(lack), lack)
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
// maintenanceStateExtra lists maintenance-state signals the concept map
// cannot name, because Socket has no alert for them.
var maintenanceStateExtra = map[string]bool{"maint.relocated": true}

// csMaintenanceConcept reports whether any maintenance-state signal fired:
// every signal the concept map pairs with Socket's deprecated/unmaintained,
// plus maintenanceStateExtra. Derived from the map so a new mapping counts
// without a second list to keep in step.
func csMaintenanceConcept(signals []string) bool {
	for _, id := range signals {
		if maintenanceStateExtra[id] {
			return true
		}
		for _, sk := range socketConceptMap[id].Socket {
			if sk == "deprecated" || sk == "unmaintained" {
				return true
			}
		}
	}
	return false
}

func skMaintenanceConcept(r socketRow) bool {
	for _, a := range r.Alerts {
		if a.Type == "deprecated" || a.Type == "unmaintained" {
			return true
		}
	}
	return false
}

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

// reportLaneProbes are the lanes whose silence the input probes cannot see:
// the field a provider writes even when it finds nothing, or the provider's
// own timing entry. A lane absent on EVERY row never ran, and its signals are
// unobservable, derived from the corpus rather than listed. rev4 and rev5
// carried typosquatStatus on 0 of 1,885 rows and the harness printed "0 fired".
var reportLaneProbes = []struct {
	Lane  string
	Ran   func(*intelligence.Report) bool
	Feeds []string
}{
	{"supplyChain.typosquatStatus", func(r *intelligence.Report) bool { return r.SupplyChain.TyposquatStatus != "" },
		[]string{"sc.typosquat_high", "sc.typosquat_medium", "sc.typosquat_low"}},
	{"supplyChain.repoLinkStatus", func(r *intelligence.Report) bool { return r.SupplyChain.RepoLinkStatus != "" },
		[]string{"sc.repo_archived", "sc.repo_missing", "sc.repo_missing_established", "sc.repo_ownership_mismatch"}},
	{"provider debugtelemetry", func(r *intelligence.Report) bool {
		for _, pt := range r.Observation.ProviderTimings {
			if pt.Provider == "debugtelemetry" {
				return true
			}
		}
		return false
	}, []string{"cap.debug_access", "cap.telemetry", "cap.dynamic_require"}},
}

// silentSignalReasons covers the case no probe can: a mapped signal that fired
// on no row while Socket raised its pairing, on a lane that DID run. Without a
// reason here TestSocketComparison fails, because that silence is either a
// measured miss or a lane nobody asked. Measured misses stay in the metric;
// a reason for a signal that fires is stale and also fails.
var silentSignalReasons = map[string]string{
	"sc.http_url_dependency":         "measured miss: registrymetadata ran on every row; counted socket-only",
	"sc.install_script_eval_encoded": "measured zero: installscripts ran, installScriptKind was never eval_encoded; counted",
	// rev6 (engine 898551d5, deployed v0.22.81 code) carries the signal since
	// 1045f82f, so this is no longer "the corpus predates the detector": it is
	// a measured zero. The signal is narrower than the alert it pairs with — it
	// fires only on a shell primitive executed at Python import time, not on
	// any shell use — so Socket's rows stay counted as Socket-only.
	"sc.import_time_shell": "measured zero on rev6: narrower than its pairing (shell at Python import time only); counted",
	// sc.dependency_credential's rev5 entry ("engine predates the indicator")
	// was deleted on rev6, where the signal fires — the stale-reason guard
	// above caught it. A reason must describe the corpus being graded.
}

type cmpRow struct {
	Eco, Pkg, Ver, Label, Stratum     string
	CSVerdict                         string
	CSVerdictNoRepo                   string // the verdict with withoutRepoLiveness applied
	CSVerdictWithTransitive           string // the verdict as scored: sc.transitive_* kept on Go rows too
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
	laneSawData := map[string]bool{}
	firedRows := map[string]int{} // signal -> rows it fired on (not on its unknown arm)
	var goT struct{ rows, withCounts, changed int }

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
		unmeasured := map[string]bool{} // signals that fired on their SevUnknown arm

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
			ev, withT, noRepo := headlineEval(sr.Eco, in)
			row.CSVerdictWithTransitive, row.CSVerdictNoRepo = withT, noRepo
			if sr.Eco == "go" && withT != "" {
				goT.rows++
				if in.TransitiveCriticalCount+in.TransitiveHighCount+in.TransitiveMediumCount+
					in.TransitiveLowCount+in.TransitiveMalwareCount+in.TransitiveBlockedCount > 0 {
					goT.withCounts++
				}
			}
			if ev != nil {
				row.CSVerdict = string(ev.Verdict)
				row.CSOverall = ev.DirectScore.Overall
				for cat, cs := range ev.DirectScore.Categories {
					if cs.DataAvailable {
						row.CSCats[string(cat)] = cs.Score
					}
					for _, fs := range cs.FiredSignals {
						row.CSSignals = append(row.CSSignals, fs.ID)
						if !countsTowardConcept(fs) {
							unmeasured[fs.ID] = true
						}
					}
				}
				row.CSOut = cmpOutcome(ev.Verdict)
			} else {
				row.CSOut = outNotEvaluated
			}
		} else {
			row.CSOut = outNotEvaluated
		}
		sort.Strings(row.CSSignals)
		row.Stratum = stratumOf(lr.Label, cites[key], row.CSResolvable)

		// Concept level. Compared pairings only; NONE_STRUCTURAL is excluded from
		// BOTH sides, because a positive signal has no possible counterpart.
		// Each concept is tagged with its bucket so the ratios stay separate.
		for _, a := range sr.Alerts {
			if strings.HasPrefix(a.Type, "unknown:") {
				unmapped[a.Type]++
			}
		}
		conceptSignals := row.CSSignals
		if recovered, rUnmeasured := recoveredConceptSignals(&rep); len(recovered) > 0 {
			conceptSignals = append(append([]string(nil), row.CSSignals...), recovered...)
			for id := range rUnmeasured {
				unmeasured[id] = true
			}
		}
		for _, lp := range reportLaneProbes {
			if lp.Ran(&rep) {
				laneSawData[lp.Lane] = true
			}
		}
		rowFired := map[string]bool{}
		for _, id := range conceptSignals {
			if !unmeasured[id] && !rowFired[id] {
				rowFired[id] = true
				firedRows[id]++
			}
		}
		csC, skC, csWorst, skWorst := rowConcepts(conceptSignals, unmeasured, &rep.Scan, skAlertTypes(sr))
		row.CSWorstCVE, row.SKWorstCVE = csWorst, skWorst
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
	// B1: no Go row's headline may carry a transitive rollup. headlineEval is
	// what removes them; this catches a call site that stops using it.
	for _, l := range ledger {
		if l.Eco != "go" {
			continue
		}
		if l.CSVerdict != l.CSVerdictWithTransitive {
			goT.changed++
		}
		for _, s := range l.CSSignals {
			if strings.HasPrefix(s, "sc.transitive_") {
				t.Errorf("B1: Go headline row %s@%s carries %s; the headline excludes sc.transitive_* on Go", l.Pkg, l.Ver, s)
			}
		}
	}
	t.Logf("B1: Go headline excludes sc.transitive_*: %d Go rows, %d carry a transitive count, %d change verdict with it",
		goT.rows, goT.withCounts, goT.changed)

	// ─── unobservable signals, and the Socket alerts they pair with ──────
	unobservable := map[string]string{}   // chainsaw signal -> why
	unobservableSK := map[string]string{} // socket alert    -> why
	if !treeEvaluated {
		for _, sig := range []string{
			"sc.transitive_critical_vuln", "sc.transitive_high_vuln", "sc.transitive_malware",
		} {
			unobservable[sig] = "TransitiveSeverity (dependency tree never evaluated)"
			if m, ok := socketConceptMap[sig]; ok && m.compared() {
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
			if m, ok := socketConceptMap[sig]; ok && m.compared() {
				for _, sk := range m.Socket {
					unobservableSK[sk] = pr.Field
				}
			}
		}
	}
	for _, lp := range reportLaneProbes {
		if laneSawData[lp.Lane] {
			continue
		}
		for _, sig := range lp.Feeds {
			unobservable[sig] = lp.Lane + " absent on every row"
			if m, ok := socketConceptMap[sig]; ok && m.compared() {
				for _, sk := range m.Socket {
					unobservableSK[sk] = lp.Lane
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
						if !m.compared() {
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
			t.Logf("    %-34s %s", s, unobservable[s])
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

	// ─── THE LANE GATE (B7) ─────────────────────────────────────────────
	// Every signal with a Socket pairing must fire on at least one row, or be
	// unobservable with a reason, or carry a silentSignalReasons entry. A
	// mapped signal that is silent everywhere while Socket raises its alert
	// is otherwise indistinguishable from a lane that was never asked.
	pcRows := map[string]int{} // signal -> rows where Socket raised a paired alert
	for i := range ledger {
		raised := map[string]bool{}
		for _, a := range skAlertTypes(ledger[i].SK) {
			raised[a] = true
		}
		for id, m := range socketConceptMap {
			for _, sk := range m.Socket {
				if raised[sk] {
					pcRows[id]++
					break
				}
			}
		}
	}
	var mapped []string
	for id, m := range socketConceptMap {
		if len(m.Socket) > 0 {
			mapped = append(mapped, id)
		}
	}
	sort.Strings(mapped)
	silent := map[string]string{}
	t.Log("LANE GATE — every Socket-paired signal fired, or says why it did not")
	for _, id := range mapped {
		_, unobs := unobservable[id]
		why, hasWhy := silentSignalReasons[id]
		switch {
		case firedRows[id] > 0 && unobs:
			t.Errorf("%s fired on %d rows but is declared unobservable (%s) — the probe is wrong",
				id, firedRows[id], unobservable[id])
		case firedRows[id] > 0 && hasWhy:
			t.Errorf("%s fired on %d rows; its silentSignalReasons entry is stale — delete it", id, firedRows[id])
		case firedRows[id] > 0, unobs:
		case pcRows[id] == 0:
			unobservable[id] = "no positive control: neither side fired on any row"
		case hasWhy:
			silent[id] = why
			t.Logf("  %-34s silent, Socket %d rows: %s", id, pcRows[id], why)
		default:
			t.Errorf("%s fired on NO row while Socket raised %v on %d, and no probe or "+
				"silentSignalReasons entry explains it. A lane that never ran reads here as "+
				"\"0 fired\" — add a reportLaneProbes entry if it did not run, or record "+
				"the measured miss in silentSignalReasons", id, socketConceptMap[id].Socket, pcRows[id])
		}
	}
	t.Log("")

	// ─── MEASURED AGREEMENT PER COMPARED PAIRING (B8) ────────────────────
	t.Log("MEASURED AGREEMENT — 2b/(2b+cs+sk) per compared pairing; EXACT needs")
	t.Logf("  >= %.2f over >= %d agreeing rows. Paste a changed tally into Measured.", exactMinAgreement, minCoFire)
	measuredOut := map[string]agreeCounts{}
	for _, id := range mapped {
		m := socketConceptMap[id]
		if !m.compared() {
			continue
		}
		concepts := map[string]bool{}
		for _, sk := range m.Socket {
			if m.Bucket == bucketAdvisory {
				concepts[conceptCVEAny] = true
			} else {
				concepts[aliasConcept(sk)] = true
			}
		}
		anyIn := func(ss []string) bool {
			for _, c := range ss {
				if concepts[c] {
					return true
				}
			}
			return false
		}
		var a agreeCounts
		for i := range ledger {
			l := &ledger[i]
			ours := anyIn(l.ConceptBoth) || anyIn(l.ConceptCS)
			theirs := anyIn(l.ConceptBoth) || anyIn(l.ConceptSK)
			switch {
			case ours && theirs:
				a.Both++
			case ours:
				a.CSOnly++
			case theirs:
				a.SKOnly++
			}
		}
		measuredOut[id] = a
		rec := "none"
		if m.Measured != nil {
			rec = fmt.Sprintf("%v", *m.Measured)
		}
		t.Logf("  %-30s %-7s &agreeCounts{%d, %d, %d} agr=%.2f  recorded %s",
			id, m.Grade, a.Both, a.CSOnly, a.SKOnly, a.agreement(), rec)
		if m.Grade == gradeExact && (!(a.agreement() >= exactMinAgreement) || a.Both < minCoFire) {
			t.Errorf("%s is EXACT but measures %.2f over %d agreeing rows on this corpus", id, a.agreement(), a.Both)
		}
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

	// ─── 4b. D AT CONCEPT LEVEL ──────────────────────────────────────────
	// discrimination_D above is verdict-based, and by design a maintenance
	// fact that is our inference (staleness, version age) never moves a
	// verdict. So D is ALSO reported as "did the maintenance-state concept
	// fire", on both sides: a maintenance-state signal for us, a
	// deprecated/unmaintained alert for Socket. The verdict metric is
	// unchanged; this sits next to it.
	t.Log("D CONCEPT COVERAGE — maintenance state surfaced (any severity), next to the verdict count")
	t.Logf("  %-10s %5s | %10s %10s | %10s %10s", "ecosystem", "n", "cs_concept", "cs_verdict", "sk_concept", "sk_det")
	dConcept := map[string][5]int{}
	for _, l := range ledger {
		if l.Stratum != "D" {
			continue
		}
		v := dConcept[l.Eco]
		v[0]++
		if csMaintenanceConcept(l.CSSignals) {
			v[1]++
		}
		if l.CSOut == outDetected {
			v[2]++
		}
		if skMaintenanceConcept(l.SK) {
			v[3]++
		}
		if socketDetected(l.SK, headlineFloor) == outDetected {
			v[4]++
		}
		dConcept[l.Eco] = v
	}
	var dEcos []string
	for e := range dConcept {
		dEcos = append(dEcos, e)
	}
	sort.Strings(dEcos)
	var dTot [5]int
	for _, e := range dEcos {
		v := dConcept[e]
		for i := range v {
			dTot[i] += v[i]
		}
		t.Logf("  %-10s %5d | %10d %10d | %10d %10d", e, v[0], v[1], v[2], v[3], v[4])
	}
	if dTot[0] > 0 {
		t.Logf("  %-10s %5d | %10d %10d | %10d %10d", "TOTAL", dTot[0], dTot[1], dTot[2], dTot[3], dTot[4])
		stratTotals["maintenance_concept_D"] = map[string]int{"n": dTot[0], "cs_concept": dTot[1],
			"cs_verdict_detected": dTot[2], "sk_concept": dTot[3], "sk_detected": dTot[4]}
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
	t.Log("CONCEPT-LEVEL FIDELITY (compared pairings: EXACT, and PARTIAL demoted on a")
	t.Log("measurement; positive signals and")
	t.Log("transitive rollups excluded structurally, not thresholded out).")
	t.Log("Three buckets, NEVER one ratio — mixing them reports architecture as")
	t.Log("detector quality:")
	t.Log("  metadata  both sides reach it from registry metadata: a real comparison")
	t.Log("  artifact  needs package BYTES. Our public intelligence path is")
	t.Log("            metadata-only (artifact providers declare NeedsArtifact and are")
	t.Log("            skipped); cap.* rides those bytes on every ecosystem, no flag.")
	t.Log("            Socket-only here is ARCHITECTURE, not blindness.")
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
		"concepts_sk_only", "adjudication", "adjudicator", "adjudicated_at", "cs_verdict_norepo",
		"cs_verdict_with_transitive", "cs_outcome_with_transitive"}
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
			strings.Join(l.ConceptSK, ","), "", "", "", l.CSVerdictNoRepo,
			l.CSVerdictWithTransitive, cmpOutcome(risk.Verdict(l.CSVerdictWithTransitive)).String()}
		for i, c := range cells {
			if strings.ContainsAny(c, "\t\n") {
				t.Fatalf("ledger field %d for %s/%s contains a tab or newline: %q",
					i, l.Eco, l.Pkg, c)
			}
		}
		fmt.Fprintln(lf, strings.Join(cells, "\t"))
	}
	lf.Close()

	bBoth, bCS, bSK, bSKBy := conceptTotals(ledger, func(l *cmpRow) bool { return !feedKnownMalicious(l) })
	nFeed := 0
	for i := range ledger {
		if feedKnownMalicious(&ledger[i]) {
			nFeed++
		}
	}
	t.Logf("concepts, behavioural view (%d feed-known malicious rows excluded): both %d, chainsaw-only %d, socket-only %d",
		nFeed, bBoth, bCS, bSK)

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
		"socket_states":      states,
		"threshold_sweep":    sweep,
		"stratum_totals":     stratTotals,
		"agreement":          map[string]any{"both_detected": bothY, "both_cleared": bothN, "chainsaw_only": csOnly, "socket_only": skOnly, "kappa": jsonNum(kap), "raw_agreement": jsonNum(raw)},
		"category_spearman":  rhoOut,
		"concepts_by_bucket": conceptOut,
		"concepts_all":       map[string]int{"both": both, "chainsaw_only": csO, "socket_only": skO},
		// The same concepts with feed-known malicious rows left out: on those
		// the engine emits only sc.known_malicious, so this is the view in
		// which a Socket-only concept can be a behavioural miss.
		"concepts_behavioural": map[string]any{"both": bBoth, "chainsaw_only": bCS, "socket_only": bSK,
			"rows_excluded_feed_known_malicious": nFeed},
		"socket_only_concepts_behavioural": bSKBy,
		"cve_tier_agreement":               map[string]any{"exact": tierAgree, "n": tierTotal, "matrix": tierMat},
		"socket_only_concepts":             socketOnlyAll,
		"unmapped_socket_alerts":           unmapped,
		"unobservable_signals":             unobservable,
		"unobservable_socket_alerts":       unobservableSK,
		"silent_signals":                   silent,
		"measured_pairings":                measuredOut,
		// B1: the headline grades Go rows without sc.transitive_*; the ledger's
		// cs_verdict_with_transitive is the verdict as scored, disclosed beside it.
		"go_headline_excludes_transitive": map[string]int{"go_rows": goT.rows,
			"go_rows_with_transitive_counts": goT.withCounts, "go_rows_verdict_changed": goT.changed},
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

// TestMaintenanceConceptCoversRegistryStateSignals pins the D concept-level
// count to the signals that express a maintenance fact. A signal dropped
// from the concept map would silently stop counting.
func TestMaintenanceConceptCoversRegistryStateSignals(t *testing.T) {
	for _, id := range []string{"sc.deprecated_by_maintainer", "maint.no_recent_release", "maint.abandoned_repo",
		"sc.repo_archived", "maint.relocated", "maint.outdated_version"} {
		if !csMaintenanceConcept([]string{id}) {
			t.Errorf("%s does not count toward D concept coverage", id)
		}
	}
	for _, id := range []string{"maint.single_maintainer", "maint.unpopular_package", "cap.network"} {
		if csMaintenanceConcept([]string{id}) {
			t.Errorf("%s is not a maintenance-state fact but counts toward D", id)
		}
	}
}

// TestSocketDeclinedSurfacesAreNotCoverage is the G-3 guard, and the thing it
// guards is the difference between a decision and a claim.
//
// Declining a surface records that we will not build it. It must not change a
// single agreement number: Socket really does report those 52 alerts and we
// really do not, so they have to keep counting as socket-only. There are
// exactly two ways to turn the decision into a false claim of coverage, and
// this test refuses both:
//
//  1. Naming a declined slug in socketConceptMap. At EXACT it enters
//     socketAlertBucket, so the alert starts reaching skC AND csC and lands in
//     ConceptBoth — it does not move out of socketOnlyAll, it was never in it;
//     it enters the metric for the first time, as agreement, with no detector
//     behind it. At PARTIAL or NONE it stays out of socketAlertBucket but the
//     pairing still claims in the map that we cover an alert we decided not to
//     build, which is the documentation half of the same lie. The guard refuses
//     every grade.
//  2. Adding a declined slug to chainsawDetectsButDoesNotScore, which writes
//     our side of the concept and so can score it as agreement.
//
// It also pins the per-surface counts, so a slug quietly added to or removed
// from a surface fails instead of silently redefining what was decided.
func TestSocketDeclinedSurfacesAreNotCoverage(t *testing.T) {
	t.Parallel()

	var taxonomy map[string]socketAlert
	if err := json.Unmarshal(socketAlertTypesJSON, &taxonomy); err != nil {
		t.Fatalf("parse embedded socket taxonomy: %v", err)
	}
	if len(taxonomy) == 0 {
		t.Fatal("embedded socket taxonomy parsed to zero entries — every assertion " +
			"below would pass vacuously")
	}
	byType := map[string]bool{}
	for _, a := range taxonomy {
		byType[a.Type] = true
	}

	// Every declined slug must be a REAL Socket alert. Declining something
	// that does not exist is a decision about nothing, and it would hide a
	// renamed alert as "already decided".
	for slug, surface := range socketDeclinedSurfaces {
		if !byType[slug] {
			t.Errorf("socketDeclinedSurfaces declines %q (%s), which is not in the "+
				"%d-type taxonomy — the alert was renamed or retired, so this decision "+
				"now covers nothing. Re-fetch socket.dev/alerts and re-decide.",
				slug, surface, len(taxonomy))
		}
		if _, ok := expectedDeclinedPerSurface[surface]; !ok {
			t.Errorf("slug %q names surface %q, which is not a decided surface "+
				"— add it to expectedDeclinedPerSurface deliberately or fix "+
				"the surface name", slug, surface)
		}
	}

	// Failure mode 1: a declined slug named by any signal, at any grade.
	for id, m := range socketConceptMap {
		for _, slug := range m.Socket {
			if surface, declined := socketDeclinedSurfaces[slug]; declined {
				t.Errorf("signal %q maps to %q, which is DECLINED as part of the %q "+
					"surface (grade %s).\n"+
					"A declined surface is work we chose not to do, not work we have "+
					"done. The concept loop writes csC for every slug in a Socket "+
					"slice, so this pairing moves the alert out of socketOnlyAll and "+
					"raises the agreement ratio with no detector behind it.\n"+
					"If the detector genuinely covers this alert now, the surface is no "+
					"longer declined: remove the slug from socketDeclinedSurfaces, drop "+
					"its per-surface count, and say so in the plan.",
					id, slug, surface, m.Grade)
			}
		}
	}

	// Failure mode 2: a declined slug smuggled in as a detected-but-unscored
	// finding, which is counted as agreement on both sides.
	for slug := range chainsawDetectsButDoesNotScore {
		if surface, declined := socketDeclinedSurfaces[slug]; declined {
			t.Errorf("%q is in BOTH chainsawDetectsButDoesNotScore and "+
				"socketDeclinedSurfaces (%s). Those are contradictory: the first says "+
				"we detect it and write it into the report, the second says we have "+
				"decided not to build the surface. Pick one.", slug, surface)
		}
	}

	// The shape of the decision itself.
	got := map[string]int{}
	for _, surface := range socketDeclinedSurfaces {
		got[surface]++
	}
	total := 0
	for surface, want := range expectedDeclinedPerSurface {
		if got[surface] != want {
			t.Errorf("surface %q has %d declined slugs, expected %d — a slug was added "+
				"or dropped, which changes what G-3 decided", surface, got[surface], want)
		}
		total += want
	}
	if len(socketDeclinedSurfaces) != total {
		t.Errorf("socketDeclinedSurfaces holds %d slugs but the decided surfaces account "+
			"for %d — a slug names a surface outside expectedDeclinedPerSurface",
			len(socketDeclinedSurfaces), total)
	}
	t.Logf("G-3: %d alerts declined across %d surfaces %v. None is named by "+
		"socketConceptMap or chainsawDetectsButDoesNotScore, so none can be counted as "+
		"agreement. Note they are not counted as socket-only either: socketAlertBucket "+
		"is built from EXACT pairings only, so every unmapped alert — declined or not — "+
		"sits outside the published concept metric. The decision moves no number.",
		len(socketDeclinedSurfaces), len(expectedDeclinedPerSurface), got)
}

// dynamicRequire is require(<non-literal>) and has its own detector,
// cap.dynamic_require. It was once paired with cap.dynamic_eval*, a
// different claim (eval/Function), which made ~117 rows read as
// Chainsaw-only against Socket's 8. Keep the eval pair out.
func TestDynamicRequireIsNotPairedWithEval(t *testing.T) {
	for _, id := range []string{"cap.dynamic_eval", "cap.dynamic_eval_observed"} {
		for _, s := range socketConceptMap[id].Socket {
			if s == "dynamicRequire" {
				t.Errorf("%s is paired with dynamicRequire; that alert belongs to cap.dynamic_require", id)
			}
		}
	}
	if m := socketConceptMap["cap.dynamic_require"]; len(m.Socket) != 1 || m.Socket[0] != "dynamicRequire" {
		t.Errorf("cap.dynamic_require must pair with exactly dynamicRequire, got %v", m.Socket)
	}
}
