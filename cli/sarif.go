package cli

// sarif.go — SARIF 2.1.0 emitter for the scan family (P1.6).
//
// `chainsaw scan --format sarif` (and pr-scan / scan-actions) renders the
// already-computed scan results as a SARIF 2.1.0 log so the findings drop
// straight into GitHub code-scanning, GitLab, Azure DevOps, or any SARIF
// ingester without a translation step.
//
// Modeling decisions (kept close to OSV-Scanner's SARIF output so consumers
// who already parse OSV reports need no new handling):
//
//   - One rule PER vulnerability, keyed by its alias (the CVE / GHSA / OSV id).
//     Multiple affected packages that share a vulnerability collapse onto the
//     same rule, so a code-scanning dashboard groups them under one entry.
//   - One result PER affected package occurrence, referencing its rule. The
//     result message names the package@version so the row is self-describing.
//   - Supply-chain conditions that carry no CVE alias still surface as rules
//     keyed by a synthetic "CHAINSAW-<condition>" id, so a publisherChanged /
//     hidden-unicode finding is not silently dropped from the SARIF view.
//   - help.markdown carries the remediation guidance (severity, affected
//     package, upgrade hint) — the field GitHub renders in the alert detail.
//
// SARIF is a RESULT artifact: it is written to outWriter(cmd) (a file when
// --output is set, else stdout) via the foundation's purity-aware path. The
// envelope carries schemaVersion alongside the SARIF version so a consumer can
// tell which chainsaw schema produced it.

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// sarifSchemaURI is the canonical SARIF 2.1.0 JSON-schema URL. Emitting it in
// $schema lets validators and editors resolve the schema without guessing.
const sarifSchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"

// sarifVersion is the SARIF spec version this emitter targets. Pinned as a
// constant so the version field and any consumer-facing docs never drift.
const sarifVersion = "2.1.0"

// sarifToolName / sarifInformationURI identify chainsaw as the producing tool
// in tool.driver. Kept terse; the rules carry the per-finding detail.
const (
	sarifToolName       = "chainsaw"
	sarifInformationURI = "https://chain305.com"
)

// ── SARIF 2.1.0 wire types ──────────────────────────────────────────────────
//
// Only the subset chainsaw populates is modeled; every optional field is
// `omitempty` so the emitted log stays compact and a strict validator sees no
// empty-string noise. Field names match the SARIF schema exactly.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string           `json:"id"`
	Name                 string           `json:"name,omitempty"`
	ShortDescription     sarifMessage     `json:"shortDescription"`
	FullDescription      *sarifMessage    `json:"fullDescription,omitempty"`
	Help                 *sarifHelp       `json:"help,omitempty"`
	DefaultConfiguration *sarifRuleConfig `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any   `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level,omitempty"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// ── Builder ─────────────────────────────────────────────────────────────────

// scanResultsToSARIF converts the enriched scan results into a SARIF 2.1.0 log.
//
// Rules are deduplicated and ordered deterministically (vulnerability aliases
// first in their natural sort order, then synthetic supply-chain rules) so the
// emitted log is byte-stable across runs for the same input — a property CI
// diffing depends on. Results preserve input package order; each references its
// rule by both ruleId and ruleIndex (required by some strict SARIF ingesters).
func scanResultsToSARIF(results []scanResultItem) sarifLog {
	// ruleIndex tracks the position of each rule id in the driver.rules slice
	// so results can carry the matching ruleIndex. Rules are appended in a
	// deterministic order below.
	ruleIndex := map[string]int{}
	var rules []sarifRule

	// addRule registers a rule once, returning its stable index. Idempotent on
	// id (first-wins) so a rule is appended exactly once even if many results
	// reference it.
	addRule := func(r sarifRule) int {
		if idx, ok := ruleIndex[r.ID]; ok {
			return idx
		}
		idx := len(rules)
		ruleIndex[r.ID] = idx
		rules = append(rules, r)
		return idx
	}

	// Rule metadata is collected into id-keyed maps as results are emitted
	// (first affected package supplies the human text), then materialized into
	// driver.rules in a deterministic order so the log is byte-stable.
	aliasRule := map[string]sarifRule{}
	condRule := map[string]sarifRule{}

	var sarifResults []sarifResult
	for _, r := range results {
		pkgRef := r.Name + "@" + r.Version
		level := sarifLevelFor(r.Severity)

		// Emit a result per CVE alias on this package (each references the
		// shared alias rule). A package with N CVEs produces N results — one
		// per (package, vulnerability) pair, mirroring OSV-Scanner.
		emittedForPkg := false
		for _, cve := range r.CVEs {
			if cve == "" {
				continue
			}
			if _, ok := aliasRule[cve]; !ok {
				aliasRule[cve] = sarifAliasRule(cve, r)
			}
			sarifResults = append(sarifResults, sarifResult{
				RuleID:  cve,
				Level:   level,
				Message: sarifMessage{Text: fmt.Sprintf("%s is affected by %s (severity: %s)", pkgRef, cve, sarifSeverityLabel(r.Severity))},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: pkgRef},
					},
				}},
			})
			emittedForPkg = true
		}

		// Vulnerable but no enumerated CVE: synthetic per-package rule so the
		// vulnerability is not dropped from the SARIF view.
		if r.Status == "vulnerable" && !emittedForPkg {
			id := sarifVulnRuleID(r)
			if _, ok := condRule[id]; !ok {
				condRule[id] = sarifVulnRule(id, r)
			}
			sarifResults = append(sarifResults, sarifResult{
				RuleID:  id,
				Level:   level,
				Message: sarifMessage{Text: fmt.Sprintf("%s is flagged vulnerable (severity: %s)", pkgRef, sarifSeverityLabel(r.Severity))},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: pkgRef},
					},
				}},
			})
		}

		// Supply-chain conditions: one result per (package, condition).
		for _, cond := range r.TriggeredConditions {
			id := sarifConditionRuleID(cond)
			if _, ok := condRule[id]; !ok {
				condRule[id] = sarifConditionRule(id, cond)
			}
			condLevel := sarifLevelFor(supplyChainConditionSeverity[cond])
			sarifResults = append(sarifResults, sarifResult{
				RuleID:  id,
				Level:   condLevel,
				Message: sarifMessage{Text: fmt.Sprintf("%s triggers supply-chain condition %q", pkgRef, cond)},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: pkgRef},
					},
				}},
			})
		}
	}

	// Materialize rules in deterministic order: sorted aliases, then sorted
	// conditions. addRule assigns the stable index used to backfill results.
	for _, id := range sortedKeys(mapKeys(aliasRule)) {
		addRule(aliasRule[id])
	}
	for _, id := range sortedKeys(mapKeys(condRule)) {
		addRule(condRule[id])
	}

	// Backfill ruleIndex on every result now that the rule order is final.
	for i := range sarifResults {
		sarifResults[i].RuleIndex = ruleIndex[sarifResults[i].RuleID]
	}

	return newSARIFLog(rules, sarifResults)
}

// writeScanSARIF encodes the SARIF log for the given results to w using the
// shared indented encoder so the bytes match every other chainsaw JSON sink.
func writeScanSARIF(w io.Writer, results []scanResultItem) error {
	return encodeJSON(w, scanResultsToSARIF(results))
}

// newSARIFLog wraps a rule set and result set into the single-run SARIF 2.1.0
// envelope every chainsaw emitter shares (same $schema, version, and tool
// driver). Callers pass already-deterministically-ordered rules/results.
func newSARIFLog(rules []sarifRule, results []sarifResult) sarifLog {
	if rules == nil {
		rules = []sarifRule{}
	}
	if results == nil {
		results = []sarifResult{}
	}
	return sarifLog{
		Schema:  sarifSchemaURI,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           sarifToolName,
				InformationURI: sarifInformationURI,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

// ── scan-actions SARIF ──────────────────────────────────────────────────────

// scanActionsToSARIF converts GitHub-Actions scanner findings into a SARIF
// 2.1.0 log. One rule PER signal id (unpinned_ref, typosquat, …); each finding
// is a result located at its workflow file:line so a code-scanning ingester
// annotates the exact YAML line. Rules are emitted in sorted signal-id order
// for byte stability; results preserve the report's (already-sorted) order.
func scanActionsToSARIF(report scanActionsReport) sarifLog {
	ruleIndex := map[string]int{}
	var rules []sarifRule
	ruleMeta := map[string]sarifRule{}

	results := make([]sarifResult, 0, len(report.Findings))
	for _, f := range report.Findings {
		if _, ok := ruleMeta[f.Signal]; !ok {
			ruleMeta[f.Signal] = sarifActionsRule(f)
		}
		file := f.File
		if file == "" {
			file = "<unknown>"
		}
		results = append(results, sarifResult{
			RuleID:  f.Signal,
			Level:   sarifLevelFor(f.Severity),
			Message: sarifMessage{Text: f.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: file},
				},
			}},
		})
	}

	for _, id := range sortedKeys(mapKeys(ruleMeta)) {
		ruleIndex[id] = len(rules)
		rules = append(rules, ruleMeta[id])
	}
	for i := range results {
		results[i].RuleIndex = ruleIndex[results[i].RuleID]
	}
	return newSARIFLog(rules, results)
}

// sarifActionsRule builds the rule for a scan-actions signal id. The first
// finding carrying the signal supplies the level + description text.
func sarifActionsRule(f scanActionsFinding) sarifRule {
	var md strings.Builder
	fmt.Fprintf(&md, "## %s\n\n", f.Signal)
	fmt.Fprintf(&md, "%s\n\n", f.Message)
	if f.Detail != "" {
		fmt.Fprintf(&md, "%s\n\n", f.Detail)
	}
	md.WriteString("### Remediation\n\n")
	md.WriteString("Pin the action to a full-length commit SHA and confirm the publisher is trusted before re-enabling the workflow.\n")
	return sarifRule{
		ID:               f.Signal,
		Name:             f.Signal,
		ShortDescription: sarifMessage{Text: fmt.Sprintf("GitHub Actions signal: %s", f.Signal)},
		Help:             &sarifHelp{Text: f.Message, Markdown: md.String()},
		DefaultConfiguration: &sarifRuleConfig{
			Level: sarifLevelFor(f.Severity),
		},
		Properties: map[string]any{
			"tags": []string{"security", "supply-chain", "github-actions"},
		},
	}
}

// writeScanActionsSARIF encodes the scan-actions SARIF log to w.
func writeScanActionsSARIF(w io.Writer, report scanActionsReport) error {
	return encodeJSON(w, scanActionsToSARIF(report))
}

// ── pr-scan SARIF ───────────────────────────────────────────────────────────

// prScanToSARIF converts a pr-scan report into a SARIF 2.1.0 log. One rule PER
// signal id; each added/upgraded entry that fired a signal becomes a result
// located at the dependency coordinate. Entries with an "allow" verdict and no
// signals produce no result (nothing to annotate). Deterministic rule order.
func prScanToSARIF(report prScanReport) sarifLog {
	ruleIndex := map[string]int{}
	var rules []sarifRule
	ruleMeta := map[string]sarifRule{}

	var results []sarifResult
	emit := func(e prScanEntry) {
		coord := e.Ecosystem + ":" + e.Name + "@" + e.Version
		for _, sig := range e.Signals {
			if _, ok := ruleMeta[sig.ID]; !ok {
				ruleMeta[sig.ID] = sarifPRScanRule(sig)
			}
			results = append(results, sarifResult{
				RuleID:  sig.ID,
				Level:   sarifPRScanLevel(sig.Severity),
				Message: sarifMessage{Text: fmt.Sprintf("%s: %s", coord, sig.Reason)},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: coord},
					},
				}},
			})
		}
	}
	for _, e := range report.Added {
		emit(e)
	}
	for _, e := range report.Upgraded {
		emit(e)
	}

	for _, id := range sortedKeys(mapKeys(ruleMeta)) {
		ruleIndex[id] = len(rules)
		rules = append(rules, ruleMeta[id])
	}
	for i := range results {
		results[i].RuleIndex = ruleIndex[results[i].RuleID]
	}
	return newSARIFLog(rules, results)
}

// sarifPRScanRule builds the rule for a pr-scan signal id.
func sarifPRScanRule(sig prScanSignal) sarifRule {
	var md strings.Builder
	fmt.Fprintf(&md, "## %s\n\n", sig.ID)
	fmt.Fprintf(&md, "%s\n\n", sig.Reason)
	md.WriteString("### Remediation\n\n")
	md.WriteString("Review the newly added or upgraded dependency before merging. Run `chainsaw scan <name>@<version>` for full offline-plus-server signals.\n")
	return sarifRule{
		ID:               sig.ID,
		Name:             sig.ID,
		ShortDescription: sarifMessage{Text: fmt.Sprintf("PR dependency signal: %s", sig.ID)},
		Help:             &sarifHelp{Text: sig.Reason, Markdown: md.String()},
		DefaultConfiguration: &sarifRuleConfig{
			Level: sarifPRScanLevel(sig.Severity),
		},
		Properties: map[string]any{
			"tags": []string{"security", "supply-chain", "pr-scan"},
		},
	}
}

// sarifPRScanLevel maps pr-scan's two severities (warn|block) onto SARIF levels.
// block→error so a code-scanning gate treats it as a failure; warn→warning.
func sarifPRScanLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "block":
		return "error"
	case "warn":
		return "warning"
	default:
		return "note"
	}
}

// writePRScanSARIF encodes the pr-scan SARIF log to w.
func writePRScanSARIF(w io.Writer, report prScanReport) error {
	return encodeJSON(w, prScanToSARIF(report))
}

// ── Rule constructors ───────────────────────────────────────────────────────

// sarifAliasRule builds the rule for a CVE/GHSA/OSV alias. The first affected
// package supplies the severity used for the default configuration level and
// the remediation markdown.
func sarifAliasRule(alias string, r scanResultItem) sarifRule {
	help := sarifVulnHelp(alias, r)
	return sarifRule{
		ID:               alias,
		Name:             alias,
		ShortDescription: sarifMessage{Text: fmt.Sprintf("Vulnerability %s", alias)},
		FullDescription:  &sarifMessage{Text: fmt.Sprintf("Package %s is affected by %s.", r.Name, alias)},
		Help:             help,
		DefaultConfiguration: &sarifRuleConfig{
			Level: sarifLevelFor(r.Severity),
		},
		Properties: map[string]any{
			"security-severity": sarifSecuritySeverity(r),
			"tags":              []string{"security", "supply-chain", "vulnerability"},
		},
	}
}

// sarifVulnRuleID returns the synthetic rule id for a vulnerable package that
// carries no enumerated CVE. Namespaced so it never collides with a real alias.
func sarifVulnRuleID(r scanResultItem) string {
	return "CHAINSAW-VULN-" + strings.ToUpper(r.Name)
}

// sarifVulnRule builds the rule for a vulnerable-but-aliasless package.
func sarifVulnRule(id string, r scanResultItem) sarifRule {
	return sarifRule{
		ID:               id,
		Name:             id,
		ShortDescription: sarifMessage{Text: fmt.Sprintf("Vulnerable package %s", r.Name)},
		Help:             sarifVulnHelp("", r),
		DefaultConfiguration: &sarifRuleConfig{
			Level: sarifLevelFor(r.Severity),
		},
		Properties: map[string]any{
			"security-severity": sarifSecuritySeverity(r),
			"tags":              []string{"security", "supply-chain", "vulnerability"},
		},
	}
}

// sarifConditionRuleID namespaces a supply-chain condition into a SARIF rule id.
func sarifConditionRuleID(cond string) string {
	return "CHAINSAW-" + cond
}

// sarifConditionRule builds the rule for a supply-chain condition (e.g.
// publisherChanged, hasHiddenUnicode). The level derives from the product's
// condition→severity mapping so a SARIF dashboard inherits the same triage
// that --severity / --fail-on apply.
func sarifConditionRule(id, cond string) sarifRule {
	sev := supplyChainConditionSeverity[cond]
	help := &sarifHelp{
		Text:     sarifConditionRemediationText(cond),
		Markdown: sarifConditionRemediationMarkdown(cond, sev),
	}
	return sarifRule{
		ID:               id,
		Name:             cond,
		ShortDescription: sarifMessage{Text: fmt.Sprintf("Supply-chain condition: %s", cond)},
		Help:             help,
		DefaultConfiguration: &sarifRuleConfig{
			Level: sarifLevelFor(sev),
		},
		Properties: map[string]any{
			"tags": []string{"security", "supply-chain"},
		},
	}
}

// ── Remediation help text ───────────────────────────────────────────────────

// sarifVulnHelp renders the markdown remediation block GitHub shows in the
// alert detail. Modeled on OSV-Scanner: a heading, the affected package, and
// the upgrade guidance we can offer offline.
func sarifVulnHelp(alias string, r scanResultItem) *sarifHelp {
	var md strings.Builder
	if alias != "" {
		fmt.Fprintf(&md, "## %s\n\n", alias)
	} else {
		fmt.Fprintf(&md, "## Vulnerable package: %s\n\n", r.Name)
	}
	fmt.Fprintf(&md, "**Affected package:** `%s@%s`\n\n", r.Name, r.Version)
	if r.Severity != "" {
		fmt.Fprintf(&md, "**Severity:** %s\n\n", sarifSeverityLabel(r.Severity))
	}
	if r.CVSSScore != nil {
		fmt.Fprintf(&md, "**CVSS:** %.1f\n\n", *r.CVSSScore)
	}
	md.WriteString("### Remediation\n\n")
	md.WriteString("Upgrade `" + r.Name + "` to a fixed release, or remove the dependency if no fix is available. ")
	md.WriteString("Run `chainsaw scan " + r.Name + "@<version>` to confirm a candidate version is clean before pinning it.\n")

	text := fmt.Sprintf("Vulnerable package %s@%s. Upgrade to a fixed release or remove the dependency.", r.Name, r.Version)
	return &sarifHelp{Text: text, Markdown: md.String()}
}

// sarifConditionRemediationText is the plain-text help for a supply-chain
// condition rule (the SARIF `help.text` fallback when a viewer can't render
// markdown).
func sarifConditionRemediationText(cond string) string {
	if hint, ok := sarifConditionHints[cond]; ok {
		return hint
	}
	return "Review this supply-chain signal before allowing the package into your build."
}

// sarifConditionRemediationMarkdown renders the GitHub-facing markdown for a
// supply-chain condition rule.
func sarifConditionRemediationMarkdown(cond, sev string) string {
	var md strings.Builder
	fmt.Fprintf(&md, "## Supply-chain condition: %s\n\n", cond)
	if sev != "" {
		fmt.Fprintf(&md, "**Severity:** %s\n\n", sarifSeverityLabel(sev))
	}
	md.WriteString("### Remediation\n\n")
	md.WriteString(sarifConditionRemediationText(cond))
	md.WriteString("\n")
	return md.String()
}

// sarifConditionHints maps each derived supply-chain condition to a one-line
// remediation hint. Conditions without an entry fall back to a generic line.
var sarifConditionHints = map[string]string{
	"hasInstallScript":           "This package runs an install script. Audit the script before installing, or install with scripts disabled.",
	"installScriptFetchesRemote": "The install script fetches and executes remote code — a common malware delivery vector. Do not install until the script is reviewed.",
	"publisherChanged":           "The publishing identity changed for this package. Verify the new publisher is legitimate before upgrading.",
	"versionAnomaly":             "This version shows a version-numbering anomaly (e.g. a regression or major skip). Confirm it is an intentional release.",
	"hasHiddenUnicode":           "The package contains hidden/bidirectional Unicode that can hide malicious code from review. Inspect the source with Unicode rendering enabled.",
	"publishVelocityAnomaly":     "An unusually high publish velocity was observed in the last 24h, which can indicate a compromised account. Hold the upgrade until the cadence normalizes.",
	"malware":                    "This package matched a known-malware signature. Do not install; remove it from your dependency tree.",
	"typosquat":                  "This package name resembles a popular package and may be a typosquat. Confirm you intended this exact name.",
	"repoLinkMissing":            "The declared source repository is missing or its ownership does not match the publisher. Verify provenance before trusting the package.",
	"repoLinkArchived":           "The source repository is archived — the package is likely unmaintained. Consider an actively maintained alternative.",
	"provenanceUnverified":       "Build provenance could not be verified for this package. Prefer a release with verifiable provenance where possible.",
}

// ── Severity / level mapping ────────────────────────────────────────────────

// sarifLevelFor maps a chainsaw severity onto a SARIF result level. SARIF
// defines error|warning|note|none; we map critical/high→error, medium→warning,
// low→note, and anything else→note (never "none", so the finding stays visible).
func sarifLevelFor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "note"
	}
}

// sarifSeverityLabel renders a human label for a severity, defaulting to
// "unknown" for the empty/unmapped case so messages never read "severity: ".
func sarifSeverityLabel(severity string) string {
	if severity == "" {
		return "unknown"
	}
	return severity
}

// sarifSecuritySeverity returns the GitHub-recognized numeric security-severity
// string (0.0–10.0) used to bucket alerts. Prefer the real CVSS score when the
// server supplied one; otherwise fall back to a representative value per
// severity band so the alert still sorts sensibly.
func sarifSecuritySeverity(r scanResultItem) string {
	if r.CVSSScore != nil {
		return fmt.Sprintf("%.1f", *r.CVSSScore)
	}
	switch strings.ToLower(r.Severity) {
	case "critical":
		return "9.0"
	case "high":
		return "7.0"
	case "medium":
		return "5.0"
	case "low":
		return "2.0"
	default:
		return "0.0"
	}
}

// ── tiny map helpers ────────────────────────────────────────────────────────

// mapKeys returns the keys of a string-keyed map (order undefined; callers sort).
func mapKeys[V any](m map[string]V) map[string]struct{} {
	out := make(map[string]struct{}, len(m))
	for k := range m {
		out[k] = struct{}{}
	}
	return out
}

// sortedKeys returns the keys of a set in ascending order for deterministic
// rule emission.
func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
