package intelligence

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
	"github.com/chain305/chainsaw-core/risk"
)

// intelligence_reports and intelligence_latest_probes are keyed on the
// package coordinate alone (ecosystem, package_name, version). Package
// facts — CVEs, malware verdicts, typosquat signals, risk evaluations —
// are universal and do not vary by tenant, so the tables are shared
// across orgs. The orgID parameter on every method below is retained
// for API compatibility with older callers but no longer narrows the
// query. See internal/pgstore/store.go for the migration that strips
// org_id from the table PKs.
//
// KNOWN DEFECT (L-02) — the paragraph above states the INTENT, not the
// current behaviour. Two values written to this table are tenant-derived
// today, so the row is not in fact universal:
//
//  1. Vulnerabilities. cveProvider (provider_cve.go) reads the ORG-SCOPED
//     vulnerability_metadata table — metadata/store.go queries
//     `WHERE org_id=? AND repository=? AND package=? AND version=?` — and
//     the resulting VulnSection is merged into the report this Upsert
//     persists. mergeReportPayload then lists report.vulnerabilities as a
//     PRESERVED subtree, so the value is sticky.
//  2. SupplyChain.TrustScore. scanner.go calls
//     ComputeTrustScoreForOrg(report, req.OrgID), which applies the
//     REQUESTING org's private risk-weight overrides, and the merge rules
//     below always take TrustScore from the incoming report.
//
// Severity, stated deliberately and not inflated: what crosses the tenant
// boundary is a verdict about a PUBLIC package coordinate derived from a
// PUBLIC vulnerability database, plus a scanner digest and a weight-tuned
// score. The row names neither the authoring org nor its repository. This
// is cross-tenant cache contamination and non-reproducible verdicts — NOT
// a data breach, and it must not be described as one to a customer or an
// auditor. The real harms are that a tenant's verdict is unreproducible
// from its own scanner, that it is last-writer-wins in BOTH directions
// (one tenant's populated scan replaces another's wholesale, so CVEs can
// be suppressed as well as injected), and that a tenant who shapes its own
// scanner payload can move what other tenants see.
//
// Both behaviours are pinned by characterization tests in
// store_tenancy_test.go; invert those assertions when the fix lands.
//
// The remedy is NOT to strip the vuln section from this row and resolve it
// per-org at read time, and it is NOT to persist an OSV-only baseline
// instead. Both make VulnDataAvailable (risk_projection.go, literally
// `Vulnerabilities.ScannedAt != nil`) false for the majority of cache
// hits: the OSV index is built solely from advisory records, so it has
// nothing to say about a CLEAN package and stamps no ScannedAt for one.
// That drops the Vulnerability category out of the risk rollup for most
// coordinates and feeds the opt-in core/coverage fail-closed gate. See
// TestOSVProvider_CannotServeAsUniversalVulnBaseline in
// provider_osv_test.go, which pins that blocker, and
// docs/qa-remediation/L-02-REDIAGNOSIS.md for the four earlier diagnoses
// that were wrong. Any real fix has to supply a universal "scanned, clean"
// stamp from a source that actually covers clean packages before the
// per-org split can be made without a product-wide score shift.

// Store persists Report rows to the intelligence_reports table and the
// latest-version probe results to intelligence_latest_probes.
type Store struct {
	sql *pgstore.Store
}

// NewStore wires an intelligence store against the shared pgstore.Store.
// A nil *pgstore.Store is allowed (tests), in which case every method
// returns ErrNotFound or noop-upserts.
func NewStore(db *pgstore.Store) *Store {
	s := &Store{sql: db}
	// Install the probe-backed corroborator used by the
	// upgrade_available promotion gate. ComputeTrustScoreForOrg runs
	// with no context and no store handle, so the seam is a
	// package-level hook (same shape as OrgWeightsResolver); this is
	// the only place a real store exists early enough to fill it.
	// Last-writer-wins is harmless — every Store points at the same
	// intelligence_latest_probes table.
	LatestVersionCorroborator = s.latestVersionCorroborator
	return s
}

// latestVersionCorroborator answers the promotion gate's "is this fix
// version actually published?" question from the daily probe row.
//
// It is deliberately conservative: an errored probe, an empty
// latest_version, or a probe past its fresh_until returns ok=false, which
// the caller reads as "no corroboration available" rather than as a veto.
// A stale probe must not veto a real fix, and must not endorse one
// either.
//
// The 2s budget bounds the cost this adds to the scan hot path. The gate
// only reaches here for a package that already passed the evidence and
// category gates AND whose Report carries no Release.LatestVersion, which
// is a small slice of scans.
func (s *Store) latestVersionCorroborator(ecosystem, pkg string) (string, bool) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	probe, err := s.GetLatestVersionProbe(ctx, "", ecosystem, pkg)
	if err != nil || probe == nil {
		return "", false
	}
	if probe.Error != "" || strings.TrimSpace(probe.LatestVersion) == "" {
		return "", false
	}
	if !probe.FreshUntil.IsZero() && time.Now().After(probe.FreshUntil) {
		return "", false
	}
	return probe.LatestVersion, true
}

// Get returns the cached Report, or ErrNotFound if no row exists.
// orgID is ignored — intelligence reports are universal; the parameter
// is retained to avoid changing every caller's signature.
func (s *Store) Get(ctx context.Context, orgID string, key Key) (*Report, error) {
	_ = orgID
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return nil, ErrNotFound
	}
	// risk_evaluation is selected as NULLable — rows predating Phase 2
	// carry SQL NULL and must deserialise to report.Risk = nil, never
	// an empty Evaluation struct.
	row := s.sql.DB().QueryRowContext(ctx, `
		SELECT report, risk_evaluation FROM intelligence_reports
		WHERE ecosystem=$1 AND package_name=$2 AND version=$3
	`, key.Ecosystem, key.Package, key.Version)
	var (
		payload  []byte
		riskBlob []byte
	)
	if err := row.Scan(&payload, &riskBlob); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("intelligence: load report: %w", err)
	}
	var r Report
	if err := json.Unmarshal(payload, &r); err != nil {
		return nil, fmt.Errorf("intelligence: decode report: %w", err)
	}
	// Attach risk evaluation if the dedicated column has a value. We
	// trust the dedicated column over r.Risk (which may also be
	// embedded in the JSONB report) so the column can be reindexed /
	// rewritten without touching the bulk report blob.
	if len(riskBlob) > 0 {
		var eval risk.Evaluation
		if err := json.Unmarshal(riskBlob, &eval); err != nil {
			return nil, fmt.Errorf("intelligence: decode risk evaluation: %w", err)
		}
		r.Risk = &eval
	}
	return &r, nil
}

// ListVersions returns every cached version of (ecosystem, name) so
// callers can pick one that satisfies a range constraint. Order is
// not guaranteed — the caller is responsible for parsing and ranking.
// orgID is ignored — see the package-level comment.
func (s *Store) ListVersions(ctx context.Context, orgID, ecosystem, name string) ([]string, error) {
	_ = orgID
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return nil, nil
	}
	rows, err := s.sql.DB().QueryContext(ctx, `
		SELECT version FROM intelligence_reports
		WHERE ecosystem=$1 AND package_name=$2
	`, ecosystem, name)
	if err != nil {
		return nil, fmt.Errorf("intelligence: list versions: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("intelligence: scan version: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("intelligence: iterate versions: %w", err)
	}
	return out, nil
}

// Upsert writes the Report and its denormalised search columns. When a
// prior row exists, the report JSONB is *merged* — Tier-2 subtrees the
// new report leaves empty (Scan, Vulns, Maintenance version timeline +
// repo-activity counts) are preserved from the prior row so a Tier-1-only
// refresher tick cannot clobber Tier-2 data the proxy hot-path populated
// 24h earlier. The denormalised columns (is_malicious, max_cvss, etc.)
// continue to reflect the *new* incoming report — those track the latest
// scan's verdict, not the merged blob. orgID is ignored — see the
// package-level comment.
// crossOrgVulnOverwrites counts how many times a report Upsert replaced a
// non-empty vulnerability section that a DIFFERENT org had authored.
//
// This is the L-02 measurement, and it exists because the severity of that
// defect is genuinely unknown: the one production instance we sampled showed
// the shared row carrying an `osv-bundle` digest, i.e. the legitimately
// universal source, with no contamination visible. Partitioning the hottest
// cache in the product is a multi-week change; a counter is a day. Read it
// before deciding.
//
// Deliberately a process counter and not a metric export: it is a
// decision-support number for us, not an SLI, and wiring it into the metrics
// surface would imply operators should act on it.
var crossOrgVulnOverwrites atomic.Int64

// CrossOrgVulnOverwrites reports the counter above. Test and diagnostic use.
func CrossOrgVulnOverwrites() int64 { return crossOrgVulnOverwrites.Load() }

// TyposquatConfidenceOf normalises the (status, confidence) pair the
// typosquat provider writes into the value stored in the denormalised
// intelligence_reports.typosquat_confidence column.
//
// Returns "" for anything that is not a suspected hit, and the
// lowercased grade ("high" / "medium" / "low") otherwise. A suspected
// hit that carries no grade — a report written before the provider
// started emitting one — also returns "", which readers must treat as
// "ungraded", NOT as "low".
func TyposquatConfidenceOf(status, confidence string) string {
	if !strings.EqualFold(strings.TrimSpace(status), "suspected") {
		return ""
	}
	switch c := strings.ToLower(strings.TrimSpace(confidence)); c {
	case "high", "medium", "low":
		return c
	default:
		return ""
	}
}

// TyposquatIsActionable reports whether a typosquat hit deserves the
// is_typosquat denormalised flag — the flag that drives the list filter,
// the sidebar facet count, and (before this change) the red chip.
//
// WHY THIS IS NOT `status == "suspected"`. The detector grades hits
// high / medium / low and the risk engine tiers them -40 / -20 / -8
// (core/risk/registry_supplychain.go). "low" is the combosquat lane:
// "this name CONTAINS a popular name with <= 8 extra characters". That
// is a real signal but a very broad one — `lodash.merge`, a first-party
// package published by the lodash team, contains `lodash` with 6 extra
// characters and scores -8, landing at 96 / grade A / verdict allow.
// Measured against a held-out corpus of 24,206 real download-ranked
// benign packages (npm rank 5,001-17,334 and PyPI rank 3,001-15,000,
// built by scripts/detection-eval/build-heldout-name-corpus.sh), 3,151
// of them — 13.0% — take a low-confidence combosquat hit.
//
// Collapsing that 13% into the same boolean as a homoglyph attack made
// the flagship Package Intelligence surface contradict itself: a red
// ATTACK chip beside an "allow 96" verdict. So the boolean now means
// "actionable typosquat" (high or medium), and the grade travels
// separately in typosquat_confidence so low-confidence hits can still be
// SHOWN — quietly — without being COUNTED as attacks.
//
// Ungraded suspected hits (legacy rows, or a future provider that
// forgets to grade) stay actionable. Absence of evidence about severity
// must not silently downgrade a real signal.
func TyposquatIsActionable(status, confidence string) bool {
	if !strings.EqualFold(strings.TrimSpace(status), "suspected") {
		return false
	}
	return !strings.EqualFold(strings.TrimSpace(confidence), "low")
}

func (s *Store) Upsert(ctx context.Context, orgID string, r *Report) error {
	if s == nil || s.sql == nil || s.sql.DB() == nil || r == nil {
		return nil
	}

	// Ingest choke point. A coordinate whose version can never be ordered
	// against an advisory range (`${…}` build property, the synthetic
	// maven-metadata marker, a Maven meta-version, empty) is persisted —
	// deliberately, see markUnevaluableVersion for the store-vs-refuse
	// reasoning — but it is persisted MARKED, so it can never be read back
	// as scanned-and-clean.
	//
	// This is the last gate before a Report becomes a row, and every
	// writer reaches it: the proxy hot path, the refresher, the scan
	// worker, the dependency enqueuer, and anything a future producer
	// adds. runFanout already stamps the Scan path; this call is what
	// makes the guarantee hold for a Report that was built by hand
	// instead. It is idempotent, so the double-stamp is a no-op.
	//
	// The stamp lands before both consumers of r.Observation.Warnings
	// below: mergeReportPayload marshals them into the report JSONB, and
	// warning_count is written as len(r.Observation.Warnings) — so a
	// SQL-level consumer sees warning_count > 0 without decoding the blob.
	//
	// This mutates the caller's Report on purpose: a caller that inspects
	// what it just persisted should see the same warning the row carries.
	markUnevaluableVersion(r, r.Observation.CollectedAt)

	// Wrap the read-then-write in a transaction so a concurrent Upsert
	// for the same key cannot race between SELECT and INSERT. The
	// SELECT … FOR UPDATE inside this tx blocks concurrent writers on
	// the existing row's PK; the INSERT path naturally serialises through
	// the unique index when no prior row exists.
	tx, err := s.sql.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("intelligence: begin upsert tx: %w", err)
	}
	// Rollback is a no-op after a successful commit.
	defer func() { _ = tx.Rollback() }()

	// Read any prior row's report JSONB so we can preserve Tier-2 subtrees
	// the incoming report leaves empty. FOR UPDATE blocks concurrent
	// writers on the same key from interleaving.
	var (
		priorPayload []byte
		priorOrg     sql.NullString
	)
	row := tx.QueryRowContext(ctx, `
		SELECT report, authored_by_org FROM intelligence_reports
		WHERE ecosystem=$1 AND package_name=$2 AND version=$3
		FOR UPDATE
	`, r.Identity.Ecosystem, r.Identity.Package, r.Identity.Version)
	switch err := row.Scan(&priorPayload, &priorOrg); {
	case err == nil, errors.Is(err, sql.ErrNoRows):
		// Both fine — sql.ErrNoRows means this is a fresh insert and
		// priorPayload stays nil so the merge step becomes a no-op.
	default:
		return fmt.Errorf("intelligence: load prior report for merge: %w", err)
	}

	// Compute the merged report payload. mergeReportPayload is a no-op
	// when there is no prior row (priorPayload nil/empty), so the
	// fresh-insert path is unaffected.
	payload, err := mergeReportPayload(priorPayload, r)
	if err != nil {
		return fmt.Errorf("intelligence: merge report payload: %w", err)
	}

	var (
		artifactSHA     sql.NullString
		hasArtifactScan = r.Scan.Performed
		isMalicious     = strings.EqualFold(r.SupplyChain.MalwareStatus, "malicious")
		tsConfidence    = TyposquatConfidenceOf(r.SupplyChain.TyposquatStatus, r.SupplyChain.TyposquatConfidence)
		isTyposquat     = TyposquatIsActionable(r.SupplyChain.TyposquatStatus, r.SupplyChain.TyposquatConfidence)
		trustScore      sql.NullInt64
		maxCVSS         sql.NullFloat64
		riskPayload     []byte // nil ⇒ NULL in the risk_evaluation column
	)
	if r.Scan.ScannedArtifactSHA != "" {
		artifactSHA = sql.NullString{String: r.Scan.ScannedArtifactSHA, Valid: true}
	}
	if r.SupplyChain.TrustScore != 0 {
		trustScore = sql.NullInt64{Int64: int64(r.SupplyChain.TrustScore), Valid: true}
	}
	if r.Vulnerabilities.CVSSScore > 0 {
		maxCVSS = sql.NullFloat64{Float64: r.Vulnerabilities.CVSSScore, Valid: true}
	}
	// Marshal the v2 risk evaluation if present; leaving riskPayload nil
	// preserves the "flag-off" contract that no new column writes happen
	// for reports without Risk attached.
	if r.Risk != nil {
		riskPayload, err = json.Marshal(r.Risk)
		if err != nil {
			return fmt.Errorf("intelligence: encode risk evaluation: %w", err)
		}
	}

	// L-02 slice 1 — MEASUREMENT ONLY. Nothing here changes what is written.
	//
	// This table is keyed (ecosystem, package_name, version) with no org_id,
	// so whoever scans last owns the row. Most of a Report genuinely is a
	// fact about a coordinate, but the CVE section comes from the writing
	// org's own vulnerability_metadata — and mergeReportPayload preserves the
	// prior section ONLY when the incoming one is empty. A non-empty incoming
	// section therefore REPLACES another tenant's verdict, in either
	// direction: it can inject a false positive, and it can retract a real
	// critical. Both were reproduced against Postgres.
	//
	// Partitioning this table is expensive and was deliberately not attempted
	// (docs/qa-remediation/L-02-REDIAGNOSIS.md records why the obvious fix is
	// worse than the bug). So: count it first. The counter answers "does this
	// actually happen, and how often" before anyone pays for the fix.
	if prior := strings.TrimSpace(priorOrg.String); prior != "" && prior != strings.TrimSpace(orgID) &&
		!vulnSectionEmpty(r.Vulnerabilities) {
		crossOrgVulnOverwrites.Add(1)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO intelligence_reports (
			ecosystem, package_name, version, report,
			collected_at, fresh_until, artifact_sha256, has_artifact_scan,
			is_malicious, is_typosquat, trust_score, max_cvss, warning_count,
			risk_evaluation, authored_by_org, typosquat_confidence
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (ecosystem, package_name, version) DO UPDATE SET
			report = EXCLUDED.report,
			collected_at = EXCLUDED.collected_at,
			fresh_until = EXCLUDED.fresh_until,
			artifact_sha256 = COALESCE(EXCLUDED.artifact_sha256, intelligence_reports.artifact_sha256),
			has_artifact_scan = EXCLUDED.has_artifact_scan OR intelligence_reports.has_artifact_scan,
			is_malicious = EXCLUDED.is_malicious,
			is_typosquat = EXCLUDED.is_typosquat,
			typosquat_confidence = EXCLUDED.typosquat_confidence,
			trust_score = EXCLUDED.trust_score,
			max_cvss = EXCLUDED.max_cvss,
			warning_count = EXCLUDED.warning_count,
			risk_evaluation = EXCLUDED.risk_evaluation,
			authored_by_org = EXCLUDED.authored_by_org
	`,
		r.Identity.Ecosystem, r.Identity.Package, r.Identity.Version, payload,
		r.Observation.CollectedAt, r.Observation.FreshUntil, artifactSHA, hasArtifactScan,
		isMalicious, isTyposquat, trustScore, maxCVSS, len(r.Observation.Warnings),
		riskPayload, strings.TrimSpace(orgID), tsConfidence,
	)
	if err != nil {
		return fmt.Errorf("intelligence: upsert report: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("intelligence: commit upsert: %w", err)
	}
	return nil
}

// mergeReportPayload computes the JSONB payload to persist for an Upsert.
// When priorPayload is empty (no prior row) it returns json.Marshal(next).
// When priorPayload is populated, Tier-2/Tier-3 subtrees the *next* report
// left empty are filled in from the prior row before marshaling — so a
// Tier-1-only refresh tick does not clobber the artifact-scan / CVE /
// version-timeline data the proxy hot-path populated earlier, nor Tier-3
// enricher output (signature verification, repo-link probes, metadiff
// publisher signals, RTT account-age lookups, sigstore SLSA levels).
//
// Preserved subtrees / fields:
//   - report.artifactScan          — full ArtifactScanSection
//   - report.vulnerabilities       — full VulnSection (CVE list, KEV, etc.)
//   - report.maintenance.versionTimeline
//   - report.maintenance.firstPublishedAt
//   - report.maintenance.stars / forks / openIssues / subscribers
//   - report.artifact              — digests.actual / digests.verified /
//     signatureVerified / signatureKind /
//     signatureKeyId (Tier-2/3 outputs)
//   - report.supplyChain           — Tier-3 repo-link, metadiff, RTT fields
//     (RepoLinkStatus, PublisherChanged,
//     VersionAnomaly, SuspiciousRepoStars,
//     MaintainerAccountAgeDays,
//     FirstTimeCollaborator, NonExistentAuthor)
//     plus Tier-1 MalwareStatus/TyposquatStatus
//     when the new report's fields are empty.
//     TrustScore + TrustScoreBreakdown are
//     always taken from the incoming report
//     (recomputed every scan).
//   - report.people                — Authors / Maintainers / PublisherIDs /
//     TrustedPublisher (Tier-1 sourced, but
//     FirstTimeCollaborator reads prior.People
//     so we must not let it disappear)
//   - report.provenance            — Kind / Verified / SourceRepo /
//     BundleURL / SLSALevel (Tier-2/3
//     sigstore + signature-verify outputs)
//
// The denorm columns (is_malicious, max_cvss, etc.) are written from the
// *new* report by the caller — they reflect the latest scan's verdict
// rather than the merged blob.
//
// A field is "missing or empty" when the incoming Report's section is a
// zero value (Scan.Performed=false AND no scan fields set, Vulnerabilities
// has no CVEs AND no ScannedAt, etc.). When the new report carries a
// populated Tier-2/3 subtree, the new value wins — staleness is the failure
// mode we are guarding against, not freshness.
//
// Sticky-true semantics. PublisherChanged, VersionAnomaly, SuspiciousRepoStars,
// and NonExistentAuthor are *observed* events: once a Tier-3 enricher has
// recorded them, a later Tier-1-only refresh whose section is empty must
// not flip them off. They stay sticky-true until a future report
// explicitly observes a different value — i.e. the incoming field is non-
// zero (for *bool: the pointer is set; for bool: prior was true and incoming
// is false stays prior). This is symmetric with the "no scan ran" guard we
// already apply to Vulnerabilities: silence from one tier is not evidence
// the prior observation has been withdrawn.
func mergeReportPayload(priorPayload []byte, next *Report) ([]byte, error) {
	if len(priorPayload) == 0 {
		return json.Marshal(next)
	}
	// Decode the prior payload as a Report so we can apply field-aware
	// merge rules (rather than a deep-merge of arbitrary JSON, which
	// would incorrectly preserve stale values for fields that legitimately
	// transition from "set" to "unset" in the new report).
	var prior Report
	if err := json.Unmarshal(priorPayload, &prior); err != nil {
		// Corrupted prior row — surface the failure rather than falling
		// back to a plain marshal of next (which would silently lose the
		// Tier-2 preservation contract). Caller can retry.
		return nil, fmt.Errorf("decode prior report: %w", err)
	}

	merged := *next // shallow copy is safe — we replace whole subsections, never mutate the caller's pointer.

	// Scan: preserve the prior ArtifactScanSection when the new report's
	// Scan section is effectively empty. "Empty" means no scan was
	// performed AND every signal-bearing field is at its zero value.
	if scanSectionEmpty(merged.Scan) && !scanSectionEmpty(prior.Scan) {
		merged.Scan = prior.Scan
	}

	// Vulnerabilities: preserve the prior VulnSection when the new
	// report has not been scanned (no ScannedAt) and carries no CVE
	// data. A non-nil ScannedAt — even with empty CVEs — means the new
	// scan ran and is authoritative.
	if vulnSectionEmpty(merged.Vulnerabilities) && !vulnSectionEmpty(prior.Vulnerabilities) {
		merged.Vulnerabilities = prior.Vulnerabilities
	}

	// Maintenance: per-field preservation rather than whole-section,
	// because Tier-1 refreshers legitimately overwrite some fields
	// (LatestReleaseAt, VersionCount, etc.) while leaving the timeline +
	// repo-activity bits empty.
	if len(merged.Maintenance.VersionTimeline) == 0 && len(prior.Maintenance.VersionTimeline) > 0 {
		merged.Maintenance.VersionTimeline = prior.Maintenance.VersionTimeline
	}
	if merged.Maintenance.FirstPublishedAt == nil && prior.Maintenance.FirstPublishedAt != nil {
		merged.Maintenance.FirstPublishedAt = prior.Maintenance.FirstPublishedAt
	}
	if merged.Maintenance.Stars == 0 && prior.Maintenance.Stars != 0 {
		merged.Maintenance.Stars = prior.Maintenance.Stars
	}
	if merged.Maintenance.Forks == 0 && prior.Maintenance.Forks != 0 {
		merged.Maintenance.Forks = prior.Maintenance.Forks
	}
	if merged.Maintenance.OpenIssues == 0 && prior.Maintenance.OpenIssues != 0 {
		merged.Maintenance.OpenIssues = prior.Maintenance.OpenIssues
	}
	if merged.Maintenance.Subscribers == 0 && prior.Maintenance.Subscribers != 0 {
		merged.Maintenance.Subscribers = prior.Maintenance.Subscribers
	}

	// Artifact: per-field preservation. Tier-1 (registrymetadata) is
	// authoritative for filename/size/declared digests so those always
	// flow through from `next`. The Tier-2 checksum result
	// (Digests.Actual / Digests.Verified) and the Tier-3 signature
	// verification (SignatureVerified / SignatureKind / SignatureKeyID)
	// are preserved when the incoming report leaves them empty — a
	// Tier-1-only tick must not wipe verified-signature data.
	if merged.Artifact.Digests.Actual == "" && prior.Artifact.Digests.Actual != "" {
		merged.Artifact.Digests.Actual = prior.Artifact.Digests.Actual
	}
	if !merged.Artifact.Digests.Verified && prior.Artifact.Digests.Verified {
		merged.Artifact.Digests.Verified = prior.Artifact.Digests.Verified
	}
	if merged.Artifact.SignatureVerified == nil && prior.Artifact.SignatureVerified != nil {
		merged.Artifact.SignatureVerified = prior.Artifact.SignatureVerified
	}
	if merged.Artifact.SignatureKind == "" && prior.Artifact.SignatureKind != "" {
		merged.Artifact.SignatureKind = prior.Artifact.SignatureKind
	}
	if merged.Artifact.SignatureKeyID == "" && prior.Artifact.SignatureKeyID != "" {
		merged.Artifact.SignatureKeyID = prior.Artifact.SignatureKeyID
	}

	// SupplyChain: per-field preservation. TrustScore + TrustScoreBreakdown
	// are deliberately NOT preserved — they are recomputed by the risk
	// engine on every scan and must reflect the latest evaluation. The
	// Tier-3 enricher fields (repo-link probe, metadiff, RTT lookups)
	// preserve the prior observation when the incoming field is empty.
	// PublisherChanged / VersionAnomaly / SuspiciousRepoStars /
	// NonExistentAuthor are sticky-true: once observed, a Tier-1-only
	// refresher whose section is empty cannot flip them off (see the
	// function comment for the rationale).
	if merged.SupplyChain.MalwareStatus == "" && prior.SupplyChain.MalwareStatus != "" {
		merged.SupplyChain.MalwareStatus = prior.SupplyChain.MalwareStatus
	}
	if merged.SupplyChain.TyposquatStatus == "" && prior.SupplyChain.TyposquatStatus != "" {
		merged.SupplyChain.TyposquatStatus = prior.SupplyChain.TyposquatStatus
	}
	if merged.SupplyChain.RepoLinkStatus == "" && prior.SupplyChain.RepoLinkStatus != "" {
		merged.SupplyChain.RepoLinkStatus = prior.SupplyChain.RepoLinkStatus
	}
	if merged.SupplyChain.RepoLastCommitAt == nil && prior.SupplyChain.RepoLastCommitAt != nil {
		merged.SupplyChain.RepoLastCommitAt = prior.SupplyChain.RepoLastCommitAt
	}
	// PublisherChanged: *bool, sticky-true ON SILENCE ONLY.
	//
	// Preserve when incoming is nil — a Tier-1-only refresh that never ran
	// the metadiff provider has observed nothing, and silence is not a
	// withdrawal. An explicit incoming *false IS an observation and DOES
	// clear the flag: provider_metadiff.go computes
	// `changed := len(added) > 0 || len(removed) > 0` and always assigns
	// it, so a later scan that finds the publisher set unchanged returns
	// the package to clean.
	//
	// This comment previously also claimed "OR when prior was *true and
	// incoming is *false ... isn't withdrawn". That was never implemented,
	// and implementing it would be a BUG, not a fix: a package would stay
	// flagged forever after a single legitimate maintainer handover, with
	// no path back. P8-35 was filed against exactly that behaviour on the
	// strength of this sentence; the code was correct and the comment was
	// not. TestPublisherChangedClearsOnExplicitFalse pins the real
	// behaviour so the "fix" cannot be applied.
	if merged.SupplyChain.PublisherChanged == nil && prior.SupplyChain.PublisherChanged != nil {
		merged.SupplyChain.PublisherChanged = prior.SupplyChain.PublisherChanged
	}
	if merged.SupplyChain.VersionAnomaly == nil && prior.SupplyChain.VersionAnomaly != nil {
		merged.SupplyChain.VersionAnomaly = prior.SupplyChain.VersionAnomaly
	}
	// Note: SuspiciousRepoStars, MaintainerAccountAgeDays,
	// FirstTimeCollaborator, and NonExistentAuthor live on
	// ArtifactScanSection (not SupplyChainSection — the audit groups them
	// by *signal source* rather than struct location). They are
	// preserved by the whole-Scan-section guard above when the incoming
	// Scan is empty, and naturally overwritten when a fresh Tier-2 scan
	// runs and writes the section.

	// People: per-field preservation. Tier-1 populates these from
	// registry metadata; a Tier-1-only refresher that fails mid-way may
	// emit an empty section. The Tier-3 FirstTimeCollaborator path reads
	// prior.People to compute the publisher-set diff, so dropping
	// Maintainers / PublisherIDs here would silently disable that signal.
	if len(merged.People.Authors) == 0 && len(prior.People.Authors) > 0 {
		merged.People.Authors = prior.People.Authors
	}
	if len(merged.People.Maintainers) == 0 && len(prior.People.Maintainers) > 0 {
		merged.People.Maintainers = prior.People.Maintainers
	}
	if len(merged.People.PublisherIDs) == 0 && len(prior.People.PublisherIDs) > 0 {
		merged.People.PublisherIDs = prior.People.PublisherIDs
	}
	if merged.People.TrustedPublisher == nil && prior.People.TrustedPublisher != nil {
		merged.People.TrustedPublisher = prior.People.TrustedPublisher
	}

	// Provenance: per-field preservation. Tier-1 sigstore/x509/sumdb
	// providers populate Kind / SourceRepo / BundleURL / Verified at the
	// initial fetch; the Tier-3 signature-verify enricher refines
	// SignerID / BuilderID / SLSALevel. A Tier-1-only refresher whose
	// provider didn't run should not blank these out. Verified is a
	// plain bool — sticky-true semantics: preserve when prior was true
	// and incoming is false (no fresh observation).
	if merged.Provenance.Kind == "" && prior.Provenance.Kind != "" {
		merged.Provenance.Kind = prior.Provenance.Kind
	}
	if !merged.Provenance.Verified && prior.Provenance.Verified {
		merged.Provenance.Verified = prior.Provenance.Verified
	}
	if merged.Provenance.SourceRepo == "" && prior.Provenance.SourceRepo != "" {
		merged.Provenance.SourceRepo = prior.Provenance.SourceRepo
	}
	if merged.Provenance.BundleURL == "" && prior.Provenance.BundleURL != "" {
		merged.Provenance.BundleURL = prior.Provenance.BundleURL
	}
	if merged.Provenance.SLSALevel == 0 && prior.Provenance.SLSALevel != 0 {
		merged.Provenance.SLSALevel = prior.Provenance.SLSALevel
	}

	return json.Marshal(&merged)
}

// scanSectionEmpty reports whether an ArtifactScanSection carries no
// Tier-2 signal data. Used by the Upsert merge to decide whether the
// prior row's Scan subtree should be preserved.
//
// "Empty" means: no scan was performed AND no signal-bearing field is
// set. We deliberately do not include the diagnostic fields
// (ManifestFilesSeen, ExtraFindings) — those are housekeeping only.
func scanSectionEmpty(s ArtifactScanSection) bool {
	if s.Performed {
		return false
	}
	if s.InstallScriptKind != "" || s.HasInstallScript || s.InstallScriptFetches {
		return false
	}
	if s.HiddenUnicodeHits > 0 || len(s.HiddenUnicodeKinds) > 0 {
		return false
	}
	if s.ShrinkwrapPresent || s.ShrinkwrapSuppressed || s.ManifestConfusion {
		return false
	}
	if s.UsesEval || s.NetworkAccess || s.ShellAccess || s.FilesystemAccess ||
		s.EnvVarAccess || s.NativeBinaryPresent || s.HighEntropyStrings ||
		s.URLStrings || s.MinifiedCode {
		return false
	}
	if s.TrivialPackage || s.TooManyFiles || s.NonExistentAuthor ||
		s.SuspiciousRepoStars || s.MaintainerAccountAgeDays > 0 {
		return false
	}
	if s.DangerousPickleOpcode || s.SuspiciousPickleOpcode ||
		s.UnsafeSerializationFormat || s.PrefersSafetensorsAvailable ||
		s.ModelCardInjection || s.AgentToolDeclared ||
		s.AgentToolDangerousCapability || s.MCPServerUnverified ||
		s.PromptTemplateInjection {
		return false
	}
	if len(s.MinifiedFiles) > 0 || s.CapabilityReport != nil {
		return false
	}
	if s.ScannedArtifactSHA != "" || s.ScannedAt != nil {
		return false
	}
	return true
}

// vulnSectionEmpty reports whether a VulnSection carries no scan data.
// Empty means the CVE provider did not produce a row — no ScannedAt, no
// CVEs, no severity score, no KEV entries. An empty-but-scanned vuln
// section (ScannedAt != nil, no CVEs) is *not* empty — it means "we
// scanned and found nothing", which is authoritative new data and must
// not be overwritten by a stale prior section.
func vulnSectionEmpty(v VulnSection) bool {
	if v.ScannedAt != nil {
		return false
	}
	if v.IsVulnerable || v.CVSSScore > 0 || v.EPSSScore > 0 || v.KnownExploited {
		return false
	}
	if len(v.CVEs) > 0 || len(v.CVEDetails) > 0 || len(v.KEVEntries) > 0 {
		return false
	}
	// A section carrying only vetoes is NOT empty. "These CVEs were
	// evaluated and do not apply" is a finding in its own right, and
	// treating it as empty would restore the prior payload — the exact
	// stickiness the veto exists to break.
	if len(v.ClearedCVEs) > 0 {
		return false
	}
	if v.ScannerDBDigest != "" {
		return false
	}
	return true
}

// Search returns rows for the admin UI list view. Keyset pagination uses
// the opaque Cursor token encoded as base64(collected_at|ecosystem|package|version).
// q.OrgID is ignored — see the package-level comment.
//
// Matcher staleness is DISCLOSED, not filtered. Every row is returned
// regardless of the epoch that produced it, and each one carries
// SearchRow.MatcherStale so the caller can mark it. An epoch predicate in the
// WHERE clause would be the wrong trade three times over: the whole inventory
// would disappear for as long as a recompute takes, the facet totals would
// stop reconciling with the paged table, and the keyset cursor would skip over
// rows that reappear mid-scroll as the refresher catches up. Filtering on
// TrustScore and sorting on it still use the persisted values — a stale row
// keeps its place in the ordering and its place in the counts, and says so.
func (s *Store) Search(ctx context.Context, q SearchQuery) (*SearchResults, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return &SearchResults{}, nil
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	args := []any{}
	conds := []string{"TRUE"}
	idx := 1

	if q.Ecosystem != "" {
		conds = append(conds, fmt.Sprintf("ecosystem = $%d", idx))
		args = append(args, q.Ecosystem)
		idx++
	}
	if q.OnlyMalicious {
		conds = append(conds, "is_malicious = TRUE")
	}
	if q.OnlyTyposquat {
		conds = append(conds, "is_typosquat = TRUE")
	}
	if q.OnlyHasCVE {
		conds = append(conds, "max_cvss IS NOT NULL AND max_cvss > 0")
	}
	if q.MinTrustScore != nil {
		conds = append(conds, fmt.Sprintf("trust_score >= $%d", idx))
		args = append(args, *q.MinTrustScore)
		idx++
	}
	if q.MaxTrustScore != nil {
		conds = append(conds, fmt.Sprintf("trust_score <= $%d", idx))
		args = append(args, *q.MaxTrustScore)
		idx++
	}
	if q.SinceScannedAt != nil {
		conds = append(conds, fmt.Sprintf("collected_at >= $%d", idx))
		args = append(args, *q.SinceScannedAt)
		idx++
	}
	if q.OnlyHasWarnings {
		conds = append(conds, "warning_count > 0")
	}
	if q.OnlyArtifactScan {
		conds = append(conds, "has_artifact_scan = TRUE")
	}
	if qStr := strings.TrimSpace(q.Q); qStr != "" {
		// Shodan-style free text: match on package name, version, or
		// ecosystem. Operators paste coordinates like "lodash@4.17.21"
		// or bare names and we find the rows that fit. Split on "@" so
		// a name@version query narrows both halves at once; otherwise
		// broadcast the pattern across all three columns. Escape the
		// three LIKE metacharacters so "foo_bar" or "50%off" stays
		// literal instead of wildcard-matching the world.
		pattern := "%" + escapeLike(qStr) + "%"
		if at := strings.Index(qStr, "@"); at > 0 && at < len(qStr)-1 {
			name := strings.TrimSpace(qStr[:at])
			ver := strings.TrimSpace(qStr[at+1:])
			conds = append(conds, fmt.Sprintf("package_name ILIKE $%d ESCAPE '\\' AND version ILIKE $%d ESCAPE '\\'", idx, idx+1))
			args = append(args, "%"+escapeLike(name)+"%", "%"+escapeLike(ver)+"%")
			idx += 2
		} else {
			conds = append(conds, fmt.Sprintf("(package_name ILIKE $%d ESCAPE '\\' OR version ILIKE $%d ESCAPE '\\' OR ecosystem ILIKE $%d ESCAPE '\\')", idx, idx+1, idx+2))
			args = append(args, pattern, pattern, pattern)
			idx += 3
		}
	}
	// Cursor-based pagination is only well-defined for the default
	// sort (collected_at DESC). For other sort modes we rely on a
	// single-page limit — fine for admin UI use (50 rows per page
	// default) where an operator is scanning, not iterating.
	cursorSortMode := strings.ToLower(strings.TrimSpace(q.Sort))
	cursorApplied := false
	if q.Cursor != "" && (cursorSortMode == "" || cursorSortMode == "recent") {
		cur, err := decodeCursor(q.Cursor)
		if err == nil {
			conds = append(conds, fmt.Sprintf(
				"(collected_at, ecosystem, package_name, version) < ($%d, $%d, $%d, $%d)",
				idx, idx+1, idx+2, idx+3,
			))
			args = append(args, cur.CollectedAt, cur.Ecosystem, cur.Package, cur.Version)
			idx += 4
			cursorApplied = true
		}
	}
	// Sort modes that don't support cursoring fall through to a single
	// page — callers get one window of results with an empty NextCursor
	// instead of a token that would duplicate rows on the next request.
	cursorable := cursorApplied || (q.Cursor == "" && (cursorSortMode == "" || cursorSortMode == "recent"))
	whereClause := strings.Join(conds, " AND ")
	args = append(args, limit+1)

	// ORDER BY drives the keyset-pagination cursor shape; all sort modes
	// end with the same (ecosystem, package, version) tiebreaker so
	// decodeCursor stays stable.
	orderBy := sortToOrderBy(q.Sort)

	// matcherEpochExpr reads the epoch that produced this row. It is NOT a
	// WHERE predicate, deliberately — see SearchRow.MatcherStale for why the
	// list discloses staleness instead of filtering on it. The epoch lives
	// inside the report JSONB (Report.Observation.MatcherEpoch, tag
	// `matcherEpoch,omitempty`) rather than in a denormalised column, so the
	// `omitempty` case — every row written before the field existed — yields
	// SQL NULL and must land on 0, which is below every real epoch and
	// therefore always stale. NULLIF guards the empty string so a
	// hand-edited row can never abort the whole query on a cast error.
	const matcherEpochExpr = `COALESCE(NULLIF(report->'observation'->>'matcherEpoch', '')::int, 0)`

	query := fmt.Sprintf(`
		SELECT ecosystem, package_name, version, collected_at, fresh_until,
		       COALESCE(trust_score,0), COALESCE(max_cvss,0),
		       is_malicious, is_typosquat, has_artifact_scan, warning_count,
		       COALESCE(typosquat_confidence,''),
		       risk_evaluation->>'verdict',
		       (risk_evaluation->'rolledUp'->>'overall')::int,
		       %s
		FROM intelligence_reports
		WHERE %s
		ORDER BY %s
		LIMIT $%d
	`, matcherEpochExpr, whereClause, orderBy, idx)

	rows, err := s.sql.DB().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("intelligence: search: %w", err)
	}
	defer rows.Close()

	results := &SearchResults{Rows: make([]SearchRow, 0, limit)}
	for rows.Next() {
		var row SearchRow
		var verdict sql.NullString
		var overallScore sql.NullInt64
		var rowEpoch int
		if err := rows.Scan(
			&row.Ecosystem, &row.Package, &row.Version,
			&row.CollectedAt, &row.FreshUntil,
			&row.TrustScore, &row.MaxCVSS,
			&row.IsMalicious, &row.IsTyposquat, &row.HasArtifactScan, &row.WarningCount,
			&row.TyposquatConfidence,
			&verdict, &overallScore, &rowEpoch,
		); err != nil {
			return nil, fmt.Errorf("intelligence: scan search row: %w", err)
		}
		// Same comparison as Report.MatcherStale(), against the persisted
		// epoch rather than a decoded Report — Search never materialises the
		// Report, and reading the JSONB blob per row just to call the method
		// would undo the point of the denormalised list query.
		row.MatcherStale = rowEpoch < CurrentMatcherEpoch
		if verdict.Valid {
			row.Verdict = verdict.String
		}
		if overallScore.Valid {
			v := int(overallScore.Int64)
			row.OverallScore = &v
		}
		results.Rows = append(results.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("intelligence: search rows: %w", err)
	}

	// Keyset pagination: if we fetched limit+1 rows, the last row is the
	// cursor for the next page. Only emit NextCursor when the sort mode
	// actually honors the cursor — otherwise the next request would
	// re-return rows from the top of the window.
	if len(results.Rows) > limit {
		last := results.Rows[limit-1]
		results.Rows = results.Rows[:limit]
		if cursorable {
			results.NextCursor = encodeCursor(searchCursor{
				CollectedAt: last.CollectedAt,
				Ecosystem:   last.Ecosystem,
				Package:     last.Package,
				Version:     last.Version,
			})
		}
	}
	return results, nil
}

// GetLatestVersionProbe returns the cached latest-version probe for the
// package, or (nil, ErrNotFound) if none exists. orgID is ignored.
func (s *Store) GetLatestVersionProbe(ctx context.Context, orgID, ecosystem, pkg string) (*LatestVersionProbe, error) {
	_ = orgID
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return nil, ErrNotFound
	}
	row := s.sql.DB().QueryRowContext(ctx, `
		SELECT latest_version, probed_at, fresh_until, error
		FROM intelligence_latest_probes
		WHERE ecosystem=$1 AND package_name=$2
	`, ecosystem, pkg)
	var (
		latest   sql.NullString
		probedAt time.Time
		freshTil time.Time
		errStr   sql.NullString
	)
	if err := row.Scan(&latest, &probedAt, &freshTil, &errStr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("intelligence: load latest probe: %w", err)
	}
	out := &LatestVersionProbe{
		Ecosystem:     ecosystem,
		Package:       pkg,
		LatestVersion: latest.String,
		ProbedAt:      probedAt,
		FreshUntil:    freshTil,
		Error:         errStr.String,
	}
	return out, nil
}

// UpsertLatestVersionProbe writes a probe result. orgID is ignored.
func (s *Store) UpsertLatestVersionProbe(ctx context.Context, orgID string, p LatestVersionProbe) error {
	_ = orgID
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return nil
	}
	var latest sql.NullString
	if p.LatestVersion != "" {
		latest = sql.NullString{String: p.LatestVersion, Valid: true}
	}
	var errStr sql.NullString
	if p.Error != "" {
		errStr = sql.NullString{String: p.Error, Valid: true}
	}
	_, err := s.sql.DB().ExecContext(ctx, `
		INSERT INTO intelligence_latest_probes
		  (ecosystem, package_name, latest_version, probed_at, fresh_until, error)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (ecosystem, package_name) DO UPDATE SET
		  latest_version = EXCLUDED.latest_version,
		  probed_at = EXCLUDED.probed_at,
		  fresh_until = EXCLUDED.fresh_until,
		  error = EXCLUDED.error
	`, p.Ecosystem, p.Package, latest, p.ProbedAt, p.FreshUntil, errStr)
	if err != nil {
		return fmt.Errorf("intelligence: upsert latest probe: %w", err)
	}
	return nil
}

// LatestVersionProbe is the in-memory shape for a daily probe.
type LatestVersionProbe struct {
	Ecosystem     string
	Package       string
	LatestVersion string
	ProbedAt      time.Time
	FreshUntil    time.Time
	Error         string
}

// Facets returns the aggregate counts used by the Shodan-style sidebar.
// One DB round-trip per facet keeps the endpoint fast; the tsvector
// index makes the ecosystem breakdown cheap. Filters from the caller's
// SearchQuery are NOT applied — the facet counts are always over the
// full cache so the sidebar shows "what's available to filter on" rather
// than "what's left after my current filter". orgID is ignored.
//
// Matcher-stale rows are counted in every bucket exactly as they were, and
// additionally counted once in StalePending. See FacetCounts.StalePending for
// why disclosure beats subtraction here.
func (s *Store) Facets(ctx context.Context, orgID string) (*FacetCounts, error) {
	_ = orgID
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return &FacetCounts{}, nil
	}
	out := &FacetCounts{}

	// The stale count is an ADDITIONAL cell, not a filter on the others.
	// Every count below still spans the whole table — Total, the trust
	// buckets and the signal counts all keep including matcher-stale rows,
	// because the sidebar's job is to reconcile with the list beside it and
	// that list still shows them (marked). StalePending answers "how much of
	// this is awaiting recompute" without moving any of the other numbers.
	// See FacetCounts.StalePending.
	row := s.sql.DB().QueryRowContext(ctx, `
		SELECT
		  COUNT(*),
		  COUNT(*) FILTER (WHERE is_malicious),
		  COUNT(*) FILTER (WHERE is_typosquat),
		  COUNT(*) FILTER (WHERE max_cvss IS NOT NULL AND max_cvss > 0),
		  COUNT(*) FILTER (WHERE warning_count > 0),
		  COUNT(*) FILTER (WHERE has_artifact_scan),
		  COUNT(*) FILTER (WHERE collected_at > NOW() - INTERVAL '24 hours'),
		  COUNT(*) FILTER (WHERE trust_score IS NOT NULL AND trust_score < 40),
		  COUNT(*) FILTER (WHERE trust_score IS NOT NULL AND trust_score >= 40 AND trust_score < 70),
		  COUNT(*) FILTER (WHERE trust_score IS NOT NULL AND trust_score >= 70),
		  COUNT(*) FILTER (
		    WHERE COALESCE(NULLIF(report->'observation'->>'matcherEpoch', '')::int, 0) < $1
		  )
		FROM intelligence_reports
	`, CurrentMatcherEpoch)
	var lowTrust, medTrust, highTrust int
	if err := row.Scan(
		&out.Total, &out.Malicious, &out.Typosquat, &out.HasCVE,
		&out.HasWarnings, &out.ArtifactScan, &out.Last24h,
		&lowTrust, &medTrust, &highTrust, &out.StalePending,
	); err != nil {
		return nil, fmt.Errorf("intelligence: facets aggregate: %w", err)
	}
	out.TrustBuckets = []FacetBucket{
		{Key: "low", Label: "low (<40)", Count: lowTrust},
		{Key: "medium", Label: "medium (40–70)", Count: medTrust},
		{Key: "high", Label: "high (≥70)", Count: highTrust},
	}

	// Ecosystem breakdown — separate query because GROUP BY
	// doesn't compose cleanly with the aggregate row above.
	rows, err := s.sql.DB().QueryContext(ctx, `
		SELECT ecosystem, COUNT(*) AS c
		FROM intelligence_reports
		GROUP BY ecosystem
		ORDER BY c DESC, ecosystem ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("intelligence: facets ecosystem: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var b FacetBucket
		if err := rows.Scan(&b.Key, &b.Count); err != nil {
			return nil, fmt.Errorf("intelligence: facets ecosystem scan: %w", err)
		}
		b.Label = b.Key
		out.Ecosystems = append(out.Ecosystems, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("intelligence: facets ecosystem rows: %w", err)
	}
	return out, nil
}

// sortToOrderBy translates a SearchQuery.Sort value to a SQL ORDER BY
// clause. Every mode ends with the same (ecosystem, package_name,
// version) tiebreaker so the keyset-pagination cursor shape remains
// stable across modes.
func sortToOrderBy(sort string) string {
	base := " ecosystem ASC, package_name ASC, version ASC"
	switch strings.ToLower(strings.TrimSpace(sort)) {
	case "trust_asc":
		return "COALESCE(trust_score, 0) ASC, collected_at DESC," + base
	case "trust_desc":
		return "COALESCE(trust_score, 0) DESC, collected_at DESC," + base
	case "cvss_desc":
		return "COALESCE(max_cvss, 0) DESC, collected_at DESC," + base
	case "name":
		return "package_name ASC, version DESC," + base
	case "", "recent":
		fallthrough
	default:
		return "collected_at DESC," + base
	}
}

// searchCursor is the opaque pagination token used by Search.
type searchCursor struct {
	CollectedAt time.Time `json:"at"`
	Ecosystem   string    `json:"eco"`
	Package     string    `json:"pkg"`
	Version     string    `json:"ver"`
}

// escapeLike escapes the three LIKE metacharacters (\, %, _) so an
// operator's search input can never widen the ILIKE match unexpectedly.
// Backslashes go first so a later replacement doesn't double-escape.
// Callers must pair the returned pattern with `ESCAPE '\\'` in SQL.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

func encodeCursor(c searchCursor) string {
	payload, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeCursor(s string) (searchCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return searchCursor{}, err
	}
	var c searchCursor
	if err := json.Unmarshal(raw, &c); err != nil {
		return searchCursor{}, err
	}
	return c, nil
}
