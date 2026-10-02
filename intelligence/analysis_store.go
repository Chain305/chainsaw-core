package intelligence

// analysis_store.go — the read/write seam for artifact_analyses (A-3).
//
// The table is keyed (artifact_sha256, analyzer, analyzer_version) and carries
// one provider's PartialReport per row. It holds NO org_id, by construction:
// an analysis result is a fact about bytes, and bytes have no tenant. That is
// the same reasoning that keeps org_id off intelligence_reports (see
// personalize.go) and it is why the L-02 federation decision survives this
// change untouched.
//
// WHAT IS STORED IS THE PROVIDER'S OWN OUTPUT, NOT A MERGED SECTION. A reused
// row is replayed through mergePartial — the same function the fan-out calls —
// so the cache introduces no second merge semantics and cannot diverge from
// the live path. Storing a merged ArtifactScanSection instead would also be
// wrong: provider_checksum returns PartialReport{Artifact: ...} while the
// codesmell providers return PartialReport{Scan: ...}, so a Scan-only cache
// would silently drop the checksum facts.
//
// THIS IS A CACHE, NOT A SOURCE OF TRUTH FOR ANY VERDICT. Nothing reads it
// except the scanner, before the evaluation, and the facts reach the report
// through exactly the path they take today. intelligence_reports remains the
// canonical record.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// maxStoredAnalysisBytes caps one row's encoded PartialReport.
//
// A provider partial is flags plus a few short strings, so the realistic size
// is order 1 KB. The cap is a backstop against a provider that one day returns
// something unbounded (a file list, an opcode dump): the write is skipped and
// the provider simply keeps running on every scan, which is today's behaviour.
// Silently storing a multi-megabyte row per artifact is the failure this
// avoids.
const maxStoredAnalysisBytes = 256 << 10

// AcceptedAnalysis is what a lookup will accept for one analyzer: the version
// AND the configuration fingerprint this binary would produce right now.
//
// Both are compared. A row matching on version but not config was computed
// under a different operator threshold or lane flag and is not reusable.
type AcceptedAnalysis struct {
	Version int
	Config  string
}

// ArtifactAnalysisKey identifies one analyzer generation's output over one
// artifact.
type ArtifactAnalysisKey struct {
	SHA256    string
	Ecosystem string
	Analyzer  string
	Version   int
	// Config is the analyzer's operator-configuration fingerprint, "" when it
	// reads none. Part of the key, never ordered — see ConfiguredAnalyzer.
	Config string
}

// LoadArtifactAnalyses returns the stored partials for sha256 that match the
// requested analyzer versions exactly.
//
// want maps analyzer name to the version the caller will accept. An analyzer
// whose stored row is at any OTHER version is omitted from the result, which
// is what makes a version bump invalidate one analyzer and nothing else.
//
// A nil store, an empty digest or an empty want is a miss, not an error: the
// caller runs every provider, which is the pre-cache behaviour.
func (s *Store) LoadArtifactAnalyses(ctx context.Context, sha256, ecosystem string, want map[string]AcceptedAnalysis) (map[string]PartialReport, error) {
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
	if s == nil || s.sql == nil || s.sql.DB() == nil || sha256 == "" || ecosystem == "" || len(want) == 0 {
		return nil, nil
	}

	// One round trip for every analyzer, filtered in Go against want.
	//
	// Filtering here rather than with a composite tuple-IN keeps the SQL a
	// plain primary-key prefix scan and keeps the version comparison in the
	// same place the version manifest is built, so the two cannot drift. The
	// row count is bounded by the number of analyzer generations ever written
	// for one artifact — tens, not thousands.
	rows, err := s.sql.DB().QueryContext(ctx, `
		SELECT analyzer, analyzer_version, analyzer_config, partial
		  FROM artifact_analyses
		 WHERE artifact_sha256 = $1 AND ecosystem = $2`, sha256, ecosystem)
	if err != nil {
		return nil, fmt.Errorf("intelligence: load artifact analyses: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]PartialReport, len(want))
	for rows.Next() {
		var (
			analyzer string
			version  int
			config   string
			payload  []byte
		)
		if err := rows.Scan(&analyzer, &version, &config, &payload); err != nil {
			return nil, fmt.Errorf("intelligence: scan artifact analysis: %w", err)
		}
		accept, ok := want[analyzer]
		// EVERY key component is compared, not just the version. A row whose
		// config differs was computed under a different operator threshold or
		// lane flag, and serving it is the defect this column exists to close.
		if !ok || accept.Version != version || accept.Config != config {
			continue
		}
		var p PartialReport
		if err := json.Unmarshal(payload, &p); err != nil {
			// A row we cannot decode is a miss, never an error: the provider
			// runs and overwrites it. Failing the scan over an unreadable
			// cache entry would turn a cache defect into an outage.
			continue
		}
		out[analyzer] = p
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("intelligence: iterate artifact analyses: %w", err)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// SaveArtifactAnalysis records one analyzer's output over one artifact.
//
// Idempotent on the key and last-writer-wins on the payload: two concurrent
// scans of the same bytes at the same analyzer version produce the same facts,
// so which one lands does not matter.
func (s *Store) SaveArtifactAnalysis(ctx context.Context, key ArtifactAnalysisKey, p PartialReport) error {
	sha := strings.ToLower(strings.TrimSpace(key.SHA256))
	analyzer := strings.TrimSpace(key.Analyzer)
	eco := strings.ToLower(strings.TrimSpace(key.Ecosystem))
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return nil
	}
	if sha == "" || analyzer == "" || eco == "" || key.Version <= AnalyzerNotCacheable {
		return nil
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("intelligence: encode artifact analysis: %w", err)
	}
	if len(payload) > maxStoredAnalysisBytes {
		return nil
	}
	if _, err := s.sql.DB().ExecContext(ctx, `
		INSERT INTO artifact_analyses (
			artifact_sha256, ecosystem, analyzer, analyzer_version, analyzer_config,
			partial, analyzed_at
		) VALUES ($1,$2,$3,$4,$5,$6,NOW())
		ON CONFLICT (artifact_sha256, ecosystem, analyzer, analyzer_version, analyzer_config)
		DO UPDATE SET
			partial     = EXCLUDED.partial,
			analyzed_at = EXCLUDED.analyzed_at
	`, sha, eco, analyzer, key.Version, strings.TrimSpace(key.Config), payload); err != nil {
		return fmt.Errorf("intelligence: save artifact analysis: %w", err)
	}
	return nil
}

// CountStaleAnalyses sizes the selective-backfill population for one analyzer:
// how many coordinates hold an analysis from a SUPERSEDED version of it.
//
// This is the number that answers "how far along is the re-derive" after a
// version bump. Its failure mode is reporting zero while work remains — the
// shape of the epoch-15 drain being called complete with 3,843 rows left — so
// its guard seeds superseded rows and asserts the count is NON-zero, not that
// it eventually falls to zero.
func (s *Store) CountStaleAnalyses(ctx context.Context, analyzer string, currentVersion int) (int, error) {
	analyzer = strings.TrimSpace(analyzer)
	if s == nil || s.sql == nil || s.sql.DB() == nil || analyzer == "" {
		return 0, nil
	}
	var n int
	if err := s.sql.DB().QueryRowContext(ctx, `
		SELECT COUNT(*) FROM intelligence_reports
		 WHERE `+reportArtifactSHAExpr+` IS NOT NULL
		   AND EXISTS (
			SELECT 1 FROM artifact_analyses a
			 WHERE a.artifact_sha256  = `+reportArtifactSHAExpr+`
			   AND a.analyzer         = $1
			   AND a.analyzer_version < $2)`, analyzer, currentVersion).Scan(&n); err != nil {
		return 0, fmt.Errorf("intelligence: count stale analyses: %w", err)
	}
	return n, nil
}

// ErrUnknownAnalyzer is returned when a caller names an analyzer that no
// registered provider declares. A typo must not silently select zero rows and
// read as "nothing to do".
var ErrUnknownAnalyzer = errors.New("intelligence: unknown analyzer")

// StaleAnalyzerScope is the selective-backfill entry point: the scope that
// selects ONLY the coordinates whose artifact holds an analysis from a
// superseded version of analyzer.
//
// It returns a StaleReportScope, so it drives the EXISTING stale-report sweep
// (refresher_stale_reports.go) rather than a new worker. OlderThan is left at
// its zero value on purpose: `collected_at < '0001-01-01'` matches nothing, so
// the ordinary staleness half contributes no rows and the population is the
// analyzer half alone. That is what makes "selects only X's rows" a property of
// the scope and not of how carefully a caller composed it.
//
// Pass the analyzer's CURRENT version — the predicate is `< currentVersion`,
// so a row already at the current version is never reselected.
func StaleAnalyzerScope(analyzer string, currentVersion int) (StaleReportScope, error) {
	analyzer = strings.TrimSpace(analyzer)
	if analyzer == "" || currentVersion <= AnalyzerNotCacheable {
		return StaleReportScope{}, fmt.Errorf("%w: %q at version %d", ErrUnknownAnalyzer, analyzer, currentVersion)
	}
	return StaleReportScope{StaleAnalyzer: analyzer, StaleAnalyzerVersion: currentVersion}, nil
}

// analysisRowCount is a test/diagnostic helper: how many rows the table holds
// for one digest. Kept unexported — nothing in production reads a raw count.
func (s *Store) analysisRowCount(ctx context.Context, sha256 string) (int, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return 0, nil
	}
	var n int
	err := s.sql.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM artifact_analyses WHERE artifact_sha256 = $1`,
		strings.ToLower(strings.TrimSpace(sha256))).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return n, nil
}
