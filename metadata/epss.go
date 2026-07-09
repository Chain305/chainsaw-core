package metadata

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/tenancy"
)

// CVEEPSS captures EPSS data for a single CVE.
type CVEEPSS struct {
	CVE           string
	Score         float64
	Percentile    float64
	PublishedDate string
	FetchedAt     time.Time
	RawPayload    string
}

// UpsertCVEEPSS stores or updates EPSS scores.
func (s *Store) UpsertCVEEPSS(records []CVEEPSS) error {
	if s == nil || s.sql == nil {
		return ErrUnavailable
	}
	if len(records) == 0 {
		return nil
	}
	now := time.Now().UTC()
	for _, record := range records {
		cve := strings.TrimSpace(strings.ToUpper(record.CVE))
		if cve == "" {
			continue
		}
		fetchedAt := record.FetchedAt
		if fetchedAt.IsZero() {
			fetchedAt = now
		}
		if _, err := s.sql.DB().Exec(`INSERT INTO cve_epss(cve, score, percentile, published_date, fetched_at, raw_payload, updated_at)
			VALUES(?,?,?,?,?,?,?)
			ON CONFLICT(cve) DO UPDATE SET
				score=excluded.score,
				percentile=excluded.percentile,
				published_date=excluded.published_date,
				fetched_at=excluded.fetched_at,
				raw_payload=excluded.raw_payload,
				updated_at=excluded.updated_at`,
			cve,
			record.Score,
			record.Percentile,
			nullIfEmpty(record.PublishedDate),
			fetchedAt,
			nullIfEmpty(record.RawPayload),
			now,
		); err != nil {
			return err
		}
	}
	return nil
}

// ListObservedCVEsNeedingRefresh returns observed CVEs missing EPSS or older than staleBefore.
func (s *Store) ListObservedCVEsNeedingRefresh(staleBefore time.Time) ([]string, error) {
	if s == nil || s.sql == nil {
		return nil, ErrUnavailable
	}
	orgID := strings.TrimSpace(s.orgID)
	if orgID == "" {
		orgID = tenancy.DefaultOrgID
	}

	rows, err := s.sql.DB().Query(`SELECT cves FROM vulnerability_metadata WHERE org_id=? AND COALESCE(cves, '') <> ''`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	observed := map[string]struct{}{}
	for rows.Next() {
		var cvesJSON string
		if err := rows.Scan(&cvesJSON); err != nil {
			return nil, err
		}
		var cves []string
		if err := json.Unmarshal([]byte(cvesJSON), &cves); err != nil {
			continue
		}
		for _, cve := range cves {
			cve = strings.TrimSpace(strings.ToUpper(cve))
			if cve != "" {
				observed[cve] = struct{}{}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(observed) == 0 {
		return nil, nil
	}

	index := map[string]time.Time{}
	scoreRows, err := s.sql.DB().Query(`SELECT cve, fetched_at FROM cve_epss`)
	if err != nil {
		return nil, err
	}
	defer scoreRows.Close()
	for scoreRows.Next() {
		var (
			cve       string
			fetchedAt sql.NullTime
		)
		if err := scoreRows.Scan(&cve, &fetchedAt); err != nil {
			return nil, err
		}
		if fetchedAt.Valid {
			index[strings.TrimSpace(strings.ToUpper(cve))] = fetchedAt.Time.UTC()
		}
	}
	if err := scoreRows.Err(); err != nil {
		return nil, err
	}

	results := make([]string, 0, len(observed))
	for cve := range observed {
		fetchedAt, ok := index[cve]
		if !ok || fetchedAt.Before(staleBefore) {
			results = append(results, cve)
		}
	}
	return results, nil
}

// LoadCVEEPSSMap returns a score lookup for the requested CVEs.
func (s *Store) LoadCVEEPSSMap(cves []string) (map[string]CVEEPSS, error) {
	if s == nil || s.sql == nil {
		return nil, ErrUnavailable
	}
	results := make(map[string]CVEEPSS, len(cves))
	rows, err := s.sql.DB().Query(`SELECT cve, score, percentile, published_date, fetched_at, raw_payload FROM cve_epss`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	allowed := map[string]struct{}{}
	filterAll := len(cves) == 0
	for _, cve := range cves {
		cve = strings.TrimSpace(strings.ToUpper(cve))
		if cve != "" {
			allowed[cve] = struct{}{}
		}
	}
	for rows.Next() {
		var (
			record        CVEEPSS
			publishedDate sql.NullString
			fetchedAt     sql.NullTime
			rawPayload    sql.NullString
		)
		if err := rows.Scan(&record.CVE, &record.Score, &record.Percentile, &publishedDate, &fetchedAt, &rawPayload); err != nil {
			return nil, err
		}
		record.CVE = strings.TrimSpace(strings.ToUpper(record.CVE))
		if !filterAll {
			if _, ok := allowed[record.CVE]; !ok {
				continue
			}
		}
		if record.CVE == "" {
			continue
		}
		record.PublishedDate = publishedDate.String
		if fetchedAt.Valid {
			record.FetchedAt = fetchedAt.Time.UTC()
		}
		record.RawPayload = rawPayload.String
		results[record.CVE] = record
	}
	return results, rows.Err()
}

// RefreshPackageEPSSScores recomputes package-level EPSS as the max score across each package's CVEs.
func (s *Store) RefreshPackageEPSSScores() error {
	if s == nil || s.sql == nil {
		return ErrUnavailable
	}
	orgID := strings.TrimSpace(s.orgID)
	if orgID == "" {
		orgID = tenancy.DefaultOrgID
	}

	rows, err := s.sql.DB().Query(`SELECT repository, package, version, cves FROM vulnerability_metadata
		WHERE org_id=? AND COALESCE(cves, '') <> ''`, orgID)
	if err != nil {
		return err
	}
	defer rows.Close()

	scoreMap, err := s.LoadCVEEPSSMap(nil)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for rows.Next() {
		var (
			repository  string
			packageName string
			version     string
			cvesJSON    string
		)
		if err := rows.Scan(&repository, &packageName, &version, &cvesJSON); err != nil {
			return err
		}
		var cves []string
		if err := json.Unmarshal([]byte(cvesJSON), &cves); err != nil {
			continue
		}
		maxScore := 0.0
		for _, cve := range cves {
			cve = strings.TrimSpace(strings.ToUpper(cve))
			if record, ok := scoreMap[cve]; ok && record.Score > maxScore {
				maxScore = record.Score
			}
		}
		if _, err := s.sql.DB().Exec(`UPDATE vulnerability_metadata
			SET epss_score=?, updated_at=?
			WHERE org_id=? AND repository=? AND package=? AND version=?`,
			floatToNull(maxScore), now, orgID, repository, packageName, version); err != nil {
			return err
		}
	}
	return rows.Err()
}
