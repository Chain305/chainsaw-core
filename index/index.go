package index

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
	"github.com/chain305/chainsaw-core/tenancy"
)

// PackageCoordinate captures package + version pairs.
type PackageCoordinate struct {
	Package string `json:"package"`
	Format  string `json:"format"`
	Version string `json:"version"`
}

// PackageSummary is returned by API responses.
type PackageSummary struct {
	Name     string   `json:"name"`
	Format   string   `json:"format"`
	Versions []string `json:"versions"`
}

// VersionInfo surfaces metadata stored for a package version.
type VersionInfo struct {
	LogicalPaths []string        `json:"logical_paths,omitempty"`
	Quarantine   *QuarantineInfo `json:"quarantine,omitempty"`
}

// QuarantineInfo records when/why a version was quarantined.
type QuarantineInfo struct {
	Reason           string    `json:"reason"`
	At               time.Time `json:"at"`
	RemovedArtifacts int       `json:"removed_artifacts,omitempty"`
	// Source is the action-surface tag (W7) — values from
	// internal/server/action_source.go's allowlist. Empty on legacy
	// rows; defaults to "direct" for new rows when no header is set.
	Source string `json:"source,omitempty"`
}

// Index persists package metadata to the database.
type Index struct {
	store  *pgstore.Store
	logger *slog.Logger
	orgID  string
}

// New constructs an Index backed by the provided database store.
func New(store *pgstore.Store) (*Index, error) {
	if store == nil {
		return nil, errors.New("database store is required")
	}
	return &Index{
		store:  store,
		logger: slog.Default(),
	}, nil
}

// ForOrg scopes index operations to a specific org.
func (idx *Index) ForOrg(orgID string) *Index {
	if idx == nil {
		return nil
	}
	next := *idx
	next.orgID = tenancy.NormalizeOrgID(orgID)
	return &next
}

// Record stores a package coordinate for the provided repository.
func (idx *Index) Record(repo string, coord PackageCoordinate, logicalPath string) error {
	repo = strings.TrimSpace(repo)
	if repo == "" || coord.Package == "" || coord.Version == "" {
		return errors.New("missing package coordinate")
	}
	orgID := tenancy.NormalizeOrgID(idx.orgID)
	return idx.store.WithTx(context.Background(), func(tx *sql.Tx) error {
		var (
			currentPaths sql.NullString
			currentFmt   sql.NullString
		)
		err := tx.QueryRow(`SELECT logical_paths, format FROM index_entries WHERE org_id=? AND repository=? AND package=? AND version=?`,
			orgID, repo, coord.Package, coord.Version).Scan(&currentPaths, &currentFmt)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		paths := decodePaths(currentPaths.String)
		if logicalPath != "" && !containsPath(paths, logicalPath) {
			paths = append(paths, logicalPath)
		}
		payload := encodePaths(paths)
		format := coord.Format
		if format == "" && currentFmt.Valid {
			format = currentFmt.String
		}
		if errors.Is(err, sql.ErrNoRows) {
			_, err = tx.Exec(`INSERT INTO index_entries(org_id, repository, package, version, format, logical_paths)
				VALUES(?,?,?,?,?,?)`, orgID, repo, coord.Package, coord.Version, format, payload)
			return err
		}
		if payload == currentPaths.String {
			return nil
		}
		_, err = tx.Exec(`UPDATE index_entries SET logical_paths=?, format=COALESCE(NULLIF(?, ''), format) 
			WHERE org_id=? AND repository=? AND package=? AND version=?`, payload, format, orgID, repo, coord.Package, coord.Version)
		return err
	})
}

// ListPackages returns package summaries for a repository.
func (idx *Index) ListPackages(repo string) []PackageSummary {
	orgID := tenancy.NormalizeOrgID(idx.orgID)
	rows, err := idx.store.DB().Query(`SELECT package, format, version FROM index_entries WHERE org_id=? AND repository=? ORDER BY package, version`, orgID, repo)
	if err != nil {
		idx.logger.Error("list packages failed", "repository", repo, "error", err)
		return nil
	}
	defer rows.Close()
	type agg struct {
		format   string
		versions []string
	}
	pkgs := make(map[string]*agg)
	for rows.Next() {
		var pkgName, format, version string
		if err := rows.Scan(&pkgName, &format, &version); err != nil {
			idx.logger.Error("scan packages failed", "error", err)
			return nil
		}
		entry, ok := pkgs[pkgName]
		if !ok {
			entry = &agg{format: format}
			pkgs[pkgName] = entry
		}
		entry.versions = append(entry.versions, version)
	}
	if err := rows.Err(); err != nil {
		idx.logger.Error("iterate packages failed", "error", err)
		return nil
	}
	results := make([]PackageSummary, 0, len(pkgs))
	for name, entry := range pkgs {
		sort.Strings(entry.versions)
		results = append(results, PackageSummary{
			Name:     name,
			Format:   entry.format,
			Versions: entry.versions,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})
	return results
}

// ListPackageVersions returns the version list for a specific package.
func (idx *Index) ListPackageVersions(repo, packageName string) []string {
	orgID := tenancy.NormalizeOrgID(idx.orgID)
	rows, err := idx.store.DB().Query(`SELECT version FROM index_entries WHERE org_id=? AND repository=? AND package=? ORDER BY version`, orgID, repo, packageName)
	if err != nil {
		idx.logger.Error("list package versions failed", "repository", repo, "package", packageName, "error", err)
		return nil
	}
	defer rows.Close()
	var versions []string
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			idx.logger.Error("scan package version failed", "error", err)
			return nil
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		idx.logger.Error("iterate package versions failed", "error", err)
		return nil
	}
	return versions
}

// VersionPaths returns cached logical paths for a package version.
func (idx *Index) VersionPaths(repo, packageName, version string) []string {
	var raw sql.NullString
	orgID := tenancy.NormalizeOrgID(idx.orgID)
	err := idx.store.DB().QueryRow(`SELECT logical_paths FROM index_entries WHERE org_id=? AND repository=? AND package=? AND version=?`,
		orgID, repo, packageName, version).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) || raw.String == "" {
		return nil
	}
	if err != nil {
		idx.logger.Error("fetch version paths failed", "repository", repo, "package", packageName, "version", version, "error", err)
		return nil
	}
	return decodePaths(raw.String)
}

// VersionInfo returns stored metadata for a package version.
func (idx *Index) VersionInfo(repo, packageName, version string) (VersionInfo, bool) {
	var (
		rawPaths sql.NullString
		reason   sql.NullString
		at       sql.NullTime
		removed  sql.NullInt64
		source   sql.NullString
	)
	orgID := tenancy.NormalizeOrgID(idx.orgID)
	err := idx.store.DB().QueryRow(`SELECT logical_paths, quarantine_reason, quarantine_at, quarantine_removed_artifacts, quarantine_source
		FROM index_entries WHERE org_id=? AND repository=? AND package=? AND version=?`,
		orgID, repo, packageName, version).Scan(&rawPaths, &reason, &at, &removed, &source)
	if errors.Is(err, sql.ErrNoRows) {
		return VersionInfo{}, false
	}
	if err != nil {
		idx.logger.Error("fetch version info failed", "repository", repo, "package", packageName, "version", version, "error", err)
		return VersionInfo{}, false
	}
	info := VersionInfo{
		LogicalPaths: decodePaths(rawPaths.String),
	}
	if reason.Valid || at.Valid || removed.Valid || source.Valid {
		info.Quarantine = &QuarantineInfo{
			Reason:           reason.String,
			At:               at.Time,
			RemovedArtifacts: int(removed.Int64),
			Source:           source.String,
		}
	}
	return info, true
}

// MarkQuarantined records quarantine metadata for a package version.
// info.Source is persisted to the quarantine_source column (W7); empty
// strings are stored as NULL so legacy quarantine rows that predate the
// column don't drift away from the back-compat default.
func (idx *Index) MarkQuarantined(repo, packageName, version string, info QuarantineInfo) error {
	if info.At.IsZero() {
		info.At = time.Now().UTC()
	}
	orgID := tenancy.NormalizeOrgID(idx.orgID)
	var sourceArg any
	if s := strings.TrimSpace(info.Source); s != "" {
		sourceArg = s
	}
	_, err := idx.store.DB().Exec(`INSERT INTO index_entries(org_id, repository, package, version, format, quarantine_reason, quarantine_at, quarantine_removed_artifacts, quarantine_source)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(org_id, repository, package, version) DO UPDATE SET
			quarantine_reason=excluded.quarantine_reason,
			quarantine_at=excluded.quarantine_at,
			quarantine_removed_artifacts=excluded.quarantine_removed_artifacts,
			quarantine_source=excluded.quarantine_source`,
		orgID, repo, packageName, version, "", strings.TrimSpace(info.Reason), info.At, info.RemovedArtifacts, sourceArg)
	return err
}

// ClearQuarantine removes the quarantine flag from an index_entries
// row by NULL-ing the quarantine_* columns. Used by the bulk-action
// rollback path (W7 slice 2) when a multi-item quarantine partially
// applied and must be reversed. The row itself is preserved — only
// the quarantine metadata is cleared, mirroring the contract of
// MarkQuarantined which only writes the same set of columns.
//
// Returns nil even when the row does not exist (idempotent rollback)
// so callers compensating multiple writes don't have to special-case
// "already cleared" against "never existed".
func (idx *Index) ClearQuarantine(repo, packageName, version string) error {
	orgID := tenancy.NormalizeOrgID(idx.orgID)
	_, err := idx.store.DB().Exec(`UPDATE index_entries
		SET quarantine_reason=NULL,
		    quarantine_at=NULL,
		    quarantine_removed_artifacts=NULL,
		    quarantine_source=NULL
		WHERE org_id=? AND repository=? AND package=? AND version=?`,
		orgID, repo, packageName, version)
	return err
}

func decodePaths(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var paths []string
	if err := json.Unmarshal([]byte(raw), &paths); err != nil {
		return nil
	}
	return paths
}

func encodePaths(paths []string) string {
	trimmed := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !containsPath(trimmed, p) {
			trimmed = append(trimmed, p)
		}
	}
	if len(trimmed) == 0 {
		return ""
	}
	b, err := json.Marshal(trimmed)
	if err != nil {
		return ""
	}
	return string(b)
}

func containsPath(paths []string, candidate string) bool {
	for _, existing := range paths {
		if existing == candidate {
			return true
		}
	}
	return false
}
