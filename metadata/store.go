package metadata

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
	"github.com/chain305/chainsaw-core/tenancy"
)

// ErrNotFound indicates the requested metadata does not exist.
var ErrNotFound = errors.New("metadata not found")

// ErrUnavailable indicates the metadata store has no live DB handle.
// Callers (notably the intelligence providers) treat this as "no data
// yet" rather than a hard failure so startup races and zero-value test
// stores do not surface as user-visible errors.
var ErrUnavailable = errors.New("metadata store unavailable")

// PackageMetadata captures package-level metadata.
type PackageMetadata struct {
	Repository         string     `json:"repository"`
	Package            string     `json:"package"`
	Version            string     `json:"version"`
	LicenseSPDX        string     `json:"licenseSpdx,omitempty"`
	PackageReleaseDate *time.Time `json:"packageReleaseDate,omitempty"`
	VersionReleaseDate *time.Time `json:"versionReleaseDate,omitempty"`
	SHA256Hash         string     `json:"sha256Hash,omitempty"`
	UpstreamURL        string     `json:"upstreamUrl,omitempty"`
	InternalPackage    bool       `json:"internalPackage"`
	CreatedAt          time.Time  `json:"createdAt"`
	UpdatedAt          time.Time  `json:"updatedAt"`

	// Supply chain integrity fields.
	ProvenanceStatus    string `json:"provenanceStatus,omitempty"`    // verified, unverified, unavailable, missing, failed
	TrustScore          int    `json:"trustScore,omitempty"`          // composite 0-100
	TrustScoreBreakdown string `json:"trustScoreBreakdown,omitempty"` // JSON breakdown
	TyposquatStatus     string `json:"typosquatStatus,omitempty"`     // clean, suspected, confirmed_safe
	TyposquatSimilarTo  string `json:"typosquatSimilarTo,omitempty"`  // popular package it resembles
	MalwareStatus       string `json:"malwareStatus,omitempty"`       // clean, malicious, unknown
	MalwareID           string `json:"malwareId,omitempty"`           // OSV ID if malicious
	ChecksumVerified    bool   `json:"checksumVerified,omitempty"`
	// ChecksumDeclared records the hash chainsaw extracted from the
	// upstream registry metadata (npm dist.integrity, pypi sha256, etc.).
	// Paired with ChecksumActual so operators have a full audit trail
	// of what was compared on every fetch, not just on mismatch. See
	// internal/checksum/declared.go for per-ecosystem extraction.
	ChecksumDeclared string `json:"checksumDeclared,omitempty"`
	// ChecksumActual is the hex digest chainsaw computed over the
	// bytes it served. Populated on every fetch that produced a
	// Decision (matched, unavailable, or mismatch); empty only for
	// cached fetches that bypassed the checksum pipeline.
	ChecksumActual string `json:"checksumActual,omitempty"`
	SourceRepo     string `json:"sourceRepo,omitempty"` // linked source repository

	// Repo liveness (PR 11).
	// RepoLinkStatus is the classification of the linked source repository:
	// unknown / ok / archived / missing / ownership_mismatch. Empty means
	// the enricher has never run for this package (treated as unknown by
	// the trust-score factor).
	RepoLinkStatus        string     `json:"repoLinkStatus,omitempty"`
	RepoLinkLastCheckedAt *time.Time `json:"repoLinkLastCheckedAt,omitempty"`

	// Install-script classification — populated by the static scan.
	// Values: "none" | "present" | "fetches_remote" | "eval_encoded" | "mutates_dependency".
	// Empty string means the scan has not run for this version yet.
	InstallScriptKind string `json:"installScriptKind,omitempty"`

	// PublisherSet holds the normalised publisher/maintainer identifiers for
	// this package version (lowercase, trimmed). Populated by the
	// publisherChanged feature PR — compared across versions via
	// metadiff.PublisherSetDiff to detect account takeovers (e.g. Axios
	// v1.14.1 / v0.30.4 publisher swaps). Persisted to the JSONB
	// package_metadata.publisher_set column added in the foundation migration.
	PublisherSet []string `json:"publisherSet,omitempty"`

	// VersionAnomalyFlags carries the per-kind flags produced by
	// internal/supplychain/metadiff.VersionSequenceFlags against this
	// version's history — one or more of "semver_regression", "major_skip",
	// "timestamp_regression". An empty slice means "no anomaly detected".
	// nil means "never computed" (lazy backfill).
	VersionAnomalyFlags []string `json:"versionAnomalyFlags,omitempty"`

	// Hidden Unicode hit count (PR 8). Zero = no scan performed OR scan
	// found nothing; see CHAINSAW_HIDDEN_UNICODE_THRESHOLD for the gate
	// the evaluator compares this against. Kinds are NOT persisted — the
	// scanner re-emits them in CheckResult.Signals per request so the
	// evaluator can do intersection matching without a DB column.
	HiddenUnicodeHits int `json:"hiddenUnicodeHits,omitempty"`

	// Supply-chain columns from the foundation migration (PR 9 fills this in
	// for display/BOM use; the live policy condition uses the sync query
	// rather than this cached counter).
	PublishVelocity24h int `json:"publishVelocity24h,omitempty"`

	// Yanked mirrors Report.Release.Yanked at upsert time. The
	// PublishCountByPublishers velocity query filters yanked=FALSE so a
	// post-incident yank-and-republish flurry doesn't trip the >20/24h
	// anomaly. Defaults to false for callers that don't set it.
	Yanked bool `json:"yanked,omitempty"`

	// SLSA-substrate columns (Phase 5). These are the denormalised
	// projections the policy evaluator reads on the request hot path —
	// the canonical store of full attestation bundles + history is the
	// dedicated `attestations` table (see internal/attestation). When
	// the package has no verified attestation, SLSALevel is 0 and the
	// other fields are empty.
	SLSALevel                  int    `json:"slsaLevel,omitempty"`
	AttestationBuilderID       string `json:"attestationBuilderId,omitempty"`
	AttestationIssuer          string `json:"attestationIssuer,omitempty"`
	AttestationSourceRepo      string `json:"attestationSourceRepo,omitempty"`
	AttestationTransparencyLog string `json:"attestationTransparencyLog,omitempty"`
	AttestationCacheStale      bool   `json:"attestationCacheStale,omitempty"`
}

// VulnerabilityMetadata captures vulnerability information.
type VulnerabilityMetadata struct {
	Repository      string    `json:"repository"`
	Package         string    `json:"package"`
	Version         string    `json:"version"`
	IsVulnerable    bool      `json:"isVulnerable"`
	CVSSScore       float64   `json:"cvssScore"`
	EPSSScore       float64   `json:"epssScore"`
	CVEs            []string  `json:"cves,omitempty"`
	ScannerDBDigest string    `json:"scannerDbDigest,omitempty"`
	ScannedAt       time.Time `json:"scannedAt"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`

	// CVEDetails carries per-CVE fix-version data extracted by the Trivy
	// ingestion path. Persisted as JSONB in vulnerability_metadata.cve_details
	// so the v2 risk engine's SignalVulnFixAvailable can fire on real rows.
	// Defined locally (parallel to intelligence.CVEDetail) because
	// internal/intelligence imports internal/metadata — the reverse import
	// would cycle.
	CVEDetails []CVEDetail `json:"cveDetails,omitempty"`
}

// CVEDetail is the storage-layer twin of intelligence.CVEDetail, kept here
// to avoid an import cycle. Field tags match the intelligence type so the
// JSONB blob round-trips byte-for-byte across the layer boundary.
type CVEDetail struct {
	CVE          string `json:"cve"`
	FixedVersion string `json:"fixedVersion,omitempty"`
	FixAvailable bool   `json:"fixAvailable,omitempty"`
}

// Store maintains package metadata in the database.
type Store struct {
	sql   *pgstore.Store
	orgID string
}

// NewStore wires a metadata store backed by the database.
func NewStore(db *pgstore.Store) (*Store, error) {
	if db == nil {
		return nil, errors.New("database store is required")
	}
	return &Store{sql: db}, nil
}

// ForOrg scopes metadata operations to a specific org.
func (s *Store) ForOrg(orgID string) *Store {
	if s == nil {
		return nil
	}
	next := *s
	next.orgID = tenancy.NormalizeOrgID(orgID)
	return &next
}

// GetPackageMetadata retrieves package metadata.
func (s *Store) GetPackageMetadata(repository, packageName, version string) (PackageMetadata, error) {
	if s == nil || s.sql == nil {
		return PackageMetadata{}, ErrUnavailable
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)

	var (
		meta                                   PackageMetadata
		licenseSPDX, sha256Hash, upstreamURL   sql.NullString
		sourceRepo, repoLinkStatus             sql.NullString
		installScriptKind                      sql.NullString
		publisherSetJSON                       sql.NullString
		checksumDeclared, checksumActual       sql.NullString
		packageReleaseDate, versionReleaseDate sql.NullTime
		repoLinkLastCheckedAt                  sql.NullTime
		internalPackage                        int
		// versionAnomalyFlags must use pgstore.PgTextArray, not raw
		// []string. pgx/v5/stdlib accepts []string as an INSERT param
		// for text[] but does NOT auto-decode the reverse on Scan —
		// the asymmetry that produced CHW-5307 on findings.owners
		// also applies here. Without the wrapper, this Scan returns
		// "unsupported Scan, storing driver.Value type string into
		// type *[]string" and silently breaks every package-metadata
		// read that lands on a row whose flags column is non-NULL.
		versionAnomalyFlags        pgstore.PgTextArray
		hiddenUnicodeHits          sql.NullInt64
		provenanceStatus           sql.NullString
		attestationBuilderID       sql.NullString
		attestationIssuer          sql.NullString
		attestationSourceRepo      sql.NullString
		attestationTransparencyLog sql.NullString
		slsaLevel                  sql.NullInt64
		attestationCacheStale      sql.NullBool
		yanked                     sql.NullBool
	)

	// Include source_repo, repo_link_status, repo_link_last_checked_at
	// because the repo-liveness enricher (PR 11) needs them to decide
	// whether to re-probe the repository and to compute the trust-score
	// factor. install_script_kind (PR 1) is nullable and may still be
	// NULL for versions whose artifact has not been scanned yet;
	// callers treat the empty string as "not yet scanned".
	//
	// provenance_status and the attestation_* columns hydrate the SLSA
	// substrate fields on the EvaluationContext (Phase 5). They are
	// read on the hot path so policies expressed against
	// RequireSLSALevel / RequireBuilderID / RequireSourceRepo etc. can
	// fire on the cached row without a second round-trip to the
	// dedicated `attestations` table.
	row := s.sql.DB().QueryRow(`SELECT repository, package, version, license_spdx, package_release_date,
		version_release_date, sha256_hash, upstream_url, internal_package, source_repo,
		repo_link_status, repo_link_last_checked_at, install_script_kind, publisher_set, version_anomaly_flags, hidden_unicode_hits,
		checksum_declared, checksum_actual,
		provenance_status, slsa_level, attestation_builder_id, attestation_issuer,
		attestation_source_repo, attestation_transparency_log, attestation_cache_stale,
		yanked, created_at, updated_at
		FROM package_metadata WHERE org_id=? AND repository=? AND package=? AND version=?`,
		orgID, repository, packageName, version)

	err := row.Scan(&meta.Repository, &meta.Package, &meta.Version, &licenseSPDX, &packageReleaseDate,
		&versionReleaseDate, &sha256Hash, &upstreamURL, &internalPackage, &sourceRepo,
		&repoLinkStatus, &repoLinkLastCheckedAt, &installScriptKind, &publisherSetJSON, &versionAnomalyFlags, &hiddenUnicodeHits,
		&checksumDeclared, &checksumActual,
		&provenanceStatus, &slsaLevel, &attestationBuilderID, &attestationIssuer,
		&attestationSourceRepo, &attestationTransparencyLog, &attestationCacheStale,
		&yanked, &meta.CreatedAt, &meta.UpdatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return PackageMetadata{}, ErrNotFound
	}
	if err != nil {
		return PackageMetadata{}, err
	}

	meta.LicenseSPDX = licenseSPDX.String
	meta.SHA256Hash = sha256Hash.String
	meta.UpstreamURL = upstreamURL.String
	meta.SourceRepo = sourceRepo.String
	meta.RepoLinkStatus = repoLinkStatus.String
	meta.ChecksumDeclared = checksumDeclared.String
	meta.ChecksumActual = checksumActual.String
	meta.InternalPackage = internalPackage == 1
	meta.InstallScriptKind = installScriptKind.String
	if packageReleaseDate.Valid {
		meta.PackageReleaseDate = &packageReleaseDate.Time
	}
	if versionReleaseDate.Valid {
		meta.VersionReleaseDate = &versionReleaseDate.Time
	}
	if repoLinkLastCheckedAt.Valid {
		t := repoLinkLastCheckedAt.Time
		meta.RepoLinkLastCheckedAt = &t
	}
	if publisherSetJSON.Valid && publisherSetJSON.String != "" {
		_ = json.Unmarshal([]byte(publisherSetJSON.String), &meta.PublisherSet)
	}
	meta.VersionAnomalyFlags = []string(versionAnomalyFlags)
	if hiddenUnicodeHits.Valid {
		meta.HiddenUnicodeHits = int(hiddenUnicodeHits.Int64)
	}
	meta.ProvenanceStatus = provenanceStatus.String
	if slsaLevel.Valid {
		meta.SLSALevel = int(slsaLevel.Int64)
	}
	meta.AttestationBuilderID = attestationBuilderID.String
	meta.AttestationIssuer = attestationIssuer.String
	meta.AttestationSourceRepo = attestationSourceRepo.String
	meta.AttestationTransparencyLog = attestationTransparencyLog.String
	if attestationCacheStale.Valid {
		meta.AttestationCacheStale = attestationCacheStale.Bool
	}
	if yanked.Valid {
		meta.Yanked = yanked.Bool
	}

	return meta, nil
}

// PackageMetadataRow is a per-tenant view of package_metadata used by the
// scheduled intelligence refresher. The refresher runs across every org, so
// the iterator returns org_id alongside the metadata instead of scoping to a
// single org like GetPackageMetadata does.
type PackageMetadataRow struct {
	OrgID string
	PackageMetadata
}

// PackageMetadataCursor is the keyset pagination cursor for
// IteratePackageMetadata. Pagination orders by (updated_at ASC, org_id,
// repository, package, version) so the stalest rows refresh first and a
// continuous walk never revisits a row twice within the same pass.
type PackageMetadataCursor struct {
	UpdatedAt  time.Time
	OrgID      string
	Repository string
	Package    string
	Version    string
}

// IsZero reports whether the cursor is the starting position (first page).
func (c PackageMetadataCursor) IsZero() bool {
	return c.UpdatedAt.IsZero() && c.OrgID == "" && c.Repository == "" && c.Package == "" && c.Version == ""
}

// IteratePackageMetadata returns one page of package_metadata rows ordered
// by updated_at ASC so the scheduled refresher hits the stalest rows first.
// Pagination is keyset-based over (updated_at, org_id, repository, package,
// version) so concurrent writes against the table do not cause skips or
// duplicates within a walk.
//
// A zero `after` cursor yields the first page. The second return is the
// cursor for the next page; IsZero() is true when there are no more rows.
// Limit is clamped to [1, 1000]; 0 falls back to 200.
func (s *Store) IteratePackageMetadata(ctx context.Context, after PackageMetadataCursor, limit int) ([]PackageMetadataRow, PackageMetadataCursor, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return nil, PackageMetadataCursor{}, ErrUnavailable
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}

	// The scheduled refresher doesn't consume version_anomaly_flags
	// directly — the Scan providers recompute it on cache miss — so
	// we skip that column here to avoid the pgx/v5 "NULL TEXT[] →
	// *[]string" Scan incompatibility that bit us on rows pre-dating
	// PR 3. Callers that need the flags use GetPackageMetadata.
	query := `SELECT org_id, repository, package, version, license_spdx, package_release_date,
		version_release_date, sha256_hash, upstream_url, internal_package, source_repo,
		repo_link_status, repo_link_last_checked_at, install_script_kind, publisher_set,
		hidden_unicode_hits, checksum_declared, checksum_actual,
		created_at, updated_at FROM package_metadata`
	args := []any{}
	if !after.IsZero() {
		// Keyset predicate: (updated_at, org_id, repository, package, version)
		// strictly greater than the cursor. Tuple comparison is
		// Postgres-native and uses the (org_id, updated_at) index via the
		// updated_at filter, then narrows by the tail keys.
		query += ` WHERE (updated_at, org_id, repository, package, version) > (?, ?, ?, ?, ?)`
		args = append(args, after.UpdatedAt, after.OrgID, after.Repository, after.Package, after.Version)
	}
	query += ` ORDER BY updated_at ASC, org_id ASC, repository ASC, package ASC, version ASC LIMIT ?`
	args = append(args, limit)

	rows, err := s.sql.DB().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, PackageMetadataCursor{}, err
	}
	defer rows.Close()

	out := make([]PackageMetadataRow, 0, limit)
	var next PackageMetadataCursor
	for rows.Next() {
		var (
			row                                    PackageMetadataRow
			licenseSPDX, sha256Hash, upstreamURL   sql.NullString
			sourceRepo, repoLinkStatus             sql.NullString
			installScriptKind                      sql.NullString
			publisherSetJSON                       sql.NullString
			checksumDeclared, checksumActual       sql.NullString
			packageReleaseDate, versionReleaseDate sql.NullTime
			repoLinkLastCheckedAt                  sql.NullTime
			internalPackage                        int
			hiddenUnicodeHits                      sql.NullInt64
		)
		if err := rows.Scan(&row.OrgID, &row.Repository, &row.Package, &row.Version,
			&licenseSPDX, &packageReleaseDate, &versionReleaseDate, &sha256Hash, &upstreamURL,
			&internalPackage, &sourceRepo, &repoLinkStatus, &repoLinkLastCheckedAt,
			&installScriptKind, &publisherSetJSON, &hiddenUnicodeHits,
			&checksumDeclared, &checksumActual, &row.CreatedAt, &row.UpdatedAt); err != nil {
			return nil, PackageMetadataCursor{}, err
		}
		row.LicenseSPDX = licenseSPDX.String
		row.SHA256Hash = sha256Hash.String
		row.UpstreamURL = upstreamURL.String
		row.SourceRepo = sourceRepo.String
		row.RepoLinkStatus = repoLinkStatus.String
		row.ChecksumDeclared = checksumDeclared.String
		row.ChecksumActual = checksumActual.String
		row.InternalPackage = internalPackage == 1
		row.InstallScriptKind = installScriptKind.String
		if packageReleaseDate.Valid {
			t := packageReleaseDate.Time
			row.PackageReleaseDate = &t
		}
		if versionReleaseDate.Valid {
			t := versionReleaseDate.Time
			row.VersionReleaseDate = &t
		}
		if repoLinkLastCheckedAt.Valid {
			t := repoLinkLastCheckedAt.Time
			row.RepoLinkLastCheckedAt = &t
		}
		if publisherSetJSON.Valid && publisherSetJSON.String != "" {
			_ = json.Unmarshal([]byte(publisherSetJSON.String), &row.PublisherSet)
		}
		if hiddenUnicodeHits.Valid {
			row.HiddenUnicodeHits = int(hiddenUnicodeHits.Int64)
		}
		out = append(out, row)
		next = PackageMetadataCursor{
			UpdatedAt:  row.UpdatedAt,
			OrgID:      row.OrgID,
			Repository: row.Repository,
			Package:    row.Package,
			Version:    row.Version,
		}
	}
	if err := rows.Err(); err != nil {
		return nil, PackageMetadataCursor{}, err
	}
	if len(out) < limit {
		// Exhausted — signal end-of-walk with a zero cursor so callers can
		// wrap back to the top without a dedicated "done" return.
		return out, PackageMetadataCursor{}, nil
	}
	return out, next, nil
}

// PackageVersionExists reports whether a (repository, package, version) row
// already exists for the given org. Used by the scheduled refresher to skip
// duplicate stub inserts when a newer upstream version was already observed
// by the live proxy path between refresher ticks.
func (s *Store) PackageVersionExists(ctx context.Context, orgID, repository, packageName, version string) (bool, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return false, ErrUnavailable
	}
	normalizedOrg := tenancy.NormalizeOrgID(orgID)
	var exists int
	err := s.sql.DB().QueryRowContext(ctx,
		`SELECT 1 FROM package_metadata WHERE org_id=? AND repository=? AND package=? AND version=? LIMIT 1`,
		normalizedOrg, repository, packageName, version).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// SetPackageMetadata stores or updates package metadata.
func (s *Store) SetPackageMetadata(meta PackageMetadata) error {
	if s == nil || s.sql == nil {
		return ErrUnavailable
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)

	now := time.Now().UTC()
	if meta.CreatedAt.IsZero() {
		meta.CreatedAt = now
	}
	meta.UpdatedAt = now

	internalPackage := 0
	if meta.InternalPackage {
		internalPackage = 1
	}

	// Serialize PublisherSet to JSON for the JSONB column. nil/empty slices
	// are persisted as SQL NULL so the row stays lazily backfilled — the
	// foundation migration column exists but stays NULL for packages whose
	// publisher set hasn't been extracted yet.
	publisherSetPayload := publisherSetAsJSONB(meta.PublisherSet)

	_, err := s.sql.DB().Exec(`INSERT INTO package_metadata(org_id, repository, package, version, license_spdx,
		package_release_date, version_release_date, sha256_hash, upstream_url, internal_package, publisher_set,
		checksum_declared, checksum_actual, yanked, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(org_id, repository, package, version) DO UPDATE SET
			license_spdx=excluded.license_spdx,
			package_release_date=excluded.package_release_date,
			version_release_date=excluded.version_release_date,
			sha256_hash=excluded.sha256_hash,
			upstream_url=excluded.upstream_url,
			internal_package=excluded.internal_package,
			publisher_set=COALESCE(excluded.publisher_set, package_metadata.publisher_set),
			checksum_declared=excluded.checksum_declared,
			checksum_actual=excluded.checksum_actual,
			yanked=excluded.yanked,
			updated_at=excluded.updated_at`,
		orgID, meta.Repository, meta.Package, meta.Version, nullIfEmpty(meta.LicenseSPDX),
		timeToNull(meta.PackageReleaseDate), timeToNull(meta.VersionReleaseDate),
		nullIfEmpty(meta.SHA256Hash), nullIfEmpty(meta.UpstreamURL), internalPackage, publisherSetPayload,
		nullIfEmpty(meta.ChecksumDeclared), nullIfEmpty(meta.ChecksumActual), meta.Yanked,
		meta.CreatedAt, meta.UpdatedAt)

	return err
}

// publisherSetAsJSONB renders PublisherSet for storage in the JSONB column.
// Empty slices return nil so the column stays SQL NULL — distinguishable
// from "extracted but genuinely empty" (which we persist as "[]").
func publisherSetAsJSONB(set []string) any {
	if set == nil {
		return nil
	}
	b, err := json.Marshal(set)
	if err != nil {
		return nil
	}
	return string(b)
}

// UpdateSupplyChainMetadata updates only the supply chain integrity fields for a package.
func (s *Store) UpdateSupplyChainMetadata(repository, packageName, version string, update SupplyChainUpdate) error {
	if s == nil || s.sql == nil {
		return ErrUnavailable
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)
	now := time.Now().UTC()

	query, args, ok := buildSupplyChainUpdateSQL(now, update)
	if !ok {
		return nil // nothing to update
	}
	args = append(args, orgID, repository, packageName, version)
	_, err := s.sql.DB().Exec(query, args...)
	return err
}

// buildSupplyChainUpdateSQL renders the UPDATE statement for
// UpdateSupplyChainMetadata. Extracted so the SET-clause invariants (no
// column assigned twice — Postgres rejects that with SQLSTATE 42601) are
// testable without a live DB. Returns ok=false when no field besides
// updated_at would be set, in which case the caller should no-op.
func buildSupplyChainUpdateSQL(now time.Time, update SupplyChainUpdate) (string, []any, bool) {
	// Check if there's anything to update beyond updated_at.
	if update.ProvenanceStatus == nil && update.TrustScore == nil &&
		update.TrustScoreBreakdown == nil && update.TyposquatStatus == nil &&
		update.TyposquatSimilarTo == nil && update.MalwareStatus == nil &&
		update.MalwareID == nil && update.ChecksumVerified == nil &&
		update.SourceRepo == nil && update.RepoLinkStatus == nil &&
		update.RepoLinkLastCheckedAt == nil && update.InstallScriptKind == nil &&
		update.PublisherSet == nil && update.VersionAnomalyFlags == nil &&
		update.HiddenUnicodeHits == nil && update.PublishVelocity24h == nil &&
		update.ChecksumDeclared == nil && update.ChecksumActual == nil &&
		update.SLSALevel == nil && update.AttestationBuilderID == nil &&
		update.AttestationIssuer == nil && update.AttestationSourceRepo == nil &&
		update.AttestationTransparencyLog == nil && update.AttestationCacheStale == nil {
		return "", nil, false
	}

	setClauses := []string{"updated_at=?"}
	args := []any{now}

	if update.ProvenanceStatus != nil {
		setClauses = append(setClauses, "provenance_status=?")
		args = append(args, *update.ProvenanceStatus)
	}
	if update.TrustScore != nil {
		setClauses = append(setClauses, "trust_score=?")
		args = append(args, *update.TrustScore)
	}
	if update.TrustScoreBreakdown != nil {
		setClauses = append(setClauses, "trust_score_breakdown=?")
		args = append(args, *update.TrustScoreBreakdown)
	}
	if update.TyposquatStatus != nil {
		setClauses = append(setClauses, "typosquat_status=?")
		args = append(args, *update.TyposquatStatus)
	}
	if update.TyposquatSimilarTo != nil {
		setClauses = append(setClauses, "typosquat_similar_to=?")
		args = append(args, *update.TyposquatSimilarTo)
	}
	if update.MalwareStatus != nil {
		setClauses = append(setClauses, "malware_status=?")
		args = append(args, *update.MalwareStatus)
	}
	if update.MalwareID != nil {
		setClauses = append(setClauses, "malware_id=?")
		args = append(args, *update.MalwareID)
	}
	if update.ChecksumVerified != nil {
		v := 0
		if *update.ChecksumVerified {
			v = 1
		}
		setClauses = append(setClauses, "checksum_verified=?")
		args = append(args, v)
	}
	if update.ChecksumDeclared != nil {
		setClauses = append(setClauses, "checksum_declared=?")
		args = append(args, nullIfEmpty(*update.ChecksumDeclared))
	}
	if update.ChecksumActual != nil {
		setClauses = append(setClauses, "checksum_actual=?")
		args = append(args, nullIfEmpty(*update.ChecksumActual))
	}
	if update.SourceRepo != nil {
		setClauses = append(setClauses, "source_repo=?")
		args = append(args, *update.SourceRepo)
	}
	if update.RepoLinkStatus != nil {
		setClauses = append(setClauses, "repo_link_status=?")
		args = append(args, *update.RepoLinkStatus)
	}
	if update.RepoLinkLastCheckedAt != nil {
		setClauses = append(setClauses, "repo_link_last_checked_at=?")
		args = append(args, *update.RepoLinkLastCheckedAt)
	}
	if update.InstallScriptKind != nil {
		setClauses = append(setClauses, "install_script_kind=?")
		args = append(args, *update.InstallScriptKind)
	}
	if update.PublisherSet != nil {
		setClauses = append(setClauses, "publisher_set=?")
		args = append(args, publisherSetAsJSONB(*update.PublisherSet))
	}
	if update.VersionAnomalyFlags != nil {
		setClauses = append(setClauses, "version_anomaly_flags=?")
		// pgx/stdlib maps []string ↔ TEXT[] directly; a non-nil empty
		// slice persists an empty array (evaluated, no anomaly).
		flags := *update.VersionAnomalyFlags
		if flags == nil {
			flags = []string{}
		}
		args = append(args, flags)
	}
	if update.HiddenUnicodeHits != nil {
		setClauses = append(setClauses, "hidden_unicode_hits=?")
		args = append(args, *update.HiddenUnicodeHits)
	}
	if update.PublishVelocity24h != nil {
		setClauses = append(setClauses, "publish_velocity_24h=?")
		args = append(args, *update.PublishVelocity24h)
	}
	// NOTE: ChecksumDeclared / ChecksumActual are handled above (just after
	// ChecksumVerified). A second pair of identical branches used to live
	// here, which produced an "ERROR: multiple assignments to same column
	// \"checksum_declared\"" (SQLSTATE 42601) on every docker manifest/blob
	// fetch (any path that sets both fields in one UpdateSupplyChainMetadata
	// call). Do not re-add — see Wave V fix, task #90.
	if update.SLSALevel != nil {
		setClauses = append(setClauses, "slsa_level=?")
		args = append(args, *update.SLSALevel)
	}
	if update.AttestationBuilderID != nil {
		setClauses = append(setClauses, "attestation_builder_id=?")
		args = append(args, nullIfEmpty(*update.AttestationBuilderID))
	}
	if update.AttestationIssuer != nil {
		setClauses = append(setClauses, "attestation_issuer=?")
		args = append(args, nullIfEmpty(*update.AttestationIssuer))
	}
	if update.AttestationSourceRepo != nil {
		setClauses = append(setClauses, "attestation_source_repo=?")
		args = append(args, nullIfEmpty(*update.AttestationSourceRepo))
	}
	if update.AttestationTransparencyLog != nil {
		setClauses = append(setClauses, "attestation_transparency_log=?")
		args = append(args, nullIfEmpty(*update.AttestationTransparencyLog))
	}
	if update.AttestationCacheStale != nil {
		setClauses = append(setClauses, "attestation_cache_stale=?")
		args = append(args, *update.AttestationCacheStale)
	}

	query := "UPDATE package_metadata SET " + strings.Join(setClauses, ", ") +
		" WHERE org_id=? AND repository=? AND package=? AND version=?"
	return query, args, true
}

// ProjectSLSAFields writes the SLSA-substrate columns of an SLSAReport
// onto every package_metadata row matching (package, version) — across
// all orgs and repositories. SLSA / Sigstore claims are universal facts
// about a package coordinate, so the projection is keyed only on
// (package, version) (and ecosystem when present, to avoid touching
// same-name packages from different ecosystems).
//
// Rows that already carry the same values are unchanged (best-effort
// minimisation via column COALESCE/conditional update). When no row
// exists for the coordinate yet, ProjectSLSAFields is a no-op — the
// pipeline's first request for that package will INSERT a row, which
// the sink can then project on the next refresh cycle.
//
// Errors propagate; the caller (typically SLSAReportSink) decides
// whether to log-and-continue.
func (s *Store) ProjectSLSAFields(ctx context.Context, r SLSAReport) error {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return ErrUnavailable
	}
	now := time.Now().UTC()
	setClauses := []string{"updated_at=$1"}
	args := []any{now}
	idx := 2
	if r.ProvenanceStatus != "" {
		setClauses = append(setClauses, fmt.Sprintf("provenance_status=$%d", idx))
		args = append(args, r.ProvenanceStatus)
		idx++
	}
	if r.SLSALevel > 0 {
		setClauses = append(setClauses, fmt.Sprintf("slsa_level=$%d", idx))
		args = append(args, r.SLSALevel)
		idx++
	}
	if r.AttestationBuilderID != "" {
		setClauses = append(setClauses, fmt.Sprintf("attestation_builder_id=$%d", idx))
		args = append(args, r.AttestationBuilderID)
		idx++
	}
	if r.AttestationIssuer != "" {
		setClauses = append(setClauses, fmt.Sprintf("attestation_issuer=$%d", idx))
		args = append(args, r.AttestationIssuer)
		idx++
	}
	if r.AttestationSourceRepo != "" {
		setClauses = append(setClauses, fmt.Sprintf("attestation_source_repo=$%d", idx))
		args = append(args, r.AttestationSourceRepo)
		idx++
	}
	if r.AttestationTransparencyLog != "" {
		setClauses = append(setClauses, fmt.Sprintf("attestation_transparency_log=$%d", idx))
		args = append(args, r.AttestationTransparencyLog)
		idx++
	}
	if r.AttestationCacheStale {
		setClauses = append(setClauses, fmt.Sprintf("attestation_cache_stale=$%d", idx))
		args = append(args, r.AttestationCacheStale)
		idx++
	}
	if len(setClauses) == 1 {
		// Only updated_at would be touched — nothing to project.
		return nil
	}
	args = append(args, r.Package, r.Version)
	pkgIdx := idx
	verIdx := idx + 1
	query := fmt.Sprintf(
		"UPDATE package_metadata SET %s WHERE package=$%d AND version=$%d",
		strings.Join(setClauses, ", "), pkgIdx, verIdx,
	)
	_, err := s.sql.DB().ExecContext(ctx, query, args...)
	return err
}

// LatestPublisherSet returns the most recently-updated non-null PublisherSet
// for (repository, package), excluding the provided version. Callers pass the
// *incoming* version so we look up "the prior version's publishers" without
// having to sort semver ourselves. The sort falls back to updated_at DESC
// because registries aren't always semver-clean (e.g. Axios v0.30.4 after
// v1.14.x is a valid prior from the store's perspective — it's still the most
// recently persisted set).
//
// Returns:
//   - non-nil slice with the decoded publisher set when a prior row carries one
//   - nil slice + nil error when no prior version has a persisted publisher_set
//     (first-seen package, or publisher_set column still NULL pending the
//     lazy backfill from the foundation migration)
func (s *Store) LatestPublisherSet(repository, packageName, excludeVersion string) ([]string, error) {
	if s == nil || s.sql == nil {
		return nil, ErrUnavailable
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)

	var payload sql.NullString
	err := s.sql.DB().QueryRow(`SELECT publisher_set FROM package_metadata
		WHERE org_id=? AND repository=? AND package=? AND version<>?
		  AND publisher_set IS NOT NULL
		ORDER BY updated_at DESC
		LIMIT 1`,
		orgID, repository, packageName, excludeVersion).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !payload.Valid || strings.TrimSpace(payload.String) == "" {
		return nil, nil
	}
	var set []string
	if err := json.Unmarshal([]byte(payload.String), &set); err != nil {
		// Row exists but JSON is corrupted — treat as no prior set rather
		// than failing the whole request path. Corrupt publisher_set JSON
		// would otherwise block every download for this package.
		return nil, nil
	}
	return set, nil
}

// PublishCountByPublishers counts distinct (package, version) rows in
// package_metadata whose persisted publisher_set JSONB contains at least one
// of the supplied normalized publisher identifiers AND whose updated_at is
// at or after `since`. Used by the publishVelocityAnomaly condition: we only
// fire if the same publisher (or any publisher from the incoming version's
// set) has pushed more than the policy threshold in the last 24h.
//
// The foundation migration created a GIN index on publisher_set so this
// query is O(matched rows) rather than a full scan even on large tenants.
//
// An empty publishers slice yields 0 without touching the DB.
func (s *Store) PublishCountByPublishers(ctx context.Context, publishers []string, since time.Time) (int, error) {
	if s == nil || s.sql == nil {
		return 0, ErrUnavailable
	}
	normalized := make([]string, 0, len(publishers))
	seen := make(map[string]struct{}, len(publishers))
	for _, id := range publishers {
		key := strings.ToLower(strings.TrimSpace(id))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, key)
	}
	if len(normalized) == 0 {
		return 0, nil
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)

	// Build `ARRAY[?, ?, ...]::text[]` inline so we stay compatible with
	// database/sql's value plumbing (it can't pass a native []string through
	// the rewriting pg driver). Using ARRAY[...] keeps every identifier a
	// parameterized value — no string concatenation of user input.
	placeholders := make([]string, len(normalized))
	args := make([]any, 0, len(normalized)+2)
	args = append(args, orgID)
	for i, p := range normalized {
		placeholders[i] = "?"
		args = append(args, p)
	}
	args = append(args, since.UTC())

	query := fmt.Sprintf(
		`SELECT COUNT(*) FROM package_metadata
		 WHERE org_id=?
		   AND publisher_set IS NOT NULL
		   AND jsonb_exists_any(publisher_set, ARRAY[%s]::text[])
		   AND yanked = FALSE
		   AND updated_at >= ?`,
		strings.Join(placeholders, ","),
	)

	var count int
	row := s.sql.DB().QueryRowContext(ctx, query, args...)
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// SupplyChainUpdate holds optional updates for supply chain fields.
type SupplyChainUpdate struct {
	ProvenanceStatus      *string
	TrustScore            *int
	TrustScoreBreakdown   *string
	TyposquatStatus       *string
	TyposquatSimilarTo    *string
	MalwareStatus         *string
	MalwareID             *string
	ChecksumVerified      *bool
	SourceRepo            *string
	RepoLinkStatus        *string
	RepoLinkLastCheckedAt *time.Time
	InstallScriptKind     *string
	// PublisherSet is the normalised maintainer/author set for this version.
	// Nil means "leave as-is"; an explicit empty slice means "clear" —
	// matches the pointer-semantics of the other optional fields.
	PublisherSet *[]string
	// VersionAnomalyFlags persists the metadiff flag subset for this
	// version. A non-nil, empty slice means "evaluated, no anomaly";
	// nil means "not evaluated" and leaves the column untouched.
	VersionAnomalyFlags *[]string
	// HiddenUnicodeHits (PR 8) is the scanner's total hit count for the
	// artifact's text files; compared against
	// CHAINSAW_HIDDEN_UNICODE_THRESHOLD to derive HasHiddenUnicode at
	// evaluation time. Zero is a meaningful value ("we scanned and
	// cleared") so the pointer distinguishes "unchanged" from "mark
	// clean".
	HiddenUnicodeHits *int
	// PublishVelocity24h persists the trailing-24h publish count for this
	// package's publisher set, used by the UI/BOM views. Non-nil writes the
	// value (including zero) to package_metadata.publish_velocity_24h.
	PublishVelocity24h *int
	// ChecksumDeclared / ChecksumActual persist the raw hash audit
	// trail from internal/checksum. Populated on every fetch the
	// enforcer evaluates so operators can reconcile a disputed
	// artifact without re-downloading. Nil means "leave existing
	// value untouched" — PR-12 tests assert non-nil propagation.
	ChecksumDeclared *string
	ChecksumActual   *string

	// SLSA-substrate fields (Phase 5). Populated by the provenance
	// provider when verification produces an SLSA-bearing attestation.
	// Nil means "leave existing column value untouched"; explicit zero
	// (SLSALevel=0 or empty strings) writes the cleared value, which
	// the evaluator reads as "no verified attestation".
	SLSALevel                  *int
	AttestationBuilderID       *string
	AttestationIssuer          *string
	AttestationSourceRepo      *string
	AttestationTransparencyLog *string
	AttestationCacheStale      *bool
}

// PackageVersionHistoryEntry is the minimal shape the version-anomaly
// path needs: a semver string plus the publish timestamp for the
// timestamp-regression check. Ordered by publish time ascending (oldest
// first) so callers can append the incoming version to the end and
// hand the full sequence to metadiff.VersionSequenceFlags.
type PackageVersionHistoryEntry struct {
	Version     string
	PublishedAt time.Time
}

// GetPackageVersionHistory returns the most recent `limit` prior
// versions of (repository, packageName), ordered ascending by publish
// time (oldest first). Intended for the version-anomaly check: callers
// append the incoming version and pass the full slice to
// metadiff.VersionSequenceFlags. Rows missing a version_release_date
// are excluded — the timestamp sub-check can't evaluate them and the
// semver sub-check only needs the semver string, which is already the
// primary key.
//
// A non-positive limit yields an empty slice. An error from the
// underlying query is returned unmodified; callers typically log and
// proceed with a nil history (short-circuit in VersionSequenceFlags).
func (s *Store) GetPackageVersionHistory(repository, packageName string, limit int) ([]PackageVersionHistoryEntry, error) {
	if s == nil || s.sql == nil {
		return nil, ErrUnavailable
	}
	if limit <= 0 {
		return nil, nil
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)

	// Pull the most recent `limit` rows (DESC), then reverse in code so
	// callers get ascending order. Cheap for small limits (≤5 per plan).
	rows, err := s.sql.DB().Query(`SELECT version, version_release_date
		FROM package_metadata
		WHERE org_id=? AND repository=? AND package=? AND version_release_date IS NOT NULL
		ORDER BY version_release_date DESC
		LIMIT ?`, orgID, repository, packageName, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]PackageVersionHistoryEntry, 0, limit)
	for rows.Next() {
		var (
			version string
			pub     sql.NullTime
		)
		if err := rows.Scan(&version, &pub); err != nil {
			return nil, err
		}
		entry := PackageVersionHistoryEntry{Version: version}
		if pub.Valid {
			entry.PublishedAt = pub.Time
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Reverse — we queried DESC, callers want ASC.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// GetVulnerabilityMetadata retrieves vulnerability metadata.
func (s *Store) GetVulnerabilityMetadata(repository, packageName, version string) (VulnerabilityMetadata, error) {
	if s == nil || s.sql == nil {
		return VulnerabilityMetadata{}, ErrUnavailable
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)

	var (
		meta                      VulnerabilityMetadata
		isVulnerable              int
		cvssScore, epssScore      sql.NullFloat64
		cvesJSON, scannerDBDigest sql.NullString
		cveDetailsJSON            sql.NullString
		scannedAt                 sql.NullTime
	)

	row := s.sql.DB().QueryRow(`SELECT repository, package, version, is_vulnerable, cvss_score, epss_score,
		cves, cve_details, scanner_db_digest, scanned_at, created_at, updated_at
		FROM vulnerability_metadata WHERE org_id=? AND repository=? AND package=? AND version=?`,
		orgID, repository, packageName, version)

	err := row.Scan(&meta.Repository, &meta.Package, &meta.Version, &isVulnerable, &cvssScore, &epssScore,
		&cvesJSON, &cveDetailsJSON, &scannerDBDigest, &scannedAt, &meta.CreatedAt, &meta.UpdatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return VulnerabilityMetadata{}, ErrNotFound
	}
	if err != nil {
		return VulnerabilityMetadata{}, err
	}

	meta.IsVulnerable = isVulnerable == 1
	if cvssScore.Valid {
		meta.CVSSScore = cvssScore.Float64
	}
	if epssScore.Valid {
		meta.EPSSScore = epssScore.Float64
	}
	if cvesJSON.Valid && cvesJSON.String != "" {
		_ = json.Unmarshal([]byte(cvesJSON.String), &meta.CVEs)
	}
	if cveDetailsJSON.Valid && cveDetailsJSON.String != "" {
		_ = json.Unmarshal([]byte(cveDetailsJSON.String), &meta.CVEDetails)
	}
	if scannerDBDigest.Valid {
		meta.ScannerDBDigest = scannerDBDigest.String
	}
	if scannedAt.Valid {
		meta.ScannedAt = scannedAt.Time
	}

	return meta, nil
}

// SetVulnerabilityMetadata stores or updates vulnerability metadata.
func (s *Store) SetVulnerabilityMetadata(meta VulnerabilityMetadata) error {
	if s == nil || s.sql == nil {
		return ErrUnavailable
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)

	now := time.Now().UTC()
	if meta.CreatedAt.IsZero() {
		meta.CreatedAt = now
	}
	meta.UpdatedAt = now
	if meta.ScannedAt.IsZero() {
		meta.ScannedAt = now
	}

	isVulnerable := 0
	if meta.IsVulnerable {
		isVulnerable = 1
	}

	cvesJSON := ""
	if len(meta.CVEs) > 0 {
		b, _ := json.Marshal(meta.CVEs)
		cvesJSON = string(b)
	}

	cveDetailsJSON := ""
	if len(meta.CVEDetails) > 0 {
		b, _ := json.Marshal(meta.CVEDetails)
		cveDetailsJSON = string(b)
	}

	_, err := s.sql.DB().Exec(`INSERT INTO vulnerability_metadata(org_id, repository, package, version, is_vulnerable,
		cvss_score, epss_score, cves, cve_details, scanner_db_digest, scanned_at, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(org_id, repository, package, version) DO UPDATE SET
			is_vulnerable=excluded.is_vulnerable,
			cvss_score=excluded.cvss_score,
			epss_score=excluded.epss_score,
			cves=excluded.cves,
			cve_details=excluded.cve_details,
			scanner_db_digest=excluded.scanner_db_digest,
			scanned_at=excluded.scanned_at,
			updated_at=excluded.updated_at`,
		orgID, meta.Repository, meta.Package, meta.Version, isVulnerable, floatToNull(meta.CVSSScore),
		floatToNull(meta.EPSSScore), nullIfEmpty(cvesJSON), nullIfEmpty(cveDetailsJSON), nullIfEmpty(meta.ScannerDBDigest), meta.ScannedAt, meta.CreatedAt, meta.UpdatedAt)

	return err
}

// SearchVulnerability finds vulnerability records for a specific package+version across all repositories.
func (s *Store) SearchVulnerability(packageName, version string) ([]VulnerabilityMetadata, error) {
	if s == nil || s.sql == nil {
		return nil, ErrUnavailable
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)

	rows, err := s.sql.DB().Query(`SELECT repository, package, version, is_vulnerable, cvss_score, epss_score,
		cves, cve_details, scanner_db_digest, scanned_at, created_at, updated_at
		FROM vulnerability_metadata WHERE org_id=? AND package=? AND version=?`,
		orgID, packageName, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []VulnerabilityMetadata
	for rows.Next() {
		var (
			meta                      VulnerabilityMetadata
			isVulnerable              int
			cvssScore, epssScore      sql.NullFloat64
			cvesJSON, scannerDBDigest sql.NullString
			cveDetailsJSON            sql.NullString
			scannedAt                 sql.NullTime
		)
		if err := rows.Scan(&meta.Repository, &meta.Package, &meta.Version, &isVulnerable, &cvssScore, &epssScore,
			&cvesJSON, &cveDetailsJSON, &scannerDBDigest, &scannedAt, &meta.CreatedAt, &meta.UpdatedAt); err != nil {
			return nil, err
		}
		meta.IsVulnerable = isVulnerable == 1
		if cvssScore.Valid {
			meta.CVSSScore = cvssScore.Float64
		}
		if epssScore.Valid {
			meta.EPSSScore = epssScore.Float64
		}
		if cvesJSON.Valid && cvesJSON.String != "" {
			_ = json.Unmarshal([]byte(cvesJSON.String), &meta.CVEs)
		}
		if cveDetailsJSON.Valid && cveDetailsJSON.String != "" {
			_ = json.Unmarshal([]byte(cveDetailsJSON.String), &meta.CVEDetails)
		}
		if scannerDBDigest.Valid {
			meta.ScannerDBDigest = scannerDBDigest.String
		}
		if scannedAt.Valid {
			meta.ScannedAt = scannedAt.Time
		}
		results = append(results, meta)
	}
	return results, rows.Err()
}

// ListVulnerablePackages returns all packages marked as vulnerable.
func (s *Store) ListVulnerablePackages(repository string) ([]VulnerabilityMetadata, error) {
	if s == nil || s.sql == nil {
		return nil, ErrUnavailable
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)

	query := `SELECT repository, package, version, is_vulnerable, cvss_score, epss_score, cves, cve_details, scanner_db_digest, scanned_at, created_at, updated_at
		FROM vulnerability_metadata WHERE org_id=? AND is_vulnerable=1`
	args := []any{orgID}

	if strings.TrimSpace(repository) != "" {
		query += ` AND repository=?`
		args = append(args, repository)
	}

	query += ` ORDER BY cvss_score DESC, package ASC`

	rows, err := s.sql.DB().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []VulnerabilityMetadata
	for rows.Next() {
		var (
			meta                      VulnerabilityMetadata
			isVulnerable              int
			cvssScore, epssScore      sql.NullFloat64
			cvesJSON, scannerDBDigest sql.NullString
			cveDetailsJSON            sql.NullString
			scannedAt                 sql.NullTime
		)

		if err := rows.Scan(&meta.Repository, &meta.Package, &meta.Version, &isVulnerable, &cvssScore, &epssScore,
			&cvesJSON, &cveDetailsJSON, &scannerDBDigest, &scannedAt, &meta.CreatedAt, &meta.UpdatedAt); err != nil {
			return nil, err
		}

		meta.IsVulnerable = isVulnerable == 1
		if cvssScore.Valid {
			meta.CVSSScore = cvssScore.Float64
		}
		if epssScore.Valid {
			meta.EPSSScore = epssScore.Float64
		}
		if cvesJSON.Valid && cvesJSON.String != "" {
			_ = json.Unmarshal([]byte(cvesJSON.String), &meta.CVEs)
		}
		if cveDetailsJSON.Valid && cveDetailsJSON.String != "" {
			_ = json.Unmarshal([]byte(cveDetailsJSON.String), &meta.CVEDetails)
		}
		if scannerDBDigest.Valid {
			meta.ScannerDBDigest = scannerDBDigest.String
		}
		if scannedAt.Valid {
			meta.ScannedAt = scannedAt.Time
		}

		results = append(results, meta)
	}

	return results, rows.Err()
}

// Helper functions

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func timeToNull(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return *t
}

func floatToNull(f float64) any {
	if f == 0 {
		return nil
	}
	return f
}
