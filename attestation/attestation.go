// Package attestation persists verified provenance and SBOM attestations
// to the shared `attestations` table in pgstore. It is the storage layer
// that sits beneath both internal/provenance (which produces SLSA / GPG /
// x509 / sumdb attestations during package verification) and internal/sbom
// (which produces signed CycloneDX SBOM attestations on export).
//
// Attestation rows are facts about a package coordinate, not about a
// tenant — like internal/intelligence reports. The primary key
// (ecosystem, package, version, attestation_type) lets multiple types
// coexist for one version (typically one "sigstore" row plus one "sbom"
// row) while keeping most-recent-wins semantics within a type.
package attestation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
)

// ErrNotFound is returned by Get when no attestation row matches.
var ErrNotFound = errors.New("attestation: not found")

// Attestation is the in-memory shape of one row in the attestations table.
//
// The value semantics intentionally mirror provenance.Result so producers
// can copy fields in directly without translation. Bundle is the raw
// signed envelope (Sigstore bundle JSON, in-toto envelope, GPG-detached
// signature, etc.) — verbatim — so callers can re-verify offline or
// surface the full chain in audit views.
type Attestation struct {
	Ecosystem          string    `json:"ecosystem"`
	Package            string    `json:"package"`
	Version            string    `json:"version"`
	AttestationType    string    `json:"attestationType"` // sigstore | gpg | x509 | sumdb | sbom
	SubjectDigest      string    `json:"subjectDigest,omitempty"`
	BundleFormat       string    `json:"bundleFormat,omitempty"`
	SLSALevel          int       `json:"slsaLevel,omitempty"`
	BuilderID          string    `json:"builderId,omitempty"`
	SourceRepo         string    `json:"sourceRepo,omitempty"`
	SourceCommit       string    `json:"sourceCommit,omitempty"`
	TransparencyLogURL string    `json:"transparencyLogUrl,omitempty"`
	CacheStale         bool      `json:"cacheStale,omitempty"`
	Bundle             []byte    `json:"-"`
	VerifiedAt         time.Time `json:"verifiedAt"`
}

// Store reads and writes Attestation rows.
type Store struct {
	sql *pgstore.Store
}

// NewStore wires an attestation store against the shared pgstore.Store.
// A nil *pgstore.Store is allowed (tests and offline modes) — every
// method becomes a no-op or returns ErrNotFound.
func NewStore(db *pgstore.Store) *Store {
	return &Store{sql: db}
}

// Upsert writes a single attestation, replacing any prior row for the same
// (ecosystem, package, version, attestation_type) tuple. The most-recent
// verification wins — older verifications are not retained.
func (s *Store) Upsert(ctx context.Context, a *Attestation) error {
	if s == nil || s.sql == nil || s.sql.DB() == nil || a == nil {
		return nil
	}
	if a.Ecosystem == "" || a.Package == "" || a.Version == "" || a.AttestationType == "" {
		return fmt.Errorf("attestation: missing required identity fields")
	}
	verifiedAt := a.VerifiedAt
	if verifiedAt.IsZero() {
		verifiedAt = time.Now().UTC()
	}
	_, err := s.sql.DB().ExecContext(ctx, `
		INSERT INTO attestations (
			ecosystem, package_name, version, attestation_type,
			subject_digest, bundle_format,
			slsa_level, builder_id, source_repo, source_commit,
			transparency_log_url, cache_stale, bundle, verified_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (ecosystem, package_name, version, attestation_type)
		DO UPDATE SET
			subject_digest       = EXCLUDED.subject_digest,
			bundle_format        = EXCLUDED.bundle_format,
			slsa_level           = EXCLUDED.slsa_level,
			builder_id           = EXCLUDED.builder_id,
			source_repo          = EXCLUDED.source_repo,
			source_commit        = EXCLUDED.source_commit,
			transparency_log_url = EXCLUDED.transparency_log_url,
			cache_stale          = EXCLUDED.cache_stale,
			bundle               = EXCLUDED.bundle,
			verified_at          = EXCLUDED.verified_at,
			updated_at           = CURRENT_TIMESTAMP
	`,
		a.Ecosystem, a.Package, a.Version, a.AttestationType,
		nullString(a.SubjectDigest), nullString(a.BundleFormat),
		a.SLSALevel, nullString(a.BuilderID), nullString(a.SourceRepo), nullString(a.SourceCommit),
		nullString(a.TransparencyLogURL), a.CacheStale, a.Bundle, verifiedAt,
	)
	if err != nil {
		return fmt.Errorf("attestation: upsert: %w", err)
	}
	return nil
}

// Get returns the most-recent attestation of the given type for a package
// version, or ErrNotFound when no row exists.
func (s *Store) Get(ctx context.Context, ecosystem, pkg, version, attType string) (*Attestation, error) {
	if s == nil || s.sql == nil || s.sql.ReadDB() == nil {
		return nil, ErrNotFound
	}
	row := s.sql.ReadDB().QueryRowContext(ctx, `
		SELECT ecosystem, package_name, version, attestation_type,
		       subject_digest, bundle_format,
		       slsa_level, builder_id, source_repo, source_commit,
		       transparency_log_url, cache_stale, bundle, verified_at
		FROM attestations
		WHERE ecosystem=$1 AND package_name=$2 AND version=$3 AND attestation_type=$4
	`, ecosystem, pkg, version, attType)
	a, err := scanAttestation(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("attestation: get: %w", err)
	}
	return a, nil
}

// List returns every attestation for a package version, ordered by
// verified_at DESC. Used by the dashboard / verify CLI to render the
// full chain attached to one version.
func (s *Store) List(ctx context.Context, ecosystem, pkg, version string) ([]*Attestation, error) {
	if s == nil || s.sql == nil || s.sql.ReadDB() == nil {
		return nil, nil
	}
	rows, err := s.sql.ReadDB().QueryContext(ctx, `
		SELECT ecosystem, package_name, version, attestation_type,
		       subject_digest, bundle_format,
		       slsa_level, builder_id, source_repo, source_commit,
		       transparency_log_url, cache_stale, bundle, verified_at
		FROM attestations
		WHERE ecosystem=$1 AND package_name=$2 AND version=$3
		ORDER BY verified_at DESC
	`, ecosystem, pkg, version)
	if err != nil {
		return nil, fmt.Errorf("attestation: list: %w", err)
	}
	defer rows.Close()
	var out []*Attestation
	for rows.Next() {
		a, err := scanAttestation(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("attestation: scan: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("attestation: rows: %w", err)
	}
	return out, nil
}

// scanAttestation is shared between row-scan and rows-scan paths. The
// scan function is the row's Scan method passed in (so we don't need
// generics or duplicated SELECT lists).
func scanAttestation(scan func(...any) error) (*Attestation, error) {
	var (
		a                                            Attestation
		subjectDigest, bundleFormat                  sql.NullString
		builderID, sourceRepo, sourceCommit, tlogURL sql.NullString
	)
	err := scan(
		&a.Ecosystem, &a.Package, &a.Version, &a.AttestationType,
		&subjectDigest, &bundleFormat,
		&a.SLSALevel, &builderID, &sourceRepo, &sourceCommit,
		&tlogURL, &a.CacheStale, &a.Bundle, &a.VerifiedAt,
	)
	if err != nil {
		return nil, err
	}
	a.SubjectDigest = subjectDigest.String
	a.BundleFormat = bundleFormat.String
	a.BuilderID = builderID.String
	a.SourceRepo = sourceRepo.String
	a.SourceCommit = sourceCommit.String
	a.TransparencyLogURL = tlogURL.String
	return &a, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
