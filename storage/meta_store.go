package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// MetaStore is the abstraction over per-blob metadata. The default
// implementation is [SidecarMetaStore], which writes a `.meta` file
// next to every blob — preserving prior behaviour for single-instance
// file-backend deployments.
//
// Multi-instance / S3 deployments use [PostgresMetaStore], which keeps
// metadata in the `cached_content_meta` table so the S3 backend
// doesn't need a second object GET to retrieve metadata. Both stores
// satisfy the same interface and the LocalStorage type is agnostic.
type MetaStore interface {
	// Get returns the metadata for the blob keyed by blobKey. The
	// returned (zero, false, nil) signals "not present" without
	// being an error condition.
	Get(ctx context.Context, blobKey string) (ContentMetadata, bool, error)

	// Put writes (or overwrites) metadata for the blob keyed by
	// blobKey. orgID and repository are stored alongside so the
	// table can be queried by org/repo cheaply.
	Put(ctx context.Context, blobKey, orgID, repo string, meta ContentMetadata) error

	// Delete removes metadata for blobKey. Idempotent — missing
	// entries are not an error.
	Delete(ctx context.Context, blobKey string) error
}

// SidecarMetaStore writes metadata to `<blobKey>.meta` files next to
// the blob. blobKey is treated as a filesystem path. Used as the
// default for file-backend deployments to preserve prior behaviour.
type SidecarMetaStore struct{}

// NewSidecarMetaStore returns a sidecar meta store.
func NewSidecarMetaStore() *SidecarMetaStore { return &SidecarMetaStore{} }

// Get reads the sidecar file.
func (s *SidecarMetaStore) Get(_ context.Context, blobKey string) (ContentMetadata, bool, error) {
	meta, err := readMetadata(blobKey)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ContentMetadata{}, false, nil
		}
		return ContentMetadata{}, false, err
	}
	return meta, true, nil
}

// Put writes the sidecar file.
func (s *SidecarMetaStore) Put(_ context.Context, blobKey, _, _ string, meta ContentMetadata) error {
	return writeMetadata(blobKey, meta)
}

// Delete removes the sidecar file. Missing files are not an error.
func (s *SidecarMetaStore) Delete(_ context.Context, blobKey string) error {
	metaPath := metadataPath(blobKey)
	if err := os.Remove(metaPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove metadata sidecar: %w", err)
	}
	return nil
}

// PostgresMetaStore persists metadata in the `cached_content_meta`
// table. Reads fall back to sidecar files (when the SidecarFallback
// is set) so a deployment migrating from the file backend continues
// to serve previously cached blobs while the migration runs.
type PostgresMetaStore struct {
	db              *sql.DB
	SidecarFallback bool
	WriteSidecarToo bool // also write sidecar when true (dual-write during cutover)
}

// NewPostgresMetaStore constructs a Postgres-backed metadata store.
// db must point at the writable pool. Reads default to falling back
// to sidecar files for backwards compatibility.
func NewPostgresMetaStore(db *sql.DB) *PostgresMetaStore {
	return &PostgresMetaStore{db: db, SidecarFallback: true}
}

// Get loads metadata from Postgres, falling back to sidecar files
// when configured and the row is missing.
func (p *PostgresMetaStore) Get(ctx context.Context, blobKey string) (ContentMetadata, bool, error) {
	if p.db == nil {
		return ContentMetadata{}, false, errors.New("postgres meta store requires a database")
	}
	var raw []byte
	err := p.db.QueryRowContext(ctx,
		`SELECT metadata FROM cached_content_meta WHERE blob_key = ?`, blobKey,
	).Scan(&raw)
	if err == nil {
		var meta ContentMetadata
		if err := json.Unmarshal(raw, &meta); err != nil {
			return ContentMetadata{}, false, fmt.Errorf("unmarshal cached_content_meta: %w", err)
		}
		return meta, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ContentMetadata{}, false, fmt.Errorf("query cached_content_meta: %w", err)
	}
	if p.SidecarFallback {
		// Fall back to sidecar; we deliberately do NOT auto-promote
		// here because Get doesn't know the orgID / repository.
		// Promotion happens implicitly on the next Put for this blob
		// (which always happens before a re-Open in the cache flow).
		// Use the chainsaw-migrate-meta CLI for a one-shot bulk
		// migration that preserves org_id / repository attribution.
		meta, err := readMetadata(blobKey)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return ContentMetadata{}, false, nil
			}
			return ContentMetadata{}, false, err
		}
		return meta, true, nil
	}
	return ContentMetadata{}, false, nil
}

// Put upserts metadata in Postgres (and optionally writes a sidecar
// when WriteSidecarToo is set, enabling a safe rollback during
// cutover).
func (p *PostgresMetaStore) Put(ctx context.Context, blobKey, orgID, repo string, meta ContentMetadata) error {
	if p.db == nil {
		return errors.New("postgres meta store requires a database")
	}
	payload, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	_, err = p.db.ExecContext(ctx,
		`INSERT INTO cached_content_meta (blob_key, org_id, repository, logical_path, metadata, cached_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		 ON CONFLICT (blob_key) DO UPDATE SET
		   metadata = EXCLUDED.metadata,
		   logical_path = EXCLUDED.logical_path,
		   updated_at = CURRENT_TIMESTAMP`,
		blobKey, orgID, repo, meta.LogicalPath, payload,
	)
	if err != nil {
		return fmt.Errorf("upsert cached_content_meta: %w", err)
	}
	if p.WriteSidecarToo {
		if err := writeMetadata(blobKey, meta); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes the row from Postgres and the sidecar (when present).
func (p *PostgresMetaStore) Delete(ctx context.Context, blobKey string) error {
	if p.db == nil {
		return errors.New("postgres meta store requires a database")
	}
	if _, err := p.db.ExecContext(ctx, `DELETE FROM cached_content_meta WHERE blob_key = ?`, blobKey); err != nil {
		return fmt.Errorf("delete cached_content_meta: %w", err)
	}
	metaPath := metadataPath(blobKey)
	if err := os.Remove(metaPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove metadata sidecar: %w", err)
	}
	return nil
}

// MigrateSidecarsToPostgres scans every `.meta` file under root,
// inserts each into the Postgres meta store (idempotent — uses
// ON CONFLICT DO NOTHING semantics), and reports the count migrated
// and the count skipped because a row already existed. Failures
// against individual files are returned in the third slice so a
// cutover script can surface them without aborting the whole walk.
func MigrateSidecarsToPostgres(ctx context.Context, db *sql.DB, root string) (migrated, skipped int, failures []error, err error) {
	if db == nil {
		return 0, 0, nil, errors.New("database is required")
	}
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, fs.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".meta") {
			return nil
		}
		blobKey := strings.TrimSuffix(path, ".meta")
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			failures = append(failures, fmt.Errorf("read %s: %w", path, readErr))
			return nil
		}
		var meta ContentMetadata
		if err := json.Unmarshal(raw, &meta); err != nil {
			failures = append(failures, fmt.Errorf("parse %s: %w", path, err))
			return nil
		}
		// Best-effort org/repo derivation: if the blobKey lives under
		// `<root>/<orgID>/<repo>/...` use those segments, else leave empty.
		orgID, repo := deriveOrgRepoFromPath(root, blobKey)
		res, err := db.ExecContext(ctx,
			`INSERT INTO cached_content_meta (blob_key, org_id, repository, logical_path, metadata, cached_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
			 ON CONFLICT (blob_key) DO NOTHING`,
			blobKey, orgID, repo, meta.LogicalPath, raw,
		)
		if err != nil {
			failures = append(failures, fmt.Errorf("insert %s: %w", blobKey, err))
			return nil
		}
		if affected, _ := res.RowsAffected(); affected > 0 {
			migrated++
		} else {
			skipped++
		}
		return ctx.Err()
	})
	if walkErr != nil && !errors.Is(walkErr, fs.ErrNotExist) {
		return migrated, skipped, failures, walkErr
	}
	return migrated, skipped, failures, nil
}

func deriveOrgRepoFromPath(root, blobKey string) (string, string) {
	rel, err := filepath.Rel(root, blobKey)
	if err != nil {
		return "", ""
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	switch {
	case len(parts) >= 2 && parts[0] != "":
		// Layout: <root>/<orgID>/<repo>/...
		return parts[0], parts[1]
	case len(parts) == 1:
		return "", ""
	}
	return "", ""
}

// Compile-time interface assertions.
var (
	_ MetaStore = (*SidecarMetaStore)(nil)
	_ MetaStore = (*PostgresMetaStore)(nil)
)
