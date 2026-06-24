package pgstore

import "fmt"

func (s *Store) ensurePackageRegistryColumns() error {
	// Internal package registry column on index_entries.
	if err := s.addColumnIfMissing("index_entries", "internal", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}

	// Supply chain integrity columns on package_metadata.
	if err := s.addColumnIfMissing("package_metadata", "provenance_status", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "trust_score", "INTEGER"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "trust_score_breakdown", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "typosquat_status", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "typosquat_similar_to", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "malware_status", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "malware_id", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "checksum_verified", "INTEGER DEFAULT 0"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "source_repo", "TEXT"); err != nil {
		return err
	}

	// Foundation migration (chainsaw-fnd): additive, nullable columns shared
	// across the 12 supply-chain feature PRs. Lazy backfill — every column
	// stays NULL until the feature PR that populates it lands. Zero-downtime
	// upgrade, no data migration required.
	if err := s.addColumnIfMissing("package_metadata", "publisher_set", "JSONB"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "install_script_kind", "TEXT"); err != nil {
		return err
	}
	if err := s.addConstraintIfMissing("package_metadata", "chk_package_metadata_install_script_kind",
		"CHECK (install_script_kind IS NULL OR install_script_kind IN ('none','present','fetches_remote','eval_encoded'))"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "hidden_unicode_hits", "INTEGER"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "publish_velocity_24h", "INTEGER"); err != nil {
		return err
	}
	// yanked: per-version-snapshot truthy state mirroring Report.Release.Yanked.
	// Filtered out of PublishCountByPublishers so post-incident yank-and-republish
	// recovery operations don't trip the >20/24h velocity threshold.
	//
	// No backfill: existing rows default to FALSE. Any pre-migration row that was
	// actually yanked will be silently misclassified as live until it next ages
	// out of the 24h sliding window — which is fast enough that a separate
	// backfill from package_versions.yanked isn't worth the cross-table sync.
	if err := s.addColumnIfMissing("package_metadata", "yanked", "BOOLEAN NOT NULL DEFAULT FALSE"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "version_anomaly_flags", "TEXT[]"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "checksum_declared", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "checksum_actual", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "repo_link_status", "TEXT"); err != nil {
		return err
	}
	if err := s.addConstraintIfMissing("package_metadata", "chk_package_metadata_repo_link_status",
		"CHECK (repo_link_status IS NULL OR repo_link_status IN ('unknown','ok','archived','missing','ownership_mismatch'))"); err != nil {
		return err
	}
	// PR 11: TTL column powering the weekly re-check cadence for the repo
	// liveness enricher. NULL means never checked; the enricher reads this
	// alongside repo_link_status and skips recheck when it's within the
	// configured cadence (default 7 days).
	if err := s.addColumnIfMissing("package_metadata", "repo_link_last_checked_at", "TIMESTAMPTZ"); err != nil {
		return err
	}
	// SLSA-substrate columns (Phase 5): cached on package_metadata so the
	// pipeline's existing pkgMeta lookup hydrates the EvaluationContext
	// without an extra round-trip per request. The dedicated `attestations`
	// table remains the canonical store of full bundles + history; these
	// are the denormalised projections the policy evaluator reads.
	if err := s.addColumnIfMissing("package_metadata", "slsa_level", "SMALLINT NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "attestation_builder_id", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "attestation_issuer", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "attestation_source_repo", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "attestation_transparency_log", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("package_metadata", "attestation_cache_stale", "BOOLEAN NOT NULL DEFAULT FALSE"); err != nil {
		return err
	}
	// GIN index on publisher_set supports the publisherChanged condition
	// lookups (PR 2) and publishVelocityAnomaly counts (PR 9). Gated on the
	// column's existence so the index is created idempotently alongside
	// the column.
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_package_metadata_publisher_set ON package_metadata USING GIN (publisher_set)`); err != nil {
		return fmt.Errorf("create package_metadata publisher_set index: %w", err)
	}
	// Powers the scheduled intelligence refresher's stalest-first keyset
	// walk (internal/intelligence/refresher.go). Without this, a full-
	// table scan orders by PRIMARY KEY and skews toward historical rows
	// while recent activity goes unrefreshed.
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_package_metadata_org_updated_at ON package_metadata(org_id, updated_at)`); err != nil {
		return fmt.Errorf("create package_metadata org_updated_at index: %w", err)
	}

	if err := s.addColumnIfMissing("vulnerability_metadata", "scanner_db_digest", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("vulnerability_metadata", "cve_details", "JSONB"); err != nil {
		return err
	}

	// Popular packages table for typosquat detection index.
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS popular_packages (
		ecosystem TEXT NOT NULL,
		name TEXT NOT NULL,
		rank INTEGER NOT NULL DEFAULT 0,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		PRIMARY KEY (ecosystem, name)
	)`); err != nil {
		return fmt.Errorf("create popular_packages table: %w", err)
	}
	return nil
}
