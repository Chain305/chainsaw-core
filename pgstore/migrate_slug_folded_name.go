package pgstore

import (
	"fmt"
	"log/slog"
)

// SlugFoldedNameExpr folds package_slugs.package_name the way the publish
// gate compares names (canonicalPackageName in the proxy's publish gate):
// PEP 503 for pip; case for NuGet, Composer, Swift and CocoaPods; case and
// _ = - for Cargo; a bare Docker image is library/<image>; every other
// format is exact.
const SlugFoldedNameExpr = `(CASE format
	WHEN 'pip' THEN lower(regexp_replace(btrim(package_name), '[-_.]+', '-', 'g'))
	WHEN 'nuget' THEN lower(package_name)
	WHEN 'composer' THEN lower(package_name)
	WHEN 'swift' THEN lower(package_name)
	WHEN 'cocoapods' THEN lower(package_name)
	WHEN 'cargo' THEN replace(lower(package_name), '_', '-')
	WHEN 'docker' THEN CASE WHEN strpos(package_name, '/') > 0 THEN lower(package_name) ELSE 'library/' || lower(package_name) END
	ELSE package_name END)`

// ensureSlugFoldedNameIndex makes one claim per folded name in a
// repository: without it two concurrent first publishes of `Acme_Foo` and
// `acme-foo` each claimed a slug, and one version could exist twice with
// different bytes (artifact-repo gap, REVIEW_PUBLISH #8). Deleted slugs
// count; RELEASED slugs do not, so a released name can be claimed again
// under any spelling (matches uq_package_slugs_unreleased_name). An earlier
// non-partial build of this index (idx_package_slugs_folded_name) is
// replaced.
//
// A database that already holds two spellings of one name cannot take the
// index. That must not stop the proxy booting: the duplicates are counted
// and logged, the index is skipped, and the next boot tries again once an
// operator has merged them.
func (s *Store) ensureSlugFoldedNameIndex() error {
	dups, err := s.slugFoldedNameDuplicates()
	if err != nil {
		return err
	}
	if dups == 0 {
		_, err = s.migExec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_package_slugs_folded_name_live ON package_slugs (org_id, repository, ` + SlugFoldedNameExpr + `) WHERE released_at IS NULL`)
		if err == nil {
			_, err = s.migExec(`DROP INDEX IF EXISTS idx_package_slugs_folded_name`)
			return err
		}
		// A duplicate written since the count (a publish on another
		// replica) fails the build; anything else is a real error.
		if dups, _ = s.slugFoldedNameDuplicates(); dups == 0 {
			return fmt.Errorf("create idx_package_slugs_folded_name_live: %w", err)
		}
	}
	slog.Warn("pgstore: package_slugs holds more than one spelling of a folded name; the folded-name unique index is NOT created until they are merged",
		"duplicate_groups", dups)
	return nil
}

func (s *Store) slugFoldedNameDuplicates() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM (SELECT 1 FROM package_slugs WHERE released_at IS NULL GROUP BY org_id, repository, ` +
		SlugFoldedNameExpr + ` HAVING count(*) > 1) d`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count folded package_slugs duplicates: %w", err)
	}
	return n, nil
}
