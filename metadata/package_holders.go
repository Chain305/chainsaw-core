package metadata

// package_holders.go — "which orgs hold this coordinate".
//
// WHY IT EXISTS. `intelligence_reports` has exactly one row per coordinate and
// no `org_id` (the federation model, core/intelligence/personalize.go), so a
// refresh that discovers a new CVE or a new malware verdict knows WHAT changed
// and has no idea WHO to tell. `package_metadata` is the table that knows: its
// primary key is `(org_id, repository, package, version)`, so a coordinate N
// tenants pull is N rows. This is the lookup that turns one shared fact back
// into a per-tenant audience (defect C-7).
//
// WHY A NARROW TYPE RATHER THAN PackageMetadataRow. Exactly four fields reach
// an alert — DiffReports (core/intelligence/vuln_alert.go) and DiffSupplyChain
// (supplychain_alert.go) stamp OrgID, Repository, Package and Version onto the
// event and read nothing else off the row, and neither dispatcher in
// internal/server touches the row at all. Returning a 20-column
// PackageMetadataRow with four fields populated would be a half-filled struct
// inviting a later caller to read a field that is silently zero; returning the
// four that exist says what this query can actually answer.
//
// COST. `package_metadata` is indexed `(org_id, repository)` and
// `(org_id, internal_package)`, so a predicate on `(package, version)` with no
// org is a sequential scan. That is deliberate and currently cheap — the table
// holds the coordinates the PROXY has served (~2.2k in production) and this
// query runs only on a refresh that actually produced a diff, not per examined
// row. If package_metadata grows by an order of magnitude, the fix is a one
// line index on `(package, version)`; it is not added here because it is a
// migration and this is not yet the bottleneck.

import (
	"context"
	"fmt"
	"strings"
)

// PackageHolder is one org's claim on a coordinate: the org, and the proxy
// repository IT pulled through. Repository is per-org and must not be
// substituted across tenants — it becomes RepoName on the alert event, the
// RepoID on the finding and the Repository on the webhook payload, so handing
// org B the walker's repository would misattribute the finding.
type PackageHolder struct {
	OrgID      string
	Repository string
	Package    string
	Version    string
}

// PackageMetadataHolders returns every org's row for one (package, version),
// capped at limit and ordered deterministically.
//
// The ORDER is load-bearing because there is a cap: with a limit below the
// number of holders, the order decides whose alert is dropped, and a
// nondeterministic one would drop a different tenant each time. Ordered by
// (org_id, repository) so truncation is at least stable and auditable — the
// caller logs when it truncates.
//
// Returns rows for EVERY ecosystem. package_metadata stores a proxy repository
// name, not an ecosystem, and resolving one to the other needs the repository
// manager the refresher already holds (intelligence.EcosystemResolver). Doing
// it here would mean a second resolver that could disagree with the first, so
// the caller filters.
func (s *Store) PackageMetadataHolders(ctx context.Context, packageName, version string, limit int) ([]PackageHolder, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return nil, ErrUnavailable
	}
	packageName = strings.TrimSpace(packageName)
	version = strings.TrimSpace(version)
	if packageName == "" || version == "" {
		// Not an error: an empty coordinate has no holders. Returning nil
		// rather than scanning the table on a predicate that cannot match.
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.sql.DB().QueryContext(ctx, `
		SELECT org_id, repository, package, version
		FROM package_metadata
		WHERE package = $1 AND version = $2
		ORDER BY org_id ASC, repository ASC
		LIMIT $3
	`, packageName, version, limit)
	if err != nil {
		return nil, fmt.Errorf("metadata: package holders: %w", err)
	}
	defer rows.Close()

	out := make([]PackageHolder, 0, 8)
	for rows.Next() {
		var h PackageHolder
		if err := rows.Scan(&h.OrgID, &h.Repository, &h.Package, &h.Version); err != nil {
			return nil, fmt.Errorf("metadata: scan package holder: %w", err)
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("metadata: iterate package holders: %w", err)
	}
	return out, nil
}
