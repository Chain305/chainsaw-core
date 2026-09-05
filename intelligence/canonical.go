package intelligence

// Canonical report identity (Phase 9 Fresh, A4).
//
// A report row is keyed on (ecosystem, package_name, version) as the caller
// typed them. For the ecosystems whose registries FOLD names, that made one
// project several rows: `REQUESTS`, `Requests` and `requests` are one
// project on PyPI, but three identities here. Only one of them carried the
// sticky supply-chain facts an earlier proxy pull had written, so a CI gate
// keyed on those facts (`scan --path` on a requirements file, `intel scan
// --lockfile`) could be walked past by changing the case in the manifest —
// same installed bytes, different row, no publisher-changed signal.
//
// The fold is applied where a HUMAN-TYPED coordinate enters, never inside
// Scan. Scan is what the proxy calls, and the proxy already writes the
// registry's own spelling; folding there would re-key every proxy row.
//
// WHAT IS DELIBERATELY NOT FOLDED, and why the controls in the test matter:
//
//   - npm is case-preserving. Its registry serves `JSONStream` and
//     `jsonstream` as different documents, OSV keeps npm case
//     (osv/bundle.go lowercases pypi, nuget and packagist only), runNPM
//     sends the raw name, and the proxy resolver does too. Lowercasing npm
//     here would SPLIT the intel row from the proxy's row for the same
//     bytes — the opposite of the defect being fixed.
//   - go module paths are case-significant by specification, and the
//     proxy's `!x` escaping decodes to the canonical mixed case.
//   - rubygems 404s `RAILS`; cargo and maven likewise keep their case.
//   - The ECOSYSTEM string IS folded, but only onto the spelling the proxy
//     already writes, and only for aliases the proxy never writes itself.
//     `pypi` -> `pip` merges the lockfile scanner's row onto the proxy's
//     with no proxy change; `bun`/`yarn`/`gradle` are excluded because
//     those ARE proxy-written spellings and folding them would move a
//     lookup off the proxy's row. See canonicalEcosystemAliases.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/chain305/chainsaw-core/typosquat"
)

// canonicalPEP503Ecosystems fold under PEP 503: case-fold, then collapse
// any run of `-`, `_` and `.` to a single `-`. `pip` is the proxy's
// spelling of `pypi` and folds the same way.
//
// Both spellings are kept even though canonicalEcosystem now folds `pypi`
// to `pip` before the name rule is chosen: nonCanonicalPredicate matches
// these lists against the RAW `ecosystem` column, which still holds `pypi`
// rows written before the fold existed.
var canonicalPEP503Ecosystems = []string{"pypi", "pip"}

// canonicalLowercaseEcosystems fold on case alone. These are exactly the
// non-pypi ecosystems osv/bundle.go lowercases, plus composer's registry
// (Packagist) under the name this product uses for it.
var canonicalLowercaseEcosystems = []string{"nuget", "composer", "packagist"}

// canonicalEcosystemAliases maps an ALIAS spelling of a registry onto the
// spelling the PROXY writes for it. This is the ecosystem half of
// BUG-F-007 and the direction is the whole safety argument:
//
// The proxy keys its rows on `string(repository.Format)` — `pip`, `cargo`,
// `composer`, `rubygems`, `go` — with no folding at all. `/api/scan`
// already folds onto the same spellings via policy.EcosystemForFormat
// (EcoPyPI is the string "pip"). What did NOT fold were
// `intel scan --lockfile` (internal/scan LangToEcosystem returns `pypi`)
// and the raw `/api/v1/intel/packages/{eco}/…` path segment plus the MCP
// tool, which pass whatever the caller typed — `pypi`, `PyPI`, `gomod`.
// Those are separate rows from the proxy's, so proxy-written sticky facts
// never reach the row the CI gate reads.
//
// Folding those aliases onto the proxy's spelling MERGES the identities
// without touching a single proxy write. Folding the other way would
// re-key every proxy row, which needs a production flip count first.
//
// WHAT IS DELIBERATELY ABSENT, and why the guard test matters:
// `bun` and `yarn` (→ npm) and `gradle` (→ maven) are alias pairs in
// policy.EcosystemForFormat and in malware.NormalizeEcosystem, but for
// those three the ALIAS is what the proxy writes: a format:bun repository
// keys on `bun`, a format:gradle one on `gradle`. Folding them here would
// move a human-typed lookup OFF the proxy's row — this defect in reverse.
// Converging those pairs is a proxy-side re-key, not a fold.
// TestCanonicalKeyNeverFoldsAProxyWrittenEcosystem holds the line.
var canonicalEcosystemAliases = map[string]string{
	// PyPI: proxy `pip`; malware.NormalizeEcosystem("PyPI") == "pip";
	// policy.EcoPyPI == "pip"; provider whitelists carry both spellings.
	"pypi":   "pip",
	"python": "pip",
	// crates.io: proxy `cargo`; osv/bundle.go:348 and provider_osv.go:163
	// accept cargo/crates/crates.io.
	"crates.io": "cargo",
	"crates-io": "cargo",
	"crates":    "cargo",
	// Packagist: proxy `composer`; malware.NormalizeEcosystem folds it.
	"packagist": "composer",
	// RubyGems: proxy `rubygems`; provider_osv.go:164 and
	// provider_reservedns.go:171 accept `gem`.
	"gem": "rubygems",
	// Go: internal/formats/gomod/resolver.go Format() returns "go";
	// `gomod` and `golang` are accepted elsewhere (provider_osv.go:167,
	// provider_transitiverisk.go:634).
	"gomod":  "go",
	"golang": "go",
	// Swift: OSV publishes the ecosystem as "SwiftURL" (malware/osv.go:106).
	"swifturl": "swift",
}

// CanonicalNameRuleSpec is this package's fold, exported so the SQL side of
// the cleanup selects exactly the population CanonicalKey would rewrite.
// One definition, no second hand-maintained list to drift.
type CanonicalNameRuleSpec struct {
	// PEP503Ecosystems fold under PEP 503 (case + separator runs).
	PEP503Ecosystems []string
	// LowercaseEcosystems fold on case alone.
	LowercaseEcosystems []string
	// EcosystemAliases maps an alias ecosystem spelling onto the spelling
	// the proxy writes. Keys are already lower-cased and trimmed.
	EcosystemAliases map[string]string
}

// CanonicalNameRule returns the fold definition. The slices are copied so a
// caller cannot mutate the package-level lists through the returned value —
// a drifting list here would widen a DELETE on a shared, org-less table.
func CanonicalNameRule() CanonicalNameRuleSpec {
	aliases := make(map[string]string, len(canonicalEcosystemAliases))
	for k, v := range canonicalEcosystemAliases {
		aliases[k] = v
	}
	return CanonicalNameRuleSpec{
		PEP503Ecosystems:    append([]string(nil), canonicalPEP503Ecosystems...),
		LowercaseEcosystems: append([]string(nil), canonicalLowercaseEcosystems...),
		EcosystemAliases:    aliases,
	}
}

func matchesEcosystem(list []string, ecosystem string) bool {
	e := strings.ToLower(strings.TrimSpace(ecosystem))
	for _, want := range list {
		if e == want {
			return true
		}
	}
	return false
}

// canonicalEcosystem folds an ecosystem spelling onto the one the proxy
// writes. Unknown ecosystems are lower-cased and trimmed only — that alone
// is convergent, because every proxy-written spelling is already lower-case
// (repository.Format) while a URL path segment or an MCP argument can carry
// any casing.
func canonicalEcosystem(ecosystem string) string {
	e := strings.ToLower(strings.TrimSpace(ecosystem))
	if canon, ok := canonicalEcosystemAliases[e]; ok {
		return canon
	}
	return e
}

// canonicalPackageName returns the folded form of a package name for its
// ecosystem, or the name unchanged when the ecosystem does not fold.
func canonicalPackageName(ecosystem, pkg string) string {
	trimmed := strings.TrimSpace(pkg)
	switch {
	case matchesEcosystem(canonicalPEP503Ecosystems, ecosystem):
		// typosquat.NormalizePyPI is the same PEP 503 implementation the
		// typosquat detector keys on; sharing it keeps the two views of
		// "the same project" from diverging.
		return typosquat.NormalizePyPI(trimmed)
	case matchesEcosystem(canonicalLowercaseEcosystems, ecosystem):
		return strings.ToLower(trimmed)
	default:
		return pkg
	}
}

// CanonicalKey folds a key onto one identity: the ECOSYSTEM onto the
// spelling the proxy writes, and then the PACKAGE NAME for the ecosystems
// whose registries fold it. Version is returned untouched.
//
// The ecosystem is folded FIRST so the name rule is chosen by the canonical
// ecosystem rather than by whichever alias the caller typed.
//
// Idempotent: CanonicalKey(CanonicalKey(k)) == CanonicalKey(k).
func CanonicalKey(k Key) Key {
	k.Ecosystem = canonicalEcosystem(k.Ecosystem)
	k.Package = canonicalPackageName(k.Ecosystem, k.Package)
	return k
}

// ---------------------------------------------------------------------------
// Cleanup of rows written before the fold existed.
//
// OPT-IN, operator-triggered, dry run first — the same shape and for the
// same reason as PurgeLatestSentinelCoordinates: this mutates a shared,
// org-less cache table, so it never runs at boot or on a refresh tick.
// ---------------------------------------------------------------------------

// CanonicalCleanupResult is the outcome of one cleanup pass.
type CanonicalCleanupResult struct {
	// Scanned is how many candidate rows were considered.
	Scanned int
	// Renamed is rows moved to their canonical key in place, because no
	// canonical sibling existed. Nothing is merged or deleted.
	Renamed int
	// Merged is rows whose sticky facts were written onto an existing
	// canonical sibling before the non-canonical row was removed.
	Merged int
	// Retained is rows deliberately left alone: a malicious verdict the
	// canonical sibling cannot inherit (see below).
	Retained int
	// Skipped is candidates CanonicalKey does not actually fold, or that
	// vanished between the listing and the read.
	Skipped int
	// Errors are per-row failures; the pass continues past them.
	Errors []string
}

// canonicalCleanupBackend is the storage surface the cleanup needs. It is
// an interface so the ordering property below can be tested without a
// database.
type canonicalCleanupBackend interface {
	ListNonCanonicalKeys(ctx context.Context, limit int) ([]Key, error)
	Get(ctx context.Context, k Key) (*Report, error)
	Author(ctx context.Context, k Key) (string, error)
	Upsert(ctx context.Context, orgID string, r *Report) error
	Rename(ctx context.Context, from, to Key) (bool, error)
	Delete(ctx context.Context, k Key) (bool, error)
}

// canonicaliseReportNames folds every listed non-canonical row onto its
// canonical key.
//
// THE ORDERING IS THE SAFETY PROPERTY. Sticky facts are read by EXACT key,
// so a non-canonical row can hold a fact — a publisher change, a repo-link
// status, a typosquat verdict — that its canonical sibling has never seen.
// Deleting first would retract that fact for every tenant at once, on a
// table with no org_id. So the merge write lands BEFORE the delete, and if
// the write fails the row is left exactly where it was.
//
// The malicious case cannot be merged at all: applyStickySupplyChain fills
// only SILENT fields, so a canonical row already carrying MalwareStatus
// "clean" would not take the malicious verdict, and deleting the row that
// holds it would drop a block. Those rows are retained and reported.
func canonicaliseReportNames(ctx context.Context, be canonicalCleanupBackend, limit int) (CanonicalCleanupResult, error) {
	var res CanonicalCleanupResult
	if be == nil {
		return res, nil
	}
	candidates, err := be.ListNonCanonicalKeys(ctx, limit)
	if err != nil {
		return res, fmt.Errorf("list non-canonical report keys: %w", err)
	}

	for _, typed := range candidates {
		res.Scanned++
		canon := CanonicalKey(typed)
		if canon == typed {
			// The SQL predicate is advisory: anything the Go rule does not
			// fold is never touched, so a predicate that drifts wider than
			// this rule still cannot rename or delete a row.
			res.Skipped++
			continue
		}

		canonRep, err := be.Get(ctx, canon)
		switch {
		case err == nil:
			// fall through to the merge path below
		case isNotFound(err):
			moved, rerr := be.Rename(ctx, typed, canon)
			if rerr != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("rename %s: %v", keyLabel(typed), rerr))
				continue
			}
			if !moved {
				// A canonical sibling appeared between the read and the
				// rename, or the row vanished. Leave it for the next pass
				// rather than guessing.
				res.Retained++
				continue
			}
			res.Renamed++
			continue
		default:
			res.Errors = append(res.Errors, fmt.Sprintf("read canonical %s: %v", keyLabel(canon), err))
			continue
		}

		typedRep, err := be.Get(ctx, typed)
		if err != nil {
			if isNotFound(err) {
				res.Skipped++
				continue
			}
			res.Errors = append(res.Errors, fmt.Sprintf("read %s: %v", keyLabel(typed), err))
			continue
		}

		if typedRep.SupplyChain.MalwareStatus == "malicious" &&
			canonRep.SupplyChain.MalwareStatus != "malicious" {
			res.Retained++
			continue
		}

		applyStickySupplyChain(canonRep, typedRep)

		// Attribute the merge write to the canonical row's own author, not
		// to an empty org: Upsert records authored_by_org, and a blank one
		// would rewrite the provenance of a row this pass only touched up.
		author, err := be.Author(ctx, canon)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("read author %s: %v", keyLabel(canon), err))
			continue
		}
		if err := be.Upsert(ctx, author, canonRep); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("merge into %s: %v", keyLabel(canon), err))
			continue
		}
		if _, err := be.Delete(ctx, typed); err != nil {
			// The facts are already safe on the canonical row; the leftover
			// duplicate is unreachable by Scan and the next pass removes it.
			res.Errors = append(res.Errors, fmt.Sprintf("delete %s after merge: %v", keyLabel(typed), err))
			continue
		}
		res.Merged++
	}
	return res, nil
}

func isNotFound(err error) bool {
	return err == ErrNotFound || strings.Contains(strings.ToLower(err.Error()), "not found")
}

func keyLabel(k Key) string {
	return k.Ecosystem + "/" + k.Package + "@" + k.Version
}

// storeCanonicalBackend adapts *Store to canonicalCleanupBackend.
type storeCanonicalBackend struct{ s *Store }

func (b storeCanonicalBackend) ListNonCanonicalKeys(ctx context.Context, limit int) ([]Key, error) {
	return b.s.listNonCanonicalKeys(ctx, limit)
}

func (b storeCanonicalBackend) Get(ctx context.Context, k Key) (*Report, error) {
	return b.s.Get(ctx, "", k)
}

func (b storeCanonicalBackend) Author(ctx context.Context, k Key) (string, error) {
	return b.s.reportAuthorOrg(ctx, k)
}

func (b storeCanonicalBackend) Upsert(ctx context.Context, orgID string, r *Report) error {
	return b.s.Upsert(ctx, orgID, r)
}

func (b storeCanonicalBackend) Rename(ctx context.Context, from, to Key) (bool, error) {
	return b.s.renameReportKey(ctx, from, to)
}

func (b storeCanonicalBackend) Delete(ctx context.Context, k Key) (bool, error) {
	return b.s.deleteReportKey(ctx, k)
}

// nonCanonicalPredicate builds the WHERE fragment selecting rows whose
// package_name OR ecosystem differs from the fold this package would apply.
// Derived from CanonicalNameRule() so it cannot drift from CanonicalKey.
//
// Both dimensions are listed, not just the name: the `pypi` population the
// ecosystem fold exists to merge can carry an already-canonical name (a
// lockfile's `requests` under `pypi`), so a name-only predicate would list
// none of it and the cleanup would silently do nothing.
//
// An empty rule yields FALSE — an under-populated rule touches nothing,
// which is the safe direction for a fragment that drives a DELETE.
func nonCanonicalPredicate(rule CanonicalNameRuleSpec) (string, []any) {
	var clauses []string
	var args []any
	mark := func(v string) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	addName := func(ecos []string, folded string) {
		if len(ecos) == 0 {
			return
		}
		marks := make([]string, 0, len(ecos))
		for _, e := range ecos {
			marks = append(marks, mark(e))
		}
		clauses = append(clauses, fmt.Sprintf(
			"(lower(btrim(ecosystem)) IN (%s) AND package_name <> %s)",
			strings.Join(marks, ", "), folded))
	}
	addName(rule.PEP503Ecosystems, "lower(regexp_replace(btrim(package_name), '[-_.]+', '-', 'g'))")
	addName(rule.LowercaseEcosystems, "lower(btrim(package_name))")

	// Ecosystem dimension. Sorted so the fragment (and therefore the query
	// plan cache and any operator diff of it) is stable across runs — Go
	// map iteration order is not.
	if len(rule.EcosystemAliases) > 0 {
		aliases := make([]string, 0, len(rule.EcosystemAliases))
		for alias := range rule.EcosystemAliases {
			aliases = append(aliases, alias)
		}
		sort.Strings(aliases)
		marks := make([]string, 0, len(aliases))
		for _, a := range aliases {
			marks = append(marks, mark(a))
		}
		clauses = append(clauses, fmt.Sprintf(
			"(lower(btrim(ecosystem)) IN (%s))", strings.Join(marks, ", ")))
		// Case / whitespace drift on an ecosystem that is NOT an alias:
		// `PyPI` is caught by the IN above, `NuGet` only by this.
		clauses = append(clauses, "(ecosystem <> lower(btrim(ecosystem)))")
	}

	if len(clauses) == 0 {
		return "FALSE", nil
	}
	return "(" + strings.Join(clauses, " OR ") + ")", args
}

// CanonicalNameCleanupCounts is the read-only dry run: how many rows would
// be folded, bucketed by their CURRENT ecosystem spelling. Run it
// immediately before the cleanup.
//
// The buckets are the flip count the plan asks for: a large `pypi` bucket
// is the lockfile-written population that will move onto the proxy's `pip`
// rows. It counts candidates, not outcomes — the pass itself reports the
// rename / merge / retain split, and a retained row stays put.
func (s *Store) CanonicalNameCleanupCounts(ctx context.Context) (map[string]int, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return nil, nil
	}
	pred, args := nonCanonicalPredicate(CanonicalNameRule())
	rows, err := s.sql.DB().QueryContext(ctx, `
		SELECT ecosystem, count(*) FROM intelligence_reports
		WHERE `+pred+`
		GROUP BY 1 ORDER BY 2 DESC, 1`, args...)
	if err != nil {
		return nil, fmt.Errorf("count non-canonical report names: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var eco string
		var n int
		if err := rows.Scan(&eco, &n); err != nil {
			return nil, fmt.Errorf("scan non-canonical count: %w", err)
		}
		out[eco] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate non-canonical counts: %w", err)
	}
	return out, nil
}

// CanonicaliseReportNames folds pre-fix rows onto their canonical key.
//
// OPT-IN. Not wired into Open(), bootstrap or any refresh tick — call it
// from an operator-triggered path after reading
// CanonicalNameCleanupCounts. limit <= 0 means no limit.
func (s *Store) CanonicaliseReportNames(ctx context.Context, limit int) (CanonicalCleanupResult, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return CanonicalCleanupResult{}, nil
	}
	return canonicaliseReportNames(ctx, storeCanonicalBackend{s: s}, limit)
}

func (s *Store) listNonCanonicalKeys(ctx context.Context, limit int) ([]Key, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return nil, nil
	}
	pred, args := nonCanonicalPredicate(CanonicalNameRule())
	q := `SELECT ecosystem, package_name, version FROM intelligence_reports
	       WHERE ` + pred + ` ORDER BY ecosystem, package_name, version`
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := s.sql.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list non-canonical report keys: %w", err)
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		var k Key
		if err := rows.Scan(&k.Ecosystem, &k.Package, &k.Version); err != nil {
			return nil, fmt.Errorf("scan non-canonical key: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) reportAuthorOrg(ctx context.Context, k Key) (string, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return "", nil
	}
	var org string
	err := s.sql.DB().QueryRowContext(ctx, `
		SELECT COALESCE(authored_by_org, '') FROM intelligence_reports
		WHERE ecosystem=$1 AND package_name=$2 AND version=$3
	`, k.Ecosystem, k.Package, k.Version).Scan(&org)
	if err != nil {
		return "", nil // absent or column-less: fall back to an empty author
	}
	return org, nil
}

func (s *Store) renameReportKey(ctx context.Context, from, to Key) (bool, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return false, nil
	}
	// Both key columns move: the fold rewrites the ecosystem as well as the
	// name, so a `pypi` row with an already-canonical name still has to
	// travel to `pip`.
	//
	// ON CONFLICT DO NOTHING semantics via a guarded UPDATE: if a canonical
	// row appeared since the listing, the rename is a no-op and the caller
	// leaves the row for the next pass rather than clobbering the sibling.
	// The guard reads the DESTINATION key, not the source.
	res, err := s.sql.DB().ExecContext(ctx, `
		UPDATE intelligence_reports SET ecosystem=$1, package_name=$2
		WHERE ecosystem=$3 AND package_name=$4 AND version=$5
		  AND NOT EXISTS (
		      SELECT 1 FROM intelligence_reports c
		      WHERE c.ecosystem=$1 AND c.package_name=$2 AND c.version=$5)
	`, to.Ecosystem, to.Package, from.Ecosystem, from.Package, from.Version)
	if err != nil {
		return false, fmt.Errorf("rename report key: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *Store) deleteReportKey(ctx context.Context, k Key) (bool, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return false, nil
	}
	res, err := s.sql.DB().ExecContext(ctx, `
		DELETE FROM intelligence_reports
		WHERE ecosystem=$1 AND package_name=$2 AND version=$3
	`, k.Ecosystem, k.Package, k.Version)
	if err != nil {
		return false, fmt.Errorf("delete report key: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
