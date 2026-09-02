package pgstore

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/tenancy"
)

func (s *Store) ensureDefaultOrg() error {
	if s == nil || s.db == nil {
		return nil
	}
	_, err := s.db.Exec(`INSERT INTO orgs(id, name, slug, created_at, updated_at)
		VALUES(?,?,?,?,?) ON CONFLICT(id) DO NOTHING`,
		tenancy.DefaultOrgID, tenancy.DefaultOrgName, tenancy.DefaultOrgSlug, currentTimestamp(), currentTimestamp())
	if err != nil {
		return fmt.Errorf("ensure default org: %w", err)
	}
	return nil
}

// backfillDefaultPlanAssignment ensures every existing org has a row in
// org_plan_assignments. Without it the plan-feature gate (and billing page)
// has to fall back to an implicit default which can surprise admins on
// rollout. Explicit assignment makes the org's tier visible in the admin
// panel and means feature gates behave deterministically.
func (s *Store) backfillDefaultPlanAssignment() error {
	// Resolve the default plan (Free) so we stamp a consistent value.
	var defaultPlanID string
	if err := s.db.QueryRow(`SELECT id FROM pricing_plans WHERE is_default = 1 LIMIT 1`).Scan(&defaultPlanID); err != nil {
		// No default plan means seedPricingPlans hasn't run yet (or the
		// schema is stale). Leave existing rows alone — they'll be
		// backfilled on next successful startup.
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}
	now := time.Now().UTC()
	_, err := s.db.Exec(`
		INSERT INTO org_plan_assignments (org_id, plan_id, billing_period_start, billing_period_end, assigned_at)
		SELECT o.id, ?, ?, ?, ?
		FROM orgs o
		WHERE o.deleted_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM org_plan_assignments a WHERE a.org_id = o.id)
	`, defaultPlanID, now, now.Add(30*24*time.Hour), now)
	return err
}

// bundledFeatureDerivations maps a "parent" plan feature to the features that
// are bundled with it and must be granted wherever the parent is granted.
//
// `sso` → `scim`: founder ruling — SSO and SCIM travel together, so any plan
// that includes SSO also includes SCIM provisioning. SCIM is gated on its own
// `scim` key (internal/server/authapi/scim.go) rather than borrowing `sso`, so
// a denial names the feature the caller actually hit and the two can be
// reasoned about separately. Deriving the grant here — rather than repeating
// `"scim": true` in each plan literal — is what stops them drifting apart when
// someone edits one plan and forgets the other.
//
// TestSeededPlansGrantSCIMWhereverSSO pins the invariant.
var bundledFeatureDerivations = map[string][]string{
	"sso": {"scim"},
}

// deriveBundledFeatures grants every bundled child feature whose parent the
// plan already grants. It only ever adds grants: a plan without the parent is
// left untouched, so Free stays Free.
func deriveBundledFeatures(features map[string]bool) map[string]bool {
	derived := make(map[string]bool, len(features)+len(bundledFeatureDerivations))
	for k, v := range features {
		derived[k] = v
	}
	for parent, children := range bundledFeatureDerivations {
		if !derived[parent] {
			continue
		}
		for _, child := range children {
			derived[child] = true
		}
	}
	return derived
}

type pricingPlanSeed struct {
	id                     string
	name                   string
	description            string
	storageBytes           int64
	bandwidthBytes         int64
	maxMembers             int
	basePriceCents         int64
	priceStorageCentsPerGB int64
	priceBwCentsPerGB      int64
	isDefault              int
	features               map[string]bool
	paddlePriceMonthly     string
	paddlePriceAnnual      string
}

// pricingPlanSeeds is the code-owned definition of the three advertised tiers.
// Split out of seedPricingPlans so tests can assert on the exact values that
// ship without needing a live database — in particular the SSO/SCIM bundling
// invariant (TestSeededPlansGrantSCIMWhereverSSO).
//
// Note these are the RAW grants: `scim` is absent here on purpose and is added
// by deriveBundledFeatures at write time. Assert on the derived value, not on
// these literals, when you care about what an org actually gets.
func pricingPlanSeeds() []pricingPlanSeed {
	return []pricingPlanSeed{
		{
			id:             "free",
			name:           "Free",
			description:    "Get started with dependency policy enforcement at no cost.",
			storageBytes:   500 * 1024 * 1024,      // 500 MiB
			bandwidthBytes: 1 * 1024 * 1024 * 1024, // 1 GiB
			maxMembers:     3,
			basePriceCents: 0,
			isDefault:      1,
			features:       map[string]bool{},
		},
		{
			id:                     "pro",
			name:                   "Pro",
			description:            "For teams rolling Chainsaw into production pipelines.",
			storageBytes:           5 * 1024 * 1024 * 1024,  // 5 GiB
			bandwidthBytes:         25 * 1024 * 1024 * 1024, // 25 GiB
			maxMembers:             10,
			basePriceCents:         14900,
			priceStorageCentsPerGB: 150,
			priceBwCentsPerGB:      150,
			isDefault:              0,
			// Billy (AI assistant) and SSO (SAML/OIDC) are available on Pro and
			// Enterprise. SSO lives on the first paid tier deliberately — no SSO
			// tax for a security product. `scim` is NOT listed here: it is
			// derived from `sso` by deriveBundledFeatures below, because SSO and
			// SCIM travel together by founder ruling.
			features:           map[string]bool{"sso": true, "billy": true},
			paddlePriceMonthly: strings.TrimSpace(os.Getenv("PADDLE_PRICE_PRO_MONTHLY")),
			paddlePriceAnnual:  strings.TrimSpace(os.Getenv("PADDLE_PRICE_PRO_ANNUAL")),
		},
		{
			// id stays "unlimited" so Paddle env-var names, org_plan_assignments
			// rows, and analytics labels (start_unlimited) keep working. Only the
			// display name becomes "Enterprise".
			id:             "unlimited",
			name:           "Enterprise",
			description:    "Unlimited capacity plus enterprise integrations, on-prem eligibility, and SLAs.",
			storageBytes:   0,
			bandwidthBytes: 0,
			maxMembers:     0,
			basePriceCents: 119900,
			isDefault:      0,
			// Enterprise adds external integrations (SIEM, ticketing) and on-prem
			// on top of everything in Pro. SSO/SCIM are no longer exclusive here
			// — they moved to Pro (see the pro plan's `sso` flag above). `scim`
			// is derived from `sso`, not listed.
			features:           map[string]bool{"integrations_external": true, "onprem": true, "sso": true, "billy": true},
			paddlePriceMonthly: strings.TrimSpace(os.Getenv("PADDLE_PRICE_UNLIMITED_MONTHLY")),
			paddlePriceAnnual:  strings.TrimSpace(os.Getenv("PADDLE_PRICE_UNLIMITED_ANNUAL")),
		},
	}
}

// seedPricingPlans inserts the three advertised tiers (Free / Pro / Enterprise)
// if they do not already exist. Idempotent — safe to run on every startup.
// Byte limits use IEC units (1 GiB = 1024^3) to match the usage rollup math.
// A limit of 0 means "unlimited" (see checkUsageQuota in usage_rollup.go).
func (s *Store) seedPricingPlans() error {
	for _, p := range pricingPlanSeeds() {
		// DO UPDATE keeps the plan definitions (prices, limits, feature
		// flags) in sync with code on every startup. Plans are code-owned,
		// not admin-editable, so refreshing is safe and prevents drift
		// between a running DB and the source of truth.
		// Paddle Price IDs: only overwrite the DB value when an env var is
		// set, so ops can also manage Price IDs directly in the DB if they
		// prefer (useful during a sandbox→production cutover where env vars
		// are swapped but DB state should roll forward).
		paddleMonthly := sql.NullString{String: p.paddlePriceMonthly, Valid: p.paddlePriceMonthly != ""}
		paddleAnnual := sql.NullString{String: p.paddlePriceAnnual, Valid: p.paddlePriceAnnual != ""}

		// Features are stored as a JSON object string. json.Marshal emits map
		// keys in sorted order, so the serialised value is stable across runs
		// and the ON CONFLICT DO UPDATE below is a genuine no-op when nothing
		// changed.
		featuresJSON, err := json.Marshal(deriveBundledFeatures(p.features))
		if err != nil {
			return fmt.Errorf("marshal features for plan %s: %w", p.id, err)
		}

		_, err = s.db.Exec(`
			INSERT INTO pricing_plans (
				id, name, description,
				storage_bytes_limit, bandwidth_bytes_limit,
				price_per_gb_storage_cents, price_per_gb_bandwidth_cents,
				base_price_cents, billing_period, is_default,
				max_members_per_org, features,
				paddle_price_id_monthly, paddle_price_id_annual
			) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				description = EXCLUDED.description,
				storage_bytes_limit = EXCLUDED.storage_bytes_limit,
				bandwidth_bytes_limit = EXCLUDED.bandwidth_bytes_limit,
				price_per_gb_storage_cents = EXCLUDED.price_per_gb_storage_cents,
				price_per_gb_bandwidth_cents = EXCLUDED.price_per_gb_bandwidth_cents,
				base_price_cents = EXCLUDED.base_price_cents,
				billing_period = EXCLUDED.billing_period,
				is_default = EXCLUDED.is_default,
				max_members_per_org = EXCLUDED.max_members_per_org,
				features = EXCLUDED.features,
				paddle_price_id_monthly = COALESCE(EXCLUDED.paddle_price_id_monthly, pricing_plans.paddle_price_id_monthly),
				paddle_price_id_annual = COALESCE(EXCLUDED.paddle_price_id_annual, pricing_plans.paddle_price_id_annual),
				updated_at = CURRENT_TIMESTAMP
		`, p.id, p.name, p.description,
			p.storageBytes, p.bandwidthBytes,
			p.priceStorageCentsPerGB, p.priceBwCentsPerGB,
			p.basePriceCents, "monthly", p.isDefault,
			p.maxMembers, string(featuresJSON),
			paddleMonthly, paddleAnnual)
		if err != nil {
			return fmt.Errorf("upsert plan %s: %w", p.id, err)
		}
	}
	return nil
}
