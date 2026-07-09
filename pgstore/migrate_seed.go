package pgstore

import (
	"database/sql"
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

// seedPricingPlans inserts the three advertised tiers (Free / Pro / Enterprise)
// if they do not already exist. Idempotent — safe to run on every startup.
// Byte limits use IEC units (1 GiB = 1024^3) to match the usage rollup math.
// A limit of 0 means "unlimited" (see checkUsageQuota in usage_rollup.go).
func (s *Store) seedPricingPlans() error {
	type plan struct {
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
		features               string
		paddlePriceMonthly     string
		paddlePriceAnnual      string
	}
	plans := []plan{
		{
			id:             "free",
			name:           "Free",
			description:    "Get started with dependency policy enforcement at no cost.",
			storageBytes:   500 * 1024 * 1024,      // 500 MiB
			bandwidthBytes: 1 * 1024 * 1024 * 1024, // 1 GiB
			maxMembers:     3,
			basePriceCents: 0,
			isDefault:      1,
			features:       `{}`,
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
			// Billy (AI assistant), SSO (SAML/OIDC), and SCIM provisioning are
			// available on Pro and Enterprise. The `sso` flag gates both SSO and
			// SCIM (see billingapi/plan_features.go). SSO lives on the first paid
			// tier deliberately — no SSO tax for a security product.
			features:           `{"sso":true,"billy":true}`,
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
			// on top of everything in Pro. SSO/SCIM are no longer gated here —
			// they moved to Pro (see the pro plan's `sso` flag above).
			features:           `{"integrations_external":true,"onprem":true,"sso":true,"billy":true}`,
			paddlePriceMonthly: strings.TrimSpace(os.Getenv("PADDLE_PRICE_UNLIMITED_MONTHLY")),
			paddlePriceAnnual:  strings.TrimSpace(os.Getenv("PADDLE_PRICE_UNLIMITED_ANNUAL")),
		},
	}
	for _, p := range plans {
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

		_, err := s.db.Exec(`
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
			p.maxMembers, p.features,
			paddleMonthly, paddleAnnual)
		if err != nil {
			return fmt.Errorf("upsert plan %s: %w", p.id, err)
		}
	}
	return nil
}
