package storage

import (
	"context"
	"strings"

	"github.com/chain305/chainsaw-core/tenancy"
)

type orgContextKey struct{}

// WithOrg annotates a context with the org identifier for tenant-scoped storage paths.
func WithOrg(ctx context.Context, orgID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	orgID = tenancy.NormalizeOrgID(orgID)
	if strings.TrimSpace(orgID) == "" {
		return ctx
	}
	return context.WithValue(ctx, orgContextKey{}, orgID)
}

// OrgFromContext extracts the org identifier used for tenant-scoped storage.
func OrgFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	orgID, _ := ctx.Value(orgContextKey{}).(string)
	return strings.TrimSpace(orgID)
}
