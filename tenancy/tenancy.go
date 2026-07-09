package tenancy

import "strings"

const (
	DefaultOrgID   = "org-default"
	DefaultOrgSlug = "default"
	DefaultOrgName = "Default Workspace"
)

const (
	RoleGlobalAdmin = "global-admin"
	RoleOrgAdmin    = "org-admin"
	RoleOwner       = "org-owner"
	RoleManager     = "org-manager"
	RoleMember      = "org-member"
)

const (
	PermOrgDelete        = "org:delete"
	PermOrgMembersRead   = "org:members:read"
	PermOrgMembersInvite = "org:members:invite"
	PermOrgMembersUpdate = "org:members:update_role"
	PermOrgMembersRemove = "org:members:remove"
	PermClientsCreate    = "clients:create"
	PermClientsManageAll = "clients:manage:all"
	PermClientsManageOwn = "clients:manage:own"
	PermReposRead        = "repos:read"
	PermReposManage      = "repos:manage"
	PermSettingsRead     = "settings:read"
	PermSettingsUpdate   = "settings:update"
	PermPoliciesRead     = "policies:read"
	PermPoliciesManage   = "policies:manage"
	PermExceptionsRead   = "exceptions:read"
	PermExceptionsManage = "exceptions:manage"
	PermMetricsRead      = "metrics:read"
	PermMetricsManage    = "metrics:manage"
	PermAuditRead        = "audit:read"
	// PermAuditWrite gates POST /api/dashboard/audit-events. Sole
	// production callsite as of W-W9 audit:
	// internal/server/dashboard.go:handleAuditEvents (one
	// requirePermission(PermAuditWrite) call). Granted to most roles
	// (global-admin / org-admin / org-owner / org-manager) so the
	// orphan-permission risk is high if the gate is ever silently
	// removed: the constant would still appear in role grants and
	// look "wired" by inspection. The tripwire test
	// TestPermAuditWriteHasProductionCallsite in
	// internal/server/rbac_matrix_test.go fails the build if no
	// requirePermission call references this constant. If the gate
	// genuinely needs to move (e.g. a different middleware), update
	// the tripwire with the new callsite reference.
	PermAuditWrite         = "audit:write"
	PermWebhooksManage     = "webhooks:manage"
	PermOrgMembers2FAReset = "org:members:reset-2fa"
	PermCacheManage        = "cache:manage"
	PermPackagesRead       = "packages:read"
	PermPackagesManage     = "packages:manage"
	// PermPackagesPublish and PermUsageManage were declared and granted to
	// roles but never enforced server-side. They were removed (W-W2 audit
	// finding) rather than wired in because no dashboard publish flow or
	// usage-management endpoint exists today: client-credential uploads
	// gate on the per-package package_permissions table (see
	// checkPackageWritePermission in internal/server/packages_api.go) and
	// usage endpoints all gate on PermUsageRead. If a future feature adds
	// a dashboard publish handler or org-level usage-mutation endpoint,
	// reintroduce the constants alongside the requirePermission gate.
	PermSSOGroupMappings = "sso:group-mappings:manage"
	PermSCIMManage       = "scim:manage"
	PermUsageRead        = "usage:read"
	// PermAPIKeysManage gates CRUD on the api_keys table — minting,
	// listing, narrowing, and revoking management-API keys (PATs and
	// AI-agent credentials). Distinct from PermClientsCreate, which
	// gates registry-side proxy credentials. Granted to org-owner /
	// org-admin / global-admin by default; manager and member do not
	// receive it (a manager who needs an agent key gets one minted by
	// an owner).
	PermAPIKeysManage = "api-keys:manage"
	// PermComplianceRead gates the endpoint-compliance dashboard — reading
	// attestations posted by enrolled endpoints / CI runners and deriving
	// per-org compliance metrics. Granted to global-admin, org-admin,
	// org-owner, and org-manager (same shape as PermAuditRead). Members do
	// not see the dashboard by default; orgs that want developers to see
	// their own device posture can add it to a custom role.
	PermComplianceRead = "compliance:read"
	// PermComplianceWrite gates POST /api/attestations — endpoints / CI
	// runners post compliance reports with this permission. It is granted
	// to API keys with the agent / client-setup preset and inherited by
	// any user role that can already read compliance.
	PermComplianceWrite = "compliance:write"
	// PermFindingsRead gates GET /api/findings (list + detail). Granted
	// to every role from member up — findings are the main triage
	// surface so developers need to see their own team's queue. See
	// DESIGN.md §12 (entity model) and §18 (permission UX).
	PermFindingsRead = "findings:read"
	// PermFindingsManage gates the lifecycle transitions — ack, snooze,
	// resolve, reopen, assign. Restricted to manager+ so a regular
	// member cannot silently acknowledge a finding raised against their
	// own commit. Suppression is gated separately (PermFindingsSuppress)
	// because it permanently silences a security signal from triage and
	// so carries a higher bar. (It does NOT bypass enforcement — see
	// internal/finding/finding.go package docs.)
	PermFindingsManage = "findings:manage"
	// PermFindingsSuppress gates POST /api/findings/{id}/suppress. Kept
	// as its own permission — not folded into PermFindingsManage —
	// because suppressing a finding is an admission that the policy
	// should not have fired, and some orgs will want to tighten the
	// role matrix (manager can ack, owner can suppress) in a follow-up
	// without another migration. Today both permissions land on the
	// same role set; the shape lets the role matrix diverge later
	// without a schema change.
	PermFindingsSuppress = "findings:suppress"
)

var rolePermissions = map[string][]string{
	RoleGlobalAdmin: {
		PermOrgDelete,
		PermOrgMembersRead,
		PermOrgMembersInvite,
		PermOrgMembersUpdate,
		PermOrgMembersRemove,
		PermOrgMembers2FAReset,
		PermClientsCreate,
		PermClientsManageAll,
		PermClientsManageOwn,
		PermReposRead,
		PermReposManage,
		PermSettingsRead,
		PermSettingsUpdate,
		PermPoliciesRead,
		PermPoliciesManage,
		PermExceptionsRead,
		PermExceptionsManage,
		PermMetricsRead,
		PermMetricsManage,
		PermAuditRead,
		PermAuditWrite,
		PermWebhooksManage,
		PermCacheManage,
		PermPackagesRead,
		PermPackagesManage,
		PermSSOGroupMappings,
		PermSCIMManage,
		PermUsageRead,
		PermAPIKeysManage,
		PermComplianceRead,
		PermComplianceWrite,
		PermFindingsRead,
		PermFindingsManage,
		PermFindingsSuppress,
	},
	RoleOrgAdmin: {
		PermOrgDelete,
		PermOrgMembersRead,
		PermOrgMembersInvite,
		PermOrgMembersUpdate,
		PermOrgMembersRemove,
		PermOrgMembers2FAReset,
		PermClientsCreate,
		PermClientsManageAll,
		PermClientsManageOwn,
		PermReposRead,
		PermReposManage,
		PermSettingsRead,
		PermSettingsUpdate,
		PermPoliciesRead,
		PermPoliciesManage,
		PermExceptionsRead,
		PermExceptionsManage,
		PermMetricsRead,
		PermMetricsManage,
		PermAuditRead,
		PermAuditWrite,
		PermWebhooksManage,
		PermCacheManage,
		PermSSOGroupMappings,
		PermSCIMManage,
		PermPackagesRead,
		PermPackagesManage,
		PermUsageRead,
		PermAPIKeysManage,
		PermComplianceRead,
		PermComplianceWrite,
		PermFindingsRead,
		PermFindingsManage,
		PermFindingsSuppress,
	},
	RoleOwner: {
		PermOrgDelete,
		PermOrgMembersRead,
		PermOrgMembersInvite,
		PermOrgMembersUpdate,
		PermOrgMembersRemove,
		PermOrgMembers2FAReset,
		PermClientsCreate,
		PermClientsManageAll,
		PermClientsManageOwn,
		PermReposRead,
		PermReposManage,
		PermSettingsRead,
		PermSettingsUpdate,
		PermPoliciesRead,
		PermPoliciesManage,
		PermExceptionsRead,
		PermExceptionsManage,
		PermMetricsRead,
		PermMetricsManage,
		PermAuditRead,
		PermAuditWrite,
		PermWebhooksManage,
		PermCacheManage,
		PermPackagesRead,
		PermPackagesManage,
		PermSSOGroupMappings,
		PermSCIMManage,
		PermUsageRead,
		PermAPIKeysManage,
		PermComplianceRead,
		PermComplianceWrite,
		PermFindingsRead,
		PermFindingsManage,
		PermFindingsSuppress,
	},
	RoleManager: {
		PermOrgMembersRead,
		PermOrgMembersInvite,
		PermOrgMembersUpdate,
		PermOrgMembersRemove,
		PermClientsCreate,
		PermClientsManageAll,
		PermReposRead,
		PermReposManage,
		PermSettingsRead,
		PermSettingsUpdate,
		PermPoliciesRead,
		PermPoliciesManage,
		PermExceptionsRead,
		PermExceptionsManage,
		PermMetricsRead,
		PermMetricsManage,
		PermAuditRead,
		PermAuditWrite,
		PermWebhooksManage,
		PermCacheManage,
		PermPackagesRead,
		PermPackagesManage,
		PermUsageRead,
		PermComplianceRead,
		PermFindingsRead,
		PermFindingsManage,
		PermFindingsSuppress,
	},
	RoleMember: {
		PermOrgMembersRead,
		PermClientsCreate,
		PermClientsManageOwn,
		PermReposRead,
		PermPoliciesRead,
		PermExceptionsRead,
		PermMetricsRead,
		PermAuditRead,
		PermPackagesRead,
		PermFindingsRead,
	},
}

func NormalizeOrgID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return DefaultOrgID
	}
	return id
}

// NormalizeRole trims surrounding whitespace from a role identifier and
// returns it. The earlier implementation had two identical return
// branches gated on IsBuiltinRole; that dead branch is removed because a
// future editor might assume the two returns must differ and add
// divergent logic that silently splits behaviour between built-in and
// custom roles. Callers that need built-in-only normalisation should use
// NormalizeBuiltinRole.
func NormalizeRole(role string) string {
	return strings.TrimSpace(role)
}

func NormalizeBuiltinRole(role string) string {
	role = strings.TrimSpace(role)
	if IsBuiltinRole(role) {
		return role
	}
	return ""
}

func IsBuiltinRole(role string) bool {
	switch strings.TrimSpace(role) {
	case RoleGlobalAdmin, RoleOrgAdmin, RoleOwner, RoleManager, RoleMember:
		return true
	default:
		return false
	}
}

func BuiltinRoles() []string {
	return []string{RoleGlobalAdmin, RoleOrgAdmin, RoleOwner, RoleManager, RoleMember}
}

func PermissionsForRole(role string) map[string]bool {
	role = NormalizeRole(role)
	perms := make(map[string]bool)
	for _, perm := range rolePermissions[role] {
		perms[perm] = true
	}
	return perms
}

func PermissionsListForRole(role string) []string {
	role = NormalizeRole(role)
	perms := rolePermissions[role]
	out := make([]string, len(perms))
	copy(out, perms)
	return out
}

func AllPermissions() []string {
	seen := make(map[string]bool)
	var perms []string
	for _, role := range BuiltinRoles() {
		for _, perm := range rolePermissions[role] {
			if seen[perm] {
				continue
			}
			seen[perm] = true
			perms = append(perms, perm)
		}
	}
	return perms
}

func RoleAllows(role, permission string) bool {
	role = NormalizeRole(role)
	for _, perm := range rolePermissions[role] {
		if perm == permission {
			return true
		}
	}
	return false
}
