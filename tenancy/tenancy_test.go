package tenancy

import "testing"

func TestUnknownRoleFailsClosed(t *testing.T) {
	role := NormalizeRole("custom-reviewer")
	if role != "custom-reviewer" {
		t.Fatalf("expected custom role identifier to be preserved, got %q", role)
	}
	if perms := PermissionsForRole(role); len(perms) != 0 {
		t.Fatalf("expected unknown role to have no built-in permissions, got %#v", perms)
	}
	if RoleAllows(role, PermPoliciesManage) {
		t.Fatal("unknown role unexpectedly inherited permissions")
	}
}

func TestBuiltInRoleCompatibility(t *testing.T) {
	perms := PermissionsForRole(RoleManager)
	if !perms[PermPoliciesManage] {
		t.Fatal("manager should keep policies:manage")
	}
	if !RoleAllows(RoleMember, PermClientsManageOwn) {
		t.Fatal("member should keep clients:manage:own")
	}
}
