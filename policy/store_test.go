package policy

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
)

func TestNormalizePolicyNormalizesRequestingScopes(t *testing.T) {
	t.Parallel()

	normalized, err := normalizePolicy(Policy{
		Scope: Scope{
			TargetRequestingCountry: []string{" gb ", "GB", "all"},
			TargetRequestingIP:      []string{" 192.168.1.10 ", "192.168.1.10", "10.10.10.8/24", "*"},
		},
	})
	if err != nil {
		t.Fatalf("normalizePolicy returned error: %v", err)
	}

	if got, want := len(normalized.Scope.TargetRequestingCountry), 1; got != want {
		t.Fatalf("expected %d normalized countries, got %d", want, got)
	}
	if normalized.Scope.TargetRequestingCountry[0] != "GB" {
		t.Fatalf("expected normalized country code GB, got %q", normalized.Scope.TargetRequestingCountry[0])
	}

	if got, want := len(normalized.Scope.TargetRequestingIP), 2; got != want {
		t.Fatalf("expected %d normalized IP entries, got %d", want, got)
	}
	if normalized.Scope.TargetRequestingIP[0] != "192.168.1.10" {
		t.Fatalf("expected canonical exact IP, got %q", normalized.Scope.TargetRequestingIP[0])
	}
	if normalized.Scope.TargetRequestingIP[1] != "10.10.10.0/24" {
		t.Fatalf("expected canonical CIDR, got %q", normalized.Scope.TargetRequestingIP[1])
	}
}

func TestNormalizePolicyRejectsInvalidRequestingIP(t *testing.T) {
	t.Parallel()

	_, err := normalizePolicy(Policy{
		Scope: Scope{
			TargetRequestingIP: []string{"not-an-ip"},
		},
	})
	if err == nil {
		t.Fatalf("expected invalid requesting IP to be rejected")
	}
}

func TestValidatePolicyModes(t *testing.T) {
	t.Parallel()

	constraint := Conditions{IsVulnerable: boolPtr(true)}

	cases := []struct {
		name    string
		mode    Mode
		wantErr bool
	}{
		{name: "allow accepted", mode: ModeAllow, wantErr: false},
		{name: "block accepted", mode: ModeBlock, wantErr: false},
		{name: "monitor accepted", mode: ModeMonitor, wantErr: false},
		{name: "quarantine accepted", mode: ModeQuarantine, wantErr: false},
		{name: "unknown mode rejected", mode: Mode("snoop"), wantErr: true},
		{name: "empty mode rejected", mode: Mode(""), wantErr: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validatePolicy(Policy{
				Mode:       tc.mode,
				Status:     StatusEnabled,
				Conditions: constraint,
			})
			if tc.wantErr && err == nil {
				t.Fatalf("expected validation error for mode %q", tc.mode)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected validation error for mode %q: %v", tc.mode, err)
			}
		})
	}
}

func TestValidatePolicyAllowsMeaningfulIdentifierConstraint(t *testing.T) {
	t.Parallel()

	err := validatePolicy(Policy{
		Mode:   ModeBlock,
		Status: StatusEnabled,
		Identifier: Identifier{
			TargetPackageName: "axios",
		},
	})
	if err != nil {
		t.Fatalf("expected exact package identifier policy to be valid: %v", err)
	}
}

func TestValidatePolicyRejectsWildcardOnlyIdentifier(t *testing.T) {
	t.Parallel()

	err := validatePolicy(Policy{
		Mode:   ModeBlock,
		Status: StatusEnabled,
		Identifier: Identifier{
			TargetPackageName: "*",
			TargetPackageRepo: "all",
		},
	})
	if err == nil {
		t.Fatalf("expected wildcard-only identifier policy to be invalid")
	}
}

func TestPolicyParameterHashIgnoresUserMetadataPrecedenceAndStatus(t *testing.T) {
	t.Parallel()

	base := Policy{
		Name:        "Block vulnerable packages",
		Description: "Initial description",
		Precedence:  10,
		Mode:        ModeBlock,
		Status:      StatusEnabled,
		Identifier:  Identifier{TargetPackageName: "lodash"},
		Conditions:  Conditions{IsVulnerable: boolPtr(true), PackageLicense: []string{"MIT", "Apache-2.0"}},
		Scope:       Scope{TargetRepos: []string{"npmjs", "yarnpkg"}},
	}
	changedMetadata := base
	changedMetadata.Name = "Different name"
	changedMetadata.Description = "Different description"
	changedMetadata.Precedence = 200
	changedMetadata.Status = StatusDisabled
	changedMetadata.Conditions.PackageLicense = []string{"Apache-2.0", "MIT"}
	changedMetadata.Scope.TargetRepos = []string{"yarnpkg", "npmjs"}

	baseHash, err := PolicyParameterHash(base)
	if err != nil {
		t.Fatalf("hash base policy: %v", err)
	}
	changedHash, err := PolicyParameterHash(changedMetadata)
	if err != nil {
		t.Fatalf("hash changed policy: %v", err)
	}
	if baseHash != changedHash {
		t.Fatalf("expected metadata/status/precedence changes and slice ordering to be ignored")
	}

	changedBehavior := base
	changedBehavior.Mode = ModeMonitor
	behaviorHash, err := PolicyParameterHash(changedBehavior)
	if err != nil {
		t.Fatalf("hash behavior policy: %v", err)
	}
	if behaviorHash == baseHash {
		t.Fatalf("expected mode changes to affect policy hash")
	}
}

func TestDuplicatePolicyParameterErrorIgnoresEditedPolicy(t *testing.T) {
	t.Parallel()

	edited := Policy{
		ID:         "policy-a",
		Mode:       ModeBlock,
		Conditions: Conditions{PackageAge: intPtr(14)},
	}
	parameterHash, err := PolicyParameterHash(edited)
	if err != nil {
		t.Fatalf("hash edited policy: %v", err)
	}

	err = duplicatePolicyParameterError([]Policy{
		edited,
		{
			ID:         "policy-b",
			Mode:       ModeBlock,
			Conditions: Conditions{PackageAge: intPtr(30)},
		},
	}, edited.ID, parameterHash)
	if err != nil {
		t.Fatalf("expected edited policy's own ID to be excluded from duplicate check: %v", err)
	}

	err = duplicatePolicyParameterError([]Policy{
		edited,
		{
			ID:         "policy-b",
			Mode:       ModeBlock,
			Conditions: Conditions{PackageAge: intPtr(14)},
		},
	}, edited.ID, parameterHash)
	if !errors.Is(err, ErrDuplicatePolicy) {
		t.Fatalf("expected duplicate policy error when update matches another policy, got %v", err)
	}
}

func TestPolicyStoreDescriptionAndDuplicateConflicts(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("new policy store: %v", err)
	}
	orgID := "test-policy-" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM policies WHERE org_id=?`, orgID)
	})
	orgStore := store.ForOrg(orgID)

	created, err := orgStore.Create(Policy{
		Name:        "Block vulnerable",
		Description: "Review quarterly",
		Precedence:  10,
		Mode:        ModeBlock,
		Status:      StatusEnabled,
		Conditions:  Conditions{IsVulnerable: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	got, err := orgStore.Get(created.ID)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if got.Description != "Review quarterly" {
		t.Fatalf("expected description round trip, got %q", got.Description)
	}

	_, err = orgStore.Create(Policy{
		Name:       "Same precedence",
		Precedence: 10,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		Conditions: Conditions{PackageAge: intPtr(1)},
	})
	if !errors.Is(err, ErrDuplicatePrecedence) {
		t.Fatalf("expected duplicate precedence error, got %v", err)
	}

	_, err = orgStore.Create(Policy{
		Name:        "Same effective rule",
		Description: "Different description",
		Precedence:  20,
		Mode:        ModeBlock,
		Status:      StatusDisabled,
		Conditions:  Conditions{IsVulnerable: boolPtr(true)},
	})
	if !errors.Is(err, ErrDuplicatePolicy) {
		t.Fatalf("expected duplicate policy error, got %v", err)
	}

	editable, err := orgStore.Create(Policy{
		Name:       "Editable policy",
		Precedence: 30,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		Conditions: Conditions{PackageAge: intPtr(14)},
	})
	if err != nil {
		t.Fatalf("create editable policy: %v", err)
	}

	_, err = orgStore.Update(editable.ID, Policy{
		Name:        "Editable policy renamed",
		Description: "Metadata changes should not conflict with itself",
		Precedence:  30,
		Mode:        ModeBlock,
		Status:      StatusDisabled,
		Conditions:  Conditions{PackageAge: intPtr(14)},
	})
	if err != nil {
		t.Fatalf("expected updating a policy without changing effective parameters to succeed: %v", err)
	}

	_, err = orgStore.Update(editable.ID, Policy{
		Name:       "Duplicate existing by update",
		Precedence: 40,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		Conditions: Conditions{IsVulnerable: boolPtr(true)},
	})
	if !errors.Is(err, ErrDuplicatePolicy) {
		t.Fatalf("expected update duplicate policy error, got %v", err)
	}
}

func intPtr(v int) *int { return &v }

// TestExceptionDecisionFieldsRoundTrip pins the storage-layer round-trip
// for the Wave-2 exception metadata: a policy created with
// decision="monitor" must come back with the same values from List() and
// Get(). Drift here would silently homogenize the VEX export back to the
// pre-Wave-2 "every exception is allow" behavior.
func TestExceptionDecisionFieldsRoundTrip(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("new policy store: %v", err)
	}
	orgID := "test-exc-decision-" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM policies WHERE org_id=?`, orgID)
	})
	orgStore := store.ForOrg(orgID)

	created, err := orgStore.Create(Policy{
		Name:       "Exception: lodash@4.17.20",
		Precedence: 10,
		Mode:       ModeAllow,
		Status:     StatusEnabled,
		Identifier: Identifier{
			TargetPackageName:    "lodash",
			TargetPackageRepo:    "npm-prod",
			TargetPackageVersion: "4.17.20",
		},
		Conditions: Conditions{IsVulnerable: boolPtr(true)},
		Decision:   "monitor",
		CVE:        "CVE-2024-22222",
		Note:       "tracking upstream patch",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if created.Decision != "monitor" || created.CVE != "CVE-2024-22222" || created.Note != "tracking upstream patch" {
		t.Fatalf("create round-trip drift: got decision=%q cve=%q note=%q",
			created.Decision, created.CVE, created.Note)
	}

	got, err := orgStore.Get(created.ID)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if got.Decision != "monitor" {
		t.Errorf("Get().Decision = %q, want monitor", got.Decision)
	}
	if got.CVE != "CVE-2024-22222" {
		t.Errorf("Get().CVE = %q, want CVE-2024-22222", got.CVE)
	}
	if got.Note != "tracking upstream patch" {
		t.Errorf("Get().Note = %q, want forwarded", got.Note)
	}

	listed, err := orgStore.List()
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	var found *Policy
	for i := range listed {
		if listed[i].ID == created.ID {
			found = &listed[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("created policy not in List() output")
	}
	if found.Decision != "monitor" || found.CVE != "CVE-2024-22222" || found.Note != "tracking upstream patch" {
		t.Errorf("List() round-trip drift: got %+v", found)
	}

	// Update path: change the note, confirm it persists.
	updateReq := Policy{
		Name:       found.Name,
		Precedence: found.Precedence,
		Mode:       ModeAllow,
		Status:     StatusEnabled,
		Identifier: found.Identifier,
		Conditions: found.Conditions,
		Decision:   "allow",
		CVE:        "CVE-2024-22222",
		Note:       "patched upstream — keep until next release",
	}
	updated, err := orgStore.Update(created.ID, updateReq)
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}
	if updated.Decision != "allow" || updated.Note != "patched upstream — keep until next release" {
		t.Errorf("Update() round-trip drift: got decision=%q note=%q",
			updated.Decision, updated.Note)
	}
}

// TestExceptionDecisionValidation pins the allow/deny/monitor/empty
// gate at the storage layer. The server-side parser also validates, but
// the storage layer is the last line of defense if a future caller
// bypasses parseExceptionRequest.
func TestExceptionDecisionValidation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		decision string
		valid    bool
	}{
		{"", true},
		{"allow", true},
		{"deny", true},
		{"monitor", true},
		{"unknown", false},
		{"ALLOW", true}, // normalize lowercases first
	}
	for _, tc := range cases {
		p := Policy{
			Mode:   ModeAllow,
			Status: StatusEnabled,
			Conditions: Conditions{
				IsVulnerable: boolPtr(true),
			},
			Decision: tc.decision,
		}
		normalized, err := normalizePolicy(p)
		if err != nil {
			t.Fatalf("normalize %q: %v", tc.decision, err)
		}
		err = validatePolicy(normalized)
		if tc.valid && err != nil {
			t.Errorf("decision %q: want valid, got error %v", tc.decision, err)
		}
		if !tc.valid && err == nil {
			t.Errorf("decision %q: want validation error, got nil", tc.decision)
		}
	}
}

// TestValidatePolicyRejectsStandaloneContextOnlyConditions confirms that the
// noisy Wave-3 codesmell signals (UsesEval, NetworkAccess, ShellAccess,
// FilesystemAccess, EnvVarAccess) cannot be used as the only constraint on a
// policy — their FP rates on legitimate top-100 packages are too high to
// gate decisions on in isolation. The four lower-FP signals (NativeBinary,
// HighEntropyStrings, URLStrings, MinifiedCode) remain eligible as standalone
// gates.
func TestValidatePolicyRejectsStandaloneContextOnlyConditions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		conditions Conditions
		identifier Identifier
		wantErr    bool
	}{
		{
			name:       "UsesEval standalone rejected",
			conditions: Conditions{UsesEval: boolPtr(true)},
			wantErr:    true,
		},
		{
			name:       "NetworkAccess standalone rejected",
			conditions: Conditions{NetworkAccess: boolPtr(true)},
			wantErr:    true,
		},
		{
			name:       "ShellAccess standalone rejected",
			conditions: Conditions{ShellAccess: boolPtr(true)},
			wantErr:    true,
		},
		{
			name:       "FilesystemAccess standalone rejected",
			conditions: Conditions{FilesystemAccess: boolPtr(true)},
			wantErr:    true,
		},
		{
			name:       "EnvVarAccess standalone rejected",
			conditions: Conditions{EnvVarAccess: boolPtr(true)},
			wantErr:    true,
		},
		{
			name: "all five context-only conditions standalone rejected",
			conditions: Conditions{
				UsesEval:         boolPtr(true),
				NetworkAccess:    boolPtr(true),
				ShellAccess:      boolPtr(true),
				FilesystemAccess: boolPtr(true),
				EnvVarAccess:     boolPtr(true),
			},
			wantErr: true,
		},
		{
			name:       "NativeBinary standalone allowed",
			conditions: Conditions{NativeBinaryPresent: boolPtr(true)},
			wantErr:    false,
		},
		{
			name:       "HighEntropyStrings standalone allowed",
			conditions: Conditions{HighEntropyStrings: boolPtr(true)},
			wantErr:    false,
		},
		{
			name:       "URLStrings standalone allowed",
			conditions: Conditions{URLStrings: boolPtr(true)},
			wantErr:    false,
		},
		{
			name:       "MinifiedCode standalone allowed",
			conditions: Conditions{MinifiedCode: boolPtr(true)},
			wantErr:    false,
		},
		{
			name: "UsesEval paired with another gateable condition allowed",
			conditions: Conditions{
				UsesEval:         boolPtr(true),
				HasInstallScript: boolPtr(true),
			},
			wantErr: false,
		},
		{
			name:       "UsesEval narrowed by package identifier allowed",
			conditions: Conditions{UsesEval: boolPtr(true)},
			identifier: Identifier{TargetPackageName: "left-pad"},
			wantErr:    false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validatePolicy(Policy{
				Mode:       ModeBlock,
				Status:     StatusEnabled,
				Identifier: tc.identifier,
				Conditions: tc.conditions,
			})
			if tc.wantErr && err == nil {
				t.Fatalf("expected validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

// TestGraceDaysAndPendingApprovalRoundTrip pins the storage round-trip
// for the two Item-2/Item-3b additive columns: a ModeBlockAfterGrace
// policy with grace_days=14 must come back with GraceDays=14, and a
// StatusPendingApproval exception must round-trip its status (not get
// coerced to enabled/disabled). Drift here would silently change
// enforcement: a lost grace_days falls back to the 7d default, and a
// lost pending status would let an un-approved exception go live.
func TestGraceDaysAndPendingApprovalRoundTrip(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("new policy store: %v", err)
	}
	orgID := "test-grace-" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM policies WHERE org_id=?`, orgID)
	})
	orgStore := store.ForOrg(orgID)

	// block_after_grace with an explicit 14-day window.
	grace := orgStore
	created, err := grace.Create(Policy{
		Name:       "Grace block lodash",
		Precedence: 10,
		Mode:       ModeBlockAfterGrace,
		Status:     StatusEnabled,
		Identifier: Identifier{TargetPackageName: "lodash", TargetPackageRepo: "npm-prod", TargetPackageVersion: "*"},
		GraceDays:  intPtr(14),
	})
	if err != nil {
		t.Fatalf("create block_after_grace policy: %v", err)
	}
	got, err := grace.Get(created.ID)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if got.Mode != ModeBlockAfterGrace {
		t.Fatalf("Get().Mode = %q, want block_after_grace", got.Mode)
	}
	if got.GraceDays == nil || *got.GraceDays != 14 {
		t.Fatalf("Get().GraceDays = %v, want 14", got.GraceDays)
	}
	if got.EffectiveGraceDays() != 14 {
		t.Fatalf("EffectiveGraceDays = %d, want 14", got.EffectiveGraceDays())
	}

	// nil grace_days must read back nil and resolve to the 7d default.
	nilGrace, err := grace.Create(Policy{
		Name:       "Grace block default",
		Precedence: 20,
		Mode:       ModeBlockAfterGrace,
		Status:     StatusEnabled,
		Identifier: Identifier{TargetPackageName: "express", TargetPackageRepo: "npm-prod", TargetPackageVersion: "*"},
	})
	if err != nil {
		t.Fatalf("create nil-grace policy: %v", err)
	}
	gotNil, err := grace.Get(nilGrace.ID)
	if err != nil {
		t.Fatalf("get nil-grace policy: %v", err)
	}
	if gotNil.GraceDays != nil {
		t.Fatalf("nil grace_days must round-trip nil, got %v", gotNil.GraceDays)
	}
	if gotNil.EffectiveGraceDays() != DefaultGraceDays {
		t.Fatalf("nil grace_days EffectiveGraceDays = %d, want %d", gotNil.EffectiveGraceDays(), DefaultGraceDays)
	}

	// pending_approval exception round-trip.
	pending, err := grace.Create(Policy{
		Name:       "Exception: pending@1.0.0",
		Precedence: 30,
		Mode:       ModeAllow,
		Kind:       KindException,
		Status:     StatusPendingApproval,
		CreatedBy:  "user-requester",
		Identifier: Identifier{TargetPackageName: "pending", TargetPackageRepo: "npm-prod", TargetPackageVersion: "1.0.0"},
	})
	if err != nil {
		t.Fatalf("create pending exception: %v", err)
	}
	gotPending, err := grace.Get(pending.ID)
	if err != nil {
		t.Fatalf("get pending exception: %v", err)
	}
	if gotPending.Status != StatusPendingApproval {
		t.Fatalf("Get().Status = %q, want pending_approval", gotPending.Status)
	}
	if gotPending.CreatedBy != "user-requester" {
		t.Fatalf("Get().CreatedBy = %q, want user-requester", gotPending.CreatedBy)
	}
}
