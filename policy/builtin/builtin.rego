# Chainsaw built-in default policy.
#
# COMPILED INTO THE BINARY (see defaults.go go:embed). This is the
# policy that runs when an operator has shipped no bundle of their own.
#
# Why this file exists at all, rather than a Go constant:
#
#   The 2026-08-24 ruling is that warn-vs-block on a degraded analysis
#   is a POLICY question, not a per-surface Go table. "Falls back to
#   defaults when no bundle is present" would violate that ruling if
#   "defaults" meant hardcoded Go — it would be the same hardcoding
#   under a different name. So the defaults are themselves a policy
#   object, "no bundle on disk" means BUILT-IN POLICY rather than NO
#   policy, and one decision path serves both cases.
#
# SCOPE — read before adding a rule here.
#
#   Policy TIGHTENS, never loosens. policyengine folds the Rego verdict
#   with dsl.Stricter, so a rule here can raise a verdict and can never
#   clear one. That is deliberate and load-bearing: the guard's Go lanes
#   (known-malicious, known-vulnerable, typosquat, behavioral-*) are
#   ground truth about a published incident or the artifact's own bytes,
#   and a rule file must not be able to wave them through. The same
#   boundary the local allowlist respects — see core/cli/guard_allow.go,
#   "THE SECURITY BOUNDARY".
#
#   So this bundle does NOT restate the Go lanes. Duplicating them would
#   buy nothing (Stricter means the stricter of two identical verdicts)
#   and would create two places to keep in sync. It covers only decisions
#   the Go lanes do not make.

package chainsaw.policy

# --- degraded-analysis --------------------------------------------
#
# input.signalsUnavailable is set when byte acquisition returned
# acquireIncomplete: the guard tried to analyze the artifact and could
# not finish — walk budget exhausted, a truncated cache scan, a
# transport failure, or an artifact present at a resolved content-
# addressed path that would not read. See acquireResult in
# core/cli/guard_artifact.go.
#
# This is materially different from "the package was not cached", and
# it is the difference an attacker can drive: exhausting the shared
# walk budget earlier in the same process used to buy exactly the same
# silent ALLOW as a package the guard was never asked about.
#
# DEFAULT ACTION IS monitor, NOT block.
#
#   Blocking by default would hard-fail installs on every machine with
#   a large enough package cache to exhaust the walk budget — a silent
#   posture change for every existing free-guard user, on a surface
#   whose entire job is to not surprise people. Monitor makes the
#   degradation visible, which is the actual defect being fixed, and
#   preserves the "never hard-fail an install" guarantee.
#
#   An operator who wants fail-closed coverage ships a bundle with the
#   same rule at "block". That is the ruling working as intended: the
#   posture is a policy edit, not a code change, and it is expressed
#   once rather than per surface.
decision contains {
	"action":             "monitor",
	"rule_id":            "builtin/degraded-analysis",
	"message":            "behavioral analysis did not complete for this artifact; the bytes were not fully inspected",
	"exception_eligible": true,
} if {
	input.signalsUnavailable == true
}
