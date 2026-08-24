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
# input.signalsUnavailable is set for EITHER degraded byte-acquisition
# outcome — see acquireResult.degraded() in core/cli/guard_artifact.go,
# which is the single predicate this input is projected from:
#
#   acquireIncomplete    — the guard tried to analyze the artifact and
#                          could not finish: a truncated cache index
#                          scan, a transport failure, or an artifact
#                          present at a resolved content-addressed path
#                          that would not read.
#   acquireDigestMismatch — the guard DID get bytes and they are not the
#                          bytes that will be installed: the archive did
#                          not hash to the project's lockfile integrity,
#                          or to the one npm's own index claims.
#
# Naming only the first (as this comment used to) understates the rule:
# an operator reading it would not know that shipping it at "block" also
# refuses a cache/lockfile digest disagreement.
#
# Both are materially different from "the package was not cached", and
# the first is the difference an attacker can drive: exhausting the
# shared index-scan budget earlier in the same process used to buy
# exactly the same silent ALLOW as a package the guard was never asked
# about.
#
# DEFAULT ACTION IS monitor, NOT block.
#
#   Blocking by default would hard-fail installs on every machine whose
#   package cache the scan cannot finish — a silent posture change for
#   every existing free-guard user, on a surface whose entire job is to
#   not surprise people. Monitor makes the degradation visible, which is
#   the actual defect being fixed, and preserves the "never hard-fail an
#   install" guarantee.
#
#   An operator who wants fail-closed coverage ships a bundle with the
#   same rule at "block". That is the ruling working as intended: the
#   posture is a policy edit, not a code change, and it is expressed
#   once rather than per surface.
#
#   BEFORE SHIPPING THAT RULE, read the budget note on
#   guardCacheWalkMaxFiles. This default was measured against a real
#   9,859-file ~/.npm/_cacache: with the pre-2026-08-24 scan budget a
#   third of an HONEST 90-package install set this input, so the same
#   rule at "block" would have refused a third of a clean `npm ci`. The
#   scan is now memoized and completes, and the measured rate on that
#   cache is 0 — but the rule is only as safe as the cache it runs
#   against, so measure yours before you turn it into a refusal.
# WHY THE MESSAGE IS GENERIC, and must stay that way. This rule keys on
# input.signalsUnavailable, which is a single bool. It is set by BOTH
# acquireIncomplete (the analyzer could not finish) and
# acquireDigestMismatch (the analyzer finished and the bytes disagreed
# with the lockfile anchor). Rego cannot tell those apart, so a message
# naming only one of them is wrong half the time — the earlier text said
# "the bytes were not fully inspected", which is false for a mismatch,
# where they were read in full and simply were not the right bytes.
# The specific fact is surfaced separately by the guard's own
# "! integrity" line, which is driven by guardVerdict.DigestMismatch.
decision contains {
	"action":             "monitor",
	"rule_id":            "builtin/degraded-analysis",
	"message":            "this artifact was not confirmed as the bytes that will be installed: analysis did not complete, or the bytes did not match the lockfile digest",
	"exception_eligible": true,
} if {
	input.signalsUnavailable == true
}
