# Chainsaw demo policy bundle.
#
# This is the rule the README, the deep-research report, and the
# platform-engineer wishlist all converge on:
#
#   "Block packages with install scripts from maintainers younger
#    than 90 days."
#
# Authored once. Enforced at six surfaces (PR, proxy, publish,
# promote, deploy, runtime) by the policyengine facade. The same
# rule fires at every surface where the input fields it references
# are populated; surfaces that lack the signal (e.g. PR check has
# no tarball → no install-script signal) skip silently because the
# `signals.has_install_script` clause stays false.
#
# Rule shape:
#   decision := { ... }   # one or more partial rules
#   action: "block" | "quarantine" | "monitor" | "allow"
#   rule_id: stable identifier the audit log records
#   message: human-readable reason; can sprintf in field values
#   exception_eligible: whether operators can grant a per-package waiver

package chainsaw.policy

# Built-in signals shim. Keeps policy authors out of the raw input
# field names so we can rename fields later without rewriting every
# rule. `data.chainsaw.signals.<name>` is the public API.

signals := {
	"has_install_script":             input.hasInstallScript == true,
	"install_script_fetches_remote":  input.installScriptFetchesRemote == true,
	"is_known_malicious":             input.isKnownMalicious == true,
	"is_typosquat":                   input.isSuspectedTyposquat == true,
	"has_provenance":                 input.hasProvenance == true,
	"publisher_changed":              input.publisherChanged == true,
}

# --- young-maintainer-with-install-script -------------------------
#
# Fires when:
#   - some maintainer/publisher account on this version is <= 90
#     days old AND
#   - the package declares an install/lifecycle script.
#
# Both conditions matter on their own — the combination is what
# distinguishes "ordinary new package" from "install-time exfil
# vector authored by a fresh account".

decision contains {
	"action":             "block",
	"rule_id":            "young-maintainer-with-install-script",
	"message":            sprintf("youngest maintainer is %d days old; package declares install script", [input.maintainerAccountAgeDays]),
	"exception_eligible": true,
} if {
	input.maintainerAccountAgeDays > 0
	input.maintainerAccountAgeDays <= 90
	input.hasInstallScript == true
}

# Same rule, harder verdict when the install script makes a remote
# fetch — that's the supply-chain exfil signature, not just a build
# step.

decision contains {
	"action":             "block",
	"rule_id":            "young-maintainer-with-remote-fetching-install-script",
	"message":            "young maintainer + install script that fetches remote payload",
	"exception_eligible": false,
} if {
	input.maintainerAccountAgeDays > 0
	input.maintainerAccountAgeDays <= 90
	input.installScriptFetchesRemote == true
}

# Surface-scoped tightening: at runtime install we want monitor-mode
# even when the install-script signal is missing (some ecosystems
# only get it after a tarball-side scan). Demonstrates how a rule
# author can react to `input.surface`.

decision contains {
	"action":             "monitor",
	"rule_id":            "runtime-young-maintainer",
	"message":            "young maintainer at install time — flagging for review",
	"exception_eligible": true,
} if {
	input.surface == "runtime"
	input.maintainerAccountAgeDays > 0
	input.maintainerAccountAgeDays <= 30
}
