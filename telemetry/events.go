// Package telemetry is the chainsaw event emission layer shared across CLI,
// MCP server, chainproxy, and backend API.
//
// The canonical event list is defined in events.yaml (same directory) and
// mirrored to Go constants here and to TS constants in
// ui_new/src/lib/events.generated.ts. If you add an event you must add it
// to ALL three places — the CI lint at scripts/lint-events.go blocks PRs
// that skip the registry.
//
// Common properties (required on every event; enforced by Validate):
// event_version, source, surface, channel, install_id, user_id (nullable),
// org_id (nullable), session_id, chainsaw_version, plan, persona, env.
package telemetry

const (
	// EventVersion is the schema version for all events. Bump when a
	// breaking change is rolled out; the ingest handler dual-writes under
	// the old and new names during migrations so dashboards keep working.
	EventVersion = 2
)

// Surface is the originating binary/runtime for an event. One of these
// must be set on every event as the `source` property.
type Surface string

const (
	SurfaceWeb     Surface = "web"
	SurfaceAPI     Surface = "api"
	SurfaceCLI     Surface = "cli"
	SurfaceMCP     Surface = "mcp"
	SurfaceProxy   Surface = "proxy"
	SurfaceLanding Surface = "landing"
)

// Event names — kept sorted within each surface. Add additions to events.yaml
// at the same time. Each constant's RHS must match the YAML `name` exactly.
const (
	// Web
	EventWebPageViewed    = "web.page.viewed"
	EventWebOrgFirstLogin = "web.org.first_login"
	EventWebActionFirst   = "web.action.first"

	// Landing
	EventLandingCTAClicked              = "landing.cta.clicked"
	EventLandingProcurementKitRequested = "landing.procurement_kit.requested"

	// API
	EventAPISignupStarted           = "api.signup.started"
	EventAPISignupVerified          = "api.signup.verified"
	EventAPIOrgCreated              = "api.org.created"
	EventAPIPersonaSet              = "api.persona.set"
	EventAPIPaywallHit              = "api.paywall.hit"
	EventAPIUpgradeClicked          = "api.upgrade.clicked"
	EventAPICheckoutStarted         = "api.checkout.started"
	EventAPISubscriptionCreated     = "api.subscription.created"
	EventAPISSOConfigured           = "api.sso.configured"
	EventAPISIEMWebhookAdded        = "api.siem.webhook_added"
	EventAPISCIMEnabled             = "api.scim.enabled"
	EventAPITeammateInvited         = "api.teammate.invited"
	EventAPIDeviceCodeApproved      = "api.device_code.approved"
	EventAPIOnboardingStepCompleted = "api.onboarding.step_completed"
	EventAPIDormancyFlagged         = "api.dormancy.flagged"

	// API: revenue (Paddle billing lifecycle)
	EventAPISubscriptionCanceled   = "api.subscription.canceled"
	EventAPISubscriptionUpgraded   = "api.subscription.upgraded"
	EventAPISubscriptionDowngraded = "api.subscription.downgraded"
	EventAPIPaymentFailed          = "api.payment.failed"

	// API: activation (hosted scan)
	EventAPIScanCompleted    = "api.scan.completed"
	EventAPIScanMalwareFound = "api.scan.malware_found"

	// CLI
	EventCLISessionStarted       = "cli.session.started"
	EventCLISessionCompleted     = "cli.session.completed"
	EventCLIAuthDeviceStarted    = "cli.auth.device_started"
	EventCLIAuthDeviceApproved   = "cli.auth.device_approved"
	EventCLIAuthDeviceFailed     = "cli.auth.device_failed"
	EventCLIAuthBrowserStarted   = "cli.auth.browser_started"
	EventCLIAuthLogout           = "cli.auth.logout"
	EventCLISetupCompleted       = "cli.setup.completed"
	EventCLISetupAbandoned       = "cli.setup.abandoned"
	EventCLIIntroduceShown       = "cli.introduce.shown"
	EventCLIScanCompleted        = "cli.scan.completed"
	EventCLIPolicyCreated        = "cli.policy.created"
	EventCLIPolicyUpdated        = "cli.policy.updated"
	EventCLIPolicyDeleted        = "cli.policy.deleted"
	EventCLIPolicyListed         = "cli.policy.listed"
	EventCLIPolicySimulated      = "cli.policy.simulated"
	EventCLIPkgInspected         = "cli.pkg.inspected"
	EventCLISbomGenerated        = "cli.sbom.generated"
	EventCLIDoctorRun            = "cli.doctor.run"
	EventCLIInstallHookInstalled = "cli.install_hook.installed"
	EventCLIInstallHookRemoved   = "cli.install_hook.removed"
	EventCLIPolicyFlippedToBlock = "cli.policy.flipped_to_block"
	EventCLIPolicyPreflight      = "cli.policy.preflight"
	EventCLIDoctorUpgradeCheck   = "cli.doctor.upgrade_check"
	EventCLIDoctorBypassCheck    = "cli.doctor.bypass_check"
	EventCLIDoctorVerifyHook     = "cli.doctor.verify_hook"
	EventCLIErrorUnexpected      = "cli.error.unexpected"

	// MCP
	EventMCPSessionInitialized = "mcp.session.initialized"
	EventMCPToolInvoked        = "mcp.tool.invoked"
	EventMCPToolCompleted      = "mcp.tool.completed"
	EventMCPToolFailed         = "mcp.tool.failed"
	EventMCPResourceRead       = "mcp.resource.read"
	EventMCPResourceListed     = "mcp.resource.listed"
	EventMCPSuggestionEmitted  = "mcp.suggestion.emitted"
	EventMCPSuggestionFollowed = "mcp.suggestion.followed"

	// Proxy
	EventProxyPackageBlocked           = "proxy.package.blocked"
	EventProxyPackageAllowed           = "proxy.package.allowed"
	EventProxyPackagePassthrough       = "proxy.package.passthrough"
	EventProxyPackageDenied            = "proxy.package.denied"
	EventProxyEcosystemFirstSeen       = "proxy.ecosystem.first_seen"
	EventProxySbomIngested             = "proxy.sbom.ingested"
	EventProxyMalwareDetected          = "proxy.malware.detected"
	EventProxyVulnCriticalFound        = "proxy.vuln.critical_found"
	EventProxyRollupHourly             = "proxy.rollup.hourly"
	EventProxyHealthDegraded           = "proxy.health.degraded"
	EventProxyActivationFirstBlock     = "proxy.activation.first_block"
	EventProxyActivationConfigVerified = "proxy.activation.config_verified"
	EventProxyConversionFirstRefusal   = "proxy.conversion.first_refusal"
	EventProxyBypassSuspected          = "proxy.bypass.suspected"
	EventProxyConfigRejected           = "proxy.config.rejected"
	EventProxyRequestFailed            = "proxy.request.failed"
	// EventProxyHeartbeat is the affirmative-liveness signal (WS4 #1). A
	// running proxy emits it once per ~5m dedup window with install_id,
	// version, and mode so "is it protecting me?" is answerable from a
	// present heartbeat instead of inferred from passthrough absence.
	EventProxyHeartbeat = "proxy.heartbeat"

	// EventPolicyModeChanged is the enforce-vs-monitor transition signal
	// (WS4 #2). Emitted on any policy mode change with {from, to, rule_id,
	// candidates}. SHARED CONTRACT: the product UI builds against this exact
	// name and field set — do not rename.
	EventPolicyModeChanged = "policy.mode.changed"

	// Install guard (free local-first wrapper; D-NUDGE). Emitted from the
	// CLI guard path on every run; the block event carries the identifying
	// package payload when refusal sharing is enabled (default-on, opt-out).
	EventInstallGuardScan            = "install.guard.scan"
	EventInstallGuardBlock           = "install.guard.block"
	EventInstallGuardActivated       = "install.guard.activated"
	EventInstallGuardNudgeShown      = "install.guard.nudge_shown"
	EventInstallGuardNudgeSuppressed = "install.guard.nudge_suppressed"
	EventInstallGuardDailyActive     = "install.guard.daily_active"
)

// registry is the set of known event names. Kept in sync with events.yaml
// by CI. Validate() checks membership before any event is emitted so we
// never ship a typo into PostHog's immutable event catalog.
var registry = map[string]struct{}{
	EventWebPageViewed:    {},
	EventWebOrgFirstLogin: {},
	EventWebActionFirst:   {},

	EventLandingCTAClicked:              {},
	EventLandingProcurementKitRequested: {},

	EventAPISignupStarted:           {},
	EventAPISignupVerified:          {},
	EventAPIOrgCreated:              {},
	EventAPIPersonaSet:              {},
	EventAPIPaywallHit:              {},
	EventAPIUpgradeClicked:          {},
	EventAPICheckoutStarted:         {},
	EventAPISubscriptionCreated:     {},
	EventAPISSOConfigured:           {},
	EventAPISIEMWebhookAdded:        {},
	EventAPISCIMEnabled:             {},
	EventAPITeammateInvited:         {},
	EventAPIDeviceCodeApproved:      {},
	EventAPIOnboardingStepCompleted: {},
	EventAPIDormancyFlagged:         {},

	EventAPISubscriptionCanceled:   {},
	EventAPISubscriptionUpgraded:   {},
	EventAPISubscriptionDowngraded: {},
	EventAPIPaymentFailed:          {},

	EventAPIScanCompleted:    {},
	EventAPIScanMalwareFound: {},

	EventCLISessionStarted:       {},
	EventCLISessionCompleted:     {},
	EventCLIAuthDeviceStarted:    {},
	EventCLIAuthDeviceApproved:   {},
	EventCLIAuthDeviceFailed:     {},
	EventCLIAuthBrowserStarted:   {},
	EventCLIAuthLogout:           {},
	EventCLISetupCompleted:       {},
	EventCLISetupAbandoned:       {},
	EventCLIIntroduceShown:       {},
	EventCLIScanCompleted:        {},
	EventCLIPolicyCreated:        {},
	EventCLIPolicyUpdated:        {},
	EventCLIPolicyDeleted:        {},
	EventCLIPolicyListed:         {},
	EventCLIPolicySimulated:      {},
	EventCLIPkgInspected:         {},
	EventCLISbomGenerated:        {},
	EventCLIDoctorRun:            {},
	EventCLIInstallHookInstalled: {},
	EventCLIInstallHookRemoved:   {},
	EventCLIPolicyFlippedToBlock: {},
	EventCLIPolicyPreflight:      {},
	EventCLIDoctorUpgradeCheck:   {},
	EventCLIDoctorBypassCheck:    {},
	EventCLIDoctorVerifyHook:     {},
	EventCLIErrorUnexpected:      {},

	EventMCPSessionInitialized: {},
	EventMCPToolInvoked:        {},
	EventMCPToolCompleted:      {},
	EventMCPToolFailed:         {},
	EventMCPResourceRead:       {},
	EventMCPResourceListed:     {},
	EventMCPSuggestionEmitted:  {},
	EventMCPSuggestionFollowed: {},

	EventProxyPackageBlocked:           {},
	EventProxyPackageAllowed:           {},
	EventProxyPackagePassthrough:       {},
	EventProxyPackageDenied:            {},
	EventProxyEcosystemFirstSeen:       {},
	EventProxySbomIngested:             {},
	EventProxyMalwareDetected:          {},
	EventProxyVulnCriticalFound:        {},
	EventProxyRollupHourly:             {},
	EventProxyHealthDegraded:           {},
	EventProxyActivationFirstBlock:     {},
	EventProxyActivationConfigVerified: {},
	EventProxyConversionFirstRefusal:   {},
	EventProxyBypassSuspected:          {},
	EventProxyConfigRejected:           {},
	EventProxyRequestFailed:            {},
	EventProxyHeartbeat:                {},

	EventPolicyModeChanged: {},

	EventInstallGuardScan:            {},
	EventInstallGuardBlock:           {},
	EventInstallGuardActivated:       {},
	EventInstallGuardNudgeShown:      {},
	EventInstallGuardNudgeSuppressed: {},
	EventInstallGuardDailyActive:     {},
}

// IsKnownEvent reports whether name is a registered event. Used by the
// ingest handler and the lint tool. False for an empty string.
func IsKnownEvent(name string) bool {
	if name == "" {
		return false
	}
	_, ok := registry[name]
	return ok
}

// KnownEvents returns a snapshot copy of the event registry. Order is not
// specified. Used by `chainsaw telemetry status` to print the catalog.
func KnownEvents() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	return out
}
