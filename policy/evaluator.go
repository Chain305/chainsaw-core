package policy

import (
	"context"
	"log/slog"
	"net/netip"
	"path"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

// EvaluationContext captures the request context for policy evaluation.
type EvaluationContext struct {
	Repository        string
	RepositoryFormat  string // ecosystem format (npm, pypi, cargo, …) — enables proxy-matrix skip auditing
	PackageName       string
	PackageVersion    string
	ClientID          string
	ClientGroups      []string
	RequestingIP      string
	RequestingCountry string

	// Package metadata
	IsInternalPackage bool
	// PackageReleaseDate is when the PACKAGE was first published (creation).
	PackageReleaseDate *time.Time
	// VersionReleaseDate is when THIS VERSION was published — distinct from
	// PackageReleaseDate. Cooldown gates on this: a poisoned new version of an
	// old package (Axios-class account-takeover) has a young VersionReleaseDate
	// but an old PackageReleaseDate, so package-age would miss it.
	VersionReleaseDate *time.Time
	LicenseSPDX        string

	// Vulnerability metadata
	IsVulnerable bool
	CVSSScore    float64
	EPSSScore    float64
	CVEs         []string

	// Supply chain integrity metadata
	HasProvenance        bool   // true if provenance attestation was verified
	ProvenanceStatus     string // "verified", "missing", "unavailable", "failed"
	IsSuspectedTyposquat bool   // true if flagged by typosquat detection
	IsKnownMalicious     bool   // true if in OpenSSF malware database
	TrustScore           int    // composite trust score (0-100)
	PublisherChanged     bool   // true if the publisher set changed vs the most recent prior version

	// Attestation context fields. Populated by intelligence's
	// provenance provider from the verified ProvenanceSection. These
	// describe the SLSA / Sigstore claim that was verified — the
	// matchers against them (RequireSLSALevel, RequireBuilderID,
	// RequireSourceRepo, RequireTransparencyLog, ForbidCacheStale)
	// live on Conditions, NOT on intelligence — intelligence only
	// reports facts; enforcement is policy's job.
	SLSALevel                  int    // 0 when no verified attestation, 1-4 otherwise
	AttestationBuilderID       string // OIDC subject of the build (workflow URL)
	AttestationIssuer          string // OIDC issuer URL
	AttestationSourceRepo      string // canonicalised source repo URL from the cert
	AttestationTransparencyLog string // Rekor entry URL (empty for offline-signed)
	AttestationCacheStale      bool   // verification served from stale Sigstore cache

	// Install-script signals (static scan of the unpacked artifact).
	HasInstallScript           bool // true if a lifecycle script is declared in the package manifest
	InstallScriptFetchesRemote bool // true if the install-script body references curl/wget/fetch/subprocess/etc.

	// Version anomaly signals (PR 3). VersionAnomaly is the coarse bool:
	// true when the metadiff helper reported at least one flag against the
	// incoming version's history. VersionAnomalyFlags is the per-kind
	// breakdown (semver_regression, major_skip, timestamp_regression) that
	// a VersionAnomalyKinds policy condition intersects against.
	VersionAnomaly      bool
	VersionAnomalyFlags []string

	// Hidden Unicode payload metadata (PR 8). HasHiddenUnicode is the
	// bool signal — true when the scanner found at least
	// CHAINSAW_HIDDEN_UNICODE_THRESHOLD (default 1) suspect runes in the
	// artifact's text files. HiddenUnicodeKinds is the sorted union of
	// kinds observed for this version; used for the intersection match
	// against Conditions.HiddenUnicodeKinds.
	HasHiddenUnicode   bool
	HiddenUnicodeKinds []string

	// PublishVelocity24h is the count of distinct versions published in the
	// trailing 24h by any publisher that overlaps with the incoming version's
	// publisher set. Populated by the orchestrator at sync time; the evaluator
	// compares it against the policy-configured threshold (default 20).
	PublishVelocity24h int

	// Socket-gap Wave 1 context fields.
	// LicenseTags is the result of risk.Classify over the declared
	// license expression. Empty slice = not yet classified; signals
	// that depend on these tags stay dormant.
	LicenseTags []string

	DeprecatedByMaintainer bool
	ShrinkwrapPresent      bool
	ManifestConfusion      bool

	// Socket-gap Wave 2 context fields. Computed from the parsed
	// dep-specifier list in internal/formats/depspec/ and populated
	// by the manifest-hygiene intelligence provider. Nil state
	// (false) means the manifest wasn't parsed (non-registry
	// request, binary-only ecosystem, or empty manifest).
	GitDependency           bool
	HTTPTarballDependency   bool
	WildcardDependencyRange bool
	BadDependencySemver     bool

	// Socket-gap Wave 3 context fields. Each mirrors the per-scanner
	// bool on ArtifactScanSection, hydrated by the providers in
	// internal/intelligence/provider_codesmell.go.
	UsesEval            bool
	NetworkAccess       bool
	ShellAccess         bool
	FilesystemAccess    bool
	EnvVarAccess        bool
	NativeBinaryPresent bool
	HighEntropyStrings  bool
	URLStrings          bool
	MinifiedCode        bool

	// Socket-gap Wave 4 context fields. TrivialPackage / TooManyFiles
	// ride the Wave-0 artifact map and are populated deterministically
	// from the scanner. The three RTT signals are feature-flagged OFF
	// by default; see internal/intelligence for the env-var gates.
	TrivialPackage    bool
	TooManyFiles      bool
	NonExistentAuthor bool
	// FirstTimeCollaborator is three-state. nil = no prior-uploader
	// history available (sparse-data, ecosystem unsupported, RTT signal
	// disabled). &true = uploader has not published this package
	// before. &false = uploader has prior history. Preserving nil at
	// the policy boundary lets rules express "warn on unknown" without
	// conflating it with confirmed-not-first-time.
	FirstTimeCollaborator *bool
	SuspiciousRepoStars   bool

	// MaintainerAccountAgeDays is the minimum publisher/maintainer
	// account age (in days) observed across the People section of the
	// merged Report. -1 sentinel means "no age signal available" — a
	// MaintainerAccountAgeDaysMax condition with a -1 context value
	// stays inert (does not fire) so an unreachable upstream cannot
	// silently block traffic.
	MaintainerAccountAgeDays int

	// AI artifact context fields. Populated by provider_pickle,
	// provider_modelcard, and provider_agenttool. ArtifactSubtype
	// mirrors the request's subtype tag (model / dataset / space /
	// agent-tool / mcp-server / prompt-template) for policy authors
	// who want to scope rules to specific AI artifact classes.
	ArtifactSubtype              string
	DangerousPickle              bool
	UnsafeSerializationFormat    bool
	ModelCardInjection           bool
	AgentToolDangerousCapability bool
	MCPServerDeclared            bool
	PromptTemplateInjection      bool

	// ChecksumUnavailable is true when chainsaw could not derive a
	// registry-declared hash for this artifact (go modules, legacy
	// packages). Policy conditions that depend on hash-driven
	// signals (isVulnerable, hasProvenance) fire
	// SkipReasonChecksumUnavailable for operator visibility — see
	// internal/checksum/enforcer.go.
	ChecksumUnavailable bool

	// OrgID is used to tag skip-audit events; best-effort, may be empty.
	OrgID string
}

// DefaultPublishVelocityThreshold24h is the threshold applied when a policy
// sets PublishVelocityAnomaly=true but leaves PublishVelocityThreshold24h nil.
// Chosen to match Shai-Hulud style worm bursts (hundreds of publishes per
// day) while tolerating normal active maintainers.
const DefaultPublishVelocityThreshold24h = 20

// SkipAuditEvent records a single silently-inert policy rule that the
// evaluator would otherwise have applied. When a rule's condition is ❌ for
// the context's ecosystem (per the proxy compatibility matrix), we log it and
// emit one of these events so operators can see the silent no-op.
type SkipAuditEvent struct {
	OrgID     string
	PolicyID  string
	Ecosystem string
	Condition string
	// Reason is the enum reason this rule was inert. See the
	// SkipReason* constants; callers should not invent new values
	// without also updating the evaluator_supplychain_test enum
	// check.
	Reason string
}

// Skip-audit reason enum. Adding a new reason requires also teaching
// the evaluator_supplychain_test.go enumeration check so downstream
// audit sinks (audit_events rows, UI facet) learn about it.
const (
	// SkipReasonUnsupportedEcosystem fires when a policy condition is
	// ❌ for the request's ecosystem per the proxy compatibility
	// matrix — historically the only reason.
	SkipReasonUnsupportedEcosystem = "unsupported_ecosystem"
	// SkipReasonChecksumUnavailable fires when a policy whose
	// evaluation depends on checksum integrity (isVulnerable or
	// hasProvenance tied to the declared-hash path) cannot be decided
	// because upstream advertised no declared hash. Distinct from
	// checksum_mismatch, which is a real failure; this is "no signal
	// to act on". See internal/checksum/enforcer.go and the PR-12
	// patch in internal/server/checksum_enforce.go.
	SkipReasonChecksumUnavailable = "checksum_unavailable"
)

// SkipAuditor receives skip events. Implementations must be safe for
// concurrent use (Evaluator is called from per-request goroutines).
type SkipAuditor interface {
	RecordPolicyRuleSkipped(ctx context.Context, ev SkipAuditEvent)
}

// SkipAuditorFunc adapts a function to the SkipAuditor interface.
type SkipAuditorFunc func(ctx context.Context, ev SkipAuditEvent)

// RecordPolicyRuleSkipped implements SkipAuditor.
func (f SkipAuditorFunc) RecordPolicyRuleSkipped(ctx context.Context, ev SkipAuditEvent) {
	if f == nil {
		return
	}
	f(ctx, ev)
}

// EvaluationResult represents the outcome of policy evaluation.
type EvaluationResult struct {
	Action        Mode    // allow, block, quarantine
	MatchedPolicy *Policy // the policy that matched
	Reason        string
}

// Evaluator evaluates policies against request contexts.
type Evaluator struct {
	store         *Store
	auditor       SkipAuditor
	logger        *slog.Logger
	cache         *evalCache
	bypassChecker BypassQuarantineChecker
	grace         *graceMode
}

// NewEvaluator creates a new policy evaluator.
func NewEvaluator(store *Store) *Evaluator {
	return &Evaluator{store: store}
}

// ReasonBypassSuspected is the marker string injected into
// EvaluationResult.Reason when a request originates from a client_id
// the operator has confirmed as a bypass-quarantine subject (D.12).
//
// The injection is ADDITIVE — it never flips the engine's verdict from
// allow to block on its own. It rides alongside whatever the engine
// decided so audit, telemetry, and webhook payloads carry the flag.
// Operators escalate from "suspected" to "block" via policy authoring,
// not via this hook. See internal/server/bypass_reports_api.go.
const ReasonBypassSuspected = "BYPASS_SUSPECTED"

// BypassQuarantineChecker reports whether a (org, client) pair is on
// the bypass-quarantine list (i.e. has at least one bypass_reports row
// with status='confirmed'). Implementations must be safe for concurrent
// use; the policy hot path will call this once per evaluation.
//
// The interface lives here, but the only production implementation
// lives in internal/server/bypass_reports_api.go (IsBypassQuarantined),
// so the policy package stays free of the database/sql dependency.
type BypassQuarantineChecker interface {
	IsBypassQuarantined(ctx context.Context, orgID, clientID string) bool
}

// BypassQuarantineCheckerFunc adapts a function to the
// BypassQuarantineChecker interface — mirrors the SkipAuditorFunc
// pattern above so the server can plug a closure directly without
// declaring a new struct.
type BypassQuarantineCheckerFunc func(ctx context.Context, orgID, clientID string) bool

// IsBypassQuarantined implements BypassQuarantineChecker.
func (f BypassQuarantineCheckerFunc) IsBypassQuarantined(ctx context.Context, orgID, clientID string) bool {
	if f == nil {
		return false
	}
	return f(ctx, orgID, clientID)
}

// WithBypassQuarantineChecker wires a quarantine checker that the
// evaluator consults after a verdict is produced. When the checker
// reports the request's (OrgID, ClientID) as quarantined, the
// evaluator stamps ReasonBypassSuspected into the result Reason
// additively — the engine's Action is preserved verbatim.
//
// Passing a nil checker disables the hook (matches the default
// pre-D.12 behaviour).
func (e *Evaluator) WithBypassQuarantineChecker(c BypassQuarantineChecker) *Evaluator {
	if e == nil {
		return nil
	}
	e.bypassChecker = c
	return e
}

// GraceModeFlagChecker reports whether the `policy_grace_mode` feature
// flag is ON for an org. Injected so the policy package stays free of
// the featureflags / PostHog dependency — the server wires a closure
// over its *featureflags.Client (see wirePolicyGraceMode in
// internal/server/policy_support_matrix.go). A nil checker (or a nil
// grace config) is treated as flag-OFF, which is the safe default:
// ModeBlockAfterGrace then evaluates as a plain block.
type GraceModeFlagChecker interface {
	GraceModeEnabled(orgID string) bool
}

// GraceModeFlagCheckerFunc adapts a function to GraceModeFlagChecker.
type GraceModeFlagCheckerFunc func(orgID string) bool

// GraceModeEnabled implements GraceModeFlagChecker.
func (f GraceModeFlagCheckerFunc) GraceModeEnabled(orgID string) bool {
	if f == nil {
		return false
	}
	return f(orgID)
}

// PreexistingChecker reports whether a package coordinate was already
// observed for an org BEFORE the cutoff instant. "Observed before T"
// means there is at least one prior `events` row for (org, repo,
// package) with a timestamp earlier than the policy's created_at — i.e.
// the dependency predates the policy and so qualifies for the grace
// window. The lookup is injected (not hard-coupled to database/sql) so
// the policy package keeps its existing dependency shape; the server
// supplies the events-table query.
//
// Implementations MUST be safe for concurrent use (called from the
// per-request hot path) and SHOULD fail CLOSED — when the lookup cannot
// be answered (DB error, missing wiring) it must return false so an
// unknown package is treated as "not pre-existing" and therefore stays
// BLOCKED. Never weaken a block on a lookup failure.
type PreexistingChecker interface {
	SeenBefore(ctx context.Context, orgID, repository, packageName string, before time.Time) bool
}

// PreexistingCheckerFunc adapts a function to PreexistingChecker.
type PreexistingCheckerFunc func(ctx context.Context, orgID, repository, packageName string, before time.Time) bool

// SeenBefore implements PreexistingChecker.
func (f PreexistingCheckerFunc) SeenBefore(ctx context.Context, orgID, repository, packageName string, before time.Time) bool {
	if f == nil {
		return false
	}
	return f(ctx, orgID, repository, packageName, before)
}

// graceMode bundles the two injected collaborators for Item-3b. Both
// must be non-nil for the downgrade path to ever run; otherwise the
// evaluator treats ModeBlockAfterGrace as a plain block.
type graceMode struct {
	flag        GraceModeFlagChecker
	preexisting PreexistingChecker
}

// WithGraceMode wires the Item-3b (ADR-008) grace-window collaborators:
// a flag checker (`policy_grace_mode`, default OFF) and a "seen before
// T" lookup against the org's events history. Both are required for the
// downgrade to fire — passing a nil for either disables the feature
// (ModeBlockAfterGrace then evaluates as a plain block), matching the
// rollback-safe default. Returns the same Evaluator for chaining.
//
// The downgrade this enables is STRICTLY a block→monitor relaxation for
// a ModeBlockAfterGrace policy whose package is (a) pre-existing and (b)
// inside the grace window. It NEVER touches a ModeBlock policy and is
// suppressed for known-malicious / vulnerable packages, so it cannot
// weaken a malware/vuln block (the keystone invariant).
func (e *Evaluator) WithGraceMode(flag GraceModeFlagChecker, preexisting PreexistingChecker) *Evaluator {
	if e == nil {
		return nil
	}
	if flag == nil || preexisting == nil {
		e.grace = nil
		return e
	}
	e.grace = &graceMode{flag: flag, preexisting: preexisting}
	return e
}

// WithEvalCache enables in-memory memoisation of evaluation results
// keyed on (org, repo, package, version). ttl <= 0 applies
// DefaultEvalCacheTTL. Passing a zero-value / disabled cache is safe:
// nil cache keeps the original every-request walk, matching pre-cache
// behaviour.
func (e *Evaluator) WithEvalCache(ttl time.Duration) *Evaluator {
	if e == nil {
		return nil
	}
	e.cache = newEvalCache(ttl)
	return e
}

// InvalidateCache drops every memoised evaluation. Safe to call when
// caching is disabled. The policy-update publisher in invalidation.go
// should route incoming invalidations here — either directly, or
// through the existing Subscriber callback that already fans out to
// the CachedStore.
func (e *Evaluator) InvalidateCache() {
	if e == nil {
		return
	}
	e.cache.Invalidate()
}

// InvalidateCacheForOrg drops memoised evaluations belonging to orgID.
// Matches the per-org shape of invalidateSubjectFor in invalidation.go
// so a Subscriber can forward orgIDs verbatim.
func (e *Evaluator) InvalidateCacheForOrg(orgID string) {
	if e == nil {
		return
	}
	e.cache.InvalidateOrg(orgID)
}

// evalMetricsRecorder is a package-level callback the observability
// wiring installs via SetEvalMetricsRecorder. It receives the
// user-visible evaluation result ("allow", "block", "error") and is
// called exactly once per Evaluate/EvaluateWithPolicies invocation.
// nil is a no-op so tests and metrics-disabled builds are unaffected.
var evalMetricsRecorder func(result string)

// conditionFireRecorder is a sibling callback for the per-condition
// fires counter. Called once per evaluation that matched a policy
// driven by exactly one condition — the condition label is the
// ConditionType name (bounded by the proxy-matrix enum, so cardinality
// stays small). Evaluations driven by zero or multiple conditions do
// not emit here; only the aggregate chainsaw_policy_eval_total fires.
var conditionFireRecorder func(condition, result string)

// SetEvalMetricsRecorder installs (or clears) the package-level
// evaluation metrics recorder. Intended to be called once at process
// startup from cmd/chainsaw-proxy/init_server.go after the Prometheus
// Metrics struct is constructed. Pass nil to disable.
func SetEvalMetricsRecorder(rec func(result string)) {
	evalMetricsRecorder = rec
}

// SetConditionFireRecorder installs (or clears) the per-condition
// fires recorder. Intended to be called once at process startup from
// cmd/chainsaw-proxy/init_server.go alongside SetEvalMetricsRecorder.
// Pass nil to disable.
func SetConditionFireRecorder(rec func(condition, result string)) {
	conditionFireRecorder = rec
}

// recordEvalResult routes a user-visible evaluation result to the
// installed recorder. Safe for nil.
func recordEvalResult(result string) {
	rec := evalMetricsRecorder
	if rec == nil {
		return
	}
	rec(result)
}

// recordConditionFire routes a per-condition fire to the installed
// recorder. Only called when the matched policy was driven by exactly
// one condition — callers must enforce that gate. Safe for nil.
func recordConditionFire(condition ConditionType, result string) {
	rec := conditionFireRecorder
	if rec == nil {
		return
	}
	rec(string(condition), result)
}

// WithSkipAuditor wires an auditor that will receive a `policy.rule.skipped`
// event whenever a rule's condition is ❌ for the request's ecosystem per the
// proxy compatibility matrix. Returns the same Evaluator for chaining.
func (e *Evaluator) WithSkipAuditor(a SkipAuditor) *Evaluator {
	if e == nil {
		return nil
	}
	e.auditor = a
	return e
}

// WithLogger wires a slog.Logger the evaluator will use to emit INFO-level
// log lines when a rule is skipped due to an unsupported ecosystem.
func (e *Evaluator) WithLogger(l *slog.Logger) *Evaluator {
	if e == nil {
		return nil
	}
	e.logger = l
	return e
}

// Evaluate runs policy evaluation against the provided context.
// exceptionAgeDays controls how long exception policies (allow + isVulnerable)
// remain active. Zero disables expiry.
func (e *Evaluator) Evaluate(ctx EvaluationContext, exceptionAgeDays int) (EvaluationResult, error) {
	if e == nil || e.store == nil {
		recordEvalResult("allow")
		return EvaluationResult{Action: ModeAllow, Reason: "no policy store"}, nil
	}

	key, keyable := evalCacheKeyFor(ctx)
	if e.cache != nil && keyable {
		if cached, ok := e.cache.Get(key); ok {
			recordEvalResult(evalResultLabel(cached.Action))
			recordConditionFireIfSingle(cached)
			// Bypass-quarantine status is keyed on ClientID, which is
			// deliberately absent from the eval cache key — so the
			// cached row never carries a stamped BYPASS_SUSPECTED. Re-
			// apply the hook against the live (org, client) pair on
			// every cache hit so a confirmed bypass takes effect within
			// one request, not one cache TTL.
			cached = e.applyBypassQuarantine(ctx, cached)
			return cached, nil
		}
	}

	policies, err := e.store.List()
	if err != nil {
		recordEvalResult("error")
		return EvaluationResult{Action: ModeAllow, Reason: "policy fetch failed"}, err
	}

	result := e.evaluatePolicies(ctx, policies, exceptionAgeDays)
	if e.cache != nil && keyable {
		// Cache the pre-bypass result so a confirmed bypass on one
		// client_id doesn't leak its BYPASS_SUSPECTED stamp into other
		// clients hitting the same (org, repo, pkg, version) tuple.
		e.cache.Put(key, result)
	}
	result = e.applyBypassQuarantine(ctx, result)
	recordEvalResult(evalResultLabel(result.Action))
	recordConditionFireIfSingle(result)
	return result, nil
}

// evalCacheKeyFor builds the cache key for ctx. Returns keyable=false
// when any load-bearing identifier is empty — caching an "unknown
// package" decision would give a single stale verdict to every
// miss-request that happens to lack a version.
func evalCacheKeyFor(ctx EvaluationContext) (cacheKey, bool) {
	if ctx.PackageName == "" || ctx.PackageVersion == "" {
		return cacheKey{}, false
	}
	return cacheKey{
		OrgID:       ctx.OrgID,
		Repo:        ctx.Repository,
		PackageName: ctx.PackageName,
		Version:     ctx.PackageVersion,
	}, true
}

// EvaluateWithPolicies runs policy evaluation using a pre-fetched policy list,
// avoiding a database round-trip. The policies must already be sorted by
// precedence ascending (as returned by Store.List or CachedStore.ListPolicies).
func (e *Evaluator) EvaluateWithPolicies(ctx EvaluationContext, policies []Policy, exceptionAgeDays int) EvaluationResult {
	result := e.evaluatePolicies(ctx, policies, exceptionAgeDays)
	result = e.applyBypassQuarantine(ctx, result)
	recordEvalResult(evalResultLabel(result.Action))
	recordConditionFireIfSingle(result)
	return result
}

// applyBypassQuarantine additively stamps ReasonBypassSuspected into
// result.Reason when the (OrgID, ClientID) pair is confirmed on the
// bypass quarantine list. The injection NEVER changes result.Action —
// per the D.12 contract, bypass detection is observation+alerting, not
// enforcement. Operators escalate by authoring policy that targets the
// client_id, not by repurposing this hook.
//
// Safe to call with a nil evaluator or nil checker (no-op). When the
// reason is empty (typical ALLOW path) the stamp becomes the sole
// reason; otherwise it is appended after a separator so the original
// engine-produced reason remains greppable.
func (e *Evaluator) applyBypassQuarantine(ctx EvaluationContext, result EvaluationResult) EvaluationResult {
	if e == nil || e.bypassChecker == nil {
		return result
	}
	if ctx.OrgID == "" || ctx.ClientID == "" {
		return result
	}
	if !e.bypassChecker.IsBypassQuarantined(context.Background(), ctx.OrgID, ctx.ClientID) {
		return result
	}
	if result.Reason == "" {
		result.Reason = ReasonBypassSuspected
	} else if !strings.Contains(result.Reason, ReasonBypassSuspected) {
		// Append, don't overwrite — the engine's reason is the primary
		// signal; BYPASS_SUSPECTED is a secondary flag riding alongside.
		result.Reason = result.Reason + "; " + ReasonBypassSuspected
	}
	return result
}

// recordConditionFireIfSingle emits chainsaw_policy_condition_fires_total
// for matched-policy evaluations whose policy was driven by exactly one
// condition. Zero-condition (identifier/scope-only) and multi-condition
// policies are deliberately skipped — attributing a fire to "the
// condition that caused it" is ambiguous when multiple conditions
// combined, and emitting under every label would explode cardinality.
func recordConditionFireIfSingle(result EvaluationResult) {
	if result.MatchedPolicy == nil {
		return
	}
	used := ConditionsUsedBy(result.MatchedPolicy.Conditions)
	if len(used) != 1 {
		return
	}
	recordConditionFire(used[0], evalResultLabel(result.Action))
}

// evalResultLabel maps an evaluation Mode to the prometheus label value
// for chainsaw_policy_eval_total{result}. ModeBlock and ModeQuarantine
// both represent deny outcomes for the request, so they share the
// "block" label; ModeMonitor is a pass-through that logs but lets the
// request proceed, so it counts as "allow" for this metric. Unknown
// modes also fall back to "allow" so no eval goes unrecorded.
func evalResultLabel(m Mode) string {
	switch m {
	case ModeBlock, ModeQuarantine:
		return "block"
	case ModeAllow, ModeMonitor:
		return "allow"
	default:
		return "allow"
	}
}

// IsExpiredException returns true when the policy is an exception (allow mode
// with isVulnerable condition, OR Kind=KindException) and has exceeded its
// expiry. A non-nil, non-zero ExpiresAt on the policy wins; otherwise the
// createdAt + ageDays computation runs (ageDays==0 disables the legacy
// fallback so a policy whose ExpiresAt is unset never auto-expires).
//
// Zero-time ExpiresAt semantics: a non-nil pointer whose value is time.Time{}
// (Go zero, "0001-01-01T00:00:00Z") is treated as "no expiry configured",
// identically to a nil pointer. This matches the Postgres NULL → pgx round-
// trip convention and prevents the chain305.com smoke regression where a
// freshly-created exception with no expires_at / expires_in_days hint was
// filtered out of the decision path because the zero-time pointer was read
// as "expired in year 1" by callers comparing now.After(*p.ExpiresAt). See
// internal/server/exception_bypass_e2e_test.go::
// TestExceptionWithoutExpiryBypassesBlock for the regression coverage.
func IsExpiredException(p Policy, ageDays int, now time.Time) bool {
	if p.Mode != ModeAllow {
		return false
	}
	// Per-row expiry override (set via the /api/exceptions create body
	// or `chainsaw exception create --expires-at|--days`). When set to
	// a real future/past timestamp, it is authoritative — the org
	// ExceptionAge default is ignored. A nil pointer OR a pointer-to-
	// zero-time falls through to the legacy ageDays-based logic below
	// (which itself returns false when ageDays<=0). Treating zero-time
	// as "never expires" — instead of "expired in year 1" — is what
	// keeps exceptions created without an explicit expiry from being
	// silently dropped by the evaluator.
	if p.ExpiresAt != nil && !p.ExpiresAt.IsZero() {
		return now.After(*p.ExpiresAt)
	}
	// Legacy fallback. Exception discriminator widened in this fix to
	// accept Kind=KindException so the new exception shape (which does
	// NOT carry IsVulnerable=true) still ages out under the org default.
	isException := p.Kind == KindException ||
		(p.Conditions.IsVulnerable != nil && *p.Conditions.IsVulnerable)
	if !isException {
		return false
	}
	if ageDays <= 0 {
		return false
	}
	return now.Sub(p.CreatedAt) > time.Duration(ageDays)*24*time.Hour
}

func (e *Evaluator) evaluatePolicies(ctx EvaluationContext, policies []Policy, exceptionAgeDays int) EvaluationResult {
	now := time.Now()
	for _, policy := range policies {
		if policy.Status != StatusEnabled {
			continue
		}

		if IsExpiredException(policy, exceptionAgeDays, now) {
			continue
		}

		// Proxy-matrix guard: if this rule references a condition that the
		// ecosystem proxy doesn't populate, emit a skip audit event and move
		// on. Matching would silently never fire otherwise — operators need
		// a signal to catch misconfiguration.
		if skipped := e.detectUnsupported(ctx, policy); len(skipped) > 0 {
			e.recordSkipped(ctx, policy, skipped, SkipReasonUnsupportedEcosystem)
			continue
		}

		// PR 12: if the upstream couldn't give us a declared hash, any
		// policy whose decision depends on integrity signals (isVulnerable,
		// hasProvenance) would evaluate against potentially-tampered
		// metadata. We emit a distinct skip reason so operators can
		// distinguish "no signal" from "real mismatch" without grepping
		// logs.
		if ctx.ChecksumUnavailable {
			if skipped := detectChecksumUnavailable(ctx, policy); len(skipped) > 0 {
				e.recordSkipped(ctx, policy, skipped, SkipReasonChecksumUnavailable)
				continue
			}
		}

		if matches := e.matchesPolicy(ctx, policy); matches {
			action, reason := e.resolveAction(ctx, policy, now)
			return EvaluationResult{
				Action:        action,
				MatchedPolicy: &policy,
				Reason:        reason,
			}
		}
	}

	return EvaluationResult{Action: ModeAllow, Reason: "no matching policy"}
}

// resolveAction maps a matched policy's authored Mode to the action the
// evaluator actually returns. For every mode except ModeBlockAfterGrace
// this is the identity (action == policy.Mode, reason == buildReason).
//
// ModeBlockAfterGrace (Item-3b, ADR-008) is the sole exception and is
// resolved with rollback-safe, keystone-preserving precedence:
//
//  1. Default (flag OFF, no grace wiring, or any precondition unmet):
//     map to a plain ModeBlock. This is the byte-for-byte-identical
//     flag-off behaviour — an un-flagged deploy of a block_after_grace
//     policy enforces exactly like a block.
//  2. Keystone guard: if the package is known-malicious OR vulnerable,
//     stay BLOCKED even with the flag ON and the package in-grace. An
//     in-grace package can therefore NEVER bypass a malware/vuln block.
//  3. Downgrade (flag ON, package pre-existing AND inside the grace
//     window): relax block→monitor so the request proceeds while the
//     operator remediates. Outside the window, or for a brand-new
//     (not pre-existing) package, stay BLOCKED.
//
// The "pre-existing" lookup fails closed (see PreexistingChecker): a
// lookup error yields "not pre-existing" → BLOCK.
func (e *Evaluator) resolveAction(ctx EvaluationContext, policy Policy, now time.Time) (Mode, string) {
	if policy.Mode != ModeBlockAfterGrace {
		return policy.Mode, buildReason(policy)
	}

	// (1) Flag OFF / no wiring → plain block. Default-safe.
	if e == nil || e.grace == nil || e.grace.flag == nil || e.grace.preexisting == nil ||
		!e.grace.flag.GraceModeEnabled(ctx.OrgID) {
		return ModeBlock, blockAfterGraceReason(policy, "block")
	}

	// (2) Keystone guard: malware / vuln always blocks, no downgrade.
	if ctx.IsKnownMalicious || ctx.IsVulnerable {
		return ModeBlock, blockAfterGraceReason(policy, "block")
	}

	// (3) Downgrade only when pre-existing AND inside the grace window.
	graceDays := policy.EffectiveGraceDays()
	windowEnd := policy.CreatedAt.Add(time.Duration(graceDays) * 24 * time.Hour)
	if !now.Before(windowEnd) {
		// Grace window has elapsed → enforce.
		return ModeBlock, blockAfterGraceReason(policy, "block")
	}
	seenBefore := e.grace.preexisting.SeenBefore(
		context.Background(), ctx.OrgID, ctx.Repository, ctx.PackageName, policy.CreatedAt)
	if !seenBefore {
		// New package (first seen at/after the policy) → enforce.
		return ModeBlock, blockAfterGraceReason(policy, "block")
	}
	// Pre-existing + in-window + not malware/vuln → grace downgrade.
	return ModeMonitor, blockAfterGraceReason(policy, "monitor")
}

// detectUnsupported returns the condition columns this policy uses that are
// ❌ for the request's ecosystem. Empty when RepositoryFormat is unset
// (caller hasn't opted in) or when every used column is ✅/⚠️.
func (e *Evaluator) detectUnsupported(ctx EvaluationContext, p Policy) []ConditionType {
	if ctx.RepositoryFormat == "" {
		return nil
	}
	eco := EcosystemForFormat(strings.ToLower(strings.TrimSpace(ctx.RepositoryFormat)))
	if eco == "" {
		return nil
	}
	used := ConditionsUsedBy(p.Conditions)
	if len(used) == 0 {
		return nil
	}
	var unsupported []ConditionType
	for _, cond := range used {
		if IsUnsupported(eco, cond) {
			unsupported = append(unsupported, cond)
		}
	}
	return unsupported
}

// detectChecksumUnavailable returns the conditions whose evaluation
// depends on checksum-derived signals when the context reports no
// declared hash. Currently isVulnerable (maps to ConditionCVE in the
// proxy compatibility matrix) and hasProvenance — both chain back
// through supply-chain integrity to the artifact bytes. Returns
// empty when ChecksumUnavailable is false or the policy uses neither
// condition.
func detectChecksumUnavailable(_ EvaluationContext, p Policy) []ConditionType {
	var affected []ConditionType
	if p.Conditions.IsVulnerable != nil {
		// isVulnerable is reported under ConditionCVE in
		// proxy_matrix.go (see ConditionsUsedBy) — mirror that here
		// so downstream audit sinks see a consistent condition name.
		affected = append(affected, ConditionCVE)
	}
	if p.Conditions.HasProvenance != nil {
		affected = append(affected, ConditionHasProvenance)
	}
	return affected
}

// recordSkipped fires one audit event per (policy, unsupported condition) pair
// and logs at INFO level. Both auditor and logger are optional.
func (e *Evaluator) recordSkipped(ctx EvaluationContext, p Policy, conditions []ConditionType, reason string) {
	if strings.TrimSpace(reason) == "" {
		reason = SkipReasonUnsupportedEcosystem
	}
	eco := strings.ToLower(strings.TrimSpace(ctx.RepositoryFormat))
	for _, cond := range conditions {
		ev := SkipAuditEvent{
			OrgID:     ctx.OrgID,
			PolicyID:  p.ID,
			Ecosystem: eco,
			Condition: string(cond),
			Reason:    reason,
		}
		if e.auditor != nil {
			e.auditor.RecordPolicyRuleSkipped(context.Background(), ev)
		}
		if e.logger != nil {
			e.logger.Info("policy rule skipped",
				"event", "policy.rule.skipped",
				"policy_id", ev.PolicyID,
				"ecosystem", ev.Ecosystem,
				"condition", ev.Condition,
				"reason", ev.Reason,
				"package", ctx.PackageName,
			)
		}
	}
}

func (e *Evaluator) matchesPolicy(ctx EvaluationContext, policy Policy) bool {
	// Check identifier match
	if !matchesIdentifier(ctx, policy.Identifier) {
		return false
	}

	// Check scope match
	if !matchesScope(ctx, policy.Scope) {
		return false
	}

	// KindException short-circuit. Exceptions are scoped allow-rules
	// (Mode=Allow) pinned to a specific (repo, package, version). They
	// MUST bypass any subsequent block-mode policy for that coordinate
	// regardless of condition state — that's the whole point. The old
	// shape required Conditions.IsVulnerable=true to also be set on
	// both sides, which silently caused malware-feed blocks (which fire
	// on IsKnownMalicious, not IsVulnerable) to ignore active
	// exceptions. See the smoke-evidence at qa/smoke-evidence/D51.
	if policy.Kind == KindException {
		return true
	}

	// Check conditions match
	if !matchesConditions(ctx, policy.Conditions) {
		return false
	}

	return true
}

func matchesIdentifier(ctx EvaluationContext, id Identifier) bool {
	// If all identifier fields are empty, it matches everything
	if id.TargetPackageName == "" && id.TargetPackageRepo == "" && id.TargetPackageVersion == "" {
		return true
	}

	// Check repository match
	if id.TargetPackageRepo != "" && !matchesPattern(ctx.Repository, id.TargetPackageRepo) {
		return false
	}

	// Check package name match
	if id.TargetPackageName != "" && !matchesPattern(ctx.PackageName, id.TargetPackageName) {
		return false
	}

	// Check version match (supports semver constraints)
	if id.TargetPackageVersion != "" && !matchesVersion(ctx.PackageVersion, id.TargetPackageVersion) {
		return false
	}

	return true
}

func matchesScope(ctx EvaluationContext, scope Scope) bool {
	// Empty scope means applies to all
	if len(scope.TargetClient) == 0 && len(scope.TargetGroup) == 0 &&
		len(scope.TargetRepos) == 0 && len(scope.TargetRequestingCountry) == 0 &&
		len(scope.TargetRequestingIP) == 0 {
		return true
	}

	// Check client match
	if len(scope.TargetClient) > 0 {
		if !contains(scope.TargetClient, ctx.ClientID) {
			return false
		}
	}

	// Check group match
	if len(scope.TargetGroup) > 0 {
		if !hasAnyIntersection(scope.TargetGroup, ctx.ClientGroups) {
			return false
		}
	}

	// Check repository match
	if len(scope.TargetRepos) > 0 {
		if !contains(scope.TargetRepos, ctx.Repository) {
			return false
		}
	}

	// Check requesting country match
	if len(scope.TargetRequestingCountry) > 0 {
		if !matchesCountryList(ctx.RequestingCountry, scope.TargetRequestingCountry) {
			return false
		}
	}

	// Check requesting IP match (supports CIDR)
	if len(scope.TargetRequestingIP) > 0 {
		if !matchesIPList(ctx.RequestingIP, scope.TargetRequestingIP) {
			return false
		}
	}

	return true
}

// one policy condition (CVSS, EPSS, KEV, license, capability, install-script,
// publish velocity, hidden-Unicode, typosquat, maintainer-takeover, etc.).
// Splitting by condition family would create a dispatch table with the same
// total branches plus indirection; the linear flat list is the easiest place
// for a non-Go reader to verify a single condition. TODO: extract by signal
// tier if/when condition count crosses 60.
//
//nolint:gocyclo // Cyclomatic complexity 133 (limit 76). Each branch matches
func matchesConditions(ctx EvaluationContext, cond Conditions) bool {
	// Ecosystem narrowing — short-circuits before any other matcher so
	// rules scoped to (e.g.) Tier-1 SLSA ecosystems never evaluate
	// against a request from a non-matching format. Empty list = any
	// ecosystem; an empty ctx.RepositoryFormat with a non-empty
	// allow-list cannot match (defensive: we never want a rule scoped
	// to "npm" to fire on a request whose format the proxy didn't
	// resolve).
	if len(cond.Ecosystems) > 0 {
		if !matchesEcosystemList(ctx.RepositoryFormat, cond.Ecosystems) {
			return false
		}
	}

	// Check vulnerability condition
	if cond.IsVulnerable != nil {
		if *cond.IsVulnerable != ctx.IsVulnerable {
			return false
		}
	}

	// Check package age condition (days since release)
	if cond.PackageAge != nil {
		if ctx.PackageReleaseDate == nil {
			return false
		}
		age := int(time.Since(*ctx.PackageReleaseDate).Hours() / 24)
		if age > *cond.PackageAge {
			return false
		}
	}

	// Cooldown: match VERSIONS published within the last CooldownDays days
	// (publish-age quarantine). Uses VersionReleaseDate (this version's publish
	// date), NOT PackageReleaseDate — an account-takeover poisons a NEW version
	// of an OLD package (Axios/Chalk/Mastra), so the version is young but the
	// package is old; gating on package age would miss it entirely. Malicious
	// versions are typically unpublished within hours, so a short window defeats
	// the zero-hour class. Missing version date fails the match (fail-open: we
	// don't quarantine when we can't confirm the age, to avoid blocking on
	// absent metadata).
	if cond.CooldownDays != nil {
		if ctx.VersionReleaseDate == nil {
			return false
		}
		versionAge := int(time.Since(*ctx.VersionReleaseDate).Hours() / 24)
		if versionAge > *cond.CooldownDays {
			return false
		}
	}

	// Check CVSS score conditions
	if cond.CVSSMin != nil && ctx.CVSSScore < *cond.CVSSMin {
		return false
	}
	if cond.CVSSMax != nil && ctx.CVSSScore > *cond.CVSSMax {
		return false
	}

	// Check EPSS score conditions
	if cond.EPSSMin != nil && ctx.EPSSScore < *cond.EPSSMin {
		return false
	}
	if cond.EPSSMax != nil && ctx.EPSSScore > *cond.EPSSMax {
		return false
	}

	// Check license condition
	if len(cond.PackageLicense) > 0 {
		if !matchesLicenseCondition(cond.PackageLicense, ctx.LicenseSPDX) {
			return false
		}
	}

	// Check provenance condition
	if cond.HasProvenance != nil {
		if *cond.HasProvenance != ctx.HasProvenance {
			return false
		}
	}

	// Attestation-first conditions. These compose against the same
	// HasProvenance bool above — a rule that asks for "SLSA L3 from
	// the slsa-github-generator built from github.com/foo/bar" reads
	// as four matchers AND'd together.

	// RequireAttestation is the convenience matcher used by the
	// seeded baseline policy. Equivalent to RequireSLSALevel=1 plus
	// HasProvenance=true.
	if cond.RequireAttestation != nil {
		hasVerifiedAttestation := ctx.HasProvenance && ctx.SLSALevel >= 1
		if *cond.RequireAttestation != hasVerifiedAttestation {
			return false
		}
	}
	if cond.RequireSLSALevel != nil {
		if ctx.SLSALevel < *cond.RequireSLSALevel {
			return false
		}
	}
	if len(cond.RequireBuilderID) > 0 {
		if !containsAnySubstring(ctx.AttestationBuilderID, cond.RequireBuilderID) {
			return false
		}
	}
	if len(cond.RequireBuilderIssuer) > 0 {
		if !containsAnySubstring(ctx.AttestationIssuer, cond.RequireBuilderIssuer) {
			return false
		}
	}
	if len(cond.RequireSourceRepo) > 0 {
		if !containsAnySubstring(ctx.AttestationSourceRepo, cond.RequireSourceRepo) {
			return false
		}
	}
	if cond.RequireTransparencyLog != nil {
		hasTLog := ctx.AttestationTransparencyLog != ""
		if *cond.RequireTransparencyLog != hasTLog {
			return false
		}
	}
	if cond.ForbidCacheStale != nil && *cond.ForbidCacheStale {
		if ctx.AttestationCacheStale {
			return false
		}
	}

	// Check typosquatting condition
	if cond.IsSuspectedTyposquat != nil {
		if *cond.IsSuspectedTyposquat != ctx.IsSuspectedTyposquat {
			return false
		}
	}

	// Check known malicious condition
	if cond.IsKnownMalicious != nil {
		if *cond.IsKnownMalicious != ctx.IsKnownMalicious {
			return false
		}
	}

	// Check trust score conditions
	if cond.TrustScoreMin != nil && ctx.TrustScore < *cond.TrustScoreMin {
		return false
	}
	if cond.TrustScoreMax != nil && ctx.TrustScore > *cond.TrustScoreMax {
		return false
	}

	// Check reserved namespaces (dependency confusion protection)
	if len(cond.ReservedNamespaces) > 0 {
		if !matchesReservedNamespace(ctx.PackageName, cond.ReservedNamespaces) {
			return false
		}
	}

	// Check install-script conditions.
	if cond.HasInstallScript != nil {
		if *cond.HasInstallScript != ctx.HasInstallScript {
			return false
		}
	}
	if cond.InstallScriptFetchesRemote != nil {
		if *cond.InstallScriptFetchesRemote != ctx.InstallScriptFetchesRemote {
			return false
		}
	}

	// Check publisher-changed condition.
	if cond.PublisherChanged != nil {
		if *cond.PublisherChanged != ctx.PublisherChanged {
			return false
		}
	}

	// Check version anomaly. Two-part condition:
	//   - VersionAnomaly bool: coarse match against ctx.VersionAnomaly (or
	//     equivalently ctx.VersionAnomalyFlags non-empty).
	//   - VersionAnomalyKinds []string: narrow match requiring at least one
	//     overlap between the listed flags and ctx.VersionAnomalyFlags.
	// Both can be set on the same policy; matching requires BOTH to pass.
	if cond.VersionAnomaly != nil {
		hasAny := ctx.VersionAnomaly || len(ctx.VersionAnomalyFlags) > 0
		if *cond.VersionAnomaly != hasAny {
			return false
		}
	}
	if len(cond.VersionAnomalyKinds) > 0 {
		if !hasAnyIntersection(cond.VersionAnomalyKinds, ctx.VersionAnomalyFlags) {
			return false
		}
	}

	// Check hidden-Unicode condition.
	// HasHiddenUnicode nil → wildcard (any). When set, both the bool must
	// agree AND (if HiddenUnicodeKinds is populated) at least one of the
	// policy's requested kinds must appear in the context's detected-kinds
	// set. Intersection semantics mirror PR 3's versionAnomalyKinds pattern.
	if cond.HasHiddenUnicode != nil {
		if *cond.HasHiddenUnicode != ctx.HasHiddenUnicode {
			return false
		}
	}
	if len(cond.HiddenUnicodeKinds) > 0 {
		if !hasAnyKindIntersection(cond.HiddenUnicodeKinds, ctx.HiddenUnicodeKinds) {
			return false
		}
	}

	// Check publish-velocity anomaly. The orchestrator hydrates
	// ctx.PublishVelocity24h with the live count of trailing-24h publishes
	// from any overlapping publisher; the evaluator applies the policy-chosen
	// threshold (or the default when nil). Pre-threshold counts are not
	// meaningful in isolation — a threshold-only policy stays inert because
	// PublishVelocityAnomaly is the gate.
	if cond.PublishVelocityAnomaly != nil {
		threshold := DefaultPublishVelocityThreshold24h
		if cond.PublishVelocityThreshold24h != nil && *cond.PublishVelocityThreshold24h > 0 {
			threshold = *cond.PublishVelocityThreshold24h
		}
		isAnomalous := ctx.PublishVelocity24h > threshold
		if *cond.PublishVelocityAnomaly != isAnomalous {
			return false
		}
	}

	// Socket-gap Wave 1: license-taxonomy, deprecation, shrinkwrap,
	// manifest-confusion conditions. All are simple bool gates over
	// fields the risk projection (and/or scan providers) populate
	// onto the EvaluationContext.
	if cond.LicenseCopyleft != nil {
		if *cond.LicenseCopyleft != hasLicenseTag(ctx.LicenseTags, "license.copyleft") {
			return false
		}
	}
	if cond.LicenseNonPermissive != nil {
		if *cond.LicenseNonPermissive != hasLicenseTag(ctx.LicenseTags, "license.non_permissive") {
			return false
		}
	}
	if cond.LicenseExceptionPresent != nil {
		if *cond.LicenseExceptionPresent != hasLicenseTag(ctx.LicenseTags, "license.exception_present") {
			return false
		}
	}
	if cond.LicenseAmbiguousClassifier != nil {
		if *cond.LicenseAmbiguousClassifier != hasLicenseTag(ctx.LicenseTags, "license.ambiguous_classifier") {
			return false
		}
	}
	if cond.LicenseUnidentified != nil {
		if *cond.LicenseUnidentified != hasLicenseTag(ctx.LicenseTags, "license.unidentified") {
			return false
		}
	}
	if cond.DeprecatedByMaintainer != nil {
		if *cond.DeprecatedByMaintainer != ctx.DeprecatedByMaintainer {
			return false
		}
	}
	if cond.ShrinkwrapPresent != nil {
		if *cond.ShrinkwrapPresent != ctx.ShrinkwrapPresent {
			return false
		}
	}
	if cond.ManifestConfusion != nil {
		if *cond.ManifestConfusion != ctx.ManifestConfusion {
			return false
		}
	}
	// Wave 2 — manifest hygiene.
	if cond.GitDependency != nil {
		if *cond.GitDependency != ctx.GitDependency {
			return false
		}
	}
	if cond.HTTPTarballDependency != nil {
		if *cond.HTTPTarballDependency != ctx.HTTPTarballDependency {
			return false
		}
	}
	if cond.WildcardDependencyRange != nil {
		if *cond.WildcardDependencyRange != ctx.WildcardDependencyRange {
			return false
		}
	}
	if cond.BadDependencySemver != nil {
		if *cond.BadDependencySemver != ctx.BadDependencySemver {
			return false
		}
	}
	// Wave 3 — source-code scanner conditions. Simple bool gates;
	// providers in internal/intelligence/provider_codesmell.go set
	// them on the ArtifactScanSection and the risk projection
	// (plus adapters.go) carries them here.
	if cond.UsesEval != nil {
		if *cond.UsesEval != ctx.UsesEval {
			return false
		}
	}
	if cond.NetworkAccess != nil {
		if *cond.NetworkAccess != ctx.NetworkAccess {
			return false
		}
	}
	if cond.ShellAccess != nil {
		if *cond.ShellAccess != ctx.ShellAccess {
			return false
		}
	}
	if cond.FilesystemAccess != nil {
		if *cond.FilesystemAccess != ctx.FilesystemAccess {
			return false
		}
	}
	if cond.EnvVarAccess != nil {
		if *cond.EnvVarAccess != ctx.EnvVarAccess {
			return false
		}
	}
	if cond.NativeBinaryPresent != nil {
		if *cond.NativeBinaryPresent != ctx.NativeBinaryPresent {
			return false
		}
	}
	if cond.HighEntropyStrings != nil {
		if *cond.HighEntropyStrings != ctx.HighEntropyStrings {
			return false
		}
	}
	if cond.URLStrings != nil {
		if *cond.URLStrings != ctx.URLStrings {
			return false
		}
	}
	if cond.MinifiedCode != nil {
		if *cond.MinifiedCode != ctx.MinifiedCode {
			return false
		}
	}
	// Wave 4 — two artifact-map signals + three feature-flagged RTT
	// signals. Each compares the context bool against the policy bool;
	// when the provider is gated off the context stays false and the
	// condition stays inert.
	if cond.TrivialPackage != nil {
		if *cond.TrivialPackage != ctx.TrivialPackage {
			return false
		}
	}
	if cond.TooManyFiles != nil {
		if *cond.TooManyFiles != ctx.TooManyFiles {
			return false
		}
	}
	if cond.NonExistentAuthor != nil {
		if *cond.NonExistentAuthor != ctx.NonExistentAuthor {
			return false
		}
	}
	if cond.FirstTimeCollaborator != nil {
		// Pointer-aware tri-state match. ctx is also *bool now: a rule
		// with FirstTimeCollaborator=&true matches only when the
		// context is &true (confirmed first-time uploader); &false
		// matches only confirmed-not-first-time. Unknown context (nil)
		// never matches a literal-bool rule — authors who want to fire
		// on unknown express that as a separate rule (FirstTimeCollaborator
		// pointer left nil + a future explicit "unknown" matcher when
		// the DSL grows one).
		if ctx.FirstTimeCollaborator == nil {
			return false
		}
		if *cond.FirstTimeCollaborator != *ctx.FirstTimeCollaborator {
			return false
		}
	}
	if cond.SuspiciousRepoStars != nil {
		if *cond.SuspiciousRepoStars != ctx.SuspiciousRepoStars {
			return false
		}
	}

	// MaintainerAccountAgeDaysMax: numeric threshold. Fires when the
	// youngest maintainer/publisher account on the version is at most
	// the configured number of days old. Sentinel ctx.MaintainerAccountAgeDays<=0
	// means "no signal available" (provider disabled or upstream
	// unreachable) — fail-open so a transport blip cannot silently
	// block traffic.
	if cond.MaintainerAccountAgeDaysMax != nil {
		if ctx.MaintainerAccountAgeDays <= 0 {
			return false
		}
		if ctx.MaintainerAccountAgeDays > *cond.MaintainerAccountAgeDaysMax {
			return false
		}
	}

	// AI artifact conditions. Each mirrors the boolean ctx field that
	// the projection populates from the AI artifact providers'
	// ArtifactScanSection output. nil-on-Conditions means "any".
	if cond.DangerousPickle != nil && *cond.DangerousPickle != ctx.DangerousPickle {
		return false
	}
	if cond.UnsafeSerializationFormat != nil && *cond.UnsafeSerializationFormat != ctx.UnsafeSerializationFormat {
		return false
	}
	if cond.ModelCardInjection != nil && *cond.ModelCardInjection != ctx.ModelCardInjection {
		return false
	}
	if cond.AgentToolDangerousCapability != nil && *cond.AgentToolDangerousCapability != ctx.AgentToolDangerousCapability {
		return false
	}
	if cond.MCPServerDeclared != nil && *cond.MCPServerDeclared != ctx.MCPServerDeclared {
		return false
	}
	if cond.PromptTemplateInjection != nil && *cond.PromptTemplateInjection != ctx.PromptTemplateInjection {
		return false
	}

	return true
}

// hasLicenseTag is a small helper for the Wave-1 License* conditions.
func hasLicenseTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

// hasAnyKindIntersection reports whether the policy-requested kind slice
// shares any member with the signals slice — case-insensitive match with
// whitespace tolerance. Used for Conditions.HiddenUnicodeKinds (PR 8) and
// mirrors the pattern PR 3 uses for versionAnomalyKinds.
func hasAnyKindIntersection(policyKinds, ctxKinds []string) bool {
	if len(policyKinds) == 0 || len(ctxKinds) == 0 {
		return false
	}
	want := make(map[string]struct{}, len(policyKinds))
	for _, k := range policyKinds {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		want[k] = struct{}{}
	}
	for _, k := range ctxKinds {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		if _, ok := want[k]; ok {
			return true
		}
	}
	return false
}

// Helper functions

func matchesPattern(value, pattern string) bool {
	// Simple wildcard matching: * matches everything
	if pattern == "*" {
		return true
	}
	// Exact match (case-insensitive)
	return strings.EqualFold(value, pattern)
}

func matchesVersion(version, constraint string) bool {
	// Try semver constraint matching
	v, err := semver.NewVersion(version)
	if err != nil {
		// Fallback to exact match if not valid semver
		return strings.EqualFold(version, constraint)
	}

	c, err := semver.NewConstraint(constraint)
	if err != nil {
		// Fallback to exact match if not valid constraint
		return strings.EqualFold(version, constraint)
	}

	return c.Check(v)
}

// matchesEcosystemList returns true when format equals any entry in
// allowed (case-insensitive). Both sides are trimmed and lowercased
// before comparison so YAML/JSON variations ("npm", " NPM ", "NPM")
// converge. Empty allowed slice never matches — callers gate on
// len(allowed)>0 before invoking.
func matchesEcosystemList(format string, allowed []string) bool {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		return false
	}
	for _, eco := range allowed {
		if strings.EqualFold(strings.TrimSpace(eco), format) {
			return true
		}
	}
	return false
}

// containsAnySubstring returns true when haystack contains any of the
// needle substrings. Used by attestation matchers (RequireBuilderID,
// RequireBuilderIssuer, RequireSourceRepo) which match against subjects
// like "https://github.com/foo/bar/.github/workflows/release.yml@…" by
// substring rather than exact equality, so policies survive workflow
// path renames and ref/tag suffixes.
func containsAnySubstring(haystack string, needles []string) bool {
	if haystack == "" {
		return false
	}
	for _, n := range needles {
		if n == "" {
			continue
		}
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

func contains(list []string, value string) bool {
	value = strings.TrimSpace(value)
	for _, item := range list {
		if strings.EqualFold(strings.TrimSpace(item), value) {
			return true
		}
	}
	return false
}

func matchesLicenseCondition(policyLicenses []string, resolved string) bool {
	resolved = strings.TrimSpace(resolved)
	if resolved == "" {
		return false
	}
	if contains(policyLicenses, resolved) {
		return true
	}
	for _, token := range spdxExpressionTokens(resolved) {
		if contains(policyLicenses, token) {
			return true
		}
	}
	return false
}

func spdxExpressionTokens(expr string) []string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}
	replacer := strings.NewReplacer("(", " ", ")", " ")
	fields := strings.Fields(replacer.Replace(expr))
	seen := make(map[string]struct{}, len(fields))
	tokens := make([]string, 0, len(fields))
	skipNext := false
	for _, field := range fields {
		field = strings.TrimSpace(field)
		upper := strings.ToUpper(field)
		switch upper {
		case "", "AND", "OR":
			continue
		case "WITH":
			skipNext = true
			continue
		}
		if skipNext {
			skipNext = false
			continue
		}
		if _, ok := seen[upper]; ok {
			continue
		}
		seen[upper] = struct{}{}
		tokens = append(tokens, field)
	}
	return tokens
}

func hasAnyIntersection(list1, list2 []string) bool {
	for _, item1 := range list1 {
		for _, item2 := range list2 {
			if strings.EqualFold(strings.TrimSpace(item1), strings.TrimSpace(item2)) {
				return true
			}
		}
	}
	return false
}

func matchesCountryList(country string, patterns []string) bool {
	country = strings.TrimSpace(country)
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if isUnrestrictedScopeValue(pattern) {
			return true
		}
		if strings.EqualFold(pattern, country) {
			return true
		}
	}
	return false
}

func matchesIPList(ip string, patterns []string) bool {
	for _, pattern := range patterns {
		if isUnrestrictedScopeValue(pattern) {
			return true
		}
	}
	parsedIP, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	parsedIP = parsedIP.Unmap()

	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if isUnrestrictedScopeValue(pattern) {
			return true
		}
		// Check if pattern is CIDR
		if strings.Contains(pattern, "/") {
			prefix, err := netip.ParsePrefix(pattern)
			if err != nil {
				continue
			}
			if prefix.Masked().Contains(parsedIP) {
				return true
			}
		} else {
			// Exact IP match
			patternIP, err := netip.ParseAddr(pattern)
			if err == nil && patternIP.Unmap() == parsedIP {
				return true
			}
		}
	}
	return false
}

func isUnrestrictedScopeValue(value string) bool {
	value = strings.TrimSpace(value)
	return value == "*" || strings.EqualFold(value, "all")
}

func matchesReservedNamespace(packageName string, patterns []string) bool {
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		// Wildcard suffix: "@scope/*", "prefix-*", "com.company.*"
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(strings.ToLower(packageName), strings.ToLower(prefix)) {
				return true
			}
			continue
		}
		// Scope-only: "@scope/"
		if strings.HasSuffix(pattern, "/") && strings.HasPrefix(pattern, "@") {
			if strings.HasPrefix(strings.ToLower(packageName), strings.ToLower(pattern)) {
				return true
			}
			continue
		}
		// Trailing dot for Maven-style groupIds: "com.company."
		if strings.HasSuffix(pattern, ".") {
			if strings.HasPrefix(strings.ToLower(packageName), strings.ToLower(pattern)) {
				return true
			}
			continue
		}
		// Glob pattern.
		if matched, _ := path.Match(strings.ToLower(pattern), strings.ToLower(packageName)); matched {
			return true
		}
		// Exact match fallback.
		if strings.EqualFold(packageName, pattern) {
			return true
		}
	}
	return false
}

func buildReason(policy Policy) string {
	if policy.Mode == ModeBlock {
		return "blocked by policy: " + policy.ID
	}
	if policy.Mode == ModeMonitor {
		return "monitored by policy: " + policy.ID
	}
	if policy.Mode == ModeQuarantine {
		return "quarantined by policy: " + policy.ID
	}
	return "allowed by policy: " + policy.ID
}

// blockAfterGraceReason renders the reason string for a resolved
// ModeBlockAfterGrace policy. resolvedAs is the user-visible bucket the
// evaluator chose ("block" when enforcing, "monitor" when inside the
// grace window). Kept distinct from buildReason so the grace verdict is
// greppable in audit / telemetry without overloading the plain-block
// reason.
func blockAfterGraceReason(policy Policy, resolvedAs string) string {
	switch resolvedAs {
	case "monitor":
		return "within grace window by policy: " + policy.ID
	default:
		return "blocked after grace by policy: " + policy.ID
	}
}
