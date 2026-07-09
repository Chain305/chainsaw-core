// Package policyengine is the single decision facade every chainsaw
// enforcement surface (PR check, registry proxy, publish gate, env
// promotion gate, k8s admission webhook, install-time runtime hook)
// calls into. It hides the split between the native Go evaluator
// (fast path, ~50 built-in conditions) and the OPA Rego DSL
// (extensible path, custom org rules) behind one Decide call.
//
// Surfaces produce a policy.EvaluationContext + a SurfaceTag and get
// back a Decision. The same Rego rule can be authored once and fire
// at every surface — that is the point of the package.
package policyengine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync/atomic"

	"github.com/chain305/chainsaw-core/policy"
	"github.com/chain305/chainsaw-core/policy/dsl"
)

// dslPanicStackLimit caps how much of the runtime stack we copy into a
// log line on a Rego rule panic. 4 KiB identifies the offending frame
// without flooding the log pipeline if a panic chain is deep.
const dslPanicStackLimit = 4096

// Decision is what a surface receives back. It merges the native Go
// evaluator's verdict (legacy struct-policy match) with the Rego
// engine's verdict (custom rule). The strictest action wins; both
// sets of violations are surfaced so audit / UI never lose a
// matched rule.
type Decision struct {
	Action     dsl.Action        `json:"action"`
	Surface    policy.SurfaceTag `json:"surface"`
	Violations []dsl.Violation   `json:"violations,omitempty"`
	// MatchedNative is the legacy policy.Mode that the Go evaluator
	// returned, kept on the decision for callers that need to log it
	// alongside the merged verdict.
	MatchedNative policy.Mode `json:"matchedNative,omitempty"`
	// NativePolicyID is the ID of the matched native policy, or the
	// empty string when no native policy fired.
	NativePolicyID string `json:"nativePolicyId,omitempty"`
	// BundleDigest names the Rego bundle that produced the dsl
	// portion of the decision. Useful for reproducing a decision.
	BundleDigest string `json:"bundleDigest,omitempty"`
}

// OwnerResolver resolves a (orgID, repo, path) tuple into an owning team's
// contact information for Pain 4 (ownership routing). Returns "", false
// when no team is known — the engine then leaves the routing fields on the
// notify_owner violation empty and the downstream surface skips the
// team-targeted webhook fan-out (per the default-OFF semantics).
//
// Implementations live in internal/ownership/store.go (ResolveOwners).
// The interface stays here so policyengine doesn't import internal/ownership
// (which transitively pulls in pgstore — engine has to be construction-light).
type OwnerResolver interface {
	ResolveOwners(ctx context.Context, orgID, repo, path string) (team, handle, contactURL string, ok bool)
}

// Engine combines the native policy evaluator with the OPA dsl engine.
// It is safe for concurrent use; the underlying components already are.
type Engine struct {
	native           *policy.Evaluator
	exceptionAgeDays int
	dslAtom          atomic.Pointer[dsl.Engine] // hot-swappable on bundle reload
	logger           *slog.Logger
	// ownerResolverAtom holds the optional Pain 4 hook. nil-safe — when
	// unset the notify_owner emission path is a no-op (route fields stay
	// empty). Wired by the server at construction time when feature flag
	// `ownership_routing` is enabled.
	//
	// Stored as atomic.Pointer mirroring dslAtom so SetOwnerResolver can
	// race-freely swap the resolver while Decide() concurrently reads it
	// on the hot path. Without the atomic, a concurrent reconfiguration
	// (admin edits team→destination mapping) would race with reads in
	// emitOwnerRouting and `go test -race` would flag it.
	ownerResolverAtom atomic.Pointer[ownerResolverHolder]
}

// ownerResolverHolder boxes the OwnerResolver interface for atomic.Pointer.
// We can't atomic.Pointer an interface directly (atomic.Pointer requires a
// concrete type), and we want nil to be representable distinctly from a
// non-nil holder wrapping a nil interface — so the holder pattern lets
// SetOwnerResolver(nil) clear the slot via Store(nil).
type ownerResolverHolder struct{ r OwnerResolver }

// Config wires an Engine.
type Config struct {
	Native           *policy.Evaluator // existing struct-policy evaluator (may be nil for stateless tests)
	ExceptionAgeDays int               // forwarded to policy.Evaluator.Evaluate
	DSL              *dsl.Engine       // compiled Rego bundle (may be nil → DSL path is a no-op)
	Logger           *slog.Logger
}

// New constructs an Engine from the wired components.
func New(cfg Config) *Engine {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	e := &Engine{native: cfg.Native, exceptionAgeDays: cfg.ExceptionAgeDays, logger: logger}
	if cfg.DSL != nil {
		e.dslAtom.Store(cfg.DSL)
	}
	return e
}

// SetDSL hot-swaps the Rego engine. Used by the bundle-watcher path
// when a fresher chainsaw.policy bundle lands on disk or in OCI. Pass
// nil to disable the DSL path entirely.
func (e *Engine) SetDSL(d *dsl.Engine) {
	e.dslAtom.Store(d)
}

// SetOwnerResolver wires the optional Pain 4 ownership router. Pass nil
// to disable ownership routing emission. The resolver is read on every
// Decide call (uncontended fast path); the atomic.Pointer makes the
// publish race-free even when an admin swaps the team→destination
// mapping while requests are in flight.
func (e *Engine) SetOwnerResolver(r OwnerResolver) {
	if e == nil {
		return
	}
	if r == nil {
		e.ownerResolverAtom.Store(nil)
		return
	}
	e.ownerResolverAtom.Store(&ownerResolverHolder{r: r})
}

// ownerResolver loads the current resolver via atomic.Pointer. Returns
// nil when no resolver is wired or after SetOwnerResolver(nil). Read on
// every Decide call.
func (e *Engine) ownerResolver() OwnerResolver {
	if e == nil {
		return nil
	}
	h := e.ownerResolverAtom.Load()
	if h == nil {
		return nil
	}
	return h.r
}

// Decide is the unified entry point. Every surface calls this with
// the same shape: a SurfaceTag identifying where the decision is
// being made plus the EvaluationContext that surface was able to
// build. Missing fields stay zero-valued.
//
// Strictness merge: action returned is the more severe of the
// native verdict and the Rego verdict. Block > quarantine > monitor
// > allow.
//
// Fail-open on DSL errors: a syntax error or runtime panic in a
// custom rule must not block production traffic. The error is
// logged and the DSL path treated as allow; the native verdict
// still applies. (Operators who want fail-closed semantics for
// custom rules can wrap Decide with their own fail-closed shim.)
func (e *Engine) Decide(ctx context.Context, surface policy.SurfaceTag, ec policy.EvaluationContext) (Decision, error) {
	out := Decision{
		Action:        dsl.ActionAllow,
		Surface:       surface,
		MatchedNative: policy.ModeAllow,
	}

	if e.native != nil {
		nativeRes, err := e.native.Evaluate(ec, e.exceptionAgeDays)
		if err != nil {
			return out, err
		}
		out.MatchedNative = nativeRes.Action
		if nativeRes.MatchedPolicy != nil {
			out.NativePolicyID = nativeRes.MatchedPolicy.ID
			// Translate the native mode → dsl.Action and emit a
			// synthetic violation so the DSL view of the decision is
			// complete.
			a := nativeToAction(nativeRes.Action)
			out.Action = dsl.Stricter(out.Action, a)
			if a != dsl.ActionAllow {
				v := dsl.Violation{
					RuleID:  "native:" + nativeRes.MatchedPolicy.ID,
					Action:  a,
					Message: nativeRes.Reason,
				}
				out.Violations = append(out.Violations, v)
			}
		}
	}

	if d := e.dslAtom.Load(); d != nil && !d.Empty() {
		input := policy.ContextToInput(surface, ec)
		// Wrap d.Decide in a closure with a deferred recover() so a
		// panicking Rego rule (nil deref, divide-by-zero in a custom
		// builtin, runtime stack overflow) cannot kill the goroutine.
		// A recovered panic is funnelled into the same fail-open path
		// as a returned error: we log loudly and skip merging the DSL
		// verdict, leaving the native verdict intact.
		dec, err := safeDecide(ctx, d, input)
		if err != nil {
			// Fail-open. Log loudly so operators notice; do not
			// promote the error to the caller because that would
			// turn a buggy rule into a hard deny.
			e.logger.Error("dsl decide error — failing open",
				"err", err,
				"surface", string(surface),
				"package", ec.PackageName,
				"version", ec.PackageVersion,
				"bundle_digest", d.Digest(),
			)
		} else {
			out.Action = dsl.Stricter(out.Action, dec.Action)
			out.Violations = append(out.Violations, dec.Violations...)
		}
		out.BundleDigest = d.Digest()
	}

	// Pain 4 (ownership routing): when an enforcement-bearing verdict
	// landed AND a custom rule emitted notify_owner (or the engine has
	// a resolver wired), populate routing metadata on the existing
	// notify_owner violations and append one synthetic notify_owner
	// violation for downstream surfaces if none already exist. The
	// owner_team / owner_handle / owner_contact_url fields are the
	// payload Agent A's tests / webhook templates depend on.
	//
	// Strictness is preserved exactly: notify_owner ranks at allow level
	// (see dsl.strictness), so this never escalates the decision; it is
	// pure side-effect plumbing.
	e.emitOwnerRouting(ctx, ec, &out)

	return out, nil
}

// emitOwnerRouting is the Pain 4 hook. It mutates `out` in place:
//   - resolves the owning team from (orgID, repo, path) when a resolver
//     is wired,
//   - back-fills OwnerTeam / OwnerHandle / OwnerContactURL on any
//     existing notify_owner violation,
//   - appends a synthetic notify_owner violation when the merged
//     decision is non-allow but no rule emitted one (so the downstream
//     router still sees the routing intent).
//
// Call sites that don't want routing simply leave ownerResolver nil.
func (e *Engine) emitOwnerRouting(ctx context.Context, ec policy.EvaluationContext, out *Decision) {
	if e == nil || out == nil {
		return
	}
	resolver := e.ownerResolver()
	if resolver == nil {
		return
	}
	// Only emit routing for decisions that carry an enforcement signal.
	// Pure-allow decisions don't need an owner notification.
	enforcement := out.Action == dsl.ActionBlock ||
		out.Action == dsl.ActionQuarantine ||
		out.Action == dsl.ActionMonitor
	hasNotifyOwner := false
	for _, v := range out.Violations {
		if v.Action == dsl.ActionNotifyOwner {
			hasNotifyOwner = true
			break
		}
	}
	if !enforcement && !hasNotifyOwner {
		return
	}
	team, handle, contactURL, ok := resolver.ResolveOwners(ctx, ec.OrgID, ec.Repository, ec.PackageName)
	if !ok {
		return
	}
	// Back-fill any existing notify_owner violation that came from a
	// custom rule so callers reading the violation list see the same
	// routing metadata regardless of which path emitted the action.
	for i := range out.Violations {
		if out.Violations[i].Action != dsl.ActionNotifyOwner {
			continue
		}
		if out.Violations[i].OwnerTeam == "" {
			out.Violations[i].OwnerTeam = team
		}
		if out.Violations[i].OwnerHandle == "" {
			out.Violations[i].OwnerHandle = handle
		}
		if out.Violations[i].OwnerContactURL == "" {
			out.Violations[i].OwnerContactURL = contactURL
		}
	}
	// If the enforcement-bearing decision didn't already include a
	// notify_owner violation, append one so the downstream router has a
	// stable shape to read.
	if enforcement && !hasNotifyOwner {
		out.Violations = append(out.Violations, dsl.Violation{
			RuleID:          "ownership:auto",
			Action:          dsl.ActionNotifyOwner,
			Message:         "violation routed to owning team",
			OwnerTeam:       team,
			OwnerHandle:     handle,
			OwnerContactURL: contactURL,
		})
	}
}

func nativeToAction(m policy.Mode) dsl.Action {
	switch m {
	case policy.ModeBlock:
		return dsl.ActionBlock
	case policy.ModeQuarantine:
		return dsl.ActionQuarantine
	case policy.ModeMonitor:
		return dsl.ActionMonitor
	default:
		return dsl.ActionAllow
	}
}

// ErrNoEvaluator signals neither path is wired — use it for surface
// callsites that want to fail loudly when the engine is not yet
// constructed (typical at process start before the policy store is
// loaded).
var ErrNoEvaluator = errors.New("policyengine: neither native evaluator nor dsl engine wired")

// safeDecide wraps dsl.Engine.Decide with a deferred recover() so a
// panicking Rego rule cannot kill the calling goroutine. A recovered
// panic is converted into an error of the same shape the caller
// already handles (fail-open: log and skip the DSL verdict). The full
// stack is captured into the error message — Engine.Decide's caller
// logs it via slog so operators see the offending frame without the
// goroutine being torn down.
func safeDecide(ctx context.Context, d *dsl.Engine, input policy.Input) (dec dsl.Decision, err error) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			if len(stack) > dslPanicStackLimit {
				stack = stack[:dslPanicStackLimit]
			}
			// Reset any partial decision so the merge step does not
			// see half-populated violations.
			dec = dsl.Decision{}
			err = fmt.Errorf("dsl decide panicked: %v\nstack:\n%s", r, stack)
		}
	}()
	return d.Decide(ctx, input)
}
