package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/chain305/chainsaw-core/tenancy"
)

// E3: policy cache invalidation bus.
//
// CachedStore (in store.go) keeps a per-org snapshot of the policy list
// for `defaultPolicyCacheTTL` (15s). In a single-replica deployment an
// admin Update/Delete call clears the cache directly via Invalidate;
// the next ListPolicies hits Postgres. In a multi-replica deployment
// the local Invalidate only clears ONE replica's cache — every other
// replica continues to serve stale policies until its TTL elapses,
// which is up to 30 seconds of policy divergence per the original
// E3 brief.
//
// This file adds a small pub/sub bus on top of NATS subjects:
//
//	chainsaw.policy.invalidate.<orgID>   — fan-out, no consumer group
//
// Replicas subscribe with a wildcard (`chainsaw.policy.invalidate.*`),
// parse the orgID from the subject, and call CachedStore.Invalidate
// locally. Replicas publish on the matching subject inside Update,
// Delete, Renew, and SetStatus.
//
// Key design decisions:
//
//  1. The bus is OPTIONAL. Both Publisher and Subscriber are no-ops
//     when constructed with a nil InvalidationBus. This preserves the
//     pre-E3 behaviour for development environments and keeps the TTL
//     fallback as belt-and-braces — even if NATS is down, divergence
//     is bounded.
//
//  2. The bus interface is intentionally narrow: Publish + Subscribe
//     on raw subject strings. This lets us back the bus by either
//     bare nats.Conn (the production path) or an in-memory fake (tests
//     in this file).
//
//  3. Subscribers parse the orgID from the LAST dot-segment of the
//     subject, NOT from the message body, to keep the wire format
//     trivially debuggable from the NATS CLI: `nats sub
//     'chainsaw.policy.invalidate.*'` shows everything.

// InvalidationBus is the narrow pub/sub surface the publisher and
// subscriber depend on. Implementations: natsInvalidationBus (real)
// and the in-memory fake used by the tests.
type InvalidationBus interface {
	// Publish posts an invalidation message on subject. The body is
	// reserved for future expansion (currently empty).
	Publish(ctx context.Context, subject string, body []byte) error
	// Subscribe registers handler for every message matching pattern.
	// pattern may include the NATS wildcard "*". The returned cancel
	// function tears down the subscription.
	Subscribe(ctx context.Context, pattern string, handler func(subject string, body []byte)) (cancel func(), err error)
}

// invalidateSubjectPrefix is the NATS subject namespace.
const invalidateSubjectPrefix = "chainsaw.policy.invalidate"

// invalidateSubjectPattern matches every per-org invalidation subject.
const invalidateSubjectPattern = invalidateSubjectPrefix + ".*"

// invalidateSubjectFor returns the per-org subject. orgID is normalised
// because callers might pass mixed-case identifiers; downstream
// subscribers normalise on receive too.
func invalidateSubjectFor(orgID string) string {
	return invalidateSubjectPrefix + "." + sanitiseSubjectSegment(tenancy.NormalizeOrgID(orgID))
}

// sanitiseSubjectSegment ensures the orgID is safe to embed in a NATS
// subject. NATS subjects are dot-separated tokens; ".", "*", ">" and
// whitespace are reserved. We replace all of those with "_". Org IDs
// are typically UUIDs or short slugs so this is a no-op in practice.
func sanitiseSubjectSegment(s string) string {
	repl := strings.NewReplacer(".", "_", "*", "_", ">", "_", " ", "_", "\t", "_")
	return strings.TrimSpace(repl.Replace(s))
}

// subjectMatchesPattern: literal "chainsaw.policy.invalidate.*" matches
// "chainsaw.policy.invalidate.<anything>" with no further dots. Used by
// bus implementations that can't rely on broker-side wildcard matching
// (e.g. the Postgres LISTEN/NOTIFY bus, which uses a single channel
// and carries the subject in the payload).
func subjectMatchesPattern(pattern, subject string) bool {
	if pattern == subject {
		return true
	}
	if !strings.HasSuffix(pattern, ".*") {
		return false
	}
	prefix := strings.TrimSuffix(pattern, ".*") + "."
	if !strings.HasPrefix(subject, prefix) {
		return false
	}
	rest := subject[len(prefix):]
	return rest != "" && !strings.Contains(rest, ".")
}

// orgIDFromSubject inverts invalidateSubjectFor: pull the trailing
// dot-segment off `subject`. Returns "" if `subject` does not match
// the expected prefix.
func orgIDFromSubject(subject string) string {
	prefix := invalidateSubjectPrefix + "."
	if !strings.HasPrefix(subject, prefix) {
		return ""
	}
	return tenancy.NormalizeOrgID(subject[len(prefix):])
}

// Publisher fans out cache-invalidation notifications. A nil bus
// produces a no-op publisher; that's the safe default for replicas
// that have no NATS configured.
type Publisher struct {
	bus    InvalidationBus
	logger *slog.Logger
}

// NewPublisher constructs a Publisher. logger may be nil (slog.Default
// is used).
func NewPublisher(bus InvalidationBus, logger *slog.Logger) *Publisher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Publisher{bus: bus, logger: logger}
}

// Invalidate publishes "evict the cache for this org" to every other
// replica. Returns nil when bus is nil so callers don't have to branch.
//
// Errors are returned to the caller because the CachedStore mutation
// path treats publish failures as a signal that the local invalidation
// won't propagate — operators get a log line. We do NOT roll back the
// local mutation on publish failure: divergence for `cacheTTL`
// seconds is preferable to bouncing a perfectly good policy edit.
func (p *Publisher) Invalidate(ctx context.Context, orgID string) error {
	if p == nil || p.bus == nil {
		return nil
	}
	subject := invalidateSubjectFor(orgID)
	if err := p.bus.Publish(ctx, subject, nil); err != nil {
		p.logger.Warn("policy invalidation publish failed",
			"subject", subject, "org_id", orgID, "error", err)
		return fmt.Errorf("policy: publish invalidation: %w", err)
	}
	return nil
}

// Subscriber listens for invalidation messages and calls the supplied
// callback on each one. The callback is typically (*CachedStore).Invalidate.
type Subscriber struct {
	bus      InvalidationBus
	callback func(orgID string)
	cancel   func()
	logger   *slog.Logger
	mu       sync.Mutex
	started  bool
}

// NewSubscriber constructs a Subscriber. callback is invoked once per
// inbound message with the parsed orgID. Pass nil for bus to get a
// no-op subscriber.
func NewSubscriber(bus InvalidationBus, callback func(orgID string), logger *slog.Logger) *Subscriber {
	if logger == nil {
		logger = slog.Default()
	}
	return &Subscriber{bus: bus, callback: callback, logger: logger}
}

// Start subscribes to the wildcard subject. Returns nil if bus is nil.
// Start is idempotent — calling it twice on the same Subscriber returns
// an error so misuse is caught early.
func (s *Subscriber) Start(ctx context.Context) error {
	if s == nil || s.bus == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("policy: subscriber already started")
	}
	cancel, err := s.bus.Subscribe(ctx, invalidateSubjectPattern, s.handle)
	if err != nil {
		return fmt.Errorf("policy: subscribe: %w", err)
	}
	s.cancel = cancel
	s.started = true
	return nil
}

// Stop tears down the subscription. Safe to call multiple times.
func (s *Subscriber) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.started = false
}

func (s *Subscriber) handle(subject string, _ []byte) {
	orgID := orgIDFromSubject(subject)
	if orgID == "" {
		s.logger.Warn("policy invalidation: malformed subject", "subject", subject)
		return
	}
	if s.callback == nil {
		return
	}
	// Run the callback synchronously; CachedStore.Invalidate is a
	// fast map delete under a mutex, no need to spawn a goroutine.
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("policy invalidation callback panic",
				"subject", subject, "panic", r)
		}
	}()
	s.callback(orgID)
}
