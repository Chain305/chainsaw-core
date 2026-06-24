// Package xreplicaflight coordinates compute-once-per-key work across
// multiple replicas of chainsaw-proxy using Postgres advisory locks.
//
// In-process de-duplication is already handled by
// golang.org/x/sync/singleflight in internal/intelligence/scanner.go.
// That only coalesces concurrent callers within a single process, so
// N replicas that all see the same package at the same time perform N
// upstream fetches. xreplicaflight adds a cross-replica layer on top:
// one replica wins an advisory lock and runs the expensive work; the
// others wait briefly and then re-read whatever the leader persisted.
//
// The Flight interface is designed so the feature can be toggled OFF
// at zero cost: NoopFlight.Do is a direct fn call with no allocation
// and no database round-trip, so single-instance deployments keep
// bit-identical behaviour.
package xreplicaflight

import (
	"context"
	"errors"
	"time"
)

// ErrFlightTimeout is returned by Flight.Do when a follower exceeded
// the configured wait timeout without the leader releasing the lock.
// Callers can choose to treat this as retryable: the next call will
// attempt to acquire the lock fresh.
var ErrFlightTimeout = errors.New("xreplicaflight: timed out waiting for leader")

// ErrLeaderCrashed is returned when a follower acquired the lock (so
// the prior leader finished or died) but the cache peek came back
// empty. The caller should treat this as retryable.
var ErrLeaderCrashed = errors.New("xreplicaflight: leader released lock without persisting result")

// Flight coordinates a compute-once-per-key operation across replicas.
// When enabled, callers that hit the same key concurrently elect one
// leader via a Postgres advisory lock; followers wait and then re-read
// the shared cache via peek.
type Flight interface {
	// Do executes fn if the caller wins the advisory lock for key.
	// Otherwise it waits up to timeout for the leader to release,
	// then calls peek to return whatever the leader persisted.
	//
	// Returns fn's result if the caller won the lock, or peek's
	// result if the caller was a follower.
	Do(
		ctx context.Context,
		key string,
		timeout time.Duration,
		fn func(ctx context.Context) (any, error),
		peek func(ctx context.Context) (any, error),
	) (any, error)
}

// NoopFlight is the zero-cost default: every caller is a leader. There
// is no allocation and no database interaction — wiring this in place
// of a real Flight must produce behaviour bit-identical to the
// pre-xreplicaflight scan path.
type NoopFlight struct{}

// Do on the noop simply calls fn. peek is never invoked; timeout is
// ignored. No goroutines, no locks, no allocations.
func (NoopFlight) Do(
	ctx context.Context,
	_ string,
	_ time.Duration,
	fn func(ctx context.Context) (any, error),
	_ func(ctx context.Context) (any, error),
) (any, error) {
	return fn(ctx)
}

// Ensure NoopFlight satisfies Flight at compile time.
var _ Flight = NoopFlight{}
