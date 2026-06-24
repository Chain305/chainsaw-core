package upstreamhttp

import "context"

// RedisHostLimiter is a STUB. It intentionally does not implement a
// Redis-backed sliding-window or fixed-window rate limit — that work
// is deferred until a multi-replica chainsaw-proxy deployment actually
// needs a shared upstream quota. Keeping the type here preserves the
// seam so a future PR can drop in the real implementation without
// touching any call site.
//
// Contract for a future Redis implementation (for the dev who picks
// this up):
//
//   - Keyed INCR on "chainsaw:upstream:{host}:{second}" with a 2s TTL.
//     The host bucket's capacity (req/s from Config.HostLimits[host])
//     is compared against the INCR result.
//   - When the counter exceeds capacity, Wait blocks until the current
//     second rolls over — honoring ctx.Done throughout.
//   - Redis unavailability (ErrNetwork, timeout) must fall through to
//     the Inner limiter rather than failing closed. Every chainsaw
//     Redis-backed component in the repo (ratelimit.RedisBucket, the
//     webhook queue) follows the same fail-open posture; doing
//     otherwise would mean an unreachable Redis knocks every upstream
//     fetch offline.
//   - A Prometheus counter on fall-through events is expected
//     (ratelimit.RedisUnavailableTotal is the precedent to follow).
//
// Today Wait simply delegates to Inner so any code path that wired a
// RedisHostLimiter still functions — the Redis-aware behaviour just
// isn't there yet.
type RedisHostLimiter struct {
	// Inner is the fallback limiter invoked for every Wait today.
	// Until the Redis implementation lands, this is the only path.
	// Required.
	Inner HostLimiter

	// TODO(shared-quota): add a *redis.Client field + key-prefix +
	// metric-recorder once a caller actually needs the shared quota.
	// The existing internal/ratelimit.RedisBucket is the closest
	// precedent — follow its fail-open posture and its
	// RedisUnavailableTotal counter convention.
}

// Wait delegates to Inner. Retained as a method on RedisHostLimiter
// (rather than a straight field exposure) so the future Redis
// implementation can be added here without changing the surface any
// caller sees.
func (r *RedisHostLimiter) Wait(ctx context.Context, host string) error {
	if r == nil || r.Inner == nil {
		// Defensive default — a caller that constructed an empty
		// RedisHostLimiter shouldn't silently allow unbounded
		// requests. Ctx.Err path preserves shutdown semantics.
		if err := ctx.Err(); err != nil {
			return err
		}
		return nil
	}
	return r.Inner.Wait(ctx, host)
}
