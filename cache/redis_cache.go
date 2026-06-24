package cache

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCache implements [Cache] against any Redis-protocol server
// (Redis OSS, Valkey, KeyDB, Dragonfly, ElastiCache, Upstash).
//
// Failure model: callers receive a non-nil error from the backend
// when Redis is unreachable. Higher-level wrappers ([NegativeCache],
// the metadata cache) should treat that as "cache unavailable, fall
// through to the source of truth" — i.e. fail open. JWT revocation
// and other safety-critical caches must fail closed; that policy
// lives in the consumer, not the cache.
type RedisCache struct {
	client    redis.UniversalClient
	keyPrefix string
	logger    *slog.Logger
}

// NewRedisCache constructs a [Cache] backed by Redis. Mode "sentinel"
// or "cluster" expects the matching SentinelAddrs / ClusterAddrs
// fields; everything else falls back to standalone via the URL.
func NewRedisCache(cfg RedisConfig, keyPrefix string, logger *slog.Logger) (Cache, error) {
	if logger == nil {
		logger = slog.Default()
	}

	var client redis.UniversalClient
	switch strings.ToLower(strings.TrimSpace(cfg.Mode)) {
	case "sentinel":
		if cfg.SentinelMasterName == "" || len(cfg.SentinelAddrs) == 0 {
			return nil, errors.New("cache: redis sentinel mode requires master name and at least one sentinel address")
		}
		opts := &redis.FailoverOptions{
			MasterName:    cfg.SentinelMasterName,
			SentinelAddrs: cfg.SentinelAddrs,
			Username:      cfg.Username,
			Password:      cfg.Password,
			PoolSize:      cfg.PoolSize,
		}
		if cfg.TLS {
			opts.TLSConfig = cfg.TLSConfig
		}
		client = redis.NewFailoverClient(opts)
	case "cluster":
		if len(cfg.ClusterAddrs) == 0 {
			return nil, errors.New("cache: redis cluster mode requires at least one cluster address")
		}
		opts := &redis.ClusterOptions{
			Addrs:    cfg.ClusterAddrs,
			Username: cfg.Username,
			Password: cfg.Password,
			PoolSize: cfg.PoolSize,
		}
		if cfg.TLS {
			opts.TLSConfig = cfg.TLSConfig
		}
		client = redis.NewClusterClient(opts)
	default:
		if strings.TrimSpace(cfg.URL) == "" {
			return nil, errors.New("cache: redis URL is required for standalone mode")
		}
		opts, err := redis.ParseURL(cfg.URL)
		if err != nil {
			return nil, fmt.Errorf("cache: parse redis URL: %w", err)
		}
		if cfg.Username != "" {
			opts.Username = cfg.Username
		}
		if cfg.Password != "" {
			opts.Password = cfg.Password
		}
		if cfg.PoolSize > 0 {
			opts.PoolSize = cfg.PoolSize
		}
		if cfg.TLS {
			switch {
			case cfg.TLSConfig != nil:
				opts.TLSConfig = cfg.TLSConfig
			case opts.TLSConfig == nil:
				// Sane defaults — no client cert, verify server cert
				// against the system trust roots. Setting any non-nil
				// *tls.Config is what tells go-redis to dial TLS.
				opts.TLSConfig = &tls.Config{}
			}
		}
		client = redis.NewClient(opts)
	}

	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		return nil, fmt.Errorf("cache: redis ping failed: %w", err)
	}

	prefix := strings.Trim(strings.TrimSpace(keyPrefix), ":")
	return &RedisCache{
		client:    client,
		keyPrefix: prefix,
		logger:    logger,
	}, nil
}

func (r *RedisCache) prefix(key string) string {
	if r.keyPrefix == "" {
		return key
	}
	return r.keyPrefix + ":" + key
}

// Get retrieves bytes at key.
func (r *RedisCache) Get(ctx context.Context, key string) ([]byte, bool, error) {
	val, err := r.client.Get(ctx, r.prefix(key)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("redis get %s: %w", key, err)
	}
	return val, true, nil
}

// Set stores bytes at key with TTL.
func (r *RedisCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := r.client.Set(ctx, r.prefix(key), value, ttl).Err(); err != nil {
		return fmt.Errorf("redis set %s: %w", key, err)
	}
	return nil
}

// Delete removes the named keys.
func (r *RedisCache) Delete(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	prefixed := make([]string, len(keys))
	for i, k := range keys {
		prefixed[i] = r.prefix(k)
	}
	if err := r.client.Del(ctx, prefixed...).Err(); err != nil {
		return fmt.Errorf("redis del: %w", err)
	}
	return nil
}

// Exists reports whether key is present.
func (r *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	n, err := r.client.Exists(ctx, r.prefix(key)).Result()
	if err != nil {
		return false, fmt.Errorf("redis exists %s: %w", key, err)
	}
	return n > 0, nil
}

// SetAdd inserts members into the Redis set at key.
func (r *RedisCache) SetAdd(ctx context.Context, key string, members ...string) error {
	if len(members) == 0 {
		return nil
	}
	args := make([]any, len(members))
	for i, m := range members {
		args[i] = m
	}
	if err := r.client.SAdd(ctx, r.prefix(key), args...).Err(); err != nil {
		return fmt.Errorf("redis sadd %s: %w", key, err)
	}
	return nil
}

// SetMembers returns every member of the Redis set at key.
func (r *RedisCache) SetMembers(ctx context.Context, key string) ([]string, error) {
	members, err := r.client.SMembers(ctx, r.prefix(key)).Result()
	if err != nil {
		return nil, fmt.Errorf("redis smembers %s: %w", key, err)
	}
	return members, nil
}

// SetRemove removes members from the Redis set at key.
func (r *RedisCache) SetRemove(ctx context.Context, key string, members ...string) error {
	if len(members) == 0 {
		return nil
	}
	args := make([]any, len(members))
	for i, m := range members {
		args[i] = m
	}
	if err := r.client.SRem(ctx, r.prefix(key), args...).Err(); err != nil {
		return fmt.Errorf("redis srem %s: %w", key, err)
	}
	return nil
}

// Publish broadcasts msg to subscribers of channel.
func (r *RedisCache) Publish(ctx context.Context, channel string, msg []byte) error {
	if err := r.client.Publish(ctx, r.prefix(channel), msg).Err(); err != nil {
		return fmt.Errorf("redis publish %s: %w", channel, err)
	}
	return nil
}

// Subscribe attaches to channel; the returned chan emits inbound
// messages until either cancel is invoked or the parent ctx is
// cancelled. Both paths drain the goroutine and close out.
func (r *RedisCache) Subscribe(ctx context.Context, channel string) (<-chan []byte, func(), error) {
	pubsub := r.client.Subscribe(ctx, r.prefix(channel))
	out := make(chan []byte, 16)

	// Derive from the parent so a cancelled parent ctx tears the
	// goroutine down even when the caller forgets to invoke stop.
	subCtx, cancel := context.WithCancel(ctx)
	go func() {
		defer close(out)
		ch := pubsub.Channel()
		for {
			select {
			case <-subCtx.Done():
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				select {
				case out <- []byte(msg.Payload):
				case <-subCtx.Done():
					return
				default:
					// drop on full buffer (matches MemoryCache semantics)
				}
			}
		}
	}()

	stop := func() {
		cancel()
		_ = pubsub.Close()
	}
	return out, stop, nil
}

// Close releases the Redis connection pool.
func (r *RedisCache) Close() error {
	if r == nil || r.client == nil {
		return nil
	}
	return r.client.Close()
}

// Compile-time interface assertion.
var _ Cache = (*RedisCache)(nil)
