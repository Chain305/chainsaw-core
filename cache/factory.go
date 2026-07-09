package cache

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"strings"
)

// Config selects the cache backend at startup. The zero value selects
// the in-process [MemoryCache], preserving prior single-instance
// behaviour.
type Config struct {
	// Type chooses the backend: "" or "memory" → MemoryCache, "redis"
	// → RedisCache (multi-instance, opt-in).
	Type string

	// KeyPrefix is prepended to every key sent to the backend. Lets
	// multiple chainsaw deployments share a Redis without colliding.
	KeyPrefix string

	// Redis carries the Redis backend's connection options. Required
	// when Type == "redis".
	Redis *RedisConfig
}

// RedisConfig configures the Redis-protocol backend (Redis OSS,
// Valkey, KeyDB, Dragonfly, ElastiCache, Upstash). All fields except
// URL are optional.
type RedisConfig struct {
	// URL is the Redis connection URL, e.g. "redis://host:6379/0".
	URL string

	// Username / Password override URL-supplied credentials.
	Username string
	Password string

	// PoolSize caps the connection pool. Zero leaves the client
	// default (10 × NumCPU) in place.
	PoolSize int

	// Mode selects the topology: "", "standalone", "sentinel",
	// "cluster". Sentinel and cluster require additional fields.
	Mode string

	// SentinelMasterName is the named master in sentinel mode.
	SentinelMasterName string

	// SentinelAddrs lists sentinel addresses for sentinel mode.
	SentinelAddrs []string

	// ClusterAddrs lists initial seed nodes for cluster mode.
	ClusterAddrs []string

	// TLS enables TLS to the Redis endpoint. The default config is
	// used (no client cert) — operators with custom CAs supply
	// TLSConfig directly when constructing programmatically.
	TLS bool

	// TLSConfig overrides the default TLS config when TLS is true.
	TLSConfig *tls.Config
}

// New returns the Cache selected by cfg. With cfg.Type == "" or
// "memory" the in-process cache is returned and no network resources
// are consumed.
func New(cfg Config, logger *slog.Logger) (Cache, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Type)) {
	case "", "memory":
		return NewMemoryCache(), nil
	case "redis":
		if cfg.Redis == nil {
			return nil, fmt.Errorf("cache: redis backend requires Redis configuration")
		}
		return NewRedisCache(*cfg.Redis, cfg.KeyPrefix, logger)
	default:
		return nil, fmt.Errorf("cache: unknown backend type %q (supported: memory, redis)", cfg.Type)
	}
}
