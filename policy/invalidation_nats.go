package policy

import (
	"context"
	"fmt"

	"github.com/nats-io/nats.go"
)

// NATSInvalidationBus is the production InvalidationBus, backed by a
// raw NATS pub/sub connection (NOT JetStream — invalidation is a
// best-effort, low-latency notification, not a durable event).
//
// Operators wire it during process startup; the existing NATSConfig in
// internal/queue is reused for connection parameters in the wiring
// site, this struct just needs the connection itself so unit tests can
// inject a stub conn.
type NATSInvalidationBus struct {
	conn *nats.Conn
}

// NewNATSInvalidationBus wraps an existing nats.Conn. The connection
// is owned by the caller — Close() does not close the conn.
func NewNATSInvalidationBus(conn *nats.Conn) *NATSInvalidationBus {
	return &NATSInvalidationBus{conn: conn}
}

// Publish posts body on subject. NATS pub/sub fire-and-forget — there
// is no broker ack to wait on.
func (b *NATSInvalidationBus) Publish(_ context.Context, subject string, body []byte) error {
	if b == nil || b.conn == nil {
		return nil
	}
	if err := b.conn.Publish(subject, body); err != nil {
		return fmt.Errorf("nats publish %s: %w", subject, err)
	}
	// Flush to ensure the publish actually leaves this process, even
	// when the caller drops out before the connection's batch tick.
	// Errors are non-fatal — Publish above already succeeded.
	_ = b.conn.Flush()
	return nil
}

// Subscribe registers handler for every message matching pattern.
// pattern may include "*" / ">" wildcards (NATS-native).
func (b *NATSInvalidationBus) Subscribe(_ context.Context, pattern string, handler func(subject string, body []byte)) (func(), error) {
	if b == nil || b.conn == nil {
		return func() {}, nil
	}
	sub, err := b.conn.Subscribe(pattern, func(m *nats.Msg) {
		handler(m.Subject, m.Data)
	})
	if err != nil {
		return nil, fmt.Errorf("nats subscribe %s: %w", pattern, err)
	}
	return func() {
		_ = sub.Unsubscribe()
	}, nil
}

// Compile-time assertion.
var _ InvalidationBus = (*NATSInvalidationBus)(nil)
