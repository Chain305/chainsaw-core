package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// PostgresInvalidationBus implements [InvalidationBus] on top of
// Postgres LISTEN/NOTIFY. It is the production multi-replica wiring
// for the policy cache invalidation bus.
//
// Design notes:
//
//  1. LISTEN is per-connection state in Postgres. Subscribe therefore
//     opens a *dedicated* pgx.Conn (NOT a pooled handle) and keeps
//     WaitForNotification running on it until the caller cancels.
//  2. Publish uses a short-lived pgx.Conn too. NOTIFY is cheap and the
//     write path is not hot (admin policy edits only), so the extra
//     connect cost per call is fine and keeps Publish from starving
//     the main writable pool.
//  3. The subscriber reconnects on any error other than ctx.Done() with
//     an exponential backoff capped at 30 seconds. Each reconnect logs
//     at info; the successful start logs once.
//  4. Postgres identifier constraints: LISTEN accepts any channel name
//     up to NAMEDATALEN-1 (63 bytes), but unquoted identifiers are
//     lower-cased. To keep the channel name stable regardless of case
//     and to keep the wire format identical to the NATS implementation
//     we use a single channel ("chainsaw_policy_invalidate") and
//     carry the orgID in the NOTIFY payload. Subscribe(pattern, ...)
//     reuses the same subject-style matching the NATS bus uses so
//     the Subscriber wrapper in invalidation.go does not need to
//     know which bus it is talking to.
type PostgresInvalidationBus struct {
	dsn    string
	logger *slog.Logger
}

// postgresChannel is the single LISTEN channel this bus uses. Postgres
// doesn't support wildcard LISTEN, so we multiplex every per-org
// invalidation through one channel and put the orgID in the payload.
const postgresChannel = "chainsaw_policy_invalidate"

// NewPostgresInvalidationBus constructs a bus bound to dsn. The DSN is
// NOT opened eagerly — the first Publish or Subscribe call spawns the
// connection so construction stays cheap and failure surfaces where
// the caller is already handling errors.
//
// logger may be nil (slog.Default is used for reconnect / error lines).
func NewPostgresInvalidationBus(dsn string, logger *slog.Logger) *PostgresInvalidationBus {
	if logger == nil {
		logger = slog.Default()
	}
	return &PostgresInvalidationBus{dsn: dsn, logger: logger}
}

// Publish sends NOTIFY <channel>, '<subject>' on a short-lived
// connection. The subject is embedded in the payload so the subscriber
// side reconstructs the (subject, body) pair expected by the
// Subscriber wrapper.
//
// body is currently ignored — the wire format is "just the subject" so
// a `psql` operator can eyeball LISTEN output. If we ever need to
// carry a body, encode both as JSON in a future revision; today's
// subscriber and publisher in invalidation.go use an empty body.
func (b *PostgresInvalidationBus) Publish(ctx context.Context, subject string, _ []byte) error {
	if b == nil || b.dsn == "" {
		return nil
	}
	conn, err := pgx.Connect(ctx, b.dsn)
	if err != nil {
		return fmt.Errorf("policy bus: pg connect: %w", err)
	}
	defer conn.Close(ctx)
	// pgx escapes the $1 parameter, so an attacker-controlled orgID
	// cannot break out and inject SQL — NOTIFY accepts a plain text
	// payload. NOTIFY itself does not support $N parameterisation for
	// the channel name, which is why the channel is a constant.
	if _, err := conn.Exec(ctx, "SELECT pg_notify($1, $2)", postgresChannel, subject); err != nil {
		return fmt.Errorf("policy bus: pg notify: %w", err)
	}
	return nil
}

// Subscribe opens a dedicated pgx.Conn, runs LISTEN, and fans every
// inbound notification to handler. The pattern is only used to match
// inbound subjects on the subscriber side (e.g.
// "chainsaw.policy.invalidate.*") — Postgres itself does not filter
// on the wire. Returns a cancel function that tears down the listener
// goroutine and closes the connection.
func (b *PostgresInvalidationBus) Subscribe(ctx context.Context, pattern string, handler func(subject string, body []byte)) (func(), error) {
	if b == nil || b.dsn == "" {
		return func() {}, nil
	}
	if handler == nil {
		return nil, errors.New("policy bus: nil handler")
	}

	runCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		b.listenLoop(runCtx, pattern, handler)
	}()

	return func() {
		cancel()
		// Best-effort join so teardown is deterministic in tests.
		wg.Wait()
	}, nil
}

// listenLoop is the reconnect-with-backoff driver. It opens a
// dedicated connection, issues LISTEN, and forwards notifications
// until the connection errors or ctx is cancelled. On error it closes
// the connection and reconnects with exponential backoff.
func (b *PostgresInvalidationBus) listenLoop(ctx context.Context, pattern string, handler func(string, []byte)) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	first := true
	// Reuse a single Timer across reconnect attempts so a long-lived
	// listener that flaps doesn't allocate a fresh runtime timer per
	// loop iteration. Stop+drain before each Reset is the standard
	// idiom; the !timer.Stop() guard skips draining when the timer
	// has already fired and we're about to receive on it.
	timer := time.NewTimer(backoff)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		err := b.runListener(ctx, pattern, handler, first)
		if ctx.Err() != nil {
			return
		}
		first = false
		if err != nil {
			b.logger.Error("policy invalidation: listener error, reconnecting",
				"error", err, "backoff", backoff)
		}
		timer.Reset(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// runListener owns one connection for its lifetime. It returns when
// the connection errors (the caller reconnects) or when ctx is
// cancelled (the caller stops).
func (b *PostgresInvalidationBus) runListener(ctx context.Context, pattern string, handler func(string, []byte), firstConnect bool) error {
	conn, err := pgx.Connect(ctx, b.dsn)
	if err != nil {
		return fmt.Errorf("pg connect: %w", err)
	}
	defer conn.Close(context.Background())

	// LISTEN doesn't accept parameters; the channel is a constant so
	// this is safe. If the channel ever becomes operator-configurable,
	// quote-sanitise the identifier before concatenating.
	if _, err := conn.Exec(ctx, "LISTEN "+postgresChannel); err != nil {
		return fmt.Errorf("pg listen: %w", err)
	}

	if firstConnect {
		b.logger.Info("policy invalidation: postgres listener started",
			"channel", postgresChannel)
	} else {
		b.logger.Info("policy invalidation: postgres listener reconnected",
			"channel", postgresChannel)
	}

	for {
		notif, err := conn.WaitForNotification(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		subject := notif.Payload
		if !subjectMatchesPattern(pattern, subject) {
			continue
		}
		// Dispatch in a goroutine so a slow handler can't wedge the
		// listener loop (and therefore future notifications). The
		// callback in CachedStore is a map delete under a lock, so
		// this is belt-and-braces.
		go func(s string) {
			defer func() {
				if r := recover(); r != nil {
					b.logger.Error("policy invalidation: handler panic",
						"subject", s, "panic", r)
				}
			}()
			handler(s, nil)
		}(subject)
	}
}

// Compile-time assertion that PostgresInvalidationBus satisfies
// InvalidationBus.
var _ InvalidationBus = (*PostgresInvalidationBus)(nil)
