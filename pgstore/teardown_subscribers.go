package pgstore

import (
	"context"
	"fmt"
	"strings"
)

// teardown_subscribers.go owns the persistence for the launch C1
// owned-audience capture surface (the "monthly supply-chain teardown"
// list). The only writer is the public, UNAUTHENTICATED POST
// /teardowns/subscribe handler (internal/server/launch_capture.go), so
// the insert is deliberately the narrowest possible: email + a coarse
// source label, nothing request-derived. See the table comment in
// migrate.go for the privacy rationale.

// AddTeardownSubscriber records an opted-in email for the teardown
// list. It is idempotent: a repeat email is a no-op via
// `ON CONFLICT (email) DO NOTHING`, and the method returns the SAME
// (nil) error whether the row was new or already present. Callers MUST
// NOT branch their HTTP response on "was this new" — that would turn the
// endpoint into an email-enumeration oracle. `inserted` is returned for
// telemetry/metrics ONLY (e.g. counting genuinely-new subscribers); it
// is intentionally not surfaced to the unauthenticated caller.
//
// email MUST already be validated and lower-cased by the caller — the
// table has no citext, so case-folding happens in the handler and the
// plain TEXT UNIQUE constraint enforces dedup on the normalised value.
// source is a short, bounded label ("teardowns", "show_hn", …) and is
// clamped here as defence-in-depth against an over-long caller value.
func (s *Store) AddTeardownSubscriber(ctx context.Context, email, source string) (inserted bool, err error) {
	if s == nil || s.db == nil {
		return false, fmt.Errorf("pgstore: store not initialized")
	}
	email = strings.TrimSpace(email)
	if email == "" {
		return false, fmt.Errorf("pgstore: empty teardown subscriber email")
	}
	source = strings.TrimSpace(source)
	if source == "" {
		source = "teardowns"
	}
	// Defence-in-depth bound; the handler also clamps, but a direct
	// store caller shouldn't be able to park an unbounded label.
	if len(source) > 64 {
		source = source[:64]
	}

	res, err := s.db.ExecContext(ctx,
		`INSERT INTO teardown_subscribers (email, source)
		 VALUES (?, ?)
		 ON CONFLICT (email) DO NOTHING`,
		email, source,
	)
	if err != nil {
		return false, fmt.Errorf("insert teardown subscriber: %w", err)
	}
	// RowsAffected is 1 on a genuine insert, 0 when the conflict clause
	// suppressed a duplicate. Some drivers don't support it; treat an
	// error here as "unknown" (inserted=false) rather than failing the
	// whole call — the row is committed regardless.
	n, raErr := res.RowsAffected()
	if raErr != nil {
		return false, nil
	}
	return n > 0, nil
}
