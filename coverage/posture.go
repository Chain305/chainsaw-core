package coverage

import (
	"fmt"
	"time"
)

// Mode is the enforcement posture.
type Mode string

const (
	// ModeOff is the default. No gate runs and no code path changes.
	ModeOff Mode = "off"
	// ModeWarn evaluates the gate and reports what ModeClosed would have
	// refused, without refusing anything. This is a first-class mode, not a
	// debug flag: an operator must be able to measure their real block rate
	// against production traffic before flipping to closed, or the first
	// upstream outage turns this feature into an org-wide outage.
	ModeWarn Mode = "warn"
	// ModeClosed refuses the package.
	ModeClosed Mode = "closed"
)

// DefaultGrace and DefaultMaxLedgerAge are used when config omits them.
// 30s mirrors the admission webhook's last-known-good decision cache, which
// was tuned to ride out a Postgres rolling restart without flapping.
const (
	DefaultGrace        = 30 * time.Second
	DefaultMaxLedgerAge = 15 * time.Minute
)

// Posture is the operator's declared configuration.
type Posture struct {
	Version      int
	Mode         Mode
	Required     []Source
	Grace        time.Duration
	MaxLedgerAge time.Duration
}

// Validate rejects a configuration that cannot mean what the operator intended.
//
// Callers MUST treat a validation error on an explicitly-configured posture as
// fatal and refuse to proceed. Silently degrading to ModeOff would reproduce
// exactly the failure this feature exists to prevent — see decision D3 in
// docs/plan_optional_fail_closed.md.
func (p Posture) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("coverage: unsupported config version %d (want 1)", p.Version)
	}
	switch p.Mode {
	case ModeOff, ModeWarn, ModeClosed:
	default:
		return fmt.Errorf("coverage: unknown mode %q (want off, warn, or closed)", p.Mode)
	}
	if p.Mode == ModeOff {
		return nil
	}
	if len(p.Required) == 0 {
		return fmt.Errorf("coverage: mode %q requires at least one source in `required`", p.Mode)
	}
	for _, s := range p.Required {
		if _, err := ParseSource(string(s)); err != nil {
			return err
		}
	}
	if p.Grace < 0 {
		return fmt.Errorf("coverage: grace must not be negative (got %s)", p.Grace)
	}
	if p.MaxLedgerAge <= 0 {
		return fmt.Errorf("coverage: max_ledger_age must be positive (got %s)", p.MaxLedgerAge)
	}
	if p.Grace >= p.MaxLedgerAge {
		return fmt.Errorf(
			"coverage: grace (%s) must be shorter than max_ledger_age (%s), otherwise the grace window is unreachable",
			p.Grace, p.MaxLedgerAge)
	}
	return nil
}
