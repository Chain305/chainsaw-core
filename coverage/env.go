package coverage

import (
	"fmt"
	"strings"
	"time"
)

// Environment variables every surface reads. One spelling, one parser, so the
// guard, the proxy, the publish path, CI and admission cannot drift into
// dialects of the same option — which is the failure the whole design exists
// to prevent (see decision D1 in docs/plan_optional_fail_closed.md).
const (
	EnvMode       = "CHAINSAW_COVERAGE_MODE"
	EnvRequired   = "CHAINSAW_COVERAGE_REQUIRED"
	EnvGrace      = "CHAINSAW_COVERAGE_GRACE"
	EnvMaxAge     = "CHAINSAW_COVERAGE_MAX_LEDGER_AGE"
	EnvBreakGlass = "CHAINSAW_COVERAGE_BREAK_GLASS"
)

// Getenv is the lookup seam. Callers pass os.Getenv; tests pass a map so no
// process state is involved.
type Getenv func(string) string

// PostureFromEnv builds and validates a Posture from the environment.
//
// Returns the zero-value (ModeOff) posture when CHAINSAW_COVERAGE_MODE is
// unset — the default, in which no surface changes behaviour at all.
//
// An explicitly configured posture that fails validation returns an error, and
// the caller MUST surface it and refuse to proceed rather than continuing with
// the gate disabled. Silently degrading to off would reproduce exactly the
// failure this option exists to prevent (decision D3).
//
// onBreakGlass, when non-nil, is invoked if the break-glass escape hatch is
// engaged, so each surface can log it in its own voice. Bypassing a security
// control silently is worse than not having it.
func PostureFromEnv(getenv Getenv, onBreakGlass func()) (Posture, error) {
	off := Posture{Version: 1, Mode: ModeOff}

	mode := strings.TrimSpace(strings.ToLower(getenv(EnvMode)))
	if mode == "" {
		return off, nil
	}
	if isTruthy(getenv(EnvBreakGlass)) {
		if onBreakGlass != nil {
			onBreakGlass()
		}
		return off, nil
	}

	p := Posture{
		Version:      1,
		Mode:         Mode(mode),
		Grace:        DefaultGrace,
		MaxLedgerAge: DefaultMaxLedgerAge,
	}
	for _, raw := range strings.Split(getenv(EnvRequired), ",") {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		src, err := ParseSource(name)
		if err != nil {
			return Posture{}, err
		}
		p.Required = append(p.Required, src)
	}
	var err error
	if p.Grace, err = durationOr(getenv(EnvGrace), DefaultGrace, EnvGrace); err != nil {
		return Posture{}, err
	}
	if p.MaxLedgerAge, err = durationOr(getenv(EnvMaxAge), DefaultMaxLedgerAge, EnvMaxAge); err != nil {
		return Posture{}, err
	}
	if err := p.Validate(); err != nil {
		return Posture{}, err
	}
	return p, nil
}

func durationOr(raw string, fallback time.Duration, name string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return d, nil
}

func isTruthy(v string) bool {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
