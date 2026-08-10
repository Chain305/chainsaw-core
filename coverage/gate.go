package coverage

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Decision is Gate's output.
type Decision struct {
	// Block is true when the caller must refuse the package.
	Block bool
	// Warn is true in ModeWarn when Block would have been true in
	// ModeClosed. Exactly one of Block/Warn is ever set.
	Warn bool
	// Missing lists the required sources that could not be evaluated,
	// sorted, so log lines and user-facing messages are stable.
	Missing []Source
	// Reason is a ready-to-print one-liner for the refusal message.
	Reason string
}

// Gate decides whether a package may proceed.
//
// Pure: no I/O, no ambient clock (`now` is injected), no dependency on
// intelligence, risk, or policy. This function is the entire control — if you
// want to know what the fail-closed option does, read this and gate_test.go.
//
// Gate runs BEFORE and INDEPENDENTLY of policy evaluation, and a Block is not
// overridable by a policy allow. That ordering is what keeps the guarantee
// alive when the Rego bundle is broken, absent, or stale — every Decide()
// error path in the tree is specified to fail open, so a fail-closed
// guarantee cannot live inside the policy engine.
func Gate(p Posture, led Ledger, now time.Time) Decision {
	if p.Mode == ModeOff {
		return Decision{}
	}
	var missing []Source
	for _, src := range p.Required {
		if effectiveStatus(led[src], p, now) == StatusUnavailable {
			missing = append(missing, src)
		}
	}
	if len(missing) == 0 {
		return Decision{}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i] < missing[j] })

	names := make([]string, len(missing))
	for i, s := range missing {
		names[i] = string(s)
	}
	reason := fmt.Sprintf("required signal coverage unavailable: %s", strings.Join(names, ", "))

	if p.Mode == ModeWarn {
		return Decision{Warn: true, Missing: missing, Reason: reason}
	}
	return Decision{Block: true, Missing: missing, Reason: reason}
}

// effectiveStatus applies the two staleness bounds, which pull in opposite
// directions on purpose:
//
//  1. MaxLedgerAge is the outer bound and ALWAYS wins. A Report served from
//     cache replays whatever coverage it recorded, so without this bound a
//     report cached while healthy would vouch for a source during a total
//     outage.
//  2. Grace rescues a source that is down now but was OK very recently, so a
//     three-second registry hiccup does not refuse a build. It only ever
//     applies to a source with a real LastOKAt — a source that has never
//     worked is not a blip.
//
// Posture.Validate rejects Grace >= MaxLedgerAge, so rule 2 is always
// reachable when configured.
func effectiveStatus(e Entry, p Posture, now time.Time) Status {
	if e.ObservedAt.IsZero() || now.Sub(e.ObservedAt) > p.MaxLedgerAge {
		return StatusUnavailable
	}
	if e.Status == StatusUnavailable &&
		!e.LastOKAt.IsZero() && now.Sub(e.LastOKAt) <= p.Grace {
		return StatusOK
	}
	return e.Status
}
