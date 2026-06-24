package risk

import (
	"fmt"
	"sort"
)

// Registry is the authoritative table of risk signals. Populated at
// package-init time by calls to register() from registry_<category>.go
// files.
//
// --------------------------------------------------------------------------
// Pattern (mirrors internal/errcodes/registry.go):
//
//  1. Create internal/risk/registry_<category>.go. One category per file.
//
//  2. Declare your signal ID constants for the category (dotted form:
//     "<prefix>.<name>", e.g. "vuln.kev", "sc.typosquat_high").
//
//  3. Add an init() that calls register(...) once per signal:
//
//     func init() {
//     register(Signal{
//     ID:       SignalVulnKEV,
//     Category: CategoryVulnerability,
//     Severity: SevCritical,
//     Weight:   -60,
//     Title:    "Known-exploited vulnerability (CISA KEV)",
//     Fires:    func(in Input) (bool, string, map[string]any) { ... },
//     })
//     }
//
//  4. register() panics on duplicate IDs — two registry_*.go files racing
//     to claim the same ID will fail at import time, not in production.
//
// --------------------------------------------------------------------------
var Registry = map[string]Signal{}

// register adds a Signal to the Registry. Panics on malformed or duplicate
// signals — these are programmer errors that should fail on binary startup
// rather than at evaluation time.
func register(s Signal) {
	if s.ID == "" {
		panic("risk.register: empty ID")
	}
	if s.Category == "" {
		panic(fmt.Sprintf("risk.register: %s has empty Category", s.ID))
	}
	if s.Fires == nil {
		panic(fmt.Sprintf("risk.register: %s has nil Fires", s.ID))
	}
	if s.Title == "" {
		panic(fmt.Sprintf("risk.register: %s has empty Title", s.ID))
	}
	if _, ok := Registry[s.ID]; ok {
		panic(fmt.Sprintf("risk.register: duplicate signal ID %q", s.ID))
	}
	Registry[s.ID] = s
}

// SignalsByCategory returns signals in a category, sorted by ID for stable
// iteration (the registry map order is non-deterministic in Go).
func SignalsByCategory(cat Category) []Signal {
	out := make([]Signal, 0, len(Registry))
	for _, s := range Registry {
		if s.Category == cat {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// AllSignals returns all registered signals sorted by (category, id). Used
// by the `/api/v1/intel/signals` endpoint and by the docs generator.
func AllSignals() []Signal {
	out := make([]Signal, 0, len(Registry))
	for _, s := range Registry {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].ID < out[j].ID
	})
	return out
}
