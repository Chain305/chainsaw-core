package coverage

import "time"

// Entry is what one surface observed about one data source for one package.
type Entry struct {
	Status   Status
	Producer string // provider or subsystem that produced this observation
	Code     string // raw warn code, retained for the audit trail
	// ObservedAt is when this observation was made. It is NOT the time the
	// Ledger was assembled: a Report served from cache replays the coverage
	// of whenever it was scanned, so the age of each observation has to
	// travel with it or a stale-healthy report will vouch for a source that
	// is currently down.
	ObservedAt time.Time
	// LastOKAt is the most recent time this source was observed OK, zero if
	// never. Gate's grace window only ever rescues a source that was healthy
	// recently — a source that has never worked is not a blip.
	LastOKAt time.Time
}

// Ledger is the per-package coverage picture a surface hands to Gate.
//
// A source absent from the map is treated as unavailable: "we have no record
// of consulting it" and "we consulted it and failed" are the same fact from
// the operator's point of view.
type Ledger map[Source]Entry
