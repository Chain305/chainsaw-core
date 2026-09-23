package intelligence

import (
	"context"
	"time"
)

// reportIsFresh decides whether the refresher may skip a row, measured on the
// REPORT rather than on package_metadata.
//
// Extracted as a pure function because RefresherConfig.Store is a concrete
// *Store over a live database, so the decision cannot otherwise be exercised
// without one — and this decision is exactly the thing that was wrong.
//
// haveStore separates "no store is configured" from "the store had nothing".
// They need opposite answers: with no store there is nothing better than the
// package_metadata column to go on, but a store that returns nothing means no
// report exists, which is a reason to scan rather than to skip. loadPriorReport
// also returns nil on error, so an unreachable store fails toward doing the
// work.
func reportIsFresh(prior *Report, haveStore bool, rowUpdatedAt, staleAfter time.Time) bool {
	if !haveStore {
		return rowUpdatedAt.After(staleAfter)
	}
	return prior != nil && prior.Observation.CollectedAt.After(staleAfter)
}

// loadReportForKey reads the persisted Report for an arbitrary coordinate.
// loadPriorReport answers only for the row under refresh; the new-version check
// needs a DIFFERENT version of the same package.
func (r *Refresher) loadReportForKey(ctx context.Context, orgID string, key Key) *Report {
	if r == nil || r.cfg.Store == nil {
		return nil
	}
	loadCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rep, err := r.cfg.Store.Get(loadCtx, orgID, key)
	if err != nil {
		return nil
	}
	return rep
}
