package intelligence

// verdict_history.go — the append-only record of verdict transitions.
//
// intelligence_reports upserts in place and keeps no history, so "why
// was this allowed in March" is not a hard question, it is an
// unanswerable one: there is no data. This is the table that answers it,
// and the same table that makes the recall subscription measurable
// (docs/plan_signal_repair.md Wave 4).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// VerdictTransition is one recorded change.
type VerdictTransition struct {
	HistoryID     int64     `json:"historyId"`
	Ecosystem     string    `json:"ecosystem"`
	Package       string    `json:"package"`
	Version       string    `json:"version"`
	PriorVerdict  string    `json:"priorVerdict,omitempty"`
	NextVerdict   string    `json:"nextVerdict"`
	PriorScore    *int      `json:"priorScore,omitempty"`
	NextScore     *int      `json:"nextScore,omitempty"`
	Trigger       string    `json:"trigger"`
	EngineVersion string    `json:"engineVersion,omitempty"`
	AuthoredByOrg string    `json:"authoredByOrg,omitempty"`
	ObservedAt    time.Time `json:"observedAt"`
}

// recordVerdictTransition appends a row when, and only when, the verdict
// or the score actually moved.
//
// ONLY TRANSITIONS. A rescan that changes nothing writes nothing. This
// is what makes an append-only table affordable on the upsert hot path:
// row count tracks how much the world moved, not how often we looked.
// The refresher re-scans continuously, so the alternative is a table
// that grows without bound and answers no additional question.
//
// A FIRST observation IS recorded, with a NULL prior_verdict. "This
// coordinate was first seen as allow on date X" is exactly the kind of
// fact the March question needs, and the absence of a prior is data
// rather than a reason to skip.
func recordVerdictTransition(ctx context.Context, tx *sql.Tx, r *Report, priorPayload []byte, orgID string) error {
	if tx == nil || r == nil || r.Risk == nil {
		// No Risk means nothing was evaluated. Recording a transition
		// to an empty verdict would put rows in the history that say
		// nothing happened.
		return nil
	}

	nextVerdict := strings.TrimSpace(string(r.Risk.Verdict))
	if nextVerdict == "" {
		return nil
	}
	nextScore := r.Risk.RolledUp.Overall

	priorVerdict, priorScore, hadPrior := priorVerdictFrom(priorPayload)
	if hadPrior && priorVerdict == nextVerdict && priorScore == nextScore {
		// Nothing moved.
		return nil
	}

	var priorVerdictArg any
	var priorScoreArg any
	if hadPrior {
		priorVerdictArg = priorVerdict
		priorScoreArg = priorScore
	}

	observedAt := r.Observation.CollectedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}

	_, err := tx.ExecContext(ctx, `
		INSERT INTO verdict_history (
			ecosystem, package_name, version,
			prior_verdict, next_verdict, prior_score, next_score,
			trigger, engine_version, authored_by_org, observed_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		r.Identity.Ecosystem, r.Identity.Package, r.Identity.Version,
		priorVerdictArg, nextVerdict, priorScoreArg, nextScore,
		"upsert", r.Risk.EngineVersion, strings.TrimSpace(orgID), observedAt,
	)
	if err != nil {
		return fmt.Errorf("intelligence: record verdict transition: %w", err)
	}
	return nil
}

// priorVerdictFrom pulls the verdict and score out of the previous row's
// report JSONB.
//
// It reads the JSONB rather than the denormalised verdict / overall_score
// COLUMNS on purpose. Those columns drifted from the JSON they project
// for long enough that 32% of production rows carried a stale verdict and
// 59% a stale score — see the note at the INSERT in store.go. A history
// built from the stale projection would record transitions that never
// happened and miss ones that did.
func priorVerdictFrom(priorPayload []byte) (verdict string, score int, ok bool) {
	if len(priorPayload) == 0 {
		return "", 0, false
	}
	var prior struct {
		Risk *struct {
			Verdict  string `json:"verdict"`
			RolledUp struct {
				Overall int `json:"overall"`
			} `json:"rolledUp"`
		} `json:"risk"`
	}
	if err := json.Unmarshal(priorPayload, &prior); err != nil || prior.Risk == nil {
		// An unparseable or Risk-less prior is "no reference frame",
		// which is the same shape as no prior at all. It must not be
		// reported as a transition FROM the empty string.
		return "", 0, false
	}
	v := strings.TrimSpace(prior.Risk.Verdict)
	if v == "" {
		return "", 0, false
	}
	return v, prior.Risk.RolledUp.Overall, true
}

// reportVerdictHistoryFailure surfaces a history write failure without
// failing the scan.
//
// The verdict is the product; the history is the record of it. Refusing
// an upsert because the audit row would not write turns a bookkeeping
// problem into an outage. But it is not swallowed either: it lands on
// the report's warnings, so a consumer reading the report can see that
// its history entry is missing.
func reportVerdictHistoryFailure(r *Report, err error) {
	if r == nil || err == nil {
		return
	}
	r.Observation.Warnings = append(r.Observation.Warnings, Warning{
		Provider: "verdict-history",
		Code:     "verdict_history_write_failed",
		Message: "the verdict was stored but its history entry was not: " +
			err.Error() + " — this report's transition is missing from the audit trail",
		At: time.Now().UTC(),
	})
}

// VerdictHistory returns a coordinate's transitions, newest first.
//
// This is the "why was this allowed in March" read. limit is clamped;
// a caller cannot ask for the whole table.
func (s *Store) VerdictHistory(ctx context.Context, key Key, limit int) ([]VerdictTransition, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return nil, nil
	}
	if limit <= 0 || limit > maxVerdictHistoryLimit {
		limit = maxVerdictHistoryLimit
	}
	rows, err := s.sql.DB().QueryContext(ctx, `
		SELECT history_id, ecosystem, package_name, version,
		       COALESCE(prior_verdict, ''), next_verdict,
		       prior_score, next_score,
		       trigger, COALESCE(engine_version, ''), COALESCE(authored_by_org, ''),
		       observed_at
		FROM verdict_history
		WHERE ecosystem = $1 AND package_name = $2 AND version = $3
		ORDER BY observed_at DESC, history_id DESC
		LIMIT $4`,
		key.Ecosystem, key.Package, key.Version, limit)
	if err != nil {
		return nil, fmt.Errorf("intelligence: verdict history: %w", err)
	}
	defer rows.Close()

	var out []VerdictTransition
	for rows.Next() {
		var (
			t          VerdictTransition
			priorScore sql.NullInt64
			nextScore  sql.NullInt64
		)
		if err := rows.Scan(&t.HistoryID, &t.Ecosystem, &t.Package, &t.Version,
			&t.PriorVerdict, &t.NextVerdict, &priorScore, &nextScore,
			&t.Trigger, &t.EngineVersion, &t.AuthoredByOrg, &t.ObservedAt); err != nil {
			return nil, fmt.Errorf("intelligence: scan verdict history: %w", err)
		}
		if priorScore.Valid {
			v := int(priorScore.Int64)
			t.PriorScore = &v
		}
		if nextScore.Valid {
			v := int(nextScore.Int64)
			t.NextScore = &v
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

const maxVerdictHistoryLimit = 500

// PruneVerdictHistory deletes transitions older than cutoff and returns
// how many rows went.
//
// An append-only table with no deleter is how intelligence_reports got
// into this state from the other direction — it has no retention either,
// and the reason its earliest row is recent is that a mass rescan
// overwrote everything, which is not retention, it is data loss.
//
// Deliberately a method the operator calls rather than a worker: the
// right window is a policy question (an enforcement log going back to
// April is evidence someone may need), and wiring a deleter on a
// default schedule would answer it by accident.
func (s *Store) PruneVerdictHistory(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return 0, nil
	}
	if cutoff.IsZero() {
		// A zero cutoff would delete everything. Refuse rather than
		// interpret: "prune with no window" is a caller bug, and the
		// cost of guessing is the audit trail.
		return 0, fmt.Errorf("intelligence: prune verdict history: cutoff is required")
	}
	res, err := s.sql.DB().ExecContext(ctx,
		`DELETE FROM verdict_history WHERE observed_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("intelligence: prune verdict history: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
