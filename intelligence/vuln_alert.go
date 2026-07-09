package intelligence

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/metadata"
)

// vuln_alert.go implements the issue #20 ("digest alerts when a new vuln
// appears on an existing repo") detection path. The refresher invokes
// VulnAlerter.OnRefreshedReport for every row it (re-)scans; the
// implementation diffs the new Report's Vulnerabilities section against
// the prior snapshot and emits exactly one alert per (package, version,
// trigger) tuple — either a brand-new CVE id, or a CVSS-score / KEV
// escalation against an already-known one.
//
// Two design decisions worth flagging:
//
//   - The diff happens INSIDE the alerter (not the refresher core) so the
//     refresher stays oblivious to vuln semantics and the alerter can be
//     unit-tested without spinning up a Scanner. The refresher just hands
//     it (prior, next) and the alerter does the per-CVE accounting.
//   - The "prior" report is the on-disk row at the moment the refresher
//     started its tick — i.e. the version BEFORE the current Scan wrote
//     the new snapshot. The refresher loads it explicitly via Store.Get
//     just before invoking Scan so the diff window matches one refresh
//     boundary, not "since deployment".

// VulnAlerter is the side-effect surface for issue #20 alerts. The
// refresher calls OnRefreshedReport once per row it scanned with the
// (prior, next) report pair so the alerter can diff CVE state and fan
// out webhook deliveries.
//
// Implementations MUST be safe for concurrent use — the refresher
// invokes the alerter from inside its per-row goroutine pool. nil-safe
// at the refresher boundary: a nil alerter disables the feature.
type VulnAlerter interface {
	// OnRefreshedReport is called after every row the refresher
	// successfully (re-)scanned. prior may be nil when no on-disk row
	// existed before the tick (first-ever scan of this coordinate);
	// next is non-nil and already persisted. ecosystem/repoName are
	// passed through verbatim from the Refresher's row so the alerter
	// can build a finding event without an extra metadata read.
	OnRefreshedReport(ctx context.Context, row metadata.PackageMetadataRow, ecosystem string, prior, next *Report)
}

// VulnAlertTrigger discriminates why OnRefreshedReport decided to emit
// one alert. Surfaced verbatim on the webhook payload's alert_reason
// field so receivers can route inside the same channel.
type VulnAlertTrigger string

const (
	// VulnAlertNewVuln — at least one CVE id appears in next that did
	// not appear in prior. Fired once per (package, version, cve)
	// tuple per refresh — multiple new CVEs on the same scan produce
	// multiple alerts (callers can throttle downstream if needed).
	VulnAlertNewVuln VulnAlertTrigger = "new_vuln"
	// VulnAlertEscalation — the same CVE id exists in both prior and
	// next, but next's CVSS score is strictly higher OR next carries
	// the KEV flag for that CVE while prior did not. Captures the
	// "Trivy DB updated, CVSS got worse" and "KEV listing landed"
	// cases the refresher is uniquely positioned to notice.
	VulnAlertEscalation VulnAlertTrigger = "severity_escalation"
)

// VulnAlertEvent is one emit-worthy delta the alerter detected. The
// concrete dispatch (webhook fan-out, finding mint, log line) is owned
// by the impl that wraps this — vuln_alert.go itself only computes
// deltas.
type VulnAlertEvent struct {
	OrgID      string
	RepoName   string
	Ecosystem  string
	Package    string
	Version    string
	CVE        string
	Trigger    VulnAlertTrigger
	CVSSScore  float64
	PriorScore float64 // 0 when Trigger == VulnAlertNewVuln
	KnownKEV   bool
}

// DiffReports computes the set of VulnAlertEvents implied by
// (prior, next). When prior is nil the function returns no events even
// if next carries vulnerabilities — issue #20 is about NEW alerts on
// EXISTING assets; a brand-new coordinate has no prior reference frame.
// Caller-supplied row fields are stamped on every returned event for
// downstream fan-out.
//
// Algorithm:
//  1. Build a map of prior CVE → (score, kev).
//  2. For every CVE in next, decide its trigger:
//     - missing from prior         → VulnAlertNewVuln
//     - present but worse in next  → VulnAlertEscalation
//     - present and not worse      → no event
//  3. Events are returned in stable CVE-sorted order so a
//     downstream throttle layer sees consistent ids per call.
//
// "Worse" is defined as: nextCVSS > priorCVSS OR (next.KEV && !prior.KEV).
// A KEV flip alone counts as an escalation even when the CVSS score is
// unchanged — KEV is operationally the highest-signal flag the refresher
// can surface, and dropping the alert would defeat the issue's intent.
func DiffReports(row metadata.PackageMetadataRow, ecosystem string, prior, next *Report) []VulnAlertEvent {
	if next == nil || prior == nil {
		return nil
	}
	priorByCVE := make(map[string]cveSnapshot, len(prior.Vulnerabilities.CVEs))
	for _, cve := range prior.Vulnerabilities.CVEs {
		priorByCVE[strings.ToUpper(strings.TrimSpace(cve))] = cveSnapshot{
			score: scoreForCVE(prior, cve),
			kev:   kevForCVE(prior, cve),
		}
	}

	var out []VulnAlertEvent
	for _, cve := range next.Vulnerabilities.CVEs {
		key := strings.ToUpper(strings.TrimSpace(cve))
		if key == "" {
			continue
		}
		nextScore := scoreForCVE(next, cve)
		nextKEV := kevForCVE(next, cve)
		prev, seenPrior := priorByCVE[key]
		switch {
		case !seenPrior:
			out = append(out, VulnAlertEvent{
				OrgID:     row.OrgID,
				RepoName:  row.Repository,
				Ecosystem: ecosystem,
				Package:   row.Package,
				Version:   row.Version,
				CVE:       key,
				Trigger:   VulnAlertNewVuln,
				CVSSScore: nextScore,
				KnownKEV:  nextKEV,
			})
		case nextScore > prev.score || (nextKEV && !prev.kev):
			out = append(out, VulnAlertEvent{
				OrgID:      row.OrgID,
				RepoName:   row.Repository,
				Ecosystem:  ecosystem,
				Package:    row.Package,
				Version:    row.Version,
				CVE:        key,
				Trigger:    VulnAlertEscalation,
				CVSSScore:  nextScore,
				PriorScore: prev.score,
				KnownKEV:   nextKEV,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CVE < out[j].CVE })
	return out
}

type cveSnapshot struct {
	score float64
	kev   bool
}

// scoreForCVE returns the CVSS score associated with a specific CVE on
// a Report. The VulnSection schema today carries a single CVSSScore
// (the maximum across the row's CVEs) plus a parallel CVEs list — there
// is no per-CVE score map in the on-disk shape, so the best we can do
// at this layer is return the section-wide score for every CVE. The
// escalation check still works because both prior and next use the same
// projection: a max-CVSS jump from 7.5 to 9.8 surfaces as a worsening
// score for every CVE in the union. When a future schema adds per-CVE
// scores (e.g. via CVEDetails), this function is the one place to
// migrate.
func scoreForCVE(r *Report, _ string) float64 {
	if r == nil {
		return 0
	}
	return r.Vulnerabilities.CVSSScore
}

// kevForCVE looks up the per-CVE KEV flag from VulnSection.KEVEntries
// if present, falling back to the section-wide KnownExploited bool when
// the per-entry list is empty. A missing entry returns false — KEV
// status is sticky-true at the section level but not at the per-CVE
// level, so we must not invent positives.
func kevForCVE(r *Report, cve string) bool {
	if r == nil {
		return false
	}
	want := strings.ToUpper(strings.TrimSpace(cve))
	for _, e := range r.Vulnerabilities.KEVEntries {
		if strings.ToUpper(strings.TrimSpace(e.CVE)) == want {
			return true
		}
	}
	// No per-entry detail — fall back to the section flag iff no entries
	// were enumerated at all. With entries present, a missing match is
	// authoritative.
	if len(r.Vulnerabilities.KEVEntries) == 0 {
		return r.Vulnerabilities.KnownExploited
	}
	return false
}

// SetVulnAlerter installs the issue #20 alerter on the refresher. nil
// is allowed and disables the feature. Safe to call once during
// bootstrap; not safe to swap once Run is in flight.
func (r *Refresher) SetVulnAlerter(a VulnAlerter) {
	if r == nil {
		return
	}
	r.alerter = a
}

// loadPriorReport reads the persisted Report for (ecosystem, pkg, ver)
// before the refresher's own Scan overwrites it. Returns nil when no
// row exists or when the Store is unavailable — DiffReports treats nil
// prior as "no diff window", which is the correct behaviour for a
// first-time scan.
func (r *Refresher) loadPriorReport(ctx context.Context, row metadata.PackageMetadataRow, ecosystem string) *Report {
	if r == nil || r.cfg.Store == nil {
		return nil
	}
	key := Key{Ecosystem: ecosystem, Package: row.Package, Version: row.Version}
	loadCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rep, err := r.cfg.Store.Get(loadCtx, row.OrgID, key)
	if err != nil {
		return nil
	}
	return rep
}
