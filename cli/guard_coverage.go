package cli

// guard_coverage.go — the optional fail-closed gate on the workstation guard.
//
// Off by default. When off, evaluateAll behaves exactly as it did before this
// file existed. See docs/plan_optional_fail_closed.md for the design, and for
// why the guard is defence-in-depth rather than proof: a developer can
// uninstall the shim, so the provable chokepoints are the proxy, CI, publish,
// and admission.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chain305/chainsaw-core/coverage"
)

const (
	coverageModeEnv       = coverage.EnvMode
	coverageRequiredEnv   = coverage.EnvRequired
	coverageGraceEnv      = coverage.EnvGrace
	coverageMaxAgeEnv     = coverage.EnvMaxAge
	coverageBreakGlassEnv = coverage.EnvBreakGlass
)

// guardPosture reads the operator's posture from the environment (MDM, a
// dotfile, or a CI runner). Local config only — there is no org distribution;
// see decision D4.
//
// Thin wrapper over coverage.PostureFromEnv: the parsing lives in the shared
// package so the guard, the proxy, the publish path, CI and admission cannot
// end up with subtly different readings of the same variables. That drift is
// the failure the single-Gate design exists to prevent.
func guardPosture() (coverage.Posture, error) {
	return coverage.PostureFromEnv(os.Getenv, func() {
		// Break-glass is loud on purpose — a silent bypass of a security
		// control is worse than no control.
		fmt.Fprintf(os.Stderr,
			"chainsaw: %s=1 — coverage fail-closed gate DISABLED for this invocation\n",
			coverage.EnvBreakGlass)
		recordGuardBreakGlass(os.Stderr, time.Now().UTC())
	})
}

// breakGlassSpoolFile is the append-only local record of coverage break-glass
// use, written under the CLI config home.
const breakGlassSpoolFile = "coverage-break-glass.jsonl"

// breakGlassSpoolCap bounds the spool. A CI job looping with break-glass set
// must not be able to fill a developer's disk through a security-logging path;
// once the file passes the cap we stop appending and say so, rather than
// silently truncating history that has not been shipped anywhere yet.
const breakGlassSpoolCap = 1 << 20 // 1 MiB

// breakGlassRecord is one spooled break-glass event.
//
// Deliberately carries no auth token and no environment dump: this file sits
// unencrypted in the user's config home. Host, user and pid are what an
// investigator actually needs to tie the bypass to a machine and a session,
// and they are the same class of identifier the server-side audit row records.
type breakGlassRecord struct {
	// ID is this record's dedup nonce. Minted once, at append time, and
	// never regenerated: it is what lets a retried flush be recognised by
	// the server as the SAME event rather than written twice. Records
	// spooled before the flush existed carry no id; loadBreakGlassSpool
	// derives a stable one from the line's content for those.
	ID          string    `json:"id,omitempty"`
	Event       string    `json:"event"`
	At          time.Time `json:"at"`
	Host        string    `json:"host,omitempty"`
	User        string    `json:"user,omitempty"`
	PID         int       `json:"pid"`
	Argv0       string    `json:"argv0,omitempty"`
	Mode        string    `json:"coverage_mode,omitempty"`
	Required    string    `json:"coverage_required,omitempty"`
	OrgID       string    `json:"org_id,omitempty"`
	ServerURL   string    `json:"server_url,omitempty"`
	Delivered   bool      `json:"delivered"`
	Undelivered string    `json:"undelivered_reason,omitempty"`
}

// recordGuardBreakGlass writes a durable local record that the coverage
// fail-closed gate was bypassed, and tells the operator where it went.
//
// THE FAILURE MODE IS THE DESIGN. Break-glass is an emergency hatch; a hatch
// that fails during an emergency is worse than no hatch. So every branch here
// is best-effort and swallowing:
//
//   - it never returns an error, so no caller can be tempted to propagate one;
//   - it never blocks (a bounded local append, no network, no lock waiting);
//   - it never exits non-zero and never introduces a new failure mode — an
//     unwritable config home, a read-only filesystem, a full disk and a
//     missing HOME all end in a printed line and a return.
//
// The stderr line the caller already printed is erasable with `2>/dev/null` by
// the very process doing the bypassing, which is why the file exists at all.
// The file is not tamper-proof either — the bypasser owns it too — but it
// survives the invocation, which the stderr line does not.
//
// DELIVERY: the record is written delivered=false and STAYS that way until a
// server has confirmed it. maybeFlushBreakGlassSpool ships it opportunistically
// on the next successful authenticated command; the spool line itself is never
// rewritten, so this file never claims a delivery it did not make. See
// breakGlassDeliveredFile for how confirmations are tracked.
func recordGuardBreakGlass(stderr *os.File, now time.Time) {
	defer func() {
		// A logging path must never be able to take down the command it is
		// logging about. Any panic below (a nil stderr in an embedding, a
		// pathological config home) dies here.
		_ = recover()
	}()

	rec := breakGlassRecord{
		Event:       "coverage.break_glass",
		At:          now,
		PID:         os.Getpid(),
		Mode:        strings.TrimSpace(os.Getenv(coverage.EnvMode)),
		Required:    strings.TrimSpace(os.Getenv(coverage.EnvRequired)),
		ID:          newBreakGlassRecordID(),
		Delivered:   false,
		Undelivered: "not yet flushed to the server; held locally",
	}
	if h, err := os.Hostname(); err == nil {
		rec.Host = h
	}
	if u, err := user.Current(); err == nil && u != nil {
		rec.User = u.Username
	}
	if len(os.Args) > 0 {
		rec.Argv0 = filepath.Base(os.Args[0])
	}
	// Best-effort context so a collected spool can be matched to a tenant.
	// cfgOrgID/cfgServerURL read viper, which is already initialised by the
	// time any guard evaluation runs; both are plain identifiers, never
	// credentials.
	rec.OrgID = strings.TrimSpace(cfgOrgID())
	rec.ServerURL = strings.TrimSpace(cfgServerURL())

	path, err := appendBreakGlassSpool(rec)
	if err != nil {
		// Even the fallback is best-effort. Say plainly that no durable
		// record exists rather than implying one does.
		fmt.Fprintf(stderr,
			"chainsaw: could not write the break-glass record (%v) — this bypass has NO durable record\n", err)
		return
	}
	fmt.Fprintf(stderr,
		"chainsaw: break-glass recorded locally at %s (sent to the server on the next authenticated command)\n", path)
}

// appendBreakGlassSpool appends one JSON line to the spool and returns its
// path. Split out from recordGuardBreakGlass so the failure branches are
// testable without capturing os.Stderr.
func appendBreakGlassSpool(rec breakGlassRecord) (string, error) {
	dir := configDir()
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("no config home")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, breakGlassSpoolFile)
	if info, err := os.Stat(path); err == nil && info.Size() > breakGlassSpoolCap {
		// Refuse to grow rather than rotating: rotation would delete
		// un-shipped security records, which is the one outcome this file
		// exists to prevent.
		return "", fmt.Errorf("spool %s is full (>%d bytes) and has not been collected", path, breakGlassSpoolCap)
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return "", err
	}
	return path, nil
}

// ---------------------------------------------------------------------------
// Flush: spool -> server.
//
// The destination is POST /api/coverage/break-glass
// (internal/server/coverage_break_glass_api.go), which needs authentication
// and nothing else — deliberately NOT the audit relay, which requires
// `audit:write` that org-member does not have.
//
// EVERY PROPERTY OF THE WRITE PATH IS PRESERVED HERE, and each one is load
// bearing:
//
//   - Cannot fail the command. maybeFlushBreakGlassSpool returns nothing,
//     swallows panics, and every error branch is a plain `return`. Its one
//     call site (APIClient.do) ignores it and cannot observe it, so no exit
//     code and no error message can be traced back to it.
//   - Cannot block the command meaningfully. The fast path on an ordinary run
//     is a single failing os.Stat — the spool only exists after a bypass. When
//     it does exist the flush is ONE request with its own short timeout,
//     issued after the caller's own response is already fully read.
//   - Never deletes a record it did not confirm delivered. The spool is never
//     rewritten, truncated or rotated by this path. Confirmations go into a
//     separate append-only sidecar, so a crash mid-flush can at worst lose a
//     confirmation, which costs one deduped re-send and never a record.
//   - Bounded. At most breakGlassFlushBatch records per attempt and at most
//     one attempt per process, so a large backlog drains over several
//     invocations instead of turning one command into a bulk uploader.
//   - De-duplicated. Each record carries a stable id; the server keys a
//     deterministic audit_events primary key off it and answers with the ids
//     it made durable. Only those are marked delivered, so a partially
//     successful flush re-sends the remainder and double-writes nothing.
// ---------------------------------------------------------------------------

// breakGlassDeliveredFile records which spool ids a server has confirmed.
//
// A SEPARATE, APPEND-ONLY file rather than a flag flipped inside the spool.
// Marking delivery in place would mean rewriting the spool, and a rewrite is
// the one operation that can lose a record: a crash or a concurrent append
// from another chainsaw process during the rewrite destroys history that has
// not been collected anywhere. Appending an id costs one line and cannot
// truncate anything.
const breakGlassDeliveredFile = "coverage-break-glass.delivered"

// breakGlassFlushBatch is how many records one attempt ships. Must stay <= the
// server's breakGlassMaxRecordsPerRequest (20), which rejects anything larger.
const breakGlassFlushBatch = 20

// breakGlassFlushPath is the server endpoint. Authentication only — see the
// file header on internal/server/coverage_break_glass_api.go for why this is
// not the audit relay.
const breakGlassFlushPath = "/api/coverage/break-glass"

// breakGlassFlushTimeout bounds the whole request. Deliberately far below the
// 30s default: this call is a passenger on someone else's command, and a
// hanging server must cost that command seconds, not half a minute.
const breakGlassFlushTimeout = 5 * time.Second

// breakGlassFlushAttempted makes the flush at-most-once per process.
//
// It is a CAS flag and NOT a sync.Once on purpose: the flush issues its own
// authenticated request, which re-enters the call site below. sync.Once.Do
// re-entered from inside its own function deadlocks; a CAS flag makes the
// inner call a no-op instead.
var breakGlassFlushAttempted atomic.Bool

// breakGlassWireRecord is the on-the-wire shape. It is a DIFFERENT type from
// breakGlassRecord, and the difference is the point: the spool's User, OrgID
// and ServerURL fields are local triage context and are NOT sent. The server
// decides who the caller is from the bearer credential; anything
// identity-shaped in this body would be ignored at best, and the server in
// fact rejects the whole request for carrying an unknown field.
type breakGlassWireRecord struct {
	ID       string    `json:"id"`
	At       time.Time `json:"at"`
	Host     string    `json:"host,omitempty"`
	PID      int       `json:"pid,omitempty"`
	Argv0    string    `json:"argv0,omitempty"`
	Mode     string    `json:"coverage_mode,omitempty"`
	Required string    `json:"coverage_required,omitempty"`
}

type breakGlassFlushRequest struct {
	Records []breakGlassWireRecord `json:"records"`
}

type breakGlassFlushResponse struct {
	// Accepted lists the record ids the server has made durable. It is the
	// ONLY thing that authorises marking a record delivered — not the HTTP
	// status, and not the count.
	Accepted   []string `json:"accepted"`
	Stored     int      `json:"stored"`
	Duplicates int      `json:"duplicates"`
}

// newBreakGlassRecordID mints a record's dedup nonce.
//
// Never fails. If the system CSPRNG is unavailable the fallback is weaker (two
// processes starting in the same nanosecond would collide) but a collision
// costs one record deduped against another, whereas returning an error would
// cost the record itself. In a path whose entire contract is "never fail",
// weaker is the correct trade.
func newBreakGlassRecordID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return fmt.Sprintf("t%dp%d", time.Now().UTC().UnixNano(), os.Getpid())
}

// maybeFlushBreakGlassSpool ships spooled break-glass records, opportunistically.
//
// Called from APIClient.do on a successful authenticated response. Returns
// nothing and can be ignored by every caller, because there is no outcome here
// that a caller should act on: the records are already durable locally, and a
// failed flush simply leaves them there for the next invocation.
//
// SILENT ON FAILURE, unlike the write path. The write path prints because it
// is running inside the bypass and the operator is watching it; this runs
// inside an unrelated later command, where a line about a coverage spool would
// be noise at best and would be read as that command failing at worst.
func maybeFlushBreakGlassSpool(baseURL, token string) {
	defer func() {
		// Same reasoning as recordGuardBreakGlass: a logging path must
		// never be able to take down the command it is a passenger on.
		_ = recover()
	}()
	if strings.TrimSpace(baseURL) == "" || strings.TrimSpace(token) == "" {
		return
	}
	if !breakGlassFlushAttempted.CompareAndSwap(false, true) {
		return
	}
	dir := configDir()
	if strings.TrimSpace(dir) == "" {
		return
	}
	// Fast path for the ~100% of runs where nobody has ever used break-glass:
	// one failing stat, no read, no allocation.
	if _, err := os.Stat(filepath.Join(dir, breakGlassSpoolFile)); err != nil {
		return
	}
	pending := pendingBreakGlassRecords(dir, breakGlassFlushBatch)
	if len(pending) == 0 {
		return
	}
	req := breakGlassFlushRequest{Records: make([]breakGlassWireRecord, 0, len(pending))}
	for _, rec := range pending {
		req.Records = append(req.Records, breakGlassWireRecord{
			ID:       rec.ID,
			At:       rec.At,
			Host:     rec.Host,
			PID:      rec.PID,
			Argv0:    rec.Argv0,
			Mode:     rec.Mode,
			Required: rec.Required,
		})
	}
	var resp breakGlassFlushResponse
	client := newAPIClientWithTimeout(baseURL, token, breakGlassFlushTimeout)
	if err := client.Post(breakGlassFlushPath, req, &resp); err != nil {
		// Server unreachable, 401, 429, 500, an older server with no such
		// route — all identical from here. The spool is untouched and the
		// next invocation tries again.
		return
	}
	if len(resp.Accepted) == 0 {
		return
	}
	// Mark ONLY what the server named. A 200 whose body listed fewer ids
	// than we sent means the rest were not persisted, and treating the
	// status as the confirmation would drop them.
	markBreakGlassDelivered(dir, resp.Accepted)
}

// pendingBreakGlassRecords returns up to limit spooled records the server has
// not confirmed. Best-effort: an unreadable spool or sidecar yields nothing,
// never an error, because there is no caller who could do anything with one.
func pendingBreakGlassRecords(dir string, limit int) []breakGlassRecord {
	if limit <= 0 {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, breakGlassSpoolFile))
	if err != nil {
		return nil
	}
	delivered := deliveredBreakGlassIDs(dir)
	var out []breakGlassRecord
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec breakGlassRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			// A corrupt line is skipped, not fatal. One truncated write
			// (a full disk mid-append) must not strand every record
			// after it.
			continue
		}
		if !breakGlassIDIsSendable(rec.ID) {
			// Two cases, one answer. Records spooled before ids existed
			// carry none; a hand-edited or corrupted spool can carry one
			// the server's charset rejects. Either way, deriving the id
			// from the line's own bytes keeps it STABLE across attempts
			// — which is what makes them dedupable at all — and, for the
			// malformed case, keeps a poison record from parking at the
			// head of every batch and 400ing the whole spool forever.
			rec.ID = breakGlassLegacyID(line)
		}
		if delivered[rec.ID] || seen[rec.ID] {
			continue
		}
		seen[rec.ID] = true
		out = append(out, rec)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// breakGlassIDIsSendable mirrors the server's record-id rule (non-empty, at
// most 128 chars, [A-Za-z0-9-_.:]). Kept client-side so the CLI can never put
// an id on the wire that the endpoint will reject: a rejected batch is a 400,
// and a 400 caused by one malformed line at the head of the spool would strand
// every record behind it.
func breakGlassIDIsSendable(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}

// breakGlassLegacyID derives a stable id for a spool line that predates the
// id field, or whose id the server would refuse. Hex, so it always satisfies
// breakGlassIDIsSendable.
func breakGlassLegacyID(line string) string {
	sum := sha256.Sum256([]byte(line))
	return "h" + hex.EncodeToString(sum[:])[:40]
}

// deliveredBreakGlassIDs reads the confirmation sidecar. A missing or
// unreadable sidecar reads as "nothing confirmed", which re-sends records the
// server already holds — harmless, because the server dedupes on the same ids.
// The opposite default (assume delivered) would silently drop records.
func deliveredBreakGlassIDs(dir string) map[string]bool {
	out := make(map[string]bool)
	raw, err := os.ReadFile(filepath.Join(dir, breakGlassDeliveredFile))
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out[line] = true
		}
	}
	return out
}

// markBreakGlassDelivered appends confirmed ids to the sidecar.
//
// Append-only and capped the same way the spool is: a client that somehow
// loops through confirmations must not fill the disk through a security-
// logging path. Hitting the cap stops the file growing; the records are
// already durable server-side, and the only cost is that they are re-sent and
// deduped again.
func markBreakGlassDelivered(dir string, ids []string) {
	if len(ids) == 0 {
		return
	}
	path := filepath.Join(dir, breakGlassDeliveredFile)
	if info, err := os.Stat(path); err == nil && info.Size() > breakGlassSpoolCap {
		return
	}
	var buf strings.Builder
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		buf.WriteString(id)
		buf.WriteByte('\n')
	}
	if buf.Len() == 0 {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	// One Write of one small buffer: O_APPEND makes it atomic against a
	// concurrent chainsaw process doing the same thing.
	_, _ = f.WriteString(buf.String())
}

// guardLedger reports what the offline guard could actually evaluate.
//
// The guard is not the proxy: it has no CVE feed, no registry metadata, and no
// package bytes unless the operator staged artifacts or enabled deep mode.
// Those sources are reported as UNAVAILABLE rather than omitted, so that an
// operator who requires one gets an honest refusal with a readable reason
// instead of a silently inert control.
//
// The codes here are guard-local strings written straight into Entry.Code for
// the audit trail; they never pass through StatusForWarnCode, so they do not
// belong in the classifier tables.
func guardLedger(g *localGuard, now time.Time) coverage.Ledger {
	ok := func() coverage.Entry {
		return coverage.Entry{Status: coverage.StatusOK, Producer: "guard", ObservedAt: now, LastOKAt: now}
	}
	unavailable := func(code string) coverage.Entry {
		return coverage.Entry{Status: coverage.StatusUnavailable, Producer: "guard", Code: code, ObservedAt: now}
	}

	led := coverage.Ledger{
		// Always available offline: the typosquat corpus is embedded.
		coverage.SourceTyposquat: ok(),
		// Never available on the offline guard — these need the server.
		coverage.SourceCVE:              unavailable("offline_guard_no_network"),
		coverage.SourceRegistryMetadata: unavailable("offline_guard_no_network"),
		coverage.SourceProvenance:       unavailable("offline_guard_no_network"),
	}

	// The embedded floor alone is partial coverage; an operator who required
	// `malware` asked for the full OpenSSF set, not the famous-attack subset.
	if g != nil && g.fullFeed {
		led[coverage.SourceMalware] = ok()
	} else {
		led[coverage.SourceMalware] = unavailable("feed_not_downloaded")
	}

	// Artifact-bound sources need bytes, which exist only when the operator
	// staged them or turned on deep mode.
	artifactStatus := unavailable("no_artifact_bytes")
	if os.Getenv(guardArtifactDirEnv) != "" || deepFetchEnabled() {
		artifactStatus = ok()
	}
	led[coverage.SourceChecksum] = artifactStatus
	led[coverage.SourceInstallScripts] = artifactStatus
	led[coverage.SourceHiddenUnicode] = artifactStatus

	return led
}
