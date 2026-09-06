package cli

// The CLI -> server flush of the coverage break-glass spool.
//
// The spool's whole reason to exist is that it survives a bypass the bypasser
// controls. The flush must not weaken that, so these pin four things in order
// of how badly they would hurt if they broke:
//
//  1. it can never fail, delay, or change the exit code of the command it
//     rides on — proven with the destination 500ing and with it unreachable;
//  2. it never deletes or rewrites a record it did not see confirmed;
//  3. it de-duplicates, so a half-acknowledged flush does not double-write;
//  4. it is bounded, so a backlog cannot turn one command into a bulk upload.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// resetBreakGlassFlush clears the at-most-once-per-process latch so one test
// binary can exercise several flushes.
func resetBreakGlassFlush(t *testing.T) {
	t.Helper()
	breakGlassFlushAttempted.Store(false)
	t.Cleanup(func() { breakGlassFlushAttempted.Store(false) })
}

// seedSpool writes n records into the spool at dir and returns their ids.
func seedSpool(t *testing.T, dir string, n int) []string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir config home: %v", err)
	}
	ids := make([]string, 0, n)
	path := filepath.Join(dir, breakGlassSpoolFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open spool: %v", err)
	}
	defer f.Close()
	for i := 0; i < n; i++ {
		rec := breakGlassRecord{
			ID:          fmt.Sprintf("seed%02d", i),
			Event:       "coverage.break_glass",
			At:          time.Now().UTC().Add(-time.Duration(i) * time.Minute),
			Host:        "box-1",
			User:        "dev",
			PID:         1000 + i,
			Argv0:       "chainsaw",
			Mode:        "closed",
			Required:    "cve",
			OrgID:       "org-local",
			ServerURL:   "https://example.invalid",
			Delivered:   false,
			Undelivered: "not yet flushed to the server; held locally",
		}
		line, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal seed: %v", err)
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			t.Fatalf("write seed: %v", err)
		}
		ids = append(ids, rec.ID)
	}
	return ids
}

// breakGlassStub is a fake server for the flush endpoint. accept decides which
// of the posted ids it claims to have made durable.
type breakGlassStub struct {
	srv      *httptest.Server
	bodies   []string
	requests int
	accept   func(ids []string) []string
	status   int
}

func newBreakGlassStub(t *testing.T) *breakGlassStub {
	t.Helper()
	st := &breakGlassStub{status: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc(breakGlassFlushPath, func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1<<20)
		n, _ := r.Body.Read(buf)
		raw := string(buf[:n])
		st.bodies = append(st.bodies, raw)
		st.requests++
		if st.status != http.StatusOK {
			w.WriteHeader(st.status)
			_, _ = w.Write([]byte(`{"error":{"code":"CHW-5000","message":"boom"}}`))
			return
		}
		var req breakGlassFlushRequest
		if err := json.Unmarshal([]byte(raw), &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ids := make([]string, 0, len(req.Records))
		for _, rec := range req.Records {
			ids = append(ids, rec.ID)
		}
		if st.accept != nil {
			ids = st.accept(ids)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(breakGlassFlushResponse{Accepted: ids, Stored: len(ids)})
	})
	// A plain endpoint standing in for "the command the user actually ran".
	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	st.srv = httptest.NewServer(mux)
	t.Cleanup(st.srv.Close)
	return st
}

func readSidecar(t *testing.T, dir string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, breakGlassDeliveredFile))
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// TestBreakGlassFlushShipsSpoolOnTheNextAuthenticatedCommand.
//
// The flush is a passenger: nothing calls it directly, it rides the next
// successful authenticated request. This drives the real transport so the
// wiring is exercised, not just the helper.
//
// Deletion proof: remove the maybeFlushBreakGlassSpool call from APIClient.do
// and this fails.
func TestBreakGlassFlushShipsSpoolOnTheNextAuthenticatedCommand(t *testing.T) {
	dir := withTempConfigHome(t)
	resetBreakGlassFlush(t)
	want := seedSpool(t, dir, 2)
	stub := newBreakGlassStub(t)

	client := NewAPIClient(stub.srv.URL, "a-credential")
	var out map[string]any
	if err := client.Get("/api/ping", &out); err != nil {
		t.Fatalf("the command itself failed: %v", err)
	}

	if stub.requests != 1 {
		t.Fatalf("flush made %d requests, want 1", stub.requests)
	}
	var sent breakGlassFlushRequest
	if err := json.Unmarshal([]byte(stub.bodies[0]), &sent); err != nil {
		t.Fatalf("decode flushed body: %v", err)
	}
	if len(sent.Records) != 2 {
		t.Fatalf("flushed %d records, want 2", len(sent.Records))
	}
	got := []string{sent.Records[0].ID, sent.Records[1].ID}
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("flushed ids = %v, want %v", got, want)
	}
	if sent.Records[0].Mode != "closed" || sent.Records[0].Required != "cve" {
		t.Errorf("the flushed record lost WHICH control was disabled: %+v", sent.Records[0])
	}
	if ids := readSidecar(t, dir); len(ids) != 2 {
		t.Fatalf("sidecar holds %v, want both confirmed ids", ids)
	}
}

// TestBreakGlassFlushSendsNoIdentityFields.
//
// The client says WHAT; the server says WHO. The spool keeps user / org_id /
// server_url as local triage context and those must not leave the machine as
// identity claims — the server derives all of that from the credential, and
// rejects a body that carries any of it.
//
// Deletion proof: marshal breakGlassRecord onto the wire instead of
// breakGlassWireRecord and this fails.
func TestBreakGlassFlushSendsNoIdentityFields(t *testing.T) {
	dir := withTempConfigHome(t)
	resetBreakGlassFlush(t)
	seedSpool(t, dir, 1)
	stub := newBreakGlassStub(t)

	client := NewAPIClient(stub.srv.URL, "a-credential")
	if err := client.Get("/api/ping", nil); err != nil {
		t.Fatalf("the command itself failed: %v", err)
	}
	if stub.requests != 1 {
		t.Fatalf("flush made %d requests, want 1", stub.requests)
	}
	body := strings.ToLower(stub.bodies[0])
	for _, banned := range []string{"\"user\"", "org_id", "server_url", "delivered", "token", "secret", "authorization"} {
		if strings.Contains(body, banned) {
			t.Errorf("flushed body carries %s — identity and credentials are server-derived, never client-claimed: %s", banned, stub.bodies[0])
		}
	}
}

// TestBreakGlassFlushNeverFailsTheCommand is the property that matters most,
// and it is proven by DELETION: the destination is broken in two different
// ways and the guarded command must come back byte-identical to the run with
// no spool at all.
//
// A break-glass record is written during an emergency. If shipping it could
// fail the next command, the feature would have converted a logging path into
// an outage.
func TestBreakGlassFlushNeverFailsTheCommand(t *testing.T) {
	// Control: what does the command do with no spool in play?
	baseline := func() (error, string) {
		dir := withTempConfigHome(t)
		resetBreakGlassFlush(t)
		stub := newBreakGlassStub(t)
		client := NewAPIClient(stub.srv.URL, "a-credential")
		var out map[string]any
		err := client.Get("/api/ping", &out)
		return err, dir
	}
	baseErr, _ := baseline()
	if baseErr != nil {
		t.Fatalf("baseline command failed: %v", baseErr)
	}

	t.Run("destination 500s", func(t *testing.T) {
		dir := withTempConfigHome(t)
		resetBreakGlassFlush(t)
		seedSpool(t, dir, 2)
		stub := newBreakGlassStub(t)
		stub.status = http.StatusInternalServerError

		before, err := os.ReadFile(filepath.Join(dir, breakGlassSpoolFile))
		if err != nil {
			t.Fatalf("read spool: %v", err)
		}
		client := NewAPIClient(stub.srv.URL, "a-credential")
		var out map[string]any
		if err := client.Get("/api/ping", &out); err != nil {
			t.Fatalf("command returned %v with a 500ing break-glass endpoint; want nil, exactly as the baseline", err)
		}
		if out["ok"] != true {
			t.Fatalf("command lost its own response body: %v", out)
		}
		after, err := os.ReadFile(filepath.Join(dir, breakGlassSpoolFile))
		if err != nil {
			t.Fatalf("read spool after: %v", err)
		}
		if string(before) != string(after) {
			t.Fatal("the spool changed after a failed flush — a record must never be touched until it is confirmed delivered")
		}
		if ids := readSidecar(t, dir); len(ids) != 0 {
			t.Fatalf("sidecar claims %v delivered after a 500; nothing was confirmed", ids)
		}
	})

	t.Run("destination unreachable", func(t *testing.T) {
		dir := withTempConfigHome(t)
		resetBreakGlassFlush(t)
		seedSpool(t, dir, 2)
		stub := newBreakGlassStub(t)
		url := stub.srv.URL

		// A server that answers the command and then vanishes is not
		// reproducible in one process, so the flush is driven directly
		// against a dead listener — the same code path, no live command
		// needed to make the point.
		stub.srv.Close()
		maybeFlushBreakGlassSpool(url, "a-credential")

		if ids := readSidecar(t, dir); len(ids) != 0 {
			t.Fatalf("sidecar claims %v delivered against a dead server", ids)
		}
		if recs := readSpool(t, dir); len(recs) != 2 {
			t.Fatalf("spool holds %d records after an unreachable flush, want 2", len(recs))
		}
	})
}

// TestBreakGlassFlushMarksOnlyConfirmedRecords.
//
// A partially successful flush is the case the de-duplication exists for. The
// server names exactly the ids it made durable; anything it did not name stays
// spooled and is re-sent, and nothing that was named is sent again.
//
// Deletion proof: mark everything that was SENT delivered (rather than
// everything ACCEPTED) and the second flush stops re-sending the lost record.
func TestBreakGlassFlushMarksOnlyConfirmedRecords(t *testing.T) {
	dir := withTempConfigHome(t)
	resetBreakGlassFlush(t)
	ids := seedSpool(t, dir, 3)
	stub := newBreakGlassStub(t)
	// The server durably stored only the first record.
	stub.accept = func(sent []string) []string { return sent[:1] }

	maybeFlushBreakGlassSpool(stub.srv.URL, "a-credential")

	confirmed := readSidecar(t, dir)
	if len(confirmed) != 1 || confirmed[0] != ids[0] {
		t.Fatalf("sidecar = %v, want only the one id the server confirmed (%s)", confirmed, ids[0])
	}

	// Next process: the two unconfirmed records come back, the confirmed one
	// does not.
	resetBreakGlassFlush(t)
	stub.accept = nil
	maybeFlushBreakGlassSpool(stub.srv.URL, "a-credential")
	if stub.requests != 2 {
		t.Fatalf("second flush made %d total requests, want 2", stub.requests)
	}
	var second breakGlassFlushRequest
	if err := json.Unmarshal([]byte(stub.bodies[1]), &second); err != nil {
		t.Fatalf("decode second body: %v", err)
	}
	if len(second.Records) != 2 {
		t.Fatalf("second flush sent %d records, want the 2 that were never confirmed", len(second.Records))
	}
	for _, rec := range second.Records {
		if rec.ID == ids[0] {
			t.Fatalf("record %s was re-sent after the server confirmed it — a confirmed record must not be written twice", rec.ID)
		}
	}

	// And a third pass, with everything confirmed, sends nothing at all.
	resetBreakGlassFlush(t)
	maybeFlushBreakGlassSpool(stub.srv.URL, "a-credential")
	if stub.requests != 2 {
		t.Fatalf("a fully-delivered spool still produced a request (%d total)", stub.requests)
	}
}

// TestBreakGlassFlushIsBounded — a backlog drains over several invocations
// instead of turning one command into a bulk uploader, and the batch stays
// inside what the server accepts (its limit is 20; a larger batch is a 400,
// which would strand the whole spool forever).
func TestBreakGlassFlushIsBounded(t *testing.T) {
	dir := withTempConfigHome(t)
	resetBreakGlassFlush(t)
	seedSpool(t, dir, breakGlassFlushBatch+15)
	stub := newBreakGlassStub(t)

	maybeFlushBreakGlassSpool(stub.srv.URL, "a-credential")

	var sent breakGlassFlushRequest
	if err := json.Unmarshal([]byte(stub.bodies[0]), &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(sent.Records) != breakGlassFlushBatch {
		t.Fatalf("one flush shipped %d records, want the batch cap of %d", len(sent.Records), breakGlassFlushBatch)
	}
	if breakGlassFlushBatch > 20 {
		t.Fatalf("breakGlassFlushBatch is %d; the server rejects anything over 20 per request, which would strand the spool", breakGlassFlushBatch)
	}
}

// TestBreakGlassFlushHappensAtMostOncePerProcess.
//
// The flush issues its own authenticated request, which re-enters the same
// hook in APIClient.do. Without the latch that is unbounded recursion; with a
// sync.Once instead of a CAS flag it is a deadlock. Neither shows up as a test
// failure elsewhere — it shows up as a hung CLI.
func TestBreakGlassFlushHappensAtMostOncePerProcess(t *testing.T) {
	dir := withTempConfigHome(t)
	resetBreakGlassFlush(t)
	seedSpool(t, dir, 2)
	stub := newBreakGlassStub(t)

	client := NewAPIClient(stub.srv.URL, "a-credential")
	for i := 0; i < 4; i++ {
		if err := client.Get("/api/ping", nil); err != nil {
			t.Fatalf("command %d failed: %v", i, err)
		}
	}
	if stub.requests != 1 {
		t.Fatalf("flush ran %d times across 4 commands, want 1", stub.requests)
	}
}

// TestBreakGlassFlushSkipsAnonymousCommands — an anonymous call has no
// credential to attribute a record to, and the endpoint would 401. Spending
// the process's one attempt on it would silently postpone delivery to the next
// run.
func TestBreakGlassFlushSkipsAnonymousCommands(t *testing.T) {
	dir := withTempConfigHome(t)
	resetBreakGlassFlush(t)
	seedSpool(t, dir, 1)
	stub := newBreakGlassStub(t)

	anon := NewAPIClient(stub.srv.URL, "")
	if err := anon.Get("/api/ping", nil); err != nil {
		t.Fatalf("anonymous command failed: %v", err)
	}
	if stub.requests != 0 {
		t.Fatalf("flush ran on an anonymous command (%d requests)", stub.requests)
	}
	// The credential arriving later still works.
	if err := NewAPIClient(stub.srv.URL, "a-credential").Get("/api/ping", nil); err != nil {
		t.Fatalf("authenticated command failed: %v", err)
	}
	if stub.requests != 1 {
		t.Fatalf("flush ran %d times on the authenticated command, want 1", stub.requests)
	}
}

// TestBreakGlassSpoolIsNeverRewritten — the confirmation lives in a separate
// append-only sidecar precisely so this file is never rewritten. A rewrite is
// the one operation that can lose a record: a crash, or a concurrent append
// from another chainsaw process, during the rewrite destroys history nothing
// else holds.
func TestBreakGlassSpoolIsNeverRewritten(t *testing.T) {
	dir := withTempConfigHome(t)
	resetBreakGlassFlush(t)
	seedSpool(t, dir, 3)
	path := filepath.Join(dir, breakGlassSpoolFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	stub := newBreakGlassStub(t)

	maybeFlushBreakGlassSpool(stub.srv.URL, "a-credential")

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spool after: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("the spool was modified by a successful flush; delivery is tracked in the sidecar so records are never rewritten or deleted")
	}
}

// TestBreakGlassLegacySpoolLinesGetAStableID — records written before the id
// field existed must still be flushable, and their derived id must be STABLE
// across attempts. A per-attempt id would make every retry look like a brand
// new event and defeat the de-duplication entirely.
func TestBreakGlassLegacySpoolLinesGetAStableID(t *testing.T) {
	dir := withTempConfigHome(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	legacy := `{"event":"coverage.break_glass","at":"2026-09-01T10:00:00Z","host":"old-box","pid":7,"coverage_mode":"closed","delivered":false}`
	if err := os.WriteFile(filepath.Join(dir, breakGlassSpoolFile), []byte(legacy+"\n"), 0o600); err != nil {
		t.Fatalf("seed legacy spool: %v", err)
	}

	first := pendingBreakGlassRecords(dir, breakGlassFlushBatch)
	second := pendingBreakGlassRecords(dir, breakGlassFlushBatch)
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("legacy line not picked up: %d / %d", len(first), len(second))
	}
	if first[0].ID == "" {
		t.Fatal("legacy line got no id; it could never be de-duplicated")
	}
	if first[0].ID != second[0].ID {
		t.Fatalf("legacy id is not stable across attempts (%q vs %q) — every retry would write a new row",
			first[0].ID, second[0].ID)
	}
	// Confirming it must stick.
	markBreakGlassDelivered(dir, []string{first[0].ID})
	if got := pendingBreakGlassRecords(dir, breakGlassFlushBatch); len(got) != 0 {
		t.Fatalf("a confirmed legacy record is still pending: %+v", got)
	}
}

// TestBreakGlassSpoolSkipsCorruptLines — one truncated write (a full disk
// mid-append) must not strand every record after it.
func TestBreakGlassSpoolSkipsCorruptLines(t *testing.T) {
	dir := withTempConfigHome(t)
	seedSpool(t, dir, 1)
	path := filepath.Join(dir, breakGlassSpoolFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open spool: %v", err)
	}
	if _, err := f.WriteString("{\"event\":\"coverage.break_gl\n"); err != nil {
		t.Fatalf("write truncated line: %v", err)
	}
	if _, err := f.WriteString(`{"id":"after-the-corruption","event":"coverage.break_glass"}` + "\n"); err != nil {
		t.Fatalf("write trailing line: %v", err)
	}
	f.Close()

	got := pendingBreakGlassRecords(dir, breakGlassFlushBatch)
	if len(got) != 2 {
		t.Fatalf("got %d pending records, want 2 (the corrupt line skipped, the one after it kept)", len(got))
	}
	if got[1].ID != "after-the-corruption" {
		t.Fatalf("the record after a corrupt line was stranded: %+v", got)
	}
}

// TestBreakGlassFlushIsSilent — this runs inside an unrelated later command.
// A line about a coverage spool there is noise at best, and at worst is read
// as that command failing. The loud line belongs on the write path, where the
// operator is watching the bypass itself.
func TestBreakGlassFlushIsSilent(t *testing.T) {
	dir := withTempConfigHome(t)
	resetBreakGlassFlush(t)
	seedSpool(t, dir, 1)
	stub := newBreakGlassStub(t)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	maybeFlushBreakGlassSpool(stub.srv.URL, "a-credential")
	os.Stderr = orig
	w.Close()
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	if n > 0 {
		t.Fatalf("the flush wrote to stderr of an unrelated command: %q", string(buf[:n]))
	}
}

// TestNewBreakGlassRecordIDNeverEmpty — the id is minted on the write path,
// which must never fail. An empty id would make the record undeliverable.
func TestNewBreakGlassRecordIDNeverEmpty(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := newBreakGlassRecordID()
		if strings.TrimSpace(id) == "" {
			t.Fatal("newBreakGlassRecordID returned empty")
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
		// Must satisfy the server's id charset, or the record is a
		// permanent 400 and never lands.
		for _, r := range id {
			ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
				r == '-' || r == '_' || r == '.' || r == ':'
			if !ok {
				t.Fatalf("id %q contains %q, which the server rejects", id, r)
			}
		}
	}
}

// TestBreakGlassMalformedIDIsReplacedNotSent — a hand-edited or corrupted
// spool must not be able to strand every record behind it. The server's record
// id charset is mirrored client-side, so an id it would 400 on is swapped for
// the stable content-derived one before it ever goes on the wire; without
// that, one poison line at the head of the batch 400s the whole flush on every
// attempt, forever.
func TestBreakGlassMalformedIDIsReplacedNotSent(t *testing.T) {
	dir := withTempConfigHome(t)
	resetBreakGlassFlush(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	poison := `{"id":"has a space/and slash","event":"coverage.break_glass"}`
	good := `{"id":"cleanid01","event":"coverage.break_glass"}`
	if err := os.WriteFile(filepath.Join(dir, breakGlassSpoolFile),
		[]byte(poison+"\n"+good+"\n"), 0o600); err != nil {
		t.Fatalf("seed spool: %v", err)
	}

	got := pendingBreakGlassRecords(dir, breakGlassFlushBatch)
	if len(got) != 2 {
		t.Fatalf("got %d pending, want 2 — the malformed line must not strand the one behind it", len(got))
	}
	if !breakGlassIDIsSendable(got[0].ID) {
		t.Fatalf("a malformed id (%q) reached the wire; the server would 400 the whole batch", got[0].ID)
	}
	if got[0].ID == "has a space/and slash" {
		t.Fatal("the malformed id was sent verbatim")
	}
	if got[1].ID != "cleanid01" {
		t.Fatalf("a valid id was rewritten: %q", got[1].ID)
	}
	// And the substitution is stable, or the retry writes a new row.
	again := pendingBreakGlassRecords(dir, breakGlassFlushBatch)
	if again[0].ID != got[0].ID {
		t.Fatalf("substituted id is not stable across attempts (%q vs %q)", got[0].ID, again[0].ID)
	}
}
