package cli

// Wave AH gap 3: tests for the `chainsaw logs tail --severity warn+`
// filter parsing and stream rendering. These pin the operator-facing
// contract: warn+ is the default, the gap-3 lines (the six WARN-promoted
// emissions on the OCI walker + chained inspector) are kept, and
// DEBUG/INFO chatter is dropped.

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseSeverityFilter(t *testing.T) {
	cases := []struct {
		in       string
		wantMin  logLevel
		wantExct bool
		wantErr  bool
	}{
		{"", levelWarn, false, false},      // default
		{"warn+", levelWarn, false, false}, // explicit default
		{"warn", levelWarn, true, false},
		{"error", levelError, true, false},
		{"error+", levelError, false, false},
		{"info+", levelInfo, false, false},
		{"DEBUG+", levelDebug, false, false},
		{"WARNING", levelWarn, true, false},
		{"  warn+  ", levelWarn, false, false},
		{"banana", 0, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseSeverityFilter(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.minLevel != tc.wantMin || got.exact != tc.wantExct {
				t.Fatalf("parseSeverityFilter(%q) = {%v, exact=%v}; want {%v, exact=%v}",
					tc.in, got.minLevel, got.exact, tc.wantMin, tc.wantExct)
			}
		})
	}
}

func TestSeverityFilterPass(t *testing.T) {
	warnPlus := severityFilter{minLevel: levelWarn}
	if !warnPlus.pass(levelWarn) {
		t.Fatalf("warn+ should pass WARN")
	}
	if !warnPlus.pass(levelError) {
		t.Fatalf("warn+ should pass ERROR")
	}
	if warnPlus.pass(levelInfo) {
		t.Fatalf("warn+ should drop INFO")
	}
	if warnPlus.pass(levelDebug) {
		t.Fatalf("warn+ should drop DEBUG")
	}

	exactWarn := severityFilter{minLevel: levelWarn, exact: true}
	if !exactWarn.pass(levelWarn) {
		t.Fatalf("exact warn should pass WARN")
	}
	if exactWarn.pass(levelError) {
		t.Fatalf("exact warn should drop ERROR")
	}

	// Unknown level fallback: at warn+ we keep it so older text-format
	// deployments don't go silent.
	if !warnPlus.pass(levelUnknown) {
		t.Fatalf("warn+ should keep unparseable lines")
	}
}

func TestFilterLogStreamKeepsGap3Lines(t *testing.T) {
	// Mirrors the JSON shape slog.NewJSONHandler emits in prod, including
	// the six gap-3 lines this wave promoted to WARN.
	stream := strings.Join([]string{
		`{"time":"2026-05-24T10:00:00Z","level":"DEBUG","msg":"docker layer cache hit","key":"alpine:3.20"}`,
		`{"time":"2026-05-24T10:00:01Z","level":"INFO","msg":"oci layer extracted","extractor":"apk","layer_digest":"sha256:abc","packages":42}`,
		`{"time":"2026-05-24T10:00:02Z","level":"WARN","msg":"docker layer inspector failed","repository":"docker-hub","package":"library/alpine","version":"sha256-deadbeef","error":"MANIFEST_UNKNOWN"}`,
		`{"time":"2026-05-24T10:00:03Z","level":"WARN","msg":"docker layer scan errored","repository":"docker-hub","package":"library/foo","version":"1.0","digest":"sha256:x","elapsed_ms":42,"error":"extractor crashed"}`,
		`{"time":"2026-05-24T10:00:04Z","level":"WARN","msg":"oci manifest fetch: registry returned MANIFEST_UNKNOWN","repository":"docker-hub","package":"library/alpine","version":"sha256-bad","error":"remote.Get ..."}`,
		`{"time":"2026-05-24T10:00:05Z","level":"WARN","msg":"oci layer body exceeds buffer cap; skipping extractor chain","image":"library/debian","version":"12","layer_digest":"sha256:big","cap_bytes":33554432,"env_knob":"CHAINSAW_DOCKER_LAYER_BODY_CAP_BYTES"}`,
		`{"time":"2026-05-24T10:00:06Z","level":"WARN","msg":"chained inspector primary error; falling back to secondary","repository":"docker-hub","package":"library/alpine","version":"3.4","primary_error":"manifest unavailable"}`,
		`{"time":"2026-05-24T10:00:07Z","level":"WARN","msg":"oci multi-arch index: no matching platform descriptor","repository":"docker-hub","package":"library/winonly","version":"1.0","runtime_arch":"amd64","index_entries":1}`,
		`{"time":"2026-05-24T10:00:08Z","level":"ERROR","msg":"docker layer scanner failed","repository":"docker-hub"}`,
	}, "\n")
	var out bytes.Buffer
	filter, _ := parseSeverityFilter("warn+")
	read, kept, err := filterLogStream(strings.NewReader(stream), &out, filter)
	if err != nil {
		t.Fatalf("filterLogStream err = %v", err)
	}
	if read != 9 {
		t.Fatalf("read = %d, want 9", read)
	}
	// Drop: DEBUG + INFO -> 2 dropped, 7 kept.
	if kept != 7 {
		t.Fatalf("kept = %d, want 7; rendered=%q", kept, out.String())
	}
	rendered := out.String()
	// Each gap-3 WARN line must show up in the rendered output by msg.
	wantMsgs := []string{
		"docker layer inspector failed",
		"docker layer scan errored",
		"oci manifest fetch: registry returned MANIFEST_UNKNOWN",
		"oci layer body exceeds buffer cap",
		"chained inspector primary error",
		"oci multi-arch index: no matching platform descriptor",
		"docker layer scanner failed",
	}
	for _, m := range wantMsgs {
		if !strings.Contains(rendered, m) {
			t.Fatalf("rendered output missing %q; got=%s", m, rendered)
		}
	}
	// Chatty DEBUG must NOT appear.
	if strings.Contains(rendered, "docker layer cache hit") {
		t.Fatalf("rendered output should drop the cache-hit DEBUG line; got=%s", rendered)
	}
	// Steady-state INFO must NOT appear at warn+.
	if strings.Contains(rendered, "oci layer extracted") {
		t.Fatalf("rendered output should drop the INFO line; got=%s", rendered)
	}
}

func TestFilterLogStreamRendersFieldsAlphabetically(t *testing.T) {
	// Stable rendering = diff-able operator output.
	line := `{"time":"2026-05-24T10:00:02Z","level":"WARN","msg":"hi","zeta":1,"alpha":"a","beta":2}`
	var out bytes.Buffer
	filter, _ := parseSeverityFilter("warn+")
	if _, _, err := filterLogStream(strings.NewReader(line), &out, filter); err != nil {
		t.Fatalf("filterLogStream err = %v", err)
	}
	got := strings.TrimSpace(out.String())
	// alpha must precede beta must precede zeta.
	ai := strings.Index(got, "alpha=")
	bi := strings.Index(got, "beta=")
	zi := strings.Index(got, "zeta=")
	if ai < 0 || bi < 0 || zi < 0 || !(ai < bi && bi < zi) {
		t.Fatalf("fields should be alphabetically sorted; got=%q", got)
	}
}

func TestFilterLogStreamHandlesTextFallback(t *testing.T) {
	// Older deployments still emit text-format slog. The wrapper should
	// surface them at warn+ (unparseable lines fall through to the
	// "keep" branch so operators don't lose visibility).
	stream := strings.Join([]string{
		"2026/05/24 10:00:00 level=DEBUG msg=cache-hit key=alpine:3.20",
		"2026/05/24 10:00:01 level=WARN msg=docker layer inspector failed repository=docker-hub",
		"this line has no level token at all",
	}, "\n")
	var out bytes.Buffer
	filter, _ := parseSeverityFilter("warn+")
	_, kept, err := filterLogStream(strings.NewReader(stream), &out, filter)
	if err != nil {
		t.Fatalf("filterLogStream err = %v", err)
	}
	// WARN line kept, unparseable line kept (fallback), DEBUG dropped.
	if kept != 2 {
		t.Fatalf("kept = %d, want 2; rendered=%q", kept, out.String())
	}
}
