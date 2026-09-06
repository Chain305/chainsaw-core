package cli

import (
	"errors"
	"fmt"
	"testing"
)

// TestClassifyCLIError_TransportErrorNeverReadsStatusFromAURL pins A1″.
//
// classifyCLIError matched bare status-code digits anywhere in the message.
// A transport failure carries the full request URL, so a port containing
// 401/403/404 was read as a status code and a server that was simply DOWN
// was reported as a permissions, auth or not-found problem.
//
// Observed for real on 2026-09-06: TestWhy_ServerErrorWithNoLocalRecordStillSurfaces
// failed with `classifyCLIError = "permission", want "network"` because
// httptest bound port 64403. It passed on the next run with a different
// port, which is what makes this worth pinning rather than fixing once.
//
// Not test-only: the telemetry errClass and the `chainsaw status` hint in
// renderError both key off this classification.
func TestClassifyCLIError_TransportErrorNeverReadsStatusFromAURL(t *testing.T) {
	// The literal shape the CLI produces, with the port that caused the
	// observed failure plus the other two status codes this switch buckets.
	for _, port := range []int{64403, 64401, 64404, 40123, 8404} {
		err := fmt.Errorf(
			"request to http://127.0.0.1:%d/api/violations/blocked failed: "+
				`Get "http://127.0.0.1:%d/api/violations/blocked": `+
				"dial tcp 127.0.0.1:%d: connect: connection refused",
			port, port, port)

		if got := classifyCLIError(err); got != "network" {
			t.Errorf("port %d: classifyCLIError = %q, want \"network\" "+
				"(a status code was read out of the URL)", port, got)
		}
	}
}

// TestClassifyCLIError_TransportShapes covers the other transport failures
// that carry a URL, so none of them can fall through to status matching.
func TestClassifyCLIError_TransportShapes(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want string
	}{
		{"no such host", `Get "http://api-403.example:8080/v1": dial tcp: lookup api-403.example: no such host`, "network"},
		{"connection reset", `Post "http://10.0.0.1:40412/api": read tcp: connection reset by peer`, "network"},
		{"tls handshake", `Get "https://host:9403/x": net/http: TLS handshake timeout`, "timeout"},
		{"io timeout", `Get "http://127.0.0.1:64404/api": dial tcp 127.0.0.1:64404: i/o timeout`, "timeout"},
		{"unreachable", `Get "http://192.168.4.401/api": dial tcp: network is unreachable`, "network"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyCLIError(errors.New(tc.msg)); got != tc.want {
				t.Errorf("classifyCLIError = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestClassifyCLIError_RealStatusCodesStillClassify is the negative control.
// Narrowing the match must not stop genuine status codes from being read —
// otherwise the fix trades a wrong answer for a missing one.
func TestClassifyCLIError_RealStatusCodesStillClassify(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		{"unexpected status 403 from server", "permission"},
		{"unexpected status 404 from server", "not_found"},
		{"unexpected status 401 from server", "auth"},
		{"server returned HTTP 403", "permission"},
		{"403: forbidden", "permission"},
		{"request failed (404)", "not_found"},
		{"unexpected response 403", "permission"},
		{"forbidden", "permission"},
		{"unauthorized", "auth"},
		{"not found", "not_found"},
	}
	for _, tc := range cases {
		t.Run(tc.msg, func(t *testing.T) {
			if got := classifyCLIError(errors.New(tc.msg)); got != tc.want {
				t.Errorf("classifyCLIError(%q) = %q, want %q", tc.msg, got, tc.want)
			}
		})
	}
}

// TestHasStatusCode_RejectsDigitRuns pins the boundary logic directly, so a
// failure points at the predicate rather than at a whole classification.
func TestHasStatusCode_RejectsDigitRuns(t *testing.T) {
	reject := []string{
		"dial tcp 127.0.0.1:64403: connect: connection refused",
		"listening on :4031",
		"read 1403 bytes",
		"took 403ms", // a duration is not a status
		"host 1.403.2.4",
	}
	for _, msg := range reject {
		if hasStatusCode(msg, "403") {
			t.Errorf("hasStatusCode(%q, \"403\") = true, want false", msg)
		}
	}

	accept := []string{
		"status 403",
		"status: 403",
		"http 403",
		"unexpected response 403 from upstream",
		"403: forbidden",
		"failed (403)",
	}
	for _, msg := range accept {
		if !hasStatusCode(msg, "403") {
			t.Errorf("hasStatusCode(%q, \"403\") = false, want true", msg)
		}
	}
}
