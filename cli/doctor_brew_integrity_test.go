package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEvaluateBrewIntegrity(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	result := func(verdict string, age time.Duration, tamper ...string) string {
		b, _ := json.Marshal(brewVerifyResult{Schema: BrewVerifySchema, CheckedAt: now.Add(-age), Verdict: verdict, Tamper: tamper})
		return string(b)
	}
	many := make([]string, 12)
	for i := range many {
		many[i] = "bin/x" + string(rune('a'+i))
	}
	cases := []struct {
		name     string
		noPlist  bool
		body     *string
		insecure bool
		want     string
		reason   string
	}{
		{name: "not opted in", noPlist: true, want: ""},
		{name: "no result yet", want: "not_assessed"},
		{name: "clean", body: ptr(result(brewVerdictClean, time.Hour)), want: "compliant"},
		{name: "tamper", body: ptr(result(brewVerdictTamper, time.Hour, "bin/jq: regular file")), want: "drifted", reason: "bin/jq"},
		{name: "tamper list capped", body: ptr(result(brewVerdictTamper, time.Hour, many...)), want: "drifted", reason: "+2 more"},
		{name: "drift", body: ptr(result(brewVerdictDrift, time.Hour)), want: "drifted", reason: "policy drift"},
		{name: "stale clean", body: ptr(result(brewVerdictClean, 14*time.Hour)), want: "not_assessed", reason: "stale"},
		{name: "future clean", body: ptr(result(brewVerdictClean, -2*time.Hour)), want: "not_assessed", reason: "stale"},
		{name: "incomplete", body: ptr(result(brewVerdictIncomplete, time.Hour)), want: "not_assessed"},
		{name: "error", body: ptr(result(brewVerdictError, time.Hour)), want: "not_assessed"},
		{name: "wrong schema", body: ptr(`{"schema":"x","verdict":"clean"}`), want: "not_assessed"},
		{name: "garbage", body: ptr(`not json`), want: "not_assessed"},
		{name: "user-writable clean result", body: ptr(result(brewVerdictClean, time.Hour)), insecure: true, want: "drifted", reason: "not trustworthy"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			oldP, oldR, oldS, oldN := brewIntegrityPlist, brewIntegrityResultPath, brewIntegrityFileSecure, brewIntegrityNow
			t.Cleanup(func() {
				brewIntegrityPlist, brewIntegrityResultPath, brewIntegrityFileSecure, brewIntegrityNow = oldP, oldR, oldS, oldN
			})
			brewIntegrityPlist = filepath.Join(dir, "daemon.plist")
			brewIntegrityResultPath = filepath.Join(dir, "brew-verify.json")
			brewIntegrityNow = func() time.Time { return now }
			brewIntegrityFileSecure = func(string) error {
				if c.insecure {
					return errors.New("owned by uid 501")
				}
				return nil
			}
			if !c.noPlist {
				os.WriteFile(brewIntegrityPlist, nil, 0o644)
			}
			if c.body != nil {
				os.WriteFile(brewIntegrityResultPath, []byte(*c.body), 0o644)
			}
			st, ok := evaluateBrewIntegrity()
			if c.want == "" {
				if ok {
					t.Fatalf("reported %+v for a device without the daemon", st)
				}
				return
			}
			if !ok || st.Status != c.want || !strings.Contains(st.Reason, c.reason) {
				t.Fatalf("got ok=%v %+v, want %s containing %q", ok, st, c.want, c.reason)
			}
		})
	}
}
