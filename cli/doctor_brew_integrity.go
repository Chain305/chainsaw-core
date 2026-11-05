package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"
)

// The MDM opt-in (CHAINSAW_BREW_VERIFY_TOKEN) installs a root LaunchDaemon
// that runs `chainsaw brew verify` every 6h and writes a root-owned result.
// doctor --strict reports that result as the "homebrew-integrity" entry, so
// a tampered prefix reaches the compliance dashboard through the attest the
// device already sends. No daemon, no entry: devices that did not opt in
// report exactly what they did before.
var (
	brewIntegrityPlist      = "/Library/LaunchDaemons/com.chain305.chainsaw.brew-verify.plist"
	brewIntegrityResultPath = "/var/db/chainsaw/brew-verify.json"
	brewIntegrityFileSecure = rootOwnedNotWritable
	brewIntegrityNow        = time.Now
)

const (
	brewIntegrityName = "homebrew-integrity"
	// Two missed 6-hourly runs plus slack.
	brewIntegrityMaxAge = 13 * time.Hour
)

// evaluateBrewIntegrity returns the entry and whether to report it at all.
func evaluateBrewIntegrity() (ecosystemState, bool) {
	if _, err := os.Stat(brewIntegrityPlist); err != nil {
		return ecosystemState{}, false
	}
	st := ecosystemState{ConfigPath: brewIntegrityResultPath}
	// not_assessed (scan_origin.go's status): installed but no current
	// answer. Never "compliant", so the device is never counted clean on it.
	notAssessed := func(reason string) (ecosystemState, bool) {
		st.Status, st.Reason = statusNotAssessed, reason
		return st, true
	}
	b, err := os.ReadFile(brewIntegrityResultPath)
	if errors.Is(err, fs.ErrNotExist) {
		return notAssessed("daemon installed but no result yet")
	} else if err != nil {
		return notAssessed("reading result: " + err.Error())
	}
	if err := brewIntegrityFileSecure(brewIntegrityResultPath); err != nil {
		// The result is only evidence because only root can write it.
		st.Status, st.Reason = "drifted", "result file not trustworthy: "+err.Error()
		return st, true
	}
	var res brewVerifyResult
	if err := json.Unmarshal(b, &res); err != nil || res.Schema != BrewVerifySchema {
		return notAssessed("unreadable result (schema " + res.Schema + ")")
	}
	if age := brewIntegrityNow().Sub(res.CheckedAt); age > brewIntegrityMaxAge || age < -time.Hour {
		return notAssessed("stale result, checked " + res.CheckedAt.UTC().Format(time.RFC3339))
	}
	v := brewIntegrityState(res)
	v.ConfigPath = st.ConfigPath
	return v, true
}

// brewIntegrityState maps a verify result to the compliance entry; doctor
// and `brew verify --attest` (the root path) report the same thing.
func brewIntegrityState(res brewVerifyResult) ecosystemState {
	switch res.Verdict {
	case brewVerdictClean:
		return ecosystemState{Status: "compliant"}
	case brewVerdictTamper:
		return ecosystemState{Status: "drifted", Reason: "tamper: " + capList(res.Tamper, 10)}
	case brewVerdictDrift:
		return ecosystemState{Status: "drifted", Reason: "policy drift: " + capList(res.Drift, 10)}
	}
	return ecosystemState{Status: statusNotAssessed, Reason: res.Verdict + ": " + capList(append(append([]string{}, res.NotAssessed...), res.Errors...), 3)}
}

func capList(xs []string, n int) string {
	if len(xs) <= n {
		return strings.Join(xs, "; ")
	}
	return strings.Join(xs[:n], "; ") + fmt.Sprintf("; +%d more", len(xs)-n)
}
