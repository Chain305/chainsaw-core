package cli

// guard_policy_pin.go closes the downgrade the "fall back to defaults
// when no bundle is present" ruling opens.
//
// THE HOLE. Falling back to built-in defaults is right for onboarding —
// requiring a bundle would make `curl | sh` then `chainsaw npm install`
// a two-step affair on the surface whose whole job is a frictionless
// front door. But if an absent bundle silently means defaults FOREVER,
// then deleting the bundle is a downgrade: an attacker with local write
// access removes the operator's stricter rules and the guard reports
// nothing, because "no bundle" and "no bundle yet" look identical.
//
// This is the exact inverse of the threat E5 already closed. See
// internal/policy/dsl/signing/verify.go: "anyone with shell access to
// the chainsaw host can drop a .rego file into the bundle directory and
// the loader will compile + apply it on next reload". E5 made ADDITION
// require a signature. Nothing made REMOVAL noisy.
//
// THE FIX. Trust on first use, the same discipline the local allowlist
// already uses (guard_allow.go). The first time the guard sees an
// operator bundle it records that fact next to the allowlist. A later
// run with no bundle is then distinguishable from a first run, and the
// guard says so.
//
// WHAT IT DELIBERATELY DOES NOT DO. It does not block. Whether a
// missing-but-previously-seen bundle should refuse installs is — per
// the same 2026-08-24 ruling — a policy question, and the built-in
// defaults are the only policy available at precisely the moment the
// operator's policy has gone missing. Blocking here would also hand a
// denial-of-service to anyone who can delete a file. So: make it loud,
// count it, and leave the posture to the operator. The pin file itself
// is the durable record.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// guardPolicyPinFile is the TOFU record, stored beside
// guard_allowlist.json. The config home is platform-dependent — see
// cli/platform.ConfigHome; `chainsaw status` prints the resolved path.
const guardPolicyPinFile = "guard_policy_pin.json"

// guardPolicyBundleVanished counts runs where a bundle was pinned and
// is now absent. Exposed so `chainsaw status` and tests can read it.
var guardPolicyBundleVanished atomic.Uint64

// GuardPolicyBundleVanishedCount reports pinned-then-missing bundle
// observations since process start.
func GuardPolicyBundleVanishedCount() uint64 { return guardPolicyBundleVanished.Load() }

// guardPolicyPin is the on-disk record. Digest is the dsl bundle digest
// (content, not path) so moving a bundle is not mistaken for losing it,
// and so a CHANGED bundle is visible too.
type guardPolicyPin struct {
	Digest   string `json:"digest"`
	Source   string `json:"source"`
	FirstAt  string `json:"first_seen"`
	LastAt   string `json:"last_seen"`
	Modules  int    `json:"modules"`
	Revision int    `json:"revision"`
}

func guardPolicyPinPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, guardPolicyPinFile)
}

func readGuardPolicyPin() (guardPolicyPin, bool) {
	p := guardPolicyPinPath()
	if p == "" {
		return guardPolicyPin{}, false
	}
	data, err := os.ReadFile(p)
	if err != nil || len(data) == 0 {
		return guardPolicyPin{}, false
	}
	var pin guardPolicyPin
	if json.Unmarshal(data, &pin) != nil || pin.Digest == "" {
		return guardPolicyPin{}, false
	}
	return pin, true
}

// writeGuardPolicyPin records or refreshes the pin. 0600 for the same
// reason the allowlist is: this file states which rules a machine
// believes it is enforcing. Best-effort — a read-only config home must
// not break an install.
func writeGuardPolicyPin(pin guardPolicyPin) {
	p := guardPolicyPinPath()
	if p == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	data, err := json.MarshalIndent(pin, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(p, data, 0o600)
	// os.WriteFile only applies perm on CREATE; re-tighten an existing
	// loose file, same reasoning as the allowlist store.
	_ = os.Chmod(p, 0o600)
}

// observeGuardPolicyBundle reconciles what this run loaded against what
// previous runs pinned. Returns a human-facing warning when the
// operator's bundle has gone missing or changed, or "" when there is
// nothing to say.
//
// digest is the compiled bundle digest INCLUDING the built-in modules,
// and haveOperatorBundle reports whether any operator source was found.
// The two together are what distinguish "first run, no bundle" (silent)
// from "the bundle I saw yesterday is gone" (loud).
func observeGuardPolicyBundle(digest, source string, modules int, haveOperatorBundle bool) string {
	now := time.Now().UTC().Format(time.RFC3339)
	pin, pinned := readGuardPolicyPin()

	switch {
	case !pinned && !haveOperatorBundle:
		// First run with no operator bundle: the onboarding case the
		// ruling protects. Record nothing and say nothing — pinning
		// the built-in-only state would make every later first-bundle
		// install look like a change.
		return ""

	case !pinned && haveOperatorBundle:
		writeGuardPolicyPin(guardPolicyPin{
			Digest: digest, Source: source, FirstAt: now, LastAt: now,
			Modules: modules, Revision: 1,
		})
		return ""

	case pinned && !haveOperatorBundle:
		guardPolicyBundleVanished.Add(1)
		return fmt.Sprintf(
			"policy bundle missing: this machine enforced an operator bundle (last seen %s, source %s) and none is present now — running built-in defaults only",
			pin.LastAt, pin.Source)

	case pin.Digest != digest:
		pin.Digest = digest
		pin.Source = source
		pin.LastAt = now
		pin.Modules = modules
		pin.Revision++
		writeGuardPolicyPin(pin)
		return ""

	default:
		pin.LastAt = now
		writeGuardPolicyPin(pin)
		return ""
	}
}
