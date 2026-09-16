package risk

import "strings"

// CompoundRule fires when a combination of primitive signals is present
// that is materially worse than the sum of its parts. The canonical
// example — publisher-change AND new install script in the same version —
// is the fingerprint of a takeover-and-drop-payload attack. On their own,
// each signal has a moderate weight; together they should be near-block.
//
// CompoundRules run AFTER primitive signals, against the same Input. Their
// weight ADDS to the category subscore — they do not replace the primitive
// signals (both appear in FiredSignals so the UI can show the full story).
type CompoundRule struct {
	ID          string
	Category    Category
	Severity    Severity
	Weight      float64
	Title       string
	Description string
	Fires       func(in Input, fired map[string]FiredSignal) (bool, string, map[string]any)
}

// CompoundRules is the registry for compound signals. Kept separate from
// primitive Registry because they have different semantics (post-primitive
// pass, takes the map of already-fired primitives).
var CompoundRules []CompoundRule

const (
	CompoundSCTakeoverSignature = "sc.takeover_signature"
	// CompoundSCEnvNetInstall is the high-confidence "env-var read +
	// network call + install-script" combination — the active-exfil
	// fingerprint. The single-axis env-var detector remains
	// context-only (it has too high a false-positive rate to act as a
	// block by itself); this compound is the intended block carrier
	// when all three axes line up. Pain 9 (Agent D).
	CompoundSCNetShellInstallNPM = "sc.npm_install_net_shell"
	CompoundSCEnvNetInstall      = "sc.env_net_install"
)

func init() {
	// Publisher change + install script = takeover signature.
	// This is why we keep a low individual weight on install_script_only
	// (most packages legitimately have install scripts) but escalate
	// aggressively when a NEW publisher introduces one. Compound weight
	// puts the package well into quarantine territory on its own.
	CompoundRules = append(CompoundRules, CompoundRule{
		ID:          CompoundSCTakeoverSignature,
		Category:    CategorySupplyChain,
		Severity:    SevCritical,
		Weight:      -55,
		Title:       "Publisher change combined with install script",
		Description: "A different publisher set introduced an install-time lifecycle script in this version — the fingerprint of an account-takeover-and-drop-payload attack.",
		Fires: func(in Input, fired map[string]FiredSignal) (bool, string, map[string]any) {
			if !in.PublisherChanged {
				return false, "", nil
			}
			// P8-70. The -55 here is the heaviest non-instant-block weight
			// in the product, and every point of it rests on
			// "a DIFFERENT PUBLISHER did this" being an access-control
			// claim. On maven/gradle that claim is unsupported — both
			// sides of the publisher diff are the POM <developers> block,
			// self-declared prose (see registry_supplychain.go). Demoting
			// the primitive to SignalSCPOMDeveloperListChanged already
			// starves this rule, because the `fired[...]` lookup below
			// cannot find sc.publisher_changed for those ecosystems. This
			// guard is stated explicitly anyway: the implicit version
			// would silently un-guard the moment anyone re-widened the
			// primitive or added the POM signal to the lookup, and the
			// failure mode is a SevCritical block on a documentation edit.
			// TestTakeoverCompound_DoesNotEscalateOnPOMEcosystems pins it.
			if IsPOMMaintainerEco(in.Ecosystem) {
				return false, "", nil
			}
			if !in.HasInstallScript && !in.InstallScriptFetchesRemote {
				return false, "", nil
			}
			// Only fire the compound when BOTH primitives fired.
			_, pubChanged := fired[SignalSCPublisherChanged]
			_, installFetches := fired[SignalSCInstallScriptNetwork]
			_, installOnly := fired[SignalSCInstallScriptOnly]
			if !pubChanged || !(installFetches || installOnly) {
				return false, "", nil
			}
			return true, "New publisher introduced an install-time script in this version.",
				map[string]any{
					"installFetchesRemote": in.InstallScriptFetchesRemote,
				}
		},
	})

	// Env-var read + network call + install-script — the active-exfil
	// fingerprint. Tighter weight than the single-axis env-var
	// detector (which does not exist as a v2 signal — by design;
	// single-axis env-var reads are too common to act on). Only fires
	// when all three axes are present simultaneously, which keeps the
	// false-positive rate low. Pain 9, Agent D.
	//
	// Composes with CompoundSCTakeoverSignature: a takeover that
	// includes env-var exfil will trip both rules, dropping the score
	// further. That's the intent — separate axes adding evidence
	// rather than a single OR rule.
	CompoundRules = append(CompoundRules, CompoundRule{
		ID:          CompoundSCEnvNetInstall,
		Category:    CategorySupplyChain,
		Severity:    SevHigh,
		Weight:      -45,
		Title:       "Install script reads env vars and makes network calls",
		Description: "All three of (env-var read, network primitive, install-time lifecycle script) are present. The active-exfil fingerprint of credential-stealing malware in the install path.",
		Fires: func(in Input, fired map[string]FiredSignal) (bool, string, map[string]any) {
			// npm-gated as of 2026-09-16, on measurement. This rule shipped
			// ecosystem-blind and INVERTS on PyPI:
			//
			//	         malware   held-out benign
			//	npm       9.6%      0.0%  (0 of 219)
			//	PyPI      2.4%     16.4%  (36 of 220)
			//
			// At -45 -- the heaviest supply-chain compound weight -- it was
			// firing on 36 popular PyPI packages including tqdm, websockets,
			// jupyterlab-server and papermill, against 6 malware samples. It
			// fired on more benign packages than malicious ones.
			//
			// Reachable in production: pypi is in
			// supportedInstallScriptEcosystems and sc.install_script_only has
			// no ecosystem gate, so any PyPI scan with artifact bytes could
			// trip this.
			//
			// The cause is the same structural asymmetry as
			// sc.npm_install_net_shell: 65.3% of benign PyPI packages ship a
			// setup.py against 10.9% on npm, so "has an install script" is
			// near-universal there and carries almost no information.
			// Gating costs 2.4% PyPI malware recall and removes a 16.4%
			// false-positive rate on popular packages.
			if !isNPMEcosystem(in.Ecosystem) {
				return false, "", nil
			}
			if !in.EnvVarAccess || !in.NetworkAccess {
				return false, "", nil
			}
			if !in.HasInstallScript && !in.InstallScriptFetchesRemote {
				return false, "", nil
			}
			// Require an install-script primitive to have fired so the
			// compound is grounded in the same set of registered
			// signals visible in the UI.
			_, installFetches := fired[SignalSCInstallScriptNetwork]
			_, installOnly := fired[SignalSCInstallScriptOnly]
			if !(installFetches || installOnly) {
				return false, "", nil
			}
			return true, "Package reads env vars, makes network calls, and runs an install-time script.",
				map[string]any{
					"envVarAccess":         in.EnvVarAccess,
					"networkAccess":        in.NetworkAccess,
					"installFetchesRemote": in.InstallScriptFetchesRemote,
				}
		},
	})

	// sc.npm_install_net_shell — npm ONLY, and the gate is the point.
	//
	// MEASURED on retained artifacts, 2026-09-16
	// (docs/correlation-layer-measured-2026-09-16.md). The SAME conjunction,
	// on the same day, with the same harness:
	//
	//	         marginal catches    held-out benign FP
	//	npm      28 of 250 (11.2%)   0 of 219   (0.0%)
	//	PyPI     19 of 250 ( 7.6%)   26 of 220 (11.8%)
	//
	// An install script that also reaches the network and spawns a shell is
	// a strong signal on npm and NOISE on PyPI, because 65.3% of benign
	// PyPI packages ship a setup.py at all (against 10.9% on npm) and
	// building a C extension legitimately shells out. Ungated, this rule
	// would false-positive on one PyPI package in eight.
	//
	// That asymmetry is why this carries an Ecosystem check and why the two
	// compound rules above it — both ecosystem-blind — should be re-measured
	// the same way. "Marginal" above means catches NOT already covered by
	// sc.install_script_fetches_remote or sc.install_script_eval_encoded;
	// the union on npm goes 13.2% -> 24.4%.
	//
	// Weight is deliberately below CompoundSCEnvNetInstall's -45: that rule
	// requires env-var access on top, which is the exfiltration half. This
	// one asserts capability co-occurrence in the install path and nothing
	// about intent.
	CompoundRules = append(CompoundRules, CompoundRule{
		ID:          CompoundSCNetShellInstallNPM,
		Category:    CategorySupplyChain,
		Severity:    SevHigh,
		Weight:      -30,
		Title:       "npm install script with network and shell access",
		Description: "The package runs an install-time script and its source both reaches the network and spawns a shell. Measured on npm as a 0%-false-positive combination; deliberately not applied to other ecosystems, where a build-time setup script shelling out is ordinary.",
		Fires: func(in Input, fired map[string]FiredSignal) (bool, string, map[string]any) {
			if !isNPMEcosystem(in.Ecosystem) {
				return false, "", nil
			}
			if !in.HasInstallScript || !in.NetworkAccess || !in.CapShell {
				return false, "", nil
			}
			return true, "npm package runs an install script and its source uses both network and shell primitives.",
				map[string]any{
					"hasInstallScript": true,
					"networkAccess":    true,
					"shellAccess":      true,
				}
		},
	})
}

// isNPMEcosystem covers the npm family as the registry and the CLI spell it.
func isNPMEcosystem(eco string) bool {
	switch strings.ToLower(strings.TrimSpace(eco)) {
	case "npm", "yarn", "bun":
		return true
	}
	return false
}
