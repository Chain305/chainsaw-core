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
	// MaxImpact has Signal.MaxImpact's meaning and joins the same minimum in
	// applyMaxImpactCeiling. 0 = no ceiling, which every rule had until
	// CompoundSCExfilAtInstall.
	MaxImpact int
	// DampEstablished has Signal.DampEstablished's meaning for the ceiling
	// only: on a package past a download line (release history does not
	// count, see dampEstablished) with no TakeoverIndicator fired, the rule's
	// MaxImpact does not apply. The weight is kept, and the rule never
	// suspends the damper. Set it on rules whose measured benign hits
	// are popular packages (binary installers, yt-dlp, anyio), never on a
	// rule that is compromise-shaped on any package.
	DampEstablished bool
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
	// block by itself). This compound is NOT a block carrier on its own:
	// an npm package with an install script, env, network, shell and a
	// licence scores ALLOW 60 with it (-45) and sc.npm_install_net_shell
	// (-30) both firing. Pain 9 (Agent D).
	CompoundSCNetShellInstallNPM = "sc.npm_install_net_shell"
	CompoundSCEnvNetInstall      = "sc.env_net_install"
	CompoundSCExfilAtInstall     = "sc.exfil_sink_at_install"

	// The 2026-10-10 warn-ceiling set (init below).
	CompoundSCNPMInstallHookShell = "sc.npm_install_hook_shell"
	CompoundSCExfilSinkNamed      = "sc.exfil_sink_named"
	CompoundSCImportTimeBeacon    = "sc.import_time_beacon"
	CompoundSCObfuscatedExecEval  = "sc.obfuscated_exec_eval"
	CompoundSCTrivialDynamicCode  = "sc.trivial_dynamic_code"
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
		ID:       CompoundSCEnvNetInstall,
		Category: CategorySupplyChain,
		Severity: SevHigh,
		Weight:   -45,
		// Warn ceiling 2026-10-10, popular packages exempt: it fires on
		// esbuild, node-sass and canvas (see the exfil_sink_at_install note).
		MaxImpact:       maxImpactWarnTop,
		DampEstablished: true,
		Title:           "Install script reads env vars and makes network calls",
		Description:     "All three of (env-var read, network primitive, install-time lifecycle script) are present. The active-exfil fingerprint of credential-stealing malware in the install path.",
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
	// (docs/REPORTS.md#correlation-layer-measured-2026-09-16). The SAME conjunction,
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
		ID:       CompoundSCNetShellInstallNPM,
		Category: CategorySupplyChain,
		Severity: SevHigh,
		Weight:   -30,
		// Warn ceiling 2026-10-10, popular packages exempt, same reason
		// as sc.env_net_install. Not binding today: wherever this fires,
		// sc.npm_install_hook_shell (59) or sc.install_script_fetches_remote
		// (40) fires too. Kept so the rule states its own band.
		MaxImpact:       maxImpactWarnTop,
		DampEstablished: true,
		Title:           "npm install script with network and shell access",
		Description:     "The package runs an install-time script and its source both reaches the network and spawns a shell. Measured on npm as a 0%-false-positive combination; deliberately not applied to other ecosystems, where a build-time setup script shelling out is ordinary.",
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

func init() {
	// sc.exfil_sink_at_install — two independent detectors agree: code that
	// runs on install or import sends to a hard-coded exfiltration sink
	// (sc.exfil_sink_used with Input.MaliciousIOCAtEntry) AND it executes something malicious
	// at install: a malware-shaped install script (fetch-and-exec,
	// decode-and-eval, or a host-recon beacon in the script the hook runs;
	// core/installscripts) or a module-level shell command
	// (sc.import_time_shell; for setup.py that is install). Either alone
	// warns. Together they quarantine.
	//
	// MEASURED 2026-10-04 on wave fd81f358, bytes only, feed-blind: 45 of
	// 400 npm and 46 of 397 PyPI Datadog malware samples (without the
	// install/import-path gate, 46 npm); 0 of 3,115 benign packages with bytes,
	// including 381 npm install-hook versions and 696 PyPI sdists.
	// Ecosystem-blind on purpose: unlike the two rules above it rests on no
	// "has an install script" base rate.
	//
	// This was the first compound with a ceiling. The two above had none
	// until 2026-10-10: measured on the same day they fire on esbuild,
	// node-sass, canvas, chromedriver, @sentry/cli, ssh2, node-pty,
	// @tensorflow/tfjs-node and youtube-dl-exec (10 of 94 popular install-hook
	// packages), because a binary installer reads proxy settings, downloads
	// and shells out. Their warn ceiling is therefore DampEstablished.
	CompoundRules = append(CompoundRules, CompoundRule{
		ID:          CompoundSCExfilAtInstall,
		Category:    CategorySupplyChain,
		Severity:    SevCritical,
		Weight:      -40,
		MaxImpact:   thresholdQuarantine - 1,
		Title:       "Exfiltration endpoint in a package with a malicious install script",
		Description: "The package's code sends to a hard-coded exfiltration endpoint and it executes malware-shaped code at install time. Two independent detectors agree.",
		Fires: func(in Input, fired map[string]FiredSignal) (bool, string, map[string]any) {
			// The sink itself must be on the install/import path. Measured:
			// R4 vs this gate differ by 1 of 92 malware samples, and the gate
			// is what keeps a security tool that posts to Slack from its own
			// plugin module (detect-secrets) out of quarantine for good if it
			// ever also gains a malware-shaped install step.
			if !in.MaliciousIOCAtEntry {
				return false, "", nil
			}
			_, sink := fired[SignalSCExfilSinkUsed]
			_, fetch := fired[SignalSCInstallScriptNetwork]
			_, enc := fired[SignalSCInstallScriptEvalEnc]
			_, shell := fired[SignalSCImportTimeShell]
			if !sink || !(fetch || enc || shell) {
				return false, "", nil
			}
			return true, "Code sends to an exfiltration endpoint and runs malware-shaped code at install time.", nil
		},
	})
}

func init() {
	// The warn-ceiling set, 2026-10-10. Each holds a package at the top of the
	// warn band and none can quarantine. Chosen by a byte-feature combiner
	// analysis (docs/PLANS_INTELLIGENCE.md#plan-signal-repair): on the 797
	// Datadog samples, bytes only and feed-blind, the union moves warn+ recall
	// from 57.0% to 66.1%. Benign cost was measured on rev6 E/C/D with
	// bytes (1,199 rows, 431 npm/PyPI); that base holds only 8 npm packages
	// with an install hook, so the install-path rules below also lean on the
	// popular install-hook measurement quoted on sc.exfil_sink_at_install.
	//
	// Rules whose benign hits are popular packages are DampEstablished: the
	// ceiling does not apply on a package past a download line unless a
	// takeover indicator fired. A bytes-only scan carries no download data, so
	// the malware measurement is unaffected by the exemption. Those rules
	// weigh 0: the ceiling is their whole claim, and an exempt package must
	// not move. A weight on sc.npm_install_hook_shell would also stack on the
	// two install-path compounds it overlaps and warn esbuild by arithmetic.
	warn := func(r CompoundRule) {
		r.Category, r.MaxImpact = CategorySupplyChain, maxImpactWarnTop
		CompoundRules = append(CompoundRules, r)
	}

	// npm install hook AND shell. +33 Datadog malware samples to warn; on
	// rev6 2 of 431 npm/PyPI benign (at-builder, ap-browser-connect).
	// A superset of sc.npm_install_net_shell on non-fetching hooks, so it
	// shares that rule's popular binary-installer hits; hence the exemption.
	warn(CompoundRule{
		ID:              CompoundSCNPMInstallHookShell,
		Severity:        SevMedium,
		Weight:          0,
		DampEstablished: true,
		Title:           "npm install script in a package that spawns a shell",
		Description:     "The package runs an npm install hook and its source spawns a shell. On popular packages (binary installers) the warn ceiling does not apply.",
		Fires: func(in Input, fired map[string]FiredSignal) (bool, string, map[string]any) {
			if _, hook := fired[SignalSCInstallScriptOnlyNPM]; !hook || !in.CapShell {
				return false, "", nil
			}
			return true, "npm package runs an install hook and its source spawns a shell.", nil
		},
	})

	// An exfiltration host named in shipping code with no send from the same
	// file (the coupled case is sc.exfil_sink_used). +18 malware; 0 of 1,199
	// rev6 benign. Popular hits measured 2026-10-03: yt-dlp (gofile.io in its
	// unsupported-sites list) and ngrok's typings.
	warn(CompoundRule{
		ID:              CompoundSCExfilSinkNamed,
		Severity:        SevMedium,
		Weight:          0,
		DampEstablished: true,
		Title:           "Code names an exfiltration endpoint",
		Description:     "Shipping code embeds a webhook, paste drop, tunnel or out-of-band host, though no file both names it and sends.",
		Fires: func(in Input, fired map[string]FiredSignal) (bool, string, map[string]any) {
			if in.MaliciousIOCKind != "exfil_host" || in.MaliciousIOCCoupled {
				return false, "", nil
			}
			return true, "Shipping code names an exfiltration endpoint.", nil
		},
	})

	// pysource import_time_beacon: module top level sends host identity.
	// +10 malware; 0 of 1,199 rev6 benign, but it fires on anyio (top-50
	// PyPI) and metaflow-netflixext, which is why it was declined on
	// 2026-10-04 and ships now only with the exemption.
	warn(CompoundRule{
		ID:              CompoundSCImportTimeBeacon,
		Severity:        SevMedium,
		Weight:          0,
		DampEstablished: true,
		Title:           "Python module beacons on import",
		Description:     "Module-level code in the package's Python source reports host information over the network when it is imported.",
		Fires: func(in Input, fired map[string]FiredSignal) (bool, string, map[string]any) {
			if in.ImportTimeKind != "import_time_beacon" {
				return false, "", nil
			}
			return true, "Module-level code beacons host information on import.", nil
		},
	})

	// A bare decode-and-exec at module top level AND the capability scanner's
	// dynamic eval. +15 malware; 1 of 431 benign (azure-ai-contentsafety
	// 1.0.0). Not exempt: the one benign hit is accepted, and a decode-and-exec
	// is how a compromised popular package would deliver.
	warn(CompoundRule{
		ID:          CompoundSCObfuscatedExecEval,
		Severity:    SevMedium,
		Weight:      -15,
		Title:       "Obfuscated code executed on import",
		Description: "Module-level code decodes a blob and executes it, and the package evaluates dynamic code.",
		Fires: func(in Input, fired map[string]FiredSignal) (bool, string, map[string]any) {
			if in.ImportTimeKind != "obfuscated_exec_bare" || !in.CapDynamicEval {
				return false, "", nil
			}
			return true, "Module-level decode-and-exec in a package that evaluates dynamic code.", nil
		},
	})

	// A trivial package (a few lines of code) that evaluates or requires
	// code it computes. +10 malware; 0 of 1,199 rev6 benign.
	warn(CompoundRule{
		ID:          CompoundSCTrivialDynamicCode,
		Severity:    SevMedium,
		Weight:      -10,
		Title:       "Trivial package runs dynamic code",
		Description: "The package is a few lines of code and evaluates a string or requires a computed module name.",
		Fires: func(in Input, fired map[string]FiredSignal) (bool, string, map[string]any) {
			if !in.TrivialPackage || !(in.CapDynamicEvalObserved || in.CapDynamicRequire) {
				return false, "", nil
			}
			return true, "Trivial package evaluates or requires dynamic code.", nil
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
