package risk

// GitHub Actions signal IDs. These signals describe risks observed on
// `uses:` references in workflow files (unpinned refs, unknown publishers,
// typosquat name similarity).
//
// These fire on the WORKFLOW surface, not on package reports: the
// scan-actions CLI (core/cli/scan_actions.go) and the
// /api/v1/intel/evaluate-actions endpoint (internal/server/api_v1_intel.go)
// both run findings through githubactions.EvaluateRisk -> BuildReport ->
// ProjectToRiskInput, which fills the ActionRef* fields. No package
// Report carries an Actions section, so on the package path they are
// always zero — that is expected, not a dead wire.
const (
	SignalActionUnpinnedRef      = "action.unpinned_ref"
	SignalActionUnknownPublisher = "action.unknown_publisher"
	SignalActionTyposquat        = "action.typosquat"
	SignalActionMalicious        = "action.malicious"

	// Workflow-structure lint: what a workflow does with its triggers, not
	// which actions it uses. Weight 0 — they report and gate scan-actions
	// (high severity) but move no score until a replay justifies a weight.
	SignalActionPwnRequest              = "action.pwn_request"
	SignalActionCommentTriggerUnguarded = "action.comment_trigger_unguarded"
	SignalActionScriptInjection         = "action.script_injection"
	SignalActionDecodeExec              = "action.decode_exec"
)

// registerActionLint registers one weight-0 workflow-lint signal that fires
// on flag and cites locs.
func registerActionLint(id, title, desc, msg string, field func(Input) (bool, []string)) {
	register(Signal{
		ID:          id,
		Category:    CategorySupplyChain,
		Severity:    SevHigh,
		Weight:      0,
		Title:       title,
		Description: desc,
		Fires: func(in Input) (bool, string, map[string]any) {
			fired, locs := field(in)
			if !fired {
				return false, "", nil
			}
			return true, msg, map[string]any{"locations": locs}
		},
	})
}

func init() {
	// Unpinned ref — Action `uses:` line points at a branch or tag instead
	// of a 40-char commit SHA. Maintainer-controlled tags can be re-tagged
	// at any time, which is a real supply-chain risk: a compromised
	// maintainer or a stolen token can re-point `v3` at malicious code
	// retroactively. Substantial weight, but not instant-block.
	register(Signal{
		ID:          SignalActionUnpinnedRef,
		Category:    CategorySupplyChain,
		Severity:    SevMedium,
		Weight:      -15,
		Title:       "Unpinned GitHub Action reference",
		Description: "Action ref uses a branch or tag instead of a 40-char commit SHA — re-taggable upstream.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.ActionRefUnpinned {
				return false, "", nil
			}
			return true, "Action ref is not pinned to a 40-char commit SHA.",
				map[string]any{"refs": in.ActionRefUnpinnedRefs}
		},
	})

	// Unknown publisher — Action owner isn't in the known-good publisher
	// allowlist (e.g. actions/, aws-actions/, docker/, github/, microsoft/).
	// Many legitimate Actions ship from individual users, so this is a
	// nudge rather than a hard penalty. The allowlist itself is owned by
	// the parser/detector — this signal just consumes the boolean.
	register(Signal{
		ID:          SignalActionUnknownPublisher,
		Category:    CategorySupplyChain,
		Severity:    SevLow,
		Weight:      -5,
		Title:       "GitHub Action from unknown publisher",
		Description: "Action owner is not in the known-good publisher allowlist.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.ActionRefUnknownPublisher {
				return false, "", nil
			}
			return true, "Action ref's owner is not in the known-good publisher list.",
				map[string]any{"publishers": in.ActionRefUnknownPublishers}
		},
	})

	// Typosquat — Action name resembles a known-good Action via the
	// typosquat detector. Same caliber as SignalVulnKEV-class supply-chain
	// signals: an attacker squatting on `actoins/checkout` is the entire
	// kill chain in one ref.
	register(Signal{
		ID:          SignalActionTyposquat,
		Category:    CategorySupplyChain,
		Severity:    SevHigh,
		Weight:      -40,
		Title:       "GitHub Action name resembles a popular Action",
		Description: "Action name is a likely typosquat of a well-known Action.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.ActionRefTyposquat {
				return false, "", nil
			}
			return true, "Action name is highly similar to a popular Action.",
				map[string]any{"refs": in.ActionRefTyposquats}
		},
	})

	// Malicious — Action ref appears in the malicious-Action feed
	// (OSV-ingested GitHub Actions malware list). This is the heaviest
	// supply-chain signal in the Action family by design:
	//
	//   action.unknown_publisher (-5)  < action.unpinned_ref (-15)
	//     < action.typosquat (-40)     < action.malicious  (-50)
	//
	// Typosquat is "looks suspicious" — name similarity, no upstream
	// confirmation. Malicious is "confirmed bad in the feed" — a curated
	// feed has flagged this exact ref, so the penalty exceeds typosquat
	// by enough to clearly outrank it on any composite score, while
	// staying within the same order of magnitude (a single ref shouldn't
	// alone instant-block — the malware-status path on the package level
	// already handles that).
	register(Signal{
		ID:          SignalActionMalicious,
		Category:    CategorySupplyChain,
		Severity:    SevHigh,
		Weight:      -50,
		Title:       "GitHub Action ref flagged as malicious",
		Description: "Action ref appears in the curated malicious-Action feed.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.ActionRefMalicious {
				return false, "", nil
			}
			return true, "Action ref is on the malicious-Action feed.",
				map[string]any{"refs": in.ActionRefMaliciousRefs}
		},
	})

	registerActionLint(SignalActionPwnRequest,
		"Privileged workflow runs pull request code",
		"A pull_request_target or workflow_run workflow checks out the pull request head and then runs a step, so a fork's code runs with the base repository's secrets and write token.",
		"Workflow checks out the pull request head under a privileged trigger and runs it.",
		func(in Input) (bool, []string) { return in.ActionPwnRequest, in.ActionPwnRequestLocs })
	registerActionLint(SignalActionCommentTriggerUnguarded,
		"Comment-triggered workflow is not restricted to members",
		"An issue_comment or pull_request_review_comment job holds secrets, id-token: write or a publish step, and no if: checks the commenter's author_association.",
		"Any GitHub user's comment can trigger a privileged job.",
		func(in Input) (bool, []string) {
			return in.ActionCommentTriggerUnguarded, in.ActionCommentTriggerUnguardedLocs
		})
	registerActionLint(SignalActionScriptInjection,
		"Attacker-written text interpolated into a shell step",
		"A ${{ }} expression carrying a comment body, issue or pull request title/body, review body or branch name is interpolated directly into a run: step.",
		"Untrusted event text is interpolated into a shell run: step.",
		func(in Input) (bool, []string) { return in.ActionScriptInjection, in.ActionScriptInjectionLocs })
	registerActionLint(SignalActionDecodeExec,
		"Workflow step decodes a payload and executes it",
		"A run: step decodes an encoded payload (base64 -d, FromBase64String, PowerShell -EncodedCommand) and pipes or passes it to an interpreter, so the code that runs cannot be read in the workflow.",
		"A run: step executes a decoded payload.",
		func(in Input) (bool, []string) { return in.ActionDecodeExec, in.ActionDecodeExecLocs })
}
