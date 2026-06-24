package risk

// GitHub Actions signal IDs. These signals describe risks observed on
// `uses:` references in workflow files (unpinned refs, unknown publishers,
// typosquat name similarity).
//
// NOTE: these signals stay dormant until the Actions parser + risk
// projection wiring lands — mirroring how SignalVulnFixAvailable stays
// dormant on un-enriched rows. The Input fields (ActionRef*) default to
// zero values, so the Fires() callbacks return false until a future
// projection populates them.
const (
	SignalActionUnpinnedRef      = "action.unpinned_ref"
	SignalActionUnknownPublisher = "action.unknown_publisher"
	SignalActionTyposquat        = "action.typosquat"
	SignalActionMalicious        = "action.malicious"
)

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
}
