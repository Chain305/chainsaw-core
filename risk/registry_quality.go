package risk

const (
	SignalQualChecksumMismatch = "qual.checksum_mismatch"
	SignalQualChecksumVerified = "qual.checksum_verified"
	SignalQualVersionAnomaly   = "qual.version_anomaly"
	SignalQualMinifiedCode     = "qual.minified_code"
)

// versionAnomalyWeightPerFlag is the per-flag penalty for version anomaly
// findings (from metadiff). Total penalty is capped at MaxVersionAnomalyPenalty.
const (
	versionAnomalyWeightPerFlag = -10
	MaxVersionAnomalyPenalty    = -30
)

func init() {
	// Instant-block-adjacent: a mismatch between the declared and actual
	// artifact hashes is a tamper indicator. The evaluator short-circuits
	// the same way as known-malicious (see evaluator.go).
	register(Signal{
		ID:          SignalQualChecksumMismatch,
		Category:    CategoryQuality,
		Severity:    SevCritical,
		Weight:      -1000, // sentinel; triggers short-circuit
		Title:       "Artifact checksum mismatch",
		Description: "Registry-declared artifact hash does not match the downloaded bytes — tamper indicator.",
		// Pain 9 P2: see SignalSCKnownMalicious — same instant-block
		// short-circuit reasoning. Tamper indicators are bytes-on-disk
		// disagreements with the publisher's declared hash and must
		// not be policy'd down to "ignore".
		NotTunable: true,
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.ChecksumMismatch {
				return false, "", nil
			}
			return true, "Declared checksum does not match actual bytes.", nil
		},
	})

	register(Signal{
		ID:       SignalQualChecksumVerified,
		Category: CategoryQuality,
		Severity: SevInfo,
		Weight:   +5,
		Title:    "Checksum verified",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.ChecksumVerified {
				return false, "", nil
			}
			return true, "Artifact hash matches the registry declaration.", nil
		},
	})

	// Version anomaly is a composite — the evaluator counts flags and
	// applies per-flag weight up to the cap. Registered with weight 0
	// here because the actual contribution is computed in the evaluator;
	// this entry exists so the signal shows up in /signals listings and
	// docs, and so fired records flow through the same UI pipeline.
	// MaxImpact tier: MEDIUM-confidence harmful (50-60). Publishing
	// anomalies are circumstantial — degrades but doesn't dominate.
	register(Signal{
		ID:          SignalQualVersionAnomaly,
		Category:    CategoryQuality,
		Severity:    SevMedium,
		Weight:      versionAnomalyWeightPerFlag, // documented; evaluator caps total
		MaxImpact:   60,
		Title:       "Version publishing anomaly",
		Description: "Version number / timestamps / content diverge from the expected publishing pattern (e.g. timestamp regression, major-version skip).",
		Fires: func(in Input) (bool, string, map[string]any) {
			if len(in.VersionAnomalyFlags) == 0 {
				return false, "", nil
			}
			return true, "One or more version-publishing anomalies detected.",
				map[string]any{"flags": in.VersionAnomalyFlags}
		},
	})

	// Informational: the package ships minified/bundled JS. This is not
	// inherently malicious — many legitimate packages bundle for distribution
	// — but it does reduce auditability and is worth surfacing for review.
	// Weight 0: purely informational, no score impact.
	register(Signal{
		ID:       SignalQualMinifiedCode,
		Category: CategoryQuality,
		Severity: SevInfo,
		Weight:   0,
		Title:    "Shipped source appears minified or bundled",
		Description: "One or more JS/MJS/CJS files in the published artifact exhibit minification heuristics " +
			"(very long average line length, or very long single line, or no comments). " +
			"Minified code is harder to audit for malicious modifications.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.IsMinifiedCode {
				return false, "", nil
			}
			ev := map[string]any{}
			if len(in.MinifiedFiles) > 0 {
				ev["files"] = in.MinifiedFiles
			}
			return true, "Published JS source contains minified or bundled files.", ev
		},
	})
}
