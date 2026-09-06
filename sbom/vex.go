package sbom

// CycloneDX VEX (Vulnerability Exploitability eXchange) — emits a CycloneDX
// 1.6 BOM whose payload is `vulnerabilities[]` populated from Chainsaw's
// exception store. VEX is the standard way to publish "we know about this
// CVE in package X but we're not affected because Y" so downstream tooling
// (Dependency-Track, Grype, etc.) can suppress matching findings.
// Reference: https://cyclonedx.org/capabilities/vex/.
//
// Exception → VEX statement mapping (the WHY):
//
//   decision=allow, not expired, has CVE
//     - note matches /not in (the )?execution path|not reachable|unreachable/i
//         → state=not_affected, justification=vulnerable_code_not_in_execute_path
//     - else
//         → state=not_affected, justification=code_not_present (default)
//   decision=monitor, not expired, has CVE → state=in_triage
//   decision=deny                          → excluded (denials are blocks, not exemptions)
//   expired                                → excluded
//   missing CVE id                         → excluded
//
// affects[].ref is the affected component's PURL when available; otherwise
// the bom-ref short form `<name>@<version>` so the statement is still
// pinnable to a specific component.

import (
	"encoding/json"
	"strings"
	"time"
)

// CycloneDXVEX is a CycloneDX 1.6 BOM whose value is the populated
// `vulnerabilities[]` slice. Same envelope as CycloneDXBOM so consumers
// that already speak CycloneDX can ingest it without a new parser.
type CycloneDXVEX struct {
	BOMFormat       string                   `json:"bomFormat"`
	SpecVersion     string                   `json:"specVersion"`
	Version         int                      `json:"version"`
	SerialNumber    string                   `json:"serialNumber,omitempty"`
	Metadata        CycloneDXMetadata        `json:"metadata"`
	Vulnerabilities []CycloneDXVulnerability `json:"vulnerabilities"`
}

type CycloneDXVulnerability struct {
	ID       string                 `json:"id"`
	Source   CycloneDXVulnSource    `json:"source,omitempty"`
	Analysis CycloneDXVulnAnalysis  `json:"analysis"`
	Affects  []CycloneDXVulnAffects `json:"affects,omitempty"`
}

type CycloneDXVulnSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type CycloneDXVulnAnalysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

type CycloneDXVulnAffects struct {
	Ref string `json:"ref"`
}

// Exception is the DTO BuildVEX consumes. The on-the-wire exception entry
// (internal/server/entries.go: exceptionEntry) is unexported and lacks the
// decision/CVE/note fields VEX needs, so callers adapt their richer source
// of truth (policy row, server-internal entry) into this shape.
type Exception struct {
	ID         string
	Decision   string // "allow" | "monitor" | "deny"
	Repository string
	Ecosystem  string
	Name       string
	Version    string
	PURL       string
	CVE        string
	Note       string
	ExpiresAt  time.Time // zero value means "no expiry configured"
	CreatedAt  time.Time
}

// VEX analysis strings — members of the CycloneDX 1.6 impactAnalysisState
// and impactAnalysisResponse enums.
//
// A Chainsaw exception is a risk ACCEPTANCE: the operator has confirmed the
// vulnerable package is present and chosen to allow it anyway. That is
// `exploitable` + `will_not_fix`, not `not_affected`.
//
// This used to emit `not_affected` with justification `code_not_present` —
// a positive machine assertion that the vulnerable code is absent from the
// product, i.e. the opposite of what the operator recorded. Downstream
// consumers (Dependency-Track, Grype) suppress a finding on that basis, so
// every consciously-accepted CVE disappeared from the customer's scanner
// and an auditor comparing the VEX against the SBOM would find the product
// asserting the absence of code the SBOM lists.
//
// The old code also upgraded the justification to
// "vulnerable_code_not_in_execute_path" from a regex over the operator's
// free-text note — machine-asserting that a reachability analysis had been
// performed because someone typed "not reachable". That string is not a
// member of the CycloneDX impactAnalysisJustification enum at all, so the
// document was schema-invalid whenever the regex hit. Both are gone.
//
// No justification is emitted now: `justification` is only meaningful
// alongside `not_affected`, which this code no longer produces.
const (
	vexStateExploitable = "exploitable"
	vexStateInTriage    = "in_triage"

	vexResponseWillNotFix = "will_not_fix"
)

// BuildVEX converts active exceptions into a CycloneDX 1.6 VEX document.
// orgID is reserved for future serialNumber derivation; today it is not
// embedded in output (CycloneDX serialNumber is meant to be a UUID URN,
// and the org-id is not one).
func BuildVEX(orgID string, exceptions []Exception) (CycloneDXVEX, error) {
	_ = orgID
	now := time.Now().UTC()
	vulns := make([]CycloneDXVulnerability, 0, len(exceptions))

	for _, ex := range exceptions {
		if strings.TrimSpace(ex.CVE) == "" {
			continue
		}
		if !ex.ExpiresAt.IsZero() && !ex.ExpiresAt.After(now) {
			continue
		}

		analysis, ok := analyzeException(ex)
		if !ok {
			continue
		}
		if note := strings.TrimSpace(ex.Note); note != "" {
			analysis.Detail = note
		}

		vuln := CycloneDXVulnerability{
			ID:       ex.CVE,
			Source:   CycloneDXVulnSource{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/" + ex.CVE},
			Analysis: analysis,
			Affects:  []CycloneDXVulnAffects{{Ref: affectsRef(ex)}},
		}
		vulns = append(vulns, vuln)
	}

	return CycloneDXVEX{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: CycloneDXMetadata{
			Timestamp: now.Format(time.RFC3339),
			Tools: []CycloneDXTool{
				{Vendor: "chainsaw", Name: "chainsaw-vex", Version: "1.0.0"},
			},
		},
		Vulnerabilities: vulns,
	}, nil
}

func analyzeException(ex Exception) (CycloneDXVulnAnalysis, bool) {
	switch strings.ToLower(strings.TrimSpace(ex.Decision)) {
	case "allow":
		// An accepted risk is exploitable-and-knowingly-unfixed. The
		// operator's note rides along in Analysis.Detail (set by the
		// caller) rather than being pattern-matched into a stronger
		// machine claim than they made.
		return CycloneDXVulnAnalysis{
			State:    vexStateExploitable,
			Response: []string{vexResponseWillNotFix},
		}, true
	case "monitor":
		return CycloneDXVulnAnalysis{State: vexStateInTriage}, true
	default:
		return CycloneDXVulnAnalysis{}, false
	}
}

func affectsRef(ex Exception) string {
	if strings.TrimSpace(ex.PURL) != "" {
		return ex.PURL
	}
	if ex.Ecosystem != "" && ex.Name != "" && ex.Version != "" {
		return buildPURL(ex.Ecosystem, ex.Name, ex.Version)
	}
	return ex.Name + "@" + ex.Version
}

// ToJSON serializes the VEX document. Mirrors CycloneDXBOM.ToJSON so
// callers can format both kinds of documents identically.
func (v *CycloneDXVEX) ToJSON() ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
