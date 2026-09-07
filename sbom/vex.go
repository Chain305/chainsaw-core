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
//   decision=allow, in effect, not expired, has CVE
//     → state=exploitable, response=[will_not_fix]
//   decision=monitor, in effect, not expired, has CVE
//     → state=in_triage
//   decision=deny                     → excluded (denials are blocks, not exemptions)
//   status=pending_approval | denied  → excluded (not in effect; see below)
//   expired                           → excluded
//   missing CVE id                    → excluded
//
// No `justification` is ever emitted. In CycloneDX 1.6 `justification` is
// only meaningful alongside `not_affected`, and a Chainsaw exception is a
// risk ACCEPTANCE — the operator confirmed the vulnerable package is
// present and chose to ship it. See the block above the vexState* consts
// for the full history; the short version is that emitting a
// justification next to `exploitable` recreates a schema-invalid document.
// The operator's free-text note rides along verbatim in analysis.detail
// and is never pattern-matched into a machine claim.
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
	// Status is the exception's wire lifecycle/expiry status, as stamped
	// by the server's deriveExceptionStatus. BuildVEX excludes the
	// not-in-effect lifecycle values — see ExceptionStatusNotInEffect.
	// Empty means in effect.
	Status    string
	ExpiresAt time.Time // zero value means "no expiry configured"
	CreatedAt time.Time
}

// Wire lifecycle statuses that mean "this exception is not in effect".
//
// These mirror the two lifecycle values the server's deriveExceptionStatus
// can stamp (internal/server/entries.go). They are string literals rather
// than an import because core/ is a separate module that must not depend
// on the server; the missing compiler link is covered by a guard test on
// the server side.
const (
	// ExceptionStatusPendingApproval is an exception that has been drafted
	// but not approved. The policy evaluator only honours
	// policy.StatusEnabled rules, so a pending exception grants nothing at
	// enforcement time — exporting it as a VEX statement would assert the
	// org formally accepted a risk it has not.
	ExceptionStatusPendingApproval = "pending_approval"
	// ExceptionStatusDenied is the wire label for policy.StatusDisabled:
	// an exception an approver refused, or one that was later revoked.
	ExceptionStatusDenied = "denied"
)

// ExceptionStatusNotInEffect reports whether a wire status means the
// exception grants nothing and must therefore not appear in a VEX
// document.
//
// This is a DENY-LIST on the lifecycle axis only, and both halves of that
// are deliberate:
//
//   - Deny-list, not allow-list. deriveExceptionStatus emits five values
//     across two independent axes: expiry (active / expiring_soon /
//     expired) and lifecycle (pending_approval / denied). An allow-list of
//     {"", "active"} would silently drop every "expiring_soon" exception —
//     a live, enforced carve-out inside the 14-day renew window — and a
//     compliance document quietly losing true statements is not detectable
//     at runtime. A deny-list's residual risk (a future not-in-effect
//     status leaking through) is closable with a guard test, and is.
//
//   - Lifecycle only, never expiry. Expiry is BuildVEX's own timestamp
//     compare against ExpiresAt. The wire status truncates DaysRemaining
//     to whole days and stamps "expired" at <= 0, so an exception with
//     1-23 hours left reads "expired" on the wire while it is still
//     enforced. Filtering on the display status would drop up to a day of
//     genuinely in-effect statements.
//
// An empty status is in effect. The server always populates Status (all
// eight response paths route through deriveExceptionStatus), so this is
// not a compatibility shim; it is what makes the deny-list's default the
// natural one and keeps a caller that forgets the field from producing an
// empty document rather than a wrong one. A caller that forgets it does
// over-export, which is why TestBuildVEX_ZeroValueDTOIsExported pins the
// behaviour instead of a comment promising it.
func ExceptionStatusNotInEffect(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case ExceptionStatusPendingApproval, ExceptionStatusDenied:
		return true
	default:
		return false
	}
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
		// Lifecycle gate. This must run independently of the expiry
		// compare below: a pending exception is not required to carry an
		// expiry (approveException sets one, drafting does not), so a
		// pending row with a zero ExpiresAt passes the timestamp check
		// forever and would otherwise be exported for good.
		if ExceptionStatusNotInEffect(ex.Status) {
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
