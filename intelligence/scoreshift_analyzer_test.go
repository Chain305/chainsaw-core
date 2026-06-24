package intelligence

// scoreshift_analyzer_test.go is a measurement harness, not a behavioural
// test. It builds ~30 synthetic Report fixtures spanning the realistic
// state space, computes the legacy trustscore.Compute total AND the
// authoritative Risk-V2 score (post-cutover ComputeTrustScore writes
// eval.RolledUp.Overall into SupplyChain.TrustScore), and emits a
// markdown report comparing the two distributions.
//
// Idempotent: gated behind the -update flag (or CHAINSAW_UPDATE_SCORE_SHIFT
// env var) so CI runs of the package don't keep rewriting the report.
// Run with:
//   go test -run TestRiskV2ScoreShiftReport ./internal/intelligence/ -update

import (
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/hiddenunicode"
	"github.com/chain305/chainsaw-core/trustscore"
)

var updateScoreShiftReport = flag.Bool("update", false, "regenerate docs/risk-v2-score-shift.md")

// fixture pairs a descriptive name with a builder that produces a fresh
// Report. We use builders (not pre-built pointers) so each fixture's
// state is mutated only by the harness, not by sibling fixtures.
type fixture struct {
	name       string
	notableSig string // most-impactful signal label, for the report
	build      func() *Report
}

// reportSignals projects a Report onto trustscore.Signals using the same
// logic ComputeTrustScore uses internally. Kept local to this test so the
// harness doesn't depend on internals being exported.
func reportSignals(r *Report) trustscore.Signals {
	s := trustscore.Signals{
		IsKnownMalicious:             r.SupplyChain.MalwareStatus == "malicious",
		IsVulnerable:                 r.Vulnerabilities.IsVulnerable,
		MaxCVSS:                      r.Vulnerabilities.CVSSScore,
		KnownExploitedCVE:            r.Vulnerabilities.KnownExploited,
		DangerousPickleOpcode:        r.Scan.DangerousPickleOpcode,
		ModelCardInjection:           r.Scan.ModelCardInjection,
		AgentToolDangerousCapability: r.Scan.AgentToolDangerousCapability,
		LicenseSPDX:                  r.Metadata.LicenseExpression,
		VersionReleaseDate:           r.Release.PublishedAt,
		IsSuspectedTyposquat:         r.SupplyChain.TyposquatStatus == "suspected",
		TyposquatConfidence:          r.SupplyChain.TyposquatConfidence,
		ChecksumVerified:             r.Artifact.Digests.Verified,
		SignatureVerified:            r.Artifact.SignatureVerified != nil && *r.Artifact.SignatureVerified,
		HasInstallScript:             r.Scan.HasInstallScript,
		InstallScriptFetchesRemote:   r.Scan.InstallScriptFetches,
		HasProvenance:                r.Provenance.Verified || r.Provenance.Status == "verified",
		ProvenanceStatus:             r.Provenance.Status,
		SLSALevel:                    r.Provenance.SLSALevel,
		AttestationFirst:             true, // mirror production default
		HasSourceRepo:                r.URLs.SourceRepoURL != "",
		RepoLinkStatus:               r.SupplyChain.RepoLinkStatus,
		HasHiddenUnicode: r.Scan.HiddenUnicodeHits >= hiddenunicode.Threshold() &&
			r.Scan.HiddenUnicodeHits > 0,
		PublisherChanged:    deref(r.SupplyChain.PublisherChanged),
		VersionAnomalyFlags: r.SupplyChain.VersionAnomalyFlags,
		VersionCount:        r.Maintenance.VersionCount,
	}
	if r.SupplyChain.PublishVelocityAnomaly != nil {
		s.PublishVelocityAnomaly = *r.SupplyChain.PublishVelocityAnomaly
	} else if r.SupplyChain.PublishVelocity24h > publishVelocityAnomalyThreshold {
		s.PublishVelocityAnomaly = true
	}
	return s
}

// helpers for terse fixture construction.
func ptrBool(b bool) *bool     { return &b }
func daysAgo(d int) *time.Time { t := time.Now().Add(-time.Duration(d) * 24 * time.Hour); return &t }

func fixtures() []fixture {
	return []fixture{
		// --- Clean baseline (3) ---
		{
			name:       "clean: popular maintained library (lodash-like)",
			notableSig: "verified provenance + repo ok + license + age",
			build: func() *Report {
				return &Report{
					Identity:    IdentitySection{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
					Release:     ReleaseSection{PublishedAt: daysAgo(900)},
					URLs:        URLSection{SourceRepoURL: "https://github.com/lodash/lodash"},
					Artifact:    ArtifactSection{Digests: ArtifactDigest{SHA256: "abc", Verified: true}, SignatureVerified: ptrBool(true)},
					Metadata:    MetadataSection{LicenseExpression: "MIT"},
					Provenance:  ProvenanceSection{Kind: "sigstore", Status: "verified", Available: true, Verified: true, SLSALevel: 3},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance: MaintenanceSection{VersionCount: 120, MaintainerCount: 4, RepoArchived: ptrBool(false)},
				}
			},
		},
		{
			name:       "clean: new but legitimate package (15 days old)",
			notableSig: "no PackageAge bonus yet; provenance verified",
			build: func() *Report {
				return &Report{
					Identity:    IdentitySection{Ecosystem: "npm", Package: "tiny-helpers", Version: "0.1.0"},
					Release:     ReleaseSection{PublishedAt: daysAgo(15)},
					URLs:        URLSection{SourceRepoURL: "https://github.com/example/tiny-helpers"},
					Artifact:    ArtifactSection{Digests: ArtifactDigest{Verified: true}},
					Metadata:    MetadataSection{LicenseExpression: "Apache-2.0"},
					Provenance:  ProvenanceSection{Status: "verified", Verified: true, SLSALevel: 2},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance: MaintenanceSection{VersionCount: 2, MaintainerCount: 1},
				}
			},
		},
		{
			name:       "clean: small utility package",
			notableSig: "all clean, no provenance",
			build: func() *Report {
				return &Report{
					Identity:    IdentitySection{Ecosystem: "pypi", Package: "leftpad-py", Version: "1.0.4"},
					Release:     ReleaseSection{PublishedAt: daysAgo(400)},
					URLs:        URLSection{SourceRepoURL: "https://github.com/example/leftpad-py"},
					Artifact:    ArtifactSection{Digests: ArtifactDigest{Verified: true}},
					Metadata:    MetadataSection{LicenseExpression: "MIT"},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance: MaintenanceSection{VersionCount: 5, MaintainerCount: 1},
				}
			},
		},

		// --- Malware-flagged (2) ---
		{
			name:       "malware: direct malicious",
			notableSig: "MalwareCheck=-100 (instant kill)",
			build: func() *Report {
				return &Report{
					Identity:    IdentitySection{Ecosystem: "npm", Package: "evil-pkg", Version: "1.0.0"},
					Release:     ReleaseSection{PublishedAt: daysAgo(2)},
					SupplyChain: SupplyChainSection{MalwareStatus: "malicious", MalwareID: "OSV-MAL-1", MalwareSummary: "data exfiltration"},
					Maintenance: MaintenanceSection{VersionCount: 1},
				}
			},
		},
		{
			name:       "malware: typosquat suspected (high confidence)",
			notableSig: "Typosquat=-30 high",
			build: func() *Report {
				return &Report{
					Identity: IdentitySection{Ecosystem: "npm", Package: "lodahs", Version: "1.0.0"},
					Release:  ReleaseSection{PublishedAt: daysAgo(3)},
					Metadata: MetadataSection{LicenseExpression: "MIT"},
					SupplyChain: SupplyChainSection{
						MalwareStatus: "clean", TyposquatStatus: "suspected",
						TyposquatConfidence: "high", TyposquatSimilarTo: "lodash",
						RepoLinkStatus: "missing",
					},
					Maintenance: MaintenanceSection{VersionCount: 1},
				}
			},
		},

		// --- CVE-vulnerable (3) ---
		{
			name:       "cve: low CVSS, no KEV",
			notableSig: "VulnStatus=+10 low",
			build: func() *Report {
				return &Report{
					Identity:        IdentitySection{Ecosystem: "npm", Package: "minor-cve-lib", Version: "2.1.0"},
					Release:         ReleaseSection{PublishedAt: daysAgo(200)},
					URLs:            URLSection{SourceRepoURL: "https://github.com/example/minor"},
					Metadata:        MetadataSection{LicenseExpression: "MIT"},
					Vulnerabilities: VulnSection{IsVulnerable: true, CVSSScore: 3.5, CVEs: []string{"CVE-2024-0001"}},
					SupplyChain:     SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance:     MaintenanceSection{VersionCount: 8},
				}
			},
		},
		{
			name:       "cve: high CVSS, no KEV",
			notableSig: "VulnStatus=0 high (no KEV)",
			build: func() *Report {
				return &Report{
					Identity:        IdentitySection{Ecosystem: "npm", Package: "high-cve-lib", Version: "0.9.0"},
					Release:         ReleaseSection{PublishedAt: daysAgo(180)},
					URLs:            URLSection{SourceRepoURL: "https://github.com/example/high"},
					Metadata:        MetadataSection{LicenseExpression: "MIT"},
					Vulnerabilities: VulnSection{IsVulnerable: true, CVSSScore: 8.4, CVEs: []string{"CVE-2024-9999"}},
					SupplyChain:     SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance:     MaintenanceSection{VersionCount: 6},
				}
			},
		},
		{
			name:       "cve: high CVSS WITH KEV match",
			notableSig: "KnownExploitedCVE=-25 + high CVSS",
			build: func() *Report {
				return &Report{
					Identity: IdentitySection{Ecosystem: "pypi", Package: "log4-pyish", Version: "2.14.1"},
					Release:  ReleaseSection{PublishedAt: daysAgo(800)},
					URLs:     URLSection{SourceRepoURL: "https://github.com/example/log4pyish"},
					Metadata: MetadataSection{LicenseExpression: "Apache-2.0"},
					Vulnerabilities: VulnSection{
						IsVulnerable: true, CVSSScore: 9.8, CVEs: []string{"CVE-2021-44228"},
						KnownExploited: true,
						KEVEntries:     []KEVEntry{{CVE: "CVE-2021-44228", DateAdded: "2021-12-10", KnownRansomwareCampaignUse: true}},
					},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance: MaintenanceSection{VersionCount: 20},
				}
			},
		},

		// --- Provenance / SLSA (3) ---
		{
			name:       "provenance: SLSA L1 verified",
			notableSig: "AttestationBase=70 + L1=0",
			build: func() *Report {
				return &Report{
					Identity:    IdentitySection{Ecosystem: "npm", Package: "slsa1-pkg", Version: "1.0.0"},
					Release:     ReleaseSection{PublishedAt: daysAgo(120)},
					URLs:        URLSection{SourceRepoURL: "https://github.com/example/slsa1"},
					Metadata:    MetadataSection{LicenseExpression: "MIT"},
					Provenance:  ProvenanceSection{Status: "verified", Verified: true, SLSALevel: 1},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance: MaintenanceSection{VersionCount: 3},
				}
			},
		},
		{
			name:       "provenance: SLSA L3 verified",
			notableSig: "AttestationBase=70 + L3=10",
			build: func() *Report {
				return &Report{
					Identity:    IdentitySection{Ecosystem: "npm", Package: "slsa3-pkg", Version: "1.0.0"},
					Release:     ReleaseSection{PublishedAt: daysAgo(120)},
					URLs:        URLSection{SourceRepoURL: "https://github.com/example/slsa3"},
					Metadata:    MetadataSection{LicenseExpression: "MIT"},
					Provenance:  ProvenanceSection{Status: "verified", Verified: true, SLSALevel: 3},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance: MaintenanceSection{VersionCount: 3},
				}
			},
		},
		{
			name:       "provenance: SLSA L4 verified",
			notableSig: "AttestationBase=70 + L4=15",
			build: func() *Report {
				return &Report{
					Identity:    IdentitySection{Ecosystem: "npm", Package: "slsa4-pkg", Version: "1.0.0"},
					Release:     ReleaseSection{PublishedAt: daysAgo(120)},
					URLs:        URLSection{SourceRepoURL: "https://github.com/example/slsa4"},
					Metadata:    MetadataSection{LicenseExpression: "MIT"},
					Artifact:    ArtifactSection{Digests: ArtifactDigest{Verified: true}, SignatureVerified: ptrBool(true)},
					Provenance:  ProvenanceSection{Status: "verified", Verified: true, SLSALevel: 4},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance: MaintenanceSection{VersionCount: 3},
				}
			},
		},

		// --- Signature (2) ---
		{
			name:       "signature: Maven PGP verified",
			notableSig: "SignatureVerified=+5",
			build: func() *Report {
				return &Report{
					Identity: IdentitySection{Ecosystem: "maven", Package: "org.example:lib", Version: "2.0.0"},
					Release:  ReleaseSection{PublishedAt: daysAgo(300)},
					URLs:     URLSection{SourceRepoURL: "https://github.com/example/maven-lib"},
					Metadata: MetadataSection{LicenseExpression: "Apache-2.0"},
					Artifact: ArtifactSection{
						Digests:           ArtifactDigest{Verified: true},
						SignatureVerified: ptrBool(true),
						SignatureKind:     "pgp",
					},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance: MaintenanceSection{VersionCount: 14},
				}
			},
		},
		{
			name:       "signature: RubyGems X.509 verified",
			notableSig: "SignatureVerified=+5; no SLSA",
			build: func() *Report {
				return &Report{
					Identity: IdentitySection{Ecosystem: "rubygems", Package: "rack-extension", Version: "3.0.0"},
					Release:  ReleaseSection{PublishedAt: daysAgo(250)},
					URLs:     URLSection{SourceRepoURL: "https://github.com/example/rack-extension"},
					Metadata: MetadataSection{LicenseExpression: "MIT"},
					Artifact: ArtifactSection{
						Digests:           ArtifactDigest{Verified: true},
						SignatureVerified: ptrBool(true),
						SignatureKind:     "x509",
					},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance: MaintenanceSection{VersionCount: 9},
				}
			},
		},

		// --- AI artifact (3) ---
		{
			name:       "ai: clean huggingface model",
			notableSig: "no AI penalties; safetensors preferred",
			build: func() *Report {
				return &Report{
					Identity:    IdentitySection{Ecosystem: "huggingface", Package: "cleanorg/safe-model", Version: "1.0", ArtifactSubtype: "model"},
					Release:     ReleaseSection{PublishedAt: daysAgo(60)},
					URLs:        URLSection{SourceRepoURL: "https://huggingface.co/cleanorg/safe-model"},
					Metadata:    MetadataSection{LicenseExpression: "Apache-2.0"},
					Scan:        ArtifactScanSection{Performed: true, PrefersSafetensorsAvailable: true},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance: MaintenanceSection{VersionCount: 3},
				}
			},
		},
		{
			name:       "ai: pickle gadget detected",
			notableSig: "DangerousPickleOpcode=-30",
			build: func() *Report {
				return &Report{
					Identity: IdentitySection{Ecosystem: "huggingface", Package: "shady/exec-model", Version: "0.1", ArtifactSubtype: "model"},
					Release:  ReleaseSection{PublishedAt: daysAgo(5)},
					Metadata: MetadataSection{LicenseExpression: "MIT"},
					Scan: ArtifactScanSection{
						Performed:                 true,
						DangerousPickleOpcode:     true,
						DangerousPickleFiles:      []string{"weights.pkl"},
						DangerousPickleSummary:    "REDUCE -> os.system",
						UnsafeSerializationFormat: true,
					},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "missing"},
					Maintenance: MaintenanceSection{VersionCount: 1},
				}
			},
		},
		{
			name:       "ai: MCP server with dangerous capability",
			notableSig: "AgentToolDangerousCapability=-15",
			build: func() *Report {
				return &Report{
					Identity: IdentitySection{Ecosystem: "npm", Package: "@vendor/mcp-shell", Version: "1.0.0", ArtifactSubtype: "mcp-server"},
					Release:  ReleaseSection{PublishedAt: daysAgo(20)},
					URLs:     URLSection{SourceRepoURL: "https://github.com/vendor/mcp-shell"},
					Metadata: MetadataSection{LicenseExpression: "MIT"},
					Scan: ArtifactScanSection{
						Performed:                    true,
						AgentToolDeclared:            true,
						AgentToolDangerousCapability: true,
						AgentToolCapabilities:        []string{"shell", "file_write"},
						MCPServerUnverified:          true,
					},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance: MaintenanceSection{VersionCount: 2},
				}
			},
		},

		// --- Maintainer concerns (3) ---
		{
			name:       "maintainer: publisher changed",
			notableSig: "PublisherChanged=-25",
			build: func() *Report {
				return &Report{
					Identity: IdentitySection{Ecosystem: "npm", Package: "@scope/util", Version: "3.4.0"},
					Release:  ReleaseSection{PublishedAt: daysAgo(40)},
					URLs:     URLSection{SourceRepoURL: "https://github.com/example/util"},
					Metadata: MetadataSection{LicenseExpression: "MIT"},
					SupplyChain: SupplyChainSection{
						MalwareStatus: "clean", TyposquatStatus: "clean",
						PublisherChanged: ptrBool(true),
						PublisherAdded:   []string{"new-account-2026"},
						RepoLinkStatus:   "ok",
					},
					Maintenance: MaintenanceSection{VersionCount: 22, MaintainerCount: 2},
				}
			},
		},
		{
			name:       "maintainer: first-time collaborator",
			notableSig: "v2-only signal: FirstTimeCollaborator",
			build: func() *Report {
				return &Report{
					Identity:    IdentitySection{Ecosystem: "npm", Package: "team-lib", Version: "1.5.0"},
					Release:     ReleaseSection{PublishedAt: daysAgo(35)},
					URLs:        URLSection{SourceRepoURL: "https://github.com/example/team-lib"},
					Metadata:    MetadataSection{LicenseExpression: "MIT"},
					Scan:        ArtifactScanSection{Performed: true, FirstTimeCollaborator: ptrBool(true)},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance: MaintenanceSection{VersionCount: 8, MaintainerCount: 3},
				}
			},
		},
		{
			name:       "maintainer: very-young account (12 days)",
			notableSig: "v2-only signal: MaintainerAccountAgeDays=12",
			build: func() *Report {
				return &Report{
					Identity:    IdentitySection{Ecosystem: "pypi", Package: "fresh-pkg", Version: "0.1.0"},
					Release:     ReleaseSection{PublishedAt: daysAgo(10)},
					URLs:        URLSection{SourceRepoURL: "https://github.com/newuser/fresh-pkg"},
					Metadata:    MetadataSection{LicenseExpression: "MIT"},
					Scan:        ArtifactScanSection{Performed: true, MaintainerAccountAgeDays: 12},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance: MaintenanceSection{VersionCount: 1, MaintainerCount: 1},
				}
			},
		},

		// --- Artifact concerns (3) ---
		{
			name:       "artifact: install scripts that fetch remote",
			notableSig: "InstallScript=-20 fetchesRemote",
			build: func() *Report {
				return &Report{
					Identity: IdentitySection{Ecosystem: "npm", Package: "post-install-fetcher", Version: "1.0.0"},
					Release:  ReleaseSection{PublishedAt: daysAgo(8)},
					URLs:     URLSection{SourceRepoURL: "https://github.com/example/postinstall"},
					Metadata: MetadataSection{LicenseExpression: "MIT"},
					Scan: ArtifactScanSection{
						Performed: true, HasInstallScript: true, InstallScriptFetches: true,
						InstallScriptKind: "fetches_remote",
					},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance: MaintenanceSection{VersionCount: 4},
				}
			},
		},
		{
			name:       "artifact: manifest confusion",
			notableSig: "ManifestConfusion (v2 signal)",
			build: func() *Report {
				return &Report{
					Identity: IdentitySection{Ecosystem: "npm", Package: "confusing-pkg", Version: "1.2.3"},
					Release:  ReleaseSection{PublishedAt: daysAgo(45)},
					URLs:     URLSection{SourceRepoURL: "https://github.com/example/confusing"},
					Metadata: MetadataSection{LicenseExpression: "MIT"},
					Scan: ArtifactScanSection{
						Performed: true, ManifestConfusion: true,
						ManifestConfusionFields: []string{"scripts.preinstall"},
					},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance: MaintenanceSection{VersionCount: 6},
				}
			},
		},
		{
			name:       "artifact: hidden unicode payload",
			notableSig: "HiddenUnicode=-20",
			build: func() *Report {
				return &Report{
					Identity: IdentitySection{Ecosystem: "npm", Package: "trojan-source-pkg", Version: "1.0.0"},
					Release:  ReleaseSection{PublishedAt: daysAgo(70)},
					URLs:     URLSection{SourceRepoURL: "https://github.com/example/trojan"},
					Metadata: MetadataSection{LicenseExpression: "MIT"},
					Scan: ArtifactScanSection{
						Performed: true, HiddenUnicodeHits: 50,
						HiddenUnicodeKinds: []string{"bidi"},
					},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance: MaintenanceSection{VersionCount: 3},
				}
			},
		},

		// --- Repo signals (3) ---
		{
			name:       "repo: archived repo",
			notableSig: "SourceRepo=-10 archived",
			build: func() *Report {
				return &Report{
					Identity: IdentitySection{Ecosystem: "pypi", Package: "old-lib", Version: "1.0.0"},
					Release:  ReleaseSection{PublishedAt: daysAgo(1500)},
					URLs:     URLSection{SourceRepoURL: "https://github.com/example/old-lib"},
					Metadata: MetadataSection{LicenseExpression: "MIT"},
					SupplyChain: SupplyChainSection{
						MalwareStatus: "clean", TyposquatStatus: "clean",
						RepoLinkStatus: "archived",
						RepoArchived:   ptrBool(true),
					},
					Maintenance: MaintenanceSection{VersionCount: 11, RepoArchived: ptrBool(true)},
				}
			},
		},
		{
			name:       "repo: missing repo URL",
			notableSig: "SourceRepo=-10 missing",
			build: func() *Report {
				return &Report{
					Identity: IdentitySection{Ecosystem: "npm", Package: "no-repo-pkg", Version: "1.0.0"},
					Release:  ReleaseSection{PublishedAt: daysAgo(90)},
					Metadata: MetadataSection{LicenseExpression: "MIT"},
					SupplyChain: SupplyChainSection{
						MalwareStatus: "clean", TyposquatStatus: "clean",
						RepoLinkStatus: "missing",
					},
					Maintenance: MaintenanceSection{VersionCount: 2},
				}
			},
		},
		{
			name:       "repo: ownership mismatch",
			notableSig: "SourceRepo=-20 ownership_mismatch",
			build: func() *Report {
				return &Report{
					Identity: IdentitySection{Ecosystem: "npm", Package: "claimed-by-attacker", Version: "1.0.0"},
					Release:  ReleaseSection{PublishedAt: daysAgo(20)},
					URLs:     URLSection{SourceRepoURL: "https://github.com/attacker/realname"},
					Metadata: MetadataSection{LicenseExpression: "MIT"},
					SupplyChain: SupplyChainSection{
						MalwareStatus: "clean", TyposquatStatus: "clean",
						RepoLinkStatus: "ownership_mismatch",
					},
					Maintenance: MaintenanceSection{VersionCount: 1},
				}
			},
		},

		// --- Composite typosquat-candidate (3) ---
		{
			name:       "typosquat candidate: low stars + young + dormant",
			notableSig: "v2 SuspiciousRepoStars + young + dormant",
			build: func() *Report {
				dormant := time.Now().Add(-540 * 24 * time.Hour)
				return &Report{
					Identity: IdentitySection{Ecosystem: "npm", Package: "react-utils-pro", Version: "0.1.0"},
					Release:  ReleaseSection{PublishedAt: daysAgo(7)},
					URLs:     URLSection{SourceRepoURL: "https://github.com/oneoff/react-utils-pro"},
					Metadata: MetadataSection{LicenseExpression: "MIT"},
					Scan: ArtifactScanSection{
						Performed: true, SuspiciousRepoStars: true,
						MaintainerAccountAgeDays: 30,
					},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "ok"},
					Maintenance: MaintenanceSection{VersionCount: 1, LastRepoCommitAt: &dormant},
				}
			},
		},
		{
			name:       "typosquat candidate: homoglyph-detected typosquat",
			notableSig: "Typosquat=-20 medium homoglyph",
			build: func() *Report {
				return &Report{
					Identity: IdentitySection{Ecosystem: "npm", Package: "reаct", Version: "1.0.0"}, // cyrillic 'а'
					Release:  ReleaseSection{PublishedAt: daysAgo(2)},
					Metadata: MetadataSection{LicenseExpression: "MIT"},
					SupplyChain: SupplyChainSection{
						MalwareStatus: "clean", TyposquatStatus: "suspected",
						TyposquatConfidence: "medium", TyposquatSimilarTo: "react",
						RepoLinkStatus: "missing",
					},
					Maintenance: MaintenanceSection{VersionCount: 1},
				}
			},
		},
		{
			name:       "typosquat candidate: trivial package + no source repo",
			notableSig: "v2 TrivialPackage + missing repo",
			build: func() *Report {
				return &Report{
					Identity: IdentitySection{Ecosystem: "npm", Package: "is-even-better", Version: "1.0.0"},
					Release:  ReleaseSection{PublishedAt: daysAgo(4)},
					Metadata: MetadataSection{LicenseExpression: "MIT"},
					Scan: ArtifactScanSection{
						Performed: true, TrivialPackage: true, TrivialPackageLOC: 6,
					},
					SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", RepoLinkStatus: "missing"},
					Maintenance: MaintenanceSection{VersionCount: 1},
				}
			},
		},

		// --- Yanked / anomaly (2) ---
		{
			name:       "anomaly: version anomaly flags (regression + skip)",
			notableSig: "VersionAnomaly=-30 capped",
			build: func() *Report {
				return &Report{
					Identity: IdentitySection{Ecosystem: "npm", Package: "axios-style", Version: "0.27.2"},
					Release:  ReleaseSection{PublishedAt: daysAgo(15)},
					URLs:     URLSection{SourceRepoURL: "https://github.com/example/axios-style"},
					Metadata: MetadataSection{LicenseExpression: "MIT"},
					SupplyChain: SupplyChainSection{
						MalwareStatus: "clean", TyposquatStatus: "clean",
						VersionAnomalyFlags: []string{"regression", "major_skip"},
						RepoLinkStatus:      "ok",
					},
					Maintenance: MaintenanceSection{VersionCount: 30},
				}
			},
		},
		{
			name:       "anomaly: high publish velocity (Shai-Hulud tell)",
			notableSig: "PublishVelocityAnomaly=-20",
			build: func() *Report {
				return &Report{
					Identity: IdentitySection{Ecosystem: "npm", Package: "burst-pkg", Version: "1.0.45"},
					Release:  ReleaseSection{PublishedAt: daysAgo(1)},
					URLs:     URLSection{SourceRepoURL: "https://github.com/example/burst"},
					Metadata: MetadataSection{LicenseExpression: "MIT"},
					SupplyChain: SupplyChainSection{
						MalwareStatus: "clean", TyposquatStatus: "clean",
						PublishVelocity24h:     45,
						PublishVelocityAnomaly: ptrBool(true),
						RepoLinkStatus:         "ok",
					},
					Maintenance: MaintenanceSection{VersionCount: 80},
				}
			},
		},
	}
}

type result struct {
	name       string
	legacy     int
	v2         int
	delta      int
	notableSig string
}

func TestRiskV2ScoreShiftReport(t *testing.T) {
	if !*updateScoreShiftReport && os.Getenv("CHAINSAW_UPDATE_SCORE_SHIFT") == "" {
		t.Skip("set -update or CHAINSAW_UPDATE_SCORE_SHIFT=1 to regenerate docs/risk-v2-score-shift.md")
	}

	fxs := fixtures()
	results := make([]result, 0, len(fxs))

	for _, fx := range fxs {
		// Build a single Report and score it both ways from the SAME object.
		report := fx.build()

		// Legacy: project to Signals and call Compute directly.
		legacyScore := trustscore.Compute(reportSignals(report))

		// Risk-V2: end-to-end ComputeTrustScore overwrites SupplyChain.TrustScore.
		ComputeTrustScore(report)
		v2Score := report.SupplyChain.TrustScore

		results = append(results, result{
			name:       fx.name,
			legacy:     legacyScore.Total,
			v2:         v2Score,
			delta:      v2Score - legacyScore.Total,
			notableSig: fx.notableSig,
		})
	}

	md := renderMarkdown(results)

	// Resolve docs/ relative to the repo root (this test runs from
	// internal/intelligence; repo root is two parents up).
	target := filepath.Join("..", "..", "docs", "risk-v2-score-shift.md")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("mkdir docs: %v", err)
	}
	if err := os.WriteFile(target, []byte(md), 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	t.Logf("wrote %s (%d fixtures)", target, len(results))
}

func renderMarkdown(rs []result) string {
	// Stats.
	n := len(rs)
	deltas := make([]int, n)
	absDeltas := make([]int, n)
	var sum, maxAbs int
	var n5, n10, n20 int
	for i, r := range rs {
		deltas[i] = r.delta
		ad := r.delta
		if ad < 0 {
			ad = -ad
		}
		absDeltas[i] = ad
		sum += r.delta
		if ad > maxAbs {
			maxAbs = ad
		}
		if ad > 5 {
			n5++
		}
		if ad > 10 {
			n10++
		}
		if ad > 20 {
			n20++
		}
	}
	mean := float64(sum) / float64(n)
	sortedAbs := append([]int(nil), absDeltas...)
	sort.Ints(sortedAbs)
	median := sortedAbs[n/2]
	pctUnder5 := 100.0 * float64(n-n5) / float64(n)

	verdict := "GREEN — Acceptable for rollout"
	verdictDetail := fmt.Sprintf("Max abs delta = %d (<15) AND %.0f%% of fixtures shift <5 points (>70%% threshold).", maxAbs, pctUnder5)
	if maxAbs >= 15 || pctUnder5 < 70 {
		verdict = "YELLOW — Investigate before rollout"
		verdictDetail = fmt.Sprintf("Max abs delta = %d, %.0f%% of fixtures shift <5 points. Threshold (max <15, ≥70%% under-5pt) not met.", maxAbs, pctUnder5)
	}
	if n20 >= 5 {
		verdict = "RED — Do not roll out as-is"
		verdictDetail = fmt.Sprintf("%d fixtures shift >20 points; customer-visible alert calibration will materially break.", n20)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Risk-V2 vs Legacy TrustScore — Score-Shift Report\n\n")
	fmt.Fprintf(&b, "_Generated %s by `TestRiskV2ScoreShiftReport` (run with `go test -run TestRiskV2ScoreShiftReport ./internal/intelligence/ -update`)._\n\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "## Methodology\n\n")
	fmt.Fprintf(&b, "We constructed %d synthetic `*intelligence.Report` fixtures spanning the realistic state space (clean baselines, malware, CVEs, provenance/SLSA, signature, AI-artifact, maintainer concerns, artifact concerns, repo signals, typosquat composites, anomalies). For each fixture we run BOTH scorers against the same `Report`:\n\n", n)
	fmt.Fprintf(&b, "- **Legacy**: `trustscore.Compute(signalsFromReport(r))` — the previous authoritative integer score.\n")
	fmt.Fprintf(&b, "- **Risk-V2**: `ComputeTrustScore(r)` end-to-end, then read `report.SupplyChain.TrustScore` (now overwritten by `eval.RolledUp.Overall`).\n\n")
	fmt.Fprintf(&b, "Delta = Risk-V2 − Legacy. Positive = v2 scores higher. Synthetic fixtures, not live registry scans, so results are deterministic and reproducible.\n\n")

	fmt.Fprintf(&b, "## Verdict\n\n**%s**\n\n%s\n\n", verdict, verdictDetail)

	fmt.Fprintf(&b, "## Summary statistics\n\n")
	fmt.Fprintf(&b, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Fixtures | %d |\n", n)
	fmt.Fprintf(&b, "| Mean delta (v2 − legacy) | %+.1f |\n", mean)
	fmt.Fprintf(&b, "| Median absolute delta | %d |\n", median)
	fmt.Fprintf(&b, "| Max absolute delta | %d |\n", maxAbs)
	fmt.Fprintf(&b, "| Fixtures shifting >5 pts | %d (%.0f%%) |\n", n5, 100.0*float64(n5)/float64(n))
	fmt.Fprintf(&b, "| Fixtures shifting >10 pts | %d (%.0f%%) |\n", n10, 100.0*float64(n10)/float64(n))
	fmt.Fprintf(&b, "| Fixtures shifting >20 pts | %d (%.0f%%) |\n\n", n20, 100.0*float64(n20)/float64(n))

	fmt.Fprintf(&b, "## Per-fixture comparison\n\n")
	fmt.Fprintf(&b, "| Fixture | Legacy | V2 | Delta | Direction | Most-impactful signal |\n")
	fmt.Fprintf(&b, "|---|---:|---:|---:|:---:|---|\n")
	for _, r := range rs {
		dir := "same"
		if r.delta > 0 {
			dir = "up"
		} else if r.delta < 0 {
			dir = "down"
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %+d | %s | %s |\n",
			r.name, r.legacy, r.v2, r.delta, dir, r.notableSig)
	}
	b.WriteString("\n")

	// Outlier explanations.
	fmt.Fprintf(&b, "## Outliers (|Δ| > 10)\n\n")
	any := false
	for _, r := range rs {
		ad := r.delta
		if ad < 0 {
			ad = -ad
		}
		if ad > 10 {
			any = true
			fmt.Fprintf(&b, "- **%s** — legacy %d → v2 %d (Δ%+d). Driver: %s. ", r.name, r.legacy, r.v2, r.delta, r.notableSig)
			switch {
			case strings.Contains(r.name, "malware: direct"):
				fmt.Fprintf(&b, "Both engines pin malicious to 0; any non-zero shift is rounding in v2 weighting.\n")
			case strings.Contains(r.name, "SLSA L4") || strings.Contains(r.name, "SLSA L3") || strings.Contains(r.name, "SLSA L1"):
				fmt.Fprintf(&b, "v2 applies a weighted SLSA bonus across multiple risk categories instead of the single AttestationBase+SLSALevelBonus addition. Net effect varies with the rest of the signal vector.\n")
			case strings.Contains(r.name, "KEV"):
				fmt.Fprintf(&b, "v2 treats KEV as a categorical short-circuit signal; legacy stacks −25 additively. Different magnitudes are expected here.\n")
			case strings.Contains(r.name, "typosquat candidate") || strings.Contains(r.name, "trivial package") || strings.Contains(r.name, "first-time") || strings.Contains(r.name, "very-young") || strings.Contains(r.name, "manifest confusion") || strings.Contains(r.name, "MCP server"):
				fmt.Fprintf(&b, "v2 has dedicated signals (TrivialPackage, FirstTimeCollaborator, MaintainerAccountAgeDays, ManifestConfusion, MCP categories) the legacy scorer does not weigh.\n")
			case strings.Contains(r.name, "archived") || strings.Contains(r.name, "missing"):
				fmt.Fprintf(&b, "v2 weighs maintenance/repo categories higher; archived/missing repo penalties differ from the legacy −10/−10/−20 mapping.\n")
			default:
				fmt.Fprintf(&b, "Category-weight differences in v2 vs the flat additive legacy model.\n")
			}
		}
	}
	if !any {
		fmt.Fprintf(&b, "_None — every fixture stayed within ±10 points._\n")
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "## Recommendations by customer cohort\n\n")
	fmt.Fprintf(&b, "- **Alert threshold = 50** (block-medium-and-below): expect ")
	below50Legacy, below50V2 := 0, 0
	for _, r := range rs {
		if r.legacy < 50 {
			below50Legacy++
		}
		if r.v2 < 50 {
			below50V2++
		}
	}
	delta50 := below50V2 - below50Legacy
	pct50 := 0.0
	if below50Legacy > 0 {
		pct50 = 100.0 * float64(delta50) / float64(below50Legacy)
	}
	fmt.Fprintf(&b, "%d→%d fixtures alerting (%+d, %+.0f%%). Tune the threshold or expect proportional alert-volume change.\n", below50Legacy, below50V2, delta50, pct50)

	fmt.Fprintf(&b, "- **Alert threshold = 70** (block-low-and-below): ")
	b70L, b70V := 0, 0
	for _, r := range rs {
		if r.legacy < 70 {
			b70L++
		}
		if r.v2 < 70 {
			b70V++
		}
	}
	fmt.Fprintf(&b, "%d→%d fixtures alerting (%+d).\n", b70L, b70V, b70V-b70L)
	fmt.Fprintf(&b, "- **Archived-repo cohorts**: v2's category-weighted maintenance penalty differs from legacy's flat −10. Customers alerting on archived repos should re-baseline.\n")
	fmt.Fprintf(&b, "- **AI-artifact cohorts**: v2 has dedicated MCP / pickle / model-card categories; expect richer separation between clean and dangerous AI artifacts than legacy provides.\n")
	fmt.Fprintf(&b, "- **Provenance-positive packages**: SLSA bonuses propagate through the v2 category weights rather than as a flat additive — high-SLSA packages may score slightly different than the legacy +70+L tier suggests.\n\n")

	fmt.Fprintf(&b, "## Notes\n\n")
	fmt.Fprintf(&b, "- Both scorers run against the same `*Report` object — projection is identical; only the aggregator differs.\n")
	fmt.Fprintf(&b, "- The legacy scorer here uses `AttestationFirst=true` to mirror production default (CHAINSAW_TRUSTSCORE_ATTESTATION_FIRST defaults ON).\n")
	fmt.Fprintf(&b, "- Fixtures are believable real-world shapes, not contrived edge cases; values will not exactly match real packages but the SHAPE matches.\n")

	_ = math.Abs // keep import stable if math becomes unused after edits
	return b.String()
}
