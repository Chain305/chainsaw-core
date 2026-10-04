package intelligence

import (
	"context"
	"path"
	"strings"

	"github.com/chain305/chainsaw-core/installscripts"
	"github.com/chain305/chainsaw-core/iocscan"
)

// iocscanProvider runs the embedded-IOC detector (core/iocscan) over a
// package's source bodies — exfil sink hosts and coupled stealer strings that
// reveal malicious intent independent of code shape. Tier 2 (needs the
// artifact); cross-ecosystem (any package can embed a webhook).
type iocscanProvider struct{}

func newIOCScanProvider() *iocscanProvider { return &iocscanProvider{} }

func (p *iocscanProvider) Name() string        { return "iocscan" }
func (p *iocscanProvider) Signal() SignalMask  { return SignalIOCScan }
func (p *iocscanProvider) Tier() int           { return 2 }
func (p *iocscanProvider) NeedsArtifact() bool { return true }

// iocscanAnalyzerVersion — bump when the indicator corpus or the
// network-send pairing rule changes what this reports for identical bytes.
//
// 2: a .gem's data.tar.gz is now mapped, so rubygems sees its code.
// 3: exfil_host hits carry MaliciousIOCCoupled (the file also sends) and
// MaliciousIOCAtEntry (a coupled hit in an install/import entrypoint).
// 4: DependencyCredential, AppCredentialSend.
const iocscanAnalyzerVersion = 4

func (p *iocscanProvider) AnalyzerVersion() int { return iocscanAnalyzerVersion }

// Supports: every ecosystem — an exfil webhook or stealer string is malicious
// in any package's source.
func (p *iocscanProvider) Supports(string) bool { return true }

func (p *iocscanProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if req.Artifact == nil || len(req.Artifact.Bytes) == 0 {
		return PartialReport{}, nil
	}
	src := sourceFilesFor(req.Artifact)
	scan := &ArtifactScanSection{
		DependencyCredential: iocscan.DependencyCredential(dependencySpecFilesFor(req.Artifact)),
		AppCredentialSend:    iocscan.AppCredentialSend(src),
	}
	indicators := scan.DependencyCredential != "" || scan.AppCredentialSend != ""
	scan.Performed = indicators
	none := PartialReport{}
	if indicators {
		none = PartialReport{Scan: scan}
	}
	if len(src) == 0 {
		return none, nil
	}
	res := iocscan.Scan(src)
	if !res.Detected {
		return none, nil
	}
	// A Weak hit's only evidence is in the package's own tests, docs examples,
	// or vendored third-party code. The field below is named MaliciousIOC and
	// feeds risk scoring, and a URL inside an SSRF-protection test is not that
	// — reporting it would propagate the same false positive the workstation
	// guard now avoids. The workstation guard still surfaces it as a warning,
	// so the indicator is not lost to the user who is actually installing.
	if res.Weak {
		return none, nil
	}
	scan.Performed = true
	scan.MaliciousIOC = true
	scan.MaliciousIOCKind = res.Kind
	scan.MaliciousIOCDetail = res.Detail
	scan.MaliciousIOCCoupled = res.Coupled
	scan.MaliciousIOCAtEntry = res.Coupled && exfilAtEntrypoint(req, src)
	return PartialReport{Scan: scan}, nil
}

// dependencySpecFilesFor selects package.json, lockfiles and the Python
// requirement files from the shared artifact map.
func dependencySpecFilesFor(h *ArtifactHandle) map[string][]byte {
	res := h.SharedArtifactMap()
	if len(res.Files) == 0 {
		return legacyWalkArtifact(h, iocscan.WantsDependencySpec)
	}
	return res.Files.SelectLower(iocscan.WantsDependencySpec)
}

// exfilAtEntrypoint reports whether a coupled exfil_host hit sits in code that
// runs on install or import without the user calling anything: on npm, a
// script a preinstall/install/postinstall hook runs; on PyPI, setup.py or an
// __init__.py. Only those files are re-scanned, so a sink buried in an
// ordinary module (detect-secrets' Slack plugin) does not count.
func exfilAtEntrypoint(req Request, src map[string][]byte) bool {
	entry := map[string][]byte{}
	switch strings.ToLower(req.Key.Ecosystem) {
	case "npm", "yarn", "bun":
		hooks := installscripts.NPM(FirstMatch(ManifestsFor(req.Artifact), "package.json")).ScriptBody
		for _, ref := range installscripts.ReferencedScripts(hooks) {
			for _, rs := range resolveBundledScripts(src, ref) {
				entry[rs.path] = rs.body
			}
		}
	case "pip", "pypi":
		for name, body := range src {
			if b := path.Base(name); b == "setup.py" || b == "__init__.py" {
				entry[name] = body
			}
		}
	}
	if len(entry) == 0 {
		return false
	}
	r := iocscan.Scan(entry)
	return r.Kind == "exfil_host" && r.Coupled && !r.Weak
}
