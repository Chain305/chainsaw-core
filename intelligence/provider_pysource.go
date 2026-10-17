package intelligence

import (
	"context"
	"strings"

	"github.com/chain305/chainsaw-core/jssource"
	"github.com/chain305/chainsaw-core/pysource"
)

// pysourceProvider runs the import-time Python behavioral detector
// (core/pysource) over a package's .py bodies. It catches the PyPI malware
// class whose payload executes on import/install (malicious __init__.py /
// module top level / setup.py) — which the install-script and manifest
// signals miss. Tier 2 (needs the artifact). Since v0.22.105 it also runs
// core/jssource on npm: a module-top-level download/decode-and-execute shell
// call that runs on require(), with no install hook (@velora-dex/sdk 9.4.1;
// F6 of docs/attack-coverage-2026). Same facts, same kind, so
// sc.import_time_shell and the importTimeExecution policy condition apply.
type pysourceProvider struct{}

func newPysourceProvider() *pysourceProvider { return &pysourceProvider{} }

func (p *pysourceProvider) Name() string        { return "pysource" }
func (p *pysourceProvider) Signal() SignalMask  { return SignalImportTimeExecution }
func (p *pysourceProvider) Tier() int           { return 2 }
func (p *pysourceProvider) NeedsArtifact() bool { return true }

// pysourceAnalyzerVersion — bump when the import-time-execution detectors
// change what they report for identical bytes.
const pysourceAnalyzerVersion = 2 // 2: npm via core/jssource

func (p *pysourceProvider) AnalyzerVersion() int { return pysourceAnalyzerVersion }

var pysourceEcosystems = map[string]struct{}{"pip": {}, "pypi": {}, "python": {}, "npm": {}}

func (p *pysourceProvider) Supports(ecosystem string) bool {
	_, ok := pysourceEcosystems[strings.ToLower(strings.TrimSpace(ecosystem))]
	return ok
}

func (p *pysourceProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if req.Artifact == nil || len(req.Artifact.Bytes) == 0 {
		return PartialReport{}, nil
	}
	// sourceFilesFor returns the bundled source bodies (.py among them); the
	// detector filters to .py itself.
	src := sourceFilesFor(req.Artifact)
	if len(src) == 0 {
		return PartialReport{}, nil
	}
	var detected bool
	var kind, detail string
	if strings.EqualFold(strings.TrimSpace(req.Key.Ecosystem), "npm") {
		r := jssource.Scan(src)
		detected, kind, detail = r.Detected, r.Kind, r.Detail
	} else {
		r := pysource.Scan(src)
		detected, kind, detail = r.Detected, r.Kind, r.Detail
	}
	if !detected {
		return PartialReport{}, nil
	}
	return PartialReport{Scan: &ArtifactScanSection{
		Performed:           true,
		ImportTimeExecution: true,
		ImportTimeKind:      kind,
		ImportTimeDetail:    detail,
	}}, nil
}
