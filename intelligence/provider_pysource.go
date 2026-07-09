package intelligence

import (
	"context"
	"strings"

	"github.com/chain305/chainsaw-core/pysource"
)

// pysourceProvider runs the import-time Python behavioral detector
// (core/pysource) over a package's .py bodies. It catches the PyPI malware
// class whose payload executes on import/install (malicious __init__.py /
// module top level / setup.py) — which the install-script and manifest
// signals miss. Tier 2 (needs the artifact); PyPI-only.
type pysourceProvider struct{}

func newPysourceProvider() *pysourceProvider { return &pysourceProvider{} }

func (p *pysourceProvider) Name() string        { return "pysource" }
func (p *pysourceProvider) Signal() SignalMask  { return SignalImportTimeExecution }
func (p *pysourceProvider) Tier() int           { return 2 }
func (p *pysourceProvider) NeedsArtifact() bool { return true }

var pysourceEcosystems = map[string]struct{}{"pip": {}, "pypi": {}, "python": {}}

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
	res := pysource.Scan(src)
	if !res.Detected {
		return PartialReport{}, nil
	}
	return PartialReport{Scan: &ArtifactScanSection{
		Performed:           true,
		ImportTimeExecution: true,
		ImportTimeKind:      res.Kind,
		ImportTimeDetail:    res.Detail,
	}}, nil
}
