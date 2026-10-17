package intelligence

import (
	"context"
	"path"
	"strings"

	"github.com/chain305/chainsaw-core/jssource"
	"github.com/chain305/chainsaw-core/pysource"
	"github.com/chain305/chainsaw-core/scriptsource"
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
// Since v0.22.106 (F7) it reads .pth files on PyPI, and runs core/scriptsource
// on Composer (.php: an autoload.files entry runs on every autoload,
// laravel-lang) and RubyGems (.rb: lib/ runs on require, SleeperGem); a hit
// only in tests/spec/docs (scriptsource Weak) is not reported, as iocscan's.
type pysourceProvider struct{}

func newPysourceProvider() *pysourceProvider { return &pysourceProvider{} }

func (p *pysourceProvider) Name() string        { return "pysource" }
func (p *pysourceProvider) Signal() SignalMask  { return SignalImportTimeExecution }
func (p *pysourceProvider) Tier() int           { return 2 }
func (p *pysourceProvider) NeedsArtifact() bool { return true }

// pysourceAnalyzerVersion — bump when the import-time-execution detectors
// change what they report for identical bytes.
//
// 2: npm via core/jssource.
// 3: .pth files, download_exec and child-interpreter decode (F7, F14);
// composer and rubygems via core/scriptsource.
// 4: strongest result across all files (a Dispositive shape is no longer
// masked by an earlier advisory hit); .pth scanned first under its own cap;
// scriptsource masks strings/comments and downgrades non-shipping paths.
const pysourceAnalyzerVersion = 4

func (p *pysourceProvider) AnalyzerVersion() int { return pysourceAnalyzerVersion }

var pysourceEcosystems = map[string]struct{}{"pip": {}, "pypi": {}, "python": {}, "npm": {}, "composer": {}, "rubygems": {}}

func (p *pysourceProvider) Supports(ecosystem string) bool {
	_, ok := pysourceEcosystems[strings.ToLower(strings.TrimSpace(ecosystem))]
	return ok
}

func (p *pysourceProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if req.Artifact == nil || len(req.Artifact.Bytes) == 0 {
		return PartialReport{}, nil
	}
	// Each detector filters to its own extensions.
	src := importTimeSourceFor(req.Artifact)
	if len(src) == 0 {
		return PartialReport{}, nil
	}
	var detected bool
	var kind, detail string
	switch strings.ToLower(strings.TrimSpace(req.Key.Ecosystem)) {
	case "npm":
		r := jssource.Scan(src)
		detected, kind, detail = r.Detected, r.Kind, r.Detail
	case "composer":
		r := scriptsource.ScanPHP(src)
		detected, kind, detail = r.Detected && !r.Weak, r.Kind, r.Detail
	case "rubygems":
		r := scriptsource.ScanRuby(src)
		detected, kind, detail = r.Detected && !r.Weak, r.Kind, r.Detail
	default:
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

// importTimeSourceFor is sourceFilesFor plus the files only the import-time
// detectors read: .pth (executed by site.py), .php and .rb. Kept apart from
// wantsBundledScript so iocscan and the install-script resolver keep their
// measured input.
func importTimeSourceFor(h *ArtifactHandle) map[string][]byte {
	want := func(name string) bool {
		switch strings.ToLower(path.Ext(strings.TrimSpace(name))) {
		case ".pth", ".php", ".rb":
			return true
		}
		return wantsBundledScript(name)
	}
	res := h.SharedArtifactMap()
	if len(res.Files) == 0 {
		return legacyWalkArtifact(h, want)
	}
	return res.Files.SelectLower(want)
}
