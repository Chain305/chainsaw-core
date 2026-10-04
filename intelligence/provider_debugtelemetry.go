package intelligence

import (
	"context"

	"github.com/chain305/chainsaw-core/codesmell"
	"github.com/chain305/chainsaw-core/intelligence/artifactmap"
)

// debugTelemetryProvider runs the debug-module and telemetry scanners
// (core/codesmell/debug_telemetry.go) over a package's source files. Both
// facts are observations for socket.dev's debugAccess and telemetry alerts;
// the signals they feed are weight 0.
type debugTelemetryProvider struct{}

func newDebugTelemetryProvider() *debugTelemetryProvider { return &debugTelemetryProvider{} }

func (p *debugTelemetryProvider) Name() string         { return "debugtelemetry" }
func (p *debugTelemetryProvider) Signal() SignalMask   { return SignalDebugTelemetry }
func (p *debugTelemetryProvider) Tier() int            { return 2 }
func (p *debugTelemetryProvider) NeedsArtifact() bool  { return true }
func (p *debugTelemetryProvider) Supports(string) bool { return true }

// debugTelemetryAnalyzerVersion — bump when either pattern set changes what
// this reports for identical bytes.
//
// 2: codesmell walks files in path order with a source-only 500-file budget,
// and no longer drops a Go module whose PATH has a test/example segment.
// 3: also reports DynamicRequire (cap.dynamic_require).
//
// 4: codesmell redacts a URL's userinfo from every sample before it is stored.
const debugTelemetryAnalyzerVersion = 4

func (p *debugTelemetryProvider) AnalyzerVersion() int { return debugTelemetryAnalyzerVersion }

// debugTelemetryMaxSamples matches capability.MaxEvidencePerCap.
const debugTelemetryMaxSamples = 3

func (p *debugTelemetryProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if req.Artifact == nil || len(req.Artifact.Bytes) == 0 {
		return PartialReport{}, nil
	}
	res := req.Artifact.SharedArtifactMap()
	if len(res.Files) == 0 {
		return PartialReport{}, nil
	}
	// Test, vendored and generated paths are dropped, as for the other
	// noise-prone code-smell scanners.
	files := codesmell.FilterTestVendorGenerated(res.Files.Select(artifactmap.WantsSourceCode))
	if len(files) == 0 {
		return PartialReport{}, nil
	}
	debug, tel, dyn := codesmell.ScanDebugAccess(files), codesmell.ScanTelemetry(files), codesmell.ScanDynamicRequire(files)
	return PartialReport{Scan: &ArtifactScanSection{
		Performed:          true,
		DebugAccess:        debug.Fired,
		DebugAccessSamples: scanSamples(debug),
		Telemetry:          tel.Fired,
		TelemetrySamples:   scanSamples(tel),

		DynamicRequire:        dyn.Fired,
		DynamicRequireSamples: scanSamples(dyn),
	}}, nil
}

func scanSamples(r codesmell.Result) []ScanLocation {
	var out []ScanLocation
	for _, m := range r.Matches {
		if len(out) == debugTelemetryMaxSamples {
			break
		}
		out = append(out, ScanLocation{File: m.Path, Line: m.Line, Snippet: m.Snippet})
	}
	return out
}

var _ Provider = (*debugTelemetryProvider)(nil)
