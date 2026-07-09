package intelligence

import (
	"context"

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

// Supports: every ecosystem — an exfil webhook or stealer string is malicious
// in any package's source.
func (p *iocscanProvider) Supports(string) bool { return true }

func (p *iocscanProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if req.Artifact == nil || len(req.Artifact.Bytes) == 0 {
		return PartialReport{}, nil
	}
	src := sourceFilesFor(req.Artifact)
	if len(src) == 0 {
		return PartialReport{}, nil
	}
	res := iocscan.Scan(src)
	if !res.Detected {
		return PartialReport{}, nil
	}
	return PartialReport{Scan: &ArtifactScanSection{
		Performed:          true,
		MaliciousIOC:       true,
		MaliciousIOCKind:   res.Kind,
		MaliciousIOCDetail: res.Detail,
	}}, nil
}
