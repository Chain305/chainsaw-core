// Graph-aware analyzer extensions. The base Analyzer interface is
// unchanged — this file introduces an OPTIONAL interface
// (GraphAnalyzer) that ecosystem parsers can satisfy via type-assertion
// at the call site. Ecosystems that can't expose parent/child edges
// (most of them) simply don't implement it and the caller gracefully
// skips graph emission for those files.
//
// Why optional? Lockfile formats that don't encode edges (go.sum,
// Gemfile.lock for older bundler, Cargo.lock sections, etc.) would
// have to fabricate a graph — we'd rather return nothing and keep the
// scan fast than ship fake structure the risk engine treats as real.
package analyzer

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	ftypes "github.com/chain305/chainsaw-core/fanal"

	"github.com/chain305/chainsaw-core/depgraph"
)

// graphRegistry holds the GraphAnalyzer instances. Separate from the
// main registered slice so WalkDir's flat-dispatch behaviour is
// unaffected — a GraphAnalyzer that also happens to be Registered as a
// regular Analyzer would otherwise emit flat packages twice.
var (
	graphMu         sync.RWMutex
	graphRegistered []GraphAnalyzer
)

// RegisterGraph adds a GraphAnalyzer to the graph-only registry.
// Called from init() alongside (but independent of) Register.
func RegisterGraph(g GraphAnalyzer) {
	graphMu.Lock()
	defer graphMu.Unlock()
	graphRegistered = append(graphRegistered, g)
}

// AllGraph returns a snapshot of the registered GraphAnalyzers.
func AllGraph() []GraphAnalyzer {
	graphMu.RLock()
	defer graphMu.RUnlock()
	out := make([]GraphAnalyzer, len(graphRegistered))
	copy(out, graphRegistered)
	return out
}

// GraphAnalyzer is implemented by analyzers that can emit a full
// dependency graph (parent/child edges, not just a flat package list)
// from a lockfile. Only npm and pnpm qualify today. EmitGraph returns
// nil for files the analyzer doesn't recognize; a non-nil error should
// be treated the same as a Parse error — one bad file doesn't abort
// the walk.
type GraphAnalyzer interface {
	Analyzer
	EmitGraph(path string, content []byte) (*depgraph.Graph, error)
}

// WalkDirGraph walks root like WalkDir but dispatches ALSO to any
// registered analyzer that satisfies GraphAnalyzer. It returns the set
// of graphs produced (one per lockfile that emitted a graph) plus a
// list of errors encountered along the way — errors are accumulated,
// not fatal, to mirror WalkDir's behaviour.
//
// Ecosystems without a GraphAnalyzer implementation contribute nothing
// to the returned slice; callers wanting the flat package list from
// those files should call WalkDir as well.
func WalkDirGraph(ctx context.Context, root string) ([]*depgraph.Graph, []error) {
	analyzers := AllGraph()
	var (
		graphs []*depgraph.Graph
		errs   []error
	)
	if len(analyzers) == 0 {
		return graphs, errs
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, walkErr))
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if _, skip := skipDirs[d.Name()]; skip && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		for _, ga := range analyzers {
			if !ga.Required(path) {
				continue
			}
			content, rerr := os.ReadFile(path)
			if rerr != nil {
				errs = append(errs, fmt.Errorf("%s: read: %w", path, rerr))
				continue
			}
			g, gerr := ga.EmitGraph(path, content)
			if gerr != nil {
				errs = append(errs, fmt.Errorf("%s: graph: %w", path, gerr))
				continue
			}
			if g != nil && len(g.Nodes) > 0 {
				graphs = append(graphs, g)
			}
		}
		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}
	return graphs, errs
}

// graphShim is a thin struct that satisfies the GraphAnalyzer interface
// without participating in the flat-scan Analyzer registry. Its Parse
// method is never called by the graph walker — Parse exists only so
// graphShim satisfies the embedded Analyzer interface. Keep flat scans
// routing through shims.go's Register path; graph scans route through
// RegisterGraph and WalkDirGraph here.
type graphShim struct {
	langType ftypes.LangType
	match    func(string) bool
	emit     func(path string, content []byte) (*depgraph.Graph, error)
}

func (g graphShim) Type() ftypes.LangType     { return g.langType }
func (g graphShim) Required(path string) bool { return g.match(path) }
func (g graphShim) Parse(context.Context, string) ([]Package, error) {
	// Graph shims never emit flat packages — the regular shim handles
	// that and is registered separately. Returning an empty slice is
	// safe because WalkDirGraph never calls Parse.
	return nil, nil
}
func (g graphShim) EmitGraph(path string, content []byte) (*depgraph.Graph, error) {
	return g.emit(path, content)
}

func init() {
	RegisterGraph(graphShim{
		langType: ftypes.Npm,
		match:    exact("package-lock.json"),
		emit: func(_ string, c []byte) (*depgraph.Graph, error) {
			return depgraph.ParseNPMLockfile(c)
		},
	})
	RegisterGraph(graphShim{
		langType: ftypes.Pnpm,
		match:    exact("pnpm-lock.yaml"),
		emit: func(_ string, c []byte) (*depgraph.Graph, error) {
			return depgraph.ParsePnpmLockfile(c)
		},
	})
}
