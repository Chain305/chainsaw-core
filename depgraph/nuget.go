package depgraph

// NuGet: every top-level target framework is now parsed (Wave 7 follow-up
// to the Wave 1 first-framework-only limitation).
//
// NuGet's lockfile is `packages.lock.json`, opt-in via
// <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>. The
// top-level `dependencies` map is keyed by target framework
// (`net6.0`, `net8.0`, `net6.0/win-x64`, …) and a single project may
// resolve under several frameworks at once. We parse every framework
// and union the result into one Graph: nodes dedupe on (name, version),
// and each parent→child edge accumulates a "frameworks" attribute
// listing every framework that includes it (queryable via
// Graph.EdgeAttr). Single-framework lockfiles produce the same Graph
// they always did, with one entry in the frameworks list per edge.
//
// Per-package shape: `type` is one of Direct, Transitive, Project, or
// CentralTransitive. Direct entries become Roots; Transitive and
// CentralTransitive are graph nodes only; Project entries (sibling
// project references inside a solution) are skipped — they aren't
// NuGet packages and have no version on the wire we'd want to score.
//
// Identity is the package name (the map key); version is the `resolved`
// field. A missing `resolved` is rejected — the requirement string
// alone (e.g. "[13.0.1, )") is a constraint, not a pinned version, and
// the risk engine is keyed on resolved versions.

import (
	"encoding/json"
	"fmt"
	"sort"
)

type nugetLockfile struct {
	Version      int                                  `json:"version"`
	Dependencies map[string]map[string]nugetLockEntry `json:"dependencies"`
}

type nugetLockEntry struct {
	Type         string            `json:"type"`
	Requested    string            `json:"requested,omitempty"`
	Resolved     string            `json:"resolved,omitempty"`
	ContentHash  string            `json:"contentHash,omitempty"`
	Dependencies map[string]string `json:"dependencies,omitempty"`
}

// ParseNuGetLockfile parses a packages.lock.json into a Graph. Direct
// entries become Roots; Transitive and CentralTransitive entries become
// graph nodes; Project entries are skipped. Every top-level target
// framework is merged into the same Graph, deduped on (name, version);
// per-edge framework attribution is stored under the "frameworks"
// edge attribute (queryable via Graph.EdgeAttr).
//
// Limitations: requirement strings on edges (e.g. "[4.5.1, )") are
// dropped — only the resolved version is kept, since that's what gets
// installed and what the risk engine scores.
func ParseNuGetLockfile(data []byte) (*Graph, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("depgraph/nuget: empty input")
	}
	var lf nugetLockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("depgraph/nuget: parse: %w", err)
	}
	if len(lf.Dependencies) == 0 {
		return nil, fmt.Errorf("depgraph/nuget: no target frameworks in lockfile")
	}

	// Stable framework iteration: sort keys so output is deterministic.
	frameworks := make([]string, 0, len(lf.Dependencies))
	for fw := range lf.Dependencies {
		frameworks = append(frameworks, fw)
	}
	sort.Strings(frameworks)

	g := NewGraph()

	for _, fw := range frameworks {
		pkgs := lf.Dependencies[fw]

		// First pass: register every node (excluding Project type) for
		// this framework. AddNode is idempotent and promotes Direct/Prod
		// monotonically, so a package marked Direct under one framework
		// and Transitive under another lands as Direct.
		for name, entry := range pkgs {
			if entry.Type == "Project" {
				continue
			}
			if entry.Resolved == "" {
				return nil, fmt.Errorf("depgraph/nuget: package %q missing resolved version (framework %q)", name, fw)
			}
			k := Key{Ecosystem: "nuget", Name: name, Version: entry.Resolved}
			g.AddNode(k, entry.Type == "Direct", true)
		}

		// Second pass: roots and edges, sorted-name iteration for
		// deterministic root ordering. Roots are deduped by AddRoot.
		names := make([]string, 0, len(pkgs))
		for name := range pkgs {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			entry := pkgs[name]
			if entry.Type == "Project" {
				continue
			}
			parent := Key{Ecosystem: "nuget", Name: name, Version: entry.Resolved}
			if entry.Type == "Direct" {
				g.AddRoot(parent)
			}
			childNames := make([]string, 0, len(entry.Dependencies))
			for cn := range entry.Dependencies {
				childNames = append(childNames, cn)
			}
			sort.Strings(childNames)
			for _, cn := range childNames {
				childEntry, ok := pkgs[cn]
				if !ok {
					continue
				}
				if childEntry.Type == "Project" {
					continue
				}
				if childEntry.Resolved == "" {
					continue
				}
				child := Key{Ecosystem: "nuget", Name: cn, Version: childEntry.Resolved}
				g.AddEdge(parent, child)
				g.AddEdgeAttr(parent, child, "frameworks", fw)
			}
		}
	}

	if len(g.Nodes) == 0 {
		return nil, fmt.Errorf("depgraph/nuget: no packages parsed (all entries were Project type?)")
	}
	return g, nil
}
