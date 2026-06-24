// Package githubactions parses GitHub Actions workflow YAML files into a
// structured list of action references (the values of `uses:` directives).
//
// This package is a pure parsing library. It performs no network I/O, no
// version resolution, and no integration with other Chainsaw subsystems.
// Other packages consume []ActionRef as input.
package githubactions

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ActionRef is a single `uses:` reference extracted from a workflow file.
type ActionRef struct {
	// Raw is the full uses: string as it appears in the workflow.
	Raw string

	// Owner is the GitHub org/user. For "actions/checkout@v4" -> "actions".
	// For "./.github/actions/local-action" or "docker://image" -> "" with
	// Kind set accordingly.
	Owner string

	// Name is the action name (the part after the slash). For
	// "actions/checkout@v4" -> "checkout". For
	// "aws-actions/configure-aws-credentials@v1" -> "configure-aws-credentials".
	// For composite paths like "actions/aws-actions/configure-aws-credentials@v1"
	// the trailing path beyond the owner is preserved
	// ("aws-actions/configure-aws-credentials").
	Name string

	// Version is whatever appears after the @ — could be a tag (v4), a
	// branch (main), a commit SHA (40 hex), or empty if unpinned.
	Version string

	// SHA is set ONLY when Version is a 40-character lowercase hex string
	// (a commit SHA pin). Otherwise empty.
	SHA string

	// Kind is "remote" for normal owner/name@ref form, "local" for
	// ./path-relative refs (./.github/actions/...), "docker" for
	// docker://image refs, "unknown" for malformed entries that still
	// parsed enough to record.
	Kind string

	// SourceFile is the workflow file the ref came from.
	SourceFile string
	// SourceLine is the 1-indexed line number of the uses: directive.
	SourceLine int
}

const (
	KindRemote  = "remote"
	KindLocal   = "local"
	KindDocker  = "docker"
	KindUnknown = "unknown"
)

var shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// ParseUsesString parses a single uses: value into an ActionRef. It does not
// populate SourceFile / SourceLine — callers do that.
func ParseUsesString(raw string) ActionRef {
	ref := ActionRef{Raw: raw}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		ref.Kind = KindUnknown
		return ref
	}

	// docker:// scheme
	if strings.HasPrefix(trimmed, "docker://") {
		ref.Kind = KindDocker
		ref.Name = strings.TrimPrefix(trimmed, "docker://")
		// docker://image:tag — treat the tag as Version when present.
		if i := strings.LastIndex(ref.Name, ":"); i > 0 {
			ref.Version = ref.Name[i+1:]
			ref.Name = ref.Name[:i]
		}
		return ref
	}

	// Local action: starts with ./ or ../
	if strings.HasPrefix(trimmed, "./") || strings.HasPrefix(trimmed, "../") {
		ref.Kind = KindLocal
		ref.Name = trimmed
		return ref
	}

	// Remote: owner/name[/sub/path][@ref]
	body, version, hasAt := strings.Cut(trimmed, "@")
	if hasAt {
		ref.Version = version
		if shaRe.MatchString(version) {
			ref.SHA = version
		}
	}
	owner, rest, hasSlash := strings.Cut(body, "/")
	if !hasSlash || owner == "" || rest == "" {
		ref.Kind = KindUnknown
		ref.Owner = owner
		ref.Name = rest
		return ref
	}
	ref.Kind = KindRemote
	ref.Owner = owner
	ref.Name = rest
	return ref
}

// ParseWorkflowFile parses one workflow YAML and returns every uses:
// reference inside it. Returns an error only for unrecoverable parse
// failures; an empty list is a valid result.
func ParseWorkflowFile(path string, data []byte) ([]ActionRef, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse workflow %s: %w", path, err)
	}

	var refs []ActionRef
	walkForUses(&root, func(value string, line int) {
		ref := ParseUsesString(value)
		ref.SourceFile = path
		ref.SourceLine = line
		refs = append(refs, ref)
	})
	return refs, nil
}

// walkForUses traverses a yaml.Node tree and invokes fn for every mapping
// entry whose key is the literal string "uses" and whose value is a scalar.
// This catches uses: at job level (reusable workflow), step level, and
// composite-action runs.steps[].uses without needing to model the entire
// workflow schema.
func walkForUses(n *yaml.Node, fn func(value string, line int)) {
	if n == nil {
		return
	}
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			walkForUses(c, fn)
		}
	case yaml.MappingNode:
		// Mapping content is alternating key/value pairs.
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			v := n.Content[i+1]
			if k.Kind == yaml.ScalarNode && k.Value == "uses" && v.Kind == yaml.ScalarNode {
				fn(v.Value, k.Line)
			}
			walkForUses(v, fn)
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			walkForUses(c, fn)
		}
	}
}

// ParseWorkflowDir walks .github/workflows/ in the given directory and
// returns every ActionRef from every *.yml / *.yaml file found. The dir
// argument is the repository root (the directory containing .github), or
// the .github/workflows directory itself — both are accepted.
func ParseWorkflowDir(dir string) ([]ActionRef, error) {
	workflowsDir := dir
	// Accept either the repo root or the workflows dir directly.
	if base := filepath.Base(dir); base != "workflows" {
		candidate := filepath.Join(dir, ".github", "workflows")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			workflowsDir = candidate
		}
	}

	info, err := os.Stat(workflowsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat %s: %w", workflowsDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", workflowsDir)
	}

	entries, err := os.ReadDir(workflowsDir)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", workflowsDir, err)
	}

	// Stable order: sort filenames so callers get deterministic output.
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)

	var all []ActionRef
	for _, name := range files {
		full := filepath.Join(workflowsDir, name)
		data, err := os.ReadFile(full)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", full, err)
		}
		refs, err := ParseWorkflowFile(full, data)
		if err != nil {
			return nil, err
		}
		all = append(all, refs...)
	}
	return all, nil
}
