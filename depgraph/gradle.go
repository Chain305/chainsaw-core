package depgraph

// Gradle has no native lockfile in the Maven sense; the realistic,
// plugin-free input is the text output of `./gradlew :dependencies` (or
// `gradle :dependencies`). Each configuration block prints a tree using
// box-drawing prefixes:
//
//	compileClasspath - Compile classpath for source set 'main'.
//	+--- com.google.guava:guava:31.1-jre
//	|    +--- com.google.guava:failureaccess:1.0.1
//	|    \--- org.checkerframework:checker-qual:3.12.0
//	\--- org.springframework:spring-core:5.3.20
//	     \--- org.springframework:spring-jcl:5.3.20
//
// Coordinates are GAV (groupId:artifactId:version), Maven-compatible, so
// the parser collapses to the GA pair as Name. Two annotations need
// special handling:
//
//   - "(*)" suffix means the subtree was already shown elsewhere; the
//     node still exists at this position but its children are omitted.
//     We record the node + edge but skip child recursion (which is
//     automatic — the next siblings live at the same or shallower
//     indent).
//   - "-> 1.2.3" means Gradle's resolver chose a different version than
//     the one requested. We treat the resolved version (right of the
//     arrow) as authoritative since that is what actually ships.
//
// Indent depth is recovered from the prefix column count: each tree
// level adds five characters ("|    " for an open ancestor, "     " for
// a closed one) before the "+---" or "\---" marker. We count the marker
// position rather than spaces so tab-vs-space inconsistency in
// hand-edited fixtures still parses.
//
// Wave 6: every configuration block in the input is parsed, not just
// the first. Nodes and edges union across blocks; per-edge config
// attribution is stored on the Graph via AddEdgeConfig so callers can
// distinguish prod (compileClasspath / runtimeClasspath / apiElements)
// from test (testCompileClasspath / testRuntimeClasspath) and other
// configurations downstream. Single-config callers see no behavior
// change — a one-block input still yields the same Graph it always
// did, with one entry in EdgeConfigs per edge.

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// ParseGradleDependencyTree parses the text output of Gradle's
// `:dependencies` task into a Graph. Coordinates are
// groupId:artifactId:version; identity is groupId:artifactId (matching
// the Maven walker so cross-ecosystem joins line up).
//
// Every configuration block in the input is parsed. The same node may
// appear in multiple configs — it is deduped to a single Node, and
// each parent→child edge accumulates the set of configs that include
// it (queryable via Graph.EdgeConfigs). `(*)` duplicate markers are
// honored — the node and its incoming edge are recorded, but children
// are not re-walked. Resolved versions (`-> X.Y.Z`) override the
// requested version.
func ParseGradleDependencyTree(data []byte) (*Graph, error) {
	return parseGradleAllConfigs(data, "")
}

// ParseGradleDependencyTreeForConfig parses only the named
// configuration block from Gradle's `:dependencies` output and returns
// its Graph. Callers that only care about, say, `compileClasspath` or
// `runtimeClasspath` can skip the noise of test-scoped trees this way.
// Returns an error when the requested config is not present in the
// input or when the block has no dependencies.
func ParseGradleDependencyTreeForConfig(data []byte, configName string) (*Graph, error) {
	if strings.TrimSpace(configName) == "" {
		return nil, fmt.Errorf("depgraph/gradle: configName required")
	}
	return parseGradleAllConfigs(data, configName)
}

// parseGradleAllConfigs is the shared entry point. When filter is
// empty, every configuration block contributes; when filter is set,
// only the matching block is parsed and other blocks are skipped.
func parseGradleAllConfigs(data []byte, filter string) (*Graph, error) {
	// First pass: split the input into (configName, blockLines) groups.
	// Doing the split up front keeps the per-block parser pristine — it
	// only deals with tree lines for one configuration at a time.
	blocks, totalLines, err := splitGradleConfigs(data)
	if err != nil {
		return nil, err
	}
	if totalLines == 0 {
		return nil, fmt.Errorf("depgraph/gradle: empty input")
	}

	g := NewGraph()
	rootKey := Key{Ecosystem: "gradle", Name: ":root", Version: "0.0.0"}
	g.AddNode(rootKey, true, true)
	g.AddRoot(rootKey)

	matchedFilter := false
	parsedAny := false
	for _, blk := range blocks {
		if filter != "" && blk.name != filter {
			continue
		}
		if filter != "" {
			matchedFilter = true
		}
		hadDeps, err := parseGradleBlock(g, rootKey, blk.name, blk.lines)
		if err != nil {
			return nil, err
		}
		if hadDeps {
			parsedAny = true
		}
	}
	if filter != "" && !matchedFilter {
		return nil, fmt.Errorf("depgraph/gradle: configuration %q not found in input", filter)
	}
	if !parsedAny {
		return nil, fmt.Errorf("depgraph/gradle: no dependencies found in output")
	}
	return g, nil
}

// gradleBlock is one configuration's header name plus its raw tree
// lines (header line excluded, blank trailing lines trimmed).
type gradleBlock struct {
	name  string
	lines []string
}

// splitGradleConfigs scans the full input and groups lines into
// per-configuration blocks. A new block begins on a line that
// isConfigHeader recognizes; it ends at the next config header, the
// next blank line after at least one tree line, or end-of-input.
// Returns the slice of blocks and the count of non-empty input lines
// (so the caller can distinguish a truly empty input from one whose
// blocks were all empty).
func splitGradleConfigs(data []byte) ([]gradleBlock, int, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		blocks      []gradleBlock
		current     *gradleBlock
		seenTreeRow bool
		linesParsed int
	)
	flush := func() {
		if current != nil {
			blocks = append(blocks, *current)
			current = nil
			seenTreeRow = false
		}
	}
	for scanner.Scan() {
		raw := scanner.Text()
		linesParsed++
		if isConfigHeader(raw) {
			flush()
			name := strings.TrimSpace(raw)
			if i := strings.Index(name, " - "); i >= 0 {
				name = strings.TrimSpace(name[:i])
			}
			current = &gradleBlock{name: name}
			continue
		}
		if current == nil {
			// Pre-amble (Gradle banner, project header, etc.) — ignore.
			continue
		}
		if strings.TrimSpace(raw) == "" {
			// Blank line: closes the active block once we've seen at
			// least one tree row. Leading blanks between header and
			// first tree row are tolerated.
			if seenTreeRow {
				flush()
			}
			continue
		}
		if strings.TrimSpace(raw) == "No dependencies" {
			// Empty config — flush as-is so the caller can decide
			// whether to error or shrug. We choose shrug: a config
			// that legitimately has no deps shouldn't poison parsing
			// of its sibling configs.
			flush()
			continue
		}
		current.lines = append(current.lines, raw)
		seenTreeRow = true
	}
	flush()
	if err := scanner.Err(); err != nil {
		return nil, 0, fmt.Errorf("depgraph/gradle: scan: %w", err)
	}
	return blocks, linesParsed, nil
}

// parseGradleBlock walks one configuration's tree lines and merges
// them into the existing graph. configName, when non-empty, is
// recorded on every parent→child edge created by this block. Returns
// (hadDeps, err) where hadDeps is true iff at least one tree row was
// successfully parsed.
func parseGradleBlock(g *Graph, rootKey Key, configName string, lines []string) (bool, error) {
	// indentStack[i] is the parent Key at depth i. Depth 0 is the
	// project root. A new line at depth d makes indentStack[d-1] its
	// parent and truncates anything deeper. Allocated fresh per block
	// because configurations have independent trees.
	indentStack := []Key{rootKey}
	seenAnyDep := false

	for _, raw := range lines {
		depth, coord, dup, ok := parseGradleLine(raw)
		if !ok {
			return false, fmt.Errorf("depgraph/gradle: malformed line: %q", raw)
		}
		k, err := parseGradleCoord(coord)
		if err != nil {
			return false, fmt.Errorf("depgraph/gradle: %w", err)
		}
		seenAnyDep = true

		if depth < 1 {
			return false, fmt.Errorf("depgraph/gradle: invalid depth %d on line %q", depth, raw)
		}
		if depth > len(indentStack) {
			return false, fmt.Errorf("depgraph/gradle: indentation jump on line %q (depth %d > stack %d)", raw, depth, len(indentStack))
		}
		parent := indentStack[depth-1]

		direct := parent == rootKey
		g.AddNode(k, direct, true)
		g.AddEdge(parent, k)
		if configName != "" {
			g.AddEdgeConfig(parent, k, configName)
		}

		if depth >= len(indentStack) {
			indentStack = append(indentStack[:depth], k)
		} else {
			indentStack[depth] = k
			indentStack = indentStack[:depth+1]
		}
		_ = dup
	}
	return seenAnyDep, nil
}

// isConfigHeader returns true for Gradle's "<config> - <description>"
// banner lines that introduce each tree block. They start at column 0
// (no leading whitespace), have no tree marker, and contain " - ".
func isConfigHeader(line string) bool {
	if line == "" || line[0] == ' ' || line[0] == '\t' {
		return false
	}
	if strings.HasPrefix(line, "+---") || strings.HasPrefix(line, "\\---") {
		return false
	}
	return strings.Contains(line, " - ")
}

// parseGradleLine extracts (depth, coordinate, isDuplicate) from a
// single tree line. depth is 1 for top-level deps, 2 for first-level
// transitive, etc. Returns ok=false for lines without a recognizable
// `+---` or `\---` marker.
func parseGradleLine(line string) (int, string, bool, bool) {
	// Locate the marker. Gradle uses 5-char blocks for each ancestor
	// level: "|    " (open) or "     " (closed). The marker itself is
	// "+---" or "\---" followed by a single space.
	idx := strings.Index(line, "+--- ")
	if idx < 0 {
		idx = strings.Index(line, "\\--- ")
	}
	if idx < 0 {
		return 0, "", false, false
	}
	// Depth is one plus the number of 5-char prefix blocks before the
	// marker. idx==0 → depth 1 (a direct dep).
	if idx%5 != 0 {
		// Tolerate ragged indentation: round down to the nearest
		// 5-char block. Real Gradle output is regular; this guards
		// against hand-edited fixtures.
		idx = (idx / 5) * 5
	}
	depth := idx/5 + 1
	rest := strings.TrimSpace(line[idx+5:])
	if rest == "" {
		return 0, "", false, false
	}
	dup := false
	// Strip trailing annotations: "(*)", "(c)" (constraint), "(n)"
	// (not resolved). They are informational; we only care about (*)
	// to suppress phantom child edges, and the caller already handles
	// that by not seeing children at deeper indent.
	for _, suffix := range []string{" (*)", " (c)", " (n)"} {
		if strings.HasSuffix(rest, suffix) {
			if suffix == " (*)" {
				dup = true
			}
			rest = strings.TrimSuffix(rest, suffix)
			rest = strings.TrimSpace(rest)
		}
	}
	return depth, rest, dup, true
}

// parseGradleCoord normalizes "group:artifact:version" or
// "group:artifact:requested -> resolved" into a Key. The resolved
// version (right of "->") wins when present.
func parseGradleCoord(coord string) (Key, error) {
	coord = strings.TrimSpace(coord)
	if coord == "" {
		return Key{}, fmt.Errorf("invalid Gradle coordinate (empty)")
	}
	// Handle the version-resolution arrow. Gradle's format is
	// "<lhs> -> <resolved>". The lhs may be the full GAV or just a
	// version (when only the version was overridden in a constraint).
	var resolved string
	if i := strings.Index(coord, " -> "); i >= 0 {
		resolved = strings.TrimSpace(coord[i+4:])
		coord = strings.TrimSpace(coord[:i])
	}
	parts := strings.Split(coord, ":")
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			return Key{}, fmt.Errorf("invalid Gradle coordinate %q (empty segment)", coord)
		}
	}
	var group, artifact, version string
	switch len(parts) {
	case 3:
		group, artifact, version = parts[0], parts[1], parts[2]
	case 2:
		// A bare "group:artifact" with the version coming from "->"
		// (constraint-only declaration). Require resolved to be set.
		if resolved == "" {
			return Key{}, fmt.Errorf("invalid Gradle coordinate %q (no version and no resolution)", coord)
		}
		group, artifact = parts[0], parts[1]
	default:
		return Key{}, fmt.Errorf("invalid Gradle coordinate %q (need group:artifact:version)", coord)
	}
	if resolved != "" {
		// `resolved` may itself be a full GAV (rare) or just a bare
		// version. Detect by colon count.
		if strings.Contains(resolved, ":") {
			rparts := strings.Split(resolved, ":")
			if len(rparts) != 3 {
				return Key{}, fmt.Errorf("invalid Gradle resolved coordinate %q", resolved)
			}
			group, artifact, version = rparts[0], rparts[1], rparts[2]
		} else {
			version = resolved
		}
	}
	if version == "" {
		return Key{}, fmt.Errorf("invalid Gradle coordinate %q (no version)", coord)
	}
	return Key{
		Ecosystem: "gradle",
		Name:      group + ":" + artifact,
		Version:   version,
	}, nil
}
