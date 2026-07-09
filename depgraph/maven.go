package depgraph

// Maven: classifier and scope are now preserved (Wave 7 follow-up to the Wave 3 limitation).
//
// Maven has no native lockfile. The realistic, plugin-free input is the
// output of `mvn dependency:tree -DoutputType=tgf`, which renders the
// resolved tree in Trivial Graph Format: a node section (one
// "<id> <coordinate>" per line), a "#" separator, and an edge section
// (one "<from> <to>" per line). The first node (id 1) is the project
// root. Coordinates take one of these shapes:
//
//	groupId:artifactId:version
//	groupId:artifactId:packaging:version
//	groupId:artifactId:packaging:version:scope
//	groupId:artifactId:packaging:classifier:version
//	groupId:artifactId:packaging:classifier:version:scope
//
// We collapse to the GA pair as Name and the version field as Version.
// Classifier (when present) is recorded on the Node.Classifier field;
// scope (or "compile" by default when absent) is recorded as an
// edge-level "scope" attribute via Graph.AddEdgeAttr — the same edge
// metadata machinery introduced for Gradle configs. BOMs (`pom`
// packaging entries that only contribute `<dependencyManagement>`) are
// not represented in dependency:tree output at all, so this parser
// inherits that behavior.

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// ParseMavenDepTree parses Maven dependency:tree TGF output into a Graph.
// Coordinates are groupId:artifactId:version. The root node (the first
// "1 ..." entry) becomes Graph.Roots; the # block defines edges.
//
// Classifier (when present in the coordinate) is preserved on
// Node.Classifier. Scope is preserved as an edge attribute under the
// "scope" key (queryable via Graph.EdgeAttr); when the coordinate
// omits a scope segment we default to "compile" — that matches Maven's
// implicit-scope semantics for direct deps and is what dependency:tree
// emits when run without `-Dscope=*`.
//
// Residual limitation: identity is still (groupId:artifactId, version),
// so two coordinates that differ only by classifier collapse to the
// same Key — but the Classifier on the surviving Node now reflects
// whichever variant was inserted first. Eliminating the collapse fully
// would require extending Key, which would break the cross-cutting
// risk-engine joins this parser feeds.
func ParseMavenDepTree(data []byte) (*Graph, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	type rawNode struct {
		id         string
		key        Key
		classifier string
		scope      string
	}
	var (
		nodes      []rawNode
		idToKey    = map[string]Key{}
		idToScope  = map[string]string{}
		inEdges    bool
		seenAnyTok bool
	)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "#" {
			inEdges = true
			continue
		}
		seenAnyTok = true
		if !inEdges {
			id, coord, ok := splitTGFNode(line)
			if !ok {
				return nil, fmt.Errorf("depgraph/maven: malformed node line: %q", line)
			}
			k, classifier, scope, err := parseMavenCoordFull(coord)
			if err != nil {
				return nil, fmt.Errorf("depgraph/maven: %w", err)
			}
			if _, dup := idToKey[id]; dup {
				return nil, fmt.Errorf("depgraph/maven: duplicate node id %q", id)
			}
			idToKey[id] = k
			idToScope[id] = scope
			nodes = append(nodes, rawNode{id: id, key: k, classifier: classifier, scope: scope})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("depgraph/maven: scan: %w", err)
	}
	if !seenAnyTok {
		return nil, fmt.Errorf("depgraph/maven: empty TGF input")
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("depgraph/maven: no nodes in TGF input")
	}

	g := NewGraph()
	rootKey := nodes[0].key
	g.AddNode(rootKey, true, true)
	g.AddRoot(rootKey)
	if c := nodes[0].classifier; c != "" {
		g.Nodes[rootKey].Classifier = c
	}
	for _, n := range nodes[1:] {
		// Direct flag is promoted in the edge pass when the project
		// root is the parent. Prod=true because dependency:tree by
		// default emits resolved compile/runtime scope; test/provided
		// only appear when explicitly asked for, and we have no
		// reliable way to distinguish them in TGF.
		g.AddNode(n.key, false, true)
		if n.classifier != "" {
			// First classifier wins — see the residual-limitation
			// comment on ParseMavenDepTree.
			node := g.Nodes[n.key]
			if node.Classifier == "" {
				node.Classifier = n.classifier
			}
		}
	}

	// Re-scan edge section. We could have stored edges on the first
	// pass but a second pass keeps the node/edge phases readable.
	scanner = bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	inEdges = false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "#" {
			inEdges = true
			continue
		}
		if !inEdges {
			continue
		}
		fromID, toID, ok := splitTGFEdge(line)
		if !ok {
			return nil, fmt.Errorf("depgraph/maven: malformed edge line: %q", line)
		}
		from, ok := idToKey[fromID]
		if !ok {
			return nil, fmt.Errorf("depgraph/maven: edge references unknown node id %q", fromID)
		}
		to, ok := idToKey[toID]
		if !ok {
			return nil, fmt.Errorf("depgraph/maven: edge references unknown node id %q", toID)
		}
		if from == rootKey {
			g.AddNode(to, true, true)
		}
		g.AddEdge(from, to)
		// Scope lives on the child coordinate in TGF — Maven's
		// dependency:tree emits "<gav>:<scope>" on every dependency
		// line. We record it on the inbound edge so a node reachable
		// via multiple parents can carry per-edge scope (e.g. a util
		// pulled in compile-scope by lib-A and test-scope by lib-B).
		scope := idToScope[toID]
		if scope == "" {
			scope = "compile"
		}
		g.AddEdgeAttr(from, to, "scope", scope)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("depgraph/maven: scan edges: %w", err)
	}
	return g, nil
}

// splitTGFNode splits "<id> <coordinate>" tolerating tabs and
// multi-space separators. Returns false if the line lacks a separator
// or has a non-numeric id (TGF requires integer ids).
func splitTGFNode(line string) (string, string, bool) {
	idx := strings.IndexAny(line, " \t")
	if idx <= 0 {
		return "", "", false
	}
	id := strings.TrimSpace(line[:idx])
	rest := strings.TrimSpace(line[idx+1:])
	if id == "" || rest == "" {
		return "", "", false
	}
	if _, err := strconv.Atoi(id); err != nil {
		return "", "", false
	}
	return id, rest, true
}

// splitTGFEdge splits "<from> <to>" — both must parse as ints.
func splitTGFEdge(line string) (string, string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", "", false
	}
	if _, err := strconv.Atoi(fields[0]); err != nil {
		return "", "", false
	}
	if _, err := strconv.Atoi(fields[1]); err != nil {
		return "", "", false
	}
	return fields[0], fields[1], true
}

// parseMavenCoord normalises a Maven GAV(TC?S?) coordinate to a Key.
// Thin wrapper around parseMavenCoordFull for callers that only want
// the (name, version) projection.
func parseMavenCoord(coord string) (Key, error) {
	k, _, _, err := parseMavenCoordFull(coord)
	return k, err
}

// parseMavenCoordFull parses a Maven coordinate, returning the Key plus
// the classifier and scope segments (each possibly empty). Recognised
// shapes:
//
//	g:a:v
//	g:a:p:v
//	g:a:p:v:s
//	g:a:p:c:v
//	g:a:p:c:v:s
//
// Heuristic for 4 and 5 segment forms: the version slot is the segment
// that looks like a version (contains a digit or starts with a digit).
// Maven packaging values are an open set (jar, war, pom, bundle,
// maven-plugin, aar, …) so we don't whitelist them — instead we anchor
// on the version's shape.
func parseMavenCoordFull(coord string) (Key, string, string, error) {
	parts := strings.Split(strings.TrimSpace(coord), ":")
	if len(parts) < 3 {
		return Key{}, "", "", fmt.Errorf("invalid Maven coordinate %q (need at least groupId:artifactId:version)", coord)
	}
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			return Key{}, "", "", fmt.Errorf("invalid Maven coordinate %q (empty segment)", coord)
		}
	}
	group := parts[0]
	artifact := parts[1]
	var version, classifier, scope string
	switch len(parts) {
	case 3:
		version = parts[2]
	case 4:
		// g:a:packaging:v
		version = parts[3]
	case 5:
		// Either g:a:p:v:scope or g:a:p:classifier:v.
		if looksLikeVersion(parts[3]) && !looksLikeVersion(parts[4]) {
			version = parts[3]
			scope = parts[4]
		} else {
			classifier = parts[3]
			version = parts[4]
		}
	case 6:
		// g:a:p:classifier:v:scope
		classifier = parts[3]
		version = parts[4]
		scope = parts[5]
	default:
		return Key{}, "", "", fmt.Errorf("invalid Maven coordinate %q (too many segments)", coord)
	}
	if version == "" {
		return Key{}, "", "", fmt.Errorf("invalid Maven coordinate %q (no version)", coord)
	}
	return Key{
		Ecosystem: "maven",
		Name:      group + ":" + artifact,
		Version:   version,
	}, classifier, scope, nil
}

// looksLikeVersion is the cheap heuristic used to disambiguate
// classifier vs version in 5-segment coordinates. Maven versions
// virtually always contain a digit (1.0, 1.0-SNAPSHOT, 4.1.86.Final);
// classifiers like "linux-x86_64", "sources", "javadoc", "tests" don't
// start with a digit, though "linux-x86_64" contains digits in the
// middle. The heuristic checks for a leading digit, which is the
// reliable Maven version signal.
func looksLikeVersion(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	return c >= '0' && c <= '9'
}
