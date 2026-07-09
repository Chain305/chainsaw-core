package sbom

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/depgraph"
)

// CycloneDXBOM represents a CycloneDX 1.6 BOM document.
type CycloneDXBOM struct {
	BOMFormat    string               `json:"bomFormat"`
	SpecVersion  string               `json:"specVersion"`
	Version      int                  `json:"version"`
	SerialNumber string               `json:"serialNumber,omitempty"`
	Metadata     CycloneDXMetadata    `json:"metadata"`
	Components   []CycloneDXComponent `json:"components"`
	// Dependencies populates the CycloneDX `dependencies[]` graph when
	// Generate is called with a non-nil *depgraph.Graph. Always emitted
	// (as `[]` when no graph is supplied) per CycloneDX 1.6 §5.3 — see
	// finding F17. Consumers that key off "is dependencies[] absent?"
	// must instead test "len(dependencies) == 0", which is the spec's
	// canonical "no relationships declared" form.
	Dependencies []CycloneDXDependency `json:"dependencies"`
}

// CycloneDXDependency models one entry of the CycloneDX 1.6
// `dependencies` array — a `ref` (the parent component's bom-ref) plus
// the `dependsOn` list of refs it points at. We use `ref` == purl so the
// component table and the dependency table key off the same identifier
// without an extra bom-ref translation layer.
type CycloneDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// CycloneDXMetadata contains BOM metadata.
type CycloneDXMetadata struct {
	Timestamp string          `json:"timestamp"`
	Tools     []CycloneDXTool `json:"tools,omitempty"`
}

// CycloneDXTool describes a tool used to generate the BOM.
type CycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CycloneDXComponent represents a single component in the BOM.
type CycloneDXComponent struct {
	Type       string              `json:"type"`
	Name       string              `json:"name"`
	Version    string              `json:"version"`
	PURL       string              `json:"purl,omitempty"`
	Hashes     []CycloneDXHash     `json:"hashes,omitempty"`
	Licenses   []CycloneDXLicense  `json:"licenses,omitempty"`
	Properties []CycloneDXProperty `json:"properties,omitempty"`
}

// CycloneDXHash represents a component hash.
type CycloneDXHash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

// CycloneDXLicense represents a license entry.
type CycloneDXLicense struct {
	License CycloneDXLicenseID `json:"license"`
}

// CycloneDXLicenseID holds a license identifier.
type CycloneDXLicenseID struct {
	ID string `json:"id,omitempty"`
}

// CycloneDXProperty represents a custom property.
type CycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// PackageEntry captures all the metadata needed to include a package in an SBOM.
type PackageEntry struct {
	Ecosystem        string
	Repository       string
	Name             string
	Version          string
	SHA256           string
	LicenseSPDX      string
	ProvenanceStatus string
	TrustScore       int
	IsVulnerable     bool
	CVEs             []string

	// Supply-chain signals added by the 13-PR consolidation. Every
	// non-zero value is emitted as a CycloneDX `properties` entry so
	// downstream SBOM consumers (Dependency-Track, Grype, etc.) can
	// parse them without chainsaw-specific code. Naming convention:
	// "chainsaw:<category>:<field>".
	InstallScriptKind   string
	PublisherSet        []string
	PublisherChanged    bool
	VersionAnomalyFlags []string
	HiddenUnicodeHits   int
	PublishVelocity24h  int
	RepoLinkStatus      string
	ChecksumDeclared    string
	ChecksumActual      string
	MalwareStatus       string
	TyposquatStatus     string

	// Attributions carries optional per-component "pulled by"
	// metadata derived read-only from existing audit/install records.
	// Empty (the default) keeps the SBOM byte-identical to releases
	// that predate the attribution feature — Generate emits no
	// chainsaw:attribution:* properties when the slice is empty. See
	// internal/events/attribution.go for how callers populate this.
	Attributions []AttributionEntry

	// SupplyChain link-back identifiers. Each non-empty value is emitted
	// as a chainsaw:supply-chain:* property so downstream SBOM consumers
	// can join one component back to a row in the `events` table or to
	// the snapshot it was captured in. These are part of the Pain 7
	// "operationalized SBOM" contract — the SBOM stops being a
	// standalone compliance file and becomes a join key against the
	// proxy's audit timeline.
	EventID    string
	ClientID   string
	SnapshotID string
}

// AttributionEntry is the SBOM-side projection of one distinct
// (client, repo, group) tuple that pulled the parent component during
// the configured attribution window. Times are RFC3339-formatted in
// the emitted CycloneDX property values.
type AttributionEntry struct {
	ClientID   string
	Repository string
	Group      string
	FirstSeen  time.Time
	LastSeen   time.Time
}

// Generate creates a CycloneDX 1.6 BOM from a list of package entries.
//
// Back-compat shim: existing callers expect the flat-component form (no
// dependencies[] wired). Forwarding to GenerateWithGraph(entries,
// serialNumber, nil) preserves byte-equal output for those callers
// while letting Pain 7's snapshot path wire transitive edges through.
func Generate(entries []PackageEntry, serialNumber string) *CycloneDXBOM {
	return GenerateWithGraph(entries, serialNumber, nil)
}

// GenerateWithGraph is the edge-aware constructor. When graph is non-nil
// the resulting BOM populates CycloneDX `dependencies[]` with the DIRECT
// children of each component — exactly the contract CycloneDX 1.6
// section 7.6 ("Dependencies") specifies: "An entry in dependsOn MUST
// directly depend on the parent". Transitive closure is reconstructed
// by walking the graph (the same way Dependency-Track, Snyk, Grype, and
// in-toto verifiers do); emitting it here would double-count edges and
// break those consumers' graph-walk logic.
//
// Spec violation history: an earlier revision used graph.Descendants
// (full transitive closure), which generated valid JSON but broke the
// semantic contract. Fixed in the polish pass that introduced this
// comment — the affected-by MCP tool's transitive_path[] is the
// dedicated surface for transitive reconstruction (the right place for
// "show me the path from a vulnerable parent to a leaf"), so SBOM stays
// spec-conformant while operational queries still get the closure.
//
// graph is consulted by (Ecosystem, Name, Version) — entries whose
// triple is not present in the graph contribute no dependency row and
// the rest of the BOM still renders correctly. That tolerance is
// deliberate: the depgraph parsers are best-effort across 8 ecosystems,
// and a missing edge should degrade to "no transitive info for this
// component", never to a panic or empty BOM.
func GenerateWithGraph(entries []PackageEntry, serialNumber string, graph *depgraph.Graph) *CycloneDXBOM {
	components := make([]CycloneDXComponent, 0, len(entries))

	for _, e := range entries {
		comp := CycloneDXComponent{
			Type:    "library",
			Name:    e.Name,
			Version: e.Version,
			PURL:    buildPURL(e.Ecosystem, e.Name, e.Version),
		}

		if e.SHA256 != "" {
			comp.Hashes = []CycloneDXHash{
				{Algorithm: "SHA-256", Content: e.SHA256},
			}
		}

		if e.LicenseSPDX != "" {
			comp.Licenses = []CycloneDXLicense{
				{License: CycloneDXLicenseID{ID: e.LicenseSPDX}},
			}
		}

		var props []CycloneDXProperty
		if e.ProvenanceStatus != "" {
			props = append(props, CycloneDXProperty{
				Name: "chainsaw:provenance:status", Value: e.ProvenanceStatus,
			})
		}
		if e.TrustScore > 0 {
			props = append(props, CycloneDXProperty{
				Name: "chainsaw:trust:score", Value: fmt.Sprintf("%d", e.TrustScore),
			})
		}
		if e.IsVulnerable && len(e.CVEs) > 0 {
			props = append(props, CycloneDXProperty{
				Name: "chainsaw:vuln:cves", Value: strings.Join(e.CVEs, ","),
			})
		}

		// Supply-chain condition signals (13-PR consolidation). Only
		// non-zero/non-empty values are emitted so the property list
		// stays compact for the ubiquitous "clean" package case.
		if e.InstallScriptKind != "" && e.InstallScriptKind != "none" {
			props = append(props, CycloneDXProperty{
				Name: "chainsaw:supplychain:installScriptKind", Value: e.InstallScriptKind,
			})
		}
		if len(e.PublisherSet) > 0 {
			props = append(props, CycloneDXProperty{
				Name: "chainsaw:supplychain:publisherSet", Value: strings.Join(e.PublisherSet, ","),
			})
		}
		if e.PublisherChanged {
			props = append(props, CycloneDXProperty{
				Name: "chainsaw:supplychain:publisherChanged", Value: "true",
			})
		}
		if len(e.VersionAnomalyFlags) > 0 {
			props = append(props, CycloneDXProperty{
				Name: "chainsaw:supplychain:versionAnomalyFlags", Value: strings.Join(e.VersionAnomalyFlags, ","),
			})
		}
		if e.HiddenUnicodeHits > 0 {
			props = append(props, CycloneDXProperty{
				Name: "chainsaw:supplychain:hiddenUnicodeHits", Value: fmt.Sprintf("%d", e.HiddenUnicodeHits),
			})
		}
		if e.PublishVelocity24h > 0 {
			props = append(props, CycloneDXProperty{
				Name: "chainsaw:supplychain:publishVelocity24h", Value: fmt.Sprintf("%d", e.PublishVelocity24h),
			})
		}
		if e.RepoLinkStatus != "" && e.RepoLinkStatus != "ok" {
			props = append(props, CycloneDXProperty{
				Name: "chainsaw:supplychain:repoLinkStatus", Value: e.RepoLinkStatus,
			})
		}
		if e.ChecksumDeclared != "" {
			props = append(props, CycloneDXProperty{
				Name: "chainsaw:supplychain:checksumDeclared", Value: e.ChecksumDeclared,
			})
		}
		if e.ChecksumActual != "" {
			props = append(props, CycloneDXProperty{
				Name: "chainsaw:supplychain:checksumActual", Value: e.ChecksumActual,
			})
		}
		if e.MalwareStatus == "malicious" {
			props = append(props, CycloneDXProperty{
				Name: "chainsaw:supplychain:malware", Value: "true",
			})
		}
		if e.TyposquatStatus == "suspected" || e.TyposquatStatus == "confirmed" {
			props = append(props, CycloneDXProperty{
				Name: "chainsaw:supplychain:typosquat", Value: e.TyposquatStatus,
			})
		}

		// Attribution properties (chainsaw:attribution:*). Emitted only
		// when the caller explicitly populated Attributions — the
		// default empty slice yields zero properties, preserving
		// byte-equality with releases that predate this feature.
		// Multiple values become multiple properties per CycloneDX
		// convention. Property names are stable; consumers pin on
		// "chainsaw:attribution:client", ":repo", ":group",
		// ":first_seen", ":last_seen".
		for _, a := range e.Attributions {
			if a.ClientID != "" {
				props = append(props, CycloneDXProperty{
					Name: "chainsaw:attribution:client", Value: a.ClientID,
				})
			}
			if a.Repository != "" {
				props = append(props, CycloneDXProperty{
					Name: "chainsaw:attribution:repo", Value: a.Repository,
				})
			}
			if a.Group != "" && a.Group != a.Repository {
				props = append(props, CycloneDXProperty{
					Name: "chainsaw:attribution:group", Value: a.Group,
				})
			}
			if !a.FirstSeen.IsZero() {
				props = append(props, CycloneDXProperty{
					Name:  "chainsaw:attribution:first_seen",
					Value: a.FirstSeen.UTC().Format(time.RFC3339),
				})
			}
			if !a.LastSeen.IsZero() {
				props = append(props, CycloneDXProperty{
					Name:  "chainsaw:attribution:last_seen",
					Value: a.LastSeen.UTC().Format(time.RFC3339),
				})
			}
		}

		// Pain 7: link-back identifiers connecting one component back to
		// the proxy's audit row + the snapshot that captured it.
		// Emitted ONLY when populated so flat / Generate-no-graph
		// outputs stay byte-equal to pre-Pain-7 releases.
		if e.EventID != "" {
			props = append(props, CycloneDXProperty{
				Name: "chainsaw:supply-chain:event-id", Value: e.EventID,
			})
		}
		if e.ClientID != "" {
			props = append(props, CycloneDXProperty{
				Name: "chainsaw:supply-chain:client-id", Value: e.ClientID,
			})
		}
		if e.SnapshotID != "" {
			props = append(props, CycloneDXProperty{
				Name: "chainsaw:supply-chain:snapshot-id", Value: e.SnapshotID,
			})
		}

		comp.Properties = props

		components = append(components, comp)
	}

	// Build the CycloneDX dependencies[] graph when a depgraph was
	// supplied. Each component's `ref` is its purl (so the dependency
	// table and components table key off the same identifier without an
	// extra bom-ref translation layer). dependsOn[] enumerates ONLY the
	// direct children of the parent node — per CycloneDX 1.6 §7.6, an
	// entry in dependsOn MUST directly depend on the parent, and
	// transitive relationships are inferred by walking the graph. Using
	// Descendants() here would silently break that contract.
	// regression-check: F17 — always initialise as a non-nil empty slice
	// so the JSON encoder emits `"dependencies": []` rather than omitting
	// the key. CycloneDX 1.6 §5.3 lists dependencies[] as a structured
	// part of the BOM; downstream consumers (Dependency-Track, Snyk,
	// Grype, in-toto verifiers) expect either an array of relationships
	// or an explicit empty array, not key-absent.
	deps := make([]CycloneDXDependency, 0)
	if graph != nil {
		// Build a fast lookup of "is this purl present as a component?"
		// so dependsOn[] only references components that actually exist
		// in this BOM. CycloneDX validators warn on dangling refs.
		known := make(map[string]bool, len(entries))
		for _, e := range entries {
			known[buildPURL(e.Ecosystem, e.Name, e.Version)] = true
		}
		deps = make([]CycloneDXDependency, 0, len(entries))
		for _, e := range entries {
			key := depgraph.Key{Ecosystem: e.Ecosystem, Name: e.Name, Version: e.Version}
			node, ok := graph.Nodes[key]
			if !ok {
				continue
			}
			// Direct children only. node.Children is the public
			// per-node adjacency list maintained by AddEdge — no
			// recursive walk, no transitive descendants.
			directChildren := node.Children
			if len(directChildren) == 0 {
				continue
			}
			parentRef := buildPURL(e.Ecosystem, e.Name, e.Version)
			children := make([]string, 0, len(directChildren))
			seen := make(map[string]struct{}, len(directChildren))
			for _, d := range directChildren {
				ref := buildPURL(d.Ecosystem, d.Name, d.Version)
				if !known[ref] {
					// Skip edges to packages outside the BOM — keeps
					// the dependency graph internally consistent for
					// CycloneDX-strict consumers.
					continue
				}
				if _, dup := seen[ref]; dup {
					continue
				}
				seen[ref] = struct{}{}
				children = append(children, ref)
			}
			if len(children) == 0 {
				continue
			}
			// Stable order so the BOM serializes deterministically.
			sort.Strings(children)
			deps = append(deps, CycloneDXDependency{Ref: parentRef, DependsOn: children})
		}
	}

	return &CycloneDXBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		Version:      1,
		SerialNumber: serialNumber,
		Metadata: CycloneDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []CycloneDXTool{
				{Vendor: "chainsaw", Name: "chainsaw-proxy", Version: "1.0.0"},
			},
		},
		Components:   components,
		Dependencies: deps,
	}
}

// ToJSON serializes the BOM to JSON.
func (bom *CycloneDXBOM) ToJSON() ([]byte, error) {
	return json.MarshalIndent(bom, "", "  ")
}

// buildPURL constructs a Package URL per the PURL spec.
func buildPURL(ecosystem, name, version string) string {
	var purlType string
	switch strings.ToLower(ecosystem) {
	case "npm":
		purlType = "npm"
	case "pip", "pypi":
		purlType = "pypi"
	case "maven", "gradle":
		purlType = "maven"
		// Maven PURL: pkg:maven/groupId/artifactId@version
		if parts := strings.SplitN(name, ":", 2); len(parts) == 2 {
			return fmt.Sprintf("pkg:maven/%s/%s@%s", parts[0], parts[1], version)
		}
	case "cocoapods":
		purlType = "cocoapods"
	case "nuget":
		purlType = "nuget"
	case "cargo":
		purlType = "cargo"
	case "go", "gomod":
		purlType = "golang"
	case "composer":
		purlType = "composer"
	case "rubygems":
		purlType = "gem"
	case "docker":
		purlType = "docker"
	case "apt":
		purlType = "deb"
	case "dnf", "yum":
		purlType = "rpm"
	case "huggingface":
		purlType = "huggingface"
	default:
		purlType = "generic"
	}

	// Handle scoped packages (npm @scope/name).
	if purlType == "npm" && strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 2 {
			return fmt.Sprintf("pkg:%s/%s/%s@%s", purlType,
				url.PathEscape(parts[0][1:]),
				url.PathEscape(parts[1]),
				url.PathEscape(version))
		}
	}

	return fmt.Sprintf("pkg:%s/%s@%s", purlType,
		url.PathEscape(name), url.PathEscape(version))
}
