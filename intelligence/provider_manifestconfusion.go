package intelligence

// manifestConfusionProvider (npm-only) compares the registry JSON's
// package.json view against the tarball's actual package.json. An
// attacker who has publisher credentials can edit registry-side
// metadata AFTER upload so that `scripts`, `bin`, `dependencies`,
// `main`, `name`, or `version` diverge from what's actually installed
// — known colloquially as "manifest confusion". Socket alerts on this.
//
// Zero new network calls: the tarball is already decompressed via
// SharedArtifactMap, and the registry JSON is passed in via
// Request.RegistryMetadataBytes (the proxy path already fetched it).
// When the registry bytes are absent we degrade silently so the
// signal stays dormant rather than false-firing.
//
// The comparator is deliberately semantic: JSON-decode both sides,
// compare canonical fields, and ignore whitespace / key order.

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
)

type manifestConfusionProvider struct{}

func newManifestConfusionProvider() *manifestConfusionProvider {
	return &manifestConfusionProvider{}
}

func (p *manifestConfusionProvider) Name() string        { return "manifestconfusion" }
func (p *manifestConfusionProvider) Signal() SignalMask  { return SignalManifestConfusion }
func (p *manifestConfusionProvider) Tier() int           { return 2 }
func (p *manifestConfusionProvider) NeedsArtifact() bool { return true }

func (p *manifestConfusionProvider) Supports(eco string) bool {
	e := strings.ToLower(strings.TrimSpace(eco))
	return e == "npm" || e == "yarn" || e == "bun"
}

func (p *manifestConfusionProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if req.Artifact == nil || len(req.Artifact.Bytes) == 0 {
		return PartialReport{}, nil
	}
	if len(req.RegistryMetadataBytes) == 0 {
		// Registry JSON not provided — nothing to compare against.
		return PartialReport{}, nil
	}
	res := req.Artifact.SharedArtifactMap()
	tarballPkg := FirstMatch(res.Files.SelectLower(func(name string) bool {
		return strings.EqualFold(baseName(name), "package.json")
	}), "package.json")
	if len(tarballPkg) == 0 {
		return PartialReport{}, nil
	}
	divergent := CompareNpmManifests(req.RegistryMetadataBytes, tarballPkg, req.Key.Version)
	if len(divergent) == 0 {
		return PartialReport{}, nil
	}
	return PartialReport{Scan: &ArtifactScanSection{
		Performed:               true,
		ManifestConfusion:       true,
		ManifestConfusionFields: divergent,
	}}, nil
}

var _ Provider = (*manifestConfusionProvider)(nil)

// CompareNpmManifests is the pure core of the provider — exported so
// tests can drive it without a full Request. Returns the sorted list
// of fields that disagree between registry and tarball package.json.
//
// version hints which versions[<version>] entry to extract from the
// registry document. When empty, the provider compares at the top-level
// of the registry JSON (supporting scoped tests where only the version
// entry was passed in directly).
func CompareNpmManifests(registryJSON, tarballJSON []byte, version string) []string {
	regView, err := extractRegistryManifest(registryJSON, version)
	if err != nil || regView == nil {
		return nil
	}
	var tar map[string]any
	if err := json.Unmarshal(tarballJSON, &tar); err != nil {
		return nil
	}

	var diffs []string
	for _, field := range comparableManifestFields {
		if !manifestFieldEqual(regView[field], tar[field]) {
			diffs = append(diffs, field)
		}
	}
	// scripts: compare only the lifecycle hooks relevant to
	// install-time execution. Registry entries drop non-whitelisted
	// scripts, so a full-map diff would false-fire.
	regScripts, _ := regView["scripts"].(map[string]any)
	tarScripts, _ := tar["scripts"].(map[string]any)
	for _, hook := range comparableScriptHooks {
		if !manifestFieldEqual(regScripts[hook], tarScripts[hook]) {
			diffs = append(diffs, "scripts."+hook)
		}
	}
	sort.Strings(diffs)
	return diffs
}

// extractRegistryManifest returns the versions[<version>] sub-object
// from the registry JSON, falling back to the top-level JSON if the
// caller already passed in a version entry directly.
func extractRegistryManifest(raw []byte, version string) (map[string]any, error) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	if versions, ok := root["versions"].(map[string]any); ok && version != "" {
		if entry, ok := versions[version].(map[string]any); ok {
			return entry, nil
		}
	}
	return root, nil
}

var comparableManifestFields = []string{
	"name",
	"version",
	"bin",
	"main",
	"dependencies",
	"devDependencies",
}

var comparableScriptHooks = []string{"preinstall", "install", "postinstall"}

// manifestFieldEqual compares two decoded JSON values for semantic
// equality. Nil / empty map / empty string / empty slice all collapse
// to "unset" so the comparator doesn't false-fire when one side
// simply omits the field.
func manifestFieldEqual(a, b any) bool {
	if isEmptyJSON(a) && isEmptyJSON(b) {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func isEmptyJSON(v any) bool {
	if v == nil {
		return true
	}
	switch x := v.(type) {
	case string:
		return x == ""
	case map[string]any:
		return len(x) == 0
	case []any:
		return len(x) == 0
	}
	return false
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}
