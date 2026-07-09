package sbom

import "strings"

// Component is the format-neutral shape used by DiffComponents. Both
// CycloneDX and in-toto SBOM components normalize into this struct so
// the diff logic doesn't need to care which document format produced
// them. PURL is preserved verbatim for downstream rendering; Ecosystem
// is derived from PURL when present and used as the identity tiebreaker
// (so `pkg:npm/foo` and `pkg:pypi/foo` don't collide).
type Component struct {
	Name      string
	Version   string
	Type      string
	Ecosystem string
	PURL      string
	// Hash is optional metadata kept for stable diff identity when
	// callers populate it; the current diff key is (name, type,
	// ecosystem) and Hash is informational only.
	Hash string
}

type ComponentChange struct {
	Name       string
	Type       string
	Ecosystem  string
	OldVersion string
	NewVersion string
}

type DiffResult struct {
	Added   []Component
	Removed []Component
	Changed []ComponentChange
}

// componentKey is the identity tuple used to match components across
// two BOMs. PURL ecosystem is part of identity so `pkg:npm/foo` and
// `pkg:pypi/foo` don't collide; when PURL is absent we degrade to
// (name, type) — matching what most non-PURL CycloneDX emitters give us.
type componentKey struct {
	Name      string
	Type      string
	Ecosystem string
}

func keyOfComponent(c Component) componentKey {
	return componentKey{
		Name:      c.Name,
		Type:      c.Type,
		Ecosystem: c.Ecosystem,
	}
}

func ecosystemFromPURL(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return ""
	}
	return rest[:slash]
}

// cycloneDXToComponents normalizes CycloneDX components to the
// format-neutral Component shape consumed by DiffComponents.
func cycloneDXToComponents(bom *CycloneDXBOM) []Component {
	if bom == nil {
		return nil
	}
	out := make([]Component, 0, len(bom.Components))
	for _, c := range bom.Components {
		comp := Component{
			Name:      c.Name,
			Version:   c.Version,
			Type:      c.Type,
			Ecosystem: ecosystemFromPURL(c.PURL),
			PURL:      c.PURL,
		}
		// First SHA-256 hash if present, for parity with in-toto
		// digests. Diff identity does not currently use this field.
		for _, h := range c.Hashes {
			if strings.EqualFold(h.Algorithm, "SHA-256") {
				comp.Hash = h.Content
				break
			}
		}
		out = append(out, comp)
	}
	return out
}

// Diff compares two CycloneDX BOMs. Preserved as a thin wrapper around
// DiffComponents so existing callers keep working unchanged.
func Diff(a, b *CycloneDXBOM) DiffResult {
	return DiffComponents(cycloneDXToComponents(a), cycloneDXToComponents(b))
}

// DiffComponents is the format-neutral diff. Iterates `a` in source
// order so output is deterministic without forcing callers to sort.
func DiffComponents(a, b []Component) DiffResult {
	var result DiffResult

	aIndex := make(map[componentKey]Component, len(a))
	for _, c := range a {
		aIndex[keyOfComponent(c)] = c
	}
	bIndex := make(map[componentKey]Component, len(b))
	for _, c := range b {
		bIndex[keyOfComponent(c)] = c
	}

	for _, ac := range a {
		k := keyOfComponent(ac)
		bc, ok := bIndex[k]
		if !ok {
			result.Removed = append(result.Removed, ac)
			continue
		}
		if ac.Version != bc.Version {
			result.Changed = append(result.Changed, ComponentChange{
				Name:       ac.Name,
				Type:       ac.Type,
				Ecosystem:  k.Ecosystem,
				OldVersion: ac.Version,
				NewVersion: bc.Version,
			})
		}
	}
	for _, bc := range b {
		if _, ok := aIndex[keyOfComponent(bc)]; !ok {
			result.Added = append(result.Added, bc)
		}
	}
	return result
}
