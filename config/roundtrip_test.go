package config

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// configPkgPath is the import path of this package. The walker descends
// into struct types declared HERE and stops at foreign types (policy.Policy,
// time.Duration, …) — a foreign type's internals are not part of the
// Chainsaw YAML surface and must not drag the ratchet into other packages.
const configPkgPath = "github.com/chain305/chainsaw-core/config"

// configLeafPaths returns the dotted path of every YAML-reachable leaf
// field of Config, descending through nested structs, pointers, and the
// element/value types of slices and maps (rendered as "Field[].Sub").
func configLeafPaths() []string {
	var out []string
	walkConfigType("", reflect.TypeOf(Config{}), &out, map[reflect.Type]bool{})
	sort.Strings(out)
	return out
}

func walkConfigType(prefix string, rt reflect.Type, out *[]string, onPath map[reflect.Type]bool) {
	for rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}
	switch rt.Kind() {
	case reflect.Struct:
		if rt.PkgPath() != configPkgPath || onPath[rt] {
			*out = append(*out, prefix)
			return
		}
		onPath[rt] = true
		defer delete(onPath, rt)
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			// Unexported fields are unreachable from YAML and from the
			// settings layer by construction (explicitKeys is the only
			// one today), so they carry no round-trip obligation.
			if f.PkgPath != "" {
				continue
			}
			child := f.Name
			if prefix != "" {
				child = prefix + "." + f.Name
			}
			walkConfigType(child, f.Type, out, onPath)
		}
	case reflect.Slice, reflect.Array:
		walkConfigElem(prefix, rt.Elem(), out, onPath)
	case reflect.Map:
		walkConfigElem(prefix, rt.Elem(), out, onPath)
	default:
		*out = append(*out, prefix)
	}
}

// walkConfigElem descends into a container's element type when that type
// is one of ours, and otherwise records the container itself as a leaf.
func walkConfigElem(prefix string, elem reflect.Type, out *[]string, onPath map[reflect.Type]bool) {
	deref := elem
	for deref.Kind() == reflect.Pointer {
		deref = deref.Elem()
	}
	if deref.Kind() == reflect.Struct && deref.PkgPath() == configPkgPath && !onPath[deref] {
		walkConfigType(prefix+"[]", elem, out, onPath)
		return
	}
	*out = append(*out, prefix)
}

// TestConfigRoundTripCompleteness is the ratchet. Every leaf field of
// Config must be classified: either it survives the
// YAML → settings-table → memory round trip (settingsBackedFields) or it
// is deliberately ephemeral and says why (ephemeralFields).
//
// Adding a field to Config without classifying it FAILS here. That is the
// point: the twelve blocks this test was written for were lost precisely
// because LoadFromStoreForOrg's key list was hand-maintained and nothing
// noticed when it fell behind the struct. See docs/CONFIG_REFERENCE.md.
func TestConfigRoundTripCompleteness(t *testing.T) {
	var unclassified []string
	for _, path := range configLeafPaths() {
		_, backed := settingsBackedFields[path]
		_, ephemeral := ephemeralFields[path]
		switch {
		case backed && ephemeral:
			t.Errorf("config field %q is listed in BOTH settingsBackedFields and ephemeralFields", path)
		case !backed && !ephemeral:
			unclassified = append(unclassified, path)
		}
	}
	if len(unclassified) > 0 {
		t.Fatalf(`%d Config field(s) are not classified for the settings round trip:

	%s

Every field of config.Config must either round-trip through the settings
layer or be named in ephemeralFields with a reason. Pick one:

  * Durable operator config -> add a settings key, persist it in
    SaveToStoreForOrg, read it back in overlayFromSettings, and add the
    field to settingsBackedFields in roundtrip.go.
  * Genuinely per-process / stored elsewhere -> add it to ephemeralFields
    in roundtrip.go with a one-line reason.

Do NOT delete this test to get green: a field that is neither persisted
nor allow-listed is silently zeroed on every boot of every DB-backed
deployment, which is the exact bug this ratchet exists to prevent.`,
			len(unclassified), strings.Join(unclassified, "\n\t"))
	}
}

// TestConfigRoundTripRegistryHasNoStaleEntries is the other half of the
// ratchet: renaming or deleting a Config field must force the registry to
// be updated with it, or the classification silently rots.
func TestConfigRoundTripRegistryHasNoStaleEntries(t *testing.T) {
	live := map[string]bool{}
	for _, path := range configLeafPaths() {
		live[path] = true
	}
	for path := range settingsBackedFields {
		if !live[path] {
			t.Errorf("settingsBackedFields names %q, which is no longer a field of config.Config", path)
		}
	}
	for path, reason := range ephemeralFields {
		if !live[path] {
			t.Errorf("ephemeralFields names %q, which is no longer a field of config.Config", path)
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("ephemeralFields[%q] has an empty reason; every exclusion must say why", path)
		}
	}
}
