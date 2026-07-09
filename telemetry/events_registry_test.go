package telemetry

import (
	"os"
	"regexp"
	"testing"
)

// nameLine matches an event entry in events.yaml: `  - name: <event.name>`.
var nameLine = regexp.MustCompile(`(?m)^\s*-\s*name:\s*"?([a-z0-9_.]+)"?\s*$`)

// parseYAMLEventNames extracts every `- name: <x>` event name from events.yaml.
func parseYAMLEventNames(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("events.yaml")
	if err != nil {
		t.Fatalf("read events.yaml: %v", err)
	}
	matches := nameLine.FindAllStringSubmatch(string(raw), -1)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m[1])
	}
	if len(names) == 0 {
		t.Fatal("parsed zero event names from events.yaml — regex or file shape changed")
	}
	return names
}

// TestRegistryYAMLSync is the missing CI lint the package header promised
// (scripts/lint-events.go does not exist in this repo). It enforces a 3-way
// sync: every Go const is a registry key (compile-checked, since the registry
// map literal uses the constants), and this test closes the loop by asserting
// the events.yaml catalog and the Go registry map are exactly the same set.
//
// Why it matters: the server emit path (CaptureUserEvent/CaptureInstallEvent)
// does not gate on IsKnownEvent, so an emit using an unregistered literal name
// silently lands in PostHog's immutable catalog; and the CLI path DROPS
// unregistered names. Either way, drift between the YAML catalog and the Go
// registry is a real bug class. This guard fails the build on drift.
func TestRegistryYAMLSync(t *testing.T) {
	yamlNames := parseYAMLEventNames(t)

	// 1. No duplicate names in the YAML catalog.
	seen := make(map[string]struct{}, len(yamlNames))
	for _, n := range yamlNames {
		if _, dup := seen[n]; dup {
			t.Errorf("duplicate event name in events.yaml: %q", n)
		}
		seen[n] = struct{}{}
	}

	// 2. Every YAML event is a registered (known) event in the Go map.
	for _, n := range yamlNames {
		if !IsKnownEvent(n) {
			t.Errorf("events.yaml lists %q but it is NOT in the Go registry map "+
				"(add the Event* const + registry entry in events.go)", n)
		}
	}

	// 3. Every Go registry entry has a YAML catalog entry (no Go-only events).
	for name := range registry {
		if _, ok := seen[name]; !ok {
			t.Errorf("registry/events.go has %q but events.yaml does not "+
				"(add the catalog entry)", name)
		}
	}

	// 4. Sets are exactly equal in size.
	if len(seen) != len(registry) {
		t.Errorf("event count mismatch: events.yaml has %d unique names, "+
			"Go registry has %d entries", len(seen), len(registry))
	}
}
