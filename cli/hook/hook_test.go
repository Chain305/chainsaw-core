package hook

import "testing"

func TestAllReturnsExpectedSetDistinct(t *testing.T) {
	got := All()
	expected := []string{"npm", "yarn", "bun", "pip", "cargo", "maven", "gradle", "sbt", "nuget", "go", "docker"}
	if len(got) != len(expected) {
		t.Fatalf("All() returned %d managers, want %d", len(got), len(expected))
	}
	seen := map[string]bool{}
	for _, m := range got {
		if seen[m.Name()] {
			t.Errorf("duplicate manager name %q", m.Name())
		}
		seen[m.Name()] = true
	}
	for _, want := range expected {
		if !seen[want] {
			t.Errorf("All() missing %q", want)
		}
	}
}

func TestByName(t *testing.T) {
	for _, name := range []string{"npm", "pip", "cargo", "maven", "gradle", "sbt", "nuget", "go", "docker", "yarn", "bun"} {
		m, err := ByName(name)
		if err != nil {
			t.Errorf("ByName(%q) returned error: %v", name, err)
			continue
		}
		if m.Name() != name {
			t.Errorf("ByName(%q) returned manager named %q", name, m.Name())
		}
	}
	if _, err := ByName("gem"); err == nil {
		t.Error("ByName(\"gem\") returned nil error, want not-found")
	}
}

func TestIsInstalledDoesNotPanic(t *testing.T) {
	for _, m := range All() {
		_ = m.IsInstalled()
	}
}
