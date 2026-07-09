package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestConfigHome_OverrideWinsOnAllOSes(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv(EnvConfigHome, tmp)
	t.Setenv(EnvXDGConfigHome, "/should/be/ignored")

	got := ConfigHome()
	if got != tmp {
		t.Fatalf("ConfigHome() = %q, want %q", got, tmp)
	}
}

func TestConfigHome_OverrideExpandsTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home dir available")
	}
	t.Setenv(EnvConfigHome, "~/custom-chainsaw")

	got := ConfigHome()
	want := filepath.Join(home, "custom-chainsaw")
	if got != want {
		t.Fatalf("ConfigHome() = %q, want %q", got, want)
	}
}

func TestConfigHome_LinuxXDG(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}
	t.Setenv(EnvConfigHome, "")
	os.Unsetenv(EnvConfigHome)
	xdg := t.TempDir()
	t.Setenv(EnvXDGConfigHome, xdg)

	got := ConfigHome()
	want := filepath.Join(xdg, "chainsaw")
	if got != want {
		t.Fatalf("ConfigHome() = %q, want %q", got, want)
	}
}

func TestConfigHome_LinuxDefaultWhenXDGUnset(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}
	os.Unsetenv(EnvConfigHome)
	os.Unsetenv(EnvXDGConfigHome)

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home dir available")
	}
	got := ConfigHome()
	want := filepath.Join(home, ".config", "chainsaw")
	if got != want {
		t.Fatalf("ConfigHome() = %q, want %q", got, want)
	}
}

func TestConfigHome_MacOSReturnsDotChainsaw(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	os.Unsetenv(EnvConfigHome)

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home dir available")
	}
	got := ConfigHome()
	want := filepath.Join(home, ".chainsaw")
	if got != want {
		t.Fatalf("ConfigHome() = %q, want %q", got, want)
	}
}

func TestConfigHome_WindowsUsesUserConfigDir(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only")
	}
	os.Unsetenv(EnvConfigHome)

	cfg, err := os.UserConfigDir()
	if err != nil || cfg == "" {
		t.Skip("UserConfigDir unavailable")
	}
	got := ConfigHome()
	want := filepath.Join(cfg, "Chainsaw")
	if got != want {
		t.Fatalf("ConfigHome() = %q, want %q", got, want)
	}
}

func TestLegacyConfigHome_AlwaysHomeDotChainsaw(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home dir available")
	}
	got := LegacyConfigHome()
	want := filepath.Join(home, ".chainsaw")
	if got != want {
		t.Fatalf("LegacyConfigHome() = %q, want %q", got, want)
	}
}

func TestExpandTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home dir available")
	}
	cases := []struct {
		in, want string
	}{
		{"~", home},
		{"~/foo", filepath.Join(home, "foo")},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
		{"", ""},
	}
	for _, c := range cases {
		if got := expandTilde(c.in); got != c.want {
			t.Errorf("expandTilde(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
