package hook

import (
	"os/exec"
	"strings"
	"testing"
)

// install-hook go used to write ~/.config/go/env on macOS, a file the go
// command never reads there (it uses os.UserConfigDir). Ask go itself.
func TestGoEnvFileIsTheOneGoReads(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH")
	}
	t.Setenv("GOENV", "")
	out, err := exec.Command(goBin, "env", "GOENV").Output()
	if err != nil {
		t.Fatalf("go env GOENV: %v", err)
	}
	got, err := GoEnvFile()
	if err != nil || got != strings.TrimSpace(string(out)) {
		t.Fatalf("GoEnvFile() = %q, %v; go reads %q", got, err, strings.TrimSpace(string(out)))
	}
}
