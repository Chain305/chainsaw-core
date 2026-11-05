package homebrew

import (
	"os"
	"testing"
)

// The shadow rule reads the host's PATH directories; fixtures must not
// depend on what this machine has in /usr/local/bin. Tests that exercise
// the rule set their own.
func TestMain(m *testing.M) {
	SystemCommandDirs, PathHelperDirs = nil, nil
	os.Exit(m.Run())
}
