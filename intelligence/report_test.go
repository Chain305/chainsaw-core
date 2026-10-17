package intelligence

import "testing"

// Only the dispositive import-time shapes may drive the importTimeExecution
// policy condition; the advisory kinds hit 25 of 260 top PyPI packages.
func TestImportTimeRefusable(t *testing.T) {
	for _, c := range []struct {
		s    ArtifactScanSection
		want bool
	}{
		{ArtifactScanSection{}, false},
		{ArtifactScanSection{ImportTimeExecution: true, ImportTimeKind: "obfuscated_exec_bare"}, false},
		{ArtifactScanSection{ImportTimeExecution: true, ImportTimeKind: "import_time_beacon"}, false},
		{ArtifactScanSection{ImportTimeExecution: true, ImportTimeKind: "obfuscated_exec", ImportTimeDispositive: true}, true},
		// Rows stored before the flag existed: these kinds are dispositive by construction.
		{ArtifactScanSection{ImportTimeExecution: true, ImportTimeKind: "top_level_shell"}, true},
		{ArtifactScanSection{ImportTimeExecution: true, ImportTimeKind: "download_exec"}, true},
		{ArtifactScanSection{ImportTimeKind: "top_level_shell"}, false},
	} {
		if got := c.s.ImportTimeRefusable(); got != c.want {
			t.Errorf("%+v: got %v, want %v", c.s, got, c.want)
		}
	}
}
