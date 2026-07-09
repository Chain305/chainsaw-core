package common

import "testing"

func TestParseRPMFilename(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		wantName    string
		wantVersion string
	}{
		{
			name:        "standard nvr.arch",
			filename:    "bash-5.1.8-6.el9_1.x86_64.rpm",
			wantName:    "bash",
			wantVersion: "5.1.8-6.el9_1",
		},
		{
			name:        "noarch",
			filename:    "python3-pip-21.2.3-6.el9.noarch.rpm",
			wantName:    "python3-pip",
			wantVersion: "21.2.3-6.el9",
		},
		{
			name:        "multi-hyphen package",
			filename:    "kernel-headers-5.14.0-284.el9.x86_64.rpm",
			wantName:    "kernel-headers",
			wantVersion: "5.14.0-284.el9",
		},
		{name: "no hyphens", filename: "bash.rpm", wantName: "", wantVersion: ""},
		{name: "single hyphen", filename: "bash-1.0.rpm", wantName: "", wantVersion: ""},
		{name: "two hyphens but missing arch", filename: "bash-1.0-1.rpm", wantName: "", wantVersion: ""},
		{name: "empty", filename: "", wantName: "", wantVersion: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, version := ParseRPMFilename(tt.filename)
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
		})
	}
}
