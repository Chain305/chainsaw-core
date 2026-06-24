package common

import "testing"

func TestStripArchiveExtension(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		extras   []string
		want     string
	}{
		{"empty", "", nil, ""},
		{"plain tar gz", "pkg-1.0.tar.gz", nil, "pkg-1.0"},
		{"plain tgz", "pkg-1.0.tgz", nil, "pkg-1.0"},
		{"plain tar bz2", "pkg-1.0.tar.bz2", nil, "pkg-1.0"},
		{"plain tar xz", "pkg-1.0.tar.xz", nil, "pkg-1.0"},
		{"zip", "pkg-1.0.zip", nil, "pkg-1.0"},
		{"phar", "pkg-1.0.phar", nil, "pkg-1.0"},
		{"plain tar", "pkg-1.0.tar", nil, "pkg-1.0"},
		{"uppercase suffix matched", "pkg-1.0.TAR.GZ", nil, "pkg-1.0"},
		{"unknown ext falls back to filepath.Ext", "pkg-1.foo", nil, "pkg-1"},
		{"no extension passthrough", "pkg", nil, "pkg"},
		{"trailing dot segment treated as extension", "pkg-1.0", nil, "pkg-1"},
		{"compound preferred over single", "pkg-1.0.tar.gz", nil, "pkg-1.0"},
		{"extras consulted first", "pkg-1.0.whl", []string{".whl"}, "pkg-1.0"},
		{"extras case-insensitive", "pkg-1.0.WHL", []string{".whl"}, "pkg-1.0"},
		{"extras empty entries skipped", "pkg-1.0.whl", []string{"", ".whl"}, "pkg-1.0"},
		{"extras miss falls through to common list", "pkg-1.0.tar.gz", []string{".whl"}, "pkg-1.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripArchiveExtension(tt.filename, tt.extras...)
			if got != tt.want {
				t.Fatalf("StripArchiveExtension(%q, %v) = %q, want %q", tt.filename, tt.extras, got, tt.want)
			}
		})
	}
}
