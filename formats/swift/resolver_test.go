package swift

import "testing"

func TestResolverDescribe(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantName string
		wantVer  string
		ok       bool
	}{
		{
			name:     "release list",
			path:     "apple/swift-nio",
			wantName: "apple.swift-nio",
			wantVer:  "",
			ok:       true,
		},
		{
			name:     "release metadata",
			path:     "apple/swift-nio/2.62.0",
			wantName: "apple.swift-nio",
			wantVer:  "2.62.0",
			ok:       true,
		},
		{
			name:     "manifest",
			path:     "apple/swift-nio/2.62.0/Package.swift",
			wantName: "apple.swift-nio",
			wantVer:  "2.62.0",
			ok:       true,
		},
		{
			name:     "manifest with swift-version query",
			path:     "apple/swift-nio/2.62.0/Package.swift?swift-version=5.9",
			wantName: "apple.swift-nio",
			wantVer:  "2.62.0",
			ok:       true,
		},
		{
			name:     "source archive",
			path:     "apple/swift-nio/2.62.0.zip",
			wantName: "apple.swift-nio",
			wantVer:  "2.62.0",
			ok:       true,
		},
		{
			name:     "case-insensitive scope and name",
			path:     "Apple/Swift-NIO/2.62.0",
			wantName: "apple.swift-nio",
			wantVer:  "2.62.0",
			ok:       true,
		},
		{
			name:     "leading slash tolerated",
			path:     "/apple/swift-nio/2.62.0.zip",
			wantName: "apple.swift-nio",
			wantVer:  "2.62.0",
			ok:       true,
		},
		{
			// /identifiers?url=... reverse lookup — not a package path.
			// Resolver returns ok=false so policy evaluation is skipped.
			name: "identifiers reverse lookup is skipped",
			path: "identifiers?url=https://github.com/apple/swift-nio.git",
			ok:   false,
		},
		{
			name: "empty path",
			path: "",
			ok:   false,
		},
		{
			name: "single segment",
			path: "apple",
			ok:   false,
		},
		{
			name: "too many segments",
			path: "apple/swift-nio/2.62.0/extra/stuff",
			ok:   false,
		},
		{
			name:     "pre-release version",
			path:     "vapor/vapor/4.0.0-beta.3.zip",
			wantName: "vapor.vapor",
			wantVer:  "4.0.0-beta.3",
			ok:       true,
		},
	}

	resolver := NewResolver()
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, ok := resolver.Describe(tc.path)
			if ok != tc.ok {
				t.Fatalf("Describe(%q) ok = %v, want %v (coord=%+v)", tc.path, ok, tc.ok, got)
			}
			if !ok {
				return
			}
			if got.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tc.wantName)
			}
			if got.Version != tc.wantVer {
				t.Errorf("Version = %q, want %q", got.Version, tc.wantVer)
			}
			if got.Format != FormatName {
				t.Errorf("Format = %q, want %q", got.Format, FormatName)
			}
		})
	}
}

func TestNormalizeIdentifier(t *testing.T) {
	tests := []struct {
		scope, name, want string
	}{
		{"apple", "swift-nio", "apple.swift-nio"},
		{"Apple", "Swift-NIO", "apple.swift-nio"},
		{"  vapor  ", "  vapor  ", "vapor.vapor"},
	}
	for _, tc := range tests {
		got := NormalizeIdentifier(tc.scope, tc.name)
		if got != tc.want {
			t.Errorf("NormalizeIdentifier(%q, %q) = %q, want %q", tc.scope, tc.name, got, tc.want)
		}
	}
}

func TestSplitIdentifier(t *testing.T) {
	tests := []struct {
		id                string
		wantScope, wantNm string
	}{
		{"apple.swift-nio", "apple", "swift-nio"},
		{"vapor.vapor", "vapor", "vapor"},
		{"nodot", "", ""},
		{".name", "", ""},
		{"scope.", "", ""},
		{"", "", ""},
	}
	for _, tc := range tests {
		s, n := SplitIdentifier(tc.id)
		if s != tc.wantScope || n != tc.wantNm {
			t.Errorf("SplitIdentifier(%q) = (%q, %q), want (%q, %q)", tc.id, s, n, tc.wantScope, tc.wantNm)
		}
	}
}
