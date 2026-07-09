package common

import "strings"

// ParseRPMFilename decodes the canonical "<name>-<version>-<release>.<arch>.rpm"
// layout used by both yum and dnf repositories. The .rpm suffix and the trailing
// ".<arch>" segment are stripped before splitting on "-"; the last two parts
// become version-release and everything before them becomes the name.
//
// Returns ("", "") for any malformed input — callers gate the resolver on a
// non-empty name+version pair.
func ParseRPMFilename(filename string) (string, string) {
	filename = strings.TrimSuffix(filename, ".rpm")
	if idx := strings.LastIndex(filename, "."); idx != -1 {
		filename = filename[:idx]
	}
	parts := strings.Split(filename, "-")
	if len(parts) < 3 {
		return "", ""
	}
	version := parts[len(parts)-2]
	release := parts[len(parts)-1]
	name := strings.Join(parts[:len(parts)-2], "-")
	if name == "" || version == "" || release == "" {
		return "", ""
	}
	return name, version + "-" + release
}
