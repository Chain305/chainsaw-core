package cli

import "strings"

// splitPackageArg parses "name@version" handling scoped npm names like "@scope/pkg@1.0.0".
func splitPackageArg(s string) (name, version string) {
	if strings.HasPrefix(s, "@") {
		rest := s[1:]
		if idx := strings.LastIndex(rest, "@"); idx >= 0 {
			return "@" + rest[:idx], rest[idx+1:]
		}
		return s, ""
	}
	name, version, _ = strings.Cut(s, "@")
	return
}
