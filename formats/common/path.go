package common

import "strings"

// SplitPathSegments trims a logical path and splits it on "/", dropping empty
// and whitespace-only segments. It is the canonical normalization step for
// every resolver: Describe inputs are best-effort logical paths and may carry
// leading/trailing slashes or stray whitespace from upstream rewriting.
//
// Most format resolvers historically duplicated this helper verbatim. New
// resolvers should call common.SplitPathSegments directly.
func SplitPathSegments(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	raw := strings.Split(p, "/")
	segments := make([]string, 0, len(raw))
	for _, segment := range raw {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		segments = append(segments, segment)
	}
	return segments
}
