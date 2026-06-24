package swift

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

// Pure helpers for the SE-0391 publish endpoint. These live alongside the
// SE-0292 read-side resolver/transformer so the validation grammar stays in
// one place — the server-side multipart parser composes them; tests cover
// them in isolation so the grammar can evolve without re-mocking HTTP.

// SE-0292 §3.5: scope and package name share an identifier grammar that is
// alphanumeric, may contain internal hyphens (no leading/trailing hyphens
// and no consecutive hyphens), and is 1–39 characters long. RE2 has no
// lookahead so we encode the constraint as a length cap plus a positive
// shape check, then a separate scan rejects "--" and trailing "-".
var identifierShapeRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}$`)

// isValidIdentifier enforces SE-0292 §3.5 by combining the shape regex
// (covers length, alphabet, and leading-char) with a hyphen-adjacency
// check. Splitting the rule keeps the regex RE2-compatible.
func isValidIdentifier(s string) bool {
	if !identifierShapeRE.MatchString(s) {
		return false
	}
	if strings.HasSuffix(s, "-") {
		return false
	}
	if strings.Contains(s, "--") {
		return false
	}
	return true
}

// IsValidScope reports whether s is a syntactically valid SE-0292 scope.
func IsValidScope(s string) bool { return isValidIdentifier(s) }

// IsValidPackageName reports whether s is a syntactically valid SE-0292
// package name. The grammar is identical to scope.
func IsValidPackageName(s string) bool { return isValidIdentifier(s) }

// semverRE is the canonical SemVer 2.0 grammar (semver.org §9). We accept
// the leading "v" off (clients send bare versions) and trim it on input.
var semverRE = regexp.MustCompile(
	`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
		`(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?` +
		`(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`,
)

// NormalizeSemver validates a SemVer 2.0 version string and returns it
// without any leading "v". Returns an error for malformed input — callers
// should reject the upload before touching storage.
func NormalizeSemver(v string) (string, error) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return "", fmt.Errorf("empty version")
	}
	if !semverRE.MatchString(v) {
		return "", fmt.Errorf("invalid SemVer 2.0 version: %q", v)
	}
	return v, nil
}

// maxManifestBytes caps the in-memory copy of any single Package.swift
// variant we extract from the source archive. Real manifests are <100 KB;
// 1 MiB is a generous upper bound that still bounds malicious-zip pressure.
const maxManifestBytes = 1 << 20

// ParseManifest opens a Swift Package source archive (zip) and returns a
// map of manifest filename → bytes. Per SwiftPM convention the package
// root may live either at the zip root or one level below (a single
// top-level directory; this is what `swift package archive-source` emits).
//
// We require Package.swift to exist; version-specific overrides matching
// `Package@swift-X.Y.swift` are returned alongside if present.
func ParseManifest(zipBytes []byte) (map[string][]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("open source archive: %w", err)
	}

	// Detect the single-top-level-dir wrapping by inspecting the first
	// segment of every entry. If they all share one prefix, strip it for
	// the "is this at the root?" check below.
	prefix := singleTopLevelPrefix(zr.File)

	manifests := map[string][]byte{}
	for _, f := range zr.File {
		name := f.Name
		if prefix != "" {
			name = strings.TrimPrefix(name, prefix+"/")
		}
		// Manifests live at the package root only — nested dirs don't count.
		if strings.ContainsRune(name, '/') {
			continue
		}
		base := path.Base(name)
		if !isManifestName(base) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", f.Name, err)
		}
		buf, err := io.ReadAll(io.LimitReader(rc, maxManifestBytes+1))
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f.Name, err)
		}
		if int64(len(buf)) > maxManifestBytes {
			return nil, fmt.Errorf("%s exceeds %d bytes", f.Name, maxManifestBytes)
		}
		manifests[base] = buf
	}

	if _, ok := manifests["Package.swift"]; !ok {
		return nil, fmt.Errorf("source archive missing Package.swift at root")
	}
	return manifests, nil
}

// singleTopLevelPrefix returns the shared first-segment of every file in
// the archive, or "" if entries do not share one. Empty entries (the
// directory marker for the prefix itself) are ignored.
func singleTopLevelPrefix(files []*zip.File) string {
	var prefix string
	for _, f := range files {
		// Normalize separators — zip spec uses "/", but defensive.
		clean := strings.TrimPrefix(f.Name, "./")
		if clean == "" {
			continue
		}
		idx := strings.IndexByte(clean, '/')
		var head string
		if idx < 0 {
			head = clean
		} else {
			head = clean[:idx]
		}
		if head == "" {
			continue
		}
		if prefix == "" {
			prefix = head
			continue
		}
		if head != prefix {
			return ""
		}
	}
	// If the only entries lived at the root (no slashes), prefix will hold
	// some filename — that means there's no shared dir. Detect by checking
	// whether at least one entry actually had a "/" beyond the prefix.
	for _, f := range files {
		clean := strings.TrimPrefix(f.Name, "./")
		if strings.HasPrefix(clean, prefix+"/") {
			return prefix
		}
	}
	return ""
}

// isManifestName matches Package.swift and Package@swift-X.Y[.Z].swift.
// Anything else (Package.resolved, README.md, etc.) is ignored.
var manifestVariantRE = regexp.MustCompile(`^Package@swift-\d+(?:\.\d+){0,2}\.swift$`)

func isManifestName(name string) bool {
	if name == "Package.swift" {
		return true
	}
	return manifestVariantRE.MatchString(name)
}
