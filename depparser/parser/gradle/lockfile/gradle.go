// Package gradle parses Gradle's dependency-lockfile format
// (gradle.lockfile / *.gradle.lockfile).
//
// Format: text. Each non-comment line is
//
//	<group>:<artifact>:<version>=<configuration>[,<configuration>...]
//
// The configurations list tells you which build classpath the dep is
// used from (runtimeClasspath, testRuntimeClasspath, etc.). We keep all
// classpaths here; callers that want prod-only can filter later.
//
// Trivy reference: pkg/dependency/parser/gradle/lockfile/parse.go.
package gradle

import (
	"bufio"
	"io"
	"strings"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

func Parse(r io.Reader) ([]ftypes.Package, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var out []ftypes.Package
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip the "=configurations" suffix — we don't track it.
		if eq := strings.Index(line, "="); eq > 0 {
			line = line[:eq]
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		group, artifact, version := parts[0], parts[1], parts[2]
		if group == "" || artifact == "" || version == "" {
			continue
		}
		out = append(out, ftypes.Package{
			Name:    group + ":" + artifact,
			Version: version,
		})
	}
	return out, sc.Err()
}
