package intelligence

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// -- Maven parent-POM licence inheritance -----------------------------
//
// The defect these tests pin: guava and log4j-core declare NO <licenses>
// block of their own. Both inherit Apache-2.0 from a parent POM
// (guava -> guava-parent, log4j-core -> log4j -> logging-parent). The
// reader only ever looked at the artifact's own document, so every such
// coordinate came back with an empty LicenseExpression and scored
// lic.missing (-15) AND license.unidentified (-15) — a self-contradiction
// on the single most widely deployed Java library there is.

// pomFixture renders a minimal but structurally real POM.
type pomFixture struct {
	group, artifact, version string
	parent                   string // "group:artifact:version", empty for none
	licenses                 []string
	properties               map[string]string
	extraParentXML           string // raw XML injected inside <parent>
}

func (f pomFixture) xml() string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<project xmlns="http://maven.apache.org/POM/4.0.0">` + "\n")
	b.WriteString("  <groupId>" + f.group + "</groupId>\n")
	b.WriteString("  <artifactId>" + f.artifact + "</artifactId>\n")
	b.WriteString("  <version>" + f.version + "</version>\n")
	if f.parent != "" {
		parts := strings.Split(f.parent, ":")
		b.WriteString("  <parent>\n")
		b.WriteString("    <groupId>" + parts[0] + "</groupId>\n")
		b.WriteString("    <artifactId>" + parts[1] + "</artifactId>\n")
		b.WriteString("    <version>" + parts[2] + "</version>\n")
		b.WriteString(f.extraParentXML)
		b.WriteString("  </parent>\n")
	}
	if len(f.properties) > 0 {
		b.WriteString("  <properties>\n")
		for k, v := range f.properties {
			b.WriteString("    <" + k + ">" + v + "</" + k + ">\n")
		}
		b.WriteString("  </properties>\n")
	}
	if len(f.licenses) > 0 {
		b.WriteString("  <licenses>\n")
		for _, l := range f.licenses {
			b.WriteString("    <license><name>" + l + "</name>" +
				"<url>https://example.invalid/LICENSE</url></license>\n")
		}
		b.WriteString("  </licenses>\n")
	}
	b.WriteString("</project>\n")
	return b.String()
}

func (f pomFixture) path() string {
	return fmt.Sprintf("/%s/%s/%s/%s-%s.pom",
		strings.ReplaceAll(f.group, ".", "/"), f.artifact, f.version, f.artifact, f.version)
}

// mavenPOMServer serves the given POMs from a repo1-shaped layout and
// counts every .pom request by path. Anything not in the set 404s, which
// is what "the parent is unfetchable" looks like on the wire.
func mavenPOMServer(t *testing.T, poms ...pomFixture) (*registryMetadataProvider, func(string) int, func() int) {
	t.Helper()
	var mu sync.Mutex
	hits := map[string]int{}
	body := map[string]string{}
	for _, f := range poms {
		body[f.path()] = f.xml()
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if strings.HasSuffix(r.URL.Path, ".pom") {
			hits[r.URL.Path]++
		}
		doc, ok := body[r.URL.Path]
		mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(doc))
	}))
	t.Cleanup(srv.Close)

	p := newRegistryMetadataProvider()
	p.endpoints = defaultRegistryEndpoints()
	p.endpoints.maven = srv.URL
	p.endpoints.mavenGoogle = ""
	// Keep the run offline apart from this server: the star/SCM
	// enrichment paths must not reach the real internet.
	p.endpoints.github = srv.URL
	p.endpoints.gitlab = srv.URL
	p.endpoints.bitbucket = srv.URL
	p.endpoints.codeberg = srv.URL
	p.endpoints.depsdev = srv.URL

	hitsFor := func(path string) int {
		mu.Lock()
		defer mu.Unlock()
		return hits[path]
	}
	total := func() int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, v := range hits {
			n += v
		}
		return n
	}
	return p, hitsFor, total
}

func runMavenLicense(t *testing.T, p *registryMetadataProvider, pkg, ver string) string {
	t.Helper()
	pr, err := p.runMaven(context.Background(), pkg, ver)
	if err != nil {
		t.Fatalf("runMaven(%s@%s): %v", pkg, ver, err)
	}
	if pr.Metadata == nil {
		return ""
	}
	return pr.Metadata.LicenseExpression
}

// The headline case. guava 33.0.0-jre declares no licence; guava-parent
// does. This test fails on the pre-fix reader with LicenseExpression="".
func TestMavenLicenseInheritedFromParentPOM(t *testing.T) {
	child := pomFixture{group: "com.google.guava", artifact: "guava", version: "33.0.0-jre",
		parent: "com.google.guava:guava-parent:33.0.0-jre"}
	parent := pomFixture{group: "com.google.guava", artifact: "guava-parent", version: "33.0.0-jre",
		licenses: []string{"Apache License, Version 2.0"}}
	p, hitsFor, _ := mavenPOMServer(t, child, parent)

	got := runMavenLicense(t, p, "com.google.guava:guava", "33.0.0-jre")
	if got != "Apache License, Version 2.0" {
		t.Fatalf("LicenseExpression = %q, want the parent's Apache-2.0 — "+
			"guava scores lic.missing + license.unidentified without it", got)
	}
	if n := hitsFor(parent.path()); n != 1 {
		t.Errorf("parent POM fetched %d times, want exactly 1", n)
	}
}

// log4j-core shape: two hops. The immediate parent (a BOM) carries no
// licence either; the grandparent does.
func TestMavenLicenseInheritedTwoLevelsUp(t *testing.T) {
	child := pomFixture{group: "org.apache.logging.log4j", artifact: "log4j-core", version: "2.24.3",
		parent: "org.apache.logging.log4j:log4j:2.24.3"}
	mid := pomFixture{group: "org.apache.logging.log4j", artifact: "log4j", version: "2.24.3",
		parent: "org.apache.logging:logging-parent:11.3.0"}
	top := pomFixture{group: "org.apache.logging", artifact: "logging-parent", version: "11.3.0",
		licenses: []string{"Apache-2.0"}}
	p, _, _ := mavenPOMServer(t, child, mid, top)

	if got := runMavenLicense(t, p, "org.apache.logging.log4j:log4j-core", "2.24.3"); got != "Apache-2.0" {
		t.Fatalf("LicenseExpression = %q, want Apache-2.0 from the grandparent", got)
	}
}

// An artifact that declares its OWN licence must never touch the network
// for a parent, even when it has one.
func TestMavenOwnLicenseSkipsParentFetch(t *testing.T) {
	child := pomFixture{group: "com.google.guava", artifact: "guava", version: "33.0.0-jre",
		parent:   "com.google.guava:guava-parent:33.0.0-jre",
		licenses: []string{"MIT"}}
	parent := pomFixture{group: "com.google.guava", artifact: "guava-parent", version: "33.0.0-jre",
		licenses: []string{"Apache License, Version 2.0"}}
	p, hitsFor, _ := mavenPOMServer(t, child, parent)

	if got := runMavenLicense(t, p, "com.google.guava:guava", "33.0.0-jre"); got != "MIT" {
		t.Fatalf("LicenseExpression = %q, want the artifact's own MIT", got)
	}
	if n := hitsFor(parent.path()); n != 0 {
		t.Errorf("parent POM fetched %d time(s) for an artifact that declares its own licence", n)
	}
}

// A POM whose <parent> is itself must terminate, and must do so after a
// single fetch attempt.
func TestMavenSelfReferentialParentTerminates(t *testing.T) {
	self := pomFixture{group: "org.example", artifact: "loop", version: "1.0.0",
		parent: "org.example:loop:1.0.0"}
	p, hitsFor, _ := mavenPOMServer(t, self)

	if got := runMavenLicense(t, p, "org.example:loop", "1.0.0"); got != "" {
		t.Fatalf("LicenseExpression = %q, want silence", got)
	}
	// One fetch: the artifact's own POM. The parent coordinate is the
	// same coordinate, so it is never re-requested.
	if n := hitsFor(self.path()); n != 1 {
		t.Errorf("own POM fetched %d times, want 1 — the self-parent was re-fetched", n)
	}
}

// A -> B -> A cycle must terminate without re-fetching A.
func TestMavenParentCycleTerminates(t *testing.T) {
	a := pomFixture{group: "org.example", artifact: "a", version: "1.0.0", parent: "org.example:b:1.0.0"}
	b := pomFixture{group: "org.example", artifact: "b", version: "1.0.0", parent: "org.example:a:1.0.0"}
	p, hitsFor, total := mavenPOMServer(t, a, b)

	if got := runMavenLicense(t, p, "org.example:a", "1.0.0"); got != "" {
		t.Fatalf("LicenseExpression = %q, want silence", got)
	}
	if n := hitsFor(a.path()); n != 1 {
		t.Errorf("A fetched %d times, want 1 — the cycle came back around", n)
	}
	if n := total(); n != 2 {
		t.Errorf("%d POM requests for an A->B->A cycle, want 2", n)
	}
}

// The walk is depth-bounded. A chain longer than the limit stops, and
// stops at the limit rather than one hop early or late.
func TestMavenParentDepthLimitEnforced(t *testing.T) {
	var poms []pomFixture
	chainLen := maxMavenParentDepth + 3
	for i := 0; i <= chainLen; i++ {
		f := pomFixture{group: "org.example", artifact: fmt.Sprintf("p%d", i), version: "1.0.0"}
		if i < chainLen {
			f.parent = fmt.Sprintf("org.example:p%d:1.0.0", i+1)
		} else {
			f.licenses = []string{"Apache-2.0"} // beyond reach, on purpose
		}
		poms = append(poms, f)
	}
	p, _, total := mavenPOMServer(t, poms...)

	if got := runMavenLicense(t, p, "org.example:p0", "1.0.0"); got != "" {
		t.Fatalf("LicenseExpression = %q — a licence past the depth limit was reached", got)
	}
	// 1 own POM + exactly maxMavenParentDepth parent fetches.
	if n, want := total(), 1+maxMavenParentDepth; n != want {
		t.Errorf("%d POM requests, want %d (own + %d parents)", n, want, maxMavenParentDepth)
	}
}

// A parent that 404s is SILENCE, not a licence: the artifact comes back
// exactly as it does today, warnings and all.
func TestMavenUnfetchableParentLeavesArtifactUnchanged(t *testing.T) {
	child := pomFixture{group: "org.example", artifact: "orphan", version: "1.0.0",
		parent: "org.example:missing-parent:9.9.9"}
	p, _, _ := mavenPOMServer(t, child)

	pr, err := p.runMaven(context.Background(), "org.example:orphan", "1.0.0")
	if err != nil {
		t.Fatalf("runMaven: %v", err)
	}
	if pr.Metadata == nil {
		t.Fatal("Metadata section disappeared — the failed parent fetch must not abort the report")
	}
	if pr.Metadata.LicenseExpression != "" {
		t.Errorf("LicenseExpression = %q, want empty", pr.Metadata.LicenseExpression)
	}
	if pr.Artifact == nil || pr.URLs == nil {
		t.Error("the rest of the report was lost on an unfetchable parent")
	}
	for _, w := range pr.Warnings {
		if w.Code == WarnRegistryNotFound || w.Code == WarnPackageNotFound {
			t.Errorf("the parent's 404 leaked out as %q on the artifact", w.Code)
		}
	}
}

// An unresolvable ${property} in a licence name is not a licence.
// Emitting one would put the literal string "${license.name}" where an
// SPDX id belongs — the same class of defect Phase 7 Wave 5 fixed for
// versions.
func TestMavenPlaceholderLicenceNameIsNotEmitted(t *testing.T) {
	child := pomFixture{group: "org.example", artifact: "placeholder", version: "1.0.0",
		parent: "org.example:placeholder-parent:1.0.0"}
	parent := pomFixture{group: "org.example", artifact: "placeholder-parent", version: "1.0.0",
		licenses: []string{"${license.name}"}}
	p, _, _ := mavenPOMServer(t, child, parent)

	if got := runMavenLicense(t, p, "org.example:placeholder", "1.0.0"); got != "" {
		t.Fatalf("LicenseExpression = %q, want silence — a placeholder is not a licence", got)
	}
}

// ...but a placeholder the parent's own <properties> CAN answer is
// resolved, exactly as Maven would.
func TestMavenResolvablePlaceholderLicenceNameIsInterpolated(t *testing.T) {
	child := pomFixture{group: "org.example", artifact: "interp", version: "1.0.0",
		parent: "org.example:interp-parent:1.0.0"}
	parent := pomFixture{group: "org.example", artifact: "interp-parent", version: "1.0.0",
		properties: map[string]string{"license.name": "Apache-2.0"},
		licenses:   []string{"${license.name}"}}
	p, _, _ := mavenPOMServer(t, child, parent)

	if got := runMavenLicense(t, p, "org.example:interp", "1.0.0"); got != "Apache-2.0" {
		t.Fatalf("LicenseExpression = %q, want the interpolated Apache-2.0", got)
	}
}

// <relativePath> is a filesystem hint for a local reactor build. It must
// not change what we ask the registry for.
func TestMavenParentRelativePathIsIgnored(t *testing.T) {
	child := pomFixture{group: "com.google.guava", artifact: "guava", version: "33.0.0-jre",
		parent:         "com.google.guava:guava-parent:33.0.0-jre",
		extraParentXML: "    <relativePath>../pom.xml</relativePath>\n"}
	parent := pomFixture{group: "com.google.guava", artifact: "guava-parent", version: "33.0.0-jre",
		licenses: []string{"Apache License, Version 2.0"}}
	p, hitsFor, _ := mavenPOMServer(t, child, parent)

	if got := runMavenLicense(t, p, "com.google.guava:guava", "33.0.0-jre"); got != "Apache License, Version 2.0" {
		t.Fatalf("LicenseExpression = %q — <relativePath> was not ignored", got)
	}
	if n := hitsFor(parent.path()); n != 1 {
		t.Errorf("parent POM fetched %d times, want 1", n)
	}
}

// A POM is attacker-supplied bytes. A parent coordinate carrying path
// separators or traversal must not become part of a URL.
func TestMavenParentCoordinateIsValidated(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		g, a, v string
		want    bool
	}{
		{"plain", "com.google.guava", "guava-parent", "33.0.0-jre", true},
		{"version with plus", "org.example", "p", "1.0.0+build.1", true},
		{"traversal in group", "../../etc", "p", "1.0.0", false},
		{"slash in artifact", "org.example", "a/b", "1.0.0", false},
		{"placeholder version", "org.example", "p", "${revision}", false},
		{"empty artifact", "org.example", "", "1.0.0", false},
		{"space in version", "org.example", "p", "1.0 0", false},
		{"scheme injection", "org.example", "p", "http://evil.invalid/x", false},
	} {
		if got := isSafeMavenCoordinateSegment(tc.g) &&
			isSafeMavenCoordinateSegment(tc.a) &&
			isSafeMavenCoordinateSegment(tc.v); got != tc.want {
			t.Errorf("%s: coordinate %q:%q:%q accepted=%v, want %v", tc.name, tc.g, tc.a, tc.v, got, tc.want)
		}
	}
}
