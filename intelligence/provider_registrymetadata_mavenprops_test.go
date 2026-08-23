package intelligence

// Tests for same-document Maven property interpolation
// (resolveMavenVersion / mavenPOMProperties / mavenProjectVersion in
// provider_registrymetadata.go).
//
// The strings under test are the ones that were actually live in
// intelligence_reports on 2026-08-23 — ${slf4jVersion},
// ${commons.lang3.version}, ${jsr305.version} — plus ${project.version},
// which never reached the table because cache_warm's hasDigit check already
// rejected it, and which is therefore the shape most likely to be forgotten.
//
// The two halves of the contract are equally load-bearing:
//   - resolvable from THIS document → resolved, so the dependency is warmed
//     and can be matched against advisories;
//   - not resolvable from this document (parent POM, profile, cycle, depth) →
//     left as the literal placeholder, so pinnedVersion and
//     UnevaluableVersionReason both still refuse it.

import (
	"context"
	"encoding/xml"
	"net/http"
	"strings"
	"testing"
)

func TestResolveMavenVersion(t *testing.T) {
	t.Parallel()

	// A representative <properties> block: the three production placeholders,
	// one property that itself refers to another (a real and common shape),
	// one declared-but-empty entry, and the two pathological ones.
	props := map[string]string{
		"slf4jVersion":          "1.7.36",
		"commons.lang3.version": "3.12.0",
		"jsr305.version":        "3.0.2",
		"chained.version":       "${slf4jVersion}",
		"blank.version":         "   ",
		"selfref":               "${selfref}",
		"cycle.a":               "${cycle.b}",
		"cycle.b":               "${cycle.a}",
	}

	cases := []struct {
		name           string
		raw            string
		projectVersion string
		want           string
		reason         string
	}{
		{
			name:   "production slf4jVersion resolves",
			raw:    "${slf4jVersion}",
			want:   "1.7.36",
			reason: "declared in this POM's own <properties>",
		},
		{
			name:   "production commons.lang3.version resolves",
			raw:    "${commons.lang3.version}",
			want:   "3.12.0",
			reason: "dotted property names are ordinary element names",
		},
		{
			name:   "production jsr305.version resolves",
			raw:    "${jsr305.version}",
			want:   "3.0.2",
			reason: "the gradle-ecosystem row from production",
		},
		{
			name:           "project.version resolves from the POM's own version",
			raw:            "${project.version}",
			projectVersion: "2.4.1",
			want:           "2.4.1",
			reason:         "built-in alias, answerable without the hierarchy",
		},
		{
			name:           "pom.version is the Maven 2 spelling of the same alias",
			raw:            "${pom.version}",
			projectVersion: "2.4.1",
			want:           "2.4.1",
		},
		{
			name:           "bare version alias resolves",
			raw:            "${version}",
			projectVersion: "2.4.1",
			want:           "2.4.1",
		},
		{
			name:   "a property whose value is itself a property is expanded",
			raw:    "${chained.version}",
			want:   "1.7.36",
			reason: "requires more than one pass",
		},
		{
			name:   "a placeholder embedded in a larger version resolves in place",
			raw:    "${slf4jVersion}-redhat-1",
			want:   "1.7.36-redhat-1",
			reason: "vendor rebuilds append a suffix to a property",
		},
		{
			name:   "an already-concrete version is untouched",
			raw:    "  4.13.2  ",
			want:   "4.13.2",
			reason: "trimmed only; the fast path must not disturb it",
		},
		{
			name:   "an empty version stays empty",
			raw:    "",
			want:   "",
			reason: "no placeholder, nothing to do",
		},
		{
			name:   "a range constraint is untouched",
			raw:    "[1.0,2.0)",
			want:   "[1.0,2.0)",
			reason: "not a placeholder; ranges are pinnedVersion's problem, not ours",
		},

		// -- deliberately NOT resolved -------------------------------------
		{
			name:   "a property this document does not declare is refused",
			raw:    "${spring.boot.version}",
			want:   "${spring.boot.version}",
			reason: "would need the parent POM or a profile; out of scope by design",
		},
		{
			name:   "project.version with no project version is refused",
			raw:    "${project.version}",
			want:   "${project.version}",
			reason: "nothing in this document answers it",
		},
		{
			name:   "a declared-but-empty property is refused",
			raw:    "${blank.version}",
			want:   "${blank.version}",
			reason: "interpolating to nothing yields a versionless dependency",
		},
		{
			name:   "a self-referential property terminates and is refused",
			raw:    "${selfref}",
			want:   "${selfref}",
			reason: "<a>${a}</a> must not recurse forever",
		},
		{
			name:   "a two-property cycle terminates and is refused",
			raw:    "${cycle.a}",
			want:   "${cycle.a}",
			reason: "a→b→a must not recurse forever",
		},
		{
			name:   "a truncated placeholder is refused",
			raw:    "${slf4jVersion",
			want:   "${slf4jVersion",
			reason: "no closing brace; must not be half-substituted",
		},
		{
			name: "an empty property name is refused",
			raw:  "${}",
			want: "${}",
		},
		{
			name:   "a partially-resolvable version is refused whole",
			raw:    "${slf4jVersion}-${unknown.qualifier}",
			want:   "${slf4jVersion}-${unknown.qualifier}",
			reason: "a half-substituted string is a guess, and a wrong version is worse than none",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := resolveMavenVersion(tc.raw, props, tc.projectVersion)
			if got != tc.want {
				t.Fatalf("resolveMavenVersion(%q, props, %q) = %q, want %q%s",
					tc.raw, tc.projectVersion, got, tc.want, reasonSuffix(tc.reason))
			}
		})
	}
}

func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return " — " + reason
}

// TestResolveMavenVersion_DeepNestTerminates walks a chain longer than
// maxMavenPropertyDepth. It must return the raw placeholder rather than
// looping, and it must do so without the caller noticing a hang.
func TestResolveMavenVersion_DeepNestTerminates(t *testing.T) {
	t.Parallel()

	// p0 → p1 → … → p(n) where n is well past the cap, ending at a concrete
	// value. Legitimate POMs nest one or two deep; this is the hostile shape.
	const depth = maxMavenPropertyDepth + 5
	props := map[string]string{}
	for i := 0; i < depth; i++ {
		props["p"+string(rune('a'+i))] = "${p" + string(rune('a'+i+1)) + "}"
	}
	props["p"+string(rune('a'+depth))] = "9.9.9"

	got := resolveMavenVersion("${pa}", props, "")
	if got != "${pa}" {
		t.Fatalf("resolveMavenVersion over a %d-deep chain = %q, want the raw placeholder "+
			"— the depth cap must refuse rather than resolve past it", depth, got)
	}
}

// TestResolveMavenVersion_UnresolvedStaysRefusedDownstream is the contract
// between this file and cache_warm.go / version_evaluable.go: whatever
// resolveMavenVersion declines to resolve must still be refused by BOTH
// backstops, and whatever it does resolve must be accepted by them.
func TestResolveMavenVersion_UnresolvedStaysRefusedDownstream(t *testing.T) {
	t.Parallel()

	props := map[string]string{"slf4jVersion": "1.7.36"}

	resolved := resolveMavenVersion("${slf4jVersion}", props, "")
	if got := pinnedVersion(resolved); got != "1.7.36" {
		t.Fatalf("pinnedVersion(%q) = %q, want %q — a resolved property must now be warmable",
			resolved, got, "1.7.36")
	}
	if reason := UnevaluableVersionReason("maven", resolved); reason != "" {
		t.Fatalf("UnevaluableVersionReason(\"maven\", %q) = %q, want \"\" — "+
			"a resolved property names a real release", resolved, reason)
	}

	unresolved := resolveMavenVersion("${spring.boot.version}", props, "")
	if got := pinnedVersion(unresolved); got != "" {
		t.Fatalf("pinnedVersion(%q) = %q, want \"\" — the `${` backstop must still hold",
			unresolved, got)
	}
	if reason := UnevaluableVersionReason("maven", unresolved); reason != UnevaluableVersionUnresolvedProperty {
		t.Fatalf("UnevaluableVersionReason(\"maven\", %q) = %q, want %q",
			unresolved, reason, UnevaluableVersionUnresolvedProperty)
	}
}

// TestMavenPOMProperties covers the XML decoding of the <properties> block —
// the part that cannot be modelled with named struct fields.
func TestMavenPOMProperties(t *testing.T) {
	t.Parallel()

	const body = `<?xml version="1.0"?><project>
		<groupId>com.example</groupId>
		<artifactId>demo</artifactId>
		<version>2.4.1</version>
		<properties>
			<slf4jVersion>1.7.36</slf4jVersion>
			<commons.lang3.version>  3.12.0  </commons.lang3.version>
			<project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
		</properties>
	</project>`

	var pom mavenPOM
	if err := xml.Unmarshal([]byte(body), &pom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	props := mavenPOMProperties(&pom)
	if props["slf4jVersion"] != "1.7.36" {
		t.Errorf("slf4jVersion = %q, want 1.7.36", props["slf4jVersion"])
	}
	if props["commons.lang3.version"] != "3.12.0" {
		t.Errorf("commons.lang3.version = %q, want 3.12.0 (whitespace trimmed)",
			props["commons.lang3.version"])
	}
	if props["project.build.sourceEncoding"] != "UTF-8" {
		t.Errorf("non-version properties are collected too: got %q",
			props["project.build.sourceEncoding"])
	}
	if got := mavenProjectVersion(&pom, "9.9.9"); got != "2.4.1" {
		t.Errorf("mavenProjectVersion = %q, want 2.4.1 (the POM's own <version> wins)", got)
	}

	// A POM that omits <version> inherits it from <parent> — still the same
	// document, still no fetch.
	const inherited = `<?xml version="1.0"?><project>
		<parent><groupId>com.example</groupId><version>5.0.0</version></parent>
		<artifactId>child</artifactId>
	</project>`
	var childPOM mavenPOM
	if err := xml.Unmarshal([]byte(inherited), &childPOM); err != nil {
		t.Fatalf("unmarshal child: %v", err)
	}
	if got := mavenProjectVersion(&childPOM, "9.9.9"); got != "5.0.0" {
		t.Errorf("mavenProjectVersion for a child POM = %q, want 5.0.0 (<parent><version>)", got)
	}

	// Neither present: fall back to the version whose .pom we fetched, which
	// the artifact path encodes and is therefore correct by construction.
	var bare mavenPOM
	if got := mavenProjectVersion(&bare, "9.9.9"); got != "9.9.9" {
		t.Errorf("mavenProjectVersion with no declaration = %q, want the requested 9.9.9", got)
	}
	if props := mavenPOMProperties(&bare); props != nil {
		t.Errorf("mavenPOMProperties on a POM with no <properties> = %v, want nil", props)
	}
	if props := mavenPOMProperties(nil); props != nil {
		t.Errorf("mavenPOMProperties(nil) = %v, want nil", props)
	}
}

// TestRegistryMetadataProvider_MavenResolvesPropertyVersions is the
// end-to-end case: a POM shaped exactly like the ones that produced the
// production rows. The three declared properties must arrive on
// DependencyRef.Constraint as concrete versions, ${project.version} must
// resolve to the POM's own version, and the parent-inherited property must
// arrive still unresolved.
func TestRegistryMetadataProvider_MavenResolvesPropertyVersions(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/com/example/demo/2.4.1/demo-2.4.1.pom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><project>
			<groupId>com.example</groupId>
			<artifactId>demo</artifactId>
			<version>2.4.1</version>
			<properties>
				<slf4jVersion>1.7.36</slf4jVersion>
				<commons.lang3.version>3.12.0</commons.lang3.version>
				<jsr305.version>3.0.2</jsr305.version>
			</properties>
			<dependencies>
				<dependency>
					<groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId>
					<version>${slf4jVersion}</version>
				</dependency>
				<dependency>
					<groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId>
					<version>${commons.lang3.version}</version>
				</dependency>
				<dependency>
					<groupId>com.google.code.findbugs</groupId><artifactId>jsr305</artifactId>
					<version>${jsr305.version}</version>
				</dependency>
				<dependency>
					<groupId>com.example</groupId><artifactId>demo-core</artifactId>
					<version>${project.version}</version>
				</dependency>
				<dependency>
					<groupId>org.springframework.boot</groupId><artifactId>spring-boot</artifactId>
					<version>${spring.boot.version}</version>
				</dependency>
			</dependencies>
		</project>`))
	})
	mux.HandleFunc("/com/example/demo/maven-metadata.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><metadata><versioning><latest>2.4.1</latest><versions><version>2.4.1</version></versions></versioning></metadata>`))
	})

	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(),
		Request{Key: Key{Ecosystem: "maven", Package: "com.example:demo", Version: "2.4.1"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Dependencies == nil {
		t.Fatal("no Dependencies section")
	}

	got := map[string]string{}
	for _, d := range pr.Dependencies.Direct {
		got[d.Name] = d.Constraint
	}

	want := map[string]string{
		"org.slf4j:slf4j-api":                  "1.7.36",
		"org.apache.commons:commons-lang3":     "3.12.0",
		"com.google.code.findbugs:jsr305":      "3.0.2",
		"com.example:demo-core":                "2.4.1",
		"org.springframework.boot:spring-boot": "${spring.boot.version}",
	}
	for name, wantVer := range want {
		if got[name] != wantVer {
			t.Errorf("dependency %s constraint = %q, want %q", name, got[name], wantVer)
		}
	}

	// The resolved four must be warmable; the parent-inherited one must not.
	for name, ver := range got {
		pinned := pinnedVersion(ver)
		if strings.Contains(ver, "${") {
			if pinned != "" {
				t.Errorf("%s: pinnedVersion(%q) = %q, want \"\" — an unresolved property "+
					"must never be warmed into intelligence_reports", name, ver, pinned)
			}
			continue
		}
		if pinned == "" {
			t.Errorf("%s: pinnedVersion(%q) = \"\" — a resolved property must be warmable, "+
				"that is the coverage this change recovers", name, ver)
		}
	}
}
