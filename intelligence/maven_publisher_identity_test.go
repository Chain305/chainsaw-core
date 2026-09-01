package intelligence

import (
	"context"
	"net/http"
	"reflect"
	"testing"
)

// P8-70. The publisher-set diff that drives sc.publisher_changed (SevHigh,
// -25, MaxImpact 40, and the -55 CompoundSCTakeoverSignature) compares an
// INCOMING set built here in runMaven against a BASELINE set built by
// internal/server's fetchMavenPublisherSet. Before this fix the two used
// different POM elements as the identity — `<email>`/`<name>` here, `<id>`
// there — so the sets never intersected and the diff reported a total
// publisher replacement on every maven coordinate that had ever been
// scanned before. 30 of 30 flagged prod rows were manufactured this way.
//
// These tests pin the precedence itself and the wiring of the incoming
// side. The baseline side is pinned by
// TestFetchMavenPublisherSet_UsesSharedIdentityHelper in internal/server.

func TestMavenDeveloperPublisherIDs_PrefersID(t *testing.T) {
	for _, tc := range []struct {
		name             string
		id, email, dname string
		want             []string
	}{
		{"id wins over email and name", "ggregory", "ggregory@apache.org", "Gary Gregory", []string{"ggregory"}},
		{"email when no id", "", "ceki@qos.ch", "Ceki Gulcu", []string{"ceki@qos.ch"}},
		{"name when no id and no email", "", "", "LAMP/EPFL", []string{"LAMP/EPFL"}},
		// The obfuscated Apache spelling. It has no `@`, so the
		// metadiff normaliser cannot unwrap it to an address — which is
		// exactly why an email-keyed identity flipped commons-lang3
		// between 3.12.0 and 3.14.0 on nothing but a POM text edit.
		{"obfuscated email is bypassed by id", "ggregory", "ggregory at apache.org", "Gary Gregory", []string{"ggregory"}},
		{"multi-address email splits", "", "a@x.io, b@y.io", "", []string{"a@x.io", "b@y.io"}},
		{"angle-wrapped email unwraps", "", "Ceki <ceki@qos.ch>", "", []string{"ceki@qos.ch"}},
		{"whitespace-only id falls through", "   ", "ceki@qos.ch", "", []string{"ceki@qos.ch"}},
		{"nothing at all", "", "", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := MavenDeveloperPublisherIDs(tc.id, tc.email, tc.dname)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("MavenDeveloperPublisherIDs(%q,%q,%q) = %v, want %v",
					tc.id, tc.email, tc.dname, got, tc.want)
			}
		})
	}
}

// The incoming side must actually route through the helper. This is the
// regression that produced P8-70: runMaven did not parse `<id>` at all.
//
// The fixture is the real shape of an Apache Commons POM — an `<id>` plus
// the obfuscated "name at host" email — because that is the exact pair
// that made the two extractors disagree in prod.
func TestRegistryMetadataProvider_MavenPublisherIDsUseDeveloperID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/org/apache/commons/commons-text/1.15.0/commons-text-1.15.0.pom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?>
<project>
	<groupId>org.apache.commons</groupId>
	<artifactId>commons-text</artifactId>
	<version>1.15.0</version>
	<developers>
		<developer><id>kinow</id><name>Bruno P. Kinoshita</name><email>kinow@apache.org</email></developer>
		<developer><id>ggregory</id><name>Gary Gregory</name><email>ggregory at apache.org</email></developer>
		<developer><id>djones</id><name>Duncan Jones</name><email>djones@apache.org</email></developer>
	</developers>
</project>`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{
		Ecosystem: "maven", Package: "org.apache.commons:commons-text", Version: "1.15.0",
	}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.People == nil {
		t.Fatal("People section is nil; the POM declares three developers")
	}
	want := []string{"kinow", "ggregory", "djones"}
	if !reflect.DeepEqual(pr.People.PublisherIDs, want) {
		t.Fatalf("People.PublisherIDs = %v, want %v.\n"+
			"PublisherIDs is the MACHINE identity diffed against the persisted "+
			"package_metadata.publisher_set column, which stores POM <developer><id>. "+
			"Emitting emails or display names here makes the two sets disjoint and "+
			"fires sc.publisher_changed (SevHigh, -25) on every maven package with "+
			"scan history. See P8-70 / MavenDeveloperPublisherIDs.",
			pr.People.PublisherIDs, want)
	}
	// The human-readable axes must keep the `Name <email>` render — the
	// fix moves the machine identity only, not the UI People panel.
	if len(pr.People.Maintainers) != 3 || pr.People.Maintainers[1] != "Gary Gregory <ggregory at apache.org>" {
		t.Fatalf("Maintainers should keep the display render, got %v", pr.People.Maintainers)
	}
}

// A developer entry carrying ONLY an `<id>` still contributes a publisher
// identity. The pre-fix code skipped the whole entry when joinAuthor was
// empty, which would silently shrink the incoming set relative to the
// baseline and flag a removal.
func TestRegistryMetadataProvider_MavenIDOnlyDeveloperStillCounts(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/org/example/idonly/1.0.0/idonly-1.0.0.pom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?>
<project>
	<groupId>org.example</groupId><artifactId>idonly</artifactId><version>1.0.0</version>
	<developers><developer><id>solo</id></developer></developers>
</project>`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{
		Ecosystem: "maven", Package: "org.example:idonly", Version: "1.0.0",
	}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.People == nil || !reflect.DeepEqual(pr.People.PublisherIDs, []string{"solo"}) {
		t.Fatalf("PublisherIDs = %+v, want [solo]: an <id>-only developer is a "+
			"publisher even though it renders no display string", pr.People)
	}
}
