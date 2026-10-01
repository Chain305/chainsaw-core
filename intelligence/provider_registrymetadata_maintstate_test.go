package intelligence

// Registry-native maintenance state, one real-shaped fixture per ecosystem
// whose fact was not reaching the report before 2026-09-30 (corpus v1
// stratum D: NuGet paged/SemVer-2 unlisted, Go retract/Deprecated and
// latest-release date, Maven relocation and latest-release date, PyPI PEP 792
// project status, crates.io yank message).

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/mod/modfile"
)

func runStub(t *testing.T, mux *http.ServeMux, eco, pkg, ver string) PartialReport {
	t.Helper()
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: eco, Package: pkg, Version: ver}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return pr
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

const unoNuspecXML = `<?xml version="1.0"?><package><metadata><id>Uno.UI.WebAssembly</id><version>5.0.0-dev.1530</version><authors>Uno</authors></metadata></package>`

// Uno.UI.WebAssembly: a paged registration (no inline leaves) and a SemVer-2
// version that semver1 never lists. Before: no timeline, no latest date, and
// the unlisted state was never read, so it scored allow.
func TestNuGetPagedRegistrationUnlistedAndLatestDate(t *testing.T) {
	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/uno.ui.webassembly/5.0.0-dev.1530/uno.ui.webassembly.nuspec", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(unoNuspecXML))
	})
	mux.HandleFunc("/uno.ui.webassembly/index.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"count":2,"items":[
			{"@id":"`+srvURL+`/uno.ui.webassembly/page/1.0.0/2.0.0.json","count":64,"lower":"1.0.0","upper":"2.0.0"},
			{"@id":"`+srvURL+`/uno.ui.webassembly/page/2.0.1/6.1.0.json","count":64,"lower":"2.0.1","upper":"6.1.0"}]}`)
	})
	mux.HandleFunc("/uno.ui.webassembly/page/2.0.1/6.1.0.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"items":[
			{"catalogEntry":{"version":"6.0.0","published":"2025-01-10T00:00:00+00:00","listed":true}},
			{"catalogEntry":{"version":"6.1.0","published":"2025-03-02T00:00:00+00:00","listed":true}},
			{"catalogEntry":{"version":"6.1.1-dev.1","published":"1900-01-01T00:00:00+00:00","listed":false}}]}`)
	})
	mux.HandleFunc("/uno.ui.webassembly/5.0.0-dev.1530.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"@id":"x","listed":false,"published":"1900-01-01T00:00:00+00:00"}`)
	})
	p, srv := newStubProvider(t, mux)
	srvURL = srv.URL
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "nuget", Package: "Uno.UI.WebAssembly", Version: "5.0.0-dev.1530"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Release == nil || pr.Release.Yanked == nil || !*pr.Release.Yanked {
		t.Fatalf("unlisted SemVer-2 version not flagged: %+v", pr.Release)
	}
	if pr.Release.Deprecated != "unlisted" || pr.Release.Listed == nil || *pr.Release.Listed {
		t.Errorf("evidence: Deprecated=%q Listed=%v", pr.Release.Deprecated, pr.Release.Listed)
	}
	if pr.Release.LatestVersion != "6.1.0" {
		t.Errorf("LatestVersion = %q, want 6.1.0 (unlisted 1900 entry must not win)", pr.Release.LatestVersion)
	}
	want := time.Date(2025, 3, 2, 0, 0, 0, 0, time.UTC)
	if pr.Maintenance == nil || pr.Maintenance.LatestReleaseAt == nil || !pr.Maintenance.LatestReleaseAt.Equal(want) {
		t.Errorf("LatestReleaseAt = %+v, want %v", pr.Maintenance, want)
	}
	if pr.Maintenance != nil && len(pr.Maintenance.VersionTimeline) != 0 {
		t.Errorf("a partial (last-page) timeline leaked: %d entries", len(pr.Maintenance.VersionTimeline))
	}
	if pr.Release.VersionDate != nil {
		t.Errorf("the 1900 unlisted sentinel was taken as a publish date: %v", pr.Release.VersionDate)
	}
}

// An inline registration that lists the version answers the question
// already: no leaf request, and a listed version is not flagged.
func TestNuGetInlineListedVersionSkipsLeaf(t *testing.T) {
	var leafHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/uno.ui.webassembly/5.0.0-dev.1530/uno.ui.webassembly.nuspec", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(unoNuspecXML))
	})
	mux.HandleFunc("/uno.ui.webassembly/index.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"items":[{"items":[{"catalogEntry":{"version":"5.0.0-dev.1530","published":"2024-02-01T00:00:00+00:00","listed":true}}]}]}`)
	})
	mux.HandleFunc("/uno.ui.webassembly/5.0.0-dev.1530.json", func(w http.ResponseWriter, r *http.Request) {
		leafHits.Add(1)
		writeJSON(w, `{"listed":false}`)
	})
	pr := runStub(t, mux, "nuget", "Uno.UI.WebAssembly", "5.0.0-dev.1530")
	if pr.Release != nil && pr.Release.Yanked != nil && *pr.Release.Yanked {
		t.Fatalf("listed version flagged as unlisted")
	}
	if n := leafHits.Load(); n != 0 {
		t.Errorf("leaf fetched %d times for a version the inline index already covers", n)
	}
}

func goStub(latestMod string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		u := r.RequestURI
		switch {
		case strings.HasSuffix(u, "/@v/v1.2.0.info"):
			writeJSON(w, `{"Version":"v1.2.0","Time":"2021-05-18T20:19:04Z"}`)
		case strings.HasSuffix(u, "/@latest"):
			writeJSON(w, `{"Version":"v1.3.0","Time":"2022-02-01T10:00:00Z"}`)
		case strings.HasSuffix(u, "/@v/list"):
			_, _ = w.Write([]byte("v1.2.0\nv1.3.0\n"))
		case strings.HasSuffix(u, "/@v/v1.2.0.mod"):
			_, _ = w.Write([]byte("module example.com/m\n\ngo 1.21\n"))
		case strings.HasSuffix(u, "/@v/v1.3.0.mod"):
			_, _ = w.Write([]byte(latestMod))
		default:
			http.NotFound(w, r)
		}
	})
	return mux
}

func TestGoRetractedAndDeprecatedFromLatestGoMod(t *testing.T) {
	pr := runStub(t, goStub("// Deprecated: use example.com/m/v2 instead.\nmodule example.com/m\n\ngo 1.21\n\nretract [v1.1.0, v1.2.5] // leaks credentials\n"),
		"go", "example.com/m", "v1.2.0")
	if pr.Release == nil || pr.Release.Yanked == nil || !*pr.Release.Yanked {
		t.Fatalf("retracted version not flagged: %+v", pr.Release)
	}
	if got := pr.Release.Deprecated; !strings.Contains(got, "retracted: leaks credentials") || !strings.Contains(got, "deprecated: use example.com/m/v2 instead.") {
		t.Errorf("evidence = %q", got)
	}
	want := time.Date(2022, 2, 1, 10, 0, 0, 0, time.UTC)
	if pr.Maintenance == nil || pr.Maintenance.LatestReleaseAt == nil || !pr.Maintenance.LatestReleaseAt.Equal(want) {
		t.Errorf("LatestReleaseAt from @latest.Time = %+v", pr.Maintenance)
	}
}

func TestGoCleanLatestGoModFlagsNothing(t *testing.T) {
	pr := runStub(t, goStub("module example.com/m\n\ngo 1.21\n\nretract v1.0.0\n"), "go", "example.com/m", "v1.2.0")
	if pr.Release != nil && ((pr.Release.Yanked != nil && *pr.Release.Yanked) || pr.Release.Deprecated != "") {
		t.Fatalf("un-retracted, un-deprecated version flagged: %+v", pr.Release)
	}
}

func TestGoModStateRangeBounds(t *testing.T) {
	f, err := modfile.ParseLax("go.mod", []byte("module m\n\nretract [v1.1.0, v1.2.0]\nretract v0.9.0 // typo\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for ver, want := range map[string]bool{"v1.1.0": true, "v1.2.0": true, "v1.1.5": true, "v1.2.1": false, "v1.0.9": false, "v0.9.0": true, "not-semver": false} {
		if got, _ := goModState(f, ver); got != want {
			t.Errorf("goModState(%s) = %v, want %v", ver, got, want)
		}
	}
	if _, why := goModState(f, "v0.9.0"); why != "retracted: typo" {
		t.Errorf("rationale = %q", why)
	}
}

func TestMavenRelocationAndLastUpdated(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/mysql/mysql-connector-java/8.0.33/mysql-connector-java-8.0.33.pom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Last-Modified", "Tue, 18 Apr 2023 14:39:50 GMT")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion>
			<groupId>mysql</groupId><artifactId>mysql-connector-java</artifactId><version>8.0.33</version>
			<distributionManagement><relocation><groupId>com.mysql</groupId><artifactId>mysql-connector-j</artifactId>
			<message>MySQL Connector/J artifacts moved to reverse-DNS compliant Maven 2+ coordinates.</message></relocation></distributionManagement></project>`))
	})
	mux.HandleFunc("/mysql/mysql-connector-java/maven-metadata.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<metadata><groupId>mysql</groupId><artifactId>mysql-connector-java</artifactId><versioning>
			<latest>8.0.33</latest><release>8.0.33</release><versions><version>8.0.32</version><version>8.0.33</version></versions>
			<lastUpdated>20230418144015</lastUpdated></versioning></metadata>`))
	})
	pr := runStub(t, mux, "maven", "mysql:mysql-connector-java", "8.0.33")
	if pr.Release == nil || pr.Release.RelocatedTo != "com.mysql:mysql-connector-j:8.0.33 (MySQL Connector/J artifacts moved to reverse-DNS compliant Maven 2+ coordinates.)" {
		t.Fatalf("RelocatedTo = %+v", pr.Release)
	}
	if pr.Release.Deprecated != "" || (pr.Release.Yanked != nil && *pr.Release.Yanked) {
		t.Errorf("relocation must not ride the deprecated/yanked (warn) path: %+v", pr.Release)
	}
	want := time.Date(2023, 4, 18, 14, 40, 15, 0, time.UTC)
	if pr.Maintenance == nil || pr.Maintenance.LatestReleaseAt == nil || !pr.Maintenance.LatestReleaseAt.Equal(want) {
		t.Errorf("LatestReleaseAt from <lastUpdated> = %+v", pr.Maintenance)
	}
	if vd := pr.Release.VersionDate; vd == nil || !vd.Equal(time.Date(2023, 4, 18, 14, 39, 50, 0, time.UTC)) {
		t.Errorf("VersionDate from the POM Last-Modified = %v", vd)
	}
}

func pypiStub(simpleHead string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/pypi/oldpkg/1.0/json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"info":{"name":"oldpkg","version":"1.0","yanked":false},"urls":[]}`)
	})
	mux.HandleFunc("/pypi/oldpkg/json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"info":{"version":"1.0"},"releases":{"1.0":[{"upload_time_iso_8601":"2019-01-01T00:00:00Z"}]}}`)
	})
	mux.HandleFunc("/simple/oldpkg/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!DOCTYPE html>\n<html lang=\"en\">\n  <head>\n    <meta name=\"pypi:repository-version\" content=\"1.4\">\n" + simpleHead +
			"    <title>Links for oldpkg</title>\n  </head>\n  <body><a href=\"x\">oldpkg-1.0.tar.gz</a></body></html>"))
	})
	return mux
}

func TestPyPIProjectStatusArchived(t *testing.T) {
	pr := runStub(t, pypiStub(`<meta name="pypi:project-status" content="archived"><meta name="pypi:project-status-reason" content="Moved to &quot;newpkg&quot;">`), "pypi", "oldpkg", "1.0")
	if pr.Release == nil || pr.Release.Deprecated != `project status: archived: Moved to "newpkg"` {
		t.Fatalf("Deprecated = %+v", pr.Release)
	}
}

func TestPyPIProjectStatusActiveIsSilent(t *testing.T) {
	pr := runStub(t, pypiStub(`<meta name="pypi:project-status" content="active">`), "pypi", "oldpkg", "1.0")
	if pr.Release == nil || pr.Release.Deprecated != "" {
		t.Fatalf("active project flagged: %+v", pr.Release)
	}
}

func TestCargoYankMessageIsEvidence(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/crates/foo/0.1.0", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"crate":{"name":"foo"},"version":{"num":"0.1.0","created_at":"2024-01-01T00:00:00Z","yanked":true,"yank_message":"security issue, use 0.1.1"}}`)
	})
	pr := runStub(t, mux, "cargo", "foo", "0.1.0")
	if pr.Release == nil || pr.Release.Deprecated != "yanked: security issue, use 0.1.1" {
		t.Fatalf("Deprecated = %+v", pr.Release)
	}
}

func rubyGemsStub(pageStatus int, page string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/rubygems/rest-client/versions/1.6.10.json", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "This version could not be found.", http.StatusNotFound)
	})
	mux.HandleFunc("/api/v1/versions/rest-client.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `[{"number":"2.1.0","created_at":"2019-08-21T00:00:00Z","prerelease":false},{"number":"1.6.9","created_at":"2015-03-01T00:00:00Z","prerelease":false}]`)
	})
	mux.HandleFunc("/gems/rest-client/versions/1.6.10", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(pageStatus)
		_, _ = w.Write([]byte(page))
	})
	return mux
}

// rest-client 1.6.10 (yanked 2019, compromised): absent from the API's
// version list, but rubygems.org's version page says it was yanked.
func TestRubyGemsYankedVersionIsAWithdrawalNotAMissingVersion(t *testing.T) {
	pr := runStub(t, rubyGemsStub(http.StatusOK, `<div><svg></svg><span class="align-middle">
      This version has been yanked, and it is not available for download directly or for other gems that may have depended on it.</span></div>`),
		"rubygems", "rest-client", "1.6.10")
	for _, w := range pr.Warnings {
		if w.Code == WarnVersionNotFound {
			t.Fatalf("a yanked version was reported as never published: %+v", pr.Warnings)
		}
	}
	if pr.Release == nil || pr.Release.Yanked == nil || !*pr.Release.Yanked ||
		!strings.Contains(pr.Release.Deprecated, "absent from the registry's version list") {
		t.Fatalf("Release = %+v", pr.Release)
	}
	var licUnavailable bool
	for _, w := range pr.Warnings {
		licUnavailable = licUnavailable || w.Code == WarnLicenseUnavailable
	}
	if !licUnavailable {
		t.Errorf("no metadata was read, so the licence must be marked unavailable: %+v", pr.Warnings)
	}
}

// A version that was never published has a 404 version page: it stays
// version_not_found and is not claimed as yanked.
func TestRubyGemsNeverPublishedVersionIsNotClaimedYanked(t *testing.T) {
	pr := runStub(t, rubyGemsStub(http.StatusNotFound, "Not Found"), "rubygems", "rest-client", "1.6.10")
	if pr.Release != nil && pr.Release.Yanked != nil && *pr.Release.Yanked {
		t.Fatalf("never-published version claimed yanked: %+v", pr.Release)
	}
	var vnf bool
	for _, w := range pr.Warnings {
		vnf = vnf || w.Code == WarnVersionNotFound
	}
	if !vnf {
		t.Fatalf("want version_not_found, got %+v", pr.Warnings)
	}
}

func TestIsPrereleaseVersion(t *testing.T) {
	for _, c := range []struct {
		eco, v string
		want   bool
	}{
		{"npm", "1.0.0", false}, {"npm", "1.0.0-rc.1", true}, {"npm", "1.0.0+build.5", false},
		{"nuget", "5.0.0-dev.1530", true}, {"cargo", "0.2.18", false},
		{"pypi", "1.0a1", true}, {"pypi", "0.1.0.dev0", true}, {"pypi", "2.1.1", false}, {"pypi", "20210216.0.0", false},
		{"maven", "2.24.0.M2", true}, {"maven", "2.9.0.rc2", true}, {"maven", "1.0-SNAPSHOT", true}, {"maven", "33.0.0-jre", false}, {"maven", "3.0.0", false},
		{"rubygems", "1.0.pre", true}, {"rubygems", "19.5", false},
		{"composer", "v1.0-beta", true}, {"composer", "v1.1", false},
		{"go", "v1.3.0", false}, {"go", "v1.3.0-rc.1", true}, {"go", "v0.0.0-20250909063854-5dbd78f73466", false},
	} {
		if got := isPrereleaseVersion(c.eco, c.v); got != c.want {
			t.Errorf("isPrereleaseVersion(%s, %s) = %v, want %v", c.eco, c.v, got, c.want)
		}
	}
}

func TestNewerStableVersion(t *testing.T) {
	d := func(y int) time.Time { return time.Date(y, 1, 1, 0, 0, 0, 0, time.UTC) }
	pinned := d(2013)
	dated := &Report{
		Identity: IdentitySection{Ecosystem: "rubygems", Package: "deep_cloneable", Version: "1.6.0"},
		Maintenance: MaintenanceSection{VersionTimeline: []VersionRelease{
			{Version: "1.6.0", PublishedAt: pinned}, {Version: "3.2.1", PublishedAt: d(2024)},
			{Version: "4.0.0.pre", PublishedAt: d(2025)}, {Version: "1.5.0", PublishedAt: d(2012)},
		}},
	}
	if v, at := newerStableVersion(dated, versionPublishedAt(dated)); v != "3.2.1" || !at.Equal(d(2024)) {
		t.Errorf("dated timeline: got %q %v, want 3.2.1 (the pre-release is newer but must not count)", v, at)
	}
	dated.Identity.Version = "3.2.1"
	if v, _ := newerStableVersion(dated, versionPublishedAt(dated)); v != "" {
		t.Errorf("latest stable pinned: got newer %q", v)
	}
	latestAt := d(2025)
	undated := &Report{
		Identity:    IdentitySection{Ecosystem: "go", Package: "github.com/golang/mobile", Version: "v0.0.0-20190312151609-d3739f865fa6"},
		Release:     ReleaseSection{PublishedAt: &pinned, LatestVersion: "v0.0.0-20250909063854-5dbd78f73466"},
		Maintenance: MaintenanceSection{LatestReleaseAt: &latestAt, VersionTimeline: []VersionRelease{{Version: "v0.1.0"}}},
	}
	if v, _ := newerStableVersion(undated, versionPublishedAt(undated)); v != "v0.0.0-20250909063854-5dbd78f73466" {
		t.Errorf("undated timeline must fall back to the latest label; got %q", v)
	}
	vd := d(2020)
	mvn := &Report{Identity: IdentitySection{Ecosystem: "maven", Version: "2.4.2"}, Release: ReleaseSection{VersionDate: &vd}}
	if at := versionPublishedAt(mvn); at == nil || !at.Equal(vd) {
		t.Errorf("VersionDate fallback not used: %v", at)
	}
}
