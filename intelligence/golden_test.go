package intelligence

// golden_test.go is a regression-proof harness over the intelligence
// pipeline using a diverse, deterministic fixture set of well-known
// packages. Each fixture exercises a different signal so any future
// regression breaks a specific named subtest (e.g.
// TestGoldenFixtures/pypi_idna_3.15) instead of a single catch-all.
//
// Design:
//   - One JSON fixture file per package lives under testdata/golden/. Each
//     file carries a `routes` map (or `xml_routes` for Maven) keyed by the
//     URL path served by the registry stub, with each value being the
//     decoded response body. The fixture loader marshals the values back
//     to JSON (or returns the raw XML) and the httptest server replays
//     them — the runtime providers see byte-identical packuments to what
//     the real upstream would emit, just scoped to the small subset of
//     fields the providers consume.
//   - The test stands up a single httptest.Server with a mux that
//     dispatches every fixture's routes simultaneously. A registry
//     metadata provider is then constructed with `endpoints` overridden
//     to the stub URL across every ecosystem, so a Scan against the
//     fixture's coordinate is fully offline.
//   - For the malicious-package fixture (event-stream), a synthetic OSV
//     entry is seeded into a fresh malware.Index and a malwareProvider
//     is wired in alongside.
//   - For each fixture the test asserts the regression invariants listed
//     in its `_comment` field plus the cross-fixture invariants required
//     by the task brief.
//
// The OSV-bundle assertions (Vulns CVEs slice for lodash, non-nil Vulns
// section for requests) are gated with t.Skip pending an `agent-osv`
// integration that wires the internal/intelligence/osv loader into a
// dedicated provider in this package — the loader exists but no Provider
// references it today. Re-enable by deleting the relevant t.Skip lines.
//
// No network is touched; the test must pass with CHAINSAW_OFFLINE=1.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/intelligence/osv"
	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/risk"
)

// goldenFixture is the on-disk shape of one fixture file. We accept
// either JSON `routes` (the common case — npm/pypi/cargo/rubygems) OR
// `xml_routes` (Maven POMs) — the dispatcher serves whichever is set.
type goldenFixture struct {
	Routes    map[string]json.RawMessage `json:"routes,omitempty"`
	XMLRoutes map[string]string          `json:"xml_routes,omitempty"`
}

// loadGoldenFixture reads testdata/golden/<name>.json and returns the
// parsed routes maps. Unknown fields (notably `_comment`) are tolerated
// so the fixture files double as documentation.
func loadGoldenFixture(t *testing.T, name string) goldenFixture {
	t.Helper()
	path := filepath.Join("testdata", "golden", name+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var fx goldenFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}
	return fx
}

// newGoldenStubServer registers every fixture's routes against a single
// httptest server and returns the server. Tests register multiple
// fixtures into the same server so a Scan that hits e.g. both the
// version-specific and the timeline endpoint sees consistent responses.
func newGoldenStubServer(t *testing.T, fixtures map[string]goldenFixture) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for fxName, fx := range fixtures {
		fxName := fxName // capture for closures
		for path, body := range fx.Routes {
			body := body
			mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
			})
			_ = fxName
		}
		for path, xmlBody := range fx.XMLRoutes {
			xmlBody := xmlBody
			mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				_, _ = w.Write([]byte(xmlBody))
			})
		}
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// goldenMaintenanceProvider is the core test double described at its use site
// in TestGoldenFixtures: a minimal Tier-4 maintenance projector standing in
// for the premium maintenanceProvider. It mirrors the two projections the
// golden assertions read — VersionCount from the registry-supplied
// VersionTimeline, and MaintainerCount from the merged PeopleSection.
type goldenMaintenanceProvider struct{}

func (goldenMaintenanceProvider) Name() string         { return "maintenance" }
func (goldenMaintenanceProvider) Signal() SignalMask   { return SignalMaintenance }
func (goldenMaintenanceProvider) Tier() int            { return 4 }
func (goldenMaintenanceProvider) NeedsArtifact() bool  { return false }
func (goldenMaintenanceProvider) Supports(string) bool { return true }

func (goldenMaintenanceProvider) Run(_ context.Context, _ Request, prior *Report) (PartialReport, error) {
	if prior == nil {
		return PartialReport{}, nil
	}
	section := MaintenanceSection{}
	if n := len(prior.Maintenance.VersionTimeline); n > 0 {
		section.VersionCount = n
		if section.LatestReleaseAt == nil {
			var latest time.Time
			for _, v := range prior.Maintenance.VersionTimeline {
				if v.PublishedAt.After(latest) {
					latest = v.PublishedAt
				}
			}
			if !latest.IsZero() {
				section.LatestReleaseAt = &latest
			}
		}
	}
	if count := len(prior.People.Maintainers); count > 0 {
		section.MaintainerCount = count
	}
	if section.VersionCount == 0 && section.MaintainerCount == 0 && section.LatestReleaseAt == nil {
		return PartialReport{}, nil
	}
	return PartialReport{Maintenance: &section}, nil
}

// goldenStubAllEndpoints points the registry provider's endpoints map at
// the stub server's URL for every supported ecosystem. The provider's
// per-ecosystem dispatcher reads only the field that matches the request
// — overriding all of them keeps the helper ecosystem-agnostic.
func goldenStubAllEndpoints(p *registryMetadataProvider, baseURL string) {
	p.endpoints = registryEndpoints{
		npm:               baseURL,
		pypi:              baseURL,
		maven:             baseURL,
		cargo:             baseURL,
		rubygems:          baseURL,
		nuget:             baseURL,
		nugetRegistration: baseURL,
		composer:          baseURL,
		goproxy:           baseURL,
		cocoapods:         baseURL,
		cocoapodsCDN:      baseURL,
		huggingface:       baseURL,
		docker:            baseURL,
		depsdev:           baseURL,
		// github is also redirected so enrichGitHubStars 404s silently
		// against the stub instead of leaking real DNS lookups in CI.
		github: baseURL,
	}
}

// goldenFixtureSet is the canonical set the harness exercises. The
// fixture name (key) doubles as the testdata filename minus extension
// AND the subtest name — when a subtest fails the developer can read
// the fixture's `_comment` field in the file by the same name.
var goldenFixtureSet = []struct {
	name      string
	ecosystem string
	pkg       string
	version   string
}{
	{"pypi_idna_3.15", "pypi", "idna", "3.15"},
	{"pypi_requests_2.31.0", "pypi", "requests", "2.31.0"},
	{"npm_lodash_4.17.20", "npm", "lodash", "4.17.20"},
	{"npm_left-pad_1.3.0", "npm", "left-pad", "1.3.0"},
	{"cargo_serde_1.0.0", "cargo", "serde", "1.0.0"},
	{"rubygems_rails_7.0.0", "rubygems", "rails", "7.0.0"},
	{"maven_commons-lang3_3.12.0", "maven", "org.apache.commons:commons-lang3", "3.12.0"},
	{"npm_event-stream_3.3.6", "npm", "event-stream", "3.3.6"},
}

// goldenOSVBundle is the in-memory OSV advisory bundle the harness
// builds at test time. Three advisories cover the fixtures that exercise
// the OSV path:
//
//   - PyPI idna 3.15 — GHSA-jjg7-2v4v-x38h (CVE-2024-3651). Lets us
//     assert VulnDataAvailable=true on idna without depending on a
//     baked-on-disk bundle.
//   - npm lodash 4.17.20 — CVE-2020-8203 (prototype pollution). Backs
//     the "CVEs slice non-empty" assertion on lodash.
//   - PyPI requests 2.31.0 — synthetic CVE-fixture, used purely so the
//     requests fixture trips a non-nil Vulns section (we don't care
//     which real CVE; the assertion is just "OSV reported something").
//
// The slice is hand-rolled rather than read from testdata so the
// fixture stays inline + visible alongside the assertions that consume
// it. The OSV loader auto-detects gzip vs plain JSON — we hand it raw
// JSON via bytes.NewReader.
func goldenOSVBundle() []osv.Advisory {
	return []osv.Advisory{
		{
			Ecosystem:          "PyPI",
			Package:            "idna",
			VulnerableVersions: []string{"3.15"},
			AdvisoryID:         "GHSA-jjg7-2v4v-x38h",
			Summary:            "idna 3.15 quadratic-time complexity issue (golden-test fixture)",
			CVSSScore:          6.2,
			Severity:           "MEDIUM",
			FixedVersions:      []string{"3.7"},
			Aliases:            []string{"CVE-2024-3651"},
			Published:          "2024-04-12T00:00:00Z",
			Modified:           "2024-04-12T00:00:00Z",
		},
		{
			Ecosystem:          "npm",
			Package:            "lodash",
			VulnerableVersions: []string{"4.17.20"},
			AdvisoryID:         "GHSA-p6mc-m468-83gw",
			Summary:            "lodash <4.17.20 prototype pollution (golden-test fixture)",
			CVSSScore:          7.4,
			Severity:           "HIGH",
			FixedVersions:      []string{"4.17.21"},
			Aliases:            []string{"CVE-2020-8203"},
			Published:          "2020-07-15T00:00:00Z",
			Modified:           "2020-07-15T00:00:00Z",
		},
		{
			Ecosystem:          "PyPI",
			Package:            "requests",
			VulnerableVersions: []string{"2.31.0"},
			AdvisoryID:         "GHSA-9wx4-h78v-vm56",
			Summary:            "requests proxy-auth leak (golden-test fixture)",
			CVSSScore:          5.6,
			Severity:           "MEDIUM",
			FixedVersions:      []string{"2.32.0"},
			Aliases:            []string{"CVE-2024-35195"},
			Published:          "2024-05-20T00:00:00Z",
			Modified:           "2024-05-20T00:00:00Z",
		},
	}
}

// buildGoldenOSVIndex marshals goldenOSVBundle into the on-the-wire
// format and feeds it through osv.Load so the resulting Index is
// byte-for-byte identical to what the production loader would produce
// against the baked-into-image bundle. Failing here is a hard test
// error — fixture infrastructure must work.
func buildGoldenOSVIndex(t *testing.T) *osv.Index {
	t.Helper()
	raw, err := json.Marshal(goldenOSVBundle())
	if err != nil {
		t.Fatalf("marshal OSV bundle: %v", err)
	}
	idx, err := osv.Load(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("osv.Load: %v", err)
	}
	return idx
}

// seedMaliciousMalwareIndex returns a malware.Index pre-loaded with a
// synthetic OSV entry for npm/event-stream@3.3.6. The seed mirrors the
// shape the real OpenSSF feed publishes so a future swap to the live
// loader would not require changing the test surface.
func seedMaliciousMalwareIndex(t *testing.T) *malware.Index {
	t.Helper()
	idx := malware.NewIndex(nil)
	idx.Load([]*malware.OSVEntry{
		{
			ID:        "MAL-2018-EVENT-STREAM",
			Summary:   "event-stream@3.3.6 contained flatmap-stream backdoor (golden-test fixture)",
			Published: time.Date(2018, 11, 26, 0, 0, 0, 0, time.UTC),
			Affected: []malware.OSVAffected{
				{
					Package:  malware.OSVPackage{Ecosystem: "npm", Name: "event-stream"},
					Versions: []string{"3.3.6"},
				},
			},
		},
	})
	return idx
}

// TestGoldenFixtures is the umbrella test. Each fixture becomes a
// t.Run subtest so a regression reports as e.g.
// "TestGoldenFixtures/pypi_idna_3.15".
//
// Acceptance:
//   - go test ./internal/intelligence/ -run TestGoldenFixtures passes
//     all 8 fixtures (some Vulns assertions skip pending agent-osv).
//   - Each fixture has a documented regression-guard comment in
//     testdata/golden/<name>.json (the `_comment` field).
func TestGoldenFixtures(t *testing.T) {
	// Load every fixture up-front so we can register the routes on a
	// single mux. Reusing a single server keeps the harness cheap and
	// lets fixtures that happen to share a path (none today, but a
	// future maven-vs-rubygems duplicate would surface as a panic from
	// mux.HandleFunc — useful early-warning signal).
	fxByName := map[string]goldenFixture{}
	for _, fx := range goldenFixtureSet {
		fxByName[fx.name] = loadGoldenFixture(t, fx.name)
	}
	srv := newGoldenStubServer(t, fxByName)

	// One provider set, reused across subtests. Registry metadata is the
	// substrate everything else reads; malware provider is wired with a
	// pre-seeded index so the event-stream fixture trips it. A Tier-4
	// maintenance provider runs post-merge to project VersionTimeline
	// into VersionCount (the assertion most fixtures hit).
	registry := newRegistryMetadataProvider()
	goldenStubAllEndpoints(registry, srv.URL)
	malwareIdx := seedMaliciousMalwareIndex(t)
	malwareP := newMalwareProvider(malwareIdx)
	// goldenMaintenanceProvider is a core-resident Tier-4 stand-in for the
	// premium maintenanceProvider (now in internal/intelligence/premium,
	// which the core test binary cannot import — that would be a core→
	// premium cycle). It replicates only the projection these golden
	// assertions exercise: VersionCount = len(VersionTimeline) and
	// MaintainerCount = len(People.Maintainers). The premium provider's full
	// behaviour (store fallback, repo-liveness pass-through, latest-release
	// derivation) is unit-tested in the premium package's
	// provider_maintenance_test.go.
	maintP := goldenMaintenanceProvider{}

	// OSV provider: in-package construction with a hand-built in-memory
	// index. We bypass newOSVProvider() because it only loads from disk
	// (env-var path or /data/osv-bundle.json.gz); the same-package
	// access to the unexported `idx` field lets the test wire up a
	// purely in-memory bundle. The osvProvider type stays unexported so
	// production callers must continue going through Bootstrap.
	osvIdx := buildGoldenOSVIndex(t)
	osvP := &osvProvider{idx: osvIdx, logger: slog.Default()}

	svc := New(Config{
		Providers: []Provider{registry, malwareP, maintP, osvP},
		// store left nil — golden tests bypass persistence; the Scan
		// helper handles a nil store gracefully.
	})

	for _, fx := range goldenFixtureSet {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			report, err := svc.Scan(ctx, Request{
				Key:   Key{Ecosystem: fx.ecosystem, Package: fx.pkg, Version: fx.version},
				OrgID: "golden-test-org",
				Options: Options{
					RefreshReason: "golden-test",
					// MaxStaleness=1ns so the (nil) store can't shortcut us
					// to a cached row. Belt-and-suspenders — the New()
					// above also passes a nil Store.
					MaxStaleness: 1,
				},
			})
			if err != nil {
				t.Fatalf("Scan returned err: %v", err)
			}
			if report == nil {
				t.Fatalf("Scan returned nil report")
			}

			// Cross-fixture invariant: the maintenance-category data is
			// available for every fixture because we have registry data
			// for every one. Risk evaluation runs as a post-merge step
			// (ComputeTrustScoreForOrg in runFanout), so Report.Risk
			// must be non-nil and the maintenance category must report
			// dataAvailable=true. The task brief calls this out as the
			// `risk_evaluation.rolledUp.categories.maintenance.dataAvailable`
			// guard for every fixture in this set.
			if report.Risk == nil {
				t.Fatalf("report.Risk is nil — risk evaluation must run for fixtures with registry data")
			}
			maintCat, ok := report.Risk.RolledUp.Categories[risk.CategoryMaintenance]
			if !ok {
				t.Fatalf("risk.RolledUp.Categories[maintenance] missing — got categories %+v", report.Risk.RolledUp.Categories)
			}
			// dataAvailable assertion: maintenance is always available
			// once registry metadata has been fetched (publish dates +
			// maintainer count), so a fixture that has a non-empty
			// Maintenance section MUST have DataAvailable=true. A
			// regression of this (e.g. someone gating maintenance on
			// VersionDataAvailable) would break the public package
			// page's score-ring display.
			t.Run("maintenance_data_available", func(t *testing.T) {
				if !maintCat.DataAvailable {
					t.Errorf("maintCat.DataAvailable=false despite registry metadata being fetched")
				}
			})

			// Fixture-specific invariants below.
			switch fx.name {

			case "pypi_idna_3.15":
				// Regression guard for F1: idna has many published
				// versions; VersionCount must be >= 10. Pre-fix the
				// PyPI timeline fetcher dropped this whole map and the
				// risk engine saw VersionCount=0 → false-fired
				// maint.very_new_package.
				if got := report.Maintenance.VersionCount; got < 10 {
					t.Errorf("VersionCount: got %d, want >= 10 (regression F1)", got)
				}
				// Regression guard: maint.very_new_package MUST NOT fire
				// for idna (it was firing pre-fix).
				for _, sig := range maintCat.FiredSignals {
					if sig.ID == "maint.very_new_package" {
						t.Errorf("maint.very_new_package fired on idna — regression (pre-fix this was the false-positive that justified the F1 fix)")
					}
				}
				// Regression guard: VulnDataAvailable must be true. The
				// OSV provider above is seeded with an idna 3.15 advisory,
				// so VulnSection.ScannedAt is stamped and the risk
				// projector sets VulnDataAvailable=true. Pre-fix this
				// was missing because the OSV path wasn't reaching the
				// projector at all.
				if report.Vulnerabilities.ScannedAt == nil {
					t.Errorf("VulnDataAvailable regression: ScannedAt is nil — OSV provider did not produce a Vulns row for idna 3.15")
				}

			case "pypi_requests_2.31.0":
				// Regression guard for F5 (OSV): must produce a non-nil
				// Vulns section. With the in-memory OSV index seeded
				// with a synthetic requests@2.31.0 advisory, the OSV
				// provider stamps Vulns.ScannedAt and contributes a
				// CVE. Pre-fix the OSV path wasn't running for PyPI
				// fixtures at all, so Vulns stayed zero.
				if report.Vulnerabilities.ScannedAt == nil {
					t.Errorf("Vulns section not populated for requests 2.31.0 — OSV provider regression F5")
				}
				if !report.Vulnerabilities.IsVulnerable {
					t.Errorf("Vulnerabilities.IsVulnerable=false — seeded OSV advisory should flag requests 2.31.0")
				}
				// Always assert the registry path produced a non-empty
				// timeline — that's the substrate the OSV match would
				// later filter on.
				if got := len(report.Maintenance.VersionTimeline); got == 0 {
					t.Errorf("VersionTimeline empty for requests — registry path regressed")
				}

			case "npm_lodash_4.17.20":
				// Always-on: timeline populated from npm packument's
				// `time` map. This is the substrate the OSV match
				// would join against.
				if got := report.Maintenance.VersionCount; got < 5 {
					t.Errorf("VersionCount: got %d, want >= 5 (npm timeline regression)", got)
				}
				// CVEs slice non-empty: the seeded OSV advisory for
				// lodash@4.17.20 (CVE-2020-8203 prototype pollution)
				// must surface on Vulnerabilities.CVEs. Regression
				// guard against the OSV-merge path silently dropping
				// hits when the registry provider already populated
				// the section.
				if len(report.Vulnerabilities.CVEs) == 0 {
					t.Errorf("Vulnerabilities.CVEs empty — lodash 4.17.20 should expose CVE-2020-8203 via OSV")
				}
				foundProtoPollution := false
				for _, cve := range report.Vulnerabilities.CVEs {
					if strings.EqualFold(cve, "CVE-2020-8203") {
						foundProtoPollution = true
						break
					}
				}
				if !foundProtoPollution {
					t.Errorf("expected CVE-2020-8203 in Vulnerabilities.CVEs, got %v", report.Vulnerabilities.CVEs)
				}

			case "npm_left-pad_1.3.0":
				// Basic npm timeline regression guard: VersionCount >= 5.
				if got := report.Maintenance.VersionCount; got < 5 {
					t.Errorf("VersionCount: got %d, want >= 5 (npm timeline regression)", got)
				}

			case "cargo_serde_1.0.0":
				// Regression guard for F2 (cargo): VersionCount >= 50.
				// Pre-fix the cargo timeline fetcher returned only the
				// requested version row; this guards against that.
				if got := report.Maintenance.VersionCount; got < 50 {
					t.Errorf("VersionCount: got %d, want >= 50 (regression F2 cargo)", got)
				}

			case "rubygems_rails_7.0.0":
				// Regression guard for F2 (rubygems): VersionCount >= 50.
				// Rails has 300+ historical releases; the timeline path
				// must walk the entire array, not just the requested
				// version row.
				if got := report.Maintenance.VersionCount; got < 50 {
					t.Errorf("VersionCount: got %d, want >= 50 (regression F2 rubygems)", got)
				}

			case "maven_commons-lang3_3.12.0":
				// Known-good baseline: scan completes without raising
				// any provider-error warnings. Other warnings (timeouts
				// against unstubbed endpoints) are tolerated only when
				// they originate from a provider OTHER than the registry
				// metadata path, since we explicitly served the POM.
				for _, w := range report.Observation.Warnings {
					if w.Provider == "registrymetadata" && strings.Contains(w.Message, "parse") {
						t.Errorf("unexpected parse warning from registrymetadata: %+v", w)
					}
				}
				// Sanity: the POM populated the license + source repo
				// — these are the canonical "happy path" fields the
				// downstream license-policy and repolink checks read.
				if got := report.Metadata.LicenseExpression; got == "" {
					t.Errorf("LicenseExpression empty — POM <licenses> did not parse")
				}
				if got := report.URLs.SourceRepoURL; got == "" {
					t.Errorf("SourceRepoURL empty — POM <scm><url> did not parse")
				}

			case "npm_event-stream_3.3.6":
				// Malicious-package guard. The seeded OSV entry above
				// is keyed on (npm, event-stream, 3.3.6); the malware
				// provider must surface MalwareStatus="malicious".
				// The task brief uses the word "confirmed" but the
				// code's canonical status string is "malicious" — the
				// task verdict-block path keys on "malicious".
				if got := report.SupplyChain.MalwareStatus; got != "malicious" {
					t.Errorf("MalwareStatus: got %q, want %q (malicious-package regression guard)", got, "malicious")
				}
				if report.SupplyChain.MalwareID == "" {
					t.Errorf("MalwareID empty — seeded OSV record should have surfaced an ID")
				}
			}
		})
	}
}
