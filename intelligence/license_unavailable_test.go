package intelligence

// WarnLicenseUnavailable: a licence fetch that FAILED must not be scored as
// "the package declares no licence". Measured: two identical runs of the
// 400-package benign FP eval disagreed on lic.missing + license.unidentified
// (-30) for 55 coordinates — go github.com/google/go-cmp v0.7.0 whenever
// deps.dev hit its 3s budget, maven/pypi on transport.

import (
	"context"
	"net/http"
	"testing"

	"github.com/chain305/chainsaw-core/coverage"
	"github.com/chain305/chainsaw-core/risk"
)

func hasLicenseUnavailable(ws []Warning) bool {
	for _, w := range ws {
		if w.Provider == "registrymetadata" && w.Code == WarnLicenseUnavailable {
			return true
		}
	}
	return false
}

// -- projection --------------------------------------------------------

func TestProjectLicenseDataUnavailable(t *testing.T) {
	report := func(license string, ws ...Warning) *Report {
		r := &Report{Identity: IdentitySection{Ecosystem: "go", Package: "github.com/google/go-cmp", Version: "v0.7.0"}}
		r.Metadata.LicenseExpression = license
		r.Observation.Warnings = ws
		return r
	}
	licWarn := Warning{Provider: "registrymetadata", Code: WarnLicenseUnavailable}

	in := ProjectToRiskInput(report("", licWarn))
	if !in.LicenseDataUnavailable {
		t.Error("license_unavailable + empty licence: LicenseDataUnavailable=false")
	}
	if in.LicenseTags != nil {
		t.Errorf("license_unavailable + empty licence: LicenseTags=%v, want nil (Classify(\"\") tags it unidentified)", in.LicenseTags)
	}

	in = ProjectToRiskInput(report("BSD-3-Clause", licWarn))
	if in.LicenseDataUnavailable {
		t.Error("license_unavailable + a licence that WAS read: LicenseDataUnavailable=true — a read licence must still score")
	}

	// transport is also emitted by GitHub enrichment AFTER a successful
	// primary fetch; it says nothing about the licence.
	in = ProjectToRiskInput(report("MIT", Warning{Provider: "registrymetadata", Code: "transport"}))
	if in.LicenseDataUnavailable {
		t.Error("a github transport warning marked a present licence unavailable")
	}
	in = ProjectToRiskInput(report("", Warning{Provider: "registrymetadata", Code: "transport"}))
	if in.LicenseDataUnavailable {
		t.Error("transport alone must not be read as a licence failure — key on license_unavailable")
	}
}

// -- provider ----------------------------------------------------------

func TestLicenseUnavailableEmission(t *testing.T) {
	status503 := func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "down", http.StatusServiceUnavailable) }

	t.Run("maven primary POM 503 emits", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/", status503)
		p, _ := newStubProvider(t, mux)
		pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "maven", Package: "org.example:lib", Version: "1.0.0"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !hasLicenseUnavailable(pr.Warnings) {
			t.Fatalf("primary POM 503: no license_unavailable in %+v", pr.Warnings)
		}
	})

	parentCase := func(t *testing.T, parentStatus int) PartialReport {
		child := pomFixture{group: "org.example", artifact: "child", version: "1.0.0", parent: "org.example:parent:1"}
		parent := pomFixture{group: "org.example", artifact: "parent", version: "1"}
		mux := http.NewServeMux()
		mux.HandleFunc(child.path(), func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(child.xml()))
		})
		mux.HandleFunc(parent.path(), func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "x", parentStatus)
		})
		p, _ := newStubProvider(t, mux)
		p.endpoints.mavenGoogle = ""
		pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "maven", Package: "org.example:child", Version: "1.0.0"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if pr.Metadata == nil {
			t.Fatalf("primary POM was served; Metadata must be set: %+v", pr.Warnings)
		}
		return pr
	}
	t.Run("maven parent POM 503 emits", func(t *testing.T) {
		if pr := parentCase(t, http.StatusServiceUnavailable); !hasLicenseUnavailable(pr.Warnings) {
			t.Fatalf("parent 503: no license_unavailable in %+v", pr.Warnings)
		}
	})
	t.Run("maven parent POM 404 stays silent", func(t *testing.T) {
		if pr := parentCase(t, http.StatusNotFound); hasLicenseUnavailable(pr.Warnings) {
			t.Fatalf("parent 404 is a definite absence, not a failure: %+v", pr.Warnings)
		}
	})

	goCase := func(t *testing.T, depsdev http.HandlerFunc) PartialReport {
		mux := http.NewServeMux()
		registerGoBaseRoutes(mux, "github.com/foo/!bar")
		mux.HandleFunc("/v3/systems/go/packages/", depsdev)
		p, _ := newStubProvider(t, mux)
		pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "go", Package: "github.com/foo/Bar", Version: "v1.2.3"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return pr
	}
	t.Run("deps.dev 503 emits", func(t *testing.T) {
		if pr := goCase(t, status503); !hasLicenseUnavailable(pr.Warnings) {
			t.Fatalf("deps.dev 503: no license_unavailable in %+v", pr.Warnings)
		}
	})
	t.Run("deps.dev 200 with no licences stays silent", func(t *testing.T) {
		pr := goCase(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"licenses":[]}`))
		})
		if hasLicenseUnavailable(pr.Warnings) {
			t.Fatalf("deps.dev answered with no licence — a genuine absence, not a failure: %+v", pr.Warnings)
		}
	})
}

// -- end to end --------------------------------------------------------

// The go-cmp shape: the module proxy answers, deps.dev (the only Go licence
// source) fails. Through the real evaluate path, neither licence claim fires.
func TestGoDepsDevFailureDoesNotClaimMissingLicence(t *testing.T) {
	mux := http.NewServeMux()
	registerGoBaseRoutes(mux, "github.com/google/go-cmp")
	mux.HandleFunc("/v3/systems/go/packages/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	})
	p, _ := newStubProvider(t, mux)
	key := Key{Ecosystem: "go", Package: "github.com/google/go-cmp", Version: "v1.2.3"}
	pr, err := p.Run(context.Background(), Request{Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := &Report{Identity: IdentitySection{Ecosystem: key.Ecosystem, Package: key.Package, Version: key.Version}}
	mergePartial(r, pr)
	ComputeTrustScore(r)
	if r.Risk == nil {
		t.Fatal("no risk evaluation")
	}
	for _, f := range r.Risk.DirectScore.Categories[risk.CategoryLicense].FiredSignals {
		if f.ID == risk.SignalLicMissing || f.ID == risk.SignalLicUnidentified {
			t.Errorf("%s fired on a Go module whose licence fetch failed", f.ID)
		}
	}
	if r.Risk.DirectScore.Categories[risk.CategoryLicense].DataAvailable {
		t.Error("License category still counts toward the rollup on a failed licence fetch")
	}
}

// -- coverage ----------------------------------------------------------

// Unavailable, with the registrymetadata enrichment-failure siblings. Not
// not_applicable / error: LedgerFromReport is last-in-slice-wins and either
// would overwrite a primary fetch's own unavailable code.
func TestLicenseUnavailableCoverageStatus(t *testing.T) {
	if got := coverage.StatusForWarnCode(WarnLicenseUnavailable); got != coverage.StatusUnavailable {
		t.Fatalf("StatusForWarnCode(%q) = %q, want %q", WarnLicenseUnavailable, got, coverage.StatusUnavailable)
	}
}
