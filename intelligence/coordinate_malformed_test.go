package intelligence

// Tests for the coordinate_malformed syntax gate (Phase 9 fresh QA, A5 and
// A5-ext). The rejects are names no registry can serve; the controls are
// the names most likely to be caught by an over-eager rule — legacy
// mixed-case npm names, scoped npm names, /v2 Go suffixes, five-part Maven
// coordinates. Every control MUST score, because a control that stops
// scoring is a sticky-fact flip on a real coordinate.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/coverage"
	"github.com/chain305/chainsaw-core/risk"
)

// assertNotScored builds a Report for the coordinate, runs it through the
// ingest stamp and the projection, and requires the NOT EVALUATED shape:
// SignalsUnavailable with a reason, verdict Unknown, never Allow.
func assertNotScored(t *testing.T, eco, pkg, ver string) {
	t.Helper()
	if reason := MalformedCoordinateReason(eco, pkg); reason == "" {
		t.Fatalf("MalformedCoordinateReason(%q, %q) = \"\" — expected a reject", eco, pkg)
	}
	r := &Report{Identity: IdentitySection{Ecosystem: eco, Package: pkg, Version: ver}}
	if !markMalformedCoordinate(r, time.Now()) {
		t.Fatalf("markMalformedCoordinate did not stamp %s %q", eco, pkg)
	}
	in := ProjectToRiskInput(r)
	if !in.SignalsUnavailable {
		t.Fatalf("SignalsUnavailable = false for %s %q — a syntactically impossible "+
			"coordinate must not be scored as though the facts were complete", eco, pkg)
	}
	if in.UnavailableReason == "" {
		t.Error("UnavailableReason is empty; the UI renders this clause")
	}
	eval := risk.EvaluatePackage(in, risk.Options{})
	if eval == nil {
		t.Fatal("EvaluatePackage returned nil")
	}
	if eval.Verdict == risk.VerdictAllow {
		t.Errorf("verdict = allow for %s %q — reads as scanned-and-clean", eco, pkg)
	}
	if eval.Verdict != risk.VerdictUnknown {
		t.Errorf("verdict = %q, want %q", eval.Verdict, risk.VerdictUnknown)
	}
}

// assertScored is the control: the predicate is empty, nothing is stamped,
// and the projection does not take an unavailability return.
func assertScored(t *testing.T, eco, pkg, ver string) {
	t.Helper()
	if reason := MalformedCoordinateReason(eco, pkg); reason != "" {
		t.Fatalf("MalformedCoordinateReason(%q, %q) = %q — a coordinate a registry "+
			"serves was rejected (sticky-fact flip)", eco, pkg, reason)
	}
	r := &Report{Identity: IdentitySection{Ecosystem: eco, Package: pkg, Version: ver}}
	if markMalformedCoordinate(r, time.Now()) {
		t.Fatalf("markMalformedCoordinate stamped %s %q", eco, pkg)
	}
	if len(r.Observation.Warnings) != 0 {
		t.Fatalf("control %s %q picked up %d warnings", eco, pkg, len(r.Observation.Warnings))
	}
	if in := ProjectToRiskInput(r); in.SignalsUnavailable {
		t.Fatalf("SignalsUnavailable = true for %s %q — the gate is over-broad", eco, pkg)
	}
}

func TestMalformedGoModulePathIsNotScored(t *testing.T) {
	rejects := []string{
		"invalid-module-path-xyz", // no dot in the first element
		"INVALID",                 // ditto, and uppercase host
		"../x",                    // path traversal element
		"Github.com/x/y",          // uppercase in the first element
		"github.com/x/y/v1",       // v1 is never a major-version suffix
	}
	for _, eco := range []string{"go", "gomod"} {
		for _, p := range rejects {
			t.Run(eco+"/reject/"+p, func(t *testing.T) { assertNotScored(t, eco, p, "v1.0.0") })
		}
	}
	controls := []string{
		"github.com/BurntSushi/toml", // mixed case after the host is legal
		"gopkg.in/yaml.v2",           // gopkg.in's dotted-version convention
		"golang.org/x/net",
		"k8s.io/api",
		"github.com/x/y/v2", // a real major-version suffix
	}
	for _, eco := range []string{"go", "gomod"} {
		for _, p := range controls {
			t.Run(eco+"/control/"+p, func(t *testing.T) { assertScored(t, eco, p, "v1.0.0") })
		}
	}
}

func TestMalformedMavenCoordinateIsNotScored(t *testing.T) {
	rejects := []string{":x", "a:", "a: :c"}
	for _, eco := range []string{"maven", "gradle"} {
		for _, p := range rejects {
			t.Run(eco+"/reject/"+p, func(t *testing.T) { assertNotScored(t, eco, p, "1.0") })
		}
	}
	// NO segment-count rule: g:a:packaging:classifier:version is a valid
	// five-part form that splitMavenCoordinate scores today.
	controls := []string{"org.slf4j:slf4j-api", "g:a:c", "g:a:jar:sources:1.0"}
	for _, eco := range []string{"maven", "gradle"} {
		for _, p := range controls {
			t.Run(eco+"/control/"+p, func(t *testing.T) { assertScored(t, eco, p, "1.0") })
		}
	}
	// A character outside Maven's own ID grammar ([A-Za-z0-9_.-]) is a
	// reject; a bare colon-less name is a shape question for
	// splitMavenCoordinate, not a syntax reject, and stays out of scope.
	if MalformedCoordinateReason("maven", "org.x:art<script>") == "" {
		t.Error("angle brackets in an artifactId were accepted")
	}
}

func TestNPMNameSyntaxGate(t *testing.T) {
	rejects := []string{
		"<script>alert(1)</script>", // the P9F-063 name: registry answers 405, not 404
		".hidden",
		"a..b",
		"foo bar",
	}
	for _, p := range rejects {
		t.Run("reject/"+p, func(t *testing.T) { assertNotScored(t, "npm", p, "1.0.0") })
	}
	// OLD-package rules: uppercase is permitted (JSONStream is a real,
	// served, legacy name), scopes are permitted, no 214-char cap.
	controls := []string{"JSONStream", "@babel/core", "lodash"}
	for _, p := range controls {
		t.Run("control/"+p, func(t *testing.T) { assertScored(t, "npm", p, "1.0.0") })
	}
	// The remaining old-package error rules, pinned individually so a
	// refactor that drops one is visible.
	moreRejects := map[string]string{
		"_under":         "leading underscore",
		"":               "empty",
		" lodash":        "leading whitespace",
		"lodash ":        "trailing whitespace",
		"@/core":         "empty scope",
		"@babel/":        "empty scoped name",
		"@babel/a/b":     "two slashes",
		"babel/core":     "slash without a scope",
		"node_modules":   "blacklisted",
		"favicon.ico":    "blacklisted",
		"a%20b":          "percent is not URL-friendly",
		"@babel/<x>":     "scoped name with an unsafe char",
		"@sc ope/core":   "scope with whitespace",
		"a\tb":           "tab",
		"a\u00a0b":     "non-breaking space",
		"@babel/.hidden": "scoped name with a leading dot",
	}
	for name, why := range moreRejects {
		if MalformedCoordinateReason("npm", name) == "" {
			t.Errorf("npm %q accepted (%s)", name, why)
		}
	}
	// Names npm's own validator accepts for legacy packages — the
	// encodeURIComponent-unreserved punctuation. Rejecting these would be
	// a flip on any served name that carries them.
	for _, name := range []string{"a-b", "a_b", "a.b", "a~b", "a!b", "a'b", "a(b)", "a*b", "@Scope/Name", "x" + strings.Repeat("y", 300)} {
		if got := MalformedCoordinateReason("npm", name); got != "" {
			t.Errorf("npm %q rejected: %s", name, got)
		}
	}
	// yarn and bun resolve through the npm registry (osv.CanonicalEcosystem)
	// and take the same rule.
	for _, eco := range []string{"yarn", "bun"} {
		if MalformedCoordinateReason(eco, ".hidden") == "" {
			t.Errorf("%s .hidden accepted", eco)
		}
		if got := MalformedCoordinateReason(eco, "JSONStream"); got != "" {
			t.Errorf("%s JSONStream rejected: %s", eco, got)
		}
	}
}

func TestPyPINameSyntaxGate(t *testing.T) {
	rejects := []string{
		"<script>alert(1)</script>",
		"-requests",  // leading separator
		"requests-",  // trailing separator
		"re quests",  // whitespace
		"",           // empty
		"requests/x", // slash
		"req%uests",  // percent
		"_",          // lone separator
	}
	for _, eco := range []string{"pypi", "pip"} {
		for _, p := range rejects {
			t.Run(eco+"/reject/"+p, func(t *testing.T) { assertNotScored(t, eco, p, "1.0") })
		}
	}
	// PEP 508 accepts mixed case and the three separators internally; the
	// gate runs on the RAW name, before A4's canonicalisation, so a
	// non-canonical spelling must still pass.
	controls := []string{"requests", "Django", "typing_extensions", "zope.interface", "python-dateutil", "a", "A1", "PyYAML"}
	for _, eco := range []string{"pypi", "pip"} {
		for _, p := range controls {
			t.Run(eco+"/control/"+p, func(t *testing.T) { assertScored(t, eco, p, "1.0") })
		}
	}
}

// Ecosystems without a syntax rule are untouched — the predicate is empty
// for anything it does not understand, so a new ecosystem cannot be
// gated by accident.
func TestMalformedCoordinateReason_OtherEcosystemsPass(t *testing.T) {
	for _, tc := range []struct{ eco, pkg string }{
		{"cargo", "<script>"},
		{"docker", "library/../nginx"},
		{"rubygems", ".hidden"},
		{"", "anything at all"},
		{"nuget", "a..b"},
	} {
		if got := MalformedCoordinateReason(tc.eco, tc.pkg); got != "" {
			t.Errorf("MalformedCoordinateReason(%q, %q) = %q, want \"\" (no rule)", tc.eco, tc.pkg, got)
		}
	}
}

func TestMarkMalformedCoordinate_StampsAndIsIdempotent(t *testing.T) {
	at := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	r := &Report{Identity: IdentitySection{Ecosystem: "npm", Package: "<script>alert(1)</script>", Version: "1.0.0"}}
	if !markMalformedCoordinate(r, at) {
		t.Fatal("first stamp returned false")
	}
	if !markMalformedCoordinate(r, at) {
		t.Fatal("second stamp returned false — the marker must stay true")
	}
	n := 0
	for _, w := range r.Observation.Warnings {
		if w.Code == WarnCoordinateMalformed {
			n++
			if w.Provider != unevaluableVersionWarningProvider {
				t.Errorf("provider = %q, want %q", w.Provider, unevaluableVersionWarningProvider)
			}
			if w.Message == "" {
				t.Error("warning carries no message; the reason is unrecoverable")
			}
			if !w.At.Equal(at) {
				t.Errorf("At = %v, want %v", w.At, at)
			}
		}
	}
	if n != 1 {
		t.Fatalf("got %d WarnCoordinateMalformed warnings, want exactly 1 (idempotency)", n)
	}
	if markMalformedCoordinate(nil, at) {
		t.Error("nil report was stamped")
	}
}

// A coordinate that is malformed AND carries an unevaluable version gets
// both stamps; neither hides the other.
func TestMalformedAndUnevaluableStackIndependently(t *testing.T) {
	r := &Report{Identity: IdentitySection{Ecosystem: "maven", Package: ":x", Version: "${v}"}}
	at := time.Now()
	if !markUnevaluableVersion(r, at) || !markMalformedCoordinate(r, at) {
		t.Fatal("precondition: both stamps expected")
	}
	codes := map[string]int{}
	for _, w := range r.Observation.Warnings {
		codes[w.Code]++
	}
	if codes[WarnVersionNotEvaluable] != 1 || codes[WarnCoordinateMalformed] != 1 {
		t.Fatalf("codes = %v", codes)
	}
	if in := ProjectToRiskInput(r); !in.SignalsUnavailable {
		t.Fatal("SignalsUnavailable = false")
	}
}

// The coverage classification: not_applicable, with version_not_evaluable.
// A fact about the coordinate, not about any source, so it can never trip
// the opt-in fail-closed gate on its own.
func TestCoordinateMalformedIsClassifiedForCoverage(t *testing.T) {
	if got := coverage.StatusForWarnCode(WarnCoordinateMalformed); got != coverage.StatusNotApplicable {
		t.Fatalf("StatusForWarnCode(%q) = %q, want %q",
			WarnCoordinateMalformed, got, coverage.StatusNotApplicable)
	}
}

// A5-ext's second half, as amended: the non-404 4xx branch keeps its
// behaviour (http_NNN warning, non-retryable, row still scored) and gains
// a counter labelled by ecosystem and status. 404 and 5xx do not count.
func TestRegistryNon404FourXXCounter(t *testing.T) {
	var status int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", status)
	}))
	t.Cleanup(srv.Close)
	p := newRegistryMetadataProvider()

	fetch := func(eco string) *Warning {
		t.Helper()
		var out map[string]any
		warn, err := p.fetchJSON(withEcosystem(context.Background(), eco), srv.URL+"/x", "application/json", &out)
		if err != nil {
			t.Fatalf("fetchJSON: %v", err)
		}
		return warn
	}

	before := RegistryNon404FourXXTotals()

	status = http.StatusMethodNotAllowed
	if w := fetch("npm"); w == nil || w.Code != "http_405" {
		t.Fatalf("405 warning = %+v, want code http_405 (behaviour must not change)", w)
	}
	status = http.StatusForbidden
	fetch("npm")
	fetch("npm")
	status = http.StatusNotFound
	if w := fetch("npm"); w == nil || w.Code != "not_found" {
		t.Fatalf("404 warning = %+v, want not_found", w)
	}
	status = http.StatusBadGateway
	fetch("pypi") // 5xx retries and exhausts; must not count

	after := RegistryNon404FourXXTotals()
	delta := func(eco string, st int) uint64 {
		k := RegistryRejectKey{Ecosystem: eco, Status: st}
		return after[k] - before[k]
	}
	if got := delta("npm", 405); got != 1 {
		t.Errorf("npm/405 delta = %d, want 1", got)
	}
	if got := delta("npm", 403); got != 2 {
		t.Errorf("npm/403 delta = %d, want 2", got)
	}
	if got := delta("npm", 404); got != 0 {
		t.Errorf("npm/404 delta = %d, want 0 — 404 is an answer, not a rejection", got)
	}
	for k, v := range after {
		if k.Ecosystem == "pypi" && v != before[k] {
			t.Errorf("pypi counted %+v — 5xx is an outage, not a rejection", k)
		}
	}
	// The snapshot is a copy: mutating it must not touch the counter.
	after[RegistryRejectKey{Ecosystem: "npm", Status: 405}] = 999
	if RegistryNon404FourXXTotals()[RegistryRejectKey{Ecosystem: "npm", Status: 405}] == 999 {
		t.Error("RegistryNon404FourXXTotals returned the live map")
	}
}
