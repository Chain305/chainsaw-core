package intelligence

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/chain305/chainsaw-core/httpclient"
	"github.com/chain305/chainsaw-core/upstreamhttp"
)

// depRegistryRT stands in for the registries a dependency scan resolves
// against: a packument naming 2.0.0 as latest, and 404 for the tarball. It
// records the context every request arrived with.
type depRegistryRT struct {
	mu         sync.Mutex
	callers    []string
	background []bool
}

func (rt *depRegistryRT) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.callers = append(rt.callers, httpclient.EgressCallerFrom(req.Context()))
	rt.background = append(rt.background, upstreamhttp.IsBackground(req.Context()))
	rt.mu.Unlock()
	status, body := http.StatusOK, `{"dist-tags":{"latest":"2.0.0"}}`
	if strings.HasSuffix(req.URL.Path, ".tgz") {
		status, body = http.StatusNotFound, ""
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: req}, nil
}

// A dependency scan runs on the service's own background context, so the
// parent's egress tag has to be carried in explicitly. Before it was, every
// request a refresher rescan's dependency fan-out made — the version lookup,
// the tarball, the child's providers — was counted as `other`, customer
// traffic, and the fan-out's cost was invisible in every refresh.* query.
func TestDependencyScanCarriesTheEgressCaller(t *testing.T) {
	rt := &depRegistryRT{}
	old := autoDepHTTPClient
	autoDepHTTPClient = &http.Client{Transport: rt}
	t.Cleanup(func() { autoDepHTTPClient = old })

	prov := &callerRecordingProvider{}
	svc := New(Config{Providers: []Provider{prov}})
	defer svc.Close()

	svc.scanTransitiveDep("npm", "child", 1, httpclient.EgressCallerRefreshDep)

	if len(rt.callers) < 2 {
		t.Fatalf("registry saw %d requests, want the version lookup and the tarball", len(rt.callers))
	}
	for i, c := range rt.callers {
		if c != httpclient.EgressCallerRefreshDep {
			t.Errorf("registry request %d counted as %q, want %q", i, c, httpclient.EgressCallerRefreshDep)
		}
		if !rt.background[i] {
			t.Errorf("registry request %d lost the background lane — a dependency scan must not "+
				"compete with the scans someone is waiting on", i)
		}
	}
	got := prov.snapshot()
	if len(got) != 1 {
		t.Fatalf("child scan ran %d times, want 1", len(got))
	}
	if got[0] != httpclient.EgressCallerRefreshDep {
		t.Errorf("child scan's providers ran as %q, want %q", got[0], httpclient.EgressCallerRefreshDep)
	}
}

func TestDepScanEgressCaller(t *testing.T) {
	for _, tc := range []struct{ parent, want string }{
		{httpclient.EgressCallerRefresh, httpclient.EgressCallerRefreshDep},
		{httpclient.EgressCallerRefreshDocument, httpclient.EgressCallerRefreshDep},
		{httpclient.EgressCallerRefreshDep, httpclient.EgressCallerRefreshDep},
		// An install's dependency scans are not refresher cost.
		{httpclient.EgressCallerOther, httpclient.EgressCallerOther},
		{"", ""},
	} {
		if got := depScanEgressCaller(tc.parent); got != tc.want {
			t.Errorf("depScanEgressCaller(%q) = %q, want %q", tc.parent, got, tc.want)
		}
	}
}

// Source guard. The hand-off from the parent's context sits in
// enqueueDependencyScans, which returns before doing anything when the service
// has no store — and the store is a concrete *Store over a live database — so
// no unit test reaches it. This reads the source instead. It catches the
// hand-off being DELETED, not it being disabled by some other edit; the
// behaviour on the far side of it is pinned above.
func TestEnqueueDependencyScansHandsTheCallerOn(t *testing.T) {
	src, err := os.ReadFile("dep_enqueuer.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "dep_enqueuer.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body string
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "enqueueDependencyScans" {
			body = string(src[fset.Position(fn.Body.Pos()).Offset:fset.Position(fn.Body.End()).Offset])
		}
	}
	if body == "" {
		t.Fatal("enqueueDependencyScans not found in dep_enqueuer.go")
	}
	for _, want := range []string{
		"caller := depScanEgressCaller(httpclient.EgressCallerFrom(parentCtx))",
		"s.scanTransitiveDep(eco, name, depth+1, caller)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("enqueueDependencyScans no longer contains %q — the dependency fan-out "+
				"would be counted as customer traffic again", want)
		}
	}
}
