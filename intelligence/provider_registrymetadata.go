package intelligence

// registryMetadataProvider populates the descriptive-metadata sections
// of the Report (Release, URLs, Artifact, People, Metadata, and the
// SourceRepo field of Provenance) from each ecosystem's public
// registry. Before this provider existed every non-risk section of the
// intelligence report was empty for packages whose metadata the
// background metadata-persistence job hadn't yet cached in the server
// layer — the pipeline never fetched it itself.
//
// Each ecosystem has a small dispatch function that:
//   1. Builds the packument / per-version URL
//   2. Issues a GET with a tight timeout + single retry
//   3. Decodes the response (JSON or XML) into a minimal anonymous
//      struct holding only the fields the Report actually consumes
//   4. Normalises values (SPDX license expressions, people strings,
//      Maven groupId:artifactId coordinates) and returns a
//      PartialReport.
//
// Deliberately kept self-contained: no proxy.RemoteDefinition, no
// metadata.Store, no server-layer types. The provider is safe to run
// in tests with an httptest.Server just by swapping the base URLs.

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chain305/chainsaw-core/httpclient"
	"golang.org/x/mod/modfile"
)

// Default public registry base URLs. Overridable for tests.
type registryEndpoints struct {
	npm   string
	pypi  string
	maven string
	// mavenGoogle is the SECOND Maven repository, and the reason the
	// Maven family can now be answered rather than shrugged at. See
	// fetchMavenTimelineDoc: repo1 is not the whole of Maven, and the
	// namespaces Google publishes are the measured majority of what
	// repo1 misses.
	mavenGoogle       string
	cargo             string
	rubygems          string
	nuget             string
	nugetRegistration string
	composer          string
	goproxy           string
	cocoapods         string
	cocoapodsCDN      string
	pub               string
	huggingface       string
	docker            string
	depsdev           string
	github            string
	gitlab            string
	bitbucket         string
	codeberg          string
}

func defaultRegistryEndpoints() registryEndpoints {
	return registryEndpoints{
		npm:               "https://registry.npmjs.org",
		pypi:              "https://pypi.org",
		maven:             "https://repo1.maven.org/maven2",
		mavenGoogle:       "https://maven.google.com",
		cargo:             "https://crates.io",
		rubygems:          "https://rubygems.org",
		nuget:             "https://api.nuget.org/v3-flatcontainer",
		nugetRegistration: "https://api.nuget.org/v3/registration5-semver1",
		composer:          "https://repo.packagist.org",
		goproxy:           "https://proxy.golang.org",
		cocoapods:         "https://trunk.cocoapods.org",
		cocoapodsCDN:      "https://cdn.cocoapods.org",
		pub:               "https://pub.dev",
		huggingface:       "https://huggingface.co",
		docker:            "https://hub.docker.com",
		depsdev:           "https://api.deps.dev",
		github:            "https://api.github.com",
		gitlab:            "https://gitlab.com",
		bitbucket:         "https://api.bitbucket.org",
		codeberg:          "https://codeberg.org",
	}
}

// registryMetadataProvider is a Tier-1 provider — no artifact needed,
// pure metadata fetch. Runs in parallel with the other fan-out
// providers.
type registryMetadataProvider struct {
	client    *http.Client
	endpoints registryEndpoints
	now       func() time.Time
}

func newRegistryMetadataProvider() *registryMetadataProvider {
	return &registryMetadataProvider{
		// Per-attempt timeout is derived from the per-ecosystem budget via
		// context.WithTimeout in fetchDecoded. The client-level timeout is a
		// generous backstop (well above the longest per-ecosystem budget) so
		// a hung TCP read can't outlast the worker; the real deadline still
		// comes from the request context. httpclient.New also installs a
		// pooled transport with MaxIdleConnsPerHost=32 — fixing the audit
		// finding F-7 where the bare &http.Client{} fell back to Go's
		// DefaultTransport limit of 2 idle conns per host.
		client:    httpclient.New(httpclient.WithTimeout(60 * time.Second)),
		endpoints: defaultRegistryEndpoints(),
		now:       func() time.Time { return time.Now().UTC() },
	}
}

// registryTimeouts holds per-ecosystem per-attempt timeout budgets.
// Slow registries (Maven Central peak hours, NuGet during deploys, PyPI
// under load) need more headroom than the historical flat 8s. Keys are
// the lowercase canonical ecosystem names used by Run().
var registryTimeouts = map[string]time.Duration{
	"npm":         8 * time.Second,
	"yarn":        8 * time.Second,
	"bun":         8 * time.Second,
	"pip":         12 * time.Second,
	"pypi":        12 * time.Second,
	"maven":       20 * time.Second, // notoriously slow
	"gradle":      20 * time.Second,
	"nuget":       15 * time.Second,
	"rubygems":    10 * time.Second,
	"cargo":       10 * time.Second,
	"composer":    10 * time.Second,
	"go":          10 * time.Second,
	"gomod":       10 * time.Second,
	"cocoapods":   12 * time.Second,
	"swift":       12 * time.Second,
	"pub":         12 * time.Second,
	"huggingface": 15 * time.Second,
	"docker":      15 * time.Second,
}

const defaultRegistryTimeout = 8 * time.Second

// ecosystemCtxKey threads the ecosystem name from Run() down to
// fetchDecoded so the per-attempt timeout can be derived without
// changing every run*()/fetch*() signature.
type ecosystemCtxKey struct{}

func withEcosystem(ctx context.Context, eco string) context.Context {
	return context.WithValue(ctx, ecosystemCtxKey{}, strings.ToLower(strings.TrimSpace(eco)))
}

func ecosystemTimeout(ctx context.Context) time.Duration {
	v, _ := ctx.Value(ecosystemCtxKey{}).(string)
	if d, ok := registryTimeouts[v]; ok {
		return d
	}
	return defaultRegistryTimeout
}

// RegistryRejectKey labels one bucket of the intel_registry_non404_4xx_total
// counter: the ecosystem whose registry answered, and the status it
// answered with.
type RegistryRejectKey struct {
	Ecosystem string
	Status    int
}

// registryNon404FourXX counts canonical-registry answers in the 4xx range
// other than 404 — a 403 from an edge WAF, a 405 for a URL-unsafe name, a
// 410 for a withdrawn package — labelled by ecosystem and status. It is
// MEASUREMENT ONLY (Phase 9 fresh QA, A5-ext, as amended): the row's
// handling is unchanged. The draft routed these through unavailableInput
// as `registry_rejected`; that arm was dropped because unavailableInput
// carries only the malware fact and would have discarded the OSV
// vulnerability lane, so a Cloudflare 403 burst on a popular package would
// have converted CVE-based blocks to Monitored for 24h per coordinate, on
// the proxy. A vuln-preserving unavailable variant is its own wave and
// needs this number first. Same shape as recomputeSweptTotal: a
// process-local counter with an exported reader for the metrics exporter
// (internal/observability) to wrap as a Prometheus CounterVec.
var registryNon404FourXX struct {
	mu sync.Mutex
	n  map[RegistryRejectKey]uint64
}

func recordRegistryNon404FourXX(ctx context.Context, status int) {
	eco, _ := ctx.Value(ecosystemCtxKey{}).(string)
	if eco == "" {
		eco = "unknown"
	}
	registryNon404FourXX.mu.Lock()
	defer registryNon404FourXX.mu.Unlock()
	if registryNon404FourXX.n == nil {
		registryNon404FourXX.n = map[RegistryRejectKey]uint64{}
	}
	registryNon404FourXX.n[RegistryRejectKey{Ecosystem: eco, Status: status}]++
}

// RegistryNon404FourXXTotals returns a snapshot of the
// intel_registry_non404_4xx_total counter, one entry per
// (ecosystem, status) bucket seen since process start. The map is a copy.
func RegistryNon404FourXXTotals() map[RegistryRejectKey]uint64 {
	registryNon404FourXX.mu.Lock()
	defer registryNon404FourXX.mu.Unlock()
	out := make(map[RegistryRejectKey]uint64, len(registryNon404FourXX.n))
	for k, v := range registryNon404FourXX.n {
		out[k] = v
	}
	return out
}

// jitterRand is package-scoped so retry sleeps don't collide with the
// global rand mutex under high concurrency. Guarded by a mutex because
// math/rand.Source is not goroutine-safe.
var (
	jitterMu  sync.Mutex
	jitterRng = rand.New(rand.NewSource(time.Now().UnixNano()))
)

func jitterFactor() float64 {
	jitterMu.Lock()
	defer jitterMu.Unlock()
	// Uniform in [0.75, 1.25] — ±25%.
	return 0.75 + jitterRng.Float64()*0.5
}

func (p *registryMetadataProvider) Name() string        { return "registrymetadata" }
func (p *registryMetadataProvider) Signal() SignalMask  { return SignalRegistryMetadata }
func (p *registryMetadataProvider) Tier() int           { return 1 }
func (p *registryMetadataProvider) NeedsArtifact() bool { return false }

// supportedRegistryEcosystems mirrors the ecosystems with a working
// per-version metadata endpoint. "yarn" and "bun" share npm's registry.
// "pip" is aliased to "pypi". "gradle" uses the same Maven layout.
var supportedRegistryEcosystems = map[string]struct{}{
	"npm": {}, "yarn": {}, "bun": {},
	"pypi": {}, "pip": {},
	"maven": {}, "gradle": {},
	"cargo":       {},
	"rubygems":    {},
	"nuget":       {},
	"composer":    {},
	"go":          {},
	"cocoapods":   {},
	"pub":         {},
	"huggingface": {},
	"docker":      {},
}

func (p *registryMetadataProvider) Supports(ecosystem string) bool {
	_, ok := supportedRegistryEcosystems[normalizeEcosystemKey(ecosystem)]
	return ok
}

func (p *registryMetadataProvider) Run(ctx context.Context, req Request, _ *Report) (PartialReport, error) {
	pkg := strings.TrimSpace(req.Key.Package)
	ver := strings.TrimSpace(req.Key.Version)
	if pkg == "" || ver == "" {
		return PartialReport{}, nil
	}
	// Same normaliser Supports() uses (P8-33). If these two ever
	// disagree the provider claims coverage it then declines to
	// deliver: Supports()=true writes a ProviderTimings entry, which
	// core/intelligence/coverage.go reads as StatusOK, so the coverage
	// gate would vouch for a lane that fell through this switch.
	eco := normalizeEcosystemKey(req.Key.Ecosystem)
	ctx = withEcosystem(ctx, eco)
	switch eco {
	case "npm", "yarn", "bun":
		return p.runNPM(ctx, pkg, ver)
	case "pypi", "pip":
		return p.runPyPI(ctx, pkg, ver)
	case "maven", "gradle":
		return p.runMaven(ctx, pkg, ver)
	case "cargo":
		return p.runCargo(ctx, pkg, ver)
	case "rubygems":
		return p.runRubyGems(ctx, pkg, ver)
	case "nuget":
		return p.runNuGet(ctx, pkg, ver)
	case "composer":
		return p.runComposer(ctx, pkg, ver)
	case "go":
		return p.runGo(ctx, pkg, ver)
	case "cocoapods":
		return p.runCocoapods(ctx, pkg, ver)
	case "pub":
		return p.runPub(ctx, pkg, ver)
	case "huggingface":
		return p.runHuggingFace(ctx, pkg, ver)
	case "docker":
		return p.runDocker(ctx, pkg, ver)
	}
	return PartialReport{}, nil
}

var _ Provider = (*registryMetadataProvider)(nil)

// -- Shared HTTP helpers ----------------------------------------------

// fetchJSON GETs url and decodes the response as JSON into out. Soft
// failure (returns nil with a warning) on 4xx/5xx or decode errors so a
// temporary registry outage doesn't fail the whole Scan.
func (p *registryMetadataProvider) fetchJSON(ctx context.Context, endpoint string, accept string, out any) (*Warning, error) {
	return p.fetchDecoded(ctx, endpoint, accept, func(body io.Reader) error {
		dec := json.NewDecoder(body)
		dec.UseNumber()
		return dec.Decode(out)
	})
}

// fetchXML is the XML sibling of fetchJSON — used for Maven POMs and
// NuGet nuspecs.
func (p *registryMetadataProvider) fetchXML(ctx context.Context, endpoint string, out any) (*Warning, error) {
	return p.fetchDecoded(ctx, endpoint, "application/xml", func(body io.Reader) error {
		return xml.NewDecoder(body).Decode(out)
	})
}

// fetchLines GETs endpoint and returns the body split into trimmed,
// non-empty lines. Exists for proxy.golang.org's `@v/list`, the one
// package-level endpoint in this file that answers text/plain rather
// than JSON or XML — routing it through fetchDecoded keeps it on the
// same timeout, retry and warning-shape machinery as everything else.
func (p *registryMetadataProvider) fetchLines(ctx context.Context, endpoint string) ([]string, *Warning, error) {
	var lines []string
	warn, err := p.fetchDecoded(ctx, endpoint, "text/plain", func(body io.Reader) error {
		b, err := io.ReadAll(body)
		if err != nil {
			return err
		}
		for _, ln := range strings.Split(string(b), "\n") {
			if t := strings.TrimSpace(ln); t != "" {
				lines = append(lines, t)
			}
		}
		return nil
	})
	return lines, warn, err
}

// retry policy: up to 3 attempts (1 initial + 2 retries) with
// exponential backoff (200ms, 800ms = base * 4^n) and ±25% jitter.
// Retryable conditions: per-attempt timeout (DeadlineExceeded on the
// sub-context, parent still alive), 5xx status, transient net.Error.
// Non-retryable: 4xx (404/401/403 are deterministic), parent context
// cancellation, malformed URL.
const (
	registryMaxAttempts = 3
	registryBackoffBase = 200 * time.Millisecond
)

func (p *registryMetadataProvider) fetchDecoded(ctx context.Context, endpoint, accept string, decode func(io.Reader) error) (*Warning, error) {
	start := p.now()
	perAttempt := ecosystemTimeout(ctx)

	var lastErr error
	var lastStatus int
	for attempt := 0; attempt < registryMaxAttempts; attempt++ {
		// Bail immediately if the operator-set deadline is already
		// blown — don't burn another retry budget.
		if err := ctx.Err(); err != nil {
			return &Warning{Provider: "registrymetadata", Code: "context_cancelled", Message: err.Error(), At: p.now()}, nil
		}

		attemptCtx, cancel := context.WithTimeout(ctx, perAttempt)
		warn, retryable, status, err := p.fetchOnce(attemptCtx, endpoint, accept, decode)
		cancel()

		if warn == nil && err == nil {
			return nil, nil // success
		}
		lastErr = err
		lastStatus = status

		// Not retryable (4xx, decode error, request build error,
		// parent context cancelled): return the warning as-is.
		if !retryable {
			return warn, nil
		}
		// On the final attempt, fall through to the exhausted path.
		if attempt == registryMaxAttempts-1 {
			break
		}

		// Sleep with exponential backoff + jitter. base * 4^attempt
		// gives 200ms, 800ms.
		mult := 1
		for i := 0; i < attempt; i++ {
			mult *= 4
		}
		delay := time.Duration(float64(registryBackoffBase) * float64(mult) * jitterFactor())
		t := time.NewTimer(delay)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return &Warning{Provider: "registrymetadata", Code: "context_cancelled", Message: ctx.Err().Error(), At: p.now()}, nil
		}
	}

	// All attempts exhausted on a retryable failure path.
	elapsed := p.now().Sub(start)
	msg := fmt.Sprintf("endpoint=%s elapsed=%s", endpoint, elapsed)
	if lastErr != nil {
		msg = fmt.Sprintf("%s err=%s", msg, lastErr.Error())
	} else if lastStatus > 0 {
		msg = fmt.Sprintf("%s status=%d", msg, lastStatus)
	}
	return &Warning{
		Provider: "registrymetadata",
		Code:     "registry_fetch_exhausted_retries",
		Message:  msg,
		At:       p.now(),
	}, nil
}

// fetchOnce performs a single request attempt. Returns:
//   - warn:      a populated Warning when the attempt failed
//   - retryable: whether the caller should attempt again
//   - status:    HTTP status if a response was received (else 0)
//   - err:       transport error if any
//
// On success returns (nil, false, 200, nil) — body has been decoded.
func (p *registryMetadataProvider) fetchOnce(ctx context.Context, endpoint, accept string, decode func(io.Reader) error) (*Warning, bool, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return &Warning{Provider: "registrymetadata", Code: "request_build", Message: err.Error(), At: p.now()}, false, 0, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.Header.Set("User-Agent", "chainsaw-intelligence/1")

	resp, err := p.client.Do(req)
	if err != nil {
		// If the parent ctx itself is cancelled/expired, the operator
		// asked us to stop — don't retry.
		if pErr := ctx.Err(); pErr != nil {
			// Distinguish per-attempt timeout (parent still alive)
			// from parent cancellation. context.WithTimeout fires
			// DeadlineExceeded on the sub-ctx, but here ctx IS the
			// sub-ctx. Walk up: if the original parent (ctx.Err
			// here will be DeadlineExceeded for sub-timeout too).
			// We resolve this in the caller by checking parent
			// before sleeping; here just treat as transient.
			_ = pErr
		}
		return &Warning{Provider: "registrymetadata", Code: "transport", Message: err.Error(), At: p.now()}, isTransientErr(err), 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &Warning{Provider: "registrymetadata", Code: WarnRegistryNotFound, Message: endpoint, At: p.now()}, false, resp.StatusCode, nil
	}
	if resp.StatusCode >= 500 {
		// Drain a small amount so the connection can be reused.
		_, _ = io.Copy(io.Discard, &io.LimitedReader{R: resp.Body, N: 4 << 10})
		return &Warning{Provider: "registrymetadata", Code: fmt.Sprintf("http_%d", resp.StatusCode), Message: endpoint, At: p.now()}, true, resp.StatusCode, nil
	}
	if resp.StatusCode >= 400 {
		// Count, do not reclassify. A non-404 4xx from a canonical registry
		// (405 on a URL-unsafe name, 403 on a burst) leaves the row scored
		// off whatever the other lanes found, exactly as before — routing it
		// through the unavailable path would discard the OSV vulnerability
		// facts and turn a CVE block into Monitored under throttling. The
		// counter is here so the population can be measured before anyone
		// proposes that change. See §5 of plan_qa_phase9_fresh_remediation.
		recordRegistryNon404FourXX(ctx, resp.StatusCode)
		return &Warning{Provider: "registrymetadata", Code: fmt.Sprintf("http_%d", resp.StatusCode), Message: endpoint, At: p.now()}, false, resp.StatusCode, nil
	}

	// Cap the body read at 8 MiB — the largest public packument is npm's
	// facebook/react at roughly 3 MiB and growing slowly. Anything over
	// this is almost certainly a misconfigured registry.
	limited := &io.LimitedReader{R: resp.Body, N: 8 << 20}
	if err := decode(limited); err != nil {
		return &Warning{Provider: "registrymetadata", Code: "decode", Message: err.Error(), At: p.now()}, false, resp.StatusCode, err
	}
	return nil, false, resp.StatusCode, nil
}

// isTransientErr classifies a transport error as retryable. Per-attempt
// context.DeadlineExceeded counts (the operator-set parent budget is
// checked separately by the retry loop). url.Error usually wraps
// net.Error; unwrap and ask Temporary()/Timeout().
func isTransientErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	var nErr net.Error
	if errors.As(err, &nErr) {
		if nErr.Timeout() {
			return true
		}
		// net.Error.Temporary() is deprecated but still implemented
		// by *net.OpError, *url.Error wrappers — the only signal we
		// have for transient-but-not-timeout DNS/conn-reset errors.
		type temporary interface{ Temporary() bool }
		if t, ok := err.(temporary); ok && t.Temporary() {
			return true
		}
	}
	return false
}

// -- NPM / Yarn / Bun -------------------------------------------------

type npmHuman struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

func (h npmHuman) String() string {
	name := strings.TrimSpace(h.Name)
	email := strings.TrimSpace(h.Email)
	switch {
	case name != "" && email != "":
		return fmt.Sprintf("%s <%s>", name, email)
	case name != "":
		return name
	case email != "":
		return email
	}
	return ""
}

func (h *npmHuman) UnmarshalJSON(b []byte) error {
	// npm author can be either an object or a "Name <email>" string.
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		h.Name = strings.TrimSpace(s)
		return nil
	}
	type alias npmHuman
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*h = npmHuman(a)
	return nil
}

type npmVersionMeta struct {
	License  any `json:"license"`
	Licenses []struct {
		Type string `json:"type"`
	} `json:"licenses"`
	Description string `json:"description"`
	Homepage    string `json:"homepage"`
	Repository  any    `json:"repository"`
	Bugs        any    `json:"bugs"`
	Dist        struct {
		Tarball   string `json:"tarball"`
		Shasum    string `json:"shasum"`
		Integrity string `json:"integrity"`
	} `json:"dist"`
	Deprecated           string            `json:"deprecated"`
	Maintainers          []npmHuman        `json:"maintainers"`
	Author               *npmHuman         `json:"author"`
	NpmUser              *npmHuman         `json:"_npmUser"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func (p *registryMetadataProvider) runNPM(ctx context.Context, pkg, ver string) (PartialReport, error) {
	endpoint := fmt.Sprintf("%s/%s", p.endpoints.npm, encodeNPMPackage(pkg))
	var pack struct {
		Name        string                    `json:"name"`
		Description string                    `json:"description"`
		License     any                       `json:"license"`
		Homepage    string                    `json:"homepage"`
		Repository  any                       `json:"repository"`
		Bugs        any                       `json:"bugs"`
		DistTags    map[string]string         `json:"dist-tags"`
		Time        map[string]string         `json:"time"`
		Versions    map[string]npmVersionMeta `json:"versions"`
		Maintainers []npmHuman                `json:"maintainers"`
		Author      *npmHuman                 `json:"author"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &pack)
	if err != nil {
		return PartialReport{}, err
	}
	pr := PartialReport{}
	if warn != nil {
		pr.Warnings = append(pr.Warnings, *promotePackagumentNotFound(p, "npm", warn, endpoint, pkg, ver))
		return pr, nil
	}

	entry, hasEntry := pack.Versions[ver]

	// hasEntry is consulted a dozen times below, every one of them to
	// pick a packument-level FALLBACK. That silently converts "this
	// version does not exist" into "here is the package's general
	// metadata", and the report comes back scored and normal-looking —
	// a hallucinated or typo'd version pin gets a plausible risk grade
	// instead of an answer. Say it out loud instead.
	//
	// The guard is the discriminator: the packument fetched OK (we are
	// past the warn branch above), it enumerated a NON-EMPTY versions
	// set, and the requested version is not in it. An empty or absent
	// `versions` map is what a private mirror or a partial packument
	// looks like, and it must keep today's silent-degrade behaviour.
	if !hasEntry && len(pack.Versions) > 0 {
		published := make([]string, 0, len(pack.Versions))
		for v := range pack.Versions {
			published = append(published, v)
		}
		if !versionListed(published, ver) {
			pr.Warnings = append(pr.Warnings,
				*versionNotFoundWarning(p, endpoint, pkg, ver, len(published)))
		}
	}

	license := ""
	if hasEntry {
		license = npmLicense(entry.License, entry.Licenses)
	}
	if license == "" {
		license = npmLicense(pack.License, nil)
	}

	// People — prefer the version's _npmUser (actual publisher) +
	// maintainers array for that version; fall back to packument level.
	people := &PeopleSection{}
	if hasEntry && entry.NpmUser != nil {
		if s := entry.NpmUser.String(); s != "" {
			people.PublisherIDs = []string{s}
		}
	}
	var maintainers []npmHuman
	if hasEntry && len(entry.Maintainers) > 0 {
		maintainers = entry.Maintainers
	} else if len(pack.Maintainers) > 0 {
		maintainers = pack.Maintainers
	}
	for _, m := range maintainers {
		if s := m.String(); s != "" {
			people.Maintainers = append(people.Maintainers, s)
		}
	}
	var author *npmHuman
	if hasEntry && entry.Author != nil {
		author = entry.Author
	} else if pack.Author != nil {
		author = pack.Author
	}
	if author != nil {
		if s := author.String(); s != "" {
			people.Authors = []string{s}
		}
	}

	// URLs — artifact URL + repo/homepage/bugs. Fall back to packument
	// level when the per-version record doesn't carry them.
	urls := &URLSection{MetadataURL: endpoint}
	homepage := firstNonEmpty(ifEntry(hasEntry, entry.Homepage), pack.Homepage)
	if homepage != "" {
		urls.HomepageURL = homepage
	}
	repo := firstNonEmpty(npmRepoURL(ifEntryAny(hasEntry, entry.Repository)), npmRepoURL(pack.Repository))
	if repo != "" {
		urls.SourceRepoURL = repo
	}
	bugs := firstNonEmpty(npmBugsURL(ifEntryAny(hasEntry, entry.Bugs)), npmBugsURL(pack.Bugs))
	if bugs != "" {
		urls.IssuesURL = bugs
	}

	artifact := &ArtifactSection{}
	if hasEntry {
		if entry.Dist.Tarball != "" {
			urls.ArtifactURL = entry.Dist.Tarball
			artifact.Filename = filenameFromURL(entry.Dist.Tarball)
		}
		if entry.Dist.Shasum != "" {
			artifact.Digests.SHA1 = entry.Dist.Shasum
		}
		if entry.Dist.Integrity != "" {
			artifact.Digests.Integrity = entry.Dist.Integrity
		}
	}

	release := &ReleaseSection{}
	if pack.Time != nil {
		if t, ok := parseTime(pack.Time[ver]); ok {
			release.PublishedAt = &t
		}
		if t, ok := parseTime(pack.Time["created"]); ok {
			release.CreatedAt = &t
		}
		if t, ok := parseTime(pack.Time["modified"]); ok {
			release.ModifiedAt = &t
		}
	}
	if pack.DistTags != nil {
		release.LatestVersion = pack.DistTags["latest"]
	}
	if hasEntry && entry.Deprecated != "" {
		release.Deprecated = entry.Deprecated
	}

	metadata := &MetadataSection{LicenseExpression: license}
	if hasEntry && entry.Description != "" {
		metadata.Description = entry.Description
		metadata.Summary = firstLine(entry.Description)
	} else if pack.Description != "" {
		metadata.Description = pack.Description
		metadata.Summary = firstLine(pack.Description)
	}

	pr.Release = release
	pr.URLs = urls
	pr.Artifact = artifact
	pr.Metadata = metadata
	if len(people.Maintainers)+len(people.Authors)+len(people.PublisherIDs) > 0 {
		pr.People = people
	}

	// Extract the full version timeline from the packument. Every key in
	// `pack.Versions` is a published version; `pack.Time[ver]` is the
	// matching publish date. This bypasses the proxy-driven sparse store
	// (which only knows about versions chainsaw has actually fingered)
	// and is the only way to get an accurate VersionCount + prior
	// version-sequence history on a fresh scan of a popular package.
	//
	// The slice is built in stable iteration-friendly form: ordering is
	// not guaranteed (Go map iteration is random) but VersionSequenceFlags
	// and VersionCount don't care about order. Downstream consumers that
	// need a sorted view can sort their copy.
	if len(pack.Versions) > 0 {
		timeline := make([]VersionRelease, 0, len(pack.Versions))
		for v := range pack.Versions {
			rel := VersionRelease{Version: v}
			if pack.Time != nil {
				if t, ok := parseTime(pack.Time[v]); ok {
					rel.PublishedAt = t
				}
			}
			timeline = append(timeline, rel)
		}
		// Route through applyTimeline so FirstPublishedAt + sorted
		// VersionTimeline are computed the same way every other
		// ecosystem gets them. Without this, the npm runner produced
		// the timeline slice but never derived FirstPublishedAt — the
		// data was on the wire but the field stayed nil. Match: PyPI
		// applyTimeline call at the per-ecosystem timeline fetch path.
		latest := ""
		if pack.DistTags != nil {
			latest = strings.TrimSpace(pack.DistTags["latest"])
		}
		applyTimeline(&pr, timeline, latest, nil)
	}

	if hasEntry {
		deps := buildDepsFromMaps(
			entry.Dependencies,
			entry.DevDependencies,
			entry.PeerDependencies,
			entry.OptionalDependencies,
		)
		if !deps.empty() {
			pr.Dependencies = deps.section()
		}
	}
	// Surface the source repo on Provenance too so the new UI picks it up.
	if urls.SourceRepoURL != "" {
		pr.Provenance = &ProvenanceSection{SourceRepo: urls.SourceRepoURL}
	}
	// Pull GitHub stars/forks/openIssues/subscribers when the source
	// repo is on github.com. The other 5 ecosystem runners already do
	// this; npm was the omission. lodash et al. went out with NULL
	// stars on prod even though `repository.url` resolves cleanly to
	// github.com/lodash/lodash because of this gap.
	enrichRepoStars(ctx, p, &pr)
	return pr, nil
}

// depCollector accumulates per-bucket DependencyRefs in stable order so
// the JSON output is deterministic across registries that return maps.
type depCollector struct {
	direct, dev, peer, optional []DependencyRef
}

func (d *depCollector) empty() bool {
	return len(d.direct)+len(d.dev)+len(d.peer)+len(d.optional) == 0
}
func (d *depCollector) section() *DependenciesSection {
	return &DependenciesSection{
		Direct: d.direct, Dev: d.dev, Peer: d.peer, Optional: d.optional,
	}
}

func buildDepsFromMaps(direct, dev, peer, optional map[string]string) depCollector {
	return depCollector{
		direct:   refsFromMap(direct),
		dev:      refsFromMap(dev),
		peer:     refsFromMap(peer),
		optional: refsFromMap(optional),
	}
}

func refsFromMap(m map[string]string) []DependencyRef {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	out := make([]DependencyRef, 0, len(keys))
	for _, k := range keys {
		out = append(out, DependencyRef{Name: k, Constraint: strings.TrimSpace(m[k])})
	}
	return out
}

// sortStrings is a tiny sort helper; kept inline so the file stays
// dependency-thin (no "sort" import for one call site).
func sortStrings(s []string) {
	// Insertion sort — dep maps are small (median <30 entries) so the
	// simpler algorithm avoids the sort package import.
	for i := 1; i < len(s); i++ {
		j := i
		for j > 0 && s[j-1] > s[j] {
			s[j-1], s[j] = s[j], s[j-1]
			j--
		}
	}
}

func encodeNPMPackage(pkg string) string {
	// Scoped packages (@scope/name) must keep the "/" unescaped, but
	// url.PathEscape would encode it. Encode each segment separately.
	if !strings.Contains(pkg, "/") {
		return url.PathEscape(pkg)
	}
	parts := strings.SplitN(pkg, "/", 2)
	return url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1])
}

func npmLicense(lic any, legacy []struct {
	Type string `json:"type"`
}) string {
	if s, ok := lic.(string); ok {
		return strings.TrimSpace(s)
	}
	if m, ok := lic.(map[string]any); ok {
		if t, _ := m["type"].(string); t != "" {
			return strings.TrimSpace(t)
		}
	}
	for _, e := range legacy {
		if e.Type != "" {
			return strings.TrimSpace(e.Type)
		}
	}
	return ""
}

func npmRepoURL(raw any) string {
	switch v := raw.(type) {
	case string:
		return normaliseRepoURL(v)
	case map[string]any:
		if u, _ := v["url"].(string); u != "" {
			return normaliseRepoURL(u)
		}
	}
	return ""
}

func npmBugsURL(raw any) string {
	switch v := raw.(type) {
	case string:
		return v
	case map[string]any:
		if u, _ := v["url"].(string); u != "" {
			return u
		}
	}
	return ""
}

// normaliseRepoURL strips the "git+" prefix and ".git" suffix some
// maintainers tack onto their package.json repository.url values so
// the stored URL is browsable without manual clean-up.
func normaliseRepoURL(u string) string {
	u = strings.TrimSpace(u)
	u = strings.TrimPrefix(u, "git+")
	u = strings.TrimSuffix(u, ".git")
	return u
}

// -- PyPI / pip -------------------------------------------------------

func (p *registryMetadataProvider) runPyPI(ctx context.Context, pkg, ver string) (PartialReport, error) {
	endpoint := fmt.Sprintf("%s/pypi/%s/%s/json", p.endpoints.pypi, url.PathEscape(pkg), url.PathEscape(ver))
	var pack struct {
		Info struct {
			Author            string            `json:"author"`
			AuthorEmail       string            `json:"author_email"`
			Maintainer        string            `json:"maintainer"`
			MaintainerEmail   string            `json:"maintainer_email"`
			License           string            `json:"license"`
			LicenseExpression string            `json:"license_expression"`
			Summary           string            `json:"summary"`
			Description       string            `json:"description"`
			HomePage          string            `json:"home_page"`
			ProjectURL        string            `json:"project_url"`
			DocsURL           string            `json:"docs_url"`
			Keywords          string            `json:"keywords"`
			ProjectURLs       map[string]string `json:"project_urls"`
			RequiresPython    string            `json:"requires_python"`
			RequiresDist      []string          `json:"requires_dist"`
			Yanked            any               `json:"yanked"`
			YankedReason      string            `json:"yanked_reason"`
			PackageURL        string            `json:"package_url"`
			Version           string            `json:"version"`
		} `json:"info"`
		URLs []struct {
			Filename       string            `json:"filename"`
			PackageType    string            `json:"packagetype"`
			Size           int64             `json:"size"`
			URL            string            `json:"url"`
			UploadTime     string            `json:"upload_time_iso_8601"`
			Digests        map[string]string `json:"digests"`
			HasSig         bool              `json:"has_sig"`
			RequiresPython string            `json:"requires_python"`
			Yanked         bool              `json:"yanked"`
		} `json:"urls"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &pack)
	if err != nil {
		return PartialReport{}, err
	}
	pr := PartialReport{}
	if warn != nil {
		// /pypi/{pkg}/{ver}/json 404s identically for "no such project"
		// and "no such release of this project". Ask the project-level
		// document which one it was before the coordinate is scored.
		warn = p.promoteVersionNotFound(ctx, "pypi", warn, endpoint, pkg, ver, p.probePyPIPackage(pkg))
		pr.Warnings = append(pr.Warnings, *warn)
		return pr, nil
	}

	release := &ReleaseSection{}
	artifact := &ArtifactSection{}
	urls := &URLSection{MetadataURL: endpoint}
	// Pick the canonical distribution — prefer the wheel if present,
	// else the sdist.
	var picked *struct {
		Filename       string            `json:"filename"`
		PackageType    string            `json:"packagetype"`
		Size           int64             `json:"size"`
		URL            string            `json:"url"`
		UploadTime     string            `json:"upload_time_iso_8601"`
		Digests        map[string]string `json:"digests"`
		HasSig         bool              `json:"has_sig"`
		RequiresPython string            `json:"requires_python"`
		Yanked         bool              `json:"yanked"`
	}
	for i := range pack.URLs {
		u := &pack.URLs[i]
		if picked == nil || u.PackageType == "bdist_wheel" {
			picked = u
			if u.PackageType == "bdist_wheel" {
				break
			}
		}
	}
	if picked != nil {
		artifact.Filename = picked.Filename
		artifact.Packaging = picked.PackageType
		artifact.Size = picked.Size
		if picked.URL != "" {
			urls.ArtifactURL = picked.URL
		}
		if d := picked.Digests; d != nil {
			artifact.Digests.SHA256 = d["sha256"]
			artifact.Digests.MD5 = d["md5"]
			artifact.Digests.Blake2b256 = d["blake2b_256"]
		}
		if t, ok := parseTime(picked.UploadTime); ok {
			release.PublishedAt = &t
		}
	}

	if pack.Info.HomePage != "" {
		urls.HomepageURL = pack.Info.HomePage
	}
	if u := pack.Info.ProjectURLs["Documentation"]; u != "" {
		urls.DocumentationURL = u
	} else if pack.Info.DocsURL != "" {
		urls.DocumentationURL = pack.Info.DocsURL
	}
	if u := pack.Info.ProjectURLs["Source"]; u != "" {
		urls.SourceRepoURL = u
	} else if u := pack.Info.ProjectURLs["Repository"]; u != "" {
		urls.SourceRepoURL = u
	} else if u := pack.Info.ProjectURLs["Homepage"]; u != "" && urls.HomepageURL == "" {
		urls.HomepageURL = u
	}
	if u := pack.Info.ProjectURLs["Issues"]; u != "" {
		urls.IssuesURL = u
	} else if u := pack.Info.ProjectURLs["Tracker"]; u != "" {
		urls.IssuesURL = u
	}

	metadata := &MetadataSection{
		LicenseExpression: firstNonEmpty(pack.Info.LicenseExpression, pack.Info.License),
		Summary:           pack.Info.Summary,
		Description:       pack.Info.Description,
		RequiresRuntime:   pack.Info.RequiresPython,
	}
	if pack.Info.Keywords != "" {
		metadata.Keywords = splitCommaList(pack.Info.Keywords)
	}

	people := &PeopleSection{}
	// PyPI exposes author/author_email and maintainer/maintainer_email at
	// the project level. Each *_email field may be a CSV of multiple
	// addresses (e.g. "alice@x.com, bob@x.com") even when the matching
	// name field is a single string. Surface each email as its own people
	// entry so the UI can list them individually.
	for _, a := range expandPyPIPersons(pack.Info.Author, pack.Info.AuthorEmail) {
		people.Authors = append(people.Authors, a)
	}
	for _, m := range expandPyPIPersons(pack.Info.Maintainer, pack.Info.MaintainerEmail) {
		people.Maintainers = append(people.Maintainers, m)
	}

	yanked, yankReason := normalisePyPIYanked(pack.Info.Yanked, pack.Info.YankedReason)
	release.Yanked = &yanked
	if yanked && yankReason != "" {
		release.Deprecated = "yanked: " + yankReason
	}

	pr.Release = release
	pr.URLs = urls
	pr.Artifact = artifact
	pr.Metadata = metadata
	if len(people.Authors)+len(people.Maintainers) > 0 {
		pr.People = people
	}
	deps := parsePyPIRequiresDist(pack.Info.RequiresDist)
	if !deps.empty() {
		pr.Dependencies = deps.section()
	}
	if urls.SourceRepoURL != "" {
		pr.Provenance = &ProvenanceSection{SourceRepo: urls.SourceRepoURL}
	}

	// Pull the project-level packument to populate the full version
	// timeline. PyPI's `/pypi/{pkg}/json` (no version) returns a
	// `releases` map keyed by version; each value is an array of upload
	// records — we use the first record's upload_time_iso_8601 as the
	// publish time for that version. Fail-soft: a transient error here
	// just leaves Maintenance.VersionTimeline empty.
	timeline, latest, tlWarn := p.fetchPyPITimeline(ctx, pkg)
	applyTimeline(&pr, timeline, latest, tlWarn)
	// Surface stars/forks/etc. when the repo URL points at GitHub.
	enrichRepoStars(ctx, p, &pr)
	return pr, nil
}

// fetchPyPITimeline calls the project-level packument and returns the
// full (version, publish-time) timeline plus the registry-declared
// latest version. Errors are returned as a Warning the caller can append
// — the caller never aborts on this failure.
func (p *registryMetadataProvider) fetchPyPITimeline(ctx context.Context, pkg string) ([]VersionRelease, string, *Warning) {
	doc := p.fetchPyPITimelineDoc(ctx, pkg)
	return doc.timeline, doc.latest, doc.wrapped(p)
}

// fetchPyPITimelineDoc is the fetch+parse half, returning the RAW fetch
// warning. See timelineDoc for why the split exists.
func (p *registryMetadataProvider) fetchPyPITimelineDoc(ctx context.Context, pkg string) timelineDoc {
	endpoint := fmt.Sprintf("%s/pypi/%s/json", p.endpoints.pypi, url.PathEscape(pkg))
	var pack struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
		Releases map[string][]struct {
			UploadTime string `json:"upload_time_iso_8601"`
		} `json:"releases"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &pack)
	if err != nil || warn != nil {
		return timelineDoc{endpoint: endpoint, warn: warn, err: err}
	}
	timeline := make([]VersionRelease, 0, len(pack.Releases))
	for ver, uploads := range pack.Releases {
		rel := VersionRelease{Version: ver}
		// Use the earliest upload_time for that version. The PyPI JSON
		// returns multiple upload records per release (one per dist
		// type); each shares the same "upload_time_iso_8601" within a
		// release, so taking the first is enough in practice — but we
		// scan all to be safe against weird ordering.
		for _, u := range uploads {
			t, ok := parseTime(u.UploadTime)
			if !ok {
				continue
			}
			if rel.PublishedAt.IsZero() || t.Before(rel.PublishedAt) {
				rel.PublishedAt = t
			}
		}
		timeline = append(timeline, rel)
	}
	return timelineDoc{timeline: timeline, latest: strings.TrimSpace(pack.Info.Version), endpoint: endpoint}
}

// parsePyPIRequiresDist turns a PEP 508 requirement list into a
// DependenciesSection. PEP 508 lines look like:
//
//	"requests (>=2.27); python_version < '3.10'"
//	"pytest >=7 ; extra == 'test'"
//
// We split off the marker (`; extra == 'test'`), bucket "extra==test"
// or "extra=='dev'" entries into the Optional list (the closest analog
// to npm's optional/dev split for tooling extras), and put everything
// else into Direct. Constraint preserves the version part verbatim.
func parsePyPIRequiresDist(lines []string) depCollector {
	d := depCollector{}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// Split on ';' — left side is the requirement, right side the
		// PEP 508 marker (optional).
		var req, marker string
		if i := strings.Index(line, ";"); i >= 0 {
			req = strings.TrimSpace(line[:i])
			marker = strings.TrimSpace(line[i+1:])
		} else {
			req = line
		}
		// req is "name [extras] [(spec)] [spec]". Take the leading
		// identifier; the rest is the version constraint.
		name, constraint := splitPyPIRequirement(req)
		if name == "" {
			continue
		}
		ref := DependencyRef{Name: name, Constraint: constraint}
		if isPyPIExtraMarker(marker) {
			d.optional = append(d.optional, ref)
		} else {
			d.direct = append(d.direct, ref)
		}
	}
	return d
}

func splitPyPIRequirement(req string) (name, constraint string) {
	// First non-identifier character ends the name.
	for i, r := range req {
		if !(r == '_' || r == '-' || r == '.' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			name = strings.TrimSpace(req[:i])
			rest := strings.TrimSpace(req[i:])
			// PEP 508 allows "name[extra1,extra2] >=1.0" — strip the
			// bracketed extras list so the constraint is just the
			// version specifier.
			if strings.HasPrefix(rest, "[") {
				if end := strings.Index(rest, "]"); end >= 0 {
					rest = strings.TrimSpace(rest[end+1:])
				}
			}
			return name, rest
		}
	}
	return strings.TrimSpace(req), ""
}

// normalisePyPIYanked accepts a yanked value that may be a bool or a
// string-with-reason and returns a clean (bool, reason) pair.
func normalisePyPIYanked(raw any, reason string) (bool, string) {
	switch v := raw.(type) {
	case bool:
		return v, strings.TrimSpace(reason)
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return false, strings.TrimSpace(reason)
		}
		r := strings.TrimSpace(reason)
		if r == "" {
			r = s
		}
		return true, r
	}
	return false, strings.TrimSpace(reason)
}

func isPyPIExtraMarker(marker string) bool {
	return strings.Contains(marker, "extra ==") || strings.Contains(marker, "extra==")
}

// expandPyPIPersons returns one people-string per "person" represented
// by the (name, email) pair from PyPI's info block. PyPI lets either
// field be a comma-separated list — older packages put a single name
// in author and several addresses in author_email; newer ones put a
// single object encoded as comma-separated names matched to emails. We
// align them positionally when both are CSVs of equal length, otherwise
// fall back to a single joined string. Returns nil when both inputs
// are empty so the caller can leave People.* as nil.
func expandPyPIPersons(name, email string) []string {
	name = strings.TrimSpace(name)
	email = strings.TrimSpace(email)
	if name == "" && email == "" {
		return nil
	}
	names := splitCommaList(name)
	emails := splitCommaList(email)
	switch {
	case len(names) <= 1 && len(emails) <= 1:
		s := joinAuthor(name, email)
		if s == "" {
			return nil
		}
		return []string{s}
	case len(names) == len(emails):
		out := make([]string, 0, len(names))
		for i := range names {
			if s := joinAuthor(names[i], emails[i]); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		// Mismatched lengths — emit each side independently rather than
		// guessing which name pairs with which email.
		var out []string
		for _, n := range names {
			if n != "" {
				out = append(out, n)
			}
		}
		for _, e := range emails {
			if e != "" {
				out = append(out, e)
			}
		}
		return out
	}
}

// -- Maven / Gradle ---------------------------------------------------

type mavenPOM struct {
	GroupID     string `xml:"groupId"`
	ArtifactID  string `xml:"artifactId"`
	Version     string `xml:"version"`
	Name        string `xml:"name"`
	Description string `xml:"description"`
	URL         string `xml:"url"`
	// Parent is the POM's `<parent>` coordinate. ArtifactID is as
	// load-bearing as the other two: it is what turns the element into a
	// resolvable repository path (see fetchMavenPOM). It was not parsed
	// before the parent-licence walk, which is why guava and log4j-core
	// — both of which declare their licence ONLY in a parent — came back
	// with an empty LicenseExpression and scored lic.missing (-15) plus
	// license.unidentified (-15).
	//
	// `<relativePath>` is deliberately NOT modelled. It is a filesystem
	// hint for a local reactor build ("../pom.xml"); against a registry
	// it is meaningless, and honouring it could only ever produce a URL
	// that is not the parent's published location. We always resolve the
	// parent from groupId/artifactId/version.
	Parent struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	} `xml:"parent"`
	Licenses struct {
		License []struct {
			Name string `xml:"name"`
			URL  string `xml:"url"`
		} `xml:"license"`
	} `xml:"licenses"`
	SCM             mavenPOMSCM `xml:"scm"`
	IssueManagement struct {
		URL string `xml:"url"`
	} `xml:"issueManagement"`
	Developers struct {
		Developer []struct {
			// ID is the POM `<developer><id>` element. It is the
			// stable publisher key (see MavenDeveloperPublisherIDs)
			// and was NOT parsed before P8-70 — which is why the
			// incoming publisher set disagreed with the persisted
			// baseline on every maven package.
			ID    string `xml:"id"`
			Name  string `xml:"name"`
			Email string `xml:"email"`
		} `xml:"developer"`
	} `xml:"developers"`
	Dependencies struct {
		Dependency []struct {
			GroupID    string `xml:"groupId"`
			ArtifactID string `xml:"artifactId"`
			Version    string `xml:"version"`
			Scope      string `xml:"scope"`
			Optional   string `xml:"optional"`
		} `xml:"dependency"`
	} `xml:"dependencies"`
	// Properties is the POM's own <properties> block. Its children are
	// user-chosen element names (<slf4jVersion>1.7.36</slf4jVersion>), so
	// it cannot be modelled as named fields — `xml:",any"` collects each
	// child with its tag in XMLName. See resolveMavenVersion.
	Properties struct {
		Entries []mavenPOMProperty `xml:",any"`
	} `xml:"properties"`
}

// mavenPOMProperty is one <properties> child: the element name is the
// property name, the character data is its value.
type mavenPOMProperty struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// mavenPOMSCM mirrors the three URL-bearing children of a POM's <scm>
// block. Maven defines them in priority order: <url> is the
// human-browsable mirror, <connection> is the read-only checkout URL
// (prefixed `scm:<provider>:` per the SCM URL spec), and
// <developerConnection> is the read-write counterpart. Some projects
// only populate the latter two — extractMavenSourceRepo handles the
// fallback so SourceRepoURL doesn't end up empty when the human URL is
// missing.
type mavenPOMSCM struct {
	URL                 string `xml:"url"`
	Connection          string `xml:"connection"`
	DeveloperConnection string `xml:"developerConnection"`
}

// extractMavenSourceRepo returns the best git source-repo URL available
// from a POM's <scm> block. Priority: <url>, <connection>,
// <developerConnection>. The connection fields are formatted as
// `scm:<provider>:<url>` per the Maven SCM URL spec; we strip the
// prefix and only accept git providers (`scm:git:`), since GitHub,
// GitLab, Bitbucket, and Codeberg are all git-only forges and accepting
// `scm:svn:` / `scm:hg:` / `scm:bzr:` would feed enrichRepoStars URLs
// it can't action. SSH shapes (`git@host:owner/repo[.git]` and
// `ssh://git@host/owner/repo[.git]`) are normalised to
// `https://host/owner/repo` so the same downstream forge parser
// (parseForgeRepo / parseGitHubOwnerRepo) handles them.
func extractMavenSourceRepo(scm mavenPOMSCM) string {
	if u := strings.TrimSpace(scm.URL); u != "" {
		return u
	}
	if u := normalizeMavenSCMConnection(scm.Connection); u != "" {
		return u
	}
	if u := normalizeMavenSCMConnection(scm.DeveloperConnection); u != "" {
		return u
	}
	return ""
}

// normalizeMavenSCMConnection strips the `scm:git:` prefix from a Maven
// SCM connection URL and normalises SSH shapes to https. Returns "" for
// non-git providers (scm:svn:, scm:hg:, scm:bzr:, …) and for malformed
// inputs. The function is deliberately small and case-insensitive on
// the prefix because real-world POMs are inconsistent (e.g.
// `SCM:GIT:...` shows up).
func normalizeMavenSCMConnection(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// Must be a Maven SCM URL: `scm:<provider>:<rest>`. Reject anything
	// that doesn't match the shape rather than guessing.
	if !strings.HasPrefix(strings.ToLower(s), "scm:") {
		return ""
	}
	rest := s[len("scm:"):]
	colon := strings.Index(rest, ":")
	if colon <= 0 {
		return ""
	}
	provider := strings.ToLower(rest[:colon])
	if provider != "git" {
		// Reject scm:svn:, scm:hg:, scm:bzr:, scm:cvs:, … — only git
		// hosts surface stars/forks/issues via our enrichers.
		return ""
	}
	url := strings.TrimSpace(rest[colon+1:])
	if url == "" {
		return ""
	}
	// SSH with explicit scheme: `ssh://git@github.com/owner/repo[.git]`.
	if lower := strings.ToLower(url); strings.HasPrefix(lower, "ssh://") {
		tail := url[len("ssh://"):]
		// Strip optional `user@` prefix.
		if at := strings.Index(tail, "@"); at >= 0 {
			tail = tail[at+1:]
		}
		// `host/owner/repo[.git]` — host is the segment before the
		// first slash.
		slash := strings.Index(tail, "/")
		if slash <= 0 {
			return ""
		}
		host := tail[:slash]
		path := strings.TrimSuffix(tail[slash+1:], ".git")
		if host == "" || path == "" {
			return ""
		}
		return "https://" + host + "/" + path
	}
	// SCP-style SSH: `git@github.com:owner/repo[.git]`. No `://`, but
	// has a `:` after the host.
	if !strings.Contains(url, "://") {
		// Strip optional `user@` prefix.
		at := strings.Index(url, "@")
		if at < 0 {
			return ""
		}
		hostAndPath := url[at+1:]
		colon := strings.Index(hostAndPath, ":")
		if colon <= 0 {
			return ""
		}
		host := hostAndPath[:colon]
		path := strings.TrimSuffix(hostAndPath[colon+1:], ".git")
		if host == "" || path == "" {
			return ""
		}
		return "https://" + host + "/" + path
	}
	// http(s):// — trim trailing `.git` for parity with the SSH paths
	// and with how npm/cargo SourceRepoURLs are already canonicalised
	// elsewhere in this provider.
	return strings.TrimSuffix(url, ".git")
}

// -- Maven property interpolation -------------------------------------
//
// A POM routinely declares a dependency version indirectly:
//
//	<properties><slf4jVersion>1.7.36</slf4jVersion></properties>
//	...
//	<dependency>…<version>${slf4jVersion}</version></dependency>
//
// This provider used to copy that `<version>` into DependencyRef.Constraint
// verbatim. Two things then went wrong downstream: the placeholder was warmed
// into intelligence_reports as though it were a pinned version (three such
// rows were live in production on 2026-08-23, reading as scanned-and-clean),
// and after cache_warm.pinnedVersion learned to refuse `${`, the dependency
// stopped being warmed at all — real transitive coverage silently dropped for
// a shape Maven projects use constantly.
//
// Resolving the placeholder against the SAME DOCUMENT fixes both: the common
// case yields a concrete version that can be warmed and matched, and anything
// still unresolved keeps its placeholder text so pinnedVersion and
// UnevaluableVersionReason continue to refuse it.
//
// WHAT IS DELIBERATELY OUT OF SCOPE. Maven's real interpolation model is the
// *effective* POM: properties inherited from a parent POM (and from that
// parent's parent, up to a corporate BOM), from an active <profile>, from
// dependencyManagement, from settings.xml, and from the JVM/environment.
// Resolving those needs the whole POM hierarchy — fetch the parent, merge,
// recurse, decide which profiles are active — which is a project in its own
// right (upstream Trivy dedicates an entire package to it). This function
// deliberately does none of it. A property this document does not itself
// declare stays unresolved, and unresolved stays refused: a WRONG version is
// far worse than a missing one, because it silently attaches advisories to a
// release the project never depended on.

// maxMavenPropertyDepth caps how many substitution passes resolveMavenVersion
// will make. It exists purely to terminate pathological input — a
// self-referential property (<a>${a}</a>), a two-property cycle
// (<a>${b}</a><b>${a}</a>), or a deliberately deep nest in a hostile POM.
// Real POMs nest one or two levels (${foo.version} → ${project.version}); 8
// is comfortably beyond anything legitimate and small enough that a malicious
// document cannot buy meaningful CPU with it.
const maxMavenPropertyDepth = 8

// maxMavenPropertyLen caps the length of an intermediate expansion. A version
// string is a handful of bytes; a value that grows past this is either
// nonsense or an attempt at expansion blow-up, and either way the result
// cannot be a version.
const maxMavenPropertyLen = 512

// mavenPOMProperties flattens a POM's <properties> block into a lookup map.
// Whitespace is trimmed from both the name and the value, and entries with an
// empty name are dropped. Later duplicates win, matching Maven's
// last-declaration-wins behaviour for repeated elements.
func mavenPOMProperties(pom *mavenPOM) map[string]string {
	if pom == nil || len(pom.Properties.Entries) == 0 {
		return nil
	}
	props := make(map[string]string, len(pom.Properties.Entries))
	for _, e := range pom.Properties.Entries {
		name := strings.TrimSpace(e.XMLName.Local)
		if name == "" {
			continue
		}
		props[name] = strings.TrimSpace(e.Value)
	}
	return props
}

// mavenProjectVersionAliases are the built-in property names that refer to
// the POM's own <version>. `project.version` is the modern spelling;
// `pom.version` is the Maven 2 spelling, still widespread in the wild; bare
// `version` is the deprecated implicit form. All three are answered from the
// same document, so resolving them needs no hierarchy.
var mavenProjectVersionAliases = []string{"project.version", "pom.version", "version"}

// resolveMavenVersion interpolates `${…}` placeholders in a POM dependency
// version using ONLY properties declared in the same document, plus the
// project's own version for the aliases above.
//
// Returns the resolved version when every placeholder could be substituted.
// Returns `raw` UNCHANGED when any placeholder is unresolvable, cyclic, or
// nested past maxMavenPropertyDepth — deliberately, so the caller stores the
// literal `${…}` text. That text is what makes the gap visible: pinnedVersion
// refuses it (so no bogus row is warmed) and UnevaluableVersionReason marks
// it (so it cannot read as scanned-and-clean). Substituting a guess, or
// blanking the constraint, would both hide the unresolved manifest instead.
//
// A `props` entry whose own value contains `${…}` is itself expanded, which
// is why this is a loop rather than a single pass.
func resolveMavenVersion(raw string, props map[string]string, projectVersion string) string {
	v := strings.TrimSpace(raw)
	if !strings.Contains(v, unresolvedPropertyMarker) {
		return v
	}
	projectVersion = strings.TrimSpace(projectVersion)

	cur := v
	for depth := 0; depth < maxMavenPropertyDepth; depth++ {
		next, ok := expandMavenProperties(cur, props, projectVersion)
		if !ok {
			// A placeholder named something this document does not declare.
			// No number of further passes can help.
			return v
		}
		if !strings.Contains(next, unresolvedPropertyMarker) {
			return strings.TrimSpace(next)
		}
		if next == cur {
			// No progress: self-reference (<a>${a}</a>) or a cycle that has
			// come back around to a value it already produced.
			return v
		}
		if len(next) > maxMavenPropertyLen {
			return v
		}
		cur = next
	}
	// Still unresolved after the cap — a longer cycle, or a nest deeper than
	// anything legitimate. Treated exactly like an unresolvable property.
	return v
}

// expandMavenProperties performs ONE substitution pass over s, replacing each
// `${name}` with its value. ok is false as soon as a placeholder names
// something neither `props` nor the project-version aliases can answer, and
// also for a malformed placeholder (`${` with no closing brace) — in both
// cases the caller gives up rather than emitting a half-substituted string.
func expandMavenProperties(s string, props map[string]string, projectVersion string) (string, bool) {
	var b strings.Builder
	for {
		start := strings.Index(s, unresolvedPropertyMarker)
		if start < 0 {
			b.WriteString(s)
			return b.String(), true
		}
		end := strings.Index(s[start:], "}")
		if end < 0 {
			// Truncated placeholder. UnevaluableVersionReason detects on the
			// `${` substring precisely so this shape is caught too; refusing
			// here keeps the two consistent.
			return "", false
		}
		end += start
		name := strings.TrimSpace(s[start+len(unresolvedPropertyMarker) : end])
		val, ok := lookupMavenProperty(name, props, projectVersion)
		if !ok {
			return "", false
		}
		b.WriteString(s[:start])
		b.WriteString(val)
		s = s[end+1:]
	}
}

// lookupMavenProperty answers a single property name from the same document.
// A declared <properties> entry wins over the built-in project-version
// aliases, matching Maven: an explicit declaration shadows the implicit one.
// An entry declared with an EMPTY value is not an answer — Maven would
// interpolate it to nothing and produce a versionless dependency, which is
// not a version we can evaluate.
func lookupMavenProperty(name string, props map[string]string, projectVersion string) (string, bool) {
	if name == "" {
		return "", false
	}
	if v, ok := props[name]; ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v), true
	}
	for _, alias := range mavenProjectVersionAliases {
		if name == alias && projectVersion != "" {
			return projectVersion, true
		}
	}
	return "", false
}

// mavenProjectVersion is the value `${project.version}` resolves to for this
// document. Preference order:
//
//	<project><version>   — the POM's own declaration, the authoritative one;
//	<parent><version>    — what Maven inherits when the child omits its own.
//	                       This is NOT parent-POM resolution: the element is
//	                       literally in this document, so no fetch is needed;
//	requestedVersion     — the version whose .pom we just fetched. The
//	                       artifact path encodes it, so it is correct by
//	                       construction, and it is the backstop for a POM
//	                       that declares neither of the above.
func mavenProjectVersion(pom *mavenPOM, requestedVersion string) string {
	if pom != nil {
		if v := strings.TrimSpace(pom.Version); v != "" && !strings.Contains(v, unresolvedPropertyMarker) {
			return v
		}
		if v := strings.TrimSpace(pom.Parent.Version); v != "" && !strings.Contains(v, unresolvedPropertyMarker) {
			return v
		}
	}
	return strings.TrimSpace(requestedVersion)
}

// maxMavenParentDepth bounds the `<parent>` chain walk.
//
// Five is chosen from the shape of real chains, not from caution: the two
// coordinates that motivated this work are two and three hops deep
// (guava -> guava-parent; log4j-core -> log4j -> logging-parent), and the
// deepest published chains in common use — the Spring Boot starters
// (starter -> spring-boot-starters -> spring-boot-parent -> spring-boot-build)
// and the Sonatype/Apache house parents (foo -> foo-parent -> oss-parent ->
// apache) — reach four. Five clears both with one hop of headroom while
// capping the worst case at five extra HTTP requests per Maven coordinate.
// Anything deeper is answered with silence, which is the same answer the
// reader gave before this walk existed.
const maxMavenParentDepth = 5

// isSafeMavenCoordinateSegment reports whether one component of a parent
// coordinate can be pasted into a repository URL.
//
// A POM is bytes fetched from a registry, so `<parent>` is attacker-
// influenced input and this is the only place where its contents become a
// URL we then fetch. The accepted set is what Maven itself allows in a
// groupId / artifactId / version — letters, digits, `.`, `_`, `-`, `+` —
// which excludes path separators, `%`, `:`, `@`, whitespace and `${`, and
// therefore excludes traversal, scheme injection and host smuggling. `..`
// is rejected outright even though both its characters are on the list.
//
// A rejected coordinate is not an error: the walk stops and the artifact
// keeps the licence (or the absence of one) it already had.
func isSafeMavenCoordinateSegment(s string) bool {
	if s == "" || len(s) > 200 {
		return false
	}
	if strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-' || r == '+':
		default:
			return false
		}
	}
	return true
}

// mavenCoordKey is the visited-set key for one point in a parent chain.
func mavenCoordKey(group, artifact, version string) string {
	return group + ":" + artifact + ":" + version
}

// mavenDeclaredLicense returns the licence this ONE document declares,
// interpolated against its own `<properties>` where it has to be.
//
// A `${...}` that the document cannot answer is skipped rather than
// emitted. Storing the literal `${license.name}` where an SPDX id belongs
// is the licence-shaped version of the defect Phase 7 Wave 5 fixed for
// versions: it does not read as missing (so lic.missing stays quiet) and
// it does not classify (so license.unidentified fires anyway), which is
// strictly worse than declaring nothing. Silence is the honest answer.
func mavenDeclaredLicense(pom *mavenPOM, requestedVersion string) string {
	if pom == nil {
		return ""
	}
	var (
		props          map[string]string
		projectVersion string
		loaded         bool
	)
	for _, l := range pom.Licenses.License {
		s := strings.TrimSpace(l.Name)
		if s == "" {
			continue
		}
		if strings.Contains(s, unresolvedPropertyMarker) {
			if !loaded {
				props = mavenPOMProperties(pom)
				projectVersion = mavenProjectVersion(pom, requestedVersion)
				loaded = true
			}
			expanded, ok := expandMavenProperties(s, props, projectVersion)
			if !ok || strings.Contains(expanded, unresolvedPropertyMarker) {
				continue
			}
			s = strings.TrimSpace(expanded)
			if s == "" {
				continue
			}
		}
		return s
	}
	return ""
}

// fetchMavenPOM reads one published POM. Returns (nil, false) for every
// failure — a 404, a 5xx, a parse error — because the only caller is the
// parent walk, where "could not read it" and "it said nothing" have the
// same correct outcome: leave the artifact as it is.
//
// Base-URL selection mirrors fetchMavenTimelineDoc exactly: repo1 first,
// and for the namespaces Google hosts, maven.google.com on a DEFINITE
// absence only. A parent hosted on maven.google.com (every androidx
// artifact inherits from `androidx:androidx-*`) therefore resolves, and a
// repo1 outage still costs one request, not two.
func (p *registryMetadataProvider) fetchMavenPOM(ctx context.Context, group, artifact, version string) (*mavenPOM, bool) {
	groupPath := strings.ReplaceAll(group, ".", "/")
	pom, warn, err := p.fetchMavenPOMFrom(ctx, p.endpoints.maven, groupPath, artifact, version)
	if err == nil && warn == nil {
		return pom, true
	}
	if isDefiniteAbsence(warn) && groupUsesGoogleMaven(groupPath) && p.endpoints.mavenGoogle != "" {
		if alt, w, e := p.fetchMavenPOMFrom(ctx, p.endpoints.mavenGoogle, groupPath, artifact, version); e == nil && w == nil {
			return alt, true
		}
	}
	return nil, false
}

func (p *registryMetadataProvider) fetchMavenPOMFrom(ctx context.Context, base, groupPath, artifact, version string) (*mavenPOM, *Warning, error) {
	endpoint := fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom", base, groupPath, artifact, version, artifact, version)
	var pom mavenPOM
	warn, err := p.fetchXML(ctx, endpoint, &pom)
	if err != nil || warn != nil {
		return nil, warn, err
	}
	return &pom, nil, nil
}

// inheritMavenLicense walks the `<parent>` chain looking for the licence
// the artifact's own POM did not declare.
//
// This is Maven's own rule, not an invention: `<licenses>` is an
// inherited element, so a child that declares none IS licensed under its
// parent's terms. guava (33.x) and log4j-core (2.x) are the two most
// visible examples in any Java tree; before this walk both rendered a
// licence-missing warning on an Apache-2.0 artifact.
//
// Four properties, each pinned by a test:
//
//   - Bounded: at most maxMavenParentDepth hops.
//   - Cycle-safe: a self-parent, or A->B->A, terminates.
//   - Each coordinate is fetched at most once. The visited set IS the
//     cache — within one walk a repeated coordinate can only be a cycle,
//     so the right response is to stop, not to serve it again from a map.
//     (A cache spanning packages would have to live on the provider,
//     which is process-lifetime, unbounded and stale-prone; deliberately
//     not done.)
//   - A missing or unfetchable parent is silence. No warning is added to
//     the artifact's report: the artifact itself was fetched fine, and a
//     parent's 404 is not a fact about the artifact.
func (p *registryMetadataProvider) inheritMavenLicense(ctx context.Context, pom *mavenPOM, group, artifact, version string) string {
	if pom == nil {
		return ""
	}
	seen := map[string]struct{}{mavenCoordKey(group, artifact, version): {}}
	cur := pom
	for depth := 0; depth < maxMavenParentDepth; depth++ {
		pg := strings.TrimSpace(cur.Parent.GroupID)
		pa := strings.TrimSpace(cur.Parent.ArtifactID)
		pv := strings.TrimSpace(cur.Parent.Version)
		if pg == "" || pa == "" || pv == "" {
			return "" // no parent, or one we cannot address
		}
		// A `${revision}`-style parent version (the flatten-plugin
		// idiom) is not resolvable from the child document, and the
		// coordinate has to be URL-safe before it becomes a request.
		if !isSafeMavenCoordinateSegment(pg) || !isSafeMavenCoordinateSegment(pa) || !isSafeMavenCoordinateSegment(pv) {
			return ""
		}
		key := mavenCoordKey(pg, pa, pv)
		if _, dup := seen[key]; dup {
			return "" // cycle
		}
		seen[key] = struct{}{}

		parent, ok := p.fetchMavenPOM(ctx, pg, pa, pv)
		if !ok {
			return ""
		}
		if lic := mavenDeclaredLicense(parent, pv); lic != "" {
			return lic
		}
		cur = parent
	}
	return ""
}

func (p *registryMetadataProvider) runMaven(ctx context.Context, pkg, ver string) (PartialReport, error) {
	group, artifact, classifier := splitMavenCoordinate(pkg)
	if group == "" || artifact == "" {
		return PartialReport{}, nil
	}
	groupPath := strings.ReplaceAll(group, ".", "/")
	pomURL := fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom", p.endpoints.maven, groupPath, artifact, ver, artifact, ver)

	var pom mavenPOM
	warn, err := p.fetchXML(ctx, pomURL, &pom)
	if err != nil {
		return PartialReport{}, err
	}
	pr := PartialReport{}
	if warn != nil {
		// A missing .pom is a missing version directory; it says nothing
		// about whether the groupId:artifactId exists. maven-metadata.xml
		// one level up does.
		warn = p.promoteVersionNotFound(ctx, "maven", warn, pomURL, pkg, ver, p.probeMavenPackage(groupPath, artifact))
		pr.Warnings = append(pr.Warnings, *warn)
		return pr, nil
	}

	// `<licenses>` is an INHERITED POM element. An artifact that declares
	// none is not unlicensed — it is licensed under its parent's terms,
	// which is how guava and log4j-core (Apache-2.0 both) used to arrive
	// here with nothing and score lic.missing + license.unidentified.
	// Read this document first; only walk the parent chain when it is
	// genuinely silent. See inheritMavenLicense.
	license := mavenDeclaredLicense(&pom, ver)
	if license == "" {
		license = p.inheritMavenLicense(ctx, &pom, group, artifact, ver)
	}

	people := &PeopleSection{}
	// Maven/Gradle POM `<developers>` is the canonical "people who
	// publish + maintain this artifact" list — Maven Central does not
	// distinguish authors from maintainers in metadata. Surface each
	// entry on both axes so the UI's People panel renders.
	//
	// PublisherIDs is the MACHINE identity, not a display field: it is
	// diffed against the persisted package_metadata.publisher_set column
	// by the metadiff provider (sc.publisher_changed) and by the
	// first-time-collaborator provider. It therefore has to use exactly
	// the precedence the baseline extractor uses — `<id>`, then
	// `<email>`, then `<name>` — via the single shared helper. Before
	// P8-70 this branch preferred `<email>`/`<name>` while the baseline
	// preferred `<id>`, so the two sets never intersected and the
	// SevHigh publisher-changed signal fired on every maven package with
	// any scan history. Authors/Maintainers keep the human-readable
	// `Name <email>` render for the UI.
	for _, d := range pom.Developers.Developer {
		s := joinAuthor(d.Name, d.Email)
		if s != "" {
			people.Authors = append(people.Authors, s)
			people.Maintainers = append(people.Maintainers, s)
		}
		people.PublisherIDs = append(people.PublisherIDs, MavenDeveloperPublisherIDs(d.ID, d.Email, d.Name)...)
	}

	jarBase := fmt.Sprintf("%s-%s", artifact, ver)
	if classifier != "" {
		jarBase = fmt.Sprintf("%s-%s-%s", artifact, ver, classifier)
	}
	urls := &URLSection{
		MetadataURL:   pomURL,
		ArtifactURL:   fmt.Sprintf("%s/%s/%s/%s/%s.jar", p.endpoints.maven, groupPath, artifact, ver, jarBase),
		HomepageURL:   strings.TrimSpace(pom.URL),
		SourceRepoURL: extractMavenSourceRepo(pom.SCM),
		IssuesURL:     strings.TrimSpace(pom.IssueManagement.URL),
	}
	art := &ArtifactSection{
		Filename:  jarBase + ".jar",
		Packaging: "jar",
	}
	metadata := &MetadataSection{
		LicenseExpression: license,
		Summary:           firstLine(pom.Description),
		Description:       pom.Description,
	}

	pr.URLs = urls
	pr.Artifact = art
	pr.Metadata = metadata
	if len(people.Authors)+len(people.Maintainers)+len(people.PublisherIDs) > 0 {
		pr.People = people
	}
	d := depCollector{}
	// Interpolate `${…}` versions against this document's own <properties>
	// and its project version. Anything that cannot be resolved from this
	// document keeps its literal placeholder — see resolveMavenVersion.
	props := mavenPOMProperties(&pom)
	projectVersion := mavenProjectVersion(&pom, ver)
	for _, dep := range pom.Dependencies.Dependency {
		if dep.GroupID == "" || dep.ArtifactID == "" {
			continue
		}
		ref := DependencyRef{
			Name:       dep.GroupID + ":" + dep.ArtifactID,
			Constraint: resolveMavenVersion(dep.Version, props, projectVersion),
		}
		switch {
		case strings.EqualFold(dep.Optional, "true"):
			d.optional = append(d.optional, ref)
		case strings.EqualFold(dep.Scope, "test"):
			d.dev = append(d.dev, ref)
		case strings.EqualFold(dep.Scope, "provided") || strings.EqualFold(dep.Scope, "system"):
			d.peer = append(d.peer, ref)
		default:
			d.direct = append(d.direct, ref)
		}
	}
	if !d.empty() {
		pr.Dependencies = d.section()
	}
	if urls.SourceRepoURL != "" {
		pr.Provenance = &ProvenanceSection{SourceRepo: urls.SourceRepoURL}
	}

	// Pull the artifact-level maven-metadata.xml to populate the full
	// version timeline. Maven Central doesn't expose per-version publish
	// times in this document (those live on each POM's Last-Modified
	// header, which we deliberately skip — fetching N HEADs per scan is
	// prohibitive), so each VersionRelease has a zero PublishedAt. The
	// risk engine only consumes len(timeline) + Release.PublishedAt for
	// the requested version (already populated from the POM fetch via
	// other providers), so zero PublishedAt here is acceptable.
	// Fail-soft: a 5xx / parse error emits timeline_fetch_failed and the
	// primary POM fetch above remains the source of truth.
	timeline, latest, lastUpdated, tlWarn := p.fetchMavenTimeline(ctx, groupPath, artifact)
	applyTimeline(&pr, timeline, latest, tlWarn)
	// applyTimeline only derives FirstPublishedAt from non-zero
	// per-version PublishedAt values; Maven entries always have a zero
	// PublishedAt (see fetchMavenTimeline for the why), so we backfill
	// FirstPublishedAt from `<lastUpdated>` when the XML carried a
	// parseable one. This is a loose proxy ("when was the artifact last
	// touched" vs "when was it first published") but it's the only
	// timestamp the document exposes; consumers that need true
	// first-publish times should HEAD the oldest POM separately.
	if !lastUpdated.IsZero() && pr.Maintenance != nil && pr.Maintenance.FirstPublishedAt == nil {
		t := lastUpdated
		pr.Maintenance.FirstPublishedAt = &t
	}
	// Apache projects publish their POM with `<scm><url>` pointing at
	// gitbox.apache.org (the canonical authoritative mirror) even though
	// the active development repo lives on github.com/apache/<project>.
	// Without rewriting we'd no-op enrichRepoStars on EVERY Apache Maven
	// artifact (commons-lang, log4j, kafka, …) and Maintenance stars
	// would stay zero — a high-value-data blind spot. Rewriting is
	// gated tightly: ONLY gitbox.apache.org URLs are touched, the
	// candidate is HTTP-probed (via fetchGitHubRepoMeta, which
	// fail-softs on 404), and one bounded fallback strips a trailing
	// version digit (commons-lang3 → commons-lang) before giving up.
	if mirror, ok := apacheGitboxToGitHub(p.endpoints.github, pr.URLs.SourceRepoURL); ok {
		// Try the canonical candidate first. fetchGitHubRepoMeta
		// returns (nil, nil) on 404 — that's our signal to try the
		// trailing-digit-stripped fallback. Any other failure (rate
		// limit, 5xx) is surfaced as a Warning by enrichRepoStars
		// below; we just promote pr.URLs.SourceRepoURL to the
		// candidate that lit up.
		meta, warn := p.fetchGitHubRepoMeta(ctx, mirror.owner, mirror.repo)
		if meta == nil && warn == nil {
			// Canonical 404'd. Try the trimmed name (commons-lang3 →
			// commons-lang).
			if trimmed, tOK := apacheGitboxTrimTrailingDigit(mirror.repo); tOK {
				if m2, w2 := p.fetchGitHubRepoMeta(ctx, mirror.owner, trimmed); m2 != nil || w2 != nil {
					mirror.repo = trimmed
					meta, warn = m2, w2
				}
			}
		}
		if meta != nil || warn != nil {
			// We have a usable (or known-broken) GitHub mirror. Rewrite
			// SourceRepoURL so downstream signals (suspicious_repo_stars
			// in Wave-4 RTT, audit-log links) point at the real repo,
			// then apply the stars data we already fetched.
			pr.URLs.SourceRepoURL = fmt.Sprintf("https://github.com/%s/%s", mirror.owner, mirror.repo)
			if pr.Provenance != nil {
				pr.Provenance.SourceRepo = pr.URLs.SourceRepoURL
			}
			applyRepoMeta(&pr, meta, warn)
			return pr, nil
		}
		// Both candidates 404'd. Leave SourceRepoURL pointing at gitbox
		// and fall through to enrichRepoStars (which will no-op on the
		// gitbox host) so the downstream Wave-4 signal logic is
		// unchanged.
	}
	// Pull stars/forks/openIssues/subscribers when the POM's <scm><url>
	// resolves to a recognised forge. Parity with the other 6 ecosystem
	// runners.
	enrichRepoStars(ctx, p, &pr)
	return pr, nil
}

// apacheGitboxMirror is the parsed form of a github.com/apache/<project>
// candidate URL inferred from a gitbox.apache.org SCM link.
type apacheGitboxMirror struct {
	owner string // always "apache"
	repo  string // <project> as extracted from gitbox
}

// apacheGitboxToGitHub inspects a Maven `<scm><url>` value and, when it
// points at gitbox.apache.org, returns the GitHub mirror candidate.
// Recognised URL shapes:
//
//	https://gitbox.apache.org/repos/asf?p=<project>.git
//	https://gitbox.apache.org/repos/asf/<project>.git
//	https://gitbox.apache.org/repos/asf?p=<project>;a=summary       (older shape)
//
// `gitHubBase` is the api.github.com base — passed through so test
// stubs can override the host without touching this helper.
//
// Deliberately scoped: this is NOT a general "guess the mirror from any
// URL" routine. Only the gitbox host is recognised; everything else
// returns ok=false so we don't accidentally start probing github.com
// for repos that have no GitHub presence.
func apacheGitboxToGitHub(gitHubBase, raw string) (apacheGitboxMirror, bool) {
	_ = gitHubBase // gitHubBase is reserved for future direct HEAD probes; the
	// current implementation hands off to fetchGitHubRepoMeta which
	// already knows the base URL via the provider's endpoints map.
	s := strings.TrimSpace(raw)
	if s == "" {
		return apacheGitboxMirror{}, false
	}
	u, err := url.Parse(s)
	if err != nil {
		return apacheGitboxMirror{}, false
	}
	if strings.ToLower(u.Host) != "gitbox.apache.org" {
		return apacheGitboxMirror{}, false
	}
	var project string
	// Path form: /repos/asf/<project>.git
	path := strings.TrimPrefix(u.Path, "/")
	if strings.HasPrefix(path, "repos/asf/") {
		rest := strings.TrimPrefix(path, "repos/asf/")
		// Strip any trailing path segments after the project (the URL
		// occasionally carries /tree/main etc.).
		if i := strings.Index(rest, "/"); i >= 0 {
			rest = rest[:i]
		}
		project = strings.TrimSuffix(rest, ".git")
	}
	// Query form: /repos/asf?p=<project>.git[;...]
	if project == "" {
		p := u.Query().Get("p")
		// gitweb accepts ';' as well as '&' for arg separation — the
		// stdlib parser already collapses both, but in case Query() saw
		// only the first, strip any tail.
		if i := strings.IndexAny(p, ";&"); i >= 0 {
			p = p[:i]
		}
		project = strings.TrimSuffix(p, ".git")
	}
	project = strings.TrimSpace(project)
	if project == "" {
		return apacheGitboxMirror{}, false
	}
	return apacheGitboxMirror{owner: "apache", repo: project}, true
}

// apacheGitboxTrimTrailingDigit handles the artifact-vs-project name
// mismatch we observe in the Apache Commons family: commons-lang3's
// gitbox project is "commons-lang3" but the actual GitHub mirror is
// github.com/apache/commons-lang. We only strip a SINGLE trailing
// decimal digit so we don't accidentally turn "spark-2-core" into
// "spark-core" — Apache's pattern is exclusively a major-version digit
// suffix.
//
// Returns (trimmed, true) when a trim was applied; (orig, false)
// otherwise.
func apacheGitboxTrimTrailingDigit(repo string) (string, bool) {
	if repo == "" {
		return repo, false
	}
	last := repo[len(repo)-1]
	if last < '0' || last > '9' {
		return repo, false
	}
	trimmed := repo[:len(repo)-1]
	// Guard against repos like "abc-3" where stripping leaves "abc-"
	// (trailing hyphen / empty). Refuse those rather than emit a
	// malformed candidate.
	if trimmed == "" || trimmed[len(trimmed)-1] == '-' {
		return repo, false
	}
	return trimmed, true
}

// mavenMetadataXML is the subset of maven-metadata.xml we consume.
// Lives at /{groupPath}/{artifactId}/maven-metadata.xml at every Maven
// repository; the document carries the canonical version list and a
// last-build timestamp.
type mavenMetadataXML struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Versioning struct {
		Latest      string `xml:"latest"`
		Release     string `xml:"release"`
		LastUpdated string `xml:"lastUpdated"`
		Versions    struct {
			Version []string `xml:"version"`
		} `xml:"versions"`
	} `xml:"versioning"`
}

// fetchMavenTimeline fetches the artifact-level maven-metadata.xml and
// returns one VersionRelease per `<version>` entry with a zero
// PublishedAt (Maven Central doesn't surface per-version publish times
// in a JSON-friendly form). The `latest` return value comes from
// `<versioning><latest>` when set, falling back to `<release>`.
func (p *registryMetadataProvider) fetchMavenTimeline(ctx context.Context, groupPath, artifact string) ([]VersionRelease, string, time.Time, *Warning) {
	doc := p.fetchMavenTimelineDoc(ctx, groupPath, artifact)
	return doc.timeline, doc.latest, doc.lastUpdated, doc.wrapped(p)
}

// fetchMavenTimelineDoc is the fetch+parse half, returning the RAW fetch
// warning. See timelineDoc.
// googleMavenGroupPrefixes are the groupId namespaces Google publishes to
// its own Maven repository instead of to Maven Central. They are the
// measured reason the Maven family could not be answered: 1,405 of the
// 1,699 registrymetadata `not_found` rows in the 2026-08-25 production
// export are `androidx.*` / `com.android.tools.*` coordinates that are
// real, ubiquitous, and simply absent from repo1.
//
// Matched on the dotted groupId, so `androidx` matches `androidx.work`
// but not `androidxfoo`.
var googleMavenGroupPrefixes = []string{
	"androidx",
	"com.android",
	"com.google.android",
	"com.google.firebase",
}

// groupUsesGoogleMaven reports whether a Maven groupPath (slash-separated,
// as it appears in the repository layout) belongs to a namespace Google
// hosts.
func groupUsesGoogleMaven(groupPath string) bool {
	group := strings.ReplaceAll(groupPath, "/", ".")
	for _, prefix := range googleMavenGroupPrefixes {
		if group == prefix || strings.HasPrefix(group, prefix+".") {
			return true
		}
	}
	return false
}

// fetchMavenTimelineDoc reads a coordinate's published version timeline.
//
// It asks repo1 first and, for the namespaces Google hosts, falls back to
// maven.google.com when repo1 does not have the artifact. That fallback is
// what makes the federated-absence verdict honest rather than noisy: with
// it, a Maven coordinate that still comes back not-found has been missed by
// BOTH of the repositories that actually serve this ecosystem, and calling
// that "not evaluated" is a statement about the coordinate. Without it, the
// same verdict would land on every androidx dependency in the fleet.
//
// The fallback fires only on a definite miss, never on an outage, so a
// repo1 5xx does not produce a second outbound request. Ecosystems and
// namespaces outside the Google set are untouched.
func (p *registryMetadataProvider) fetchMavenTimelineDoc(ctx context.Context, groupPath, artifact string) timelineDoc {
	doc := p.fetchMavenTimelineDocFrom(ctx, p.endpoints.maven, groupPath, artifact)
	if isDefiniteAbsence(doc.probeWarning()) && groupUsesGoogleMaven(groupPath) && p.endpoints.mavenGoogle != "" {
		if alt := p.fetchMavenTimelineDocFrom(ctx, p.endpoints.mavenGoogle, groupPath, artifact); alt.probeWarning() == nil {
			return alt
		}
	}
	return doc
}

func (p *registryMetadataProvider) fetchMavenTimelineDocFrom(ctx context.Context, base, groupPath, artifact string) timelineDoc {
	endpoint := fmt.Sprintf("%s/%s/%s/maven-metadata.xml", base, groupPath, artifact)
	var meta mavenMetadataXML
	warn, err := p.fetchXML(ctx, endpoint, &meta)
	if err != nil || warn != nil {
		return timelineDoc{endpoint: endpoint, warn: warn, err: err}
	}
	timeline := make([]VersionRelease, 0, len(meta.Versioning.Versions.Version))
	for _, v := range meta.Versioning.Versions.Version {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		timeline = append(timeline, VersionRelease{Version: v})
	}
	latest := firstNonEmpty(strings.TrimSpace(meta.Versioning.Latest), strings.TrimSpace(meta.Versioning.Release))
	lastUpdated, _ := parseMavenLastUpdated(meta.Versioning.LastUpdated)
	return timelineDoc{timeline: timeline, latest: latest, lastUpdated: lastUpdated, endpoint: endpoint}
}

// parseMavenLastUpdated parses the `lastUpdated` field from
// maven-metadata.xml, which Maven Central emits as compact
// "YYYYMMDDhhmmss" or occasionally "YYYYMMDD" — neither of which
// parseTime() handles. Falls back to (zero, false) on any malformed
// input.
func parseMavenLastUpdated(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{"20060102150405", "20060102"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// splitMavenCoordinate splits "groupId:artifactId" or
// "groupId:artifactId:classifier"; a 4-segment "groupId:artifactId:
// version:classifier" form is also accepted.
func splitMavenCoordinate(coord string) (group, artifact, classifier string) {
	parts := strings.Split(coord, ":")
	switch len(parts) {
	case 0, 1:
		return "", "", ""
	case 2:
		return parts[0], parts[1], ""
	case 3:
		return parts[0], parts[1], parts[2]
	default:
		return parts[0], parts[1], parts[3]
	}
}

// -- Cargo / crates.io ------------------------------------------------

func (p *registryMetadataProvider) runCargo(ctx context.Context, pkg, ver string) (PartialReport, error) {
	endpoint := fmt.Sprintf("%s/api/v1/crates/%s/%s", p.endpoints.cargo, url.PathEscape(pkg), url.PathEscape(ver))
	var pack struct {
		Crate struct {
			Homepage    string   `json:"homepage"`
			Repository  string   `json:"repository"`
			Description string   `json:"description"`
			Keywords    []string `json:"keywords"`
			License     string   `json:"license"`
		} `json:"crate"`
		Version struct {
			License     string `json:"license"`
			CreatedAt   string `json:"created_at"`
			UpdatedAt   string `json:"updated_at"`
			DLPath      string `json:"dl_path"`
			CrateSize   *int64 `json:"crate_size"`
			Checksum    string `json:"checksum"`
			Yanked      bool   `json:"yanked"`
			PublishedBy *struct {
				Login string `json:"login"`
				Name  string `json:"name"`
			} `json:"published_by"`
		} `json:"version"`
		Dependencies []struct {
			CrateID  string `json:"crate_id"`
			Req      string `json:"req"`
			Optional bool   `json:"optional"`
			Kind     string `json:"kind"` // "normal" | "dev" | "build"
		} `json:"dependencies"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &pack)
	if err != nil {
		return PartialReport{}, err
	}
	pr := PartialReport{}
	if warn != nil {
		// crates.io returns the same 404 for an unknown crate and for an
		// unknown version of a known crate; the crate summary separates
		// them.
		warn = p.promoteVersionNotFound(ctx, "cargo", warn, endpoint, pkg, ver, p.probeCargoPackage(pkg))
		pr.Warnings = append(pr.Warnings, *warn)
		return pr, nil
	}

	release := &ReleaseSection{}
	if t, ok := parseTime(pack.Version.CreatedAt); ok {
		release.PublishedAt = &t
		release.CreatedAt = &t
	}
	if t, ok := parseTime(pack.Version.UpdatedAt); ok {
		release.ModifiedAt = &t
	}
	yanked := pack.Version.Yanked
	release.Yanked = &yanked

	urls := &URLSection{MetadataURL: endpoint}
	if pack.Crate.Homepage != "" {
		urls.HomepageURL = pack.Crate.Homepage
	}
	if pack.Crate.Repository != "" {
		urls.SourceRepoURL = pack.Crate.Repository
	}
	if pack.Version.DLPath != "" {
		urls.ArtifactURL = "https://crates.io" + pack.Version.DLPath
	}

	artifact := &ArtifactSection{Packaging: "crate"}
	if pack.Version.CrateSize != nil {
		artifact.Size = *pack.Version.CrateSize
	}
	if pack.Version.Checksum != "" {
		artifact.Digests.SHA256 = pack.Version.Checksum
	}
	artifact.Filename = fmt.Sprintf("%s-%s.crate", pkg, ver)

	metadata := &MetadataSection{
		LicenseExpression: firstNonEmpty(pack.Version.License, pack.Crate.License),
		Summary:           firstLine(pack.Crate.Description),
		Description:       pack.Crate.Description,
		Keywords:          pack.Crate.Keywords,
	}

	people := &PeopleSection{}
	if pack.Version.PublishedBy != nil {
		if s := firstNonEmpty(pack.Version.PublishedBy.Name, pack.Version.PublishedBy.Login); s != "" {
			people.PublisherIDs = []string{s}
		}
	}
	// Maintainers come from /api/v1/crates/{crate}/owners — crates.io's
	// canonical owner list. Soft-fail: if the call errors (404 on a
	// yanked-only crate, transient outage) we leave Maintainers nil so
	// the UI can show "no data" rather than a wrong empty list.
	if owners := p.fetchCargoOwners(ctx, pkg); len(owners) > 0 {
		for _, o := range owners {
			if s := firstNonEmpty(o.Name, o.Login); s != "" {
				people.Maintainers = append(people.Maintainers, s)
			}
		}
	}
	// Authors live in the (separate) /authors endpoint — historical
	// Cargo.toml `authors = [...]` survives there for back-compat.
	if authors := p.fetchCargoAuthors(ctx, pkg, ver); len(authors) > 0 {
		for _, a := range authors {
			if s := strings.TrimSpace(a); s != "" {
				people.Authors = append(people.Authors, s)
			}
		}
	}

	pr.Release = release
	pr.URLs = urls
	pr.Artifact = artifact
	pr.Metadata = metadata
	if len(people.PublisherIDs)+len(people.Maintainers)+len(people.Authors) > 0 {
		pr.People = people
	}
	d := depCollector{}
	for _, dep := range pack.Dependencies {
		if dep.CrateID == "" {
			continue
		}
		ref := DependencyRef{Name: dep.CrateID, Constraint: strings.TrimSpace(dep.Req)}
		switch {
		case dep.Optional:
			d.optional = append(d.optional, ref)
		case dep.Kind == "dev":
			d.dev = append(d.dev, ref)
		case dep.Kind == "build":
			d.peer = append(d.peer, ref)
		default:
			d.direct = append(d.direct, ref)
		}
	}
	if !d.empty() {
		pr.Dependencies = d.section()
	}
	if urls.SourceRepoURL != "" {
		pr.Provenance = &ProvenanceSection{SourceRepo: urls.SourceRepoURL}
	}

	// Pull the crate-level summary for the full version timeline.
	// Fail-soft: surfaced as a Warning.
	timeline, latest, tlWarn := p.fetchCargoTimeline(ctx, pkg)
	applyTimeline(&pr, timeline, latest, tlWarn)
	enrichRepoStars(ctx, p, &pr)
	return pr, nil
}

// fetchCargoTimeline returns the full version history for a crate from
// crates.io's `/api/v1/crates/{crate}` summary endpoint plus the
// declared `max_version` label.
func (p *registryMetadataProvider) fetchCargoTimeline(ctx context.Context, pkg string) ([]VersionRelease, string, *Warning) {
	doc := p.fetchCargoTimelineDoc(ctx, pkg)
	return doc.timeline, doc.latest, doc.wrapped(p)
}

// fetchCargoTimelineDoc is the fetch+parse half, returning the RAW fetch
// warning. See timelineDoc.
func (p *registryMetadataProvider) fetchCargoTimelineDoc(ctx context.Context, pkg string) timelineDoc {
	endpoint := fmt.Sprintf("%s/api/v1/crates/%s", p.endpoints.cargo, url.PathEscape(pkg))
	var pack struct {
		Crate struct {
			MaxVersion       string `json:"max_version"`
			MaxStableVersion string `json:"max_stable_version"`
			NewestVersion    string `json:"newest_version"`
		} `json:"crate"`
		Versions []struct {
			Num       string `json:"num"`
			CreatedAt string `json:"created_at"`
		} `json:"versions"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &pack)
	if err != nil || warn != nil {
		return timelineDoc{endpoint: endpoint, warn: warn, err: err}
	}
	timeline := make([]VersionRelease, 0, len(pack.Versions))
	for _, v := range pack.Versions {
		if v.Num == "" {
			continue
		}
		rel := VersionRelease{Version: v.Num}
		if t, ok := parseTime(v.CreatedAt); ok {
			rel.PublishedAt = t
		}
		timeline = append(timeline, rel)
	}
	latest := firstNonEmpty(pack.Crate.MaxStableVersion, pack.Crate.MaxVersion, pack.Crate.NewestVersion)
	return timelineDoc{timeline: timeline, latest: latest, endpoint: endpoint}
}

// cargoOwner is the subset of crates.io's owner record we surface.
type cargoOwner struct {
	Login string `json:"login"`
	Name  string `json:"name"`
	Kind  string `json:"kind"` // "user" or "team"
}

// fetchCargoOwners retrieves the (deduplicated) owner list for a crate.
// Returns nil on any error so the caller can render "no data" rather
// than a misleading empty list.
func (p *registryMetadataProvider) fetchCargoOwners(ctx context.Context, pkg string) []cargoOwner {
	endpoint := fmt.Sprintf("%s/api/v1/crates/%s/owners", p.endpoints.cargo, url.PathEscape(pkg))
	var resp struct {
		Users []cargoOwner `json:"users"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &resp)
	if err != nil || warn != nil {
		return nil
	}
	return resp.Users
}

// fetchCargoAuthors retrieves the version's authors list from
// crates.io. The endpoint is independent from /owners and reflects the
// `Cargo.toml` `authors = [...]` array that the version was published
// with. Returns nil on transient errors.
func (p *registryMetadataProvider) fetchCargoAuthors(ctx context.Context, pkg, ver string) []string {
	endpoint := fmt.Sprintf("%s/api/v1/crates/%s/%s/authors", p.endpoints.cargo, url.PathEscape(pkg), url.PathEscape(ver))
	var resp struct {
		Users []struct {
			Name  string `json:"name"`
			Login string `json:"login"`
		} `json:"users"`
		Meta struct {
			Names []string `json:"names"`
		} `json:"meta"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &resp)
	if err != nil || warn != nil {
		return nil
	}
	if len(resp.Meta.Names) > 0 {
		return resp.Meta.Names
	}
	out := make([]string, 0, len(resp.Users))
	for _, u := range resp.Users {
		if s := firstNonEmpty(u.Name, u.Login); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// -- RubyGems ---------------------------------------------------------

func (p *registryMetadataProvider) runRubyGems(ctx context.Context, pkg, ver string) (PartialReport, error) {
	endpoint := fmt.Sprintf("%s/api/v2/rubygems/%s/versions/%s.json", p.endpoints.rubygems, url.PathEscape(pkg), url.PathEscape(ver))
	var pack struct {
		Name             string   `json:"name"`
		Version          string   `json:"version"`
		Authors          string   `json:"authors"`
		Info             string   `json:"info"`
		Licenses         []string `json:"licenses"`
		HomepageURI      string   `json:"homepage_uri"`
		SourceCodeURI    string   `json:"source_code_uri"`
		BugTrackerURI    string   `json:"bug_tracker_uri"`
		DocumentationURI string   `json:"documentation_uri"`
		GemURI           string   `json:"gem_uri"`
		SHA              string   `json:"sha"`
		CreatedAt        string   `json:"created_at"`
		Prerelease       bool     `json:"prerelease"`
		Yanked           bool     `json:"yanked"`
		Summary          string   `json:"summary"`
		Dependencies     struct {
			Runtime []struct {
				Name         string `json:"name"`
				Requirements string `json:"requirements"`
			} `json:"runtime"`
			Development []struct {
				Name         string `json:"name"`
				Requirements string `json:"requirements"`
			} `json:"development"`
		} `json:"dependencies"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &pack)
	if err != nil {
		return PartialReport{}, err
	}
	pr := PartialReport{}
	if warn != nil {
		// /api/v2/rubygems/{gem}/versions/{ver}.json cannot distinguish a
		// missing gem from a missing version; /api/v1/versions/{gem}.json
		// can.
		warn = p.promoteVersionNotFound(ctx, "rubygems", warn, endpoint, pkg, ver, p.probeRubyGemsPackage(pkg))
		pr.Warnings = append(pr.Warnings, *warn)
		return pr, nil
	}

	release := &ReleaseSection{}
	if t, ok := parseTime(pack.CreatedAt); ok {
		release.PublishedAt = &t
	}
	pre := pack.Prerelease
	release.Prerelease = &pre
	yan := pack.Yanked
	release.Yanked = &yan

	urls := &URLSection{
		MetadataURL:      endpoint,
		HomepageURL:      pack.HomepageURI,
		SourceRepoURL:    pack.SourceCodeURI,
		IssuesURL:        pack.BugTrackerURI,
		DocumentationURL: pack.DocumentationURI,
		ArtifactURL:      pack.GemURI,
	}
	artifact := &ArtifactSection{
		Filename:  fmt.Sprintf("%s-%s.gem", pkg, ver),
		Packaging: "gem",
	}
	if pack.SHA != "" {
		artifact.Digests.SHA256 = pack.SHA
	}

	people := &PeopleSection{}
	if pack.Authors != "" {
		for _, a := range strings.Split(pack.Authors, ",") {
			s := strings.TrimSpace(a)
			if s != "" {
				people.Authors = append(people.Authors, s)
			}
		}
	}
	// RubyGems exposes the canonical maintainer list at
	// /api/v1/gems/{name}/owners.json. The handles are
	// rubygems.org accounts — they double as the publisher ids since
	// RubyGems gates `gem push` on owner membership.
	if owners := p.fetchRubyGemsOwners(ctx, pkg); len(owners) > 0 {
		for _, o := range owners {
			if s := firstNonEmpty(o.Handle, o.Email, o.ID.String()); s != "" {
				people.Maintainers = append(people.Maintainers, s)
				people.PublisherIDs = append(people.PublisherIDs, s)
			}
		}
	}

	metadata := &MetadataSection{
		LicenseExpression: strings.Join(pack.Licenses, " OR "),
		Summary:           firstNonEmpty(pack.Summary, firstLine(pack.Info)),
		Description:       pack.Info,
	}

	pr.Release = release
	pr.URLs = urls
	pr.Artifact = artifact
	pr.Metadata = metadata
	if len(people.Authors)+len(people.Maintainers)+len(people.PublisherIDs) > 0 {
		pr.People = people
	}
	d := depCollector{}
	for _, dep := range pack.Dependencies.Runtime {
		if dep.Name == "" {
			continue
		}
		d.direct = append(d.direct, DependencyRef{Name: dep.Name, Constraint: dep.Requirements})
	}
	for _, dep := range pack.Dependencies.Development {
		if dep.Name == "" {
			continue
		}
		d.dev = append(d.dev, DependencyRef{Name: dep.Name, Constraint: dep.Requirements})
	}
	if !d.empty() {
		pr.Dependencies = d.section()
	}
	if urls.SourceRepoURL != "" {
		pr.Provenance = &ProvenanceSection{SourceRepo: urls.SourceRepoURL}
	}

	// Pull the gem's full version timeline (separate endpoint from the
	// per-version JSON). Fail-soft: any error surfaces as a Warning.
	timeline, latest, tlWarn := p.fetchRubyGemsTimeline(ctx, pkg)
	applyTimeline(&pr, timeline, latest, tlWarn)
	enrichRepoStars(ctx, p, &pr)
	return pr, nil
}

// fetchRubyGemsTimeline returns the full version timeline for a gem
// from /api/v1/versions/{gem}.json. The endpoint returns an unordered
// array of `{number, created_at}` records.
func (p *registryMetadataProvider) fetchRubyGemsTimeline(ctx context.Context, pkg string) ([]VersionRelease, string, *Warning) {
	doc := p.fetchRubyGemsTimelineDoc(ctx, pkg)
	return doc.timeline, doc.latest, doc.wrapped(p)
}

// fetchRubyGemsTimelineDoc is the fetch+parse half, returning the RAW
// fetch warning. See timelineDoc.
func (p *registryMetadataProvider) fetchRubyGemsTimelineDoc(ctx context.Context, pkg string) timelineDoc {
	endpoint := fmt.Sprintf("%s/api/v1/versions/%s.json", p.endpoints.rubygems, url.PathEscape(pkg))
	var versions []struct {
		Number     string `json:"number"`
		CreatedAt  string `json:"created_at"`
		Prerelease bool   `json:"prerelease"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &versions)
	if err != nil || warn != nil {
		return timelineDoc{endpoint: endpoint, warn: warn, err: err}
	}
	timeline := make([]VersionRelease, 0, len(versions))
	var latest string
	var latestT time.Time
	for _, v := range versions {
		if v.Number == "" {
			continue
		}
		rel := VersionRelease{Version: v.Number}
		if t, ok := parseTime(v.CreatedAt); ok {
			rel.PublishedAt = t
			// The newest non-prerelease is the canonical "latest" label.
			if !v.Prerelease && (latest == "" || t.After(latestT)) {
				latest = v.Number
				latestT = t
			}
		}
		timeline = append(timeline, rel)
	}
	return timelineDoc{timeline: timeline, latest: latest, endpoint: endpoint}
}

// rubyGemsOwner is the subset of the RubyGems owners.json record we
// surface. Handle is the rubygems.org username; ID (when present) is a
// stable numeric id we fall back to when the handle is hidden.
// `id` arrives as a JSON number, so we decode into json.Number to
// avoid type-mismatch errors against the UseNumber() decoder.
type rubyGemsOwner struct {
	ID     json.Number `json:"id"`
	Handle string      `json:"handle"`
	Email  string      `json:"email"`
}

// fetchRubyGemsOwners returns the gem's authoritative owner list.
// Returns nil on any error (auth-required gems, transient outages, etc.)
// so the caller can leave the field nil instead of fabricating an
// empty array.
func (p *registryMetadataProvider) fetchRubyGemsOwners(ctx context.Context, pkg string) []rubyGemsOwner {
	endpoint := fmt.Sprintf("%s/api/v1/gems/%s/owners.json", p.endpoints.rubygems, url.PathEscape(pkg))
	var owners []rubyGemsOwner
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &owners)
	if err != nil || warn != nil {
		return nil
	}
	// rubygems sometimes returns "id" as a number; UseNumber()
	// preserves it as json.Number which decodes into a string field
	// without complaint, but if a future server tweak emits null we
	// don't want to surface "0" to users — drop fully-empty rows.
	out := owners[:0]
	for _, o := range owners {
		if strings.TrimSpace(o.Handle)+strings.TrimSpace(o.Email)+strings.TrimSpace(o.ID.String()) == "" {
			continue
		}
		out = append(out, o)
	}
	return out
}

// -- NuGet ------------------------------------------------------------

type nugetNuspec struct {
	XMLName  xml.Name `xml:"package"`
	Metadata struct {
		ID      string `xml:"id"`
		Version string `xml:"version"`
		Authors string `xml:"authors"`
		Owners  string `xml:"owners"`
		License struct {
			Type  string `xml:"type,attr"`
			Value string `xml:",chardata"`
		} `xml:"license"`
		LicenseURL  string `xml:"licenseUrl"`
		ProjectURL  string `xml:"projectUrl"`
		Description string `xml:"description"`
		Summary     string `xml:"summary"`
		Tags        string `xml:"tags"`
		Repository  struct {
			URL  string `xml:"url,attr"`
			Type string `xml:"type,attr"`
		} `xml:"repository"`
		Dependencies struct {
			Group []struct {
				TargetFramework string `xml:"targetFramework,attr"`
				Dependency      []struct {
					ID      string `xml:"id,attr"`
					Version string `xml:"version,attr"`
					Exclude string `xml:"exclude,attr"`
				} `xml:"dependency"`
			} `xml:"group"`
			Dependency []struct {
				ID      string `xml:"id,attr"`
				Version string `xml:"version,attr"`
			} `xml:"dependency"`
		} `xml:"dependencies"`
	} `xml:"metadata"`
}

func (p *registryMetadataProvider) runNuGet(ctx context.Context, pkg, ver string) (PartialReport, error) {
	lower := strings.ToLower(pkg)
	lowerVer := strings.ToLower(ver)
	endpoint := fmt.Sprintf("%s/%s/%s/%s.nuspec", p.endpoints.nuget, url.PathEscape(lower), url.PathEscape(lowerVer), url.PathEscape(lower))

	var nuspec nugetNuspec
	warn, err := p.fetchXML(ctx, endpoint, &nuspec)
	if err != nil {
		return PartialReport{}, err
	}
	pr := PartialReport{}
	if warn != nil {
		// The flat container 404s a missing nuspec whether the package id
		// is unknown or only the version is; its {id}/index.json says
		// which.
		warn = p.promoteVersionNotFound(ctx, "nuget", warn, endpoint, pkg, ver, p.probeNuGetPackage(pkg))
		pr.Warnings = append(pr.Warnings, *warn)
		return pr, nil
	}

	license := strings.TrimSpace(nuspec.Metadata.License.Value)
	if license == "" {
		license = strings.TrimSpace(nuspec.Metadata.LicenseURL)
	}

	people := &PeopleSection{}
	if nuspec.Metadata.Authors != "" {
		for _, a := range strings.Split(nuspec.Metadata.Authors, ",") {
			s := strings.TrimSpace(a)
			if s != "" {
				people.Authors = append(people.Authors, s)
			}
		}
	}
	if nuspec.Metadata.Owners != "" {
		for _, o := range strings.Split(nuspec.Metadata.Owners, ",") {
			s := strings.TrimSpace(o)
			if s != "" {
				people.Maintainers = append(people.Maintainers, s)
				// NuGet's gallery treats `owners` as the canonical
				// publisher account list; surface them on PublisherIDs
				// so audit views match the gallery's "Owners" column.
				people.PublisherIDs = append(people.PublisherIDs, s)
			}
		}
	}

	urls := &URLSection{
		MetadataURL:   endpoint,
		HomepageURL:   nuspec.Metadata.ProjectURL,
		SourceRepoURL: nuspec.Metadata.Repository.URL,
		ArtifactURL:   fmt.Sprintf("%s/%s/%s/%s.%s.nupkg", p.endpoints.nuget, lower, lowerVer, lower, lowerVer),
	}
	artifact := &ArtifactSection{
		Filename:  fmt.Sprintf("%s.%s.nupkg", lower, lowerVer),
		Packaging: "nupkg",
	}
	metadata := &MetadataSection{
		LicenseExpression: license,
		Summary:           firstNonEmpty(nuspec.Metadata.Summary, firstLine(nuspec.Metadata.Description)),
		Description:       nuspec.Metadata.Description,
	}
	if nuspec.Metadata.Tags != "" {
		metadata.Keywords = strings.Fields(nuspec.Metadata.Tags)
	}

	pr.URLs = urls
	pr.Artifact = artifact
	pr.Metadata = metadata
	if len(people.Authors)+len(people.Maintainers)+len(people.PublisherIDs) > 0 {
		pr.People = people
	}
	d := depCollector{}
	// NuGet emits dependencies either flat (legacy nuspec) or grouped
	// per-targetFramework. We dedup by id so the UI doesn't list the
	// same dependency once per framework slice.
	seen := map[string]bool{}
	addDep := func(id, version string) {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		d.direct = append(d.direct, DependencyRef{Name: id, Constraint: strings.TrimSpace(version)})
	}
	for _, dep := range nuspec.Metadata.Dependencies.Dependency {
		addDep(dep.ID, dep.Version)
	}
	for _, group := range nuspec.Metadata.Dependencies.Group {
		for _, dep := range group.Dependency {
			addDep(dep.ID, dep.Version)
		}
	}
	if !d.empty() {
		pr.Dependencies = d.section()
	}
	if urls.SourceRepoURL != "" {
		pr.Provenance = &ProvenanceSection{SourceRepo: urls.SourceRepoURL}
	}

	// Pull the full registration catalog so we get the entire version
	// history. NuGet's registration5-semver1 nests entries under
	// items[].items[].catalogEntry — most popular packages fit in a
	// single page; large packages (>64 entries) paginate with a
	// downstream `@id` we DO NOT follow here (deliberate: keeps the
	// timeline call to one request and avoids the rabbit hole of catalog
	// chasing). Fail-soft: a transient error surfaces as a Warning.
	timeline, latest, listed, tlWarn := p.fetchNuGetTimeline(ctx, pkg)
	applyTimeline(&pr, timeline, latest, tlWarn)
	// NuGet has no per-version "yanked" boolean; the registry instead
	// flips `catalogEntry.listed=false` when an owner unlists a version
	// (the closest analogue to a yank on this registry). Promote that
	// to Release.Yanked so downstream consumers (risk projection,
	// metadiff filtering) treat unlisted versions the same as yanked
	// publishes on npm / PyPI / rubygems. The map is keyed by the
	// lower-cased catalogEntry.version because NuGet treats the version
	// string case-insensitively.
	if isUnlisted, ok := listed[strings.ToLower(ver)]; ok && isUnlisted {
		if pr.Release == nil {
			pr.Release = &ReleaseSection{}
		}
		yanked := true
		pr.Release.Yanked = &yanked
	}
	enrichRepoStars(ctx, p, &pr)
	return pr, nil
}

// fetchNuGetTimeline returns the full version timeline from the NuGet
// registration5-semver1 catalog. catalogEntry.{version, published} is
// the canonical shape.
//
// The third return value is a map from (lower-cased) version to a bool
// that is true ONLY when catalogEntry.listed is explicitly false. A
// missing `listed` field is treated as listed=true (the registry's own
// default), which is why the map only contains entries for the
// unlisted-positive case — the caller never sees a false-positive from
// a payload that simply omitted the field.
func (p *registryMetadataProvider) fetchNuGetTimeline(ctx context.Context, pkg string) ([]VersionRelease, string, map[string]bool, *Warning) {
	lower := strings.ToLower(pkg)
	endpoint := fmt.Sprintf("%s/%s/index.json", p.endpoints.nugetRegistration, url.PathEscape(lower))
	var idx struct {
		Items []struct {
			Items []struct {
				CatalogEntry struct {
					Version   string `json:"version"`
					Published string `json:"published"`
					Listed    *bool  `json:"listed,omitempty"`
				} `json:"catalogEntry"`
			} `json:"items"`
		} `json:"items"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &idx)
	if err != nil || warn != nil {
		return nil, "", nil, timelineFetchFailedWarning(p, endpoint, err, warn)
	}
	timeline := []VersionRelease{}
	unlisted := map[string]bool{}
	var latest string
	var latestT time.Time
	for _, page := range idx.Items {
		for _, leaf := range page.Items {
			ce := leaf.CatalogEntry
			if ce.Version == "" {
				continue
			}
			rel := VersionRelease{Version: ce.Version}
			if t, ok := parseTime(ce.Published); ok {
				// NuGet uses year 1900-01-01 to flag unlisted (deleted)
				// packages — skip those for the "latest" label but keep
				// them in the timeline for completeness.
				rel.PublishedAt = t
				if t.Year() > 1901 && (latest == "" || t.After(latestT)) {
					latest = ce.Version
					latestT = t
				}
			}
			// Explicit `listed:false` is the unlist signal. A nil
			// pointer (field omitted) means "registry default = listed";
			// don't synthesize a yank for it.
			if ce.Listed != nil && !*ce.Listed {
				unlisted[strings.ToLower(ce.Version)] = true
			}
			timeline = append(timeline, rel)
		}
	}
	return timeline, latest, unlisted, nil
}

// -- Composer / Packagist ---------------------------------------------

// composerVersionEntry is one element of a Packagist p2 `packages[name]`
// array. It was an anonymous struct written out twice; it is a named type
// now because expandComposerMinified has to build these from raw JSON.
type composerVersionEntry struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Time        string   `json:"time"`
	License     any      `json:"license"`
	Description string   `json:"description"`
	Homepage    string   `json:"homepage"`
	Keywords    []string `json:"keywords"`
	Source      struct {
		URL  string `json:"url"`
		Type string `json:"type"`
	} `json:"source"`
	Dist struct {
		URL       string `json:"url"`
		Type      string `json:"type"`
		Shasum    string `json:"shasum"`
		Reference string `json:"reference"`
	} `json:"dist"`
	Authors []struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		Role  string `json:"role"`
	} `json:"authors"`
	Support    map[string]string `json:"support"`
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
	Suggest    map[string]string `json:"suggest"`
}

// composerUnsetSentinel is how the `composer/2.0` minified metadata format
// encodes "this field, which the previous entry had, is GONE in this one".
// It is a bare JSON string in a position the schema types as an object or
// an array.
const composerUnsetSentinel = `"__unset"`

// composerMinifiedFormat is the value of the document's `minified` key when
// the entry array is a delta chain rather than a list of complete records.
const composerMinifiedFormat = "composer/2.0"

// expandComposerMinified implements the expand half of Packagist's
// `composer/metadata-minifier`, and it is the fix for TWO defects that
// between them accounted for the single largest false-positive cell in the
// server-side risk corpus: 35 of the 60 most-installed Composer packages
// (58.3%) firing BOTH lic.missing and license.unidentified.
//
// The format, which this reader did not implement:
//
//	entry[0]  complete record
//	entry[i]  ONLY the fields that differ from entry[i-1]; a field that
//	          was REMOVED is present with the literal value "__unset"
//
// Defect one — the decode. `require`, `require-dev`, `suggest` and
// `support` are typed map[string]string, so a single `"suggest":"__unset"`
// anywhere in a package's version history is a string where an object is
// expected. encoding/json aborts the document, runComposer takes its
// warning branch, and the ENTIRE report comes back empty: no licence, no
// release date, no maintainers, no dependencies, no source repo. The
// scorer then reads a fact-free report as a clean one. psr/log carries
// `"require":"__unset"` on 1.0.0 and guzzlehttp/guzzle carries
// `"suggest":"__unset"`; both graded allow with a licence FP attached.
//
// Defect two — the deltas. Even where nothing is unset and the decode
// succeeds, 99.4% of version entries carry no `license` key at all,
// because it is unchanged from the entry before. Any coordinate that is
// not the newest release therefore lost its licence, its description, its
// homepage, its authors and its keywords. That is why the corpus's
// composer licences correlate exactly with "is this the latest version".
//
// Both are fixed by expanding before decoding: carry every field forward,
// then delete the ones this entry explicitly unsets.
//
// The `__unset` strip runs unconditionally because it is a decode-killer
// regardless of provenance. The carry-forward runs ONLY when the document
// declares itself minified — on a hypothetical non-minified document an
// absent field means absent, and inheriting one would invent a fact.
func expandComposerMinified(raw []map[string]json.RawMessage, minified bool) []map[string]json.RawMessage {
	out := make([]map[string]json.RawMessage, 0, len(raw))
	var prev map[string]json.RawMessage
	for _, entry := range raw {
		expanded := make(map[string]json.RawMessage, len(entry)+len(prev))
		if minified {
			for k, v := range prev {
				expanded[k] = v
			}
		}
		for k, v := range entry {
			if string(v) == composerUnsetSentinel {
				delete(expanded, k)
				continue
			}
			expanded[k] = v
		}
		out = append(out, expanded)
		prev = expanded
	}
	return out
}

// decodeComposerEntries re-marshals each expanded entry into the typed
// struct. An entry that still fails to decode is SKIPPED rather than
// failing the whole document — the old all-or-nothing behaviour is exactly
// what turned one malformed field into a fact-free report.
func decodeComposerEntries(raw []map[string]json.RawMessage) []composerVersionEntry {
	out := make([]composerVersionEntry, 0, len(raw))
	for _, m := range raw {
		b, err := json.Marshal(m)
		if err != nil {
			continue
		}
		var e composerVersionEntry
		if err := json.Unmarshal(b, &e); err != nil {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (p *registryMetadataProvider) runComposer(ctx context.Context, pkg, ver string) (PartialReport, error) {
	lower := strings.ToLower(pkg)
	endpoint := fmt.Sprintf("%s/p2/%s.json", p.endpoints.composer, lower)
	// Decoded as raw JSON per entry, not straight into the typed struct,
	// because the document is a delta chain that has to be expanded first.
	// See expandComposerMinified.
	var pack struct {
		Minified string                                  `json:"minified"`
		Packages map[string][]map[string]json.RawMessage `json:"packages"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &pack)
	if err != nil {
		return PartialReport{}, err
	}
	pr := PartialReport{}
	if warn != nil {
		pr.Warnings = append(pr.Warnings, *promotePackagumentNotFound(p, "composer", warn, endpoint, pkg, ver))
		return pr, nil
	}

	rawEntries := pack.Packages[lower]
	if rawEntries == nil {
		rawEntries = pack.Packages[pkg]
	}
	entries := decodeComposerEntries(
		expandComposerMinified(rawEntries, pack.Minified == composerMinifiedFormat))
	if len(entries) == 0 {
		return PartialReport{}, nil
	}
	var match *composerVersionEntry
	for i := range entries {
		if versionMatches(entries[i].Version, ver) {
			match = &entries[i]
			break
		}
	}
	if match == nil {
		// Packagist answered with the package and listed its releases,
		// and the pinned version was not one of them. Until now this
		// returned an EMPTY report with no warning at all — the most
		// silent shape of the defect: no facts, no complaint, and the
		// scorer treats a fact-free report as a clean one.
		//
		// `entries` is non-empty here (the len==0 early return above
		// already covered the partial-document case), so this is
		// positive evidence of absence, not absence of evidence.
		published := make([]string, 0, len(entries))
		for i := range entries {
			published = append(published, entries[i].Version)
		}
		if versionListed(published, ver) {
			// versionMatches is what the match loop above already used,
			// so this cannot normally fire — it is a belt-and-braces
			// guard against the two comparators drifting apart.
			return pr, nil
		}
		pr.Warnings = append(pr.Warnings,
			*versionNotFoundWarning(p, endpoint, pkg, ver, len(published)))
		return pr, nil
	}

	license := ""
	switch v := match.License.(type) {
	case string:
		license = v
	case []any:
		var parts []string
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				parts = append(parts, s)
			}
		}
		license = strings.Join(parts, " OR ")
	}

	release := &ReleaseSection{}
	if t, ok := parseTime(match.Time); ok {
		release.PublishedAt = &t
	}

	urls := &URLSection{
		MetadataURL:   endpoint,
		HomepageURL:   match.Homepage,
		SourceRepoURL: match.Source.URL,
		ArtifactURL:   match.Dist.URL,
	}
	if u := match.Support["issues"]; u != "" {
		urls.IssuesURL = u
	}
	if u := match.Support["docs"]; u != "" {
		urls.DocumentationURL = u
	}

	artifact := &ArtifactSection{
		Packaging: match.Dist.Type,
	}
	if match.Dist.Shasum != "" {
		artifact.Digests.SHA1 = match.Dist.Shasum
	}
	artifact.Filename = filenameFromURL(match.Dist.URL)

	metadata := &MetadataSection{
		LicenseExpression: license,
		Summary:           firstLine(match.Description),
		Description:       match.Description,
		Keywords:          match.Keywords,
	}

	people := &PeopleSection{}
	for _, a := range match.Authors {
		if s := joinAuthor(a.Name, a.Email); s != "" {
			if strings.EqualFold(a.Role, "maintainer") {
				people.Maintainers = append(people.Maintainers, s)
			} else {
				people.Authors = append(people.Authors, s)
			}
		}
	}
	// Packagist exposes the canonical maintainer list at
	// /packages/{name}.json (different endpoint from the p2 metadata
	// pulled above). Surface those handles as both Maintainers and
	// PublisherIDs so the UI's People panel matches packagist.org's
	// "Maintainers" sidebar.
	if maint := p.fetchPackagistMaintainers(ctx, lower); len(maint) > 0 {
		for _, m := range maint {
			s := strings.TrimSpace(m.Name)
			if s == "" {
				continue
			}
			people.Maintainers = append(people.Maintainers, s)
			people.PublisherIDs = append(people.PublisherIDs, s)
		}
	}

	pr.Release = release
	pr.URLs = urls
	pr.Artifact = artifact
	pr.Metadata = metadata
	if len(people.Authors)+len(people.Maintainers)+len(people.PublisherIDs) > 0 {
		pr.People = people
	}
	deps := buildDepsFromMaps(match.Require, match.RequireDev, nil, match.Suggest)
	if !deps.empty() {
		pr.Dependencies = deps.section()
	}
	if urls.SourceRepoURL != "" {
		pr.Provenance = &ProvenanceSection{SourceRepo: urls.SourceRepoURL}
	}

	// Composer's p2 endpoint already returned every version of the
	// package in a single response — reuse `entries` for the timeline
	// instead of issuing a second request. `time` is RFC3339 in p2.
	timeline := make([]VersionRelease, 0, len(entries))
	var latest string
	var latestT time.Time
	for _, e := range entries {
		if e.Version == "" {
			continue
		}
		rel := VersionRelease{Version: e.Version}
		if t, ok := parseTime(e.Time); ok {
			rel.PublishedAt = t
			// Packagist's p2 array is conventionally newest-first but
			// the contract doesn't guarantee ordering — pick the
			// stable (no "dev-" / no "-RC"/"-alpha"/"-beta") with the
			// max publish time.
			if isStableComposerVersion(e.Version) && (latest == "" || t.After(latestT)) {
				latest = e.Version
				latestT = t
			}
		}
		timeline = append(timeline, rel)
	}
	applyTimeline(&pr, timeline, latest, nil)
	enrichRepoStars(ctx, p, &pr)
	return pr, nil
}

// isStableComposerVersion returns true when the Composer version label
// looks like a tagged release rather than a branch alias or a
// pre-release. Composer uses "dev-" for branch refs, and "-RC", "-alpha",
// "-beta" suffixes for pre-releases.
func isStableComposerVersion(v string) bool {
	if strings.HasPrefix(strings.ToLower(v), "dev-") {
		return false
	}
	lower := strings.ToLower(v)
	for _, suffix := range []string{"-rc", "-alpha", "-beta", "-dev"} {
		if strings.Contains(lower, suffix) {
			return false
		}
	}
	return true
}

// packagistMaintainer is the subset of the maintainer record returned
// by https://packagist.org/packages/{name}.json. `name` here is the
// Packagist account handle, not a personal full name.
type packagistMaintainer struct {
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

// fetchPackagistMaintainers returns the maintainer accounts for a
// Packagist package. The endpoint is the legacy /packages JSON
// (separate from the p2 metadata we already use) — it is the only
// place Packagist exposes the maintainer list.
func (p *registryMetadataProvider) fetchPackagistMaintainers(ctx context.Context, pkg string) []packagistMaintainer {
	endpoint := fmt.Sprintf("%s/packages/%s.json", p.endpoints.composer, pkg)
	var resp struct {
		Package struct {
			Maintainers []packagistMaintainer `json:"maintainers"`
		} `json:"package"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &resp)
	if err != nil || warn != nil {
		return nil
	}
	return resp.Package.Maintainers
}

// -- Go modules (proxy.golang.org) -----------------------------------

// encodeGoModulePath escapes uppercase letters per the Go module proxy
// spec: each ASCII uppercase letter is replaced with "!" + lowercase.
func encodeGoModulePath(p string) string {
	var b strings.Builder
	b.Grow(len(p))
	for _, r := range p {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + 32)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// goProxyVersion re-adds the leading "v" the depparsers strip.
//
// The Go module proxy protocol REQUIRES canonical semver — "@v/1.6.0.info"
// is rejected as an invalid version, only "@v/v1.6.0.info" resolves. Both Go
// lockfile parsers (core/depparser/parser/golang/{mod,sum}) emit the stripped
// spelling so their coordinates dedup against each other and match how vuln
// DBs index semver, which means every version reaching this provider needs
// the prefix put back. Idempotent: a version that already has it is returned
// untouched. Mirrors the idiom in core/depparser/dependency/id.go.
func goProxyVersion(ver string) string {
	ver = strings.TrimSpace(ver)
	if ver == "" || strings.HasPrefix(ver, "v") {
		return ver
	}
	return "v" + ver
}

func (p *registryMetadataProvider) runGo(ctx context.Context, pkg, ver string) (PartialReport, error) {
	module := encodeGoModulePath(strings.TrimSpace(pkg))
	if module == "" {
		return PartialReport{}, nil
	}
	ver = goProxyVersion(ver)
	infoURL := fmt.Sprintf("%s/%s/@v/%s.info", p.endpoints.goproxy, module, url.PathEscape(ver))
	var info struct {
		Version string `json:"Version"`
		Time    string `json:"Time"`
		Origin  struct {
			URL  string `json:"URL"`
			Ref  string `json:"Ref"`
			Hash string `json:"Hash"`
		} `json:"Origin"`
	}
	warn, err := p.fetchJSON(ctx, infoURL, "application/json", &info)
	if err != nil {
		return PartialReport{}, err
	}
	pr := PartialReport{}
	if warn != nil {
		// @v/{ver}.info 404s for an unknown module and for an unknown
		// version alike. @v/list answers 404 only for the former.
		warn = p.promoteVersionNotFound(ctx, "go", warn, infoURL, pkg, ver, p.probeGoModule(module))
		pr.Warnings = append(pr.Warnings, *warn)
		return pr, nil
	}

	// Best-effort companion request for "latest" — non-fatal if it fails
	// (pseudo-versions and forks may not have a @latest pointer).
	var latest struct {
		Version string `json:"Version"`
	}
	latestURL := fmt.Sprintf("%s/%s/@latest", p.endpoints.goproxy, module)
	_, _ = p.fetchJSON(ctx, latestURL, "application/json", &latest)

	release := &ReleaseSection{}
	if t, ok := parseTime(info.Time); ok {
		release.PublishedAt = &t
	}
	if latest.Version != "" {
		release.LatestVersion = latest.Version
	}

	urls := &URLSection{
		MetadataURL: infoURL,
		ArtifactURL: fmt.Sprintf("%s/%s/@v/%s.zip", p.endpoints.goproxy, module, url.PathEscape(ver)),
	}
	if info.Origin.URL != "" {
		urls.SourceRepoURL = normaliseRepoURL(info.Origin.URL)
	}
	artifact := &ArtifactSection{
		Filename:  fmt.Sprintf("%s.zip", ver),
		Packaging: "zip",
	}
	metadata := &MetadataSection{}
	// proxy.golang.org's @v/{ver}.info has no license field — Go modules
	// store license inside the archive itself. Use deps.dev as the
	// canonical secondary source so the UI gets a license expression
	// without us shelling out to extract LICENSE files. Soft-fail.
	if lic := p.fetchDepsDevGoLicense(ctx, pkg, ver); lic != "" {
		metadata.LicenseExpression = lic
	}

	// Populate Dependencies.Direct from the module's go.mod file. We
	// extract only entries NOT marked `// indirect` because MVS-derived
	// indirects belong to transitive dependencies and the
	// transitive-risk resolver discovers them by walking each direct
	// dep's own go.mod (recursive scans cache them). Note this captures
	// the DECLARED minimum versions, not the EFFECTIVE versions Go's
	// MVS would resolve — full MVS would require a `go` toolchain on
	// PATH and a full module graph walk. This matches what most CVE
	// scanners do today.
	if deps := p.fetchGoMod(ctx, module, ver, &pr); deps != nil && len(deps.Direct) > 0 {
		pr.Dependencies = deps
	}

	pr.Release = release
	pr.URLs = urls
	pr.Artifact = artifact
	pr.Metadata = metadata
	if urls.SourceRepoURL != "" {
		pr.Provenance = &ProvenanceSection{SourceRepo: urls.SourceRepoURL}
	}

	// Version timeline, from the same @v/list endpoint probeGoModule
	// already uses on the 404 branch — hoisted onto the SUCCESS path.
	//
	// WHY. applyTimeline is the single writer of
	// Maintenance.VersionTimeline and is called from 8 of the 12
	// ecosystem handlers; runGo was not one of them, so every Go
	// coordinate held an empty timeline. Measured on a live production
	// replay of 439 CVE-bearing rows: of the 43 rows whose safe-version
	// candidate could not be checked against a published list, 39 were
	// Go. This is the fact those rows were missing, and it must land in
	// the SAME matcher epoch as the membership veto in
	// MinimumSafeVersion — the epoch drain calls Scan with
	// AllowStale:false, so a veto shipped one epoch ahead of this fetch
	// would rescan every Go row while it still had no timeline and
	// PERSIST the blanking.
	//
	// COST. One extra GET on a path that already makes four (info,
	// @latest, deps.dev licence, go.mod).
	//
	// @v/list OMITS PSEUDO-VERSIONS. Two consequences, both deliberate:
	// the membership veto that reads this list stays conditional and
	// trailing-zero-tolerant (see MinimumSafeVersion step 5), and this
	// call deliberately does NOT emit versionNotFoundWarning the way the
	// single-canonical-registry handlers do. A pseudo-versioned module is
	// legitimately absent from @v/list, and minting version_not_found for
	// it would route the whole coordinate to VerdictUnknown.
	//
	// The list carries no publish dates, so every entry has a zero
	// PublishedAt and FirstPublishedAt stays nil — applyTimeline already
	// handles that (it derives FirstPublishedAt only from non-zero
	// times). latest="" because release.LatestVersion is already set from
	// @latest above and applyTimeline only fills it when empty.
	//
	// A failed fetch is reported as timeline_fetch_failed, the same
	// recoverable code the other eight handlers use — the primary
	// per-version fetch already succeeded, so this is missing version
	// history, not a missing package. NOT swallowed the way the @latest
	// fetch above is: an operator must be able to tell "Go has no
	// timeline" from "we never asked", and core/coverage classifies the
	// code as StatusUnavailable, which is the fail-closed posture this
	// repo takes for every other ecosystem's timeline.
	//
	// SIZE THAT DECISION BEFORE THE EPOCH-9 DRAIN. Measured while
	// building the 400-coordinate FP corpus twice in 15 minutes at
	// parallelism 8: the first build got 69 of 70 Go timelines, the
	// second only 60 — proxy.golang.org throttles, and every throttled
	// coordinate now emits this code where it previously emitted nothing.
	// Harmless to scoring (the membership veto is conditional, so a
	// missing timeline vetoes nothing), but it is a new input to the
	// OPT-IN core/coverage gate. Drain at a parallelism the proxy
	// tolerates.
	listVersions, listEndpoint, listWarn := p.probeGoModule(module)(ctx)
	if listWarn != nil {
		applyTimeline(&pr, nil, "", timelineFetchFailedWarning(p, listEndpoint, nil, listWarn))
	} else if len(listVersions) > 0 {
		timeline := make([]VersionRelease, 0, len(listVersions))
		for _, v := range listVersions {
			if s := strings.TrimSpace(v); s != "" {
				timeline = append(timeline, VersionRelease{Version: s})
			}
		}
		applyTimeline(&pr, timeline, "", nil)
	}
	return pr, nil
}

// fetchGoMod retrieves and parses the per-version go.mod from the
// goproxy and returns a DependenciesSection populated from the
// `require (...)` block. Fail-soft: any fetch / parse error appends a
// warning to pr and returns nil so the caller can carry on with the
// rest of the report. Pseudo-version constraints (e.g.
// "v0.0.0-20240101000000-abc123def") are propagated verbatim — the
// downstream constraint resolver matches them against cached
// intelligence rows as exact version strings.
func (p *registryMetadataProvider) fetchGoMod(ctx context.Context, module, ver string, pr *PartialReport) *DependenciesSection {
	// Defensive: runGo already normalised, but this is reachable from any
	// future caller and an un-prefixed version 404s on the proxy.
	modURL := fmt.Sprintf("%s/%s/@v/%s.mod", p.endpoints.goproxy, module, url.PathEscape(goProxyVersion(ver)))
	var body []byte
	warn, err := p.fetchDecoded(ctx, modURL, "text/plain", func(r io.Reader) error {
		// 1 MiB ceiling: real-world go.mod files are <50KB; this is
		// purely a guard against a misbehaving proxy.
		b, rerr := io.ReadAll(io.LimitReader(r, 1<<20))
		if rerr != nil {
			return rerr
		}
		body = b
		return nil
	})
	if err != nil || warn != nil {
		// 404 is silent: legacy modules pre-go.mod era ship without a
		// .mod entry on the proxy. No deps to surface, no signal worth
		// warning about. 5xx, transport, decode errors emit a
		// breadcrumb so transitive-risk callers can tell "no deps
		// known" from "could not fetch".
		if warn == nil || warn.Code != "not_found" {
			pr.Warnings = append(pr.Warnings, Warning{
				Provider: "registrymetadata",
				Code:     "mod_fetch_failed",
				Message:  fmt.Sprintf("endpoint=%s", modURL),
				At:       p.now(),
			})
		}
		return nil
	}
	f, parseErr := modfile.Parse("go.mod", body, nil)
	if parseErr != nil {
		pr.Warnings = append(pr.Warnings, Warning{
			Provider: "registrymetadata",
			Code:     "mod_fetch_failed",
			Message:  fmt.Sprintf("endpoint=%s parse=%s", modURL, parseErr.Error()),
			At:       p.now(),
		})
		return nil
	}
	out := make([]DependencyRef, 0, len(f.Require))
	for _, r := range f.Require {
		if r == nil || r.Indirect {
			// Skip indirects: MVS-derived, resolved by walking direct
			// deps' own go.mod files (the transitive resolver's job).
			continue
		}
		name := strings.TrimSpace(r.Mod.Path)
		if name == "" {
			continue
		}
		out = append(out, DependencyRef{
			Name:       name,
			Constraint: strings.TrimSpace(r.Mod.Version),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return &DependenciesSection{Direct: out}
}

// fetchDepsDevGoLicense queries the deps.dev v3 API for license data
// on a Go module version. deps.dev resolves the LICENSE files inside
// the module archive — pkg.go.dev uses the same extractor — so the
// `licenses` array reflects what tooling like license scanners see.
// Joins multi-license entries with " OR " to match SPDX expression
// conventions used by the other providers in this file.
func (p *registryMetadataProvider) fetchDepsDevGoLicense(ctx context.Context, pkg, ver string) string {
	// deps.dev indexes Go versions in canonical "vX.Y.Z" form, same as the
	// module proxy — a stripped version returns 404.
	endpoint := fmt.Sprintf("%s/v3/systems/go/packages/%s/versions/%s",
		p.endpoints.depsdev,
		url.PathEscape(strings.TrimSpace(pkg)),
		url.PathEscape(goProxyVersion(ver)))
	var resp struct {
		Licenses []string `json:"licenses"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &resp)
	if err != nil || warn != nil {
		return ""
	}
	out := make([]string, 0, len(resp.Licenses))
	for _, l := range resp.Licenses {
		if s := strings.TrimSpace(l); s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, " OR ")
}

// -- Cocoapods (trunk.cocoapods.org) ---------------------------------

func (p *registryMetadataProvider) runCocoapods(ctx context.Context, pkg, ver string) (PartialReport, error) {
	endpoint := fmt.Sprintf("%s/api/v1/pods/%s", p.endpoints.cocoapods, url.PathEscape(pkg))
	var pod struct {
		Name     string `json:"name"`
		Versions []struct {
			Name      string `json:"name"`
			CreatedAt string `json:"created_at"`
		} `json:"versions"`
		Owners []struct {
			Email string `json:"email"`
			Name  string `json:"name"`
		} `json:"owners"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &pod)
	if err != nil {
		return PartialReport{}, err
	}
	pr := PartialReport{}
	if warn != nil {
		pr.Warnings = append(pr.Warnings, *promotePackagumentNotFound(p, "cocoapods", warn, endpoint, pkg, ver))
		return pr, nil
	}

	release := &ReleaseSection{}
	matched := false
	for _, v := range pod.Versions {
		if v.Name == ver {
			matched = true
			if t, ok := parseTime(v.CreatedAt); ok {
				release.PublishedAt = &t
			}
			break
		}
	}
	if len(pod.Versions) > 0 {
		release.LatestVersion = pod.Versions[len(pod.Versions)-1].Name
	}

	// Trunk's pod summary carries the complete published-version list,
	// so a miss against a non-empty list is positive evidence the pinned
	// version was never pushed. Before this the runner just carried on
	// and returned owners + the latest version's podspec — a report that
	// scores like any other pod while describing a version that does not
	// exist. An empty `versions` array (a partial or mirrored trunk
	// response) is NOT evidence and keeps the old behaviour.
	if !matched && len(pod.Versions) > 0 {
		published := make([]string, 0, len(pod.Versions))
		for _, v := range pod.Versions {
			published = append(published, v.Name)
		}
		if !versionListed(published, ver) {
			pr.Warnings = append(pr.Warnings,
				*versionNotFoundWarning(p, endpoint, pkg, ver, len(published)))
		}
	}

	people := &PeopleSection{}
	for _, o := range pod.Owners {
		if s := joinAuthor(o.Name, o.Email); s != "" {
			people.Maintainers = append(people.Maintainers, s)
		}
		// Trunk owners are the canonical publishers — `pod trunk push`
		// is gated on owner membership so the email is the publisher id.
		if id := strings.TrimSpace(o.Email); id != "" {
			people.PublisherIDs = append(people.PublisherIDs, id)
		} else if id := strings.TrimSpace(o.Name); id != "" {
			people.PublisherIDs = append(people.PublisherIDs, id)
		}
	}

	urls := &URLSection{MetadataURL: endpoint}
	metadata := &MetadataSection{}
	artifact := &ArtifactSection{Packaging: "podspec"}

	// Per-version podspec.json on the CDN holds license + authors —
	// data trunk's pod summary doesn't surface. The sharded path is
	// `Specs/{a}/{b}/{c}/{Name}/{Version}/{Name}.podspec.json` where
	// a/b/c are the first three hex chars of md5(name) (case sensitive).
	if spec := p.fetchCocoapodsSpec(ctx, pkg, ver); spec != nil {
		if lic := cocoapodsLicense(spec.License); lic != "" {
			metadata.LicenseExpression = lic
		}
		if spec.Summary != "" {
			metadata.Summary = spec.Summary
		}
		if spec.Description != "" {
			metadata.Description = spec.Description
		}
		if spec.Homepage != "" {
			urls.HomepageURL = spec.Homepage
		}
		if src := strings.TrimSpace(spec.Source.Git); src != "" {
			urls.SourceRepoURL = normaliseRepoURL(src)
		}
		// `authors` is either a {name: email} map or a plain string.
		for _, a := range cocoapodsAuthors(spec.Authors) {
			if a != "" {
				people.Authors = append(people.Authors, a)
			}
		}
	}

	pr.Release = release
	pr.URLs = urls
	pr.Artifact = artifact
	pr.Metadata = metadata
	if len(people.Maintainers)+len(people.Authors)+len(people.PublisherIDs) > 0 {
		pr.People = people
	}
	if urls.SourceRepoURL != "" {
		pr.Provenance = &ProvenanceSection{SourceRepo: urls.SourceRepoURL}
	}
	return pr, nil
}

// runPub fetches package metadata from pub.dev's clean JSON registry.
//
// GET /api/packages/{name} returns `latest` + `versions[]`, each with
// `version`, `published` (ISO-8601), `archive_url`, and an inlined `pubspec`.
// pub names are flat snake_case (no scopes). The endpoint does NOT carry a
// license field anywhere (verified against the live API) — pub.dev derives
// license from the archive's LICENSE file and surfaces it only via the
// separate /score endpoint's `tags` (`license:<spdx>`). We fetch that too so
// packageLicense populates; a /score miss is non-fatal (release date still
// returns).
func (p *registryMetadataProvider) runPub(ctx context.Context, pkg, ver string) (PartialReport, error) {
	endpoint := fmt.Sprintf("%s/api/packages/%s", p.endpoints.pub, url.PathEscape(pkg))
	var doc struct {
		Name   string `json:"name"`
		Latest struct {
			Version   string `json:"version"`
			Published string `json:"published"`
		} `json:"latest"`
		// NOTE: package-level discontinuation (isDiscontinued/replacedBy) is
		// NOT on this endpoint — pub.dev exposes it only on the separate
		// /api/packages/{name}/options endpoint. It is fetched below via
		// fetchPubOptions and routed onto Release.Deprecated. (Per-version
		// retraction IS inlined here, on each versions[] entry — see Retracted.)
		Versions []struct {
			Version   string `json:"version"`
			Published string `json:"published"`
			// Retracted is pub.dev's per-version "do not install this
			// version" flag (the registry left the version resolvable for
			// existing pins but withdrew it from new resolution). It is the
			// pub-native equivalent of npm's deprecate / cargo's yank and
			// maps onto the plumbed Release.Yanked field below.
			Retracted bool `json:"retracted"`
			Pubspec   struct {
				Description string `json:"description"`
				Homepage    string `json:"homepage"`
				Repository  string `json:"repository"`
			} `json:"pubspec"`
		} `json:"versions"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &doc)
	if err != nil {
		return PartialReport{}, err
	}
	pr := PartialReport{}
	if warn != nil {
		pr.Warnings = append(pr.Warnings, *promotePackagumentNotFound(p, "pub", warn, endpoint, pkg, ver))
		return pr, nil
	}

	release := &ReleaseSection{LatestVersion: strings.TrimSpace(doc.Latest.Version)}
	urls := &URLSection{MetadataURL: endpoint}
	meta := &MetadataSection{}

	matched := false
	for _, v := range doc.Versions {
		if strings.TrimSpace(v.Version) != ver {
			continue
		}
		matched = true
		if t, ok := parseTime(v.Published); ok {
			release.PublishedAt = &t
		}
		// A retracted version is the pub-native "do not install" flag.
		// Set the plumbed Release.Yanked so downstream consumers
		// (provider_pubwithdrawal routing it into ConditionVersionAnomaly,
		// risk_projection's DeprecatedByMaintainer) see it. Only set true
		// on a positive flag — leave nil otherwise so "not retracted" stays
		// distinct from "unknown" for the three-state pointer contract.
		if v.Retracted {
			yanked := true
			release.Yanked = &yanked
		}
		if d := strings.TrimSpace(v.Pubspec.Description); d != "" {
			meta.Description = d
		}
		if h := strings.TrimSpace(v.Pubspec.Homepage); h != "" {
			urls.HomepageURL = h
		}
		if r := strings.TrimSpace(v.Pubspec.Repository); r != "" {
			urls.SourceRepoURL = normaliseRepoURL(r)
		}
		break
	}
	// Fall back to `latest`'s publish date if the requested version isn't in
	// the list (e.g. yanked/retracted) so packageAge still has a signal.
	isLatest := strings.TrimSpace(doc.Latest.Version) == ver
	if !matched && isLatest {
		if t, ok := parseTime(doc.Latest.Published); ok {
			release.PublishedAt = &t
		}
	}

	// `matched` used to exist purely to drive that fallback — the one
	// place in this runner that knew the pinned version was absent, and
	// it used the knowledge to paper over the absence. A pub package
	// document lists every published version, so a miss against a
	// non-empty list is positive evidence of absence.
	//
	// Two exclusions. `latest` naming the requested version is positive
	// evidence of PRESENCE (the version exists; versions[] just did not
	// carry it), so it wins over the miss. And an empty versions[] is a
	// partial document, not an absent version.
	if !matched && !isLatest && len(doc.Versions) > 0 {
		published := make([]string, 0, len(doc.Versions))
		for _, v := range doc.Versions {
			published = append(published, v.Version)
		}
		if !versionListed(published, ver) {
			pr.Warnings = append(pr.Warnings,
				*versionNotFoundWarning(p, endpoint, pkg, ver, len(published)))
		}
	}

	// Thread the full per-version published timeline through so the
	// version-anomaly path (provider_metadiff: prior.Maintenance.VersionTimeline)
	// and VersionCount see real release-date history — not just the single
	// matched version's PublishedAt. pub.dev's GET /api/packages/{name}
	// returns the entire versions[] map in this one fetch, so no extra HTTP
	// call is needed. Mirrors the cargo/rubygems applyTimeline pattern.
	timeline := make([]VersionRelease, 0, len(doc.Versions))
	for _, v := range doc.Versions {
		name := strings.TrimSpace(v.Version)
		if name == "" {
			continue
		}
		rel := VersionRelease{Version: name}
		if t, ok := parseTime(v.Published); ok {
			rel.PublishedAt = t
		}
		timeline = append(timeline, rel)
	}

	// License lives only on the /score endpoint as a `license:<spdx>` tag.
	if lic := p.fetchPubLicense(ctx, pkg); lic != "" {
		meta.LicenseExpression = lic
	}

	// Verified publisher lives on the /publisher endpoint as a DNS-verified
	// domain id. It feeds People.PublisherIDs so the metadiff provider can
	// detect publisherChanged across versions (Phase 3). A /publisher miss
	// (unverified package, or outage) is non-fatal — the diff falls back to
	// "unknown" rather than flapping.
	if publisher := p.fetchPubPublisher(ctx, pkg); publisher != "" {
		pr.People = &PeopleSection{PublisherIDs: []string{publisher}}
	}

	// A package-level discontinuation is the maintainer signalling "stop
	// using this package". It is a registry-native withdrawal — analogous
	// to npm's maintainer deprecation — so route it onto Release.Deprecated
	// (which already feeds risk_projection's DeprecatedByMaintainer) rather
	// than minting a malware verdict. provider_pubwithdrawal reads this to
	// raise the malicious-adjacent versionAnomaly sub-signal. The flag is
	// per-package, so it applies to every version including the matched one.
	// pub.dev exposes it ONLY on the /options endpoint (not /api/packages/{name}),
	// so fetch it separately; an /options miss is non-fatal (best-effort, like
	// /score and /publisher above).
	if discontinued, replacedBy := p.fetchPubOptions(ctx, pkg); discontinued {
		reason := "discontinued"
		if rb := strings.TrimSpace(replacedBy); rb != "" {
			reason = "discontinued: replaced by " + rb
		}
		release.Deprecated = reason
	}

	pr.Release = release
	pr.URLs = urls
	if meta.LicenseExpression != "" || meta.Description != "" {
		pr.Metadata = meta
	}
	if urls.SourceRepoURL != "" {
		pr.Provenance = &ProvenanceSection{SourceRepo: urls.SourceRepoURL}
	}
	// Apply the timeline last so it sorts the slice and derives
	// FirstPublishedAt + VersionCount onto pr.Maintenance. latest="" because
	// pr.Release.LatestVersion is already set from doc.Latest above; passing it
	// again would be redundant (applyTimeline only fills LatestVersion when
	// empty). A single-entry or empty timeline is harmless — applyTimeline
	// no-ops on len==0.
	applyTimeline(&pr, timeline, "", nil)
	return pr, nil
}

// fetchPubLicense reads the SPDX license id from pub.dev's /score endpoint,
// where it is encoded as a `license:<spdx-id>` tag (e.g. license:bsd-3-clause).
// Returns "" on any miss — license is best-effort and a /score outage must not
// fail the whole metadata fetch. The score endpoint is package-scoped (not
// per-version); pub.dev reports a single license per package.
func (p *registryMetadataProvider) fetchPubLicense(ctx context.Context, pkg string) string {
	endpoint := fmt.Sprintf("%s/api/packages/%s/score", p.endpoints.pub, url.PathEscape(pkg))
	var score struct {
		Tags []string `json:"tags"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &score)
	if err != nil || warn != nil {
		return ""
	}
	return pubLicenseFromTags(score.Tags)
}

// fetchPubPublisher reads the verified-publisher id from pub.dev's
// /api/packages/{name}/publisher endpoint. pub.dev's verified-publisher model
// keys ownership on a DNS-verified domain ({"publisherId":"dart.dev"}); that
// id is the canonical, stable publisher identity exposed by the registry.
// publisherId is null for unverified (uploader-owned) packages — we return ""
// in that case so the metadiff provider treats the publisher as unknown
// rather than diffing against an empty set. A /publisher outage is non-fatal:
// publisher is best-effort and must not fail the whole metadata fetch.
func (p *registryMetadataProvider) fetchPubPublisher(ctx context.Context, pkg string) string {
	endpoint := fmt.Sprintf("%s/api/packages/%s/publisher", p.endpoints.pub, url.PathEscape(pkg))
	var payload struct {
		PublisherID *string `json:"publisherId"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &payload)
	if err != nil || warn != nil || payload.PublisherID == nil {
		return ""
	}
	return strings.TrimSpace(*payload.PublisherID)
}

// fetchPubOptions reads the package-level discontinuation flag from pub.dev's
// /api/packages/{name}/options endpoint, which returns
// {"isDiscontinued":bool,"replacedBy":string|null,"isUnlisted":bool}.
// This is the ONLY endpoint that carries discontinuation — /api/packages/{name}
// does not — so it must be fetched separately. Returns (false, "") on any miss;
// discontinuation is best-effort and an /options outage must not fail the whole
// metadata fetch (mirrors fetchPubLicense / fetchPubPublisher).
func (p *registryMetadataProvider) fetchPubOptions(ctx context.Context, pkg string) (bool, string) {
	endpoint := fmt.Sprintf("%s/api/packages/%s/options", p.endpoints.pub, url.PathEscape(pkg))
	var payload struct {
		IsDiscontinued bool   `json:"isDiscontinued"`
		ReplacedBy     string `json:"replacedBy"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &payload)
	if err != nil || warn != nil {
		return false, ""
	}
	return payload.IsDiscontinued, strings.TrimSpace(payload.ReplacedBy)
}

// pubLicenseFromTags extracts the SPDX license id from pub.dev score tags.
// Tags look like "license:bsd-3-clause"; the marker tags "license:fsf-libre"
// and "license:osi-approved" are classification flags, not SPDX ids, and are
// skipped. The remaining license: tag is upcased to the canonical SPDX form.
func pubLicenseFromTags(tags []string) string {
	const prefix = "license:"
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if !strings.HasPrefix(t, prefix) {
			continue
		}
		id := strings.TrimPrefix(t, prefix)
		switch id {
		case "", "fsf-libre", "osi-approved", "unknown":
			continue
		}
		return spdxFromPubTag(id)
	}
	return ""
}

// spdxFromPubTag maps a pub.dev lowercase license tag to its canonical SPDX
// identifier. pub.dev tags are the SPDX id lowercased (bsd-3-clause,
// apache-2.0, mit); SPDX casing rules upper-case the letter run but keep the
// version suffix. A small map covers the common ids exactly; anything else
// falls back to a best-effort upper-casing of the alphabetic head.
func spdxFromPubTag(id string) string {
	known := map[string]string{
		"mit":          "MIT",
		"apache-2.0":   "Apache-2.0",
		"bsd-2-clause": "BSD-2-Clause",
		"bsd-3-clause": "BSD-3-Clause",
		"gpl-2.0":      "GPL-2.0",
		"gpl-3.0":      "GPL-3.0",
		"lgpl-3.0":     "LGPL-3.0",
		"mpl-2.0":      "MPL-2.0",
		"isc":          "ISC",
		"unlicense":    "Unlicense",
		"bsl-1.0":      "BSL-1.0",
	}
	if spdx, ok := known[id]; ok {
		return spdx
	}
	// Fallback for ids not in the table: title-case the leading alphabetic
	// run (e.g. "zlib" → "Zlib"), keep the remainder (version suffixes etc.)
	// verbatim. Best-effort only — the common ids are covered by the map.
	if id == "" {
		return ""
	}
	i := 0
	for i < len(id) && ((id[i] >= 'a' && id[i] <= 'z') || (id[i] >= 'A' && id[i] <= 'Z')) {
		i++
	}
	head := strings.ToUpper(id[:1]) + id[1:i]
	return head + id[i:]
}

// cocoapodsSpec is the subset of a podspec.json record we read.
type cocoapodsSpec struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	License     any    `json:"license"`
	Authors     any    `json:"authors"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Homepage    string `json:"homepage"`
	Source      struct {
		Git string `json:"git"`
		Tag string `json:"tag"`
	} `json:"source"`
}

// fetchCocoapodsSpec retrieves a per-version podspec.json from the
// CocoaPods CDN. Returns nil on any error so callers can fall back to
// the trunk summary's data.
func (p *registryMetadataProvider) fetchCocoapodsSpec(ctx context.Context, name, ver string) *cocoapodsSpec {
	a, b, c := cocoapodsShard(name)
	endpoint := fmt.Sprintf("%s/Specs/%s/%s/%s/%s/%s/%s.podspec.json",
		p.endpoints.cocoapodsCDN, a, b, c,
		url.PathEscape(name), url.PathEscape(ver), url.PathEscape(name))
	var spec cocoapodsSpec
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &spec)
	if err != nil || warn != nil {
		return nil
	}
	return &spec
}

// cocoapodsShard mirrors the CDN's md5(name)[:3] sharding rule used to
// locate a pod's per-version podspec.json on cdn.cocoapods.org.
func cocoapodsShard(name string) (a, b, c string) {
	sum := md5.Sum([]byte(name))
	hexed := hex.EncodeToString(sum[:])
	return string(hexed[0]), string(hexed[1]), string(hexed[2])
}

// cocoapodsLicense unpacks the polymorphic license field from a
// podspec — it is either a SPDX-style string ("MIT") or an object
// {"type": "MIT", "file": "LICENSE"} where only `type` carries the
// expression. Returns "" when neither shape applies.
func cocoapodsLicense(raw any) string {
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case map[string]any:
		if t, _ := v["type"].(string); t != "" {
			return strings.TrimSpace(t)
		}
	}
	return ""
}

// cocoapodsAuthors flattens the polymorphic `authors` field from a
// podspec into a list of "name <email>" strings. Accepts either a
// plain string ("Foo Bar"), a list of strings, or a {name: email} map.
func cocoapodsAuthors(raw any) []string {
	switch v := raw.(type) {
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return nil
		}
		return []string{s}
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	case map[string]any:
		var out []string
		for name, emailAny := range v {
			email, _ := emailAny.(string)
			if s := joinAuthor(name, email); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// -- Hugging Face Hub -------------------------------------------------

func (p *registryMetadataProvider) runHuggingFace(ctx context.Context, pkg, ver string) (PartialReport, error) {
	endpoint := fmt.Sprintf("%s/api/models/%s", p.endpoints.huggingface, encodeHFModelID(pkg))
	if ver != "" {
		endpoint = fmt.Sprintf("%s/api/models/%s/revision/%s", p.endpoints.huggingface, encodeHFModelID(pkg), url.PathEscape(ver))
	}
	var model struct {
		ModelID      string   `json:"modelId"`
		ID           string   `json:"id"`
		SHA          string   `json:"sha"`
		LastModified string   `json:"lastModified"`
		CreatedAt    string   `json:"createdAt"`
		Tags         []string `json:"tags"`
		Downloads    int64    `json:"downloads"`
		Likes        int64    `json:"likes"`
		Library      string   `json:"library_name"`
		License      string   `json:"license"`
		Pipeline     string   `json:"pipeline_tag"`
		CardData     struct {
			License any      `json:"license"`
			Tags    []string `json:"tags"`
		} `json:"cardData"`
		Author  string `json:"author"`
		Private bool   `json:"private"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &model)
	if err != nil {
		return PartialReport{}, err
	}
	pr := PartialReport{}
	if warn != nil {
		pr.Warnings = append(pr.Warnings, *warn)
		return pr, nil
	}

	release := &ReleaseSection{}
	if t, ok := parseTime(model.LastModified); ok {
		release.ModifiedAt = &t
		release.PublishedAt = &t
	}
	if t, ok := parseTime(model.CreatedAt); ok {
		release.CreatedAt = &t
	}

	urls := &URLSection{
		MetadataURL: endpoint,
		HomepageURL: fmt.Sprintf("%s/%s", p.endpoints.huggingface, pkg),
	}
	artifact := &ArtifactSection{Packaging: "huggingface-model"}
	if model.SHA != "" {
		artifact.Digests.SHA256 = model.SHA
	}

	license := strings.TrimSpace(model.License)
	if license == "" {
		switch v := model.CardData.License.(type) {
		case string:
			license = strings.TrimSpace(v)
		case []any:
			var parts []string
			for _, x := range v {
				if s, ok := x.(string); ok && s != "" {
					parts = append(parts, s)
				}
			}
			license = strings.Join(parts, " OR ")
		}
	}

	metadata := &MetadataSection{
		LicenseExpression: license,
	}
	tags := append([]string{}, model.Tags...)
	tags = append(tags, model.CardData.Tags...)
	if len(tags) > 0 {
		metadata.Keywords = tags
	}

	people := &PeopleSection{}
	if a := strings.TrimSpace(model.Author); a != "" {
		people.Authors = append(people.Authors, a)
	}

	pr.Release = release
	pr.URLs = urls
	pr.Artifact = artifact
	pr.Metadata = metadata
	if len(people.Authors) > 0 {
		pr.People = people
	}
	return pr, nil
}

func encodeHFModelID(id string) string {
	if !strings.Contains(id, "/") {
		return url.PathEscape(id)
	}
	parts := strings.SplitN(id, "/", 2)
	return url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1])
}

// -- Docker Hub -------------------------------------------------------

func (p *registryMetadataProvider) runDocker(ctx context.Context, pkg, ver string) (PartialReport, error) {
	namespace, image := splitDockerImage(pkg)
	if image == "" {
		return PartialReport{}, nil
	}
	repoURL := fmt.Sprintf("%s/v2/repositories/%s/%s/", p.endpoints.docker, url.PathEscape(namespace), url.PathEscape(image))
	var repo struct {
		User           string `json:"user"`
		Name           string `json:"name"`
		Namespace      string `json:"namespace"`
		Description    string `json:"description"`
		FullDesc       string `json:"full_description"`
		PullCount      int64  `json:"pull_count"`
		StarCount      int64  `json:"star_count"`
		LastUpdated    string `json:"last_updated"`
		DateRegistered string `json:"date_registered"`
		IsPrivate      bool   `json:"is_private"`
	}
	warn, err := p.fetchJSON(ctx, repoURL, "application/json", &repo)
	if err != nil {
		return PartialReport{}, err
	}
	pr := PartialReport{}
	if warn != nil {
		pr.Warnings = append(pr.Warnings, *warn)
		return pr, nil
	}

	// Per-tag metadata: optional, soft-fail on 404. Multi-arch manifest
	// auth flow not implemented — surface only the manifest digest.
	var tag struct {
		Name        string `json:"name"`
		FullSize    int64  `json:"full_size"`
		LastUpdated string `json:"last_updated"`
		Digest      string `json:"digest"`
	}
	tagURL := fmt.Sprintf("%s/v2/repositories/%s/%s/tags/%s/", p.endpoints.docker, url.PathEscape(namespace), url.PathEscape(image), url.PathEscape(ver))
	// The warning is kept (it used to be discarded) purely so the
	// version_not_found promotion below can read it. Everything
	// downstream still treats a failed tag fetch as soft.
	tagWarn, _ := p.fetchJSON(ctx, tagURL, "application/json", &tag)

	release := &ReleaseSection{}
	if t, ok := parseTime(repo.DateRegistered); ok {
		release.CreatedAt = &t
	}
	if t, ok := parseTime(tag.LastUpdated); ok {
		release.PublishedAt = &t
		release.ModifiedAt = &t
	} else if t, ok := parseTime(repo.LastUpdated); ok {
		release.PublishedAt = &t
		release.ModifiedAt = &t
	}

	urls := &URLSection{
		MetadataURL: repoURL,
		HomepageURL: fmt.Sprintf("https://hub.docker.com/r/%s/%s", namespace, image),
	}

	artifact := &ArtifactSection{
		Packaging: "oci-image",
	}
	if tag.FullSize > 0 {
		artifact.Size = tag.FullSize
	}
	if tag.Digest != "" {
		artifact.Digests.SHA256 = strings.TrimPrefix(tag.Digest, "sha256:")
	}
	if tag.Name != "" {
		artifact.Filename = fmt.Sprintf("%s/%s:%s", namespace, image, tag.Name)
	} else {
		artifact.Filename = fmt.Sprintf("%s/%s:%s", namespace, image, ver)
	}

	metadata := &MetadataSection{
		Summary:     firstLine(repo.Description),
		Description: firstNonEmpty(repo.FullDesc, repo.Description),
	}
	// Docker / OCI images have no canonical license metadata. The OCI
	// image manifest spec defines `org.opencontainers.image.licenses`
	// but populating it requires pulling the image's blob layers and
	// inspecting the config JSON — out of scope for this provider's
	// metadata-only contract. Leave LicenseExpression empty so the UI
	// renders "no data" instead of a misleading guess.

	people := &PeopleSection{}
	if owner := strings.TrimSpace(repo.User); owner != "" {
		people.PublisherIDs = append(people.PublisherIDs, owner)
	} else if owner := strings.TrimSpace(repo.Namespace); owner != "" && owner != "library" {
		people.PublisherIDs = append(people.PublisherIDs, owner)
	}

	pr.Release = release
	pr.URLs = urls
	pr.Artifact = artifact
	pr.Metadata = metadata
	if len(people.PublisherIDs) > 0 {
		pr.People = people
	}

	// Docker is the one Group A ecosystem whose probe is free: the
	// repository object fetched above IS the package-level evidence (it
	// answered 200, so the image exists) and the per-tag object is the
	// version-level lookup. A 404 on the tag against a live repository is
	// positive evidence of absence — the hallucinated-tag case — and
	// without this the runner returned a repository-level report that
	// scored as though the tag were real.
	//
	// Only a literal not_found qualifies. A 401 on a private repo, a 429
	// from Hub's rate limiter and a timeout all arrive with their own
	// codes and must stay unpromoted.
	//
	// Digest pins are excluded: `image@sha256:...` is not a tag, so
	// /tags/{ref}/ 404s for every one of them, and promoting that would
	// mark every digest-pinned image NOT EVALUATED.
	//
	// The test must accept BOTH separators. The proxy's docker resolver
	// rewrites every ':' to '-' before the coordinate reaches intelligence
	// (internal/formats/docker/resolver.go, normalizeReference), so the
	// colon form only ever arrives from direct API callers. A colon-only
	// test looks exact and is in fact dead on the single path that
	// actually produces digest coordinates in production.
	if tagWarn != nil && tagWarn.Code == "not_found" && !isOCIDigestPin(ver) {
		pr.Warnings = append(pr.Warnings, *versionNotFoundByProbeWarning(p, tagURL, repoURL, pkg, ver, -1))
	}
	return pr, nil
}

// ociDigestHexLen maps an OCI digest algorithm to the exact number of hex
// characters its encoded form carries. Membership in this table is what
// makes isOCIDigestPin exact.
var ociDigestHexLen = map[string]int{
	"sha256": 64,
	"sha384": 96,
	"sha512": 128,
}

// isOCIDigestPin reports whether ver is a digest reference rather than a
// tag, accepting both `sha256:<hex>` and `sha256-<hex>`.
//
// Both separators must be accepted because the proxy's docker resolver
// rewrites ':' to '-' before the coordinate reaches intelligence, so the
// dash form is the only one the proxy path ever produces.
//
// The algorithm prefix and the exact hex length are both required. A '-'
// alone would be far too loose — `v1.2-alpine` is an ordinary tag, and
// treating it as a digest would silently suppress a real not-found.
func isOCIDigestPin(ver string) bool {
	i := strings.IndexAny(ver, ":-")
	if i <= 0 {
		return false
	}
	want, ok := ociDigestHexLen[strings.ToLower(ver[:i])]
	if !ok {
		return false
	}
	hex := ver[i+1:]
	if len(hex) != want {
		return false
	}
	for _, r := range hex {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// splitDockerImage normalises a Docker image reference into (namespace,
// image). Bare names ("nginx") get the implicit "library/" namespace.
func splitDockerImage(ref string) (namespace, image string) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", ""
	}
	if i := strings.Index(ref, "/"); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	return "library", ref
}

// -- Small shared utilities -------------------------------------------

func filenameFromURL(u string) string {
	if u == "" {
		return ""
	}
	if i := strings.LastIndex(u, "/"); i >= 0 {
		return u[i+1:]
	}
	return u
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}

func ifEntry(cond bool, v string) string {
	if cond {
		return v
	}
	return ""
}

func ifEntryAny(cond bool, v any) any {
	if cond {
		return v
	}
	return nil
}

func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func joinAuthor(name, email string) string {
	name = strings.TrimSpace(name)
	email = strings.TrimSpace(email)
	switch {
	case name != "" && email != "":
		return fmt.Sprintf("%s <%s>", name, email)
	case name != "":
		return name
	case email != "":
		return email
	}
	return ""
}

func splitCommaList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// versionMatches compares two version strings after stripping an
// optional "v" prefix so "v1.2.3" and "1.2.3" are treated as equal.
func versionMatches(a, b string) bool {
	return strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}

// versionListed reports whether ver appears anywhere in the registry's
// published version list, using the same `v`-tolerant comparison the
// per-entry matchers use.
//
// It exists only for the ABSENCE decision below: the runners do their
// primary lookup with an exact map key or an exact string compare, and a
// caller that pinned `v1.2.3` where the registry publishes `1.2.3` would
// miss that lookup while the version plainly exists. Declaring a
// hallucinated version on the back of a formatting difference is exactly
// the false positive this whole path is built to avoid, so the miss path
// pays one extra O(n) sweep before it commits to "not published".
func versionListed(published []string, ver string) bool {
	for _, p := range published {
		if versionMatches(strings.TrimSpace(p), ver) {
			return true
		}
	}
	return false
}

// versionNotFoundWarning builds the WarnVersionNotFound diagnostic for a
// coordinate whose registry document enumerated its published versions
// and did not include the requested one.
//
// CALL THIS ONLY ON POSITIVE EVIDENCE OF ABSENCE — document fetched OK,
// version list non-empty, requested version absent. The `published`
// count is carried in the message precisely so an operator reading a
// report can see the guard held: a marker claiming absence out of a
// zero-length list would be a bug, not a finding.
//
// Downstream this is not cosmetic. risk_projection.go turns the code
// into risk.Input.SignalsUnavailable, which makes the verdict `unknown`
// and flips `chainsaw intel scan` from exit 0 to exit 2. Emitting it on
// a mirror that serves partial documents would start failing builds.
func versionNotFoundWarning(p *registryMetadataProvider, endpoint, pkg, ver string, published int) *Warning {
	return &Warning{
		Provider: "registrymetadata",
		Code:     WarnVersionNotFound,
		Message: fmt.Sprintf("endpoint=%s package=%s version=%s publishedVersions=%d",
			endpoint, pkg, ver, published),
		At: p.now(),
	}
}

// -- Group A: promoting a per-version 404 into version_not_found ------
//
// Eight ecosystems ask a PER-VERSION endpoint for their metadata
// (pypi, maven, cargo, rubygems, nuget, go, huggingface, docker) instead
// of pulling a packument and indexing into it. Those endpoints answer
// one 404 for two different facts — "no such package" and "no such
// version of this package" — so the whole group fell back to the generic
// not_found warning and a hallucinated pin still got scored. That is
// precisely the LLM-invented-version case the marker exists to catch.
//
// The discriminator is a SECOND, package-level request, issued only
// after the per-version endpoint 404s:
//
//	package-level 200, version absent from its list -> version_not_found
//	package-level 404, single-canonical registry    -> package_not_found
//	package-level 404, federated ecosystem          -> keep not_found
//	package-level 5xx / timeout / transport failure -> keep not_found
//
// Rows two and three are P8-04 and its correction, and the split between
// them is the single-canonical-registry rule documented above
// promoteVersionNotFound: only an ecosystem with ONE canonical registry
// can have "this registry 404ed" mean "this package does not exist". Of
// the ecosystems on this path that is pypi, cargo, rubygems and nuget;
// maven/gradle and go are federated and keep the pre-P8-04 not_found.
//
// The last line is load-bearing for a different reason. Absence of
// evidence is not evidence of absence: promoting an unanswered probe
// would convert every registry hiccup, private mirror and replication lag
// into an `unknown` verdict and a failed build.
//
// Cost: the probe sits behind the 404 branch, so a healthy scan issues
// exactly the requests it issued before this existed — pinned by
// TestGroupAProbeDoesNotFireOnSuccessPath. It rides the shared fetch
// helpers, whose retry policy already classes 4xx as terminal, so one
// 404 stays one request rather than becoming three.
//
// Per-ecosystem decisions:
//
//	pypi        WIRED   /pypi/{pkg}/json           (reuses fetchPyPITimeline)
//	maven       WIRED   .../maven-metadata.xml     (reuses fetchMavenTimeline)
//	                    FEDERATED: the probe still separates "this version
//	                    is absent from a package repo1 does carry" from
//	                    "repo1 carries nothing under this coordinate", but
//	                    only the first is reportable. repo1 is one of
//	                    several homes for a groupId — Central,
//	                    maven.google.com, JitPack, corporate mirrors — so
//	                    the second keeps not_found.
//	cargo       WIRED   /api/v1/crates/{crate}     (reuses fetchCargoTimeline)
//	rubygems    WIRED   /api/v1/versions/{gem}.json(reuses fetchRubyGemsTimeline)
//	nuget       WIRED   flat-container {id}/index.json — deliberately NOT the
//	                    registration index fetchNuGetTimeline reads. That one
//	                    paginates past ~64 entries and this file does not
//	                    follow the page pointers, so it reports an empty list
//	                    for exactly the popular packages where a wrong
//	                    promotion would hurt most.
//	go          WIRED   /{module}/@v/list (text/plain)
//	                    FEDERATED, same split as maven: the module path is
//	                    the identity and proxy.golang.org is a cache of
//	                    public VCS, so a private, vanity or GOPRIVATE
//	                    module 404s there while existing. A total 404 keeps
//	                    not_found.
//	docker      WIRED   free — runDocker ALREADY fetches the repository
//	                    object first and the per-tag object second, so both
//	                    halves of the evidence are in hand with no extra
//	                    request. Handled inline in runDocker rather than
//	                    through promoteVersionNotFound, and it is the one
//	                    probe that proves existence without a version list:
//	                    Docker Hub's tag listing is paginated and rate
//	                    limited, so enumerating it is not cheap.
//	huggingface SKIPPED A HF "version" is a git revision — a branch, a tag,
//	                    or an arbitrary commit SHA, all equally valid pins.
//	                    /api/models/{id}/refs enumerates branches and tags
//	                    but can never enumerate commits, so a 404 on a
//	                    revision cannot be told apart from "we pinned a SHA
//	                    this replica has not fetched yet". No honest
//	                    discriminator exists, so huggingface keeps the
//	                    generic not_found.

// packageProbe issues exactly ONE package-level request and reports what
// the registry said: the version list the document enumerated, the URL
// asked (for the warning message), and the RAW warning from the fetch —
// nil when the registry answered 200.
//
// THE WARNING, NOT A BARE bool, IS THE WHOLE OF P8-04. Every probe used
// to collapse its outcome to `ok bool`, so a package-level 404 ("this
// package does not exist upstream") and a 5xx ("the registry told us
// nothing") arrived at promoteVersionNotFound as the same value and both
// kept the generic not_found code. core/coverage classifies not_found as
// an OK code — a real answer, correctly — and risk_projection.go keys
// only on version_not_found, so neither the projection nor the
// fail-closed gate ever saw a difference. The result, verified against
// live registries: `rubygems colourama` → ALLOW 96 (A), `pypi
// requests-python` → ALLOW 92 (A). A textbook slopsquat graded A.
//
// Returning the warning keeps the two facts distinguishable without
// inventing a second vocabulary: the codes are the ones the fetch
// helpers already emit.
type packageProbe func(ctx context.Context) (published []string, endpoint string, warn *Warning)

// promoteVersionNotFound upgrades a per-version not_found into the
// version_not_found marker when — and only when — the package-level
// probe supplies positive evidence of absence.
//
// Any other warning is returned untouched and the probe is NOT called.
// That early return is the cost guarantee: on the success path (warn ==
// nil) and on every non-404 failure the provider issues the same
// requests it always did.
func (p *registryMetadataProvider) promoteVersionNotFound(ctx context.Context, ecosystem string, warn *Warning, versionEndpoint, pkg, ver string, probe packageProbe) *Warning {
	if warn == nil || warn.Code != "not_found" {
		return warn
	}
	published, probeEndpoint, probeWarn := probe(ctx)
	switch {
	case isDefiniteAbsence(probeWarn):
		// The PACKAGE does not exist in the registry we asked — the
		// per-version endpoint 404ed and so did the package-level
		// document.
		//
		// Whether that is a statement about the PACKAGE or only about
		// THIS REGISTRY depends on the ecosystem, and only the former
		// may be reported as an absent package. See the
		// single-canonical-registry rule above: for the Maven family and
		// for Go a repo1 / proxy.golang.org 404 means "not in the
		// registry we checked", which is the pre-P8-04 not_found, and
		// saying anything stronger mislabels 1,405 production Android
		// coordinates as names a model invented.
		if !ecosystemHasSingleCanonicalRegistry(ecosystem) {
			return warn
		}
		// Here the premise holds, and this is a different, stronger fact
		// than "that version was never published". Until P8-04 it was
		// reported as the generic not_found, which nothing downstream
		// consumes: the coordinate came back fully scored, with every
		// category at its 100 base, as a clean ALLOW. A hallucinated
		// package name is precisely the surface this product exists to
		// catch.
		//
		// It is a positive answer from the registry, not an outage, so
		// it is classified in core/coverage's okCodes alongside
		// not_found and version_not_found — the refusal that IS
		// warranted comes from the unknown verdict, not from the
		// coverage gate.
		return packageNotFoundWarning(p, versionEndpoint, probeEndpoint, pkg, ver)
	case probeWarn != nil:
		// The registry told us nothing at all — 5xx, timeout, transport
		// error, decode failure. Absence of evidence is not evidence of
		// absence: promoting an unanswered probe would convert every
		// registry hiccup, private mirror and replication lag into an
		// `unknown` verdict and a failed build.
		return warn
	case len(published) == 0:
		// A 200 that enumerated nothing is a partial document, not a
		// version list. This is the same guard the packument path
		// applies (see versionNotFoundWarning), and the reason NuGet's
		// paginating registration index is not the endpoint we probe.
		return warn
	case versionPublished(published, ver):
		// The registry does publish it, so the per-version 404 came from
		// URL formatting or replication skew rather than from the
		// version being invented.
		return warn
	}
	return versionNotFoundByProbeWarning(p, versionEndpoint, probeEndpoint, pkg, ver, len(published))
}

// -- The single-canonical-registry rule (P8-04 correction) ------------
//
// A 404 from ONE registry only proves that a package does not exist when
// the ecosystem HAS one canonical registry. That premise is true for npm,
// PyPI, crates.io, RubyGems, NuGet, Packagist, pub.dev and the CocoaPods
// trunk: the bare coordinate `left-pad` MEANS registry.npmjs.org's
// `left-pad`, so if that registry says no such package, there is no such
// package to speak of.
//
// It is FALSE for the Maven family and for Go, and shipping it as though
// it were universal was a defect measured against production: 1,405 of the
// 1,699 registrymetadata `not_found` rows in the 2026-08-25 export are
// real Android/AndroidX coordinates — `androidx.*`, `com.android.tools.*`
// — which are published to Google's Maven repository and are simply not
// in repo1. Verified by hand:
//
//	repo1.maven.org   androidx/work/work-runtime/maven-metadata.xml -> 404
//	maven.google.com  androidx/work/work-runtime/maven-metadata.xml -> 301
//
// Under the unrestricted rule `androidx.work:work-runtime@2.11.2` — a real,
// ubiquitous dependency — was told its name may have been "invented by a
// model rather than published". That is a REGISTRY-COVERAGE GAP wearing the
// costume of a slopsquat finding, and an operator who sees it once stops
// believing the marker at all.
//
// So the marker is restricted to the ecosystems whose premise holds. The
// excluded ones keep the pre-P8-04 `not_found`, which is the honest code:
// "not found in the registry we checked".
//
//	maven, gradle  a groupId is a NAMESPACE, not a registry pointer.
//	               Coordinates legitimately live in Maven Central,
//	               maven.google.com, JitPack and corporate Nexus /
//	               Artifactory instances. repo1 is one of several homes,
//	               so its 404 is a statement about repo1.
//	go             the module PATH is the identity and proxy.golang.org is
//	               a cache of public VCS, not a namespace owner. GOPRIVATE
//	               and a direct GOPROXY are first-class in the toolchain,
//	               so a private or vanity module 404s on the public proxy
//	               while existing perfectly well. Production agrees: every
//	               go `not_found` row in the export is an `example.com/...`
//	               module path, i.e. exactly the shape that would be
//	               mislabelled.
//	docker         a coordinate names its own registry; Docker Hub is one
//	               of many. Already outside this path — runDocker handles
//	               its evidence pair inline and mints only
//	               version_not_found.
//	huggingface    already excluded upstream: a revision 404 cannot be told
//	               apart from a commit SHA this replica has not fetched.
//
// This does NOT weaken the detection P8-04 exists for. The slopsquat
// surface — `npm leftpadd`, `pypi colourama`, `pub htttp`,
// `pub flutter_secure_strorage` — is entirely inside the included set, and
// TestSlopsquatCoordinatesStillReachUnknown pins those four coordinates.
//
// SEPARATE QUESTION, deliberately NOT answered here: whether the provider
// should also query maven.google.com for `androidx.*` / `com.android.*`.
// That would be a real coverage gain, but it adds an outbound registry and
// moves verdicts in the LOOSENING direction, so it needs its own decision
// and its own measurement.
var singleCanonicalRegistryEcosystems = map[string]struct{}{
	"npm": {}, "yarn": {}, "bun": {},
	"pypi": {}, "pip": {},
	"cargo":     {},
	"rubygems":  {},
	"nuget":     {},
	"composer":  {},
	"cocoapods": {},
	"pub":       {},
}

// ecosystemHasSingleCanonicalRegistry reports whether a 404 from the one
// registry this provider asks is evidence that the PACKAGE does not exist,
// as opposed to evidence that it is not in the registry we happened to ask.
//
// Unknown ecosystems answer false. The map is an ALLOWLIST for the same
// reason isDefiniteAbsence is: the default for anything added later must be
// the pre-P8-04 `not_found`, never a claim that a real package was invented
// by a model.
func ecosystemHasSingleCanonicalRegistry(ecosystem string) bool {
	_, ok := singleCanonicalRegistryEcosystems[normalizeEcosystemKey(ecosystem)]
	return ok
}

// isDefiniteAbsence reports whether a package-level probe warning is
// POSITIVE evidence that the package does not exist upstream, as opposed
// to evidence that we could not reach the registry.
//
// The allowlist is deliberately narrow and deliberately an ALLOWLIST. Only
// a 404 is an answer. Every other failure the fetch helpers can produce —
// http_5xx, http_403, transport, decode, context_cancelled,
// registry_fetch_exhausted_retries — is silence, and silence must keep
// today's behaviour. A denylist would mean any code added later defaults
// to "the package does not exist", which is the direction that breaks
// builds.
//
// nil means the registry answered 200 and is NOT absence; that case is
// handled by the version-list arms of promoteVersionNotFound.
func isDefiniteAbsence(w *Warning) bool {
	if w == nil {
		return false
	}
	switch w.Code {
	case "not_found", "http_404":
		return true
	}
	return false
}

// packageNotFoundWarning builds the WarnPackageNotFound marker: the
// per-version endpoint 404ed AND the package-level document 404ed.
//
// The message names BOTH endpoints because the finding IS the pair — one
// 404 alone is ambiguous, and an operator reading the report has to be
// able to check the same two URLs we did. No version count: there is no
// version list, and printing 0 would read as "enumerated an empty list",
// the shape versionNotFoundWarning documents as a bug rather than a
// finding.
func packageNotFoundWarning(p *registryMetadataProvider, versionEndpoint, probeEndpoint, pkg, ver string) *Warning {
	return &Warning{
		Provider: "registrymetadata",
		Code:     WarnPackageNotFound,
		Message: fmt.Sprintf("endpoint=%s package=%s version=%s packageEndpoint=%s",
			versionEndpoint, pkg, ver, probeEndpoint),
		At: p.now(),
	}
}

// promotePackagumentNotFound upgrades the generic `not_found` produced by
// a PACKAGE-LEVEL document fetch into WarnPackageNotFound (P8-04).
//
// The packument ecosystems (npm, composer, cocoapods, pub) need no
// second probe the way the per-version ecosystems do: the document they
// fetch IS the package object, so a 404 on it is definitionally "no such
// package" rather than "no such version". They were nonetheless left on
// the generic not_found, which the projection never consumes and
// core/coverage classifies as OK — so a package name that does not exist
// anywhere came back fully scored with every category at its 100 base.
//
// SAME EVIDENCE STANDARD as the Group-A probe: only a 404. A 5xx, an auth
// wall, a timeout or a decode failure keeps today's behaviour, because
// those say nothing about whether the package exists. isDefiniteAbsence
// is the single shared allowlist.
//
// Returns warn unchanged when it is not a definite absence, so the call
// sites stay one line.
func promotePackagumentNotFound(p *registryMetadataProvider, ecosystem string, warn *Warning, endpoint, pkg, ver string) *Warning {
	if !isDefiniteAbsence(warn) {
		return warn
	}
	// Same restriction the Group-A path applies, for the same reason: a
	// 404 from one registry is only evidence about the PACKAGE when the
	// ecosystem has one canonical registry. Every ecosystem on this path
	// does today; the gate is here so that adding one which does not
	// cannot silently inherit the stronger claim.
	if !ecosystemHasSingleCanonicalRegistry(ecosystem) {
		return warn
	}
	// One endpoint, named twice, because the message shape is shared with
	// the Group-A marker and an operator re-running the check by hand
	// should see exactly the URL we asked.
	return packageNotFoundWarning(p, endpoint, endpoint, pkg, ver)
}

// versionNotFoundByProbeWarning builds the marker for the Group A
// (per-version endpoint) path. Same Code as versionNotFoundWarning —
// risk_projection.go and core/coverage's okCodes both key off it — but
// the message names BOTH halves of the evidence, because here the
// finding IS the pair: the per-version endpoint that 404ed and the
// package-level endpoint that did not.
//
// published < 0 means the package-level endpoint proved existence
// without enumerating versions (Docker Hub's repository object is the
// only such probe). The count is then omitted rather than printed as 0,
// so an operator can never read it as "enumerated an empty list" — the
// shape versionNotFoundWarning documents as a bug rather than a finding.
func versionNotFoundByProbeWarning(p *registryMetadataProvider, versionEndpoint, probeEndpoint, pkg, ver string, published int) *Warning {
	msg := fmt.Sprintf("endpoint=%s package=%s version=%s packageEndpoint=%s",
		versionEndpoint, pkg, ver, probeEndpoint)
	if published >= 0 {
		msg = fmt.Sprintf("%s publishedVersions=%d", msg, published)
	}
	return &Warning{
		Provider: "registrymetadata",
		Code:     WarnVersionNotFound,
		Message:  msg,
		At:       p.now(),
	}
}

// timelineVersions flattens a VersionRelease list to bare version
// strings, which is what lets the existing per-ecosystem timeline
// fetchers double as package-level probes instead of this file growing a
// second copy of every registry URL.
func timelineVersions(timeline []VersionRelease) []string {
	out := make([]string, 0, len(timeline))
	for _, r := range timeline {
		if s := strings.TrimSpace(r.Version); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// versionPublished is versionListed widened by a trailing-zero
// tolerance. It is used ONLY to SUPPRESS the marker, never to produce
// one, so widening it can only ever cost a finding — it can never
// manufacture a false one.
//
// NuGet forces it: the registry normalises `1.0` to `1.0.0`, so a
// packages.config pin of `1.0` 404s on the per-version nuspec while the
// flat-container index lists `1.0.0`. A strict compare would call a
// perfectly real, widely-installed package a hallucination.
//
// Maven is the counter-example — there `1.0` and `1.0.0` are genuinely
// different artifacts — so on that ecosystem the tolerance can hide a
// real miss. The trade is deliberate and one-directional: a false
// negative costs one scored report, a false positive breaks a build.
func versionPublished(published []string, ver string) bool {
	if versionListed(published, ver) {
		return true
	}
	want := canonicalVersionKey(ver)
	if want == "" {
		return false
	}
	for _, cand := range published {
		if canonicalVersionKey(cand) == want {
			return true
		}
	}
	return false
}

// canonicalVersionKey reduces a version to a comparison key: lower-cased,
// `v` prefix dropped, `+build` metadata dropped, and trailing zero
// components trimmed off the numeric core so 1.0 == 1.0.0 == 1.0.0.0.
// The pre-release suffix is preserved verbatim — 1.0.0-rc1 and 1.0.0 are
// different releases and must not collapse into each other.
func canonicalVersionKey(ver string) string {
	s := strings.ToLower(strings.TrimSpace(ver))
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return ""
	}
	core, suffix := s, ""
	if i := strings.IndexByte(s, '-'); i >= 0 {
		core, suffix = s[:i], s[i:]
	}
	parts := strings.Split(core, ".")
	for len(parts) > 1 && parts[len(parts)-1] == "0" {
		parts = parts[:len(parts)-1]
	}
	return strings.Join(parts, ".") + suffix
}

// probePyPIPackage reuses the project-level packument the success path
// already fetches for the version timeline, so the probe adds no new URL
// shape to maintain.
func (p *registryMetadataProvider) probePyPIPackage(pkg string) packageProbe {
	return func(ctx context.Context) ([]string, string, *Warning) {
		doc := p.fetchPyPITimelineDoc(ctx, pkg)
		return timelineVersions(doc.timeline), doc.endpoint, doc.probeWarning()
	}
}

// probeMavenPackage asks the artifact-level maven-metadata.xml, which
// every Maven repository publishes next to the version directories and
// which carries the canonical <versions> list. Maven has no package
// object of any other kind.
func (p *registryMetadataProvider) probeMavenPackage(groupPath, artifact string) packageProbe {
	return func(ctx context.Context) ([]string, string, *Warning) {
		doc := p.fetchMavenTimelineDoc(ctx, groupPath, artifact)
		return timelineVersions(doc.timeline), doc.endpoint, doc.probeWarning()
	}
}

func (p *registryMetadataProvider) probeCargoPackage(pkg string) packageProbe {
	return func(ctx context.Context) ([]string, string, *Warning) {
		doc := p.fetchCargoTimelineDoc(ctx, pkg)
		return timelineVersions(doc.timeline), doc.endpoint, doc.probeWarning()
	}
}

func (p *registryMetadataProvider) probeRubyGemsPackage(pkg string) packageProbe {
	return func(ctx context.Context) ([]string, string, *Warning) {
		doc := p.fetchRubyGemsTimelineDoc(ctx, pkg)
		return timelineVersions(doc.timeline), doc.endpoint, doc.probeWarning()
	}
}

// probeNuGetPackage asks the FLAT CONTAINER package index rather than
// the registration index fetchNuGetTimeline reads. The flat container
// returns the complete, unpaginated version list in a single document;
// the registration index paginates and this file deliberately does not
// chase the page pointers, so on a popular package it yields an empty
// list — which promoteVersionNotFound would (correctly) refuse to act
// on, silently disabling the check exactly where it matters most.
func (p *registryMetadataProvider) probeNuGetPackage(pkg string) packageProbe {
	lower := strings.ToLower(pkg)
	return func(ctx context.Context) ([]string, string, *Warning) {
		endpoint := fmt.Sprintf("%s/%s/index.json", p.endpoints.nuget, url.PathEscape(lower))
		var idx struct {
			Versions []string `json:"versions"`
		}
		warn, err := p.fetchJSON(ctx, endpoint, "application/json", &idx)
		if err != nil && warn == nil {
			warn = &Warning{Provider: "registrymetadata", Code: "transport",
				Message: err.Error(), At: p.now()}
		}
		if warn != nil {
			return nil, endpoint, warn
		}
		return idx.Versions, endpoint, nil
	}
}

// probeGoModule asks the module proxy's `@v/list`, the only Group A
// package-level endpoint that answers text/plain.
//
// TWO CALLERS. The existence probe below (the 404 branch of runGo), and
// runGo's SUCCESS path, which routes the same list through applyTimeline
// so Go stops being the one major ecosystem with no version timeline.
// The paragraph below is about the FIRST caller; the second one carries
// its own note on why pseudo-version omission matters there.
//
// @v/list omits pseudo-versions, which costs nothing here: a real
// pseudo-version is served by @v/{ver}.info, so a coordinate that
// reached this branch already failed the authoritative lookup. A module
// the proxy knows only through pseudo-versions answers 200 with an empty
// body, and promoteVersionNotFound's empty-list guard keeps that case on
// the generic not_found.
func (p *registryMetadataProvider) probeGoModule(module string) packageProbe {
	return func(ctx context.Context) ([]string, string, *Warning) {
		endpoint := fmt.Sprintf("%s/%s/@v/list", p.endpoints.goproxy, module)
		lines, warn, err := p.fetchLines(ctx, endpoint)
		if err != nil && warn == nil {
			warn = &Warning{Provider: "registrymetadata", Code: "transport",
				Message: err.Error(), At: p.now()}
		}
		if warn != nil {
			return nil, endpoint, warn
		}
		return lines, endpoint, nil
	}
}

// timelineDoc is what a package-level registry document yielded: the
// version list, the registry's own "latest" label, the endpoint asked,
// and the RAW fetch outcome.
//
// It exists because two callers need the SAME fetch-and-parse and
// DIFFERENT failure reporting, and collapsing them is what produced
// P8-04:
//
//   - the version-timeline path wraps every failure as
//     timeline_fetch_failed. That is right there — the primary
//     per-version fetch already succeeded, so a failed timeline is
//     recoverable and the code says "we are missing version history",
//     which core/coverage reads as an outage.
//   - the package-level EXISTENCE probe must tell a definite 404 ("this
//     package does not exist upstream") apart from a 5xx or a timeout
//     ("the registry told us nothing"). Those are opposite facts and
//     timeline_fetch_failed erases the difference.
//
// The raw warning is kept unwrapped here and wrapped by wrapped() at the
// timeline call sites, so neither caller can silently inherit the other's
// classification.
type timelineDoc struct {
	timeline    []VersionRelease
	latest      string
	lastUpdated time.Time
	endpoint    string
	// warn is the RAW warning from the fetch helpers — "not_found",
	// "http_503", "transport", "decode", … — or nil on a 200.
	warn *Warning
	err  error
}

// ok reports whether the registry answered with a document we parsed.
func (d timelineDoc) ok() bool { return d.warn == nil && d.err == nil }

// wrapped renders the fetch outcome the way the TIMELINE path reports it.
// Returns nil when the fetch succeeded.
func (d timelineDoc) wrapped(p *registryMetadataProvider) *Warning {
	if d.ok() {
		return nil
	}
	return timelineFetchFailedWarning(p, d.endpoint, d.err, d.warn)
}

// probeWarning renders the fetch outcome the way the EXISTENCE-PROBE path
// reports it: the raw warning, unwrapped, so isDefiniteAbsence can tell a
// 404 from an outage. A transport error that produced no warning is given
// one, because "no warning and no document" must not read as a 200.
func (d timelineDoc) probeWarning() *Warning {
	if d.warn != nil {
		return d.warn
	}
	if d.err != nil {
		return &Warning{Provider: "registrymetadata", Code: "transport", Message: d.err.Error()}
	}
	return nil
}

// timelineFetchFailedWarning builds a stable-code Warning for the
// secondary timeline fetch. Distinct code so dashboards can separate
// "couldn't load the primary packument" from "couldn't load the
// timeline endpoint" — the latter is recoverable (we still have all
// the per-version data, just missing version history).
func timelineFetchFailedWarning(p *registryMetadataProvider, endpoint string, err error, upstream *Warning) *Warning {
	w := &Warning{
		Provider: "registrymetadata",
		Code:     "timeline_fetch_failed",
		At:       p.now(),
	}
	switch {
	case upstream != nil && upstream.Message != "":
		w.Message = fmt.Sprintf("endpoint=%s upstream=%s err=%s", endpoint, upstream.Code, upstream.Message)
	case upstream != nil:
		w.Message = fmt.Sprintf("endpoint=%s upstream=%s", endpoint, upstream.Code)
	case err != nil:
		w.Message = fmt.Sprintf("endpoint=%s err=%s", endpoint, err.Error())
	default:
		w.Message = fmt.Sprintf("endpoint=%s", endpoint)
	}
	return w
}

// applyTimeline merges a non-empty timeline + latest version label into
// the partial report, computing FirstPublishedAt from the earliest
// known PublishedAt. Callers pass tlWarn=nil on success; a non-nil
// warning is appended verbatim.
func applyTimeline(pr *PartialReport, timeline []VersionRelease, latest string, tlWarn *Warning) {
	if tlWarn != nil {
		pr.Warnings = append(pr.Warnings, *tlWarn)
		return
	}
	if len(timeline) == 0 {
		return
	}
	// Sort by published time (ascending), keeping zero-time entries at
	// the end. Deterministic ordering helps downstream consumers and
	// makes the JSON snapshot reproducible.
	sort.SliceStable(timeline, func(i, j int) bool {
		ti, tj := timeline[i].PublishedAt, timeline[j].PublishedAt
		switch {
		case ti.IsZero() && tj.IsZero():
			return timeline[i].Version < timeline[j].Version
		case ti.IsZero():
			return false
		case tj.IsZero():
			return true
		default:
			return ti.Before(tj)
		}
	})
	if pr.Maintenance == nil {
		pr.Maintenance = &MaintenanceSection{}
	}
	pr.Maintenance.VersionTimeline = timeline
	// First non-zero publish time wins after the sort above.
	for i := range timeline {
		if !timeline[i].PublishedAt.IsZero() {
			t := timeline[i].PublishedAt
			pr.Maintenance.FirstPublishedAt = &t
			break
		}
	}
	if latest != "" {
		if pr.Release == nil {
			pr.Release = &ReleaseSection{}
		}
		if pr.Release.LatestVersion == "" {
			pr.Release.LatestVersion = latest
		}
	}
}

// -- GitHub repo metadata --------------------------------------------

// enrichRepoStars populates Stars/Forks/OpenIssues/Subscribers on
// pr.Maintenance by dispatching to the per-forge fetcher matching the
// source-repo URL host. No-op for unrecognized hosts, missing URLs, or
// fetch failures (a Warning is appended in the failure case so operators
// can tell the difference between "no data" and "fetch errored").
//
// Supported forges:
//   - github.com    → fetchGitHubRepoMeta (stars, forks, issues, subscribers)
//   - gitlab.com    → fetchGitLabRepoMeta (stars, forks, issues; no subscribers)
//   - bitbucket.org → fetchBitbucketRepoMeta (forks + watchers proxy for
//     subscribers; Bitbucket Cloud has no public star count, so Stars
//     stays at 0)
//   - codeberg.org  → fetchCodebergRepoMeta (Gitea v1: stars, forks, issues,
//     subscribers via watchers)
//
// Anything else is a silent no-op, matching the pre-multi-forge behavior
// where only GitHub was probed.
func enrichRepoStars(ctx context.Context, p *registryMetadataProvider, pr *PartialReport) {
	if pr.URLs == nil {
		return
	}
	raw := pr.URLs.SourceRepoURL
	if raw == "" {
		return
	}
	if owner, repo, ok := parseGitHubRepo(raw); ok {
		meta, warn := p.fetchGitHubRepoMeta(ctx, owner, repo)
		applyRepoMeta(pr, meta, warn)
		return
	}
	forge, owner, repo, ok := parseForgeRepo(raw)
	if !ok {
		return
	}
	var (
		meta *gitHubRepoMeta
		warn *Warning
	)
	switch forge {
	case "gitlab":
		meta, warn = p.fetchGitLabRepoMeta(ctx, owner, repo)
	case "bitbucket":
		meta, warn = p.fetchBitbucketRepoMeta(ctx, owner, repo)
	case "codeberg":
		meta, warn = p.fetchCodebergRepoMeta(ctx, owner, repo)
	default:
		return
	}
	applyRepoMeta(pr, meta, warn)
}

// applyRepoMeta is the shared write-back tail used by every forge
// fetcher. Centralising the nil checks keeps the dispatch above tidy.
func applyRepoMeta(pr *PartialReport, meta *gitHubRepoMeta, warn *Warning) {
	if warn != nil {
		pr.Warnings = append(pr.Warnings, *warn)
		return
	}
	if meta == nil {
		return
	}
	if pr.Maintenance == nil {
		pr.Maintenance = &MaintenanceSection{}
	}
	pr.Maintenance.Stars = meta.Stars
	pr.Maintenance.Forks = meta.Forks
	pr.Maintenance.OpenIssues = meta.OpenIssues
	pr.Maintenance.Subscribers = meta.Subscribers
}

// parseForgeRepo recognises the non-GitHub public forges we can probe
// by API: gitlab.com (incl. nested groups), bitbucket.org, codeberg.org.
// Mirrors the shape of parseGitHubRepo so the dispatch above can rely on
// a single helper. Returns ok=false for unknown hosts (including
// self-hosted Gitea — upstream auth posture is unknown, so we
// deliberately stay quiet).
func parseForgeRepo(raw string) (forge, owner, repo string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", "", false
	}
	for _, host := range []string{"gitlab.com", "bitbucket.org", "codeberg.org"} {
		if strings.HasPrefix(s, "git@"+host+":") {
			s = "https://" + host + "/" + strings.TrimPrefix(s, "git@"+host+":")
		}
	}
	s = strings.TrimPrefix(s, "git+")
	u, err := url.Parse(s)
	if err != nil {
		return "", "", "", false
	}
	host := strings.ToLower(u.Host)
	host = strings.TrimPrefix(host, "www.")
	var f string
	switch host {
	case "gitlab.com":
		f = "gitlab"
	case "bitbucket.org":
		f = "bitbucket"
	case "codeberg.org":
		f = "codeberg"
	default:
		return "", "", "", false
	}
	path := strings.TrimPrefix(u.Path, "/")
	if f == "gitlab" {
		if i := strings.Index(path, "/-/"); i >= 0 {
			path = path[:i]
		}
	}
	path = strings.TrimSuffix(path, "/")
	path = strings.TrimSuffix(path, ".git")
	if path == "" {
		return "", "", "", false
	}
	parts := strings.Split(path, "/")
	if f == "gitlab" {
		if len(parts) < 2 {
			return "", "", "", false
		}
		repo = strings.TrimSuffix(parts[len(parts)-1], ".git")
		owner = strings.Join(parts[:len(parts)-1], "/")
	} else {
		if len(parts) < 2 {
			return "", "", "", false
		}
		owner = parts[0]
		repo = strings.TrimSuffix(parts[1], ".git")
	}
	if owner == "" || repo == "" {
		return "", "", "", false
	}
	return f, owner, repo, true
}

// parseGitHubRepo extracts the (owner, repo) pair from a github.com URL
// in any of the common shapes:
//
//	https://github.com/owner/repo
//	https://github.com/owner/repo.git
//	https://github.com/owner/repo/tree/main/path
//	git@github.com:owner/repo.git
//
// Returns ok=false for non-GitHub URLs or malformed inputs.
func parseGitHubRepo(raw string) (owner, repo string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", false
	}
	// Normalise the scp-like SSH form.
	if strings.HasPrefix(s, "git@github.com:") {
		s = "https://github.com/" + strings.TrimPrefix(s, "git@github.com:")
	}
	// Strip any "git+" prefix and ".git" suffix the maintainers tacked on.
	s = strings.TrimPrefix(s, "git+")
	u, err := url.Parse(s)
	if err != nil {
		return "", "", false
	}
	host := strings.ToLower(u.Host)
	if host != "github.com" && host != "www.github.com" {
		return "", "", false
	}
	path := strings.TrimPrefix(u.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return "", "", false
	}
	owner = parts[0]
	repo = strings.TrimSuffix(parts[1], ".git")
	if owner == "" || repo == "" {
		return "", "", false
	}
	return owner, repo, true
}

// gitHubRepoMeta is the subset of the GitHub repo response we surface.
type gitHubRepoMeta struct {
	Stars       int
	Forks       int
	OpenIssues  int
	Subscribers int
}

// fetchGitHubRepoMeta issues ONE call to api.github.com/repos/{owner}/{repo}
// to grab the activity counts. Honors CHAINSAW_GITHUB_TOKEN for higher
// rate limits. Returns (nil, nil) silently on 404 (repo deleted /
// renamed) and (nil, warning) on transport / rate-limit failures.
func (p *registryMetadataProvider) fetchGitHubRepoMeta(ctx context.Context, owner, repo string) (*gitHubRepoMeta, *Warning) {
	endpoint := fmt.Sprintf("%s/repos/%s/%s",
		p.endpoints.github,
		url.PathEscape(owner),
		url.PathEscape(repo))
	var body struct {
		StargazersCount int `json:"stargazers_count"`
		ForksCount      int `json:"forks_count"`
		OpenIssuesCount int `json:"open_issues_count"`
		SubscribersCnt  int `json:"subscribers_count"`
		Watchers        int `json:"watchers_count"`
	}
	// Build the request directly so we can inject the Authorization
	// header when CHAINSAW_GITHUB_TOKEN is set.
	warn := p.doGitHubFetch(ctx, endpoint, &body)
	if warn != nil {
		// 404 here means "repo not found" — leave fields at zero, no
		// surfacing of a confusing warning. fetch helpers already
		// downgraded transient failures to a Warning we pass through.
		if warn.Code == "not_found" {
			return nil, nil
		}
		return nil, &Warning{
			Provider: "registrymetadata",
			Code:     "github_meta_fetch_failed",
			Message:  warn.Message,
			At:       p.now(),
		}
	}
	subs := body.SubscribersCnt
	if subs == 0 {
		subs = body.Watchers
	}
	return &gitHubRepoMeta{
		Stars:       body.StargazersCount,
		Forks:       body.ForksCount,
		OpenIssues:  body.OpenIssuesCount,
		Subscribers: subs,
	}, nil
}

// doGitHubFetch is a thin wrapper that issues GET against the GitHub
// API. Attaches the CHAINSAW_GITHUB_TOKEN bearer when present. Kept
// separate from fetchJSON so (a) the registry-metadata transport stays
// auth-free for every other ecosystem and (b) we can retry once on 403
// / 429 to soak up transient rate-limit fluctuations on the
// unauthenticated path — anonymous GitHub gives ~60 req/hour per IP,
// which a single scan of a moderately large lockfile will exhaust in
// the worst case. The retry is bounded (one extra attempt after a
// short backoff) so a hard rate-limit doesn't double our latency
// budget.
func (p *registryMetadataProvider) doGitHubFetch(ctx context.Context, endpoint string, out any) *Warning {
	token := strings.TrimSpace(os.Getenv("CHAINSAW_GITHUB_TOKEN"))
	var lastWarn *Warning
	for attempt := 0; attempt < 2; attempt++ {
		if err := ctx.Err(); err != nil {
			return &Warning{Provider: "registrymetadata", Code: "context_cancelled", Message: err.Error(), At: p.now()}
		}
		w := p.gitHubFetchOnce(ctx, endpoint, token, out)
		if w == nil {
			return nil
		}
		// Retry once on the anonymous-rate-limit codes; everything else
		// (404, 5xx already drained by fetchJSON's own retry loop,
		// transport errors that exhausted that loop's budget) is
		// returned as-is.
		if w.Code == "http_403" || w.Code == "http_429" {
			lastWarn = w
			if attempt == 0 {
				// Short jittered backoff. We deliberately stay small —
				// GitHub's rate-limit reset is hourly, so a long sleep
				// won't materially change the outcome. The retry exists
				// to clear transient/per-second secondary limits, not
				// the primary anonymous bucket.
				delay := time.Duration(float64(500*time.Millisecond) * jitterFactor())
				t := time.NewTimer(delay)
				select {
				case <-t.C:
				case <-ctx.Done():
					t.Stop()
					return &Warning{Provider: "registrymetadata", Code: "context_cancelled", Message: ctx.Err().Error(), At: p.now()}
				}
				continue
			}
		}
		return w
	}
	return lastWarn
}

// gitHubFetchOnce performs a single attempt against the GitHub API.
// When token=="" we delegate to fetchJSON so we inherit its 5xx /
// transient-error retry loop; when a token is present we issue the
// request inline so we can attach the Authorization header (fetchJSON
// doesn't expose header customisation).
func (p *registryMetadataProvider) gitHubFetchOnce(ctx context.Context, endpoint, token string, out any) *Warning {
	if token == "" {
		warn, _ := p.fetchJSON(ctx, endpoint, "application/vnd.github+json", out)
		return warn
	}
	perAttempt := ecosystemTimeout(ctx)
	attemptCtx, cancel := context.WithTimeout(ctx, perAttempt)
	defer cancel()
	req, err := http.NewRequestWithContext(attemptCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return &Warning{Provider: "registrymetadata", Code: "request_build", Message: err.Error(), At: p.now()}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "chainsaw-intelligence/1")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := p.client.Do(req)
	if err != nil {
		return &Warning{Provider: "registrymetadata", Code: "transport", Message: err.Error(), At: p.now()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return &Warning{Provider: "registrymetadata", Code: WarnRegistryNotFound, Message: endpoint, At: p.now()}
	}
	if resp.StatusCode >= 400 {
		return &Warning{Provider: "registrymetadata", Code: fmt.Sprintf("http_%d", resp.StatusCode), Message: endpoint, At: p.now()}
	}
	limited := &io.LimitedReader{R: resp.Body, N: 1 << 20}
	dec := json.NewDecoder(limited)
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return &Warning{Provider: "registrymetadata", Code: "decode", Message: err.Error(), At: p.now()}
	}
	return nil
}

// -- GitLab / Bitbucket / Codeberg repo metadata ---------------------

// isFetchNotFoundWarn reports whether a Warning returned by fetchJSON
// represents a deterministic "missing" response (404 / not_found). The
// per-forge fetchers use this to translate a 404 into a silent no-op
// — matching the GitHub fetcher's behavior where a deleted/renamed
// repo leaves stars at zero without surfacing a confusing warning.
func isFetchNotFoundWarn(w *Warning) bool {
	if w == nil {
		return false
	}
	switch w.Code {
	case "not_found", "http_404":
		return true
	}
	return false
}

// fetchGitLabRepoMeta queries the GitLab v4 projects API:
//
//	GET /api/v4/projects/{namespace%2Frepo}
//
// The path is URL-escaped because GitLab requires the encoded slash.
// Fail-soft on 4xx / transport / decode so a missing or private project
// stays quiet — downstream signals that require a star count simply
// won't observe one.
//
// GitLab does not expose a subscribers / watchers count on the v4
// project resource, so Subscribers stays at zero (a known limitation,
// not a bug).
func (p *registryMetadataProvider) fetchGitLabRepoMeta(ctx context.Context, owner, repo string) (*gitHubRepoMeta, *Warning) {
	id := url.PathEscape(owner + "/" + repo)
	endpoint := fmt.Sprintf("%s/api/v4/projects/%s", p.endpoints.gitlab, id)
	var body struct {
		StarCount     int `json:"star_count"`
		ForksCount    int `json:"forks_count"`
		OpenIssuesCnt int `json:"open_issues_count"`
	}
	warn, _ := p.fetchJSON(ctx, endpoint, "application/json", &body)
	if warn != nil {
		if isFetchNotFoundWarn(warn) {
			return nil, nil
		}
		return nil, &Warning{
			Provider: "registrymetadata",
			Code:     "gitlab_meta_fetch_failed",
			Message:  warn.Message,
			At:       p.now(),
		}
	}
	return &gitHubRepoMeta{
		Stars:      body.StarCount,
		Forks:      body.ForksCount,
		OpenIssues: body.OpenIssuesCnt,
	}, nil
}

// fetchBitbucketRepoMeta queries the Bitbucket Cloud v2 repositories
// resource:
//
//	GET /2.0/repositories/{workspace}/{repo}
//
// Bitbucket Cloud does NOT expose a public star count — there is no
// `stargazers_count` analogue on the cloud product. We surface forks
// (inline on the resource) and use the watchers count as the
// Subscribers proxy when present. Stars stays at zero on every
// Bitbucket repo — a deliberate fail-closed for downstream signals that
// require a star count.
func (p *registryMetadataProvider) fetchBitbucketRepoMeta(ctx context.Context, owner, repo string) (*gitHubRepoMeta, *Warning) {
	endpoint := fmt.Sprintf("%s/2.0/repositories/%s/%s",
		p.endpoints.bitbucket,
		url.PathEscape(owner),
		url.PathEscape(repo))
	var body struct {
		ForksCount    int `json:"forks_count"`
		WatchersCount int `json:"watchers_count"`
	}
	warn, _ := p.fetchJSON(ctx, endpoint, "application/json", &body)
	if warn != nil {
		if isFetchNotFoundWarn(warn) {
			return nil, nil
		}
		return nil, &Warning{
			Provider: "registrymetadata",
			Code:     "bitbucket_meta_fetch_failed",
			Message:  warn.Message,
			At:       p.now(),
		}
	}
	return &gitHubRepoMeta{
		// Stars: 0 — Bitbucket Cloud has no public star count.
		Forks:       body.ForksCount,
		Subscribers: body.WatchersCount,
	}, nil
}

// fetchCodebergRepoMeta queries the Codeberg (Gitea-API) v1 repos
// resource:
//
//	GET /api/v1/repos/{owner}/{repo}
//
// Gitea exposes `stars_count`, `forks_count`, `open_issues_count` and
// `watchers_count` on the same payload, so a single request hydrates
// every Maintenance field.
func (p *registryMetadataProvider) fetchCodebergRepoMeta(ctx context.Context, owner, repo string) (*gitHubRepoMeta, *Warning) {
	endpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s",
		p.endpoints.codeberg,
		url.PathEscape(owner),
		url.PathEscape(repo))
	var body struct {
		StarsCount      int `json:"stars_count"`
		ForksCount      int `json:"forks_count"`
		OpenIssuesCount int `json:"open_issues_count"`
		WatchersCount   int `json:"watchers_count"`
	}
	warn, _ := p.fetchJSON(ctx, endpoint, "application/json", &body)
	if warn != nil {
		if isFetchNotFoundWarn(warn) {
			return nil, nil
		}
		return nil, &Warning{
			Provider: "registrymetadata",
			Code:     "codeberg_meta_fetch_failed",
			Message:  warn.Message,
			At:       p.now(),
		}
	}
	return &gitHubRepoMeta{
		Stars:       body.StarsCount,
		Forks:       body.ForksCount,
		OpenIssues:  body.OpenIssuesCount,
		Subscribers: body.WatchersCount,
	}, nil
}
