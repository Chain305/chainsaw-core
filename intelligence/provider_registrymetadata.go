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
	npm               string
	pypi              string
	maven             string
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
	_, ok := supportedRegistryEcosystems[strings.ToLower(ecosystem)]
	return ok
}

func (p *registryMetadataProvider) Run(ctx context.Context, req Request, _ *Report) (PartialReport, error) {
	pkg := strings.TrimSpace(req.Key.Package)
	ver := strings.TrimSpace(req.Key.Version)
	if pkg == "" || ver == "" {
		return PartialReport{}, nil
	}
	eco := strings.ToLower(req.Key.Ecosystem)
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
		return &Warning{Provider: "registrymetadata", Code: "not_found", Message: endpoint, At: p.now()}, false, resp.StatusCode, nil
	}
	if resp.StatusCode >= 500 {
		// Drain a small amount so the connection can be reused.
		_, _ = io.Copy(io.Discard, &io.LimitedReader{R: resp.Body, N: 4 << 10})
		return &Warning{Provider: "registrymetadata", Code: fmt.Sprintf("http_%d", resp.StatusCode), Message: endpoint, At: p.now()}, true, resp.StatusCode, nil
	}
	if resp.StatusCode >= 400 {
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
		pr.Warnings = append(pr.Warnings, *warn)
		return pr, nil
	}

	entry, hasEntry := pack.Versions[ver]
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
		return nil, "", timelineFetchFailedWarning(p, endpoint, err, warn)
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
	return timeline, strings.TrimSpace(pack.Info.Version), nil
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
	Parent      struct {
		GroupID string `xml:"groupId"`
		Version string `xml:"version"`
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
		pr.Warnings = append(pr.Warnings, *warn)
		return pr, nil
	}

	license := ""
	for _, l := range pom.Licenses.License {
		if s := strings.TrimSpace(l.Name); s != "" {
			license = s
			break
		}
	}

	people := &PeopleSection{}
	// Maven/Gradle POM `<developers>` is the canonical "people who
	// publish + maintain this artifact" list — Maven Central does not
	// distinguish authors from maintainers in metadata. Surface each
	// entry on both axes so the UI's People panel renders, and use the
	// email (or name when no email) as the publisher id since Sonatype
	// keys publisher accounts on the developer email.
	for _, d := range pom.Developers.Developer {
		s := joinAuthor(d.Name, d.Email)
		if s == "" {
			continue
		}
		people.Authors = append(people.Authors, s)
		people.Maintainers = append(people.Maintainers, s)
		if id := firstNonEmpty(strings.TrimSpace(d.Email), strings.TrimSpace(d.Name)); id != "" {
			people.PublisherIDs = append(people.PublisherIDs, id)
		}
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
	for _, dep := range pom.Dependencies.Dependency {
		if dep.GroupID == "" || dep.ArtifactID == "" {
			continue
		}
		ref := DependencyRef{
			Name:       dep.GroupID + ":" + dep.ArtifactID,
			Constraint: strings.TrimSpace(dep.Version),
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
	endpoint := fmt.Sprintf("%s/%s/%s/maven-metadata.xml", p.endpoints.maven, groupPath, artifact)
	var meta mavenMetadataXML
	warn, err := p.fetchXML(ctx, endpoint, &meta)
	if err != nil || warn != nil {
		return nil, "", time.Time{}, timelineFetchFailedWarning(p, endpoint, err, warn)
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
	return timeline, latest, lastUpdated, nil
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
		return nil, "", timelineFetchFailedWarning(p, endpoint, err, warn)
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
	return timeline, latest, nil
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
	endpoint := fmt.Sprintf("%s/api/v1/versions/%s.json", p.endpoints.rubygems, url.PathEscape(pkg))
	var versions []struct {
		Number     string `json:"number"`
		CreatedAt  string `json:"created_at"`
		Prerelease bool   `json:"prerelease"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &versions)
	if err != nil || warn != nil {
		return nil, "", timelineFetchFailedWarning(p, endpoint, err, warn)
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
	return timeline, latest, nil
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

func (p *registryMetadataProvider) runComposer(ctx context.Context, pkg, ver string) (PartialReport, error) {
	lower := strings.ToLower(pkg)
	endpoint := fmt.Sprintf("%s/p2/%s.json", p.endpoints.composer, lower)
	var pack struct {
		Packages map[string][]struct {
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
		} `json:"packages"`
	}
	warn, err := p.fetchJSON(ctx, endpoint, "application/json", &pack)
	if err != nil {
		return PartialReport{}, err
	}
	pr := PartialReport{}
	if warn != nil {
		pr.Warnings = append(pr.Warnings, *warn)
		return pr, nil
	}

	entries := pack.Packages[lower]
	if entries == nil {
		entries = pack.Packages[pkg]
	}
	if len(entries) == 0 {
		return PartialReport{}, nil
	}
	var match *struct {
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
	for i := range entries {
		if versionMatches(entries[i].Version, ver) {
			match = &entries[i]
			break
		}
	}
	if match == nil {
		return PartialReport{}, nil
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

func (p *registryMetadataProvider) runGo(ctx context.Context, pkg, ver string) (PartialReport, error) {
	module := encodeGoModulePath(strings.TrimSpace(pkg))
	if module == "" {
		return PartialReport{}, nil
	}
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
	modURL := fmt.Sprintf("%s/%s/@v/%s.mod", p.endpoints.goproxy, module, url.PathEscape(ver))
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
	endpoint := fmt.Sprintf("%s/v3/systems/go/packages/%s/versions/%s",
		p.endpoints.depsdev,
		url.PathEscape(strings.TrimSpace(pkg)),
		url.PathEscape(strings.TrimSpace(ver)))
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
		pr.Warnings = append(pr.Warnings, *warn)
		return pr, nil
	}

	release := &ReleaseSection{}
	for _, v := range pod.Versions {
		if v.Name == ver {
			if t, ok := parseTime(v.CreatedAt); ok {
				release.PublishedAt = &t
			}
			break
		}
	}
	if len(pod.Versions) > 0 {
		release.LatestVersion = pod.Versions[len(pod.Versions)-1].Name
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
		pr.Warnings = append(pr.Warnings, *warn)
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
	if !matched && strings.TrimSpace(doc.Latest.Version) == ver {
		if t, ok := parseTime(doc.Latest.Published); ok {
			release.PublishedAt = &t
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
	_, _ = p.fetchJSON(ctx, tagURL, "application/json", &tag)

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
	return pr, nil
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
		return &Warning{Provider: "registrymetadata", Code: "not_found", Message: endpoint, At: p.now()}
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
