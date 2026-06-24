package cli

// Local-first install guard (D1-R). Evaluates package install requests against
// LOCAL thin signals ONLY — no network, no server, nothing leaves the box.
// This is the offline core of the install-path wrapper: the trust-sensitive
// beachhead adopts it bottom-up without a security review because the default
// path sends nothing.
//
// Pipeline:
//
//   install args ──▶ parse specs ──▶ for each (eco, name, version):
//        │   (or expand a              ├─ malware.Lookup   (known-malicious floor + cache + bundle)
//        │    lockfile tree)           └─ typosquat.Check  (offline curated corpus)
//        ▼                            ──▶ verdict: BLOCK | WARN | ALLOW
//   real `npm`/`pip`/`go` runs only if nothing BLOCKs.
//
// Coverage today (honest):
//   - Typosquat: npm + PyPI (curated embedded corpora) + Go (fetcher embedded
//     seed), fully offline — the dominant install-time attack class.
//   - Known-malicious: an always-on embedded FLOOR (famous attacks), MERGED with
//     the optional `chainsaw guard update` cache (full OpenSSF set) and the
//     signal bundle's "osv-malware" blob when present — combined into one index.
//   - Fail-open with a visible notice when coverage is thin: a tool that breaks
//     `npm install` gets uninstalled, so we never hard-fail on missing signal.

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/intelligence"
	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/typosquat"
)

// npmPopularSeed is the offline typosquat corpus for npm. The upstream
// typosquat fetcher only carries a 1-entry npm static seed (the rest needs the
// network), so the wrapper ships its own curated list to stay offline-capable
// for the #1 ecosystem. Go/CocoaPods/pub use the fetcher's embedded seeds.
//
//go:embed seeds/npm_popular.txt
var npmPopularSeed []byte

//go:embed seeds/pypi_popular.txt
var pypiPopularSeed []byte

// knownMaliciousSeed is the offline known-malicious FLOOR — a curated set of the
// famous, well-documented supply-chain attacks (event-stream/flatmap-stream,
// ua-parser-js, node-ipc, the PyPI colorama/dateutil/jellyfish typosquat-malware).
// Version-exact so it never false-positives a clean release. The full
// OpenSSF malicious-packages DB is too large to embed; a signal bundle enriches
// this floor when present.
//
//go:embed seeds/known_malicious.json
var knownMaliciousSeed []byte

// guardDBEnv overrides the local known-malicious cache path (written by
// `chainsaw guard update`). Default: <user-cache>/chainsaw/known_malicious.json.
const guardDBEnv = "CHAINSAW_GUARD_DB"

func guardDBPath() string {
	if p := os.Getenv(guardDBEnv); p != "" {
		return p
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "chainsaw", "known_malicious.json")
}

// parseOSVArray decodes a known-malicious blob into OSV entries, accepting both
// a JSON array and NDJSON (one entry per line) so it works for the embedded
// floor, the `guard update` cache file, and the bundle's "osv-malware" blob.
func parseOSVArray(data []byte) []*malware.OSVEntry {
	if len(data) == 0 {
		return nil
	}
	var arr []*malware.OSVEntry
	if err := json.Unmarshal(data, &arr); err == nil && len(arr) > 0 {
		return arr
	}
	var out []*malware.OSVEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if e, err := malware.ParseOSVEntry([]byte(line)); err == nil {
			out = append(out, e)
		}
	}
	return out
}

// loadMalwareSources combines every available known-malicious source into ONE
// Load call (Index.Load replaces, so they must be merged, not loaded serially):
//  1. the embedded floor (always),
//  2. the local cache file written by `chainsaw guard update` (opt-in, offline),
//  3. the active signal bundle's "osv-malware" blob (if present).
//
// Returns (floor, extra) counts for the user-facing notice.
func loadMalwareSources(idx *malware.Index, bundle *intelligence.Bundle) (floor, extra int) {
	entries := parseOSVArray(knownMaliciousSeed)
	floor = len(entries)

	if path := guardDBPath(); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			more := parseOSVArray(data)
			entries = append(entries, more...)
			extra += len(more)
		}
	}
	if bundle != nil {
		if data := bundle.File("osv-malware"); len(data) > 0 {
			more := parseOSVArray(data)
			entries = append(entries, more...)
			extra += len(more)
		}
	}

	idx.Load(entries)
	return floor, extra
}

// parsePopularSeed turns a newline-delimited seed (blank lines + '#' comments
// skipped) into ranked popular packages.
func parsePopularSeed(data []byte) []typosquat.PopularPackage {
	var pkgs []typosquat.PopularPackage
	for _, line := range strings.Split(string(data), "\n") {
		name := strings.TrimSpace(line)
		if name == "" || strings.HasPrefix(name, "#") {
			continue
		}
		pkgs = append(pkgs, typosquat.PopularPackage{Name: name, Rank: len(pkgs) + 1})
	}
	return pkgs
}

// guardLogger silences the signal engines on the install hot path — the wrapper
// speaks to the user via its own concise notices, not slog INFO lines.
var guardLogger = slog.New(slog.DiscardHandler)

// popularCorpusLimit is how many popular packages to load per ecosystem for the
// typosquat index. The offline seeds are smaller than this; the fetcher returns
// whatever it has.
const popularCorpusLimit = 500

// offlineTransport makes the typosquat fetcher fail any network call instantly
// so corpus construction falls back to the embedded/static seed. The wrapper
// runs on the install hot path; it must never block on the network.
type offlineTransport struct{}

func (offlineTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("chainsaw guard: offline by design")
}

// packageSpec is one package the user is asking to install.
type packageSpec struct {
	Ecosystem string
	Name      string
	Version   string // "" when the user didn't pin one
}

func (s packageSpec) String() string {
	if s.Version == "" {
		return fmt.Sprintf("%s:%s", s.Ecosystem, s.Name)
	}
	return fmt.Sprintf("%s:%s@%s", s.Ecosystem, s.Name, s.Version)
}

// guardVerdict is the decision for one spec.
type guardVerdict struct {
	Spec     packageSpec
	Block    bool
	Severity string // "malicious" | "typosquat-high" | "typosquat-medium" | ""
	Reason   string
}

// localGuard holds the offline signal engines. Build once per invocation; the
// detectors are loaded lazily per ecosystem so a `go get` never pays for the
// npm corpus and vice-versa.
type localGuard struct {
	detectors map[string]*typosquat.Detector
	malware   *malware.Index
	bundle    *intelligence.Bundle
	notices   []string
}

// newLocalGuard wires the offline engines and collects coverage/staleness
// notices to surface once to the user.
func newLocalGuard() *localGuard {
	g := &localGuard{
		detectors: map[string]*typosquat.Detector{},
		malware:   malware.NewIndex(guardLogger),
	}

	// Combine every known-malicious source (embedded floor + local cache + bundle)
	// into one index.
	g.bundle = intelligence.ActiveBundle()
	floor, extra := loadMalwareSources(g.malware, g.bundle)
	if extra > 0 {
		g.notices = append(g.notices,
			fmt.Sprintf("known-malicious: %d-entry floor + %d enriched entries active", floor, extra))
		if g.bundle != nil && g.bundle.Stale() {
			g.notices = append(g.notices,
				fmt.Sprintf("signal bundle is %d days old — refresh with `chainsaw guard update`", int(g.bundle.Age().Hours()/24)))
		}
	} else {
		g.notices = append(g.notices,
			fmt.Sprintf("offline mode: %d-entry known-malicious floor + typosquat active; run `chainsaw guard update` for the full known-malicious set", floor))
	}

	return g
}

// detector returns the typosquat detector for an ecosystem, building it from the
// offline corpus on first use. A nil detector means we couldn't build a corpus
// (the caller treats that as "no typosquat coverage for this ecosystem").
func (g *localGuard) detector(ecosystem string) *typosquat.Detector {
	ecosystem = strings.ToLower(ecosystem)
	if d, ok := g.detectors[ecosystem]; ok {
		return d
	}

	var pkgs []typosquat.PopularPackage
	switch ecosystem {
	case "npm":
		// npm ships its own embedded corpus (the fetcher's npm seed is ~1 entry).
		pkgs = parsePopularSeed(npmPopularSeed)
	case "pip", "pypi":
		pkgs = parsePopularSeed(pypiPopularSeed)
	default:
		fetcher := typosquat.NewFetcher(guardLogger, typosquat.WithHTTPClient(&http.Client{
			Transport: offlineTransport{},
			Timeout:   2 * time.Second,
		}))
		// Background context is fine: the offline transport fails the network
		// call instantly, so FetchPopularPackages returns the embedded seed.
		pkgs, _ = fetcher.FetchPopularPackages(context.Background(), ecosystem, popularCorpusLimit)
	}
	if len(pkgs) == 0 {
		g.detectors[ecosystem] = nil
		return nil
	}
	d := typosquat.NewDetector(guardLogger)
	d.LoadEcosystem(ecosystem, pkgs)
	g.detectors[ecosystem] = d
	return d
}

// evaluate renders the local verdict for one spec. Block policy:
//   - known-malicious      → BLOCK (always)
//   - high-confidence typo → BLOCK
//   - medium-confidence    → WARN (pass; avoid breaking installs on lower signal)
func (g *localGuard) evaluate(ctx context.Context, spec packageSpec) guardVerdict {
	if res := g.malware.Lookup(ctx, spec.Ecosystem, spec.Name, spec.Version); res.IsKnownMalicious {
		reason := "known-malicious package"
		if res.MalwareID != "" {
			reason = fmt.Sprintf("known-malicious (%s)", res.MalwareID)
		}
		return guardVerdict{Spec: spec, Block: true, Severity: "malicious", Reason: reason}
	}

	if d := g.detector(spec.Ecosystem); d != nil {
		res := d.Check(ctx, spec.Ecosystem, spec.Name)
		if res.IsSuspected {
			reason := fmt.Sprintf("looks like a typosquat of %q (distance %d, %s)", res.SimilarTo, res.Distance, res.Method)
			switch res.Confidence {
			case "high":
				return guardVerdict{Spec: spec, Block: true, Severity: "typosquat-high", Reason: reason}
			case "medium":
				return guardVerdict{Spec: spec, Block: false, Severity: "typosquat-medium", Reason: reason}
			}
		}
	}

	return guardVerdict{Spec: spec, Block: false}
}

// evaluateAll runs every spec and returns the verdicts plus whether any blocks.
func (g *localGuard) evaluateAll(ctx context.Context, specs []packageSpec) (verdicts []guardVerdict, blocked bool) {
	verdicts = make([]guardVerdict, 0, len(specs))
	for _, s := range specs {
		v := g.evaluate(ctx, s)
		if v.Block {
			blocked = true
		}
		verdicts = append(verdicts, v)
	}
	return verdicts, blocked
}
