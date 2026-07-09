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

	"github.com/Masterminds/semver/v3"
	"github.com/chain305/chainsaw-core/intelligence"
	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/typosquat"
)

// npmPopularSeed is the offline typosquat corpus for npm: a generated,
// download-ranked top-5000 list (see tools/popular-corpus-gen — line order is
// rank). The upstream typosquat fetcher only carries a 1-entry npm static
// seed and its live path ranks by gameable keyword search, so the wrapper
// ships this reviewed data file to stay offline-capable and deterministic
// for the #1 ecosystem. Go/CocoaPods/pub use the fetcher's embedded seeds.
// A Sigstore-verified intelligence bundle ("typosquat" content key)
// overrides it as the between-releases refresh channel.
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

// loadMalwareSources combines every available known-malicious source into ONE
// Load call (Index.Load replaces, so they must be merged, not loaded serially):
//  1. the embedded floor (always),
//  2. the local cache file written by `chainsaw guard update` (opt-in, offline),
//  3. the active signal bundle's "osv-malware" blob (if present).
//
// Returns (floor, extra) counts for the user-facing notice.
func loadMalwareSources(idx *malware.Index, bundle *intelligence.Bundle) (floor, extra int) {
	entries := malware.ParseOSVBlob(knownMaliciousSeed)
	floor = len(entries)

	if path := guardDBPath(); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			more := malware.ParseOSVBlob(data)
			entries = append(entries, more...)
			extra += len(more)
		}
	}
	if bundle != nil {
		if data := bundle.File("osv-malware"); len(data) > 0 {
			more := malware.ParseOSVBlob(data)
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
// typosquat index on the FETCHER-backed ecosystems (go, cargo, cocoapods, …).
// npm and pypi don't consult it — their generated seed files load in full
// (see tools/popular-corpus-gen), and the seed size is the knob there.
const popularCorpusLimit = 500

// guardMaxRelativeDistance tightens the typosquat relative-distance ceiling
// for the guard below the package default (0.40). The 2026-07 incident's d=2
// class sat exactly at or above 0.40: katex↔knex (2/5 = 0.40, passing the
// strict-greater check at the boundary), vaul↔vue and jiti↔vite (0.50). At
// 0.35 those never match, with no corpus dependency. d≥2 was warn-only
// already, so the recall cost is warn-level, covered by the squat-recall
// regression suite.
const guardMaxRelativeDistance = 0.35

// guardTyposquatBlockRankCutoff is the popularity rank (1 = most downloaded)
// a typosquat TARGET must be at or above for a d=1 edit-distance hit to
// BLOCK rather than warn. Squatting pays in victim installs, so real attacks
// target the head of the distribution; a d=1 neighbour of a tail-rank name
// is usually two legitimate packages. 2500 is data-derived: every
// historically-squatted npm/PyPI target (lodash #101, express #262,
// cross-env #1931 in the generated corpus) sits inside it with margin.
// Homoglyph hits block regardless of rank — that evidence is byte-level.
const guardTyposquatBlockRankCutoff = 2500

// guardBundleCorpusFloor is the minimum entry count for a bundle-delivered
// popular corpus to be honored. Mirrors the fetcher's poisoning floor: a
// tiny corpus makes real popular packages look unpopular (and squattable),
// so a suspiciously small blob is treated as absent, not authoritative.
const guardBundleCorpusFloor = 500

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
	Severity string // "malicious" | "known-vulnerable" | "typosquat-high" | "typosquat-medium" | ""
	Reason   string
}

// localGuard holds the offline signal engines. Build once per invocation; the
// detectors are loaded lazily per ecosystem so a `go get` never pays for the
// npm corpus and vice-versa.
type localGuard struct {
	detectors map[string]*typosquat.Detector
	malware   *malware.Index
	bundle    *intelligence.Bundle
	fullFeed  bool
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
	g.fullFeed = extra > 0
	if extra > 0 {
		// Once enriched, the total is a number worth showing — it's the full
		// OpenSSF set, not the small embedded floor.
		g.notices = append(g.notices,
			fmt.Sprintf("offline known-malicious + typosquat active (%d malicious packages indexed)", floor+extra))
		if g.bundle != nil && g.bundle.Stale() {
			g.notices = append(g.notices,
				fmt.Sprintf("signal bundle is %d days old — refresh with `chainsaw guard update`", int(g.bundle.Age().Hours()/24)))
		}
	} else {
		// Default offline state: ship the embedded famous-attack floor. Don't
		// print the raw floor count on the install hot path — a small number
		// reads as a stub next to the block it just performed. `guard status`
		// still reports the exact count for anyone who wants it.
		g.notices = append(g.notices, guardUpdateNudge())
	}

	// Behavioral analysis is opt-in via a staged-artifact directory; surface it
	// so a block's provenance ("we read the bytes") is clear to the operator.
	if os.Getenv(guardArtifactDirEnv) != "" {
		g.notices = append(g.notices,
			"behavioral analysis active: scanning staged package artifacts offline")
	}
	// Deep mode waives the offline guarantee — say so loudly every run.
	if deepFetchEnabled() {
		g.notices = append(g.notices,
			"deep mode: fetching pinned package archives over the NETWORK for pre-install analysis (offline guarantee waived)")
	}
	if os.Getenv(guardArtifactDirEnv) == "" && !deepFetchEnabled() {
		g.notices = append(g.notices,
			"behavioral byte scan not run; using name/feed/typosquat checks only (set CHAINSAW_GUARD_DEEP=1 or stage artifacts for byte-level coverage)")
	}

	return g
}

func guardUpdateNudge() string {
	return "offline known-malicious + typosquat active; run `chainsaw guard update` for the full OpenSSF malicious-package set"
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
		// Signed-bundle corpus first (the refresh channel), else the embedded
		// generated seed (the build-time floor). The fetcher's live npm path is
		// deliberately not used: its keyword-search ranking is non-deterministic
		// and attacker-gameable, and corpus membership grants the exact-match
		// exemption — that trust decision must ride reviewed data (seed PR) or
		// a Sigstore-verified bundle, never a live per-client fetch.
		pkgs = g.bundleCorpus("npm")
		if len(pkgs) == 0 {
			pkgs = parsePopularSeed(npmPopularSeed)
		}
	case "pip", "pypi":
		pkgs = g.bundleCorpus("pypi")
		if len(pkgs) == 0 {
			pkgs = parsePopularSeed(pypiPopularSeed)
		}
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
	d := typosquat.NewDetectorWithConfig(guardLogger, typosquat.ThresholdConfig{
		MaxRelativeDistance: guardMaxRelativeDistance,
	})
	d.LoadEcosystem(ecosystem, pkgs)
	g.detectors[ecosystem] = d
	return d
}

// bundleCorpus returns the popular-package corpus for an ecosystem from the
// active intelligence bundle's "typosquat" blob, or nil when there is no
// usable one. The blob is a JSON object of ecosystem → names in rank order
// (rank 1 first). Honored ONLY from a signature-verified bundle: corpus
// membership grants the typosquat exact-match exemption, so unsigned or
// skip-verify data must never feed it — a tampered on-disk corpus would let
// a package exempt itself. Undersized corpora are rejected the same way
// (see guardBundleCorpusFloor).
func (g *localGuard) bundleCorpus(ecosystem string) []typosquat.PopularPackage {
	if g.bundle == nil || !g.bundle.Verified() {
		return nil
	}
	data := g.bundle.File("typosquat")
	if len(data) == 0 {
		return nil
	}
	var byEco map[string][]string
	if err := json.Unmarshal(data, &byEco); err != nil {
		return nil
	}
	names := byEco[ecosystem]
	if len(names) < guardBundleCorpusFloor {
		return nil
	}
	pkgs := make([]typosquat.PopularPackage, 0, len(names))
	for i, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		pkgs = append(pkgs, typosquat.PopularPackage{Name: n, Rank: i + 1})
	}
	return pkgs
}

// evaluate renders the local verdict for one spec. Block policy — BLOCK is
// reserved for coordinate-exact or corroborated evidence; name-similarity
// alone warns:
//   - known-malicious                       → BLOCK (always)
//   - homoglyph typosquat                   → BLOCK (byte-level confusable
//     collision with a popular name has no legitimate explanation)
//   - edit-distance d=1 vs top-ranked target → BLOCK (the crossenv/loadash
//     shape; rank cutoff guardTyposquatBlockRankCutoff)
//   - any other typosquat hit (d=1 tail-rank, d≥2, reorder) → WARN
//     (pass; two real packages one edit apart is common in the long tail —
//     the 2026-07 incident's katex/preact/recharts class)
func (g *localGuard) evaluate(ctx context.Context, spec packageSpec) guardVerdict {
	if res := g.malware.Lookup(ctx, spec.Ecosystem, spec.Name, spec.Version); res.IsKnownMalicious {
		reason := "known-malicious package"
		if res.MalwareID != "" {
			reason = fmt.Sprintf("known-malicious (%s)", res.MalwareID)
		}
		return guardVerdict{Spec: spec, Block: true, Severity: "malicious", Reason: reason}
	}

	if reason, ok := supplementalInstallAdvisory(spec); ok {
		return guardVerdict{Spec: spec, Block: true, Severity: "known-vulnerable", Reason: reason}
	}

	// pendingWarn holds a warn-level (non-blocking) verdict until the byte-level
	// analysis below has had its say. A name-similarity WARN must never
	// short-circuit past the behavioral scan — a package can be both a
	// warn-tier typosquat AND carry a blockable malicious payload, and the
	// old early return let the warn mask the block.
	var pendingWarn guardVerdict

	if d := g.detector(spec.Ecosystem); d != nil {
		res := d.Check(ctx, spec.Ecosystem, spec.Name)
		if res.IsSuspected {
			reason := fmt.Sprintf("looks like a typosquat of %q (distance %d, %s)", res.SimilarTo, res.Distance, res.Method)
			if res.TargetRank > 0 {
				reason = fmt.Sprintf("looks like a typosquat of %q (distance %d, %s, target rank #%d)",
					res.SimilarTo, res.Distance, res.Method, res.TargetRank)
			}
			// Verdict ladder, split by METHOD rather than the detector's flat
			// confidence: the certainty gradient homoglyph > edit-d1-vs-top >
			// edit-d1-vs-tail > d≥2/reorder is real, and only the first two
			// earn a block. Corpus members never reach here (exact-match skip
			// in the detector), so an edit-distance hit is by construction a
			// name ABSENT from the popular corpus.
			switch {
			case res.Method == "homoglyph" && res.Confidence == "high":
				return guardVerdict{Spec: spec, Block: true, Severity: "typosquat-high", Reason: reason}
			case res.Method == "edit-distance" && res.Distance == 1 &&
				res.TargetRank > 0 && res.TargetRank <= guardTyposquatBlockRankCutoff:
				return guardVerdict{Spec: spec, Block: true, Severity: "typosquat-high", Reason: reason}
			case res.Confidence == "high" || res.Confidence == "medium":
				pendingWarn = guardVerdict{Spec: spec, Block: false, Severity: "typosquat-medium", Reason: reason}
			}
		}
	}

	// Offline behavioral analysis: when the package's actual bytes are staged
	// locally (CHAINSAW_GUARD_ARTIFACT_DIR), run the real detectors over them.
	// This catches a malicious install script or hidden-unicode payload that's
	// in no feed yet — the thing a name+version lookup structurally cannot.
	// Fail-open: nil bytes or a clean read just falls through to ALLOW.
	if data := guardArtifactBytes(spec); len(data) > 0 {
		if bv := analyzeArtifact(spec.Ecosystem, data); bv.Block {
			return guardVerdict{Spec: spec, Block: true, Severity: bv.Severity, Reason: bv.Reason}
		} else if bv.Severity != "" && pendingWarn.Severity == "" {
			pendingWarn = guardVerdict{Spec: spec, Block: false, Severity: bv.Severity, Reason: bv.Reason}
		}
	}

	if pendingWarn.Severity != "" {
		return pendingWarn
	}
	return guardVerdict{Spec: spec, Block: false}
}

func supplementalInstallAdvisory(spec packageSpec) (string, bool) {
	if !strings.EqualFold(spec.Ecosystem, "npm") || !strings.EqualFold(spec.Name, "pacote") || spec.Version == "" {
		return "", false
	}
	version, err := semver.NewVersion(spec.Version)
	if err != nil {
		return "", false
	}
	const affected = ">=5.0.0 <=19.0.1 || =20.0.0 || =21.0.0"
	const advisoryID = "npm-audit:pacote-transitive-vulnerabilities"
	const fixed = "22.0.0"
	const reason = "known-vulnerable npm audit advisory " + advisoryID + " (upgrade pacote to " + fixed + ")"
	constraint, err := semver.NewConstraint(affected)
	if err != nil {
		return "", false
	}
	if !constraint.Check(version) {
		return "", false
	}
	return reason, true
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
