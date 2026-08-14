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
//     EXCEPTION, opt-in and off by default: an operator who sets
//     CHAINSAW_COVERAGE_MODE=closed with CHAINSAW_COVERAGE_REQUIRED=<sources>
//     asks us to refuse instead. See guard_coverage.go and
//     docs/plan_optional_fail_closed.md. With the variable unset, behaviour is
//     byte-identical to the fail-open default described above.

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
	"github.com/chain305/chainsaw-core/coverage"
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
// Returns (floor, extra) counts for the user-facing notice. `extra` is also the
// evidence for the "full feed present" coverage claim, so it is counted more
// strictly than the entries are loaded: every parseable source is MERGED into
// the index (more known-malicious coordinates can only add blocks), but only a
// source that could plausibly BE the full OpenSSF set, from a channel we trust,
// counts toward `extra`. See guardMalwareFeedFloor.
func loadMalwareSources(idx *malware.Index, bundle *intelligence.Bundle) (floor, extra int) {
	entries := malware.ParseOSVBlob(knownMaliciousSeed)
	floor = len(entries)

	if path := guardDBPath(); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			more := malware.ParseOSVBlob(data)
			entries = append(entries, more...)
			if len(more) >= guardMalwareFeedFloor {
				extra += len(more)
			} else if len(more) > 0 {
				// LOUD on purpose, and never suppressed by --quiet: this file is
				// what an operator's `CHAINSAW_COVERAGE_REQUIRED=malware` gate
				// hangs on. Silently accepting a 1-entry stub as "the full set"
				// would flip a fail-closed gate from refuse to pass with no trace
				// — the exact opposite of the loud break-glass path.
				fmt.Fprintf(os.Stderr,
					"chainsaw: WARNING — %s (%s) holds only %d known-malicious entries; the full OpenSSF set is ~200,000. "+
						"Treating it as PARTIAL coverage (not the full feed); re-run `chainsaw guard update`.\n",
					guardDBEnv, path, len(more))
			}
		}
	}
	if bundle != nil {
		if data := bundle.File("osv-malware"); len(data) > 0 {
			more := malware.ParseOSVBlob(data)
			entries = append(entries, more...)
			// Mirrors bundleCorpus: an UNVERIFIED bundle never underwrites a
			// coverage claim. Its entries are still merged (they can only block
			// more), but "the full feed is present" must ride a signature.
			if bundle.Verified() && len(more) >= guardMalwareFeedFloor {
				extra += len(more)
			}
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

// guardMalwareFeedFloor is the minimum entry count for a known-malicious source
// to count as "the full OpenSSF feed" for coverage purposes. Same reasoning as
// guardBundleCorpusFloor, in the other direction: there, a tiny corpus makes
// popular packages look squattable; here, a tiny feed file makes an operator's
// fail-closed `CHAINSAW_COVERAGE_REQUIRED=malware` gate report satisfied when
// almost nothing is actually indexed. The real dataset is ~230,000 entries, so
// 1,000 is two orders of magnitude below any genuine copy and comfortably above
// any hand-written fixture, truncated download, or stub.
const guardMalwareFeedFloor = 1000

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
	Severity string // "malicious" | "known-vulnerable" | "typosquat-high" | "typosquat-demoted" | "typosquat-medium" | ""
	Reason   string
	// Unwaivable marks a verdict the local allowlist must never clear and
	// whose escape-hatch hint must never be printed, EVEN THOUGH its severity
	// is in the allowlistable family. Exactly one arm sets it today: the
	// homoglyph block. Its severity stays "typosquat-high" (that is what the
	// user is being told, and the recall suite pins it), but a name built from
	// Unicode confusables is not inference a user can sensibly overrule — and
	// the hint would render a coordinate that LOOKS like the real package
	// ("chainsaw guard allow npm:lоdash" with a Cyrillic о reads as `lodash`),
	// i.e. advice to allow the very package the user thinks they are
	// installing. See guardAllowlistableVerdict in guard_allow.go.
	Unwaivable bool
	// WaivedSeverity and WaivedReason record the typosquat verdict an explicit
	// local allowlist entry SUPPRESSED for this coordinate — empty when nothing
	// was waived. They ride the verdict that was actually returned (usually an
	// ALLOW, but a behavioral block or warn from the byte scan below is equally
	// possible), because a waiver is orthogonal to the outcome: the user needs
	// to be told both "this was cleared by your allowlist" and whatever the rest
	// of the ladder went on to say.
	//
	// They exist because the waiver used to be COMPLETELY silent. A cleared
	// verdict produced no output line, so one planted line in
	// ~/.chainsaw/guard_allowlist.json was a permanent hole that looked
	// byte-identical to an install the guard never had an opinion about. The
	// only surface that revealed it was `guard allow --list`, which nobody runs
	// on a machine they do not already suspect. printGuardVerdicts now prints a
	// waiver notice for every one of these, --quiet included.
	//
	// WHY NOT ALSO RecentBlocks AND TELEMETRY — decided, not overlooked:
	//
	//   - RecentBlocks (guard_nudge.go) is the ring `chainsaw why` reads to
	//     explain a BLOCK offline. A waived coordinate was not blocked; putting
	//     it there would make `chainsaw why <pkg>` report a refusal that never
	//     happened, and it would evict real blocks from a 25-slot ring. The ring
	//     is also local-only and never transmitted, so it does nothing for the
	//     fleet-visibility half of the problem either. The local audit surface
	//     for waivers already exists and is exact — the allowlist file itself,
	//     which carries the verdict text and a timestamp per entry.
	//
	//   - Telemetry is consent-gated precisely because a BLOCKED package's name
	//     may be a private or internal one (the consent prompt says so in those
	//     words). A WAIVED name is strictly more sensitive, not less: it is a
	//     name this user singled out and vouched for, and the set of waivers is
	//     a machine-specific configuration fingerprint. It is also not a block,
	//     so it cannot ride install.guard.block without corrupting the blocked
	//     count that activation and the dashboards key off. A fleet operator who
	//     needs waiver visibility should get it from the server-side exception
	//     surface, where the coordinate is already known and the reporting is
	//     an explicit org decision — not by widening the anonymous local-guard
	//     stream to carry names that were never refused.
	//
	// So the answer to "a fleet dashboard cannot see it" is: make it loud on the
	// install output, every run, unsuppressable — which is where the operator
	// and CI log both are — and leave the telemetry stream alone.
	WaivedSeverity string
	WaivedReason   string
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
//     shape; rank cutoff guardTyposquatBlockRankCutoff, plus the target-length
//     and edit-shape predicates in guard_typosquat_gate.go — rank alone refused
//     real packages such as `nano` and `args` that merely sit one edit from a
//     popular short name)
//   - a d=1 hit the gate DEMOTED                → WARN, severity
//     "typosquat-demoted": the evidence cleared the rank cutoff and only the
//     shape/length predicates downgraded it, so it is printed even under
//     --quiet (guard_install.go). A verdict the gate itself downgraded is the
//     one a CI operator most needs to see.
//   - any other typosquat hit (d=1 tail-rank, d≥2, reorder) → WARN
//     (pass; two real packages one edit apart is common in the long tail —
//     the 2026-07 incident's katex/preact/recharts class)
//
// A coordinate the user has explicitly allowed (`chainsaw guard allow`, see
// guard_allow.go) skips the EDIT-DISTANCE typosquat lane — and only that. The
// known-malicious and known-vulnerable arms return above it, the HOMOGLYPH arm
// is hoisted above the consult (a confusable collision is not inference a
// waiver may overrule), and the byte-level scan below it still runs. A waiver
// is never silent: the suppressed verdict rides back on WaivedSeverity /
// WaivedReason and printGuardVerdicts announces it on every install, --quiet
// included.
// guardTyposquatReason renders the user-facing explanation for one typosquat
// detection. Shared by the hoisted homoglyph arm and the ladder below it so
// the two cannot drift into describing the same evidence differently.
func guardTyposquatReason(res typosquat.DetectionResult) string {
	if res.TargetRank > 0 {
		return fmt.Sprintf("looks like a typosquat of %q (distance %d, %s, target rank #%d)",
			res.SimilarTo, res.Distance, res.Method, res.TargetRank)
	}
	return fmt.Sprintf("looks like a typosquat of %q (distance %d, %s)", res.SimilarTo, res.Distance, res.Method)
}

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

	// waived carries the typosquat verdict an explicit local allowlist entry
	// suppressed, so EVERY return below can report it; withWaiver stamps it on
	// whatever verdict the rest of the ladder produces. See guardVerdict's
	// WaivedSeverity for why this is not also a RecentBlocks row or a telemetry
	// event. A waiver that produces no output at all is what this closure exists
	// to stop: it made one line of local JSON an invisible, permanent hole.
	var waived guardVerdict
	withWaiver := func(v guardVerdict) guardVerdict {
		v.WaivedSeverity, v.WaivedReason = waived.Severity, waived.Reason
		return v
	}

	if d := g.detector(spec.Ecosystem); d != nil {
		res := d.Check(ctx, spec.Ecosystem, spec.Name)

		// HOMOGLYPH, hoisted ABOVE the allowlist consult on purpose. A name
		// that collides with a popular one only through Unicode confusables is
		// byte-level evidence, not name-similarity inference, and the escape
		// hatch exists to overrule inference. Leaving it inside the consult
		// made the archetypal attack waivable by a coordinate the user cannot
		// visually distinguish from the real package: `chainsaw guard allow
		// npm:lоdash` (Cyrillic о) renders as `npm:lodash`. Unwaivable also
		// suppresses the block printer's hint — see guardAllowlistableVerdict.
		if res.IsSuspected && res.Method == "homoglyph" && res.Confidence == "high" {
			return guardVerdict{
				Spec: spec, Block: true, Severity: guardSeverityTyposquatHigh, Unwaivable: true,
				Reason: guardTyposquatReason(res),
			}
		}

		if res.IsSuspected {
			// Verdict ladder, split by METHOD rather than the detector's flat
			// confidence: the certainty gradient homoglyph > edit-d1-vs-top >
			// edit-d1-vs-tail > d≥2/reorder is real, and only the first two
			// earn a block. Corpus members never reach here (exact-match skip
			// in the detector), so an edit-distance hit is by construction a
			// name ABSENT from the popular corpus.
			//
			// DELIBERATE SILENCE at the bottom of the ladder. checkCombosquat
			// returns IsSuspected with Confidence "low", which matches no arm
			// below — no block, no warn, no telemetry — and that is CORRECT, not
			// an oversight. Measured on this repo's own corpora (held-out real,
			// popular packages: npm ranks 2501–5000, PyPI 1501–3000), a
			// low-confidence combosquat fires on 274/2500 = 11.0% of npm and
			// 184/1500 = 12.3% of PyPI names — @types/cacheable-request,
			// @npmcli/node-gyp, lodash.mergewith, django-environ,
			// tree-sitter-python. Warning on ~1 in 9 real packages would recreate
			// the 2026-07 742-false-positive incident in warn form, and warn form
			// is WORSE: warnings don't break builds, so they get tuned out —
			// taking every real warning with them. Combosquat coverage is a
			// priced-in gap in the bypass matrix, not a bug to "fix".
			// TestGuardNeverWarnsOnLowConfidenceCombosquat pins this absence.
			//
			// The reason string is built INSIDE the arms that can emit it: at the
			// low-confidence bottom of the ladder no verdict exists to carry it,
			// and a string built for a verdict that can never be emitted reads to
			// the next person as a dropped result.
			reason := func() string { return guardTyposquatReason(res) }
			// d1InCutoff is the population the block-lane gate speaks for: a
			// single edit against a target inside the rank cutoff. Splitting it
			// out is what lets a hit the GATE demoted be labelled differently
			// from a hit that was never block-eligible in the first place.
			// (The homoglyph arm returned above, before the allowlist consult.)
			d1InCutoff := res.Method == "edit-distance" && res.Distance == 1 &&
				res.TargetRank > 0 && res.TargetRank <= guardTyposquatBlockRankCutoff
			// lane is the verdict the EVIDENCE earns, computed before the
			// allowlist is consulted. That order is what makes a waiver
			// reportable rather than silent: "your allowlist suppressed this"
			// needs the this, and the consult used to run first and throw the
			// answer away.
			var lane guardVerdict
			switch {
			case d1InCutoff && guardTyposquatBlockGate.allowsD1Block(spec.Ecosystem, spec.Name, res):
				lane = guardVerdict{Spec: spec, Block: true, Severity: guardSeverityTyposquatHigh, Reason: reason()}
			case d1InCutoff:
				// DEMOTED by the gate, not by the evidence. Its own severity so
				// the printer can keep it out of the --quiet suppression that
				// covers ordinary medium-confidence chatter: this is the class
				// where the gate is trading recall for false blocks, and an
				// operator who never sees it cannot audit that trade.
				lane = guardVerdict{Spec: spec, Block: false, Severity: guardSeverityTyposquatDemoted, Reason: reason()}
			case res.Confidence == "high" || res.Confidence == "medium":
				lane = guardVerdict{Spec: spec, Block: false, Severity: guardSeverityTyposquatMedium, Reason: reason()}
			}

			// The ONE allowlist consult (guard_allow.go). It gates the whole
			// typosquat lane and nothing else, which is what makes the security
			// boundary structural rather than a rule someone must remember:
			//   - known-malicious and known-vulnerable already returned ABOVE, so
			//     a waiver is physically incapable of clearing either;
			//   - the homoglyph arm returned above it too;
			//   - the byte-level scan below is downstream and unconditioned, so a
			//     cleared name falls through to it exactly as a clean name does — a
			//     waiver can never mask a behavioral block, which is the failure the
			//     pendingWarn comment further down exists to prevent in the other
			//     direction.
			switch {
			case lane.Severity == "":
				// The deliberate silence documented above. Nothing was
				// suppressed, so a waiver notice here would announce a
				// suppression that never happened — and would leak the
				// low-confidence combosquat population we specifically decided
				// not to speak about.
			case guardAllowlistClearsTyposquat(spec):
				waived = lane
			case lane.Block:
				return lane
			default:
				pendingWarn = lane
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
			return withWaiver(guardVerdict{Spec: spec, Block: true, Severity: bv.Severity, Reason: bv.Reason})
		} else if bv.Severity != "" && pendingWarn.Severity == "" {
			pendingWarn = guardVerdict{Spec: spec, Block: false, Severity: bv.Severity, Reason: bv.Reason}
		}
	}

	if pendingWarn.Severity != "" {
		return withWaiver(pendingWarn)
	}
	return withWaiver(guardVerdict{Spec: spec, Block: false})
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
//
// The optional coverage gate runs first and independently of the per-package
// signals: if a data source the operator declared mandatory could not be
// evaluated, no per-package verdict can be trusted to mean "clean". Off by
// default, so the common path is unchanged. See
// docs/plan_optional_fail_closed.md.
func (g *localGuard) evaluateAll(ctx context.Context, specs []packageSpec) (verdicts []guardVerdict, blocked bool) {
	verdicts = make([]guardVerdict, 0, len(specs))

	posture, err := guardPosture()
	if err != nil {
		// A posture the operator explicitly configured but which we cannot
		// honour is fatal. Refusing every spec is the fail-closed reading and
		// keeps the promise the configuration made.
		for _, s := range specs {
			verdicts = append(verdicts, guardVerdict{
				Spec: s, Block: true, Severity: "coverage",
				Reason: fmt.Sprintf("invalid coverage configuration: %v", err),
			})
		}
		return verdicts, true
	}
	// One clock read, shared by the ledger and the gate: two calls could
	// straddle the grace or staleness boundary and disagree.
	now := time.Now()
	if d := coverage.Gate(posture, guardLedger(g, now), now); d.Block {
		for _, s := range specs {
			verdicts = append(verdicts, guardVerdict{
				Spec: s, Block: true, Severity: "coverage", Reason: d.Reason,
			})
		}
		return verdicts, true
	} else if d.Warn {
		fmt.Fprintf(os.Stderr, "chainsaw: coverage warning — %s (mode=warn, not blocking)\n", d.Reason)
	}

	for _, s := range specs {
		v := g.evaluate(ctx, s)
		if v.Block {
			blocked = true
		}
		verdicts = append(verdicts, v)
	}
	return verdicts, blocked
}
