package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	depanalyzer "github.com/chain305/chainsaw-core/depparser/analyzer"
	ftypes "github.com/chain305/chainsaw-core/fanal"
	"github.com/chain305/chainsaw-core/policy"
)

// scanSchemaVersion identifies the JSON envelope shape `chainsaw scan` emits.
// P2.11 — a top-level schemaVersion lets a structured consumer pin on a known
// envelope and detect a future breaking change without diffing the whole body.
// Bump only on a backward-incompatible envelope change; additive fields keep
// the same version.
const scanSchemaVersion = "chainsaw.scan/v1"

// scanStdin is the input stream stdin-batch mode reads from. Indirected so
// tests can feed a deterministic reader without touching the real os.Stdin.
// Production leaves it pointing at os.Stdin.
var scanStdin io.Reader = os.Stdin

// severityRank maps severity strings to ordinal values for comparison.
//
// Lookups MUST go through rankSeverity, never through this map directly: a bare
// map index is case-sensitive and silently yields rank 0 for any value it does
// not know, which made `--fail-on high` fail OPEN on the exact row SARIF calls
// "error" (S2).
var severityRank = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"none":     0,
}

// severityAliases maps foreign severity vocabularies onto chainsaw's ladder.
// The keys are the words other advisory sources use for the same band:
//
//	moderate                     GitHub Advisory's word for medium
//	important                    Red Hat / Microsoft's word for high
//	informational | info         "worth recording, not worth gating"
//	negligible                   Debian/Alpine's floor band
//
// Aliasing is deliberately conservative — it only covers vocabularies that map
// UNAMBIGUOUSLY onto an existing band. Anything else stays "unrecognized" and
// is reported rather than guessed at (see rankSeverity).
var severityAliases = map[string]string{
	"moderate":      "medium",
	"important":     "high",
	"informational": "none",
	"info":          "none",
	"negligible":    "none",
}

// scanSeverityFlagValues is the explicit set `--severity` / `--fail-on` accept.
//
// S11: validation used to be `_, ok := severityRank[flag]`, which silently
// admitted the map's fifth key "none" — a value the error message never
// advertised and whose threshold (0) makes `severityRank[r.Severity] >= 0` true
// for EVERY row, so `--fail-on none` (which reads as "never fail") blocked on
// any result at all. Validate against the four documented values instead.
var scanSeverityFlagValues = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
}

// rankSeverity normalizes a severity string and returns its ordinal rank plus
// whether the value was recognized at all.
//
// Normalization is ToLower+TrimSpace followed by the alias table, so "HIGH",
// " high " and "moderate" all resolve. An EMPTY severity is recognized at rank
// 0 (it is the server's "no CVE severity" encoding, not a protocol error).
//
// The (rank, ok) split matters: callers must not conflate "rank 0" with
// "unknown". Rank 0 is a real band ("none"); unknown means the CLI and the
// server disagree about the vocabulary, which is a version-skew signal the
// caller decides what to do with. We deliberately do NOT resolve unknown values
// upward to "at or above the threshold" — the SARIF emitter in this same repo
// resolves unknown DOWNWARD to "note"/0.0, so that would trade one silent
// disagreement for a louder one in the opposite direction and turn protocol
// skew into a fleet-wide CI outage. Instead: warn once per distinct value,
// echo them in the JSON envelope, and apply one surgical fail-closed rule at
// the gate (a `status=="vulnerable"` row whose severity is unrankable breaches
// any --fail-on).
func rankSeverity(s string) (int, bool) {
	n := strings.ToLower(strings.TrimSpace(s))
	if n == "" {
		return 0, true
	}
	if alias, ok := severityAliases[n]; ok {
		n = alias
	}
	rank, ok := severityRank[n]
	return rank, ok
}

// supplyChainConditionSeverity maps a triggered supply-chain condition
// name to the severity level it contributes for the `--severity` /
// `--fail-on` filters. These mirror the product decisions taken in the
// 13-PR consolidation:
//
//   - publisherChanged / installScriptFetchesRemote / hasHiddenUnicode
//     / publishVelocityAnomaly / malware / repo_link=missing →  high —
//     these are the “treat as actively hostile” signals; a CI that
//     pins `--fail-on high` should break the build.
//   - hasInstallScript (alone) / versionAnomaly / typosquat → medium —
//     suspicious but not yet indicative of compromise.
//   - provenance=unverified / repo_link=archived → low — worth
//     flagging but not CI-breaking by default.
//
// Any condition not listed here contributes "none" and is therefore
// informational only.
var supplyChainConditionSeverity = map[string]string{
	"publisherChanged":           "high",
	"installScriptFetchesRemote": "high",
	"hasHiddenUnicode":           "high",
	"publishVelocityAnomaly":     "high",
	"malware":                    "high",
	"repoLinkMissing":            "high",
	"hasInstallScript":           "medium",
	"versionAnomaly":             "medium",
	"typosquat":                  "medium",
	"provenanceUnverified":       "low",
	"repoLinkArchived":           "low",
}

type scanPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`

	// Ecosystem is the registry the coordinate came from ("npm", "pip",
	// "maven", …), canonicalised through policy.EcosystemForFormat so the
	// CLI and the server speak one spelling. Without it a name+version is
	// ambiguous — npm's commander@2.20.3 and PyPI's commander 2.20.3 are
	// different packages — and the server answers both with whichever row
	// it happens to find.
	//
	// omitempty: a bare `chainsaw scan name@version` and a stdin spec line
	// carry no ecosystem, and neither does a lockfile whose language has no
	// registry we proxy. Those items go on the wire in the pre-ecosystem
	// shape and the server falls back to the pre-ecosystem lookup.
	Ecosystem string `json:"ecosystem,omitempty"`
}

// ecosystemForLang maps the depparser LangType attached to a parsed package
// onto the canonical ecosystem name the scan API expects.
//
// Two steps on purpose. The switch collapses the lockfile-flavour aliases the
// parser registry emits (yarn.lock and pnpm-lock.yaml are both npm; poetry,
// uv and pylock are all PyPI; pom, gradle and sbt all resolve Maven
// coordinates) onto a repository FORMAT; policy.EcosystemForFormat then folds
// that format onto the canonical ecosystem. Going through the existing
// normaliser rather than returning a literal keeps this from becoming a second
// spelling table that can drift from the policy evaluator's.
//
// Collapsing the flavours matters for the dedup key: a tree carrying both
// package-lock.json and yarn.lock must NOT report lodash twice.
//
// Languages with no ecosystem we can scan (hex, conan, julia, conda) return ""
// — the item ships in the legacy shape rather than under an invented name.
func ecosystemForLang(l ftypes.LangType) string {
	var format string
	switch l {
	case ftypes.Npm, ftypes.Bun, ftypes.Yarn, ftypes.Pnpm, ftypes.NodePkg, ftypes.JavaScript:
		format = "npm"
	case ftypes.Pip, ftypes.Pipenv, ftypes.Poetry, ftypes.Uv, ftypes.PyLock, ftypes.PythonPkg:
		format = "pip"
	case ftypes.Bundler, ftypes.GemSpec:
		format = "rubygems"
	case ftypes.Cargo, ftypes.RustBinary:
		format = "cargo"
	case ftypes.Composer, ftypes.ComposerVendor:
		format = "composer"
	case ftypes.NuGet, ftypes.DotNetCore, ftypes.PackagesProps:
		format = "nuget"
	case ftypes.Pom, ftypes.Gradle, ftypes.Sbt, ftypes.Jar:
		format = "maven"
	case ftypes.GoModule, ftypes.GoBinary:
		format = "go"
	case ftypes.Cocoapods:
		format = "cocoapods"
	case ftypes.Swift:
		format = "swift"
	case ftypes.Pub:
		format = "pub"
	default:
		return ""
	}
	return string(policy.EcosystemForFormat(format))
}

// scanPkgKey is the identity of a scanned coordinate. The ecosystem is part
// of it: keying on name@version alone collapsed npm's commander@2.20.3 and
// PyPI's commander 2.20.3 into a single scanned coordinate, so one of the two
// was never evaluated and the other's CVEs were attributed to both.
func scanPkgKey(ecosystem, name, version string) string {
	return ecosystem + "|" + name + "@" + version
}

type scanResultItem struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Ecosystem echoes the registry the server resolved this row against.
	// Empty against a server older than the ecosystem field, or for a
	// coordinate whose ecosystem could not be determined.
	Ecosystem  string `json:"ecosystem,omitempty"`
	Repository string `json:"repository,omitempty"`
	Status     string `json:"status"`
	Severity   string `json:"severity,omitempty"`
	// UnscannedReason is the server's one-phrase explanation of WHY this
	// coordinate could not be evaluated. Populated only when Status ==
	// "unscanned"; empty against a server older than the field.
	//
	// L-05: "scanned and clean" and "could not scan" used to render the
	// same way — a row with no CVEs and no signals — so an operator (and a
	// CI gate) read the second as the first. This string is what the two
	// renderers below use to keep them apart.
	UnscannedReason string   `json:"unscanned_reason,omitempty"`
	CVSSScore       *float64 `json:"cvss_score,omitempty"`
	EPSSScore       *float64 `json:"epss_score,omitempty"`
	CVEs            []string `json:"cves,omitempty"`

	// Supply-chain signals surfaced from the 13-PR consolidation. The
	// server populates these from package_metadata on the scan path; the
	// CLI just re-emits them in JSON and collapses them into the text
	// table when any value is non-default. Every field is `omitempty`
	// so the JSON schema stays backward-compatible for consumers that
	// pin on the legacy vulnerability-only shape.
	InstallScriptKind         string   `json:"install_script_kind,omitempty"`
	PublisherChanged          *bool    `json:"publisher_changed,omitempty"`
	PublisherSet              []string `json:"publisher_set,omitempty"`
	VersionAnomalyFlags       []string `json:"version_anomaly_flags,omitempty"`
	HiddenUnicodeHits         int      `json:"hidden_unicode_hits,omitempty"`
	HiddenUnicodeKinds        []string `json:"hidden_unicode_kinds,omitempty"`
	PublishVelocity24h        int      `json:"publish_velocity_24h,omitempty"`
	RepoLinkStatus            string   `json:"repo_link_status,omitempty"`
	RepoLinkLastCheckedAt     string   `json:"repo_link_last_checked_at,omitempty"`
	ChecksumDeclared          string   `json:"checksum_declared,omitempty"`
	ChecksumActual            string   `json:"checksum_actual,omitempty"`
	ChecksumUnavailableReason string   `json:"checksum_unavailable_reason,omitempty"`
	ProvenanceStatus          string   `json:"provenance_status,omitempty"`
	MalwareStatus             string   `json:"malware_status,omitempty"`
	TyposquatStatus           string   `json:"typosquat_status,omitempty"`
	// TriggeredConditions lists policy conditions that fire for this
	// package (CLI derives from the signal values above — see
	// deriveTriggeredConditions). Used for `--fail-on` and severity
	// mapping, and echoed in JSON so CI integrations can gate on
	// specific supply-chain conditions without re-implementing the
	// derivation.
	TriggeredConditions []string `json:"triggered_conditions,omitempty"`
}

type scanAPIResponse struct {
	Results    []scanResultItem `json:"results"`
	Total      int              `json:"total"`
	Vulnerable int              `json:"vulnerable"`
	Unscanned  int              `json:"unscanned"`
}

var scanCmd = &cobra.Command{
	Use:     "scan [package@version | -]",
	GroupID: GrpScan,
	Short:   "Scan packages for vulnerabilities",
	Long: `Scan one or more packages for known vulnerabilities using the Chainsaw server.

Output formats (--format / --json / --output):
  table   human-readable table (default)
  json    structured envelope (--json is sugar for --format=json)
  sarif   SARIF 2.1.0 log for code-scanning ingesters (normally with --output)

Batch input:
  chainsaw scan -            read newline-delimited package specs / lockfile
  chainsaw scan --stdin      paths from stdin (opt-in; bare scan never reads stdin)

Coverage:
  A package the server could not evaluate is reported as "not scanned", never
  as clean, and the reason is printed to stderr. That state does NOT fail the
  build by default; pass --fail-on-unscanned (or set
  CHAINSAW_SCAN_FAIL_ON_UNSCANNED=1) to make it exit 1.

Exit codes:
  0   clean — nothing at or above the gate
  1   blocked — findings at or above the threshold (--fail-on, else any
      vulnerable package or high/critical supply-chain condition). Also
      returned when --fail-on-unscanned is set and a package could not be
      evaluated.
  2   operational failure (network, server, IO)
  3   configuration or authentication problem
  4   bad invocation (unknown flag, unparseable package ref, --path with
      nothing scannable under it)
  30  one or more manifests failed to parse (dependencies dropped) — the
      packages that did parse were still scanned. Same code, same meaning as
      chainsaw pr-scan. A block (1) outranks it.

Naming the registry:
  A lockfile scan (--path) knows which registry every coordinate came from.
  A ref typed on the command line usually does not: "commander@2.20.3" exists
  on npm AND on PyPI, and they are different packages. The scoped form
  (@scope/pkg) and a Go module path are unambiguous and resolved for you;
  anything else needs --ecosystem, and the scan says so rather than reporting
  a coordinate nobody could look up as clean.

Examples:
  chainsaw scan lodash@4.17.11 --ecosystem npm
  chainsaw scan @babel/core@7.24.0
  chainsaw scan --path .
  chainsaw scan --path . --severity high
  chainsaw scan --path . --fail-on critical --json
  chainsaw scan --path . --fail-on-unscanned
  chainsaw scan --path . --format sarif --output results.sarif
  cat specs.txt | chainsaw scan -`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().String("path", "", "Scan all dependencies found in a local project manifest")
	// --ecosystem FILLS IN the registry for coordinates that name none — a
	// positional `name@version` and a stdin spec line. It deliberately does
	// NOT override a lockfile-derived coordinate: those already carry the
	// ecosystem their parser proved, and letting one flag restamp a whole
	// mixed tree as "npm" would reintroduce the cross-registry collision the
	// per-item ecosystem exists to prevent.
	scanCmd.Flags().String("ecosystem", "",
		"Registry a bare package@version ref belongs to ("+scanEcosystemFlagValues+"); inferred from the lockfile with --path")
	scanCmd.Flags().String("severity", "", "Minimum severity to display: critical, high, medium, low")
	scanCmd.Flags().String("fail-on", "", "Exit 1 only when vulnerabilities at or above this severity are found")
	// L-05 — opt-in, and deliberately so. This product's posture is that an
	// unavailable signal fails CLOSED, so the RIGHT default is for a
	// coordinate we could not evaluate to break the build. But flipping a
	// default exit code silently breaks every existing user's CI on upgrade,
	// with no warning and no way to have prepared for it. So: fix the
	// substance first (the server now falls back to the same fetch-and-scan
	// route `intel package` uses, which makes "unscanned" rare and truthful),
	// make the state impossible to mistake for "clean" in the output, and
	// give operators a switch they can turn on when they are ready.
	//
	// THE DEFAULT SHOULD FLIP ON THE NEXT MAJOR. When it does, this flag
	// keeps its name and gains a --no-fail-on-unscanned counterpart rather
	// than being removed, so a CI file written today still says what it means.
	//
	// P8-27 — registered through the shared helper (scan_gate.go) rather than
	// inline, so `scan` and `scan-repo` cannot drift into two different
	// spellings of the same CI contract. Name, default and usage string are
	// byte-identical to the inline form this replaced.
	addScanGateFlags(scanCmd, scanGateFlags{FailOnUnscanned: true, FailOnUnscannedDefault: false})
	// Y7: no backticks in this usage string. pflag's UnquoteUsage treats the
	// first back-quoted span as the flag's value placeholder, so "the `-`
	// arg" rendered a BOOL flag as `--stdin -`. Once the backticks are gone
	// UnquoteUsage's `case "bool": name = ""` branch fires and --stdin
	// correctly shows no argument token.
	scanCmd.Flags().Bool("stdin", false, "Read newline-delimited package specs / lockfile paths from stdin (opt-in; same as the '-' arg)")
	// S6 — the shared 30s client timeout hard-caps a scan this command
	// advertises as accepting 10,000 packages, with no way to raise it. The
	// default here is deliberately well above 30s; NewAPIClient's 30s stays put
	// for the ~40 other commands that make one small request.
	scanCmd.Flags().Duration("timeout", scanDefaultTimeout, "Maximum time to wait for the server to evaluate the submitted packages")
	rootCmd.AddCommand(scanCmd)
}

// scanDefaultTimeout is the overall HTTP budget for the /api/scan POST. Ten
// minutes is chosen to comfortably cover the documented 10,000-package ceiling;
// the shared 30s default could not.
const scanDefaultTimeout = 10 * time.Minute

func runScan(cmd *cobra.Command, args []string) error {
	scanStart := time.Now()
	pathFlag, _ := cmd.Flags().GetString("path")
	severityFlag, _ := cmd.Flags().GetString("severity")
	failOnFlag, _ := cmd.Flags().GetString("fail-on")
	stdinFlag, _ := cmd.Flags().GetBool("stdin")
	// The env var is the CI-friendly half of the same switch: it lets an
	// org turn the gate on fleet-wide without editing every workflow file.
	// An EXPLICIT flag always wins over it in both directions, so
	// `--fail-on-unscanned=false` can carve one job out of a fleet default
	// — which is why the resolver is Changed()-gated rather than a plain OR.
	// P8-27 moved that precedence into resolveFailOnUnscanned (scan_gate.go)
	// unchanged; `false` is this command's documented default.
	failOnUnscanned := resolveFailOnUnscanned(cmd, false)

	// P2.9 — stdin batch is STRICTLY opt-in. It engages only when the user
	// passes --stdin or the conventional `-` arg; a bare `chainsaw scan` must
	// never block waiting on stdin. We strip the `-` sentinel from args so the
	// later positional-package path doesn't try to parse it as name@version.
	useStdin := stdinFlag
	rest := args
	if len(rest) > 0 && rest[0] == "-" {
		useStdin = true
		rest = rest[1:]
	}

	if !useStdin && len(rest) == 0 && pathFlag == "" {
		// Bad argument shape → ExitUsage(4), consistent with cobra's own
		// unknown-flag handling (invariant B: usage != operational error).
		return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf("specify a package (e.g. lodash@4.17.11), --path <dir>, or - / --stdin to read from stdin")}
	}

	// S11 — validate against the explicit four-value set the error text
	// advertises, NOT against severityRank (whose "none" key passed validation
	// and then made --fail-on block on every row). Case/whitespace are
	// normalized first so `--fail-on HIGH` behaves like `--fail-on high`,
	// matching rankSeverity's treatment of the server's values.
	if severityFlag != "" {
		severityFlag = strings.ToLower(strings.TrimSpace(severityFlag))
		if !scanSeverityFlagValues[severityFlag] {
			return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf("unknown --severity %q; use critical, high, medium, or low", severityFlag)}
		}
	}
	if failOnFlag != "" {
		failOnFlag = strings.ToLower(strings.TrimSpace(failOnFlag))
		if !scanSeverityFlagValues[failOnFlag] {
			return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf("unknown --fail-on %q; use critical, high, medium, or low", failOnFlag)}
		}
	}

	// --ecosystem is canonicalised through the same normaliser the server and
	// the policy evaluator use (policy.EcosystemForFormat), so the CLI cannot
	// grow a second spelling table. A value it cannot place comes back "" —
	// reject it HERE rather than putting an unresolvable name on the wire and
	// getting an "unscanned" row back that blames the coordinate.
	ecosystemFlag, _ := cmd.Flags().GetString("ecosystem")
	ecosystemFlag = strings.ToLower(strings.TrimSpace(ecosystemFlag))
	if ecosystemFlag != "" {
		canonical := string(policy.EcosystemForFormat(ecosystemFlag))
		if canonical == "" {
			return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf(
				"unknown --ecosystem %q; use one of %s", ecosystemFlag, scanEcosystemFlagValues)}
		}
		ecosystemFlag = canonical
	}

	// S6 — build the client with the command's own timeout budget rather than
	// the shared 30s default. A non-positive value falls back to that default
	// inside newAPIClientWithTimeout.
	scanTimeout, _ := cmd.Flags().GetDuration("timeout")
	client := newClientWithTimeout(scanTimeout)
	if client.baseURL == "" {
		// Missing server config → ExitConfigAuth(3), carried by
		// errServerNotConfigured itself (X3) rather than re-wrapped here.
		return errServerNotConfigured(cmd)
	}
	if cfgToken() == "" {
		// Not authenticated → ExitConfigAuth(3).
		return &ExitCodeError{Code: ExitConfigAuth, Err: fmt.Errorf("not authenticated — run 'chainsaw auth login' first")}
	}

	const maxPackages = 10_000

	// Y3/Y4 — every failure below RETURNS a typed error instead of calling
	// os.Exit. A bare os.Exit inside a RunE never returns to Execute(), so it
	// bypassed BOTH the documented exit-code contract in exitcodes.go (every
	// one of these was a flat 2, including plain bad-argument shapes that the
	// contract puts at ExitUsage(4)) and the telemetry flush — the whole
	// batch, including the cli.session.completed carrying exit_code and
	// error_class, was dropped for every failing scan.
	//
	// The mapping is the contract's: a wrong ARGUMENT (unparseable ref,
	// non-existent --path, an input with nothing scannable in it, an input
	// over the ceiling) is ExitUsage(4); an IO/stream failure is
	// ExitOpError(2); dropped dependencies are ExitManifestParseError(30).
	var packages []scanPkg
	// manifestParseErr is set when a manifest or lockfile the user pointed us
	// at failed to parse. It does NOT abort the scan — everything that did
	// parse is still scanned and reported — but it is turned into
	// ExitManifestParseError(30) at the end so CI cannot read an incomplete
	// scan as a clean one (B2b).
	var manifestParseErr *manifestParseError
	switch {
	case useStdin:
		pkgs, err := collectFromStdin(scanStdin)
		if err != nil && !errors.As(err, &manifestParseErr) {
			// A hard read failure on the stream itself: operational.
			return &ExitCodeError{Code: ExitOpError, Err: err}
		}
		packages = pkgs
		if len(packages) == 0 {
			if manifestParseErr != nil {
				return &ExitCodeError{Code: ExitManifestParseError, Err: manifestParseErr}
			}
			return &ExitCodeError{Code: ExitUsage, Err: errors.New("no package specs or parseable lockfile paths read from stdin")}
		}
		if len(packages) > maxPackages {
			return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf(
				"read %d packages from stdin; maximum per scan is %d — narrow the input", len(packages), maxPackages)}
		}
	case pathFlag != "":
		if _, err := os.Stat(pathFlag); err != nil {
			return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf("--path %q: %w", pathFlag, err)}
		}
		pkgs, err := collectFromManifests(pathFlag)
		if err != nil && !errors.As(err, &manifestParseErr) {
			// The only non-parse failure this returns is "no supported
			// manifest or lockfile found here" — the user aimed --path at the
			// wrong directory, which is a bad argument, not an op failure.
			return &ExitCodeError{Code: ExitUsage, Err: err}
		}
		packages = pkgs
		if len(packages) == 0 {
			if manifestParseErr != nil {
				return &ExitCodeError{Code: ExitManifestParseError, Err: manifestParseErr}
			}
			return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf("no pinned dependencies found in %s", pathFlag)}
		}
		if len(packages) > maxPackages {
			return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf(
				"found %d packages; maximum per scan is %d — narrow the scope with a subdirectory", len(packages), maxPackages)}
		}
	default:
		pkg, err := parsePackageRef(rest[0])
		if err != nil {
			return &ExitCodeError{Code: ExitUsage, Err: err}
		}
		packages = []scanPkg{pkg}
	}

	// Fill in the ecosystem the user named for every coordinate that carries
	// none. See the flag registration for why this fills rather than
	// overrides: a lockfile coordinate already knows its own registry.
	if ecosystemFlag != "" {
		for i := range packages {
			if packages[i].Ecosystem == "" {
				packages[i].Ecosystem = ecosystemFlag
			}
		}
	}
	// Whether ANY coordinate is going out unplaced. The server can only
	// resolve what it can place, so this is the difference between an
	// "unscanned" row that means "we looked and found nothing" and one that
	// means "you have not told us where to look" — and only the second has a
	// fix the user can apply.
	var sentWithoutEcosystem bool
	for _, p := range packages {
		if p.Ecosystem == "" {
			sentWithoutEcosystem = true
			break
		}
	}
	// The one shape where an unplaceable coordinate is unambiguously a bad
	// INVOCATION rather than a gap in coverage: the operator typed exactly one
	// ref, we could not infer its registry, and they did not name one. If that
	// scan comes back unscanned there is precisely one coordinate and one
	// missing flag, so the CLI can say what to type. A --path or stdin batch
	// gets the stderr advice above instead — there the unscanned rows may have
	// several different causes and the run is usually a CI gate whose exit
	// code must not change under us.
	bareRefTyped := !useStdin && pathFlag == "" && len(packages) == 1 && packages[0].Ecosystem == ""

	// Surface the dropped dependencies BEFORE the scan runs, and never gate it
	// on --quiet: this is the reason for a non-zero exit, not chatter, and the
	// --quiet invariant forbids suppressing that. stderr keeps stdout pure for
	// the JSON/SARIF sinks.
	if manifestParseErr != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", manifestParseErr)
		fmt.Fprintf(os.Stderr, "         scanning the %d dependency/dependencies that did parse; exit code will be %d\n",
			len(packages), ExitManifestParseError)
	}

	// Resolve the result format up-front: it gates both the progress notice
	// below and the final output rendering. --json is sugar for --format=json
	// (resolveFormat reconciles the two); --format=sarif selects the SARIF
	// emitter. Any non-table format is "machine-readable" for the purpose of
	// keeping stderr clean.
	format := resolveFormat(cmd)
	machineFmt := format != "table"

	// Surface a one-line progress notice before the (potentially long,
	// blocking) scan POST so the user isn't staring at a frozen terminal
	// while up to 10k packages are evaluated server-side. Suppressed for any
	// machine format so structured consumers see no extra stderr line. The
	// notice is chatter — quiet() also suppresses it (it MUST NOT change a
	// block reason or exit code, only chatter).
	if !machineFmt && !quiet(cmd) {
		fmt.Fprintf(os.Stderr, "scanning %d package(s)…\n", len(packages))
	}

	var resp scanAPIResponse
	if err := client.Post("/api/scan", map[string]any{"packages": packages}, &resp); err != nil {
		// Return the error so Execute()/classifyCLIError buckets it: 401/403 →
		// ExitConfigAuth(3), network/IO → ExitOpError(2). A bare os.Exit(2) here
		// mislabels an auth failure as an operational error (invariant B).
		return err
	}

	// Derive triggered supply-chain conditions for each result — uses
	// the signals the server merged in from package_metadata. We fold
	// them back into the result so downstream text/JSON/--fail-on
	// paths can treat supply-chain conditions as first-class
	// citizens alongside CVE-based severity.
	//
	// S2 — the RAW server severity is inspected here, before
	// resolveHighestSeverity can overwrite it with a higher supply-chain band.
	// unrankable[i] records "this row arrived with a severity this CLI does not
	// understand", which the --fail-on gate below turns into a fail-CLOSED
	// decision for vulnerable rows.
	unrankable := make([]bool, len(resp.Results))
	unknownSeen := map[string]bool{}
	for i := range resp.Results {
		if _, ok := rankSeverity(resp.Results[i].Severity); !ok {
			unrankable[i] = true
			unknownSeen[strings.TrimSpace(resp.Results[i].Severity)] = true
		}
		resp.Results[i].TriggeredConditions = deriveTriggeredConditions(resp.Results[i])
		resp.Results[i].Severity = resolveHighestSeverity(resp.Results[i])
	}
	unknownSeverities := make([]string, 0, len(unknownSeen))
	for s := range unknownSeen {
		unknownSeverities = append(unknownSeverities, s)
	}
	sort.Strings(unknownSeverities)
	// One warning per DISTINCT unrecognized value, not one per row — a fleet
	// running a newer server would otherwise emit a line per package. quiet()
	// suppresses it: this is a diagnostic about protocol skew, and the gate
	// below (not this line) is what enforces.
	if len(unknownSeverities) > 0 && !quiet(cmd) {
		fmt.Fprintf(os.Stderr,
			"warning: server returned severity value(s) this CLI does not recognize: %s\n"+
				"         they are ranked as 'none' for display; vulnerable rows carrying them still breach --fail-on.\n"+
				"         upgrade the CLI if your server is newer.\n",
			strings.Join(unknownSeverities, ", "))
	}

	// Apply severity display filter. A result is shown when its
	// effective severity (CVE severity OR the highest supply-chain
	// condition severity) is at or above --severity. This means
	// `--severity high` now surfaces publisherChanged /
	// hasHiddenUnicode / etc. packages even if they carry no CVE —
	// which is the whole point of wiring the new conditions in.
	displayed := resp.Results
	if severityFlag != "" {
		minRank, _ := rankSeverity(severityFlag)
		// Allocate a fresh slice rather than filtering in place
		// (displayed[:0]) — the exit-code gate below iterates the
		// unfiltered resp.Results, and an in-place filter would alias and
		// overwrite that backing array, silently defeating the gate.
		filtered := make([]scanResultItem, 0, len(resp.Results))
		for _, r := range resp.Results {
			if rank, _ := rankSeverity(r.Severity); rank >= minRank {
				filtered = append(filtered, r)
			}
		}
		displayed = filtered
	}
	// S4 — how many findings the display filter removed. printScanTable cannot
	// otherwise tell "the scan was clean" apart from "the filter hid
	// everything", and it printed the clean message for both.
	hiddenBySeverity := len(resp.Results) - len(displayed)

	// L-05 — surface the coordinates the server could NOT evaluate, by name
	// and with the server's reason, before any result rendering and for
	// EVERY format.
	//
	// Two deliberate properties:
	//   - It is not gated on --quiet. Same rule as the manifest-parse
	//     warning above: --quiet suppresses chatter, never the reason a
	//     scan is incomplete, and under --fail-on-unscanned this IS the
	//     reason for the exit code.
	//   - It goes to stderr for json/sarif too, so a structured consumer's
	//     stdout stays pure while a human tailing the job still sees it.
	warnUnscanned(resp.Results, resp.Unscanned, failOnUnscanned, sentWithoutEcosystem)

	switch format {
	case "json":
		// P2.11 — schemaVersion is a NEW top-level field; every pre-existing
		// key (results/total/vulnerable/unscanned) keeps its name and meaning so
		// existing --json consumers stay byte-compatible apart from the added
		// field. Results go to the --output sink (a file when set, else stdout)
		// so JSON purity holds: stdout carries only the envelope, logs stay on
		// stderr.
		//
		// S12/S2 — three fields are CONDITIONALLY added: severityFilter and
		// filteredOut only when --severity is set, unknownSeverities only when
		// the server sent a value this CLI could not rank. An unfiltered scan
		// against a matching server therefore emits the exact same bytes as
		// before, while a filtered one stops advertising a pre-filter
		// total/vulnerable next to a post-filter results[] with no marker.
		env := map[string]any{
			"schemaVersion": scanSchemaVersion,
			"results":       displayed,
			"total":         resp.Total,
			"vulnerable":    resp.Vulnerable,
			"unscanned":     resp.Unscanned,
		}
		if severityFlag != "" {
			env["severityFilter"] = severityFlag
			env["filteredOut"] = hiddenBySeverity
		}
		if len(unknownSeverities) > 0 {
			env["unknownSeverities"] = unknownSeverities
		}
		_ = PrintJSONTo(cmd, env)
	case "sarif":
		// SARIF is normally redirected to a file via --output; outWriter honors
		// that and falls back to stdout otherwise. We emit the FULL result set
		// (not the --severity-filtered view) so a code-scanning ingester sees
		// every finding the gate considered — --severity is a human display
		// filter, not a SARIF-scope control.
		if err := writeScanSARIF(outWriter(cmd), resp.Results); err != nil {
			// A render failure is operational (unwritable sink) and must
			// abort BEFORE the gate below: emitting a verdict computed
			// against a result nobody received is worse than either outcome
			// alone (same rule emitAndGate encodes).
			return &ExitCodeError{Code: ExitOpError, Err: fmt.Errorf("write sarif: %w", err)}
		}
	default:
		// The unscanned coordinates were already named on stderr by
		// warnUnscanned above; the count is passed in here so the table's
		// own empty-state line cannot claim a clean tree alongside them.
		// Same countUnscanned the warning and the gate use, so stdout,
		// stderr and the exit code cannot report three different numbers.
		printScanTable(displayed, hiddenBySeverity, severityFlag, countUnscanned(resp.Results, resp.Unscanned))
	}

	emit("cli.scan.completed", map[string]any{
		"duration_ms":      time.Since(scanStart).Milliseconds(),
		"packages_scanned": resp.Total,
		"blocked_count":    resp.Vulnerable,
	})

	// Determine exit code.
	// --fail-on integrates BOTH vulnerability-derived severity AND the
	// new supply-chain triggered conditions. A package with no CVE but
	// publisherChanged=true will still break the build at
	// `--fail-on high` — which is the behavior CI users asked for in
	// the 13-PR consolidation review.
	//
	// A threshold breach is the EXPECTED enforcement outcome, so it is returned
	// as ExitCodeError{Code: ExitBlocked} (NOT a raw os.Exit(1)). ExitBlocked is
	// still 1, so every existing block-gating script is unchanged; routing it
	// through the typed error lets Execute() classify it as a block rather than
	// an operational failure (which now maps to ExitOpError(2)). The error
	// carries no message so renderError stays silent — the findings already
	// printed above are the user-facing block reason.
	if failOnFlag != "" {
		threshold, _ := rankSeverity(failOnFlag)
		for i, r := range resp.Results {
			// S2 fail-closed rule, deliberately narrow: a row the server calls
			// "vulnerable" whose severity this CLI cannot rank breaches ANY
			// --fail-on threshold. Ranking it 0 would fail OPEN on exactly the
			// row SARIF renders as level "error". The rule is scoped to
			// status=="vulnerable" so it carries zero false-positive surface —
			// a non-vulnerable row with an unknown severity is still just
			// informational.
			if unrankable[i] && r.Status == "vulnerable" {
				return &ExitCodeError{Code: ExitBlocked}
			}
			if rank, _ := rankSeverity(r.Severity); rank >= threshold {
				return &ExitCodeError{Code: ExitBlocked}
			}
		}
	} else {
		// Default: block if any vulnerable result OR any high/critical
		// supply-chain condition was triggered. The gate scans the full
		// resp.Results set, NOT the --severity-filtered `displayed` slice:
		// `--severity` controls only what the user sees, so a high or
		// vulnerable package filtered out of the view must still break the
		// build. Mirrors the --fail-on branch above, which also iterates
		// resp.Results.
		for _, r := range resp.Results {
			if r.Status == "vulnerable" {
				return &ExitCodeError{Code: ExitBlocked}
			}
			if rank, _ := rankSeverity(r.Severity); rank >= severityRank["high"] {
				return &ExitCodeError{Code: ExitBlocked}
			}
		}
	}

	// B2b — nothing blocked, but a manifest was dropped, so this scan is NOT
	// evidence of a clean tree and must not exit 0. Placed AFTER the block
	// gate so a real block still outranks it, mirroring pr-scan (which
	// escalates 0/10 to 30 but leaves blocking(20) alone). The warning was
	// already printed above, so this error carries the reason for anyone who
	// only reads the tail of the log.
	if manifestParseErr != nil {
		return &ExitCodeError{Code: ExitManifestParseError, Err: manifestParseErr}
	}

	// L-05 — the opt-in coverage gate, last because it is the weakest claim
	// of the three: a real block (1) and a dropped manifest (30) both mean
	// something concrete went wrong with the packages we DID see, and 30
	// carries strictly more information than this does, so when either
	// fires the build is already red and this has nothing to add.
	//
	// ExitBlocked rather than a new number on purpose. This is a gate the
	// operator explicitly switched on and it failed — the exact meaning
	// ExitBlocked already publishes ("a policy block, a failed gate, or
	// findings at or above the configured threshold"). Minting a new code
	// for an opt-in gate would put a number in the shared exit-code space
	// that only the people who already opted in could ever see.
	//
	// The error carries a message because, unlike a findings block, there
	// is no table row that explains this one on its own.
	if failOnUnscanned && countUnscanned(resp.Results, resp.Unscanned) > 0 {
		return &ExitCodeError{Code: ExitBlocked, Err: errors.New(
			"--fail-on-unscanned: one or more packages could not be evaluated (see the warning above)")}
	}

	// The single-ref usage failure, LAST of all the gates. `chainsaw scan
	// lodash@4.17.11` used to print an "unscanned" row and exit 0 — a
	// non-answer that reads as a pass, on what is most people's first command.
	// It is a usage error (ExitUsage, same code as an unparseable ref or a
	// --path with nothing under it), not an operational one: the run reached
	// the server and the server answered, the invocation was just missing the
	// one thing that makes the coordinate resolvable.
	//
	// Ordered after --fail-on-unscanned so an operator who explicitly wired
	// that gate still gets the exit code they configured; this only fires on
	// the interactive one-package path where nothing else has spoken.
	//
	// The response has to CONFIRM the diagnosis before the CLI blames the
	// invocation: one row, unscanned, and echoing no ecosystem of its own.
	// An unscanned row that came back placed ("this version does not exist
	// upstream") is a genuine coverage gap that --ecosystem would not have
	// fixed, and telling that operator to pass a flag would be a wrong answer
	// delivered with a non-zero exit code.
	if bareRefTyped && len(resp.Results) == 1 &&
		resp.Results[0].Status == "unscanned" && resp.Results[0].Ecosystem == "" {
		return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf(
			"%s could not be resolved because no registry was named — re-run with --ecosystem <%s>",
			rest[0], scanEcosystemFlagValues)}
	}
	return nil
}

// countUnscanned reports how many coordinates in this response the server
// could not evaluate.
//
// It prefers counting the rows themselves so the number always matches the
// coordinates warnUnscanned printed, and falls back to the server's own
// aggregate when the response carried a count but no rows (an older server,
// or a response shape that summarises rather than enumerates). Taking the
// max of the two is the fail-closed choice: under-reporting here is the
// original defect.
func countUnscanned(results []scanResultItem, serverCount int) int {
	n := 0
	for _, r := range results {
		if r.Status == "unscanned" {
			n++
		}
	}
	if serverCount > n {
		return serverCount
	}
	return n
}

// unscannedNoticeMax caps how many coordinates the warning enumerates. A
// 10,000-package scan against a cold server could otherwise bury the rest of
// the output; the count in the header line is always exact.
const unscannedNoticeMax = 20

// warnUnscanned prints the "could not scan" block to stderr: how many
// coordinates were not evaluated, which ones, why, and what it means for the
// exit code.
//
// This is the L-05 fix in the output layer. Before it, an unscannable
// coordinate produced a bare "note: N package(s) could not be scanned" on the
// human path only, sitting next to "No vulnerabilities or supply-chain
// signals found" — so the two states a CI gate most needs to tell apart,
// "scanned and clean" and "could not scan", read as the same result.
// sentWithoutEcosystem says at least one coordinate went out with no registry
// named, which is a cause of "unscanned" the operator can actually fix — and
// the only one whose remedy is a flag rather than a retry. It is derived from
// the REQUEST, not from the empty Ecosystem on a response row, so a server too
// old to echo the field cannot make the CLI recommend a flag that would not
// have helped.
func warnUnscanned(results []scanResultItem, serverCount int, failOnUnscanned, sentWithoutEcosystem bool) {
	total := countUnscanned(results, serverCount)
	if total == 0 {
		return
	}
	fmt.Fprintf(os.Stderr,
		"warning: %d package(s) could NOT be scanned — this result is not evidence that they are clean.\n", total)

	shown := 0
	for _, r := range results {
		if r.Status != "unscanned" {
			continue
		}
		if shown == unscannedNoticeMax {
			fmt.Fprintf(os.Stderr, "         … and %d more\n", total-shown)
			break
		}
		name := r.Name
		if r.Ecosystem != "" {
			name = r.Name + " (" + r.Ecosystem + ")"
		}
		reason := r.UnscannedReason
		if reason == "" {
			// An older server sends no reason. Say that, rather than
			// inventing one — "we don't know why" is still the honest
			// answer and is materially different from "it is clean".
			reason = "no reason reported by the server"
		}
		fmt.Fprintf(os.Stderr, "         %s@%s: %s\n", name, r.Version, reason)
		shown++
	}

	if sentWithoutEcosystem {
		fmt.Fprintf(os.Stderr,
			"         at least one coordinate named no registry, and a bare name@version cannot be\n"+
				"         resolved upstream — pass --ecosystem <%s>.\n", scanEcosystemFlagValues)
	}

	if failOnUnscanned {
		fmt.Fprintf(os.Stderr, "         --fail-on-unscanned is set, so this scan exits %d.\n", ExitBlocked)
		return
	}
	fmt.Fprintf(os.Stderr,
		"         exit code is unaffected by default; pass --fail-on-unscanned (or set\n"+
			"         CHAINSAW_SCAN_FAIL_ON_UNSCANNED=1) to make incomplete coverage fail the build.\n")
}

// deriveTriggeredConditions inspects the enriched scan result and
// returns the ordered list of supply-chain conditions that are
// effectively "tripped" for this package. The condition names match
// the policy.Conditions JSON keys (so CI integrations can cross-match
// against a `chainsaw policy list` output) with two exceptions that
// collapse the signal namespace onto our severity map:
// "malware"/"typosquat" subsume the per-status strings,
// "repoLinkMissing"/"repoLinkArchived" subsume the per-status
// RepoLinkStatus values, and "provenanceUnverified" covers
// {unverified, missing, failed}.
func deriveTriggeredConditions(r scanResultItem) []string {
	var out []string
	if r.InstallScriptKind != "" && r.InstallScriptKind != "none" {
		out = append(out, "hasInstallScript")
		if r.InstallScriptKind == "fetches_remote" || r.InstallScriptKind == "eval_encoded" {
			out = append(out, "installScriptFetchesRemote")
		}
	}
	if r.PublisherChanged != nil && *r.PublisherChanged {
		out = append(out, "publisherChanged")
	}
	if len(r.VersionAnomalyFlags) > 0 {
		out = append(out, "versionAnomaly")
	}
	if r.HiddenUnicodeHits > 0 {
		out = append(out, "hasHiddenUnicode")
	}
	if r.PublishVelocity24h > 0 {
		// The server persists the counter; the *threshold* is policy-
		// driven, so the CLI treats any non-zero 24h velocity as
		// "the policy condition could fire" for display purposes.
		// Actual pass/fail gating happens at policy evaluation time
		// on the server — this is informational for the scan view.
		out = append(out, "publishVelocityAnomaly")
	}
	switch r.MalwareStatus {
	case "malicious":
		out = append(out, "malware")
	}
	switch r.TyposquatStatus {
	case "suspected", "confirmed":
		out = append(out, "typosquat")
	}
	switch r.RepoLinkStatus {
	case "missing", "ownership_mismatch":
		out = append(out, "repoLinkMissing")
	case "archived":
		out = append(out, "repoLinkArchived")
	}
	switch r.ProvenanceStatus {
	case "unverified", "missing", "failed":
		out = append(out, "provenanceUnverified")
	}
	return out
}

// resolveHighestSeverity picks the max of the CVE-derived severity and
// every supply-chain condition's contributed severity. Used by the
// display filter and --fail-on gate so a non-vulnerable package with
// a high-severity supply-chain signal still surfaces.
func resolveHighestSeverity(r scanResultItem) string {
	best := r.Severity
	if best == "" && r.Status == "vulnerable" {
		best = "low"
	}
	// S2 — normalize through rankSeverity so "HIGH"/"moderate" from the server
	// are compared on the same ladder as our own condition severities. An
	// unrankable value ranks 0 here, so any triggered condition outranks it and
	// the row is upgraded; if no condition fires, the original (unknown) string
	// is returned verbatim rather than being invented away.
	bestRank, _ := rankSeverity(best)
	for _, cond := range r.TriggeredConditions {
		sev, ok := supplyChainConditionSeverity[cond]
		if !ok {
			continue
		}
		if rank, _ := rankSeverity(sev); rank > bestRank {
			bestRank = rank
			best = sev
		}
	}
	return best
}

// printScanTable renders the (already --severity-filtered) result rows.
//
// hiddenBySeverity/severityFilter exist because the filtered slice alone cannot
// distinguish "the scan was clean" from "the display filter hid everything" —
// the function printed the same all-clear message for both, and an operator
// read it as a clean tree (S4). The exit gate is unaffected: it iterates the
// UNFILTERED results (see runScan), which is deliberate and stays that way.
// unscanned is the count of coordinates the server could not evaluate. It is
// the L-05 half: without it the empty-state line printed an unqualified
// all-clear next to a warning saying the opposite, and stdout — which is what
// a script or a screenshot usually captures — carried only the all-clear.
func printScanTable(results []scanResultItem, hiddenBySeverity int, severityFilter string, unscanned int) {
	// coverageNote qualifies any "nothing found" claim this function makes.
	// "No vulnerabilities found" and "no vulnerabilities found in the
	// packages we could look at" are different statements and must not
	// share a rendering.
	coverageNote := func() {
		if unscanned > 0 {
			fmt.Printf("%d package(s) could NOT be scanned — this scan does not clear them.\n", unscanned)
		}
	}
	if len(results) == 0 {
		if hiddenBySeverity > 0 {
			// Keep the leading clause identical to the clean message so the
			// two read alike, but qualify it and state the count.
			fmt.Printf("No vulnerabilities or supply-chain signals found at or above --severity %s.\n", severityFilter)
			fmt.Printf("%d finding(s) hidden by --severity %s.\n", hiddenBySeverity, severityFilter)
			coverageNote()
			return
		}
		if unscanned > 0 {
			// Deliberately NOT the clean message. Nothing was found because
			// nothing was successfully looked at.
			coverageNote()
			return
		}
		fmt.Println("No vulnerabilities or supply-chain signals found.")
		return
	}
	defer func() {
		if hiddenBySeverity > 0 {
			fmt.Printf("\n%d finding(s) hidden by --severity %s.\n", hiddenBySeverity, severityFilter)
		}
		if unscanned > 0 {
			fmt.Println()
			coverageNote()
		}
	}()
	// Class-A glyph: these em dashes are not prose, they are the "no score" /
	// "no CVEs" / "no signals" VALUE in a table cell. A raw U+2014 is absent
	// from CP437, so on a legacy Windows console the cell renders as a box and
	// a package with no CVSS becomes indistinguishable from a rendering fault.
	// glyphs().none is the marker for "inert: nothing there" and degrades to
	// ASCII "-" on a console that cannot draw it.
	g := glyphs()
	rows := make([][]string, len(results))
	anySignals := false
	for i, r := range results {
		cvss := g.none
		if r.CVSSScore != nil {
			cvss = fmt.Sprintf("%.1f", *r.CVSSScore)
		}
		cves := g.none
		if len(r.CVEs) > 0 {
			cves = strings.Join(r.CVEs, ", ")
		}
		severity := r.Severity
		if severity == "" {
			severity = r.Status
			// "unscanned" sitting in a SEVERITY column reads like a band —
			// a quiet one, next to "safe". Spell out that no verdict was
			// reached instead.
			if r.Status == "unscanned" {
				severity = "NOT SCANNED"
			}
		}
		signals := g.none
		if len(r.TriggeredConditions) > 0 {
			signals = strings.Join(r.TriggeredConditions, ", ")
			anySignals = true
		}
		// Qualify the package cell with its ecosystem so two same-named
		// coordinates from different registries are distinguishable — the
		// tree that pins npm commander@2.20.3 and PyPI commander 2.20.3
		// now yields two rows, and an unqualified table would render them
		// as the same package with two different verdicts. Inert against a
		// server that does not send the field.
		name := r.Name
		if r.Ecosystem != "" {
			name = r.Name + " (" + r.Ecosystem + ")"
		}
		rows[i] = []string{name, r.Version, severity, cvss, cves, signals}
	}
	PrintTable([]string{"PACKAGE", "VERSION", "SEVERITY", "CVSS", "CVEs", "SIGNALS"}, rows)

	// Per-package detail lines for the non-trivial supply-chain signals.
	// We keep the table compact and drop the full context underneath
	// — matches the existing `pkg info` aesthetic and avoids wrapping
	// long repo-status / checksum / publisher-set strings into the
	// tabwriter columns.
	if anySignals {
		fmt.Println()
		for _, r := range results {
			if !hasNonDefaultSupplyChainSignal(r) {
				continue
			}
			fmt.Printf("%s@%s\n", r.Name, r.Version)
			if r.InstallScriptKind != "" && r.InstallScriptKind != "none" {
				fmt.Printf("  install-script:       %s\n", r.InstallScriptKind)
			}
			if r.PublisherChanged != nil && *r.PublisherChanged {
				fmt.Printf("  publisher-changed:    yes\n")
			}
			if len(r.VersionAnomalyFlags) > 0 {
				fmt.Printf("  version-anomaly:      %s\n", strings.Join(r.VersionAnomalyFlags, ","))
			}
			if r.HiddenUnicodeHits > 0 {
				kinds := ""
				if len(r.HiddenUnicodeKinds) > 0 {
					kinds = " (" + strings.Join(r.HiddenUnicodeKinds, ",") + ")"
				}
				fmt.Printf("  hidden-unicode:       %d hit(s)%s\n", r.HiddenUnicodeHits, kinds)
			}
			if r.PublishVelocity24h > 0 {
				fmt.Printf("  publish-velocity-24h: %d\n", r.PublishVelocity24h)
			}
			if r.RepoLinkStatus != "" && r.RepoLinkStatus != "ok" {
				fmt.Printf("  repo-link-status:     %s\n", r.RepoLinkStatus)
			}
			if r.ChecksumDeclared != "" || r.ChecksumActual != "" {
				fmt.Printf("  checksum:             declared=%s actual=%s\n",
					truncateHash(r.ChecksumDeclared, glyphs()), truncateHash(r.ChecksumActual, glyphs()))
			}
			if r.ChecksumUnavailableReason != "" {
				fmt.Printf("  checksum-unavailable: %s\n", r.ChecksumUnavailableReason)
			}
		}
	}
}

// hasNonDefaultSupplyChainSignal reports whether a scan result carries
// any non-default supply-chain signal — used to decide whether the
// per-package detail block is worth printing for this row.
func hasNonDefaultSupplyChainSignal(r scanResultItem) bool {
	if r.InstallScriptKind != "" && r.InstallScriptKind != "none" {
		return true
	}
	if r.PublisherChanged != nil && *r.PublisherChanged {
		return true
	}
	if len(r.VersionAnomalyFlags) > 0 {
		return true
	}
	if r.HiddenUnicodeHits > 0 {
		return true
	}
	if r.PublishVelocity24h > 0 {
		return true
	}
	if r.RepoLinkStatus != "" && r.RepoLinkStatus != "ok" {
		return true
	}
	if r.ChecksumDeclared != "" || r.ChecksumActual != "" {
		return true
	}
	if r.ChecksumUnavailableReason != "" {
		return true
	}
	return false
}

// truncateHash renders a potentially-long checksum string for the
// text table: keeps the first 12 hex chars, collapses the rest.
//
// Empty input returns the glyph set's `none` marker rather than a raw em dash:
// "no checksum recorded" is information, and U+2014 boxes on a CP437 console,
// which would make an absent checksum look like a corrupt one. The set is
// passed in rather than resolved here so a whole table renders in one alphabet.
func truncateHash(s string, g glyphSet) string {
	if s == "" {
		return g.none
	}
	if len(s) <= 16 {
		return s
	}
	return s[:12] + "..."
}

func parsePackageRef(ref string) (scanPkg, error) {
	idx := strings.LastIndex(ref, "@")
	if idx <= 0 {
		return scanPkg{}, fmt.Errorf("invalid package ref %q — use name@version (e.g. lodash@4.17.11)", ref)
	}
	name, version := ref[:idx], ref[idx+1:]
	return scanPkg{Name: name, Version: version, Ecosystem: inferEcosystemForBareRef(name, version)}, nil
}

// inferEcosystemForBareRef names the registry a bare `name@version` coordinate
// belongs to, or returns "" when the name could belong to more than one.
//
// Why infer at all: the server can only resolve a coordinate it can place in a
// registry (scanFallback in internal/server/scan.go bails outright on an empty
// ecosystem), and a lockfile scan gets that for free from the parser. A ref
// typed on the command line does not, so `chainsaw scan <name>@<version>` —
// the first thing most people try — came back "unscanned" with nothing the
// user could act on.
//
// Why infer so LITTLE: an invented ecosystem is worse than none. The server
// answers the coordinate it was handed, so guessing "npm" for a name that is
// really a PyPI package produces a confident clean verdict about a package
// nobody looked at — the exact failure shape the ecosystem field was added to
// close. So only shapes that belong to exactly ONE registry's naming grammar
// are inferred:
//
//   - "@scope/name" — npm's scoped-name grammar. The leading "@" is not legal
//     in any other registry's names, and "/" is legal in none of them either.
//   - "host.tld/path…" at a "v"-prefixed version — a Go module path. Go module
//     versions are always v-prefixed (pseudo-versions included) and a module
//     path always starts with a domain-shaped segment; nothing else we proxy
//     accepts "/" in a name once npm's scoped form is excluded.
//
// A plain "lodash" is deliberately NOT inferred even though npm is by far the
// likeliest registry: "lodash" is registrable on PyPI, RubyGems and crates.io
// too, and "most likely" is precisely the reasoning that yields a clean
// verdict for the wrong package. The caller asks for --ecosystem instead.
func inferEcosystemForBareRef(name, version string) string {
	if scope, pkg, ok := strings.Cut(name, "/"); ok {
		switch {
		case strings.HasPrefix(scope, "@") && len(scope) > 1 && pkg != "" && !strings.Contains(pkg, "/"):
			return string(policy.EcosystemForFormat("npm"))
		case strings.HasPrefix(version, "v") && strings.Contains(scope, ".") && pkg != "":
			return string(policy.EcosystemForFormat("go"))
		}
	}
	return ""
}

// scanEcosystemFlagValues renders the ecosystem names --ecosystem accepts, for
// the flag's help text and for the error a rejected value produces. Only the
// CANONICAL spelling of each is listed; policy.EcosystemForFormat also folds
// the aliases the rest of the tree carries (pypi → pip, yarn/bun → npm,
// gradle → maven, gomod → go, oci → docker), so a user who types an alias is
// accepted silently rather than being told a true value is wrong.
const scanEcosystemFlagValues = "npm|pip|maven|cargo|rubygems|composer|nuget|go|cocoapods|swift|pub|docker"

// collectFromManifests walks dir recursively and returns every pinned
// (name, version) pair produced by chainsaw's dependency-parser
// registry. Every manifest and lockfile format is discovered and parsed
// by internal/depparser/analyzer — there is no in-package switch here;
// adding a new ecosystem is a new file under internal/depparser/parser/,
// not an edit to this function.
//
// The walk CONTINUES past a single malformed lockfile, so one bad file in a
// monorepo still yields a useful scan of everything else — but the failure is
// RETURNED as a *manifestParseError wrapped around the partial package set,
// never swallowed.
//
// B2b: this used to print "warning: depparser walk: %v" to stderr and carry
// on with whatever it got, and runScan treated the nil error as success. A
// repo whose lockfile failed to parse was therefore scanned for its
// manifest's direct dependencies only and CI went green — the single most
// dangerous shape of wrong answer this command can give. The parse failure is
// a REPORTING contract, independent of any one parser's bugs: the caller
// decides the exit code (ExitManifestParseError), and the packages that did
// parse are still returned and still scanned.
//
// A complete absence of parseable files returns an error to preserve the old
// CLI behaviour of "tell the user we scanned nothing".
func collectFromManifests(dir string) ([]scanPkg, error) {
	regPkgs, walkErr := depanalyzer.WalkDir(context.Background(), dir)
	if len(regPkgs) == 0 {
		if walkErr != nil {
			// Files WERE found and every one of them failed; saying "no
			// supported manifest found" would be a second lie on top of the
			// first. Report the parse failure itself.
			return nil, &manifestParseError{Target: dir, Err: walkErr}
		}
		return nil, fmt.Errorf("no supported manifest or lockfile found in %s (see internal/depparser/analyzer for the full supported list)", dir)
	}

	all := make([]scanPkg, 0, len(regPkgs))
	seen := make(map[string]bool, len(regPkgs))
	for _, p := range regPkgs {
		if p.Name == "" || p.Version == "" {
			continue
		}
		eco := ecosystemForLang(p.Lang)
		key := scanPkgKey(eco, p.Name, p.Version)
		if seen[key] {
			continue
		}
		seen[key] = true
		all = append(all, scanPkg{Name: p.Name, Version: p.Version, Ecosystem: eco})
	}
	if walkErr != nil {
		// Partial success: `all` is everything that parsed, and the error says
		// the set is incomplete. Callers that only want a best-effort list can
		// still use the packages; runScan turns this into exit 30.
		return all, &manifestParseError{Target: dir, Err: walkErr}
	}
	return all, nil
}

// manifestParseError reports that at least one manifest or lockfile under the
// scanned tree could not be parsed, so the dependency set is INCOMPLETE. It is
// carried alongside the packages that did parse (see collectFromManifests) —
// the point is that the exit code stops lying, not that the command aborts.
type manifestParseError struct {
	// Target is the directory, file, or input stream the user named.
	Target string
	Err    error
}

func (e *manifestParseError) Error() string {
	return fmt.Sprintf("%s: one or more manifests failed to parse — dependencies were dropped: %v", e.Target, e.Err)
}

func (e *manifestParseError) Unwrap() error { return e.Err }

// collectFromStdin reads newline-delimited input (P2.9 stdin batch) and returns
// the deduplicated package set. Each non-blank, non-comment line is either:
//
//   - a package spec "name@version" (e.g. lodash@4.17.11), or
//   - a filesystem path to a manifest/lockfile (parsed via the depparser
//     registry) or a directory (walked recursively).
//
// Spec lines and path lines may be freely interleaved. A line that is neither a
// valid spec nor an existing path is reported as a single aggregate warning to
// stderr and skipped, so one bad line never aborts a large batch. The caller
// (runScan) decides what an EMPTY result means — this function only returns an
// error for a hard read failure on the stream itself.
//
// SECURITY/SAFETY: this is only ever reached when the user explicitly opted in
// with `-` or --stdin; a bare `chainsaw scan` never calls it, so the CLI never
// blocks waiting on stdin by default.
func collectFromStdin(r io.Reader) ([]scanPkg, error) {
	if r == nil {
		return nil, nil
	}
	all := make([]scanPkg, 0, 16)
	seen := make(map[string]bool, 16)
	add := func(name, version, ecosystem string) {
		if name == "" || version == "" {
			return
		}
		key := scanPkgKey(ecosystem, name, version)
		if seen[key] {
			return
		}
		seen[key] = true
		all = append(all, scanPkg{Name: name, Version: version, Ecosystem: ecosystem})
	}

	var skipped int
	// B2b: paths whose manifest/lockfile failed to parse. Distinct from
	// `skipped` (lines that never named anything scannable) — these DROPPED
	// dependencies, which is what makes the exit code lie.
	var parseFailures []error
	sc := bufio.NewScanner(r)
	// Lockfile paths are short; a generous line cap guards against a pathological
	// single line without allowing unbounded growth.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // blank line or comment
		}

		// Prefer a filesystem path: a manifest/lockfile or directory expands to
		// its full pinned dependency set. We check Stat first so a path that
		// happens to contain "@" (unusual, but possible) isn't mis-parsed as a
		// spec.
		if info, err := os.Stat(line); err == nil {
			pkgs, perr := collectFromPath(line, info.IsDir())
			// B2b: a parse failure comes back WITH whatever did parse. Keep
			// those packages (dropping them would lose coverage the pre-B2b
			// code had) and record the failure so the caller can refuse to
			// exit 0 on an incomplete set.
			for _, p := range pkgs {
				add(p.Name, p.Version, p.Ecosystem)
			}
			if perr != nil {
				var mpe *manifestParseError
				if errors.As(perr, &mpe) {
					parseFailures = append(parseFailures, perr)
				} else {
					// Not a parse failure — an unreadable path or a directory
					// with no manifests at all. Nothing was dropped because
					// nothing was ever found; warn and skip as before.
					fmt.Fprintf(os.Stderr, "warning: stdin path %q: %v\n", line, perr)
					skipped++
				}
			}
			continue
		}

		// Otherwise treat the line as a name@version spec. A bare spec
		// names no registry, so it goes on the wire in the legacy
		// ecosystem-less shape — there is nothing to infer from.
		if pkg, err := parsePackageRef(line); err == nil {
			add(pkg.Name, pkg.Version, pkg.Ecosystem)
			continue
		}

		fmt.Fprintf(os.Stderr, "warning: stdin line %q is neither a package spec (name@version) nor an existing path; skipping\n", line)
		skipped++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	_ = skipped // surfaced per-line above; kept for future telemetry hooks
	if len(parseFailures) > 0 {
		return all, &manifestParseError{Target: "stdin", Err: errors.Join(parseFailures...)}
	}
	return all, nil
}

// collectFromPath returns the pinned packages for a single stdin-supplied path:
// a directory is walked recursively (collectFromManifests), a single file is
// parsed by content through the depparser registry. Split out so collectFromStdin
// stays readable and both branches share the (name, version) normalization.
func collectFromPath(path string, isDir bool) ([]scanPkg, error) {
	if isDir {
		return collectFromManifests(path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	regPkgs, err := depanalyzer.ParseBytes(context.Background(), path, content)
	if err != nil {
		// B2b: the user named this lockfile explicitly and it failed to parse,
		// so its whole dependency set was dropped. Typed so the caller can
		// tell it apart from "this path is not a manifest at all".
		return nil, &manifestParseError{Target: path, Err: err}
	}
	out := make([]scanPkg, 0, len(regPkgs))
	for _, p := range regPkgs {
		if p.Name == "" || p.Version == "" {
			continue
		}
		out = append(out, scanPkg{Name: p.Name, Version: p.Version, Ecosystem: ecosystemForLang(p.Lang)})
	}
	return out, nil
}
