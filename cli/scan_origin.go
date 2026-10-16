package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/chain305/chainsaw-core/depparser/origin"
)

// A package whose lockfile names a source other than its ecosystem's public
// registry (a git repository, an alternate registry) is a DIFFERENT package
// from the registry crate of the same name and version. The scan server only
// knows registry coordinates, so asking it about one returns the namesake's
// verdict: feldera/feldera's 22 git dependencies were reported clean that way
// until v0.22.91 fixed the server's lockfile scan. `chainsaw scan` therefore
// never takes a verdict for such a package from the server, with ONE
// exception, mirroring internal/scan/lockfile_scan.go (nonRegistryFinding):
//
//   - Negative lanes are never suppressed. If the namesake is a
//     known-malicious registry release, the package is reported malicious
//     (critical, blocking). Otherwise rewriting a lockfile source string would
//     be a way to dodge a malware result. Only the malware status is read;
//     a clean or vulnerable namesake says nothing about the fork.
//   - Everything else is "not_assessed".
//
// not_assessed is deliberately NOT "unscanned". Unscanned means the server
// tried and failed — a gap that may close on retry, which is what
// --fail-on-unscanned gates on. A git dependency is never assessed by
// construction, so counting it there would fail every such repo's CI forever
// with no remedy. It is never clean and never a block by default: no verdict,
// no severity, its own count in every output format, and its own opt-in gate
// (--fail-on-not-assessed).

const (
	statusNotAssessed = "not_assessed"
	// statusArtifactSwap: the lockfile names another package's public
	// artifact for this one. Severity high, so the default gates block.
	statusArtifactSwap = "artifact_swap"
	// statusMalicious is the status of a non-registry row whose namesake is
	// known-malicious. Its severity is critical, so every gate blocks on it.
	statusMalicious = "malicious"
)

// splitNonRegistry separates the coordinates the server can give a verdict
// for from the ones it must not. A package from a MIRROR of the public
// registry (origin.RegistryOther) is the public package when the CLI knows
// the host — the user's own Chainsaw repository or a declared
// registry_mirrors host (knownRegistry, the install guard's rule) — and is
// looked up like one: proxied and Artifactory-backed lockfiles record the
// mirror on every package, so treating them as not assessed would turn the
// whole tree into a non-blocking blind spot. An undeclared mirror stays not
// assessed (the server-side lockfile scan decides those by content hash;
// this path has no public digest to compare with).
func splitNonRegistry(pkgs []scanPkg) (registry, nonRegistry []scanPkg) {
	for _, p := range pkgs {
		if p.Origin == "" || (p.Version != "" && knownMirror(p.Ecosystem, p.Origin)) {
			registry = append(registry, p)
		} else {
			nonRegistry = append(nonRegistry, p)
		}
	}
	return registry, nonRegistry
}

// knownMirror: o is a registry-protocol source on a host the CLI accepts as
// the public registry's mirror.
func knownMirror(ecosystem, o string) bool {
	return origin.Classify(ecosystem, o) == origin.RegistryOther && knownRegistry(ecosystem, o)
}

// namesakes returns the registry coordinates sharing name@version with the
// non-registry packages, deduplicated: what the malware-only check asks about.
func namesakes(pkgs []scanPkg) []scanPkg {
	seen := map[string]bool{}
	var out []scanPkg
	for _, p := range pkgs {
		if p.Version == "" {
			continue // nothing to look up: no registry release is "name@"
		}
		k := scanPkgKey(p.Ecosystem, p.Name, p.Version, "")
		if !seen[k] {
			seen[k] = true
			out = append(out, scanPkg{Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem})
		}
	}
	return out
}

// maliciousNamesakes reads ONLY the malware status off the namesake rows. A
// row with no ecosystem (a server older than the field) is keyed without one
// and matches any ecosystem: a false "malicious" there fails closed.
func maliciousNamesakes(rows []scanResultItem) map[string]bool {
	out := map[string]bool{}
	for _, r := range rows {
		if r.MalwareStatus == "malicious" {
			out[scanPkgKey(r.Ecosystem, r.Name, r.Version, "")] = true
		}
	}
	return out
}

// nonRegistryResults renders the non-registry packages: malicious when the
// namesake is, otherwise not_assessed.
func nonRegistryResults(pkgs []scanPkg, malicious map[string]bool) []scanResultItem {
	out := make([]scanResultItem, 0, len(pkgs))
	for _, p := range pkgs {
		r := scanResultItem{Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem, Origin: p.Origin}
		label := " (" + origin.Label(p.Origin) + ")"
		if malicious[scanPkgKey(p.Ecosystem, p.Name, p.Version, "")] || malicious[scanPkgKey("", p.Name, p.Version, "")] {
			r.Status, r.Severity, r.MalwareStatus = statusMalicious, "critical", "malicious"
			r.OriginReason = "same name and version is a known-malicious registry release" + label
		} else if guardPublicSwap(packageSpec{Ecosystem: p.Ecosystem, Origin: p.Origin}) {
			// Another package's public artifact under this name (the
			// parsers' "url+<public URL>" marker): high, as on the server.
			r.Status, r.Severity = statusArtifactSwap, "high"
			r.OriginReason = "the lockfile installs another package's public artifact under this name (" +
				strings.TrimPrefix(p.Origin, "url+") + ")"
		} else {
			r.Status = statusNotAssessed
			r.OriginReason = notAssessedReason(p.Ecosystem) + label
			if origin.Classify(p.Ecosystem, p.Origin) == origin.RegistryOther {
				r.OriginReason += "; if it mirrors the public registry, add its host to registry_mirrors"
			}
		}
		out = append(out, r)
	}
	return out
}

func notAssessedReason(ecosystem string) string {
	if ecosystem == "cargo" {
		return "not from crates.io: not assessed"
	}
	return "not from the public registry: not assessed"
}

func countNotAssessed(results []scanResultItem) int {
	n := 0
	for _, r := range results {
		if r.Status == statusNotAssessed {
			n++
		}
	}
	return n
}

// warnNotAssessed names the not-assessed packages on stderr, for every format
// and regardless of --quiet: like the unscanned warning, it is the reason the
// result is incomplete, not chatter.
func warnNotAssessed(results []scanResultItem, failOnNotAssessed bool) {
	n := countNotAssessed(results)
	if n == 0 {
		return
	}
	fmt.Fprintf(os.Stderr,
		"note: %d package(s) are not from the public registry and were NOT assessed — this result says nothing about them.\n", n)
	shown := 0
	for _, r := range results {
		if r.Status != statusNotAssessed {
			continue
		}
		if shown == unscannedNoticeMax {
			fmt.Fprintf(os.Stderr, "      … and %d more\n", n-shown)
			break
		}
		fmt.Fprintf(os.Stderr, "      %s (%s)@%s: %s\n", r.Name, r.Ecosystem, r.Version, r.OriginReason)
		shown++
	}
	if failOnNotAssessed {
		fmt.Fprintf(os.Stderr, "      --fail-on-not-assessed is set, so this scan exits %d.\n", ExitBlocked)
		return
	}
	fmt.Fprintf(os.Stderr, "      exit code is unaffected (also under --fail-on-unscanned); pass --fail-on-not-assessed to fail on them.\n")
}

// sarifNotAssessedRuleID is the rule for packages that were deliberately not
// assessed. SARIF otherwise has no way to say "present but not assessed";
// without it a code-scanning view of a tree full of git dependencies is empty.
const sarifNotAssessedRuleID = "CHAINSAW-notAssessed"

// addNotAssessedSARIF appends a note-level result per not_assessed row. A
// malicious non-registry row needs nothing here: its malware condition is
// already a result.
func addNotAssessedSARIF(log *sarifLog, results []scanResultItem) {
	run := &log.Runs[0]
	idx := -1
	for _, r := range results {
		if r.Status != statusNotAssessed {
			continue
		}
		if idx < 0 {
			idx = len(run.Tool.Driver.Rules)
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:               sarifNotAssessedRuleID,
				Name:             "notAssessed",
				ShortDescription: sarifMessage{Text: "Package not from the public registry: not assessed"},
				DefaultConfiguration: &sarifRuleConfig{
					Level: "note",
				},
			})
		}
		pkgRef := r.Name + "@" + r.Version
		run.Results = append(run.Results, sarifResult{
			RuleID:    sarifNotAssessedRuleID,
			RuleIndex: idx,
			Level:     "note",
			Message:   sarifMessage{Text: fmt.Sprintf("%s: %s", pkgRef, r.OriginReason)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: pkgRef},
				},
			}},
		})
	}
}
