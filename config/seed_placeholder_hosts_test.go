package config

// seed_placeholder_hosts_test.go — L-20 guards.
//
// A `swift` repository shipped in configs/seed.yaml with
// `remote.url: https://your-swift-registry.example.com/`. That is not a
// seed defect that stays in the seed: tools/egress-allowlist-gen reads
// this file and had already emitted the fake host into
// enforcement/network/{netskope,zscaler,generic-deny}.txt — artifacts a
// customer pastes verbatim into a Zscaler or Netskope policy.
//
// Three guards, deliberately at three different layers, because the
// defect could re-enter at any of them: the seed, its byte-for-byte
// twin in dockerized/, or a committed artifact that went stale after
// the seed was cleaned.

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot is the worktree root relative to core/config, where the Go
// test process runs. Both config files and the emitted artifacts are
// addressed from here.
const repoRoot = "../.."

// requireMonorepoTree skips when the fixtures these guards assert on are
// not reachable.
//
// core/ is rsynced verbatim into the public Chain305/chainsaw-core repo
// and scripts/opencore-export.sh runs `GOWORK=off go test ./...` against
// that export as a release gate. In the export, core/config IS the
// module root's config package, so `../..` points outside the tree
// entirely — configs/seed.yaml and enforcement/network/ simply do not
// exist there. Skipping is correct; failing would break the export gate
// on a monorepo-only fixture.
//
// The skip is keyed on the DIRECTORY, not the file, so a deleted or
// renamed seed.yaml inside the monorepo still fails loudly rather than
// quietly turning the guard off.
func requireMonorepoTree(t *testing.T, dir string) {
	t.Helper()
	info, err := os.Stat(filepath.Join(repoRoot, dir))
	if err != nil || !info.IsDir() {
		t.Skipf("%s/ not present (open-core export tree); monorepo-only guard", dir)
	}
}

// seedConfigPaths are the two files that must both be clean. They are
// listed together rather than parameterised from a glob so that adding a
// third copy is a deliberate edit here, not a silent inclusion.
var seedConfigPaths = []string{
	filepath.Join(repoRoot, "configs", "seed.yaml"),
	filepath.Join(repoRoot, "dockerized", "config.yaml"),
}

// placeholderHostSubstrings are the reserved / non-routable markers that
// must never appear in a machine-readable upstream host.
//
// SCOPE NOTE, and it matters: this applies ONLY to Remote.URL. The same
// files carry ~110 `your-chainsaw-server` occurrences inside
// client_configuration_guide prose. Those are the OPERATOR'S OWN host in
// a copy-paste snippet — correct placeholders, addressed to a human, and
// nothing machine-readable consumes them. Sweeping them would be a
// false positive at scale.
var placeholderHostSubstrings = []string{
	"example.com",
	"example.org",
	"example.net",
	"invalid",
	"localhost",
}

// placeholderReason reports why host is unusable as a real upstream, or
// "" when it looks like a genuine host. Shared by the seed guard and the
// emitted-artifact guard so the two can never drift apart on what counts
// as a placeholder.
func placeholderReason(host string) string {
	lower := strings.ToLower(strings.TrimSpace(host))
	if lower == "" {
		return ""
	}
	// Zscaler renders hosts as `.domain.tld`; normalise so one matcher
	// serves every vendor format.
	lower = strings.TrimPrefix(lower, ".")
	for _, bad := range placeholderHostSubstrings {
		if strings.Contains(lower, bad) {
			return "contains reserved/non-routable marker " + bad
		}
	}
	if strings.HasPrefix(lower, "your-") {
		return "starts with `your-`, i.e. a fill-in-your-own-value stub"
	}
	if strings.ContainsAny(lower, "<>") {
		return "contains an unsubstituted <angle-bracket> template token"
	}
	return ""
}

// TestSeedRemoteURLsAreRealHosts parses both config files with the real
// loader (not a hand-rolled YAML shape) and asserts every repository's
// upstream is a host a customer's firewall could legitimately be told to
// block.
//
// Using Load rather than yaml.Unmarshal is the point: it exercises the
// same defaults + validate path the server boots through, so a file that
// passes this test is a file that boots.
func TestSeedRemoteURLsAreRealHosts(t *testing.T) {
	t.Parallel()
	requireMonorepoTree(t, "configs")
	for _, path := range seedConfigPaths {
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load(%s): %v", path, err)
		}
		for _, repo := range cfg.Repositories {
			raw := strings.TrimSpace(repo.Remote.URL)
			if raw == "" {
				// hosted repositories have no upstream at all.
				continue
			}
			u, err := url.Parse(raw)
			if err != nil {
				t.Errorf("%s: repository %q has an unparseable remote.url %q: %v",
					path, repo.Name, raw, err)
				continue
			}
			if reason := placeholderReason(u.Hostname()); reason != "" {
				t.Errorf("%s: repository %q ships a placeholder upstream %q — %s.\n"+
					"A placeholder in remote.url reaches customers: tools/egress-allowlist-gen "+
					"copies it into enforcement/network/*.txt. If there is no real public "+
					"upstream for the format, omit the repository entry entirely (see the "+
					"Swift block in configs/seed.yaml) rather than inventing a host.",
					path, repo.Name, raw, reason)
			}
		}
	}
}

// seedTrivyDBPath / dockerizedTrivyDBPath pin the ONE line that
// legitimately differs between
// configs/seed.yaml and dockerized/config.yaml: the container image
// mounts its data volume at /data, so the Trivy database lives at a
// different absolute path there.
//
// DEVIATION FROM THE FIX DESIGN, recorded here rather than in a commit
// message that nobody re-reads: docs/qa-remediation/W5-W6-server-ux.md
// states the two files are byte-identical and asks for a raw byte
// compare. They are NOT — this drift predates the L-20 work and a plain
// byte compare could not be committed green. The guard still does the
// job it was asked to do (catch a one-file fix that leaves the twin
// stale) because the exception is a single pinned substitution and the
// comparison after it is exact: a second divergence fails the test.
const (
	seedTrivyDBPath       = `db_path: "/opt/chainsaw/data/trivy.db"`
	dockerizedTrivyDBPath = `db_path: "/data/trivy.db"`
)

// TestSeedAndDockerizedConfigsAreIdentical pins configs/seed.yaml and
// dockerized/config.yaml together. Nothing else enforces this, which is
// how a one-file fix becomes a half-fix — the swift entry existed in
// both and would have survived in the container config alone.
func TestSeedAndDockerizedConfigsAreIdentical(t *testing.T) {
	t.Parallel()
	requireMonorepoTree(t, "configs")
	seed, err := os.ReadFile(seedConfigPaths[0])
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	dockerized, err := os.ReadFile(seedConfigPaths[1])
	if err != nil {
		t.Fatalf("read dockerized: %v", err)
	}

	if !strings.Contains(string(seed), seedTrivyDBPath) {
		t.Fatalf("configs/seed.yaml no longer contains %q — the pinned "+
			"container-path exception is stale and must be re-derived", seedTrivyDBPath)
	}
	normalised := strings.Replace(string(seed), seedTrivyDBPath, dockerizedTrivyDBPath, 1)

	if normalised == string(dockerized) {
		return
	}
	seedLines := strings.Split(normalised, "\n")
	dockLines := strings.Split(string(dockerized), "\n")
	if len(seedLines) != len(dockLines) {
		t.Fatalf("configs/seed.yaml has %d lines, dockerized/config.yaml has %d — "+
			"the two must stay in lockstep; apply every seed edit to both files",
			len(seedLines), len(dockLines))
	}
	for i := range seedLines {
		if seedLines[i] != dockLines[i] {
			t.Fatalf("configs/seed.yaml and dockerized/config.yaml diverge at line %d:\n"+
				"  seed:       %q\n  dockerized: %q\n"+
				"The only sanctioned difference is the Trivy db_path (container volume "+
				"layout). Apply every other seed edit to both files.",
				i+1, seedLines[i], dockLines[i])
		}
	}
}

// egressArtifacts are the generated deny-list files customers import
// directly into their SASE / firewall tooling.
var egressArtifacts = []string{
	filepath.Join(repoRoot, "enforcement", "network", "generic-deny.txt"),
	filepath.Join(repoRoot, "enforcement", "network", "netskope-urls.txt"),
	filepath.Join(repoRoot, "enforcement", "network", "zscaler-urls.txt"),
}

// TestEmittedEgressAllowlistHasNoPlaceholderHosts checks the COMMITTED
// artifacts rather than re-running the generator.
//
// That is the whole point: the generator's output is only as fresh as
// the last person who remembered to run it. A clean seed with a stale
// committed artifact is precisely the state that shipped
// `your-swift-registry.example.com` to customers, and a test that
// regenerates before asserting would have passed throughout.
func TestEmittedEgressAllowlistHasNoPlaceholderHosts(t *testing.T) {
	t.Parallel()
	requireMonorepoTree(t, filepath.Join("enforcement", "network"))
	for _, path := range egressArtifacts {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			// Header and section-divider lines are prose for the admin
			// importing the file; only the leading host token on a
			// non-comment line is machine-consumed.
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			host := strings.Fields(trimmed)[0]
			if reason := placeholderReason(host); reason != "" {
				t.Errorf("%s:%d emits placeholder host %q — %s.\n"+
					"Regenerate with: go run ./tools/egress-allowlist-gen "+
					"-config configs/seed.yaml -out enforcement/network",
					path, i+1, host, reason)
			}
		}
	}
}
