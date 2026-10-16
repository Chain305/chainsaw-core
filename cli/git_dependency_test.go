package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/typosquat"
)

// blockGitDependencyRego is the org rule the gitDependency condition exists
// for: refuse anything built from a git repository.
const blockGitDependencyRego = `package chainsaw.policy

decision contains {
	"action":  "block",
	"rule_id": "org/no-git-deps",
	"message": "git dependencies are not allowed",
} if {
	input.gitDependency == true
}
`

func writeBlockGitDependencyBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "git.rego"), blockGitDependencyRego)
	return dir
}

// gitDependencySpecs are the ForceMemo-shaped installs: every one is built
// from a git repository, none from the registry.
func gitDependencySpecs() map[string]packageSpec {
	return map[string]packageSpec{
		"pip git+ (nameless)":    parsePipSpec("git+https://github.com/victim/zqxmemo"),
		"pip name @ git+":        parsePipSpec("zqxmemo @ git+https://github.com/victim/zqxmemo@v1.0"),
		"pip -e git+ #egg=":      pipSourceSpec("git+https://github.com/victim/zqxmemo#egg=zqxmemo"),
		"npm x@github:o/r":       parseNpmSpec("zqxmemo@github:victim/zqxmemo"),
		"npm o/r shorthand":      parseNpmSpec("victim/zqxmemo"),
		"npm git+ssh":            parseNpmSpec("zqxmemo@git+ssh://git@github.com/victim/zqxmemo.git"),
		"cargo --git":            {Ecosystem: "cargo", Name: "zqxmemo", Origin: "git+https://github.com/victim/zqxmemo"},
		"gemfile GIT (lockfile)": {Ecosystem: "rubygems", Name: "zqxmemo", Version: "1.0.0", Origin: "git+https://github.com/victim/zqxmemo.git#0123456"},
	}
}

// TestGuardGitDependencyRuleRefusesGitInstalls: an org rule keyed on
// gitDependency refuses `pip install git+…` and `npm i x@github:o/r`.
// Before the fix the guard never set the field, so the rule could not fire.
func TestGuardGitDependencyRuleRefusesGitInstalls(t *testing.T) {
	guardPolicyTestEnv(t, writeBlockGitDependencyBundle(t))
	g := &localGuard{detectors: map[string]*typosquat.Detector{}, malware: malware.NewIndex(nil)}
	for name, spec := range gitDependencySpecs() {
		t.Run(name, func(t *testing.T) {
			if spec.Origin == "" {
				t.Fatalf("fixture is not a non-registry spec: %+v", spec)
			}
			verdicts, blocked := g.evaluateAll(context.Background(), []packageSpec{spec})
			if !blocked || len(verdicts) != 1 || !strings.Contains(verdicts[0].Reason, "org/no-git-deps") {
				t.Fatalf("block-if-gitDependency must refuse %q, got blocked=%v %+v", spec.Origin, blocked, verdicts)
			}
		})
	}
}

// TestGuardGitDependencyRuleSparesNonGit: the same rule must not refuse a
// degraded-analysis REGISTRY install (the reason the field had to be its own
// fact, not signalsUnavailable), a tarball URL or a local path.
func TestGuardGitDependencyRuleSparesNonGit(t *testing.T) {
	guardPolicyTestEnv(t, writeBlockGitDependencyBundle(t))
	reg := packageSpec{Ecosystem: "npm", Name: "some-pkg", Version: "1.0.0"}
	if v, ok := guardPolicyLane(context.Background(), reg, acquireIncomplete, behavioralVerdict{}); ok && v.Block {
		t.Fatalf("a degraded-analysis registry install must not be refused by a git rule, got %+v", v)
	}
	g := &localGuard{detectors: map[string]*typosquat.Detector{}, malware: malware.NewIndex(nil)}
	for _, spec := range []packageSpec{
		parseNpmSpec("zqxmemo@https://cdn.example.com/zqxmemo-1.0.0.tgz"),
		parsePipSpec("https://cdn.example.com/zqxmemo-1.0.tar.gz"),
		parseNpmSpec("zqxmemo@file:../zqxmemo"),
		{Ecosystem: "cargo", Name: "zqxmemo", Version: "1.0.0", Origin: "registry+https://my-registry.example/index"},
	} {
		if _, blocked := g.evaluateAll(context.Background(), []packageSpec{spec}); blocked {
			t.Errorf("origin %q is not git; the git rule must not refuse it", spec.Origin)
		}
	}
}

// TestGuardGitDependencyNoRuleUnchanged: with no operator rule, a git spec
// is still today's non-blocking "not assessed".
func TestGuardGitDependencyNoRuleUnchanged(t *testing.T) {
	guardPolicyTestEnv(t, "")
	g := &localGuard{detectors: map[string]*typosquat.Detector{}, malware: malware.NewIndex(nil)}
	for name, spec := range gitDependencySpecs() {
		verdicts, blocked := g.evaluateAll(context.Background(), []packageSpec{spec})
		if blocked || len(verdicts) != 1 || verdicts[0].Severity != guardSeverityNotAssessed {
			t.Errorf("%s: without a rule a git spec stays not-assessed and non-blocking, got blocked=%v %+v", name, blocked, verdicts)
		}
	}
}

// TestPRScanPipGitLinesAreRows: pip requirements git lines used to vanish —
// `-e` lines were dropped as options and `pkg @ git+…` / bare `git+…` lines
// have no "==". Each is now a not-assessed row; a local path stays silent.
func TestPRScanPipGitLinesAreRows(t *testing.T) {
	head := strings.Join([]string{
		"requests==2.31.0",
		"-e git+https://github.com/victim/alpha#egg=alpha",
		"--editable=git+https://github.com/victim/delta.git#egg=delta",
		"beta @ git+https://github.com/victim/beta@v1.0",
		"git+https://github.com/victim/gamma",
		"-e .",
		"./libs/local",
		"wheelpkg @ https://files.pythonhosted.org/packages/wheelpkg-1.2.0-py3-none-any.whl",
	}, "\n")
	added, _, err := diffManifest(kindPipRequirements, "requirements.txt", nil, []byte(head))
	if err != nil {
		t.Fatal(err)
	}
	reg, nonReg := map[string]string{}, map[string]string{}
	for _, e := range added {
		if e.Origin != "" {
			nonReg[e.Name] = e.Origin
		} else {
			reg[e.Name] = e.Version
		}
	}
	if reg["requests"] != "2.31.0" || reg["wheelpkg"] != "1.2.0" || len(reg) != 2 {
		t.Errorf("registry rows = %v, want requests and the PyPI-hosted wheel", reg)
	}
	for _, n := range []string{"alpha", "delta", "beta", "github.com/victim/gamma"} {
		if nonReg[n] == "" {
			t.Errorf("git line %q produced no non-registry row; got %v", n, nonReg)
		}
	}
	if len(nonReg) != 4 {
		t.Errorf("non-registry rows = %v, want exactly the four git lines (local paths are first-party)", nonReg)
	}
	for _, raw := range added {
		if raw.Origin == "" {
			continue
		}
		e := evaluatePREntry(raw)
		if e.Verdict == "allow" || e.Signals[0].ID != prScanNotAssessedSignalID {
			t.Errorf("%s: a git row must lead with %s and never be allow: %+v", e.Name, prScanNotAssessedSignalID, e)
		}
	}
}

// TestPRScanPackageJSONGitSpecsGetAnOrigin: "x": "github:o/r" was scored as
// the registry's x.
func TestPRScanPackageJSONGitSpecsGetAnOrigin(t *testing.T) {
	head := `{"dependencies":{"lodash":"^4.17.21","alpha":"github:victim/alpha","beta":"git+https://github.com/victim/beta.git#v1","gamma":"victim/gamma","local":"file:../local"},
"devDependencies":{"delta":"git+ssh://git@github.com/victim/delta.git"}}`
	added, _, err := diffManifest(kindNPMPackageJSON, "package.json", nil, []byte(head))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range added {
		got[e.Name] = e.Origin
	}
	if _, ok := got["lodash"]; !ok || got["lodash"] != "" {
		t.Errorf("lodash is a registry range and must stay a registry row: %v", got)
	}
	for _, n := range []string{"alpha", "beta", "gamma", "delta"} {
		if got[n] == "" {
			t.Errorf("%s is a git spec and must carry an Origin: %v", n, got)
		}
	}
	if strings.Contains(got["delta"], "git@") {
		t.Errorf("origin must be sanitised, got %q", got["delta"])
	}
}

// TestPRScanGitDependencyRuleBlocks: pr-scan feeds gitDependency too, so the
// same org rule turns a git row into a blocking one; registry rows are spared.
func TestPRScanGitDependencyRuleBlocks(t *testing.T) {
	prScanPolicyTestEnv(t, writeBlockGitDependencyBundle(t))
	git := evaluatePREntry(rawEntry{Ecosystem: "pip", Name: "zqxmemo", Origin: "git+https://github.com/victim/zqxmemo"})
	if git.Verdict != "block" || !hasPRSignal(git.Signals, prScanPolicySignalID("org/no-git-deps")) {
		t.Fatalf("a git row must be blocked by block-if-gitDependency, got %+v", git)
	}
	for _, e := range []rawEntry{
		{Ecosystem: "pip", Name: "requests", Version: "2.31.0"},
		{Ecosystem: "cargo", Name: "x", Version: "1.0.0", Origin: "registry+https://my-registry.example/index"},
	} {
		if got := evaluatePREntry(e); got.Verdict == "block" {
			t.Errorf("%s (origin %q) is not git and must not be blocked: %+v", e.Name, e.Origin, got)
		}
	}
}
